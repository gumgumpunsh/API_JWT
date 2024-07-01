const express = require('express');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const cors = require('cors');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');

const app = express();
app.use(cors());

// Configuration globale via dotenv
dotenv.config();

// Middleware pour parser le corps des requêtes JSON
app.use(express.json());

// Chemin vers la base de données SQLite
const dbPath = path.resolve(__dirname, 'users.db');
const db = new sqlite3.Database(dbPath);

// Initialisation de la base de données
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)");

    const saltRounds = 10;
    const adminPassword = 'admin_password';
    bcrypt.hash(adminPassword, saltRounds, (err, hash) => {
        if (err) throw err;
        const stmt = db.prepare("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)");
        stmt.run('admin', hash);
        stmt.finalize();
    });
});

let PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is up and running on ${PORT} ...`);
});

// Génération de JWT
app.post("/user/generateToken", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send("Username and password are required");
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) {
            return res.status(500).send("Internal server error");
        }

        if (!user) {
            return res.status(401).send("Invalid username or password");
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                return res.status(500).send("Internal server error");
            }

            if (result) {
                let jwtSecretKey = process.env.JWT_SECRET_KEY;
                let data = {
                    time: new Date(),
                    userId: user.id,
                    username: user.username
                }

                const token = jwt.sign(data, jwtSecretKey, { expiresIn: '2d' });

                return res.json({ token });
            } else {
                return res.status(401).send("Invalid username or password");
            }
        });
    });
});

// Validation du JWT
app.get("/user/validateToken", authenticateToken, (req, res) => {
    res.json({ message: "Successfully Verified" });
});

// Middleware pour vérifier le token JWT
function authenticateToken(req, res, next) {
    const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
    const token = req.headers[tokenHeaderKey];

    if (!token) {
        return res.status(403).json({ error: "Token is required" });
    }

    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: "Invalid Token" });
        }
        req.user = decoded;
        next();
    });
}

// Middleware pour vérifier l'administrateur
function verifyAdmin(req, res, next) {
    const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
    const token = req.headers[tokenHeaderKey];

    if (!token) {
        return res.status(403).send("Token is required");
    }

    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).send("Invalid Token");
        }

        if (decoded.username === 'admin') {
            req.user = decoded;
            next();
        } else {
            return res.status(403).send("Admin privileges required");
        }
    });
}

// Ajouter un nouvel utilisateur (protégé par l'authentification admin)
app.post("/admin/addUser", verifyAdmin, (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send("Username and password are required");
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) {
            return res.status(500).send("Internal server error");
        }

        if (user) {
            return res.status(409).send("Username already exists");
        }

        const saltRounds = 10;
        bcrypt.hash(password, saltRounds, (err, hash) => {
            if (err) {
                return res.status(500).send("Internal server error");
            }

            const stmt = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
            stmt.run(username, hash, (err) => {
                if (err) {
                    return res.status(500).send("Error creating user");
                }
                return res.send("User created successfully");
            });
            stmt.finalize();
        });
    });
});

// Supprimer un utilisateur (accessible uniquement par l'admin)
app.delete("/user/delUser/:username", verifyAdmin, (req, res) => {
    const { username } = req.params;
    if (username === 'admin') {
        return res.status(403).json({ error: "Cannot delete admin user" });
    }

    const stmt = db.prepare("DELETE FROM users WHERE username = ?");
    stmt.run(username, (err) => {
        if (err) {
            return res.status(500).json({ error: "Error deleting user" });
        }
        res.json({ message: "User deleted successfully" });
    });
    stmt.finalize();
});

// Lister tous les utilisateurs (protégé par l'authentification admin)
app.get("/admin/listUsers", verifyAdmin, (req, res) => {
    db.all("SELECT id, username, password FROM users", [], (err, rows) => {
        if (err) {
            return res.status(500).send("Internal server error");
        }
        return res.json(rows);
    });
});

// ---- GraphQL Setup ----

// Define GraphQL schema
const schema = buildSchema(`
    type Token {
        token: String
    }
    
    type User {
        id: ID!
        username: String!
        password: String!
    }

    type Query {
        listUsers: [User]
    }

    type Mutation {
        generateToken(username: String!, password: String!): Token
        addUser(username: String!, password: String!): User
        deleteUser(username: String!): String
    }
`);

// Define GraphQL resolvers
const root = {
    generateToken: ({ username, password }) => {
        return new Promise((resolve, reject) => {
            db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
                if (err || !user) {
                    return reject(new Error("Nom d’utilisateur ou mot de passe incorrect"));
                }

                bcrypt.compare(password, user.password, (err, result) => {
                    if (err || !result) {
                        return reject(new Error("Nom d’utilisateur ou mot de passe incorrect"));
                    }

                    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });
                    resolve({ token });
                });
            });
        });
    },
    listUsers: (args, context) => {
        return new Promise((resolve, reject) => {
            const token = context.headers['x-access-token'];
            if (!token) {
                reject(new Error("Token is required"));
            }

            jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
                if (err) {
                    reject(new Error("Invalid Token"));
                } else if (decoded.username !== 'admin') {
                    reject(new Error("Admin privileges required"));
                } else {
                    db.all("SELECT id, username, password FROM users", [], (err, rows) => {
                        if (err) {
                            reject(new Error("Internal server error"));
                        }
                        resolve(rows);
                    });
                }
            });
        });
    },
    addUser: ({ username, password }, context) => {
        return new Promise((resolve, reject) => {
            const token = context.headers['x-access-token'];
            if (!token) {
                reject(new Error("Token is required"));
            }

            jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
                if (err) {
                    reject(new Error("Invalid Token"));
                } else if (decoded.username !== 'admin') {
                    reject(new Error("Admin privileges required"));
                } else {
                    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
                        if (err) {
                            reject(new Error("Internal server error"));
                        }

                        if (user) {
                            reject(new Error("Username already exists"));
                        }

                        const saltRounds = 10;
                        bcrypt.hash(password, saltRounds, (err, hash) => {
                            if (err) {
                                reject(new Error("Internal server error"));
                            }

                            const stmt = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
                            stmt.run(username, hash, function(err) {
                                if (err) {
                                    reject(new Error("Error creating user"));
                                }
                                resolve({ id: this.lastID, username, password: hash });
                            });
                            stmt.finalize();
                        });
                    });
                }
            });
        });
    },
    deleteUser: ({ username }, context) => {
        return new Promise((resolve, reject) => {
            const token = context.headers['x-access-token'];
            if (!token) {
                reject(new Error("Token is required"));
            }

            jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
                if (err) {
                    reject(new Error("Invalid Token"));
                } else if (decoded.username !== 'admin') {
                    reject(new Error("Admin privileges required"));
                } else if (username === 'admin') {
                    reject(new Error("Cannot delete admin user"));
                } else {
                    const stmt = db.prepare("DELETE FROM users WHERE username = ?");
                    stmt.run(username, (err) => {
                        if (err) {
                            reject(new Error("Error deleting user"));
                        } else {
                            resolve("User deleted successfully");
                        }
                    });
                    stmt.finalize();
                }
            });
        });
    }
};

// Setup GraphQL endpoint
app.use('/graphql', graphqlHTTP((req, res) => ({
    schema: schema,
    rootValue: root,
    graphiql: true,
    context: { headers: req.headers }
})));