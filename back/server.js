const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

app.use(express.json());

const users = [];

// Inscription
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.status(201).send('User registered');
});

// Connexion
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username: user.username }, 'secret_key', { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(400).send('Invalid credentials');
    }
});

// Protected
app.get('/protected', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) return res.sendStatus(403);
        res.send('This is protected data');
    });
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});