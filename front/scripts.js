// Initialize to show login form by default
document.getElementById('loginFormContainer').style.display = 'block';

document.getElementById('loginForm').addEventListener('submit', function (e) {
    e.preventDefault();

    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    const query = `
        mutation {
            generateToken(username: "${username}", password: "${password}") {
                token
            }
        }
    `;

    fetch(process.env.URL_GRAPHQL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query }),
    })
        .then(response => response.json())
        .then(data => {
            if (data.data && data.data.generateToken && data.data.generateToken.token) {
                alert('Connexion réussie !');
                localStorage.setItem('token', data.data.generateToken.token);

                // Rediriger l'utilisateur vers la Home page
                window.location.href = 'home/home.html';
            } else {
                alert('Nom d’utilisateur ou mot de passe incorrect');
            }
        })
        .catch(error => console.error('Erreur:', error));
});
