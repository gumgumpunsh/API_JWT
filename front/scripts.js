// Initialize to show login form by default
document.getElementById('loginFormContainer').style.display = 'block';

document.getElementById('loginForm').addEventListener('submit', function (e) {
    e.preventDefault();

    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    fetch('http://localhost:5000/user/generateToken', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
    })
        .then(response => response.json())
        .then(data => {
            if (data.token) {
                alert('Connexion réussie !');
                localStorage.setItem('token', data.token);

                // Rediriger l'utilisateur vers la Home page
                window.location.href = 'home/home.html'
            } else {
                alert('Nom d’utilisateur ou mot de passe incorrect');
            }
        })
        .catch(error => console.error('Erreur:', error));
});
