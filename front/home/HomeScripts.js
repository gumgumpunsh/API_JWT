// Afficher ou masquer le formulaire d'inscription lorsqu'on clique sur le bouton
document.getElementById('showRegister').addEventListener('click', function () {
    const registerFormContainer = document.getElementById('registerFormContainer');
    if (registerFormContainer.style.display === 'none' || registerFormContainer.style.display === '') {
        registerFormContainer.style.display = 'block';
    } else {
        registerFormContainer.style.display = 'none';
    }
});

document.getElementById('registerFormContainer').style.display = 'none';

document.getElementById('registerForm').addEventListener('submit', function (e) {
    e.preventDefault();

    const username = document.getElementById('registerUsername').value;
    const password = document.getElementById('registerPassword').value;

    fetch('http://localhost:5000/admin/addUser', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-access-token': `${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ username, password }),
    })
        .then(response => {
            if (response.ok) {
                alert('Inscription réussie !');
            } else {
                alert('Erreur lors de l\'inscription');
            }
        })
        .catch(error => console.error('Erreur:', error));
});

document.addEventListener('DOMContentLoaded', function() {
    const token = localStorage.getItem('token');

    if (!token) {
        console.log('Aucun token trouvé, redirection vers la page de connexion.');
        window.location.href = '/login.html'; // Rediriger l'utilisateur vers la page de connexion s'il n'est pas authentifié
        return;
    }

    fetch('http://localhost:5000/admin/listUsers', {
        method: 'GET',
        headers: {
            'x-access-token': `${localStorage.getItem('token')}`
        }
    })
        .then(response => response.json())
        .then(users => {
            const userList = document.getElementById('userList');
            users.forEach(user => {
                const li = document.createElement('li');
                li.innerHTML = `ID: ${user.id}, Username: ${user.username} <span class="delete-icon" data-username="${user.username}">&times;</span>`;
                userList.appendChild(li);
            });

            // Ajouter des écouteurs d'événements pour les icônes de suppression
            document.querySelectorAll('.delete-icon').forEach(icon => {
                icon.addEventListener('click', function() {
                    const username = this.getAttribute('data-username');
                    deleteUser(username, token);
                });
            });
        })
        .catch(error => {
            console.error('Erreur:', error);
            alert('Erreur lors de la récupération des utilisateurs.');
        });
});

// Fonction de suppression d'un utilisateur
function deleteUser(username, token) {
    if (!confirm(`Voulez-vous vraiment supprimer l'utilisateur ${username} ?`)) {
        return;
    }

    fetch(`http://localhost:5000/user/delUser/${username}`, {
        method: 'DELETE',
        headers: {
            'x-access-token': `${token}`
        }
    })
        .then(response => response.json())
        .then(result => {
            if (result.error) {
                alert(`Erreur : ${result.error}`);
            } else {
                alert(result.message);
                location.reload(); // Recharger la page pour mettre à jour la liste des utilisateurs
            }
        })
        .catch(error => {
            console.error('Erreur:', error);
            alert('Erreur lors de la suppression de l\'utilisateur.');
        });
}