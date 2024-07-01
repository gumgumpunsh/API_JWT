# Utiliser une image Node.js de base
FROM node:20-alpine

# Définir le répertoire de travail dans le conteneur
WORKDIR /usr/src/app

# Copier le package.json et le package-lock.json du répertoire parent
COPY . .

# Installer les dépendances
RUN npm install

# Copier le contenu du dossier back
COPY . /usr/src/app/back

# Exposer le port sur lequel l'application s'exécute
EXPOSE 5000

# Commande pour démarrer l'application
CMD ["node", "server.js"]
