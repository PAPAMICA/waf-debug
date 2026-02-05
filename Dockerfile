FROM node:20-alpine

WORKDIR /app

# Installation des dépendances système pour SQLite
RUN apk add --no-cache python3 make g++ sqlite

# Copie des fichiers de dépendances
COPY package*.json ./

# Installation des dépendances npm
RUN npm install --production

# Copie du code source
COPY . .

# Exposition du port 80
EXPOSE 80

# Création des répertoires nécessaires
RUN mkdir -p /app/logs /app/data

# Commande de démarrage
CMD ["node", "server.js"]
