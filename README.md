# 🛡️ WAF Debug Server

Serveur web de débogage et test de vulnérabilités pour l'apprentissage et le développement de WAF (Web Application Firewall).

## ⚠️ AVERTISSEMENT DE SÉCURITÉ

**CE SERVEUR CONTIENT DES VULNÉRABILITÉS INTENTIONNELLES !**

- ❌ NE JAMAIS utiliser en production
- ❌ NE JAMAIS déployer sur un réseau accessible publiquement
- ✅ Utiliser UNIQUEMENT dans un environnement de test isolé
- ✅ Idéal pour tester des WAF et apprendre la sécurité web

## 🚀 Démarrage Rapide

### Avec Docker (Recommandé)

```bash
# Construire et démarrer le conteneur
docker-compose up -d

# Accéder à l'interface
# Ouvrir http://localhost dans votre navigateur
```

### Sans Docker (dev)

```bash
# Installer les dépendances
npm install

# Démarrer le serveur
npm start

# Accéder à l'interface
# Ouvrir http://localhost:80 dans votre navigateur
```

## 📋 Fonctionnalités

### Interface Web
- 🏠 **Page d'accueil** : Vue d'ensemble avec logs en direct intégrés
- 📊 **Logs en direct** : Surveillance temps réel des requêtes avec WebSocket et détails complets
- 📈 **Statistiques** : Analytics et graphiques des tests
- 🐛 **Debug** : Inspection détaillée des requêtes HTTP
- 🧪 **Tests** : Génération de commandes curl pour tests externes

### Fonctionnalités Avancées
- 🌍 **Géolocalisation IP** : Détection automatique du pays via X-Real-IP
- 🔍 **Détection d'attaques** : Reconnaissance automatique des patterns suspects
- 🚨 **Alertes visuelles** : Affichage en rouge des requêtes suspectes
- 📝 **Headers formatés** : Affichage structuré et lisible des headers HTTP
- 🎯 **Tests externes** : Commandes curl prêtes à l'emploi pour tests depuis l'extérieur

### Vulnérabilités Disponibles

Le serveur expose 19 types de vulnérabilités pour les tests :

1. **SQL Injection** - `/vuln/sqli`
2. **XSS (Cross-Site Scripting)** - `/vuln/xss`
3. **Path Traversal** - `/vuln/path-traversal`
4. **Command Injection** - `/vuln/command-injection`
5. **SSRF** - `/vuln/ssrf`
6. **NoSQL Injection** - `/vuln/nosqli`
7. **Local File Inclusion** - `/vuln/lfi`
8. **LDAP Injection** - `/vuln/ldapi`
9. **HTTP Request Smuggling** - `/vuln/request-smuggling`
10. **Open Redirect** - `/vuln/open-redirect`
11. **Sensitive Files** - `/vuln/sensitive-files`
12. **CRLF Injection** - `/vuln/crlf`
13. **UTF8/Unicode Bypass** - `/vuln/unicode-bypass`
14. **XXE (XML External Entity)** - `/vuln/xxe`
15. **SSTI (Server-Side Template Injection)** - `/vuln/ssti`
16. **HTTP Parameter Pollution** - `/vuln/hpp`
17. **Web Cache Poisoning** - `/vuln/cache-poisoning`
18. **IP Bypass** - `/vuln/ip-bypass`
19. **User-Agent Detection** - `/vuln/user-agent`

## 🛠️ Stack Technique

- **Backend** : Node.js + Express
- **Base de données** : SQLite (en mémoire)
- **WebSocket** : ws (logs temps réel)
- **Géolocalisation** : geoip-lite
- **Frontend** : HTML5 + Tailwind CSS + JavaScript
- **Graphiques** : Chart.js
- **Conteneurisation** : Docker

## 📁 Structure du Projet

```
waf-debug/
├── server.js              # Serveur principal
├── package.json           # Dépendances npm
├── Dockerfile            # Configuration Docker
├── docker-compose.yml    # Configuration Docker Compose
├── public/               # Fichiers statiques
│   ├── index.html       # Page d'accueil
│   ├── logs.html        # Page logs en direct
│   ├── stats.html       # Page statistiques
│   ├── debug.html       # Page debug
│   └── tests.html       # Page tests
├── logs/                # Logs des requêtes
└── data/                # Données persistantes

```

## 🔧 Configuration

### Variables d'environnement

- `NODE_ENV` : Environnement (development/production)
- Port par défaut : `80`

### Volumes Docker

- `./logs:/app/logs` : Logs des requêtes
- `./data:/app/data` : Statistiques persistantes

## 📊 API Endpoints

### API de monitoring

- `GET /api/logs` : Récupère les logs des requêtes (avec IP réelle et géolocalisation)
- `GET /api/stats` : Récupère les statistiques
- `WS /` : WebSocket pour logs en temps réel

### Endpoints vulnérables

Tous les endpoints sous `/vuln/*` sont intentionnellement vulnérables pour les tests.

**Headers importants** :
- `X-Real-IP` : IP réelle du client (utilisée pour la géolocalisation)
- `X-Vuln-Type` : Type de vulnérabilité testée (pour les statistiques)
- `X-Forwarded-For` : Fallback si X-Real-IP n'est pas présent

## 💡 Exemples d'utilisation

### Test SQL Injection depuis l'extérieur

```bash
curl -X GET "http://YOUR_SERVER/vuln/sqli?username=admin'%20OR%20'1'%3D'1" \
  -H "X-Real-IP: YOUR_IP" \
  -H "X-Vuln-Type: sqli"
```

### Test XSS

```bash
curl -X GET "http://YOUR_SERVER/vuln/xss?name=%3Cscript%3Ealert('XSS')%3C%2Fscript%3E" \
  -H "X-Real-IP: YOUR_IP" \
  -H "X-Vuln-Type: xss"
```

### Test Command Injection

```bash
curl -X GET "http://YOUR_SERVER/vuln/command-injection?host=localhost%3B%20cat%20%2Fetc%2Fpasswd" \
  -H "X-Real-IP: YOUR_IP" \
  -H "X-Vuln-Type: command-injection"
```

**Note importante** : Le header `X-Real-IP` est utilisé pour identifier l'IP réelle du client et effectuer la géolocalisation.

## 🎨 Interface Utilisateur

L'interface utilise Tailwind CSS avec un thème sombre moderne et des dégradés colorés pour chaque section :

- 🟣 Violet pour l'accueil
- 🔵 Bleu pour les logs
- 🟢 Vert pour les stats
- 🟡 Jaune pour le debug
- 🔴 Rouge pour les tests

## 🔒 Sécurité

Ce projet est conçu UNIQUEMENT à des fins éducatives et de test. Les vulnérabilités sont intentionnelles.

**Recommandations :**
- Exécuter dans un réseau isolé
- Utiliser Docker pour l'isolation
- Ne jamais exposer sur Internet
- Surveiller les logs système

## 📝 Licence

Projet à usage éducatif et de développement uniquement.

## 👥 Contribution

Pour contribuer à ce projet :
1. Fork le projet
2. Créer une branche de feature
3. Commit les changements
4. Push vers la branche
5. Ouvrir une Pull Request

## 🆘 Support

Pour toute question ou problème, ouvrez une issue sur le dépôt GitLab.

---

**⚠️ Rappel : Utilisez ce serveur de manière responsable et uniquement dans un environnement de test isolé !**
