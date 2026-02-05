const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const xml2js = require('xml2js');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Configuration
const PORT = 80;
const logsFile = path.join(__dirname, 'logs', 'requests.log');
const statsFile = path.join(__dirname, 'data', 'stats.json');

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.text({ type: 'application/xml' }));
app.use(cookieParser());
app.use(express.static('public'));

// Initialisation des fichiers
if (!fs.existsSync('logs')) fs.mkdirSync('logs');
if (!fs.existsSync('data')) fs.mkdirSync('data');
if (!fs.existsSync(logsFile)) fs.writeFileSync(logsFile, '');
if (!fs.existsSync(statsFile)) fs.writeFileSync(statsFile, JSON.stringify({ total: 0, byVuln: {} }));

// Base de données SQLite pour les tests
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)");
  db.run("INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com')");
  db.run("INSERT INTO users VALUES (2, 'user', 'password', 'user@example.com')");
  db.run("INSERT INTO users VALUES (3, 'test', 'test123', 'test@example.com')");
});

// Stockage en mémoire pour les logs et stats
let requestLogs = [];
let stats = JSON.parse(fs.readFileSync(statsFile, 'utf8'));

// WebSocket pour les logs en temps réel
const clients = new Set();
wss.on('connection', (ws) => {
  clients.add(ws);
  ws.on('close', () => clients.delete(ws));
});

function broadcastLog(logEntry) {
  const message = JSON.stringify(logEntry);
  clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// Middleware de logging
app.use((req, res, next) => {
  const logEntry = {
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.url,
    headers: req.headers,
    query: req.query,
    body: req.body,
    cookies: req.cookies,
    ip: req.ip || req.connection.remoteAddress
  };
  
  requestLogs.unshift(logEntry);
  if (requestLogs.length > 1000) requestLogs = requestLogs.slice(0, 1000);
  
  // Sauvegarde dans le fichier
  fs.appendFileSync(logsFile, JSON.stringify(logEntry) + '\n');
  
  // Broadcast via WebSocket
  broadcastLog(logEntry);
  
  // Mise à jour des stats
  stats.total++;
  const vulnType = req.headers['x-vuln-type'] || 'unknown';
  stats.byVuln[vulnType] = (stats.byVuln[vulnType] || 0) + 1;
  fs.writeFileSync(statsFile, JSON.stringify(stats));
  
  next();
});

// Routes des pages principales
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/logs', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'logs.html'));
});

app.get('/stats', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'stats.html'));
});

app.get('/debug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'debug.html'));
});

app.get('/tests', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'tests.html'));
});

// API pour récupérer les logs
app.get('/api/logs', (req, res) => {
  res.json(requestLogs);
});

// API pour les statistiques
app.get('/api/stats', (req, res) => {
  res.json(stats);
});

// ========== ENDPOINTS VULNÉRABLES ==========

// 1. SQL Injection
app.get('/vuln/sqli', (req, res) => {
  const username = req.query.username || '';
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  
  db.all(query, [], (err, rows) => {
    if (err) {
      res.json({ error: err.message, query: query, vulnerable: true });
    } else {
      res.json({ results: rows, query: query, vulnerable: true });
    }
  });
});

// 2. XSS (Reflected)
app.get('/vuln/xss', (req, res) => {
  const name = req.query.name || 'Invité';
  res.send(`
    <!DOCTYPE html>
    <html>
      <head><title>XSS Test</title></head>
      <body>
        <h1>Bienvenue ${name}!</h1>
        <p>Cette page est vulnérable au XSS</p>
      </body>
    </html>
  `);
});

// 3. Path Traversal
app.get('/vuln/path-traversal', (req, res) => {
  const filename = req.query.file || 'default.txt';
  const filepath = path.join(__dirname, 'public', filename);
  
  fs.readFile(filepath, 'utf8', (err, data) => {
    if (err) {
      res.json({ error: err.message, path: filepath, vulnerable: true });
    } else {
      res.json({ content: data, path: filepath, vulnerable: true });
    }
  });
});

// 4. Command Injection
app.get('/vuln/command-injection', (req, res) => {
  const host = req.query.host || 'localhost';
  const command = `ping -c 1 ${host}`;
  
  exec(command, (error, stdout, stderr) => {
    res.json({
      command: command,
      output: stdout,
      error: error ? error.message : null,
      stderr: stderr,
      vulnerable: true
    });
  });
});

// 5. SSRF (Server-Side Request Forgery)
app.get('/vuln/ssrf', (req, res) => {
  const url = req.query.url || 'http://localhost';
  
  const http_module = url.startsWith('https') ? require('https') : require('http');
  
  http_module.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => {
      res.json({
        url: url,
        statusCode: response.statusCode,
        headers: response.headers,
        body: data.substring(0, 1000),
        vulnerable: true
      });
    });
  }).on('error', (err) => {
    res.json({ error: err.message, url: url, vulnerable: true });
  });
});

// 6. NoSQL Injection (simulation)
app.post('/vuln/nosqli', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  // Simulation d'une requête MongoDB vulnérable
  res.json({
    query: { username: username, password: password },
    message: "Simulation NoSQL Injection",
    vulnerable: true,
    hint: "Essayez: {\"$ne\": null}"
  });
});

// 7. Local File Inclusion
app.get('/vuln/lfi', (req, res) => {
  const page = req.query.page || 'home';
  const filepath = path.join(__dirname, page);
  
  fs.readFile(filepath, 'utf8', (err, data) => {
    if (err) {
      res.json({ error: err.message, path: filepath, vulnerable: true });
    } else {
      res.send(data);
    }
  });
});

// 8. LDAP Injection (simulation)
app.get('/vuln/ldapi', (req, res) => {
  const username = req.query.username || '';
  const ldapQuery = `(&(objectClass=user)(uid=${username}))`;
  
  res.json({
    query: ldapQuery,
    message: "Simulation LDAP Injection",
    vulnerable: true,
    hint: "Essayez: *)(uid=*))(|(uid=*"
  });
});

// 9. HTTP Request Smuggling (simulation)
app.post('/vuln/request-smuggling', (req, res) => {
  res.json({
    headers: req.headers,
    body: req.body,
    rawHeaders: req.rawHeaders,
    vulnerable: true,
    message: "Endpoint vulnérable au Request Smuggling"
  });
});

// 10. Open Redirect
app.get('/vuln/open-redirect', (req, res) => {
  const url = req.query.url || '/';
  res.redirect(url);
});

// 11. Sensitive Files
app.get('/vuln/sensitive-files', (req, res) => {
  const sensitiveData = {
    '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
    '/.env': 'DB_PASSWORD=super_secret_password\nAPI_KEY=sk-1234567890abcdef',
    '/config.json': '{"database": {"host": "localhost", "password": "admin123"}}',
    vulnerable: true
  };
  res.json(sensitiveData);
});

// 12. CRLF Injection
app.get('/vuln/crlf', (req, res) => {
  const name = req.query.name || 'User';
  res.setHeader('X-Custom-Header', name);
  res.json({ message: "CRLF Injection Test", header: name, vulnerable: true });
});

// 13. UTF8/Unicode Bypass
app.get('/vuln/unicode-bypass', (req, res) => {
  const input = req.query.input || '';
  // Pas de sanitization des caractères Unicode
  res.json({
    input: input,
    length: input.length,
    charCodes: [...input].map(c => c.charCodeAt(0)),
    vulnerable: true,
    message: "Aucune validation Unicode"
  });
});

// 14. XXE (XML External Entity)
app.post('/vuln/xxe', (req, res) => {
  const xmlData = req.body;
  
  const parser = new xml2js.Parser({
    explicitArray: false,
    // Configuration vulnérable
  });
  
  parser.parseString(xmlData, (err, result) => {
    if (err) {
      res.json({ error: err.message, vulnerable: true });
    } else {
      res.json({ parsed: result, vulnerable: true });
    }
  });
});

// 15. SSTI (Server-Side Template Injection)
app.get('/vuln/ssti', (req, res) => {
  const template = req.query.template || 'Hello World';
  try {
    // Simulation d'évaluation de template dangereuse
    const result = eval('`' + template + '`');
    res.json({ template: template, result: result, vulnerable: true });
  } catch (err) {
    res.json({ error: err.message, template: template, vulnerable: true });
  }
});

// 16. HTTP Parameter Pollution
app.get('/vuln/hpp', (req, res) => {
  res.json({
    query: req.query,
    message: "Tous les paramètres sont acceptés sans validation",
    vulnerable: true
  });
});

// 17. Web Cache Poisoning (simulation)
app.get('/vuln/cache-poisoning', (req, res) => {
  const xForwardedHost = req.headers['x-forwarded-host'] || req.headers['host'];
  res.setHeader('X-Cache', 'HIT');
  res.json({
    host: xForwardedHost,
    message: "Cache basé sur X-Forwarded-Host",
    vulnerable: true
  });
});

// 18. IP Bypass
app.get('/vuln/ip-bypass', (req, res) => {
  const realIp = req.headers['x-real-ip'] || 
                 req.headers['x-forwarded-for'] || 
                 req.ip;
  
  res.json({
    detectedIp: realIp,
    headers: {
      'x-real-ip': req.headers['x-real-ip'],
      'x-forwarded-for': req.headers['x-forwarded-for'],
      'x-originating-ip': req.headers['x-originating-ip']
    },
    message: "IP déterminée à partir des headers",
    vulnerable: true
  });
});

// 19. User-Agent Detection
app.get('/vuln/user-agent', (req, res) => {
  const userAgent = req.headers['user-agent'];
  
  // Comportement différent basé sur le User-Agent
  let response = {
    userAgent: userAgent,
    vulnerable: true
  };
  
  if (userAgent && userAgent.includes('admin')) {
    response.access = 'ADMIN';
    response.secretData = 'Données sensibles administrateur';
  } else {
    response.access = 'USER';
  }
  
  res.json(response);
});

// Route de test générique
app.all('/vuln/test', (req, res) => {
  res.json({
    method: req.method,
    headers: req.headers,
    query: req.query,
    body: req.body,
    cookies: req.cookies,
    params: req.params,
    message: "Endpoint de test générique - Vulnérable à tout"
  });
});

// Démarrage du serveur
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Serveur WAF Debug démarré sur le port ${PORT}`);
  console.log(`📊 Interface disponible sur http://localhost:${PORT}`);
  console.log(`⚠️  ATTENTION: Ce serveur contient des vulnérabilités intentionnelles!`);
  console.log(`🔒 À utiliser UNIQUEMENT dans un environnement de test isolé!`);
});
