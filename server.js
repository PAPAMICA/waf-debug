const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const geoip = require('geoip-lite');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Configuration
const PORT = 80;
const logsFile = path.join(__dirname, 'logs', 'requests.log');
const statsFile = path.join(__dirname, 'data', 'stats.json');

// Initialisation des fichiers
if (!fs.existsSync('logs')) fs.mkdirSync('logs');
if (!fs.existsSync('data')) fs.mkdirSync('data');
if (!fs.existsSync(logsFile)) fs.writeFileSync(logsFile, '');
if (!fs.existsSync(statsFile)) fs.writeFileSync(statsFile, JSON.stringify({ total: 0, byMethod: {}, byIp: {}, byCountry: {}, byPath: {} }));

// Stockage en mémoire
let requestLogs = [];
let stats = JSON.parse(fs.readFileSync(statsFile, 'utf8'));

// Initialiser les stats si nécessaire
if (!stats.byMethod) stats.byMethod = {};
if (!stats.byIp) stats.byIp = {};
if (!stats.byCountry) stats.byCountry = {};
if (!stats.byPath) stats.byPath = {};

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

// Middleware pour capturer le body brut
app.use((req, res, next) => {
  let data = '';
  req.setEncoding('utf8');
  req.on('data', chunk => data += chunk);
  req.on('end', () => {
    req.rawBody = data;
    // Tenter de parser le body
    const contentType = req.headers['content-type'] || '';
    if (contentType.includes('application/json')) {
      try {
        req.body = JSON.parse(data);
      } catch (e) {
        req.body = { _raw: data };
      }
    } else if (contentType.includes('application/x-www-form-urlencoded')) {
      try {
        req.body = Object.fromEntries(new URLSearchParams(data));
      } catch (e) {
        req.body = { _raw: data };
      }
    } else {
      req.body = data || null;
    }
    next();
  });
});

app.use(cookieParser());

// CORS headers pour les API
app.use('/api', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Fonction pour vérifier si c'est une requête interne (pages du site)
function isInternalRequest(req) {
  const url = req.url;
  const internalPages = ['/', '/logs', '/stats', '/debug', '/index.html', '/logs.html', '/stats.html', '/debug.html'];
  const urlPath = url.split('?')[0];
  if (internalPages.includes(urlPath)) return true;
  if (url.startsWith('/api/')) return true;
  if (url.match(/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|html)$/)) return true;
  return false;
}

// Fonction de détection d'attaque
function detectAttackType(req) {
  const testString = req.url + (req.rawBody || '') + JSON.stringify(req.query || {});
  const attacks = [];
  
  if (/(\.\.[\/\\]){2,}|\.\.%2[fF]/i.test(testString)) attacks.push('Path Traversal');
  if (/<script|javascript:|on\w+\s*=/i.test(testString)) attacks.push('XSS');
  if (/(union\s+select|'\s*or\s*'|'\s*or\s+\d|;\s*drop\s+table)/i.test(testString)) attacks.push('SQLi');
  if (/\{\s*['"]\$[a-z]+['"]\s*:/i.test(testString)) attacks.push('NoSQLi');
  if (/[;&|`]\s*(cat|ls|wget|curl|bash|sh|id|whoami)/i.test(testString)) attacks.push('Command Injection');
  if (/<!DOCTYPE[^>]*\[|<!ENTITY/i.test(testString)) attacks.push('XXE');
  if (/\{\{.*\}\}|<%.*%>|\$\{.*\}/i.test(testString)) attacks.push('SSTI');
  if (/(file|php|data):\/\//i.test(testString)) attacks.push('LFI/SSRF');
  if (/\/\/[a-z0-9.-]+\.[a-z]{2,}|http:\/\/[0-9.]+/i.test(testString)) attacks.push('Open Redirect/SSRF');
  if (/\$\{jndi:/i.test(testString)) attacks.push('Log4Shell');
  
  return attacks;
}

// Middleware de logging pour TOUTES les requêtes (sauf internes)
app.use((req, res, next) => {
  if (isInternalRequest(req)) {
    return next();
  }
  
  // Extraire l'IP réelle
  const realIp = req.headers['x-real-ip'] || 
                 req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                 req.ip || 
                 req.connection.remoteAddress;
  const cleanIp = realIp ? realIp.replace(/^::ffff:/, '') : 'unknown';
  
  // Géolocalisation
  let geoData = null;
  if (cleanIp && cleanIp !== '127.0.0.1' && cleanIp !== 'localhost' && cleanIp !== 'unknown') {
    const geo = geoip.lookup(cleanIp);
    if (geo) {
      geoData = {
        country: geo.country,
        region: geo.region,
        city: geo.city
      };
    }
  }
  
  // Détection des attaques
  const detectedAttacks = detectAttackType(req);
  
  const logEntry = {
    id: Date.now() + '-' + Math.random().toString(36).substr(2, 9),
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.url,
    path: req.path,
    headers: req.headers,
    query: req.query,
    body: req.body,
    rawBody: req.rawBody,
    cookies: req.cookies,
    ip: cleanIp,
    geo: geoData,
    detectedAttacks: detectedAttacks,
    userAgent: req.headers['user-agent'] || null
  };
  
  // Stocker le log
  requestLogs.unshift(logEntry);
  if (requestLogs.length > 5000) requestLogs = requestLogs.slice(0, 5000);
  
  // Sauvegarder dans le fichier
  fs.appendFileSync(logsFile, JSON.stringify(logEntry) + '\n');
  
  // Broadcast via WebSocket
  broadcastLog(logEntry);
  
  // Mise à jour des stats
  stats.total++;
  stats.byMethod[req.method] = (stats.byMethod[req.method] || 0) + 1;
  stats.byIp[cleanIp] = (stats.byIp[cleanIp] || 0) + 1;
  
  const pathBase = req.path.split('?')[0];
  stats.byPath[pathBase] = (stats.byPath[pathBase] || 0) + 1;
  
  if (geoData && geoData.country) {
    stats.byCountry[geoData.country] = (stats.byCountry[geoData.country] || 0) + 1;
  }
  
  // Sauvegarder les stats
  fs.writeFileSync(statsFile, JSON.stringify(stats));
  
  next();
});

// Servir les fichiers statiques
app.use(express.static('public'));

// Routes des pages
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/logs', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logs.html')));
app.get('/stats', (req, res) => res.sendFile(path.join(__dirname, 'public', 'stats.html')));
app.get('/debug', (req, res) => res.sendFile(path.join(__dirname, 'public', 'debug.html')));

// API pour récupérer les logs
app.get('/api/logs', (req, res) => {
  const limit = parseInt(req.query.limit) || 500;
  const offset = parseInt(req.query.offset) || 0;
  res.json(requestLogs.slice(offset, offset + limit));
});

// API pour les statistiques
app.get('/api/stats', (req, res) => {
  res.json(stats);
});

// API pour effacer les logs
app.post('/api/clear-logs', (req, res) => {
  try {
    requestLogs = [];
    stats = { total: 0, byMethod: {}, byIp: {}, byCountry: {}, byPath: {} };
    fs.writeFileSync(logsFile, '');
    fs.writeFileSync(statsFile, JSON.stringify(stats));
    console.log('✅ Logs cleared successfully');
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Error clearing logs:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Route catch-all pour capturer TOUTES les autres requêtes
// C'est ici que les tests de waf.secmy.app arriveront
app.all('*', (req, res) => {
  // Répondre avec 200 OK pour indiquer que la requête est arrivée
  // Si le WAF bloque, cette réponse ne sera jamais envoyée
  res.status(200).json({
    received: true,
    timestamp: new Date().toISOString(),
    method: req.method,
    path: req.path,
    message: 'Request logged successfully'
  });
});

// Démarrage du serveur
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 WAF Debug Receiver started on port ${PORT}`);
  console.log(`📊 Dashboard: http://localhost:${PORT}`);
  console.log(`📋 Logs: http://localhost:${PORT}/logs`);
  console.log(`📈 Stats: http://localhost:${PORT}/stats`);
  console.log(`\n⏳ Waiting for requests from waf.secmy.app...`);
});
