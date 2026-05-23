import requests
import ssl
import socket
import json
from urllib.parse import urlparse
from datetime import datetime
import concurrent.futures

HEADERS_UA = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
}

TIMEOUT = 10

def run_full_scan(target_url):
    parsed = urlparse(target_url)
    hostname = parsed.netloc or parsed.path
    
    results = {
        'target': target_url,
        'hostname': hostname,
        'scan_time': datetime.utcnow().isoformat(),
        'vulnerabilities': {},
        'info': {},
        'risk_score': 'Low'
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(check_security_headers, target_url): 'security_headers',
            executor.submit(check_ssl_tls, hostname): 'ssl_tls',
            executor.submit(check_information_disclosure, target_url): 'info_disclosure',
            executor.submit(check_common_paths, target_url): 'exposed_paths',
            executor.submit(check_xss_basic, target_url): 'xss',
            executor.submit(check_cors, target_url): 'cors',
        }
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                results['vulnerabilities'][key] = future.result()
            except Exception as e:
                results['vulnerabilities'][key] = [{'error': str(e)}]

    # Compute risk score
    total_bugs = sum(len(v) for v in results['vulnerabilities'].values())
    high_count = sum(1 for v in results['vulnerabilities'].values() 
                     for item in v if item.get('severity') == 'HIGH')
    
    if high_count >= 3 or total_bugs >= 10:
        results['risk_score'] = 'CRITICAL'
    elif high_count >= 1 or total_bugs >= 6:
        results['risk_score'] = 'HIGH'
    elif total_bugs >= 3:
        results['risk_score'] = 'MEDIUM'
    elif total_bugs >= 1:
        results['risk_score'] = 'LOW'
    else:
        results['risk_score'] = 'SAFE'

    return results


def check_security_headers(url):
    bugs = []
    try:
        r = requests.get(url, headers=HEADERS_UA, timeout=TIMEOUT, verify=False, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}

        checks = [
            ('content-security-policy', 'Content-Security-Policy missing — XSS attacks possible', 'HIGH'),
            ('x-frame-options', 'X-Frame-Options missing — Clickjacking possible', 'MEDIUM'),
            ('x-content-type-options', 'X-Content-Type-Options missing — MIME sniffing possible', 'LOW'),
            ('strict-transport-security', 'HSTS missing — SSL downgrade attacks possible', 'HIGH'),
            ('referrer-policy', 'Referrer-Policy missing — Sensitive URL leakage', 'LOW'),
            ('permissions-policy', 'Permissions-Policy missing — Camera/Mic abuse possible', 'MEDIUM'),
        ]

        for header, desc, severity in checks:
            if header not in headers:
                bugs.append({
                    'title': f'Missing: {header.title()}',
                    'description': desc,
                    'severity': severity,
                    'fix': f'Add header: {header.title()}'
                })

        # Check server header disclosure
        if 'server' in headers:
            bugs.append({
                'title': 'Server Version Disclosed',
                'description': f'Server header reveals: {headers["server"]}',
                'severity': 'LOW',
                'fix': 'Remove or obfuscate the Server header'
            })
        if 'x-powered-by' in headers:
            bugs.append({
                'title': 'Technology Disclosed (X-Powered-By)',
                'description': f'X-Powered-By: {headers["x-powered-by"]}',
                'severity': 'LOW',
                'fix': 'Remove X-Powered-By header from server config'
            })
    except requests.exceptions.SSLError:
        bugs.append({'title': 'SSL Certificate Error', 'description': 'SSL verification failed', 'severity': 'HIGH', 'fix': 'Fix SSL certificate'})
    except Exception as e:
        bugs.append({'title': 'Scan Error', 'description': str(e), 'severity': 'INFO', 'fix': 'Manual check required'})
    return bugs


def check_ssl_tls(hostname):
    bugs = []
    try:
        # Strip port if present
        host = hostname.split(':')[0]
        port = int(hostname.split(':')[1]) if ':' in hostname else 443
        
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                
                # Check cert expiry
                expire_str = cert.get('notAfter', '')
                if expire_str:
                    try:
                        expire_date = datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expire_date - datetime.utcnow()).days
                        if days_left < 30:
                            bugs.append({
                                'title': 'SSL Certificate Expiring Soon',
                                'description': f'Certificate expires in {days_left} days ({expire_str})',
                                'severity': 'HIGH' if days_left < 7 else 'MEDIUM',
                                'fix': 'Renew SSL certificate immediately'
                            })
                    except:
                        pass
                
                if protocol in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                    bugs.append({
                        'title': f'Outdated Protocol: {protocol}',
                        'description': f'Server uses deprecated {protocol}',
                        'severity': 'HIGH',
                        'fix': 'Upgrade to TLS 1.2 or TLS 1.3'
                    })
    except ssl.SSLCertVerificationError:
        bugs.append({'title': 'Invalid SSL Certificate', 'description': 'Certificate validation failed — possible MITM', 'severity': 'HIGH', 'fix': 'Install valid SSL certificate'})
    except ConnectionRefusedError:
        bugs.append({'title': 'HTTPS Not Available', 'description': 'Port 443 refused', 'severity': 'HIGH', 'fix': 'Enable HTTPS on the server'})
    except Exception as e:
        pass  # Host might just block SSL probing
    return bugs


def check_information_disclosure(url):
    bugs = []
    sensitive_paths = [
        '/.env', '/.git/config', '/config.php', '/wp-config.php',
        '/phpinfo.php', '/.htaccess', '/web.config', '/config.json',
        '/package.json', '/composer.json', '/Dockerfile', '/docker-compose.yml',
        '/backup.sql', '/dump.sql', '/database.sql', '/db.sql',
        '/admin', '/administrator', '/phpmyadmin', '/adminer.php',
        '/api/swagger', '/api/docs', '/swagger.json', '/openapi.json',
        '/graphql', '/graphiql', '/__debug__', '/debug',
        '/server-status', '/server-info', '/.DS_Store',
    ]
    
    base = url.rstrip('/')
    for path in sensitive_paths:
        try:
            r = requests.get(base + path, headers=HEADERS_UA, timeout=5, verify=False, allow_redirects=False)
            if r.status_code in [200, 301, 302] and r.status_code != 404:
                severity = 'HIGH' if path in ['/.env', '/.git/config', '/phpinfo.php', '/graphiql'] else 'MEDIUM'
                bugs.append({
                    'title': f'Exposed Path: {path}',
                    'description': f'"{base+path}" returned HTTP {r.status_code}',
                    'severity': severity,
                    'fix': f'Block access to {path} via server config or remove the file'
                })
        except:
            continue
    return bugs


def check_common_paths(url):
    bugs = []
    base = url.rstrip('/')
    checks = [
        ('/robots.txt', 'Robots.txt exposed — may reveal hidden paths'),
        ('/sitemap.xml', 'Sitemap exposed — full site structure visible'),
        ('/crossdomain.xml', 'Crossdomain.xml found — check for wildcards'),
        ('/clientaccesspolicy.xml', 'Client access policy file exposed'),
    ]
    for path, desc in checks:
        try:
            r = requests.get(base + path, headers=HEADERS_UA, timeout=5, verify=False)
            if r.status_code == 200 and len(r.text) > 10:
                # Check robots.txt for sensitive paths
                extra = ''
                if path == '/robots.txt':
                    disallowed = [line for line in r.text.splitlines() if 'Disallow' in line]
                    if disallowed:
                        extra = f' Hidden paths: {", ".join(disallowed[:3])}'
                bugs.append({
                    'title': f'Info File Found: {path}',
                    'description': desc + extra,
                    'severity': 'LOW',
                    'fix': 'Review and restrict if sensitive paths are exposed'
                })
        except:
            continue
    return bugs


def check_xss_basic(url):
    bugs = []
    # Only test if there are query parameters
    test_payload = '<script>alert(1)</script>'
    parsed = urlparse(url)
    if parsed.query:
        params = dict(p.split('=') for p in parsed.query.split('&') if '=' in p)
        for param in list(params.keys())[:3]:
            test_params = {**params, param: test_payload}
            test_url = url.split('?')[0] + '?' + '&'.join(f'{k}={v}' for k, v in test_params.items())
            try:
                r = requests.get(test_url, headers=HEADERS_UA, timeout=TIMEOUT, verify=False)
                if test_payload in r.text:
                    bugs.append({
                        'title': f'Reflected XSS in param: {param}',
                        'description': f'XSS payload reflected unescaped in parameter "{param}"',
                        'severity': 'HIGH',
                        'fix': f'Sanitize and escape parameter "{param}" output using htmlspecialchars()'
                    })
            except:
                continue
    return bugs


def check_cors(url):
    bugs = []
    try:
        headers = {**HEADERS_UA, 'Origin': 'https://evil-attacker.com'}
        r = requests.get(url, headers=headers, timeout=TIMEOUT, verify=False)
        acao = r.headers.get('Access-Control-Allow-Origin', '')
        acac = r.headers.get('Access-Control-Allow-Credentials', '')
        
        if acao == '*':
            bugs.append({
                'title': 'CORS: Wildcard Origin Allowed',
                'description': 'Access-Control-Allow-Origin: * allows any site to read responses',
                'severity': 'MEDIUM',
                'fix': 'Specify exact allowed origins instead of wildcard (*)'
            })
        elif acao == 'https://evil-attacker.com':
            bugs.append({
                'title': 'CORS: Arbitrary Origin Reflected',
                'description': 'Server reflects any Origin header — CORS misconfiguration',
                'severity': 'HIGH',
                'fix': 'Whitelist only trusted origins in CORS config'
            })
        if acac.lower() == 'true' and acao in ['*', 'https://evil-attacker.com']:
            bugs.append({
                'title': 'CORS: Credentials Allowed with Weak Origin Policy',
                'description': 'Credentials + weak CORS = authenticated data theft possible',
                'severity': 'HIGH',
                'fix': 'Never combine credentials=true with wildcard or reflected origins'
            })
    except:
        pass
    return bugs
