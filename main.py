#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ssl
import time
import json
import sys
import re
import os
import asyncio
import random
import base64
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

import aiohttp
import requests
from bs4 import BeautifulSoup
import dns.resolver
import dns.zone
import dns.query
import whois
from ipwhois import IPWhois
import tldextract
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# YASAL UYARI ve CAYDIRICILIK
# ============================================================
LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                              YASAL UYARI                                      ║
║  Bu araç YALNIZCA sahibi olduğunuz veya test yetkisi aldığınız sistemlerde  ║
║  kullanılmalıdır. İzinsiz kullanım YASA DIŞIDIR ve cezai yaptırımlara        ║
║  tabidir. Bu aracı kullanarak tüm sorumluluğu kabul etmiş olursunuz.         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

TOOL_NAME = "BER211 Scanner"
VERSION = "1.1.0-secure"
DEVELOPER = "ESRAR-I-GOZLER"
CONTACT = "discord.gg/keless"
TIMEOUT = 8
USER_AGENT = "BER211-Scanner/4.0"
MAX_RATE_TEST_REQUESTS = 100

FAST_PORTS = [80, 443, 22, 21, 8080, 8443]
FULL_PORTS = [
    80, 443, 8080, 8000, 8443, 8888, 21, 22, 23,
    25, 110, 143, 465, 587, 993, 995, 53, 135, 139, 445,
    1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    2181, 2483, 2484, 3000, 3001, 3306, 5432, 6379, 6380,
    7001, 7002, 7474, 7687, 8008, 8010, 8020, 8081, 8082,
    8088, 8090, 8091, 8181, 8880, 8888, 9000, 9001, 9042,
    9060, 9080, 9090, 9091, 2375, 2376, 2379, 2380, 5000,
    5001, 5601, 5985, 5986, 6666, 6667, 7000, 7003, 7443,
    27017, 27018, 27019
]

THREADS = 30  # Düşürüldü, ağ yükünü azaltır
ENDPOINT_TEST_LIMIT = 50  # Sadece parametreli endpointler için max 50
SUBDOMAIN_WORDS = [
    "www", "mail", "webmail", "smtp", "ftp", "api", "dev", "test", "stage",
    "staging", "beta", "admin", "panel", "login", "app", "cdn", "static",
    "assets", "blog", "shop", "support", "portal", "vpn", "m", "mobile",
    "remote", "secure", "auth", "server", "ns1", "ns2", "dns", "mysql",
    "db", "oracle", "ldap", "jira", "confluence", "gitlab", "jenkins",
    "kibana", "grafana", "prometheus", "elastic", "kafka", "queue"
]

ADMIN_PATHS = [
    "/admin", "/administrator", "/admin/login", "/login", "/dashboard",
    "/panel", "/cpanel", "/wp-admin", "/wp-login.php", "/user/login",
    "/account/login", "/manager", "/backend", "/cms", "/controlpanel",
    "/admin.php", "/index.php/admin", "/admin/index.php", "/login.php",
    "/signin", "/signin.php", "/admin/login.php", "/admin.aspx",
    "/admin.html", "/admin1", "/admin2", "/moderator", "/adminpanel",
    "/clientaccesspolicy.xml", "/crossdomain.xml"
]

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.env", "/.env.bak", "/.env.old", "/.env.dev",
    "/.env.local", "/.env.production", "/.env.stage", "/.env.staging",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/phpinfo.php", "/info.php", "/test.php", "/php_info.php",
    "/.DS_Store", "/.vscode/", "/.idea/", "/.svn/entries",
    "/config.php.bak", "/config.php.old", "/config.php~",
    "/backup.sql", "/backup.sql.gz", "/dump.sql", "/dump.sql.gz",
    "/database.sql", "/database.sql.gz", "/db.sql", "/db.sql.gz",
    "/admin.sql", "/backup.zip", "/backup.tar", "/backup.tar.gz",
    "/web.config", "/web.config.bak", "/app.config", "/application.properties",
    "/log/access.log", "/log/error.log", "/logs/access.log",
    "/server-status", "/server-info", "/status", "/actuator",
    "/actuator/health", "/actuator/info", "/actuator/env",
    "/actuator/metrics", "/actuator/mappings", "/actuator/beans",
    "/actuator/configprops", "/heapdump", "/threaddump",
    "/console", "/jmx-console", "/web-console", "/admin-console",
    "/jmx-console/HtmlAdaptor", "/invoker/JMXInvokerServlet",
    "/druid/index.html", "/druid/websession.html",
    "/druid/datasource.html", "/druid/sql.html",
    "/swagger-ui.html", "/swagger-ui/index.html",
    "/api/swagger-ui.html", "/api/swagger-ui/index.html"
]

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".pdf", ".zip", ".rar", ".7z", ".mp4", ".mp3", ".woff", ".woff2",
    ".ttf", ".eot", ".webp", ".map", ".bmp", ".tiff", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx"
)

PORT_INFO = {
    21: ("FTP", "Anonymous login veya zayıf kimlik doğrulama riski.", "Medium"),
    22: ("SSH", "Key‑based auth ve rate‑limit önerilir.", "Medium"),
    23: ("Telnet", "Üretim ortamında kritik risk.", "High"),
    25: ("SMTP", "Open relay ve SPF/DKIM/DMARC kontrolü.", "Medium"),
    53: ("DNS", "Zone transfer ve recursive resolver kontrolü.", "Medium"),
    80: ("HTTP", "HTTPS yönlendirmesi ve header kontrolü.", "Low"),
    110: ("POP3", "Şifresiz kullanım riski.", "Medium"),
    143: ("IMAP", "Şifresiz kullanım riski.", "Medium"),
    443: ("HTTPS", "TLS ve header kontrolleri yapılmalı.", "Low"),
    445: ("SMB", "İnternete açık olması yüksek risk.", "High"),
    465: ("SMTPS", "Sertifika ve auth politikası.", "Low"),
    587: ("SMTP Submission", "Rate‑limit ve auth politikası.", "Medium"),
    993: ("IMAPS", "Sertifika ve auth politikası.", "Low"),
    995: ("POP3S", "Sertifika ve auth politikası.", "Low"),
    1433: ("MSSQL", "İnternete açık olması yüksek risk.", "High"),
    3306: ("MySQL", "İnternete açık olması yüksek risk.", "High"),
    5432: ("PostgreSQL", "İnternete açık olması yüksek risk.", "High"),
    6379: ("Redis", "İnternete açıksa kritik risk.", "Critical"),
    2375: ("Docker API", "Şifresiz Docker API – kritik.", "Critical"),
    2376: ("Docker API TLS", "Yetkilendirme kontrol edilmeli.", "High"),
    27017: ("MongoDB", "İnternete açıksa kritik risk.", "Critical"),
    5601: ("Kibana", "Hassas veri riski.", "Medium"),
    8080: ("HTTP Alt", "Admin panel veya debug servisi.", "Medium"),
    8443: ("HTTPS Alt", "Admin panel veya servis arayüzü.", "Medium"),
    9090: ("Admin/Monitoring", "Yetkilendirme kontrolü.", "Medium"),
    2082: ("cPanel", "Yetkisiz erişim riski", "Medium"),
    2083: ("cPanel SSL", "Sertifika kontrolü", "Low"),
    2086: ("WHM", "Root erişim riski", "High"),
    2087: ("WHM SSL", "Yüksek yetkili", "High"),
    5000: ("Flask / Docker Registry", "Açık registry riski", "Medium"),
    5001: ("Flask HTTPS", "", "Low"),
    5900: ("VNC", "Şifresiz VNC kritik", "Critical"),
    11211: ("Memcached", "DDoS reflektor riski", "Medium"),
}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
]

SQLI_ERROR_PATTERNS = [
    "sql syntax", "mysql", "mariadb", "postgresql", "sqlite",
    "ora-", "odbc", "syntax error", "unclosed quotation",
    "you have an error in your sql", "warning: mysql",
    "microsoft ole db provider for odbc drivers",
    "microsoft ole db provider for sql server",
    "error in your sql syntax", "invalid query",
    "unexpected end of sql command",
    "postgresql query failed", "sqlite3::",
    "mssql_", "pdoexception", "mysqli_",
    "pg_query", "mssql_query",
]

SAFE_XSS_PAYLOAD = "ber211xssprobe"
SAFE_SQLI_PAYLOAD = "'ber211"
SAFE_TRAVERSAL_PAYLOAD = "ber211_traversal_probe"
SAFE_SSTI_PAYLOAD = "{{7*7}}"

COMMON_DIRS = [
    ".git/", ".svn/", ".hg/", ".bzr/", ".DS_Store",
    "CVS/", "WEB-INF/", "META-INF/", "node_modules/",
    "vendor/", "composer.json", "package.json",
    "bower.json", "Gemfile", "Gemfile.lock", "Pipfile",
    "Pipfile.lock", "requirements.txt", "yarn.lock",
    "package-lock.json", "Cargo.toml", "Cargo.lock",
    "go.mod", "go.sum", "Dockerfile", "docker-compose.yml",
    ".dockerignore", ".gitignore", ".npmrc", ".yarnrc",
    ".babelrc", ".eslintrc", ".prettierrc", ".stylelintrc",
    "tsconfig.json", "webpack.config.js", "rollup.config.js",
    "gulpfile.js", "Gruntfile.js", "Makefile", "Rakefile",
    "build.gradle", "pom.xml", "settings.gradle",
    "gradle.properties", "mvnw", "gradlew",
]

C_RESET = "\033[0m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_BLUE = "\033[94m"
C_CYAN = "\033[96m"
C_MAGENTA = "\033[95m"
C_WHITE = "\033[97m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RED_BOLD = "\033[91;1m"

def rgb(r, g, b):
    return f"\033[38;2;{r};{g};{b}m"

RESET = "\033[0m"
BOLD = "\033[1m"

def clear():
    print("\033c", end="")

def banner():
    print(rgb(0, 255, 255) + BOLD + r"""
╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║  .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .----------------.    ║
║| .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |    ║
║| |   ______     | || |  _________   | || |  _______     | || |    _____     | || |     __       | || |     __       | |    ║
║| |  |_   _ \    | || | |_   ___  |  | || | |_   __ \    | || |   / ___ `.   | || |    /  |      | || |    /  |      | |    ║
║| |    | |_) |   | || |   | |_  \_|  | || |   | |__) |   | || |  |_/___) |   | || |    `| |      | || |    `| |      | |    ║
║| |    |  __'.   | || |   |  _|  _   | || |   |  __ /    | || |   .'____.'   | || |     | |      | || |     | |      | |    ║
║| |   _| |__) |  | || |  _| |___/ |  | || |  _| |  \ \_  | || |  / /____     | || |    _| |_     | || |    _| |_     | |    ║
║| |  |_______/   | || | |_________|  | || | |____| |___| | || |  |_______|   | || |   |_____|    | || |   |_____|    | |    ║
║| |              | || |              | || |              | || |              | || |              | || |              | |    ║
║ '--------------'  '--------------'  '--------------'  '--------------'  '--------------'  '--------------'            ║
╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
""" + RESET)
    print(C_RED_BOLD + LEGAL_WARNING + C_RESET)
    print()

def log_ok(text):
    print(f"{C_GREEN}[OK]{C_RESET} {text}")

def log_info(text):
    print(f"{C_CYAN}[+]{C_RESET} {text}")

def log_warn(text):
    print(f"{C_YELLOW}[!]{C_RESET} {text}")

def log_fail(text):
    print(f"{C_RED}[-]{C_RESET} {text}")

def log_crit(text):
    print(f"{C_MAGENTA}[CRIT]{C_RESET} {text}")

def add_finding(findings, category, severity, title, evidence, safe=True):
    findings["vulnerabilities"].append({
        "category": category,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "safe": safe
    })

def safe_filename(value):
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", value)

def normalize_url(raw_url):
    raw_url = raw_url.strip()
    if not raw_url:
        return None
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if not parsed.netloc:
        return None
    return raw_url.rstrip("/")

def get_domain(url):
    return urlparse(url).hostname

def check_root_for_low_ports(ports):
    """1024 altı portlar için root kontrolü (caydırıcı & az izinli)"""
    low_ports = [p for p in ports if p < 1024]
    if low_ports and os.geteuid() != 0:
        log_warn(f"Düşük numaralı portlar ({low_ports[:5]}...) taranacak ancak root yetkisi yok. Bu portlar taranamayabilir.")
        log_info("Öneri: sudo ile çalıştırın veya düşük portları tarama listesinden çıkarın.")
        return False
    return True

def safe_request_sync(url, method="GET", params=None, data=None, headers=None, cookies=None):
    final_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        final_headers.update(headers)
    try:
        response = requests.request(
            method=method, url=url, params=params, data=data,
            headers=final_headers, cookies=cookies,
            timeout=TIMEOUT, allow_redirects=True, verify=False,
        )
        return response
    except Exception:
        return None

def build_url_with_param(url, param_name, payload):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if qs:
        first_key = list(qs.keys())[0]
        qs[first_key] = payload
    else:
        qs[param_name] = payload
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))

class RateLimiter:
    def __init__(self, max_per_second=10):
        self.max_per_second = max_per_second
        self.last_request = 0
    async def wait(self):
        now = time.time()
        diff = now - self.last_request
        if diff < 1.0 / self.max_per_second:
            await asyncio.sleep(1.0 / self.max_per_second - diff)
        self.last_request = time.time()

rate_limiter = RateLimiter(max_per_second=10)

async def async_fetch(session, url, method='GET', headers=None, data=None, json_data=None, cookies=None, timeout=TIMEOUT):
    await rate_limiter.wait()
    try:
        if method == 'GET':
            async with session.get(url, headers=headers, cookies=cookies, timeout=timeout, ssl=False) as resp:
                text = await resp.text()
                return resp.status, dict(resp.headers), text, resp.cookies
        elif method == 'POST':
            async with session.post(url, headers=headers, data=data, json=json_data, cookies=cookies, timeout=timeout, ssl=False) as resp:
                text = await resp.text()
                return resp.status, dict(resp.headers), text, resp.cookies
        elif method == 'PUT':
            async with session.put(url, headers=headers, data=data, json=json_data, cookies=cookies, timeout=timeout, ssl=False) as resp:
                text = await resp.text()
                return resp.status, dict(resp.headers), text, resp.cookies
    except Exception:
        return None, None, None, None

async def async_scan_port(ip, port, timeout=2.0):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None

async def async_port_scan(ip, ports, max_con=100):
    semaphore = asyncio.Semaphore(max_con)
    async def limited_scan(port):
        async with semaphore:
            return await async_scan_port(ip, port)
    tasks = [limited_scan(p) for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted([p for p in results if p is not None])

def scan_single_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
    except Exception:
        return None
    return None

def port_scan(ip, findings, ports):
    log_info(f"Port taraması başlatıldı... ({len(ports)} port) [async]")
    check_root_for_low_ports(ports)
    try:
        open_ports = asyncio.run(async_port_scan(ip, ports))
    except Exception as e:
        log_fail(f"Asenkron port tarama hatası: {e}, senkron deneniyor...")
        open_ports = []
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = [executor.submit(scan_single_port, ip, port) for port in ports]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)
        open_ports = sorted(open_ports)
    findings["recon"]["open_ports"] = open_ports
    for port in open_ports:
        log_warn(f"Açık port bulundu: {port}")
    if not open_ports:
        log_ok("Seçilen port listesinde açık servis bulunamadı.")
    return open_ports

def resolve_dns(domain, findings):
    log_info(f"DNS çözümleme yapılıyor: {domain}")
    try:
        ip = socket.gethostbyname(domain)
        log_ok(f"IP bulundu: {ip}")
        findings["recon"]["ip"] = ip
        return ip
    except Exception as e:
        log_fail(f"DNS çözümleme başarısız: {e}")
        findings["errors"].append(f"DNS çözümleme başarısız: {e}")
        return None

def try_axfr(domain, findings):
    log_info("DNS Zone Transfer (AXFR) deneniyor...")
    findings["recon"]["axfr_records"] = []
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        for rdata in answers:
            ns = str(rdata).rstrip('.')
            log_info(f"NS sunucu: {ns}, AXFR deneniyor...")
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
                for name, node in z.nodes.items():
                    for rdataset in node.rdatasets:
                        findings["recon"]["axfr_records"].append({
                            "name": str(name),
                            "type": dns.rdatatype.to_text(rdataset.rdtype),
                            "data": str(rdataset)
                        })
                        log_warn(f"AXFR kaydı: {name} {rdataset}")
                log_ok("AXFR başarılı, kayıtlar toplandı.")
                return
            except Exception:
                continue
        log_ok("AXFR başarısız (zone transfer engellenmiş).")
    except Exception as e:
        log_fail(f"AXFR denemesi yapılamadı: {e}")

def deep_tls_check(domain, findings):
    log_info("Derin TLS analizi başlatılıyor...")
    weak_ciphers = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    weak_indicators = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5']
    try:
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher = ssock.cipher()
                findings["tls"]["cipher"] = cipher[0]
                if any(w in cipher[0] for w in weak_indicators):
                    weak_ciphers.append(cipher[0])
                    log_warn(f"Zayıf şifre kullanılıyor: {cipher[0]}")
                    add_finding(findings, "SSL/TLS", "Medium", "Weak cipher suite detected", f"Cipher: {cipher[0]}")
                else:
                    log_ok(f"TLS cipher: {cipher[0]}")
    except Exception as e:
        log_warn(f"TLS cipher analizi başarısız: {e}")

def subdomain_bruteforce(domain, findings, wordlist_file=None):
    log_info("Subdomain brute‑force başlatıldı...")
    found = []
    if wordlist_file and os.path.exists(wordlist_file):
        with open(wordlist_file, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
    else:
        words = SUBDOMAIN_WORDS
    for word in words:
        sub = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(sub)
            found.append({"subdomain": sub, "ip": ip})
            log_warn(f"Subdomain: {sub} -> {ip}")
        except Exception:
            continue
    findings["recon"]["bruteforce_subdomains"] = found
    return found

def dns_records_enum(domain, findings):
    log_info("DNS kayıtları toplanıyor...")
    records = {}
    types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    for t in types:
        try:
            answers = dns.resolver.resolve(domain, t)
            records[t] = [str(r) for r in answers]
        except Exception:
            records[t] = []
    findings["recon"]["dns_records"] = records
    spf = [r for r in records.get('TXT', []) if r.startswith('v=spf1')]
    dmarc = [r for r in records.get('TXT', []) if r.startswith('v=DMARC1')]
    findings["recon"]["spf"] = spf
    findings["recon"]["dmarc"] = dmarc
    if not spf:
        log_warn("SPF kaydı yok.")
    if not dmarc:
        log_warn("DMARC kaydı yok.")
    return records

def whois_lookup(domain, findings):
    log_info("WHOIS sorgulanıyor...")
    try:
        w = whois.whois(domain)
        findings["recon"]["whois"] = {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers
        }
        log_ok("WHOIS bilgisi alındı.")
    except Exception as e:
        log_fail(f"WHOIS başarısız: {e}")

def asn_info(ip, findings):
    log_info("ASN sorgulanıyor...")
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        findings["recon"]["asn"] = {
            "asn": res['asn'],
            "asn_cidr": res['asn_cidr'],
            "asn_description": res['asn_description']
        }
        log_ok(f"ASN: {res['asn']} - {res['asn_description']}")
    except Exception as e:
        log_fail(f"ASN sorgulanamadı: {e}")

def banner_grabbing(ip, port, findings):
    log_info(f"Banner grabbing: {ip}:{port}")
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        s.send(b"\n")
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        if banner:
            log_warn(f"Banner ({port}): {banner[:100]}")
            findings["recon"].setdefault("banners", []).append({"port": port, "banner": banner})
    except Exception:
        pass

def s3_bucket_check(domain, findings):
    log_info("AWS S3 bucket denetimi yapılıyor...")
    extracted = tldextract.extract(domain)
    bucket_names = [
        domain,
        extracted.domain,
        f"www.{domain}",
        f"assets.{domain}",
        f"static.{domain}"
    ]
    for bucket in bucket_names[:5]:
        url = f"http://{bucket}.s3.amazonaws.com"
        resp = safe_request_sync(url)
        if resp and resp.status_code == 200:
            log_warn(f"Açık S3 bucket: {url}")
            add_finding(findings, "S3 Bucket", "High", "Public S3 bucket found", url)

def discover_endpoints(target, response, findings):
    log_info("Endpoint keşfi başlatıldı...")
    endpoints = set()
    parsed_target = urlparse(target)
    base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
    if response is not None:
        soup = BeautifulSoup(response.text, "html.parser")
        for tag in soup.find_all(["a", "form", "script", "link"]):
            href = tag.get("href") or tag.get("src") or tag.get("action")
            if not href:
                continue
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            if parsed.netloc == parsed_target.netloc:
                endpoints.add(parsed.path or "/")
    robots_url = urljoin(base_url, "/robots.txt")
    robots_resp = safe_request_sync(robots_url)
    if robots_resp and robots_resp.status_code == 200:
        for line in robots_resp.text.splitlines():
            line = line.strip()
            if line.lower().startswith(("allow:", "disallow:")):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    endpoints.add(path)
    sitemap_url = urljoin(base_url, "/sitemap.xml")
    sitemap_resp = safe_request_sync(sitemap_url)
    if sitemap_resp and sitemap_resp.status_code == 200:
        urls = re.findall(r"<loc>(.*?)</loc>", sitemap_resp.text, re.IGNORECASE)
        for item in urls:
            parsed = urlparse(item.strip())
            if parsed.netloc == parsed_target.netloc:
                endpoints.add(parsed.path or "/")
    endpoints = sorted(endpoints)
    findings["recon"]["endpoints"] = endpoints
    if endpoints:
        for endpoint in endpoints[:1000]:
            log_warn(f"Endpoint bulundu: {endpoint}")
        if len(endpoints) > 1000:
            log_info(f"Toplam {len(endpoints)} endpoint bulundu. İlk 1000 gösterildi.")
    else:
        log_ok("Endpoint bulunamadı.")
    return endpoints

def discover_subdomains(domain, findings):
    log_info("Subdomain keşfi başlatıldı...")
    found = []
    for word in SUBDOMAIN_WORDS:
        subdomain = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            found.append({"subdomain": subdomain, "ip": ip})
            log_warn(f"Subdomain bulundu: {subdomain} -> {ip}")
        except Exception:
            continue
    findings["recon"]["subdomains"] = found
    if not found:
        log_ok("Yaygın subdomain listesinde kayıt bulunamadı.")
    return found

def detect_waf_cdn(response, findings):
    log_info("WAF/CDN tespiti yapılıyor...")
    if response is None:
        log_fail("WAF/CDN tespiti için response yok.")
        return []
    headers_blob = "\n".join([f"{k}: {v}" for k, v in response.headers.items()]).lower()
    detected = []
    signatures = {
        "Cloudflare": ["cloudflare", "cf-ray", "cf-cache-status"],
        "Akamai": ["akamai", "akamai-ghost", "akamai-cache"],
        "Sucuri": ["sucuri", "x-sucuri"],
        "Fastly": ["fastly", "x-served-by", "x-cache"],
        "AWS CloudFront": ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"],
        "Vercel": ["vercel", "x-vercel"],
        "Netlify": ["netlify", "x-nf-request-id"],
    }
    for name, keys in signatures.items():
        if any(key in headers_blob for key in keys):
            detected.append(name)
    detected = sorted(set(detected))
    findings["waf_cdn"] = detected
    if detected:
        for item in detected:
            log_warn(f"WAF/CDN tespit edildi: {item}")
    else:
        log_ok("Belirgin WAF/CDN imzası görülmedi.")
    return detected

def detect_technologies(response, findings):
    log_info("Teknoloji tespiti yapılıyor...")
    technologies = set()
    if response is None:
        log_fail("Teknoloji tespiti için response yok.")
        findings["technologies"] = []
        return []
    headers = response.headers
    body = response.text.lower()
    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    if server:
        technologies.add(f"Server: {server}")
    if powered:
        technologies.add(f"X-Powered-By: {powered}")
    checks = {
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "Laravel": ["laravel", "csrf-token"],
        "React": ["react", "__react", "reactroot"],
        "Vue": ["vue", "__vue__"],
        "Next.js": ["_next/static", "next-data"],
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap"],
        "PHP": ["php", "phpsessid"],
        "Cloudflare": ["cloudflare"],
        "Java": [".jsp", "jsessionid"],
        "ASP.NET": ["__viewstate", "asp.net"],
        "Ruby on Rails": ["rails", "csrf-param"],
        "Django": ["django", "csrftoken"],
        "Flask": ["flask"],
        "Express": ["x-powered-by: express"],
    }
    for tech, patterns in checks.items():
        if any(pattern in body for pattern in patterns):
            technologies.add(tech)
    technologies = sorted(technologies)
    findings["technologies"] = technologies
    if technologies:
        for tech in technologies:
            log_warn(f"Teknoloji: {tech}")
    else:
        log_ok("Belirgin teknoloji izi bulunamadı.")
    return technologies

def admin_panel_scan(target, findings):
    log_info("Admin panel keşfi yapılıyor...")
    parsed = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    found = []
    for path in ADMIN_PATHS:
        test_url = urljoin(base_url, path)
        response = safe_request_sync(test_url)
        if response is None:
            continue
        if response.status_code in [200, 301, 302, 401, 403]:
            item = {"url": test_url, "status_code": response.status_code}
            found.append(item)
            log_warn(f"Admin/login panel olabilir: {test_url} ({response.status_code})")
    findings["recon"]["admin_panels"] = found
    if not found:
        log_ok("Yaygın admin panel yollarında bulgu yok.")
    return found

def scan_sensitive_files(target, findings):
    log_info("Hassas dosya/dizin taraması başlatıldı...")
    parsed = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    for path in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        resp = safe_request_sync(url)
        if resp is None:
            continue
        if resp.status_code == 200:
            log_warn(f"Hassas dosya bulundu: {url} (200)")
            add_finding(findings, "Sensitive File Exposure", "High", f"Accessible sensitive path: {path}", f"URL: {url} returned 200")

def is_parametrized_endpoint(endpoint):
    return '?' in endpoint or re.search(r'/\d+', endpoint)

def should_test_endpoint(endpoint):
    endpoint_lower = endpoint.lower().split("?", 1)[0]
    return not endpoint_lower.endswith(STATIC_EXTENSIONS) and is_parametrized_endpoint(endpoint)

def add_port_intelligence(findings):
    log_info("Port intelligence analizi yapılıyor...")
    open_ports = findings.get("recon", {}).get("open_ports", [])
    intelligence = []
    for port in open_ports:
        if port in PORT_INFO:
            service, note, severity = PORT_INFO[port]
            item = {"port": port, "service": service, "note": note, "severity": severity}
            intelligence.append(item)
            log_warn(f"{port}/{service}: {note}")
            if severity in ["High", "Critical"]:
                add_finding(findings, "Open Port", severity, f"Risky exposed service: {service} ({port})", note)
    findings["recon"]["port_intelligence"] = intelligence
    if not intelligence:
        log_ok("Açık portlar için özel risk yorumu bulunamadı.")
    return intelligence

def analyze_headers(response, findings):
    log_info("HTTP header analizi yapılıyor...")
    if response is None:
        log_fail("HTTP response alınamadı.")
        return
    headers = response.headers
    missing = []
    for header in SECURITY_HEADERS:
        if header not in headers:
            missing.append(header)
    if missing:
        for header in missing:
            log_warn(f"Eksik güvenlik header'ı: {header}")
            add_finding(findings, "Headers", "Medium", f"Missing security header: {header}", f"{header} header bulunamadı.")
    else:
        log_ok("Temel güvenlik header'ları mevcut.")
    server = headers.get("Server")
    powered = headers.get("X-Powered-By")
    if server:
        log_warn(f"Server bilgisi sızıyor: {server}")
        findings["info"].append(f"Server header: {server}")
    if powered:
        log_warn(f"X-Powered-By bilgisi sızıyor: {powered}")
        findings["info"].append(f"X-Powered-By: {powered}")

def analyze_cookies(response, findings):
    log_info("Cookie güvenliği kontrol ediliyor...")
    if response is None:
        log_fail("Cookie analizi için response yok.")
        return
    cookies = response.cookies
    if not cookies:
        log_ok("Cookie bulunamadı.")
        return
    raw_set_cookie = response.headers.get("Set-Cookie", "")
    for cookie in cookies:
        cname = cookie.name
        if "httponly" not in raw_set_cookie.lower():
            log_warn(f"Cookie HttpOnly eksik olabilir: {cname}")
            add_finding(findings, "Cookie", "Medium", f"Cookie HttpOnly flag missing: {cname}", "Set-Cookie içinde HttpOnly görülmedi.")
        if "secure" not in raw_set_cookie.lower():
            log_warn(f"Cookie Secure eksik olabilir: {cname}")
            add_finding(findings, "Cookie", "Medium", f"Cookie Secure flag missing: {cname}", "Set-Cookie içinde Secure görülmedi.")
        if "samesite" not in raw_set_cookie.lower():
            log_warn(f"Cookie SameSite eksik olabilir: {cname}")
            add_finding(findings, "Cookie", "Low", f"Cookie SameSite flag missing: {cname}", "Set-Cookie içinde SameSite görülmedi.")

def check_tls(domain, findings):
    log_info("TLS/SSL kontrolü yapılıyor...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                log_ok(f"TLS versiyonu: {tls_version}")
                findings["tls"]["version"] = tls_version
                if cert:
                    not_after = cert.get("notAfter")
                    subject = cert.get("subject", [])
                    findings["tls"]["expires"] = not_after
                    findings["tls"]["subject"] = str(subject)
                    log_ok(f"Sertifika bitiş tarihi: {not_after}")
    except Exception as e:
        log_warn(f"TLS kontrolü yapılamadı: {e}")
        findings["tls"]["error"] = str(e)

def check_csrf(target, response, findings):
    log_info("CSRF kontrolleri yapılıyor...")
    if response is None:
        return
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    vulnerable_forms = 0
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        if method == "post":
            inputs = form.find_all("input")
            csrf_token = False
            for inp in inputs:
                name = inp.get("name", "").lower()
                if "csrf" in name or "token" in name or "nonce" in name:
                    csrf_token = True
                    break
            if not csrf_token:
                vulnerable_forms += 1
                log_warn(f"CSRF token eksik form: action={action}")
                add_finding(findings, "CSRF", "High", "Missing CSRF token in form", f"Form action: {action} method: POST")
    if vulnerable_forms == 0 and forms:
        log_ok("POST formlarında CSRF token mevcut.")

def test_idor(target, endpoints, findings):
    log_info("IDOR zafiyet taraması yapılıyor...")
    tested = 0
    for endpoint in endpoints[:10]:
        if "id=" in endpoint or "/id/" in endpoint or re.search(r'/\d+/', endpoint):
            try:
                parsed = urlparse(target + endpoint)
                qs = parse_qs(parsed.query)
                new_qs = {}
                for k, v in qs.items():
                    if k.lower() in ["id", "user_id", "uid"] and v[0].isdigit():
                        new_id = str(int(v[0]) + 1)
                        new_qs[k] = new_id
                    else:
                        new_qs[k] = v
                new_query = urlencode(new_qs, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                resp = safe_request_sync(new_url)
                if resp and resp.status_code == 200:
                    log_warn(f"IDOR potansiyel: {new_url} 200 döndü")
                    add_finding(findings, "IDOR", "High", "Possible Insecure Direct Object Reference", f"Modified ID request returned 200: {new_url}")
                    tested += 1
            except Exception:
                pass
    if tested == 0:
        log_ok("IDOR testi için uygun parametre bulunamadı.")

def test_xss(url, findings):
    log_info("XSS güvenli probe deneniyor...")
    test_url = build_url_with_param(url, "q", SAFE_XSS_PAYLOAD)
    response = safe_request_sync(test_url)
    if response is None:
        log_fail("XSS testi için response alınamadı.")
        return
    body = response.text.lower()
    if SAFE_XSS_PAYLOAD.lower() in body:
        log_warn("XSS olabilir: gönderilen probe response içinde geri dönüyor olabilir.")
        add_finding(findings, "XSS", "High", "Reflected input detected", "Zararsız XSS probe response içinde geri döndü.")
    else:
        log_ok("XSS için doğrudan yansıma tespit edilmedi.")

def test_sqli(url, findings):
    log_info("SQL Injection güvenli probe deneniyor...")
    test_url = build_url_with_param(url, "id", SAFE_SQLI_PAYLOAD)
    response = safe_request_sync(test_url)
    if response is None:
        log_fail("SQLi testi için response alınamadı.")
        return
    body = response.text.lower()
    for pattern in SQLI_ERROR_PATTERNS:
        if pattern in body:
            log_warn(f"SQLi olabilir: hata paterni görüldü → {pattern}")
            add_finding(findings, "SQL Injection", "High", "SQL error pattern detected", f"Response içinde SQL hata paterni bulundu: {pattern}")
            return
    log_ok("SQL hata paterni tespit edilmedi.")

def test_sqli_advanced(url, findings):
    log_info("Gelişmiş SQLi (time-based) probe deneniyor...")
    time_payloads = [
        "' OR SLEEP(2)-- ",
        "1' AND SLEEP(2)-- ",
    ]
    for payload in time_payloads:
        test_url = url + "'%20OR%20SLEEP(2)--%20"
        start = time.time()
        resp = safe_request_sync(test_url)
        elapsed = time.time() - start
        if resp and elapsed > 1.5:
            log_warn(f"SQLi zaman tabanlı olabilir: {test_url} ({elapsed:.2f}s)")
            add_finding(findings, "SQL Injection (Time-based)", "Critical", "Potential time-based SQLi", f"Response time: {elapsed:.2f}s")
            return
    log_ok("Time-based SQLi görülmedi.")

def test_path_traversal(url, findings):
    log_info("Path traversal güvenli probe deneniyor...")
    test_url = urljoin(url + "/", SAFE_TRAVERSAL_PAYLOAD)
    response = safe_request_sync(test_url)
    if response is None:
        log_fail("Path traversal testi için response alınamadı.")
        return
    if response.status_code in [200, 206]:
        log_warn("Beklenmeyen dosya/path yanıtı olabilir. Manuel kontrol önerilir.")
        add_finding(findings, "Path Traversal", "Low", "Unexpected path response", f"{test_url} HTTP {response.status_code} döndürdü.")
    else:
        log_ok("Path traversal probe için riskli yanıt görülmedi.")

def test_cors(url, findings):
    log_info("CORS kontrolü yapılıyor...")
    headers = {"Origin": "https://evil.example"}
    response = safe_request_sync(url, headers=headers)
    if response is None:
        log_fail("CORS testi için response alınamadı.")
        return
    acao = response.headers.get("Access-Control-Allow-Origin")
    acac = response.headers.get("Access-Control-Allow-Credentials")
    if acao == "*" and acac and acac.lower() == "true":
        log_warn("Riskli CORS yapılandırması olabilir: wildcard origin + credentials.")
        add_finding(findings, "CORS", "High", "Potentially dangerous CORS policy", "Access-Control-Allow-Origin: * ve credentials true olabilir.")
    elif acao == "https://evil.example":
        log_warn("Origin yansıtılıyor olabilir. CORS manuel kontrol edilmeli.")
        add_finding(findings, "CORS", "Medium", "Origin reflection detected", "Sunucu test Origin değerini CORS header'ında yansıttı.")
    else:
        log_ok("Riskli CORS paterni görülmedi.")

def test_rate_limit(url, findings):
    log_info("Rate-limit testi (eşzamanlı) yapılıyor...")
    status_codes = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(safe_request_sync, url) for _ in range(MAX_RATE_TEST_REQUESTS)]
        for future in as_completed(futures):
            resp = future.result()
            if resp:
                status_codes.append(resp.status_code)
    blocked_codes = [429, 403, 503]
    blocked = any(code in blocked_codes for code in status_codes)
    if blocked:
        log_ok("Rate-limit veya koruma yanıtı görüldü.")
    else:
        log_warn(f"Rate-limit zayıf olabilir. {MAX_RATE_TEST_REQUESTS} eşzamanlı istekte engelleme yok.")
        add_finding(findings, "Rate Limit", "Medium", "Rate limiting not observed", f"{MAX_RATE_TEST_REQUESTS} concurrent requests returned no 429/403/503")

def check_directory_listing(url, findings):
    log_info("Directory listing kontrolü yapılıyor...")
    response = safe_request_sync(url)
    if response is None:
        log_fail("Directory listing testi için response alınamadı.")
        return
    body = response.text.lower()
    if "index of /" in body or "<title>index of" in body:
        log_warn("Directory listing açık olabilir.")
        add_finding(findings, "Directory Listing", "Medium", "Directory listing may be enabled", "Response içinde Index of paterni görüldü.")
    else:
        log_ok("Directory listing paterni görülmedi.")

def test_discovered_endpoints(findings):
    endpoints = findings.get("recon", {}).get("endpoints", [])
    target = findings.get("target")
    if not endpoints:
        log_ok("Endpoint bazlı test için endpoint bulunamadı.")
        return
    parsed = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    param_endpoints = [ep for ep in endpoints if is_parametrized_endpoint(ep) and not ep.lower().endswith(STATIC_EXTENSIONS)]
    if not param_endpoints:
        log_ok("Parametre içeren endpoint bulunamadı, atlanıyor.")
        return
    
    log_info(f"Parametreli endpointlere test yapılıyor: {min(len(param_endpoints), ENDPOINT_TEST_LIMIT)} adet")
    tested = 0
    tested_urls = set()
    
    for endpoint in param_endpoints:
        if tested >= ENDPOINT_TEST_LIMIT:
            break
        endpoint_url = urljoin(base_url, endpoint)
        if endpoint_url in tested_urls:
            continue
        tested_urls.add(endpoint_url)
        
        log_info(f"Test: {endpoint}")
        test_xss(endpoint_url, findings)
        time.sleep(0.3)
        test_sqli(endpoint_url, findings)
        time.sleep(0.3)
        test_sqli_advanced(endpoint_url, findings)
        time.sleep(0.3)
        tested += 1
async def ssti_test(session, url, findings):
    log_info("SSTI testi yapılıyor...")
    test_url = build_url_with_param(url, "q", SAFE_SSTI_PAYLOAD)
    status, headers, body, _ = await async_fetch(session, test_url)
    if body and "49" in body and "7*7" not in body:
        log_warn("SSTI olabilir: {{7*7}} = 49 yansıması.")
        add_finding(findings, "SSTI", "High", "Potential Server-Side Template Injection", f"Payload {SAFE_SSTI_PAYLOAD} sonucu 49 bulundu.")

async def ldap_injection_test(session, url, findings):
    log_info("LDAP Injection testi...")
    payloads = ["*)(uid=*))(|(uid=*", "*"]
    for p in payloads:
        test_url = build_url_with_param(url, "user", p)
        status, headers, body, _ = await async_fetch(session, test_url)
        if body and ("error" in body.lower() or "exception" in body.lower()):
            log_warn("LDAP hatası olabilir.")
            add_finding(findings, "LDAP Injection", "Medium", "Potential LDAP Injection", f"Payload: {p}")

async def hpp_test(session, url, findings):
    log_info("HTTP Parameter Pollution testi...")
    parsed = urlparse(url)
    test_url = urlunparse(parsed._replace(query="id=1&id=2"))
    status, headers, body, _ = await async_fetch(session, test_url)
    if body and ("1" in body or "2" in body):
        log_info("HPP yansıması olabilir, manuel kontrol.")

async def cache_poisoning_test(session, url, findings):
    log_info("Web Cache Poisoning testi...")
    headers = {"X-Forwarded-Host": "evil.com", "X-Forwarded-Scheme": "http"}
    status, resp_headers, body, _ = await async_fetch(session, url, headers=headers)
    if body and "evil.com" in body:
        log_warn("Cache poisoning olabilir.")
        add_finding(findings, "Cache Poisoning", "High", "Potential Web Cache Poisoning", "X-Forwarded-Host reflected in response.")

async def clickjacking_test(session, url, findings):
    log_info("Clickjacking kontrolü...")
    status, headers, body, _ = await async_fetch(session, url)
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        log_warn("X-Frame-Options veya CSP frame-ancestors eksik.")
        add_finding(findings, "Clickjacking", "Medium", "Missing anti-clickjacking headers", "X-Frame-Options and CSP frame-ancestors not present.")

async def user_enumeration_test(session, url, findings):
    log_info("User enumeration testi...")
    login_url = urljoin(url, "/login")
    test_usernames = ["admin", "test", "nonexistent"]
    for user in test_usernames:
        data = {"username": user, "password": "wrongpassword"}
        status, headers, body, _ = await async_fetch(session, login_url, method='POST', data=data)
        if body and ("invalid username" in body.lower() or "user not found" in body.lower()):
            log_warn(f"User enumeration: {user}")
            add_finding(findings, "User Enumeration", "Medium", "Username enumeration possible", f"Different response for user {user}")
            break

async def password_reset_poisoning_test(session, url, findings):
    log_info("Password reset poisoning testi...")
    reset_url = urljoin(url, "/reset-password")
    headers = {"Host": "evil.com", "X-Forwarded-Host": "evil.com"}
    data = {"email": "test@example.com"}
    status, _, body, _ = await async_fetch(session, reset_url, method='POST', data=data, headers=headers)
    if status == 200:
        log_info("Host başlığı enjeksiyonu denendi, manuel kontrol gerekir.")

async def two_fa_bypass_test(session, url, findings):
    log_info("2FA bypass testi (basit) ...")
    dashboard_url = urljoin(url, "/dashboard")
    status, _, _, _ = await async_fetch(session, dashboard_url)
    if status == 200:
        log_warn("Dashboard'a doğrudan erişilebiliyor (2FA kontrolü eksik olabilir).")
        add_finding(findings, "2FA Bypass", "High", "Potential 2FA bypass", "Dashboard accessible without 2FA challenge.")

async def business_logic_test(session, url, findings):
    log_info("Business logic testi (örnek: negatif fiyat) ...")
    cart_url = urljoin(url, "/api/cart")
    data = {"product_id": "1", "quantity": "-1", "price": "100"}
    status, _, body, _ = await async_fetch(session, cart_url, method='POST', json=data)
    if status == 200 and body and "total" in body:
        log_warn("Negatif miktar kabul edildi, business logic hatası olabilir.")
        add_finding(findings, "Business Logic", "High", "Business logic flaw (negative quantity)")

async def prototype_pollution_test(session, url, findings):
    log_info("Prototype Pollution testi...")
    payload = {"__proto__": {"polluted": "true"}}
    test_url = urljoin(url, "/api/data")
    status, _, body, _ = await async_fetch(session, test_url, method='POST', json=payload)
    if body and "polluted" in body:
        log_warn("Prototype Pollution mümkün olabilir.")
        add_finding(findings, "Prototype Pollution", "High", "Potential Prototype Pollution", "Response reflects polluted property")

async def graphql_batching_test(session, url, findings):
    log_info("GraphQL batching brute‑force testi...")
    queries = [{"query": "{__typename}"}] * 50
    status, _, body, _ = await async_fetch(session, url, method='POST', json=queries)
    if status == 200:
        log_warn("GraphQL batching kabul ediliyor.")

async def rest_mass_assignment(session, url, findings):
    log_info("REST Mass Assignment testi...")
    test_url = urljoin(url, "/api/users")
    payload = {"username": "test", "role": "admin"}
    status, _, body, _ = await async_fetch(session, test_url, method='POST', json=payload)
    if status == 201 and body and "admin" in body:
        log_warn("Mass assignment zafiyeti olabilir.")
        add_finding(findings, "Mass Assignment", "High", "Potential Mass Assignment", "Role admin could be set")

async def websocket_test(session, url, findings):
    log_info("WebSocket Origin kontrolü...")
    ws_url = url.replace("http", "ws") + "/socket"
    try:
        async with session.ws_connect(ws_url, headers={"Origin": "http://evil.com"}) as ws:
            if ws.status == 101:
                log_warn("WebSocket bağlantısı farklı origin ile kabul edildi.")
    except Exception:
        pass

async def deserialization_test(session, url, findings):
    log_info("Deserialization testi (hata mesajı) ...")
    data = base64.b64decode("rO0ABXNyABdqYXZhLnV0aWwuQ29sbGVjdGlvbnM=")
    headers = {"Content-Type": "application/java-serialized-object"}
    status, _, body, _ = await async_fetch(session, url, method='POST', data=data, headers=headers)
    if body and ("exception" in body.lower() or "error" in body.lower()):
        log_warn("Deserialization hatası olabilir.")
        add_finding(findings, "Deserialization", "High", "Potential insecure deserialization", "Error response to serialized object")

async def api_discovery(session, base_url, findings):
    api_paths = [
        "/api", "/swagger.json", "/openapi.json", "/graphql", "/graphiql",
        "/docs", "/redoc", "/api-docs", "/api/v1", "/api/v2"
    ]
    findings["recon"].setdefault("api_endpoints", [])
    for path in api_paths:
        url = urljoin(base_url, path)
        status, headers, body, _ = await async_fetch(session, url)
        if status == 200:
            log_warn(f"API endpoint bulundu: {url}")
            findings["recon"]["api_endpoints"].append(url)

async def graphql_introspection_test(session, url, findings):
    query = "{__schema{types{name}}}"
    status, headers, body, _ = await async_fetch(session, url, method='POST', json={"query": query})
    if status == 200 and "__schema" in body:
        log_warn("GraphQL introspection başarılı!")
        add_finding(findings, "GraphQL", "Medium", "GraphQL introspection enabled", url)

def jwt_analysis(response, findings):
    auth_header = response.headers.get("Authorization") or response.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split()[1]
        try:
            header, payload, sig = token.split('.')
            header_json = base64.urlsafe_b64decode(header + "=" * (4 - len(header) % 4))
            payload_json = base64.urlsafe_b64decode(payload + "=" * (4 - len(payload) % 4))
            findings["jwt"] = {"header": json.loads(header_json), "payload": json.loads(payload_json)}
            test_token = base64.urlsafe_b64encode(header_json).decode().rstrip("=") + "." + base64.urlsafe_b64encode(payload_json).decode().rstrip("=") + "."
            test_resp = safe_request_sync(response.url, headers={"Authorization": f"Bearer {test_token}"})
            if test_resp and test_resp.status_code == 200:
                log_warn("JWT alg=none kabul ediliyor olabilir!")
                add_finding(findings, "JWT", "Critical", "JWT algorithm confusion possible", "")
        except Exception:
            pass

async def sensitive_data_leak_detection(session, url, findings):
    patterns = {
        "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "API Key": r"[a-zA-Z0-9_]{32,}",
        "Password in response": r"password\":\s*\"[^\"]+\"",
    }
    status, _, body, _ = await async_fetch(session, url)
    if body:
        for name, regex in patterns.items():
            matches = re.findall(regex, body)
            if matches:
                log_warn(f"{name} bulgusu: {len(matches)} eşleşme")
                add_finding(findings, "Sensitive Data Leak", "High", f"{name} found in response", str(matches[:5]))

async def jwt_analysis_on_endpoint(session, url, findings):
    """JWT analizini asenkron yapar (endpoint bazlı)"""
    pass

async def test_cors_on_endpoint(session, url, findings):
    headers = {"Origin": "https://evil.example"}
    status, resp_headers, body, _ = await async_fetch(session, url, headers=headers)
    acao = resp_headers.get("Access-Control-Allow-Origin")
    acac = resp_headers.get("Access-Control-Allow-Credentials")
    if acao == "*" and acac and acac.lower() == "true":
        log_warn(f"Riskli CORS endpoint: {url}")
        add_finding(findings, "CORS", "High", "Potentially dangerous CORS policy on endpoint", url)

def test_api_endpoints(findings):
    """API endpointlerine ekstra testler (asenkron olmayan)"""
    api_urls = findings["recon"].get("api_endpoints", [])
    for api_url in api_urls:
        log_info(f"API test: {api_url}")
        test_cors(api_url, findings)
        # JWT varsa analiz et
        resp = safe_request_sync(api_url)
        if resp:
            jwt_analysis(resp, findings)

def calculate_risk_score(findings):
    weights = {"Critical": 4.0, "High": 3.0, "Medium": 1.4, "Low": 0.6, "Info": 0.2}
    score = 0.0
    for vuln in findings.get("vulnerabilities", []):
        score += weights.get(vuln.get("severity", "Info"), 0.2)
    open_ports = findings.get("recon", {}).get("open_ports", [])
    subdomains = findings.get("recon", {}).get("subdomains", [])
    admin_panels = findings.get("recon", {}).get("admin_panels", [])
    if len(open_ports) >= 8:
        score += 1.0
    elif len(open_ports) >= 4:
        score += 0.5
    if len(subdomains) >= 5:
        score += 0.7
    if admin_panels:
        score += 1.0
    if findings.get("waf_cdn"):
        score -= 0.5
    score = max(0.0, min(10.0, score))
    if score >= 8.0:
        level = "HIGH"
    elif score >= 4.5:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "INFO"
    findings["risk"] = {"score": round(score, 1), "level": level}
    return findings["risk"]

def generate_html_report(findings, json_filename):
    ensure_reports_dir()
    safe_domain = safe_filename(findings["domain"].replace(".", "_"))
    html_filename = os.path.join("reports", f"ber211_report_{safe_domain}.html")
    risk = findings.get("risk", {"score": 0, "level": "INFO"})
    vulns = findings.get("vulnerabilities", [])
    endpoints = findings.get("recon", {}).get("endpoints", [])
    subdomains = findings.get("recon", {}).get("subdomains", [])
    ports = findings.get("recon", {}).get("open_ports", [])
    port_intel = findings.get("recon", {}).get("port_intelligence", [])
    tech = findings.get("technologies", [])
    axfr = findings.get("recon", {}).get("axfr_records", [])
    waf_cdn = findings.get("waf_cdn", [])
    asn_info = findings.get("recon", {}).get("asn", {})
    whois_info = findings.get("recon", {}).get("whois", {})
    
    def esc(value):
        return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    
    vuln_rows = "\n".join(
        f"<tr><td>{i}</td><td>{esc(v.get('severity'))}</td><td>{esc(v.get('category'))}</td><td>{esc(v.get('title'))}</td><td>{esc(v.get('evidence'))}</td></tr>"
        for i, v in enumerate(vulns, start=1)
    ) or "<tr><td colspan='5'>Bulgu yok</td></tr>"
    
    port_rows = "\n".join(
        f"<tr><td>{p.get('port')}</td><td>{esc(p.get('service'))}</td><td>{esc(p.get('severity'))}</td><td>{esc(p.get('note'))}</td></tr>"
        for p in port_intel
    ) or "<tr><td colspan='4'>Port intelligence bulgusu yok</td></tr>"
    
    endpoint_items = "\n".join(f"<li>{esc(ep)}</li>" for ep in endpoints[:100]) or "<li>Endpoint bulunamadı</li>"
    subdomain_items = "\n".join(f"<li>{esc(s.get('subdomain'))} → {esc(s.get('ip'))}</li>" for s in subdomains[:100]) or "<li>Subdomain bulunamadı</li>"
    tech_items = "\n".join(f"<li>{esc(t)}</li>" for t in tech) or "<li>Teknoloji izi bulunamadı</li>"
    axfr_items = "\n".join(f"<li>{esc(a['name'])} ({a['type']}): {esc(a['data'])}</li>" for a in axfr[:50]) if axfr else "<li>AXFR kaydı yok</li>"
    waf_items = ", ".join(waf_cdn) or "Tespit edilmedi"
    
    asn_text = f"{asn_info.get('asn', 'N/A')} - {asn_info.get('asn_description', '')}" if asn_info else "N/A"
    whois_text = f"Registrar: {whois_info.get('registrar', 'N/A')}<br>Creation: {whois_info.get('creation_date', 'N/A')}<br>Expiration: {whois_info.get('expiration_date', 'N/A')}" if whois_info else "N/A"
    
    html = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>BER211 Scanner Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #0b1020;
    color: #e8eefc;
    margin: 0;
    padding: 24px;
}}
.card {{
    background: #141b34;
    border: 1px solid #253055;
    border-radius: 14px;
    padding: 18px;
    margin-bottom: 18px;
}}
h1, h2 {{
    color: #61dafb;
}}
.badge {{
    display: inline-block;
    padding: 8px 12px;
    border-radius: 999px;
    background: #263b7a;
    font-weight: bold;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
}}
th, td {{
    border: 1px solid #2a365e;
    padding: 8px;
    text-align: left;
    vertical-align: top;
}}
th {{
    background: #202a4f;
}}
code {{
    color: #9be9a8;
}}
</style>
</head>
<body>
<div class="card">
<h1>BER211 Scanner Report</h1>
<p><b>Target:</b> {esc(findings.get('target'))}</p>
<p><b>Scan Mode:</b> {esc(findings.get('scan_mode'))}</p>
<p><b>IP:</b> {esc(findings.get('recon', {}).get('ip', 'N/A'))}</p>
<p><b>Open Ports:</b> {esc(ports)}</p>
<p><b>WAF/CDN:</b> {waf_items}</p>
<p><b>ASN:</b> {asn_text}</p>
<p><b>WHOIS:</b> {whois_text}</p>
<p><span class="badge">Risk Score: {risk.get('score')} / 10 — {risk.get('level')}</span></p>
<p><b>JSON:</b> <code>{esc(json_filename)}</code></p>
</div>
<div class="card">
<h2>Vulnerabilities</h2>
<table>
<tr><th>#</th><th>Severity</th><th>Category</th><th>Title</th><th>Evidence</th></tr>
{vuln_rows}
</table>
</div>
<div class="card">
<h2>Port Intelligence</h2>
<table>
<tr><th>Port</th><th>Service</th><th>Severity</th><th>Note</th></tr>
{port_rows}
</table>
</div>
<div class="card">
<h2>Technologies</h2>
<ul>{tech_items}</ul>
</div>
<div class="card">
<h2>Subdomains</h2>
<ul>{subdomain_items}</ul>
</div>
<div class="card">
<h2>AXFR Zone Transfer Records</h2>
<ul>{axfr_items}</ul>
</div>
<div class="card">
<h2>Endpoints - İlk 100</h2>
<ul>{endpoint_items}</ul>
</div>
</body>
</html>
"""
    with open(html_filename, "w", encoding="utf-8") as file:
        file.write(html)
    log_ok(f"HTML rapor kaydedildi: {html_filename}")
    return html_filename

def normalize_finding_schema(findings):
    normalized = []
    seen = set()
    for item in findings.get("vulnerabilities", []):
        if not isinstance(item, dict):
            continue
        item.setdefault("safe", True)
        item.setdefault("category", "Unknown")
        item.setdefault("severity", "Info")
        item.setdefault("title", "No title")
        item.setdefault("evidence", "No evidence")
        key = (item.get("category"), item.get("severity"), item.get("title"), item.get("evidence"))
        if key in seen:
            continue
        seen.add(key)
        normalized.append(item)
    findings["vulnerabilities"] = normalized
    return findings

def report(findings):
    normalize_finding_schema(findings)
    calculate_risk_score(findings)
    print(f"\n{C_CYAN}{C_BOLD}╔══════════════════════════════════════════════╗")
    print("║                  SCAN REPORT                 ║")
    print(f"╚══════════════════════════════════════════════╝{C_RESET}\n")
    print(f"Target     : {findings.get('target', 'N/A')}")
    print(f"Scan Mode  : {findings.get('scan_mode', 'N/A')}")
    print(f"IP         : {findings.get('recon', {}).get('ip', 'N/A')}")
    print(f"Ports      : {findings.get('recon', {}).get('open_ports', [])}")
    print(f"Endpoints  : {len(findings.get('recon', {}).get('endpoints', []))}")
    print(f"Subdomains : {len(findings.get('recon', {}).get('subdomains', []))}")
    print(f"Admin Hits : {len(findings.get('recon', {}).get('admin_panels', []))}")
    print(f"AXFR Recs  : {len(findings.get('recon', {}).get('axfr_records', []))}")
    print(f"Risk Score : {findings.get('risk', {}).get('score', 0)} / 10")
    print(f"Risk Level : {findings.get('risk', {}).get('level', 'INFO')}\n")
    
    for vuln in findings.get("vulnerabilities", []):
        sev = vuln.get('severity', 'INFO')
        cat = vuln.get('category', 'General')
        tit = vuln.get('title', 'N/A')
        evid = vuln.get('evidence', 'No evidence provided')
        safe = vuln.get('safe', True)
        print(f"[{sev}] {cat} - {tit}")
        print(f"   Evidence: {evid}")
        print(f"   Safe    : {safe}\n")
    
    ensure_reports_dir()
    domain_val = findings.get("domain") or findings.get("target", "unknown")
    safe_domain = safe_filename(domain_val.replace(".", "_"))
    filename = os.path.join("reports", f"ber211_report_{safe_domain}.json")
    
    try:
        with open(filename, "w", encoding="utf-8") as file:
            json.dump(findings, file, indent=2, ensure_ascii=False)
        log_ok(f"JSON rapor kaydedildi: {filename}")
        generate_html_report(findings, filename)
    except Exception as e:
        log_fail(f"Rapor kaydedilemedi: {e}")

def ensure_reports_dir():
    os.makedirs("reports", exist_ok=True)

def choose_scan_mode():
    print(f"\n{C_GREEN}01{C_RESET} [ Fast Tarama ]")
    print(f"{C_YELLOW}02{C_RESET} [ Full Tarama ]")
    choice = input("Tarama modu seç: ").strip()
    if choice in ["2", "02", "full", "Full", "FULL"]:
        log_warn("Full tarama seçildi. Daha uzun sürebilir.")
        return "full", FULL_PORTS
    log_ok("Fast tarama seçildi.")
    return "fast", FAST_PORTS

def run_scan():
    clear()
    banner()
    print(C_RED_BOLD + "⚠  YASAL UYARI: Bu araç yalnızca yetkili güvenlik testleri içindir. İzinsiz kullanım suçtur. ⚠" + C_RESET)
    confirm_legal = input("Yukarıdaki uyarıyı okudum ve kabul ediyorum (evet/hayır): ").strip().lower()
    if confirm_legal not in ["evet", "e", "yes", "y"]:
        log_fail("Yasal uyarı kabul edilmedi. Program sonlandırılıyor.")
        sys.exit(1)
    
    raw_target = input("Hedef URL girin: ").strip()
    target = normalize_url(raw_target)
    if target is None:
        log_fail("Geçersiz URL.")
        input("Devam etmek için Enter...")
        return
    domain = get_domain(target)
    findings = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "developer": DEVELOPER,
        "target": target,
        "domain": domain,
        "recon": {"axfr_records": [], "api_endpoints": [], "banners": []},
        "tls": {},
        "waf_cdn": [],
        "technologies": [],
        "scan_mode": None,
        "vulnerabilities": [],
        "info": [],
        "errors": [],
    }
    print()
    log_info(f"Hedef alındı: {target}")
    log_info("Scope kontrolü: Bu araç yalnızca izinli hedeflerde kullanılmalıdır.")
    confirm = input("Bu hedef üzerinde test yapmaya yetkin var mı? [evet/hayır]: ").strip().lower()
    if confirm not in ["evet", "e", "yes", "y"]:
        log_fail("Yetki onayı verilmedi. İşlem durduruldu.")
        input("Devam etmek için Enter...")
        return
    log_ok("Scope onayı alındı.")
    
    scan_mode, selected_ports = choose_scan_mode()
    findings["scan_mode"] = scan_mode
    findings["recon"]["selected_port_count"] = len(selected_ports)
    
    ip = resolve_dns(domain, findings)
    if ip:
        port_scan(ip, findings, selected_ports)
        add_port_intelligence(findings)
    print()
    
    try_axfr(domain, findings)
    print()
    
    log_info("Web bağlantısı kontrol ediliyor...")
    response = safe_request_sync(target)
    if response is None:
        log_fail("Hedef web response vermedi. Bazı testler atlanacak.")
    else:
        log_ok(f"HTTP status: {response.status_code}")
    print()
    
    discover_subdomains(domain, findings)
    subdomain_bruteforce(domain, findings)
    dns_records_enum(domain, findings)
    whois_lookup(domain, findings)
    if ip:
        asn_info(ip, findings)
        for port in findings["recon"]["open_ports"]:
            banner_grabbing(ip, port, findings)
    s3_bucket_check(domain, findings)
    print()
    
    discover_endpoints(target, response, findings)
    admin_panel_scan(target, findings)
    scan_sensitive_files(target, findings)
    detect_waf_cdn(response, findings)
    detect_technologies(response, findings)
    analyze_headers(response, findings)
    analyze_cookies(response, findings)
    check_tls(domain, findings)
    deep_tls_check(domain, findings)
    check_csrf(target, response, findings)
    test_idor(target, findings["recon"]["endpoints"], findings)
    test_xss(target, findings)
    test_sqli(target, findings)
    test_sqli_advanced(target, findings)
    test_path_traversal(target, findings)
    test_cors(target, findings)
    check_directory_listing(target, findings)
    test_rate_limit(target, findings)
    test_discovered_endpoints(findings)
    test_api_endpoints(findings)
    async def run_async_tests():
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": USER_AGENT}) as session:
            try:
                await api_discovery(session, target, findings)
            except Exception as e:
                log_fail(f"API discovery hatası: {e}")
            for api_url in findings["recon"].get("api_endpoints", []):
                try:
                    await graphql_introspection_test(session, api_url, findings)
                except Exception as e:
                    log_fail(f"GraphQL introspection hatası {api_url}: {e}")
            try:
                await ssti_test(session, target, findings)
                await ldap_injection_test(session, target, findings)
                await hpp_test(session, target, findings)
                await cache_poisoning_test(session, target, findings)
                await clickjacking_test(session, target, findings)
                await user_enumeration_test(session, target, findings)
                await password_reset_poisoning_test(session, target, findings)
                await two_fa_bypass_test(session, target, findings)
                await business_logic_test(session, target, findings)
                await prototype_pollution_test(session, target, findings)
                await graphql_batching_test(session, target, findings)
                await rest_mass_assignment(session, target, findings)
                await websocket_test(session, target, findings)
                await deserialization_test(session, target, findings)
                await sensitive_data_leak_detection(session, target, findings)
            except Exception as e:
                log_fail(f"Asenkron test hatası: {e}")
    
    try:
        asyncio.run(run_async_tests())
    except Exception as e:
        log_fail(f"Asenkron testlerde hata: {e}")
        findings["errors"].append(f"Async test error: {str(e)}")
    
    print()
    report(findings)
    input("\nMenüye dönmek için Enter'a bas...")

def developer_info():
    clear()
    banner()
    random_texts = [
        "Kahverengi gözler debug edilemez, bal dudaklar sistem override.",
        "Çekik bakışlar cache’e yazıldı, kalp sürekli loop’ta.",
        "Gözler async çalışıyor, kalp response bekliyor.",
        "Kahverengi bakış geldi, sistem direkt crash.",
        "Bal gibi dudaklar, kalpte permanent storage.",
        "Çekik gözler bir bug, çözümü yok.",
        "Gözlerin dark mode, içim aydınlık.",
        "Kalp API attı, cevap sadece o bakış.",
        "Kahverengi gözler root access aldı.",
        "Bal dudaklar memory leak gibi, çıkmıyor aklımdan.",
        "Çekik gözler terminalde tek komut: etkilendim.",
        "Gözler signal gönderdi, kalp sürekli ping.",
        "Kahverengi bakışlar sistemde admin.",
        "Bal dudaklar, kalpte sonsuz loop.",
        "Çekik gözler code gibi, çöz çöz bitmiyor.",
        "Gözlerin veri, kalbim database.",
        "Kahverengi bakışlar firewall’u geçti.",
        "Bal dudaklar encryption gibi, çözülemiyor.",
        "Çekik gözler input, kalp output veremiyor.",
        "Gözler runtime’da yakaladı beni.",
        "Kahverengi gözler override etti aklımı.",
        "Bal dudaklar cache’te kaldı, silinmiyor.",
        "Çekik bakışlar sistemde en büyük exploit.",
        "Gözler script gibi çalışıyor içimde.",
        "Kahverengi bakışlar CPU’yu %100 yaptı.",
        "Bal dudaklar kalpte background process.",
        "Çekik gözler sürekli refresh atıyor.",
        "Gözler veri akışı, kalp kontrolsüz.",
        "Kahverengi bakışlar sistem reboot attı.",
        "Bal dudaklar final çıktı: kalp sende."
    ]
    print(f"{C_BOLD}Geliştirici :{C_RESET} {DEVELOPER}")
    print(f"{C_BOLD}Tool adı    :{C_RESET} {TOOL_NAME}")
    print(f"{C_BOLD}Versiyon    :{C_RESET} {VERSION}")
    print(f"{C_BOLD}Yazılım dili:{C_RESET} Python")
    print(f"{C_BOLD}Platform    :{C_RESET} Kali Linux / Linux / Windows / macOS")
    print(f"{C_BOLD}Amaç        :{C_RESET} Yetkili güvenlik testleri ve güvenlik açığı analizi.")
    print(f"{C_BOLD}Yöntem      :{C_RESET} Tahribatsız güvenli probe doğrulaması.")
    print(f"{C_BOLD}İletişim    :{C_RESET} {CONTACT}")
    print()
    print(f"{C_CYAN}{C_BOLD}Görürse:{C_RESET}")
    for text in random.sample(random_texts, k=1):
        print(f"{C_YELLOW}> {text}{C_RESET}")
        time.sleep(0.25)
    input("\nMenüye dönmek için Enter'a bas...")

def main_menu():
    while True:
        clear()
        banner()
        print(f"{C_GREEN}01{C_RESET} [ Başlat ]")
        print(f"{C_BLUE}02{C_RESET} [ Geliştirici Hakkında ]")
        print(f"{C_RED}03{C_RESET} [ Çık ]")
        choice = input("Seçim yap: ").strip()
        if choice in ["1", "01"]:
            run_scan()
        elif choice in ["2", "02"]:
            developer_info()
        elif choice in ["3", "03"]:
            print("Çıkılıyor...")
            sys.exit(0)
        else:
            print("Geçersiz seçim.")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nÇıkılıyor...")
        sys.exit(0)
