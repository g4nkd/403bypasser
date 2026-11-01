# 403bypasser v2.0

## Description

**403bypasser** is an advanced tool for bypass testing on web pages that return HTTP 403 Forbidden or 401 Unauthorized. It runs **16 test phases** covering techniques from real bug bounty writeups, HackTricks, and top bypass tools (nomore403, byp4xx, 400ok).

### What it tests

| Phase | Technique | Details |
|-------|-----------|---------|
| 1 | **Baseline** | Captures normal response + 404 baseline for false-positive filtering |
| 2 | **Protocol switch** | HTTP ↔ HTTPS |
| 3 | **HTTP/0.9** | Raw socket, no HTTP version header |
| 4 | **HTTP/1.0 downgrade** | Some ACLs only apply to HTTP/1.1 |
| 5 | **Root header override** | X-Original-URL, X-Rewrite-URL, X-Override-URL, X-Forwarded-Path |
| 6 | **HTTP methods** | 25 methods: GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS/TRACE/CONNECT + WebDAV (PROPFIND/MKCOL/MOVE/COPY/LOCK/UNLOCK) + made-up verbs |
| 7 | **Verb case variants** | get, Get, gEt, GEt, post, Post, etc. |
| 8 | **Method override** | X-HTTP-Method-Override / X-HTTP-Method / X-Method-Override with POST/PUT/PATCH |
| 9 | **Method with body** | POST/PUT/PATCH with JSON, XML, form-data bodies |
| 10 | **IP spoofing headers** | 23 headers × 24 IP values = 552 combos (127.0.0.1, ::1, 0.0.0.0, internal ranges, octal/hex/decimal encoding) |
| 11 | **Header bypass** | 60+ misc bypass headers (scheme, port, host, content-type, auth, cache, WAF evasion) |
| 12 | **Header combos** | Multi-header combinations that work together |
| 13 | **User-Agent bypass** | Googlebot, Bingbot, curl, wget, empty UA |
| 14 | **Host header bypass** | localhost, 127.0.0.1, ::1, trailing dot FQDN, port variants, uppercase |
| 15 | **WAF bypass** | Large header padding, cache busters, tab-separated paths |
| 16 | **Path/encoding/case** | 100+ path mutations, char-by-char encoding, double/triple encoding, case variations, Unicode fullwidth, null bytes, semicolons |

### Key features

- **False-positive filtering**: 404 baseline detection prevents custom error pages from showing as bypasses
- **Curl reproduction commands**: Every finding includes a ready-to-paste curl command
- **Phase skipping**: Skip slow/noisy phases with `--skip`
- **Threaded execution**: Parallel testing with configurable thread count
- **JSON output**: Machine-readable results for integration with other tools

## Requirements

- Python 3.6+
- `requests` library

## Installation

```bash
git clone https://github.com/g4nkd/403bypasser.git
cd 403bypasser
pip install -r requirements.txt
```

## Usage

### Basic

```bash
python3 403bypasser.py https://example.com admin
```

### Multiple paths

```bash
python3 403bypasser.py https://example.com admin,dashboard,api/v1/users
```

### Wordlist

```bash
python3 403bypasser.py https://example.com -w paths.txt -t 30
```

### With custom headers

```bash
python3 403bypasser.py https://example.com admin -H "Cookie: session=abc123" -H "Authorization: Bearer token"
```

### Save results to JSON

```bash
python3 403bypasser.py https://example.com admin -o results.json
```

### Skip slow phases

```bash
# Skip IP spoofing and WAF bypass (fastest scan)
python3 403bypasser.py https://example.com admin --skip ip-spoof,waf

# Skip heavy phases for quick check
python3 403bypasser.py https://example.com admin --skip ip-spoof,waf,path-encode,verb-case
```

### Verbose mode

```bash
python3 403bypasser.py https://example.com admin -v
```

### Available skip phases

| Flag | Phase |
|------|-------|
| `protocol` | Protocol switch |
| `http09` | HTTP/0.9 |
| `http10` | HTTP/1.0 downgrade |
| `root-override` | Root header override |
| `methods` | HTTP methods |
| `verb-case` | Verb case variants |
| `method-override` | Method override |
| `method-body` | Method with body |
| `ip-spoof` | IP spoofing headers |
| `headers` | Header bypass |
| `header-combos` | Header combos |
| `ua` | User-Agent bypass |
| `host` | Host header bypass |
| `waf` | WAF bypass |
| `path-encode` | Path/encoding/case |

## Techniques sourced from

- [HackTricks - 403 & 401 Bypasses](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses)
- [daffainfo/AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty/blob/master/Bypass/Bypass%20403.md)
- [devploit/nomore403](https://github.com/devploit/nomore403)
- [€1500 bounty — 403 bypass to intranet portal](https://medium.com/@asharm.khan7/1500-bounty-how-i-bypassed-403-forbidden-and-gained-access-to-the-intranet-portal-3464f29f4ddb)
- [Sprocket Security - Are 403 bypasses worth looking for?](https://www.sprocketsecurity.com/blog/are-403-bypasses-worth-looking-for)
- [403 Bypass Tricks Every Bug Hunter Should Know](https://blogs.jsmon.sh/403-bypass-tricks-every-bug-hunter-should-know/)

## Demo

<img width="2410" height="1310" alt="image" src="https://github.com/user-attachments/assets/05acaa13-5f9c-4696-b836-21c92a81cc36" />

## Disclaimer

This tool is intended for **authorized security testing only**. Only use it against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.
