# 403bypasser v3.0

## Description

**403bypasser** is an intelligent tool for bypass testing on web pages that return HTTP 403 Forbidden or 401 Unauthorized. It runs **14 priority-ordered test phases** with server fingerprinting, response body analysis, and confidence scoring to minimize false positives.

### What changed in v3.0

| Feature | v2.0 | v3.0 |
|---------|------|------|
| False positives | Hash + 404 baseline only | Root baseline + body analysis + login detection + title check |
| IP spoofing | 576 combos (mostly noise) | 15 high-value combos, auto-skipped behind CDN |
| Server awareness | None | Fingerprints server/WAF/CDN, skips irrelevant techniques |
| Confidence | Binary yes/no | 0-100% score with HIGH/GOOD/MEDIUM/LOW labels |
| Rate limiting | Basic 429 retry | Adaptive exponential backoff, auto-skip on block |
| Thread safety | None (race conditions) | Locks on all shared state |
| Path mutations | 137 unsorted | 77 priority-ordered (HIGH/MEDIUM/LOW) |

### What it tests

| Phase | Technique | Details |
|-------|-----------|---------|
| 1 | **Baseline** | Captures target + root + 404 baselines for FP filtering |
| 2 | **Protocol switch** | HTTP ↔ HTTPS |
| 3 | **Root header override** | X-Original-URL, X-Rewrite-URL, X-Override-URL (compared against root baseline) |
| 4 | **HTTP methods** | 17 methods: GET/POST/PUT/PATCH/DELETE + WebDAV + DEBUG/TRACK |
| 5 | **Verb case variants** | get, Get, gEt, post, Post, etc. |
| 6 | **Method override** | X-HTTP-Method-Override with POST/PUT/PATCH |
| 7 | **Method with body** | POST/PUT/PATCH with JSON, form, XML bodies |
| 8 | **Header bypass** | 28 high-value bypass headers |
| 9 | **Header combos** | Multi-header combinations |
| 10 | **IP spoofing** | 15 high-value combos (auto-skipped behind Cloudflare/Akamai) |
| 11 | **Host header** | localhost, 127.0.0.1, FQDN dot, port variants |
| 12 | **User-Agent** | Googlebot, Bingbot, curl, empty UA |
| 13 | **WAF bypass** | Large header padding, cache busters |
| 14 | **Path / encoding** | 77 priority-ordered mutations, case variants, char encoding |

### Key features

- **Server fingerprinting**: Detects nginx/Apache/Tomcat/IIS/Spring/Cloudflare/Akamai and skips irrelevant techniques
- **Body analysis**: Detects login pages, error pages, and generic placeholders returned as 200
- **Confidence scoring**: 0-100% confidence with visual bar for each finding
- **Root baseline**: Prevents false positives from root header override tests
- **Adaptive rate limiting**: Exponential backoff with automatic phase skipping on block
- **Thread safety**: All shared state protected with locks
- **Curl reproduction**: Every finding includes a ready-to-paste curl command

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

# Quick check — only high-value phases
python3 403bypasser.py https://example.com admin --skip ip-spoof,waf,path-encode,verb-case,ua
```

### Disable fingerprinting

```bash
# Run all techniques regardless of server detection
python3 403bypasser.py https://example.com admin --no-fingerprint
```

### Minimum confidence filter

```bash
# Only show high-confidence findings
python3 403bypasser.py https://example.com admin --min-confidence 70
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

## Confidence scoring

Each finding gets a 0-100% confidence score:

| Score | Label | Meaning |
|-------|-------|---------|
| 90-100% | HIGH | Response references target path content |
| 70-89% | GOOD | Substantial structured content |
| 50-69% | MEDIUM | Has content, needs manual verification |
| 40-49% | LOW | Minimal content |
| <40% | NOISE | Filtered out by default |

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
