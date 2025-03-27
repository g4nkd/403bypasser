Claro! Aqui está a versão em inglês com as atualizações que você pediu:

---

# 403bypasser

## Description

**403bypasser** is a tool designed to perform **bypass testing** on web pages that return an HTTP **403 Forbidden** status code. Through techniques like **HTTP Method fuzzing**, **HTTP Header fuzzing**, and **Path fuzzing**, it attempts to bypass restrictions set on URLs and identify vulnerabilities in misconfigured systems or security flaws.

### Main Features:
- Tests **HTTP Methods** (GET, POST, PUT, etc.).
- Tests **HTTP Headers** with common values used in bypass attacks.
- **Path Fuzzing** to explore variations of paths that might bypass restrictions.
- Ability to test multiple methods and headers in parallel using multiple **threads**.

## Requirements

- Python 3.6 or later
- **requests** library (can be installed via `pip`)

## Installation

1. Clone the repository to your local directory:

   ```bash
   git clone https://github.com/g4nkd/403bypasser.git
   cd 403bypasser
   ```

2. Install the required dependencies (if you don't have `requests` installed):

   ```bash
   pip install requests
   ```

## Usage

### Basic Execution

```bash
python3 403bypasser.py <URL> [PATH]
```

**Parameters**:
- `<URL>`: The target URL you want to test (e.g., `https://example.com`).
- `[PATH]`: The specific path to test (e.g., `admin`, `login`). This is optional. If not provided, the script will attempt to test all possible paths.

### Examples

- Testing the `admin` path of a website:

  ```bash
  python3 403bypasser.py https://example.com admin
  ```

- Testing the website without a specific path:

  ```bash
  python3 403bypasser.py https://example.com
  ```

### Additional Options

- `-v` or `--verbose`: Enables detailed output during the test.

  Example:

  ```bash
  python3 403bypasser.py https://example.com admin -v
  ```

- `-t` or `--threads`: Sets the number of threads to use for parallel testing. The default is 20.

  Example:

  ```bash
  python3 403bypasser.py https://example.com admin -t 50
  ```

## How It Works

### Path Fuzzing

The script applies various path manipulation techniques (like `/{}?`, `/*/{}`) to test if the URL can be bypassed. These techniques help identify misconfigurations on web servers, such as hidden directories or files.

### HTTP Method Testing

The script tests common HTTP methods (GET, POST, PUT, DELETE, etc.) to check if any method can be used to bypass access restrictions.

### HTTP Header Testing

It sends various HTTP headers frequently used for bypassing, such as `X-Forwarded-For`, `X-Originating-IP`, and others, to see if any of these values allow access.

## Example Output

When a successful bypass is found, the output will look something like this:

```bash
[+] Bypass found!
URL: https://example.com/admin
Method: GET
Status: 200
Headers:
  X-Forwarded-For: 127.0.0.1
  Host: localhost
--------------------------------------------------
```
