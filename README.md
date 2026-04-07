# 403bypasser

## Description

**403bypasser** is a tool designed to perform bypass testing on web pages that return an HTTP 403 Forbidden status code. Through techniques like HTTP Method fuzzing, HTTP Header fuzzing, Changing HTTP protocol version and Path fuzzing, it attempts to bypass restrictions set on URLs and identify vulnerabilities in misconfigured systems or security flaws.

### Main Features:
- Tests **HTTP Methods** (GET, POST, PUT, etc.).
- Tests **HTTP Headers** with common values used in bypass attacks.
- Tests **URL Normalization**
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

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
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

- Wordlist scanning:

  ```bash
  python3 403bypasser.py https://example.com -w paths.txt -t 30
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
  
### Demo

<img width="2410" height="1310" alt="image" src="https://github.com/user-attachments/assets/05acaa13-5f9c-4696-b836-21c92a81cc36" />

