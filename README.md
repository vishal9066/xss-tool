# XSS Detection Tool

**XSS Detection Tool** is an advanced, multi-threaded tool designed to detect Cross-Site Scripting (XSS) vulnerabilities in web applications. It supports testing for reflection of special characters, injecting XSS payloads, and generating direct links for vulnerable parameters. The tool is highly configurable and optimized for both speed and precision.

---

## Features

- **Special Character Reflection Testing:** Detects reflection of special characters like `<`, `>`, `'`, `"`, etc.
- **XSS Payload Testing:** Tests for XSS vulnerabilities using a wide range of payloads, including encoded and advanced payloads.
- **Parallel Processing:** Uses multi-threading to speed up the testing process.
- **Custom Payloads:** Supports custom payloads via a wordlist file.
- **Reflection-Only Mode:** Only tests for reflection of special characters without injecting payloads.
- **No-Reflection Mode:** Skips reflection testing and only tests for XSS vulnerabilities.
- **Direct Link Generation:** Generates direct links for vulnerable `GET` parameters.
- **User-Agent Rotation:** Rotates user-agent strings to avoid detection.

---

## Installation

Ensure you have Python 3.7 or higher installed.

Clone the repository using:

```bash
https://github.com/vishal9066/xss-tool.git
cd xss-tool
```

Install dependencies using:

```bash
pip install requests beautifulsoup4
```

## Usage

To run the tool:

```bash
python xss_tool.py -u <url> -p <parameters> [options]
```

## Options

| Option | Description | Default |
|---|---|---|
| `-u`, `--url` | Target URL to test for XSS vulnerabilities. Required. | N/A |
| `-p`, `--params` | Parameters to test (e.g., `username email`). Required. | N/A |
| `--method` | HTTP method to use (`GET` or `POST`). | `GET` |
| `--wordlist` | Path to a custom XSS payload wordlist file. | None |
| `--delay` | Delay (in seconds) between requests to handle rate limiting. | `300` |
| `-r`, `--reflection-only` | Only test for reflection of special characters, skip XSS payload testing. | None |
| `-nr`, `--no-reflection` | Skip reflection testing and only test for XSS vulnerabilities. | None |
| `-h`, `--help` | Show help message and usage instructions. | N/A |


## Examples
### Basic Usage

1. Test a URL for XSS vulnerabilities:

```bash
python xss_tool.py -u https://example.com/page -p username email
```

2. Reflection-Only Mode

Only test for reflection of special characters:

```bash
python xss_tool.py -u https://example.com/page -p username --reflection-only
```

3. No-Reflection Mode

Skip reflection testing and only test for XSS vulnerabilities:

```bash
python xss_tool.py -u https://example.com/page -p username --no-reflection
```

4. Use a Custom Wordlist

Test with a custom list of XSS payloads:

```bash
python xss_tool.py -u https://example.com/page -p username --wordlist payloads.txt
```

5. Test with POST Method

Test a URL using the POST method:

```bash
python xss_tool.py -u https://example.com/page -p username --method POST
```

6. Set a Custom Delay

Set a custom delay between requests:

```bash
python xss_tool.py -u https://example.com/page -p username --delay 10
```

### Notes
- **POST Parameters:** For POST requests, XSS vulnerabilities are less common in the backend. If a payload is injected, manually check the application's UI (e.g., forms, input fields, or output pages) to verify if the payload is reflected or executed.
- **Reflection Testing:** The tool first tests for reflection of special characters. If reflection is detected, it proceeds to test XSS payloads (unless `--reflection-only` is specified).
- **Direct Links:** For `GET` requests, the tool generates direct links for vulnerable parameters.
- **Custom Payloads:** Provide a custom wordlist file with one payload per line for advanced testing.
- **Rate Limiting:** Use `--delay` to avoid server rate-limiting issues.

---

#### License
Copyright (C) Vishal (vishalatinfosec@gmail.com)

This project is licensed under the GNU General Public License v3.0 License.

---

#### Author
Developed by [Vishal].

---

### Contributing
Contributions, feature requests, and bug reports are welcome! Submit a pull request or open an issue.

---
