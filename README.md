# HTTP Header Security Checker

A comprehensive Python tool for analyzing and validating security headers in HTTP responses. This tool helps security professionals and developers identify missing or misconfigured security headers that could leave web applications vulnerable to attacks.

![Security Headers Check](https://img.shields.io/badge/Security-Headers%20Check-brightgreen)
![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- 🔍 Checks for essential security headers (HSTS, CSP, X-Frame-Options, etc.)
- 🔒 Validates proper configuration of existing headers
- 🍪 Analyzes cookie security attributes
- 🌐 Tests CORS implementations
- 📊 Color-coded output for easy analysis
- ⚙️ Customizable checks with profiles and header selection
- 🧩 Extensive error handling and input validation

## Installation

```bash
# Clone the repository
git clone https://github.com/NonBytes/HHChecker.git
cd HHChecker

# Install required packages
pip install requests colorama
```

## Usage

### Basic Usage

```bash
python hhchecker.py <url>
```

### Command Line Arguments

```
usage: hhchecker.py [-h] [-c COOKIES] [-o ORIGIN] [-t TIMEOUT] [--no-verify]
                                      [-H HEADERS] [-l] [-p {simple,cookies,cors,all,all_without_additional}]
                                      [--skip-additional] [url]

HTTP Header Security Checker

positional arguments:
  url                   URL to check (if not specified, will prompt for input)

options:
  -h, --help            show this help message and exit
  -c COOKIES, --cookies COOKIES
                        Cookies to include in the request (format: name1=value1; name2=value2)
  -o ORIGIN, --origin ORIGIN
                        Expected CORS origin value for testing
  -t TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds (default: 10)
  --no-verify           Disable SSL certificate verification
  -H HEADERS, --header HEADERS
                        Specific header(s) to check (can be used multiple times)
  -l, --list-headers    List all available security headers that can be checked
  -p {simple,cookies,cors,all,all_without_additional}, --profile {simple,cookies,cors,all,all_without_additional}
                        Use a predefined check profile
  --skip-additional     Skip additional security checks beyond the main headers
```

### Examples

#### Check all security headers for a website:
```bash
python hhhchecker.py https://example.com
```

#### Check only specific headers:
```bash
python hhhchecker.py https://example.com -H "Content-Security-Policy" -H "X-Frame-Options"
```

#### Use a predefined profile:
```bash
python hhhchecker.py https://example.com -p simple
```

#### Check with cookies:
```bash
python hhhchecker.py https://example.com -c "session=abc123; user=john"
```

#### Test CORS implementation:
```bash
python hhhchecker.py https://api.example.com -o "https://trusted-site.com"
```

## Security Headers Checked

| Header | Description | Recommendation |
|--------|-------------|----------------|
| Strict-Transport-Security | Enforces HTTPS connections | `max-age=31536000; includeSubDomains; preload` |
| Content-Security-Policy | Controls resources the browser is allowed to load | Site-specific policy to prevent XSS |
| X-Frame-Options | Prevents clickjacking attacks | `DENY` or `SAMEORIGIN` |
| X-Content-Type-Options | Prevents MIME-sniffing | `nosniff` |
| Referrer-Policy | Controls referrer information | `no-referrer` or `strict-origin-when-cross-origin` |
| Permissions-Policy | Restricts browser features | Site-specific policy |
| Cache-Control | Controls browser caching | `no-store` or appropriate caching policy |
| Set-Cookie | Cookie attributes | `Secure; HttpOnly; SameSite=Strict` |
| Access-Control-Allow-Origin | CORS implementation | Specific trusted domain, not `*` |

## Additional Checks

The tool also performs these additional security checks:

- Deprecated security headers (X-XSS-Protection, Public-Key-Pins)
- Information leakage via Server and X-Powered-By headers
- Framework version disclosure (X-AspNet-Version, etc.)
- HSTS preload eligibility
- CSP implementation quality (unsafe-inline, unsafe-eval usage)
- Cross-Origin Resource isolation headers
- Security.txt file availability

## Predefined Check Profiles

- `simple`: Critical headers only (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Cache-Control, CORS)
- `cookies`: Cookie-related headers only
- `cors`: CORS-related headers only
- `all`: All headers with additional security checks
- `all_without_additional`: All headers without additional security checks

## Output Example

```
Checking security headers for: https://example.com
Timeout: 10 seconds

Response Status Code: 200

Received Headers:
Server: nginx
Date: Wed, 19 Apr 2023 12:34:56 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 12345
Connection: keep-alive
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
Cache-Control: no-store, must-revalidate
Set-Cookie: session=[MASKED]; HttpOnly; Secure; SameSite=Lax

Security Check Results:
[+] Strict-Transport-Security is properly configured.
[+] Content-Security-Policy is properly configured.
[+] X-Frame-Options is properly configured.
[+] X-Content-Type-Options is properly configured.
[+] Referrer-Policy is properly configured.
[+] Permissions-Policy is properly configured.
[+] Cache-Control is properly configured.
[+] Set-Cookie is properly configured.
[!] Access-Control-Allow-Origin - Missing or misconfigured. Should be set to a specific trusted domain or 'none' to prevent unauthorized cross-origin access.

Additional Security Checks:
[+] security.txt file found. Good practice for security researchers to contact you.
```

## Use Cases

- 🔒 Security audits and penetration testing
- 🛡️ DevSecOps pipeline integration
- 🔍 Continuous security monitoring
- 📋 Compliance verification
- 🎓 Security education and awareness

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OWASP Secure Headers Project
- Mozilla Observatory
- SecurityHeaders.com
