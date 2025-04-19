# HHChecker: Cybersecurity Assessment Toolkit

HHChecker is a comprehensive cybersecurity assessment toolkit designed to help security professionals identify and remediate web application security vulnerabilities. The toolkit provides specialized tools for assessing CORS configurations, HTTP headers, and other security mechanisms.

## Features

- **CORS Configuration Checker**: Identify misconfigurations in Cross-Origin Resource Sharing (CORS) implementations that could lead to security vulnerabilities
- **HTTP Header Security Checker**: Analyze HTTP security headers to ensure proper security controls are in place
- **Detailed Reporting**: Comprehensive reports with security findings and remediation recommendations
- **Customization Options**: Tailor security checks to specific requirements through various configuration options
- **Multi-threading Support**: Perform checks in parallel for improved performance
- **Color-coded Output**: Easy-to-understand visual feedback with color-coded terminal output

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Installation Steps

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/hhchecker.git
   cd hhchecker
   ```

2. Install the package and dependencies:
   ```
   pip install -e .
   ```

Alternatively, you can install directly from PyPI:
```
pip install hhchecker
```

## Usage

### CORS Configuration Checker

The CORS Configuration Checker tool tests CORS configurations and identifies potential security issues:

```bash
# Basic usage
hhchecker cors-check https://example.com

# With custom origins
hhchecker cors-check https://example.com --origins "https://evil.com,https://attacker.com"

# With multi-threading for faster scanning
hhchecker cors-check https://example.com --workers 5
```

For Python usage:

```python
from hhchecker.cors_checker import CORSChecker

# Initialize the checker
checker = CORSChecker(
    url="https://example.com",
    custom_origins=["https://evil.com", "https://attacker.com"],
    verbose=True,
    max_workers=3
)

# Run all tests
results = checker.run_all_tests()
```

### HTTP Header Security Checker

The HTTP Header Security Checker analyzes HTTP security headers to ensure proper security controls:

```bash
# Basic usage
hhchecker header-check https://example.com

# With cookies
hhchecker header-check https://example.com --cookies "session=abcd1234; token=xyz789"

# Check specific headers only
hhchecker header-check https://example.com --header "Content-Security-Policy" --header "X-Frame-Options"

# Use a predefined check profile
hhchecker header-check https://example.com --profile simple
```

For Python usage:

```python
from hhchecker.header_checker import check_headers

# Check headers
check_headers(
    url="https://example.com",
    cookies="session=abcd1234; token=xyz789",
    verify_ssl=True,
    timeout=10,
    specific_headers=["Content-Security-Policy", "X-Frame-Options"]
)
```

## Security Considerations

- **Responsible Use**: This tool is designed for security professionals, penetration testers, and system administrators to assess the security of their own systems or systems they have permission to test.
- **Legal Compliance**: Always ensure you have proper authorization before testing any system. Unauthorized security testing may be illegal.
- **Rate Limiting**: The tool implements delays between requests to avoid triggering rate limiting or denial of service protections.

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

- Thanks to all the security researchers who have contributed to web security best practices
- Special thanks to the cybersecurity community for continuously improving web security standards
