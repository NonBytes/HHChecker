# HTTP Header Security Check

## Overview
This project is a Python-based tool for checking HTTP security headers of a given URL. It allows users to input cookies and verify a custom CORS setting, helping to identify missing or misconfigured security headers.

## Features
- Checks for essential security headers, including:
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - Cache-Control
  - Set-Cookie security flags
  - Access-Control-Allow-Origin (CORS)
- Allows users to provide cookies for authentication-based scans.
- Supports custom expected CORS values to validate configurations.
- Uses color-coded output to highlight issues and properly configured headers.

## Prerequisites
Ensure you have the following dependencies installed:
```sh
pip install requests colorama
```

## Usage
1. Run the script in a Jupyter Notebook or as a standalone Python script:
   ```sh
   python script.py
   ```
2. Enter the target URL when prompted.
3. Optionally, enter cookies and an expected CORS value if needed.
4. Review the security analysis output.

## Running in Jupyter Notebook
If you prefer to run this in Jupyter Notebook:
1. Open the `.ipynb` file.
2. Execute the first cell to load the function.
3. Run the second cell to enter the required inputs and check the headers.

## Example Output
```
Checking security headers for: https://example.com

Received Headers:
Content-Type: text/html; charset=UTF-8
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY

Security Check Results:
[+] Strict-Transport-Security is properly configured.
[+] X-Frame-Options is properly configured.
[!] Content-Security-Policy - Missing. Should be set to prevent XSS and other attacks.
[!] Referrer-Policy - Missing. Should be 'no-referrer' or 'strict-origin-when-cross-origin' to limit referrer information.
...
```

## License
This project is open-source and available for use and modification under the MIT License.

## Author
Developed by [Your Name]. Feel free to contribute and suggest improvements!

