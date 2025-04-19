#!/usr/bin/env python3
"""
HTTP Header Security Checker
----------------------------
This script checks the security headers of a given URL and allows the user to input 
cookies and verify a custom CORS setting.

Improved with:
- Better input validation
- Robust error handling
- Secure cookie handling
- Improved output formatting
- Command-line arguments support
"""

import sys
import argparse
import re
import urllib.parse
from typing import Dict, Optional, Union, Tuple

# Third-party dependencies
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    from colorama import Fore, Style, init
except ImportError as e:
    print(f"Error: Missing required package - {e}")
    print("Please install required packages: pip install requests colorama")
    sys.exit(1)

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Constants
DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Predefined check profiles
CHECK_PROFILES = {
    "simple": [1, 2, 3, 4, 7, 9],  # Simple check with critical headers
    "cookies": [8],  # Cookie security specific check
    "cors": [9],  # CORS specific check
    "all": [],  # All headers (empty list means all)
    "all_without_additional": []  # All headers but skip additional checks
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Missing or misconfigured. Should be set to 'max-age=31536000; includeSubDomains; preload'",
    "Content-Security-Policy": "Missing. Should be set to prevent XSS and other attacks.",
    "X-Frame-Options": "Missing. Should be 'DENY' or 'SAMEORIGIN' to prevent clickjacking.",
    "X-Content-Type-Options": "Missing. Should be 'nosniff' to prevent MIME type sniffing.",
    "Referrer-Policy": "Missing. Should be 'no-referrer' or 'strict-origin-when-cross-origin' to limit referrer information.",
    "Permissions-Policy": "Missing. Should restrict browser features like camera, microphone, and geolocation.",
    "Cache-Control": "Missing. Should be 'no-store' or 'max-age=0, no-cache, must-revalidate' to control caching.",
    "Set-Cookie": "Secure flag missing in cookies. Should have 'Secure; HttpOnly; SameSite=Strict' or 'Lax'.",
    "Access-Control-Allow-Origin": "Missing or misconfigured. Should be set to a specific trusted domain or 'none' to prevent unauthorized cross-origin access."
}


def validate_url(url: str) -> Tuple[bool, str]:
    """
    Validate URL format and structure.
    
    Args:
        url: URL string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check if URL is empty
    if not url:
        return False, "URL cannot be empty"
    
    # Add https:// prefix if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    # Parse URL to check components
    try:
        parsed = urllib.parse.urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return False, "Invalid URL format. URL must contain a scheme (http/https) and hostname."
        
        # Verify scheme is either http or https
        if parsed.scheme not in ["http", "https"]:
            return False, f"Invalid URL scheme: {parsed.scheme}. Only http and https are supported."
            
        # Make sure there's a valid domain/hostname
        if not re.match(r'^[a-zA-Z0-9][\w\-\.]+\.[a-zA-Z]{2,}', parsed.netloc):
            return False, f"Invalid hostname: {parsed.netloc}"
            
        return True, url
        
    except Exception as e:
        return False, f"URL parsing error: {str(e)}"


def parse_cookie_string(cookie_str: str) -> Dict[str, str]:
    """
    Parse cookie string into a dictionary and check for potential issues.
    
    Args:
        cookie_str: String of cookies in format "name1=value1; name2=value2"
        
    Returns:
        Dictionary of cookies or empty dict if none provided
    """
    if not cookie_str:
        return {}
    
    cookie_dict = {}
    try:
        # Split on semicolon, then on equals for each cookie
        for cookie in cookie_str.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookie_dict[name] = value
            else:
                # Handle malformed cookies
                print(Fore.YELLOW + f"Warning: Skipping malformed cookie: {cookie}" + Style.RESET_ALL)
        
        return cookie_dict
    except Exception as e:
        print(Fore.YELLOW + f"Warning: Error parsing cookies: {str(e)}" + Style.RESET_ALL)
        return {}


def validate_cors_origin(origin: str) -> Tuple[bool, str]:
    """
    Validate CORS origin format.
    
    Args:
        origin: CORS origin string
        
    Returns:
        Tuple of (is_valid, error_message or origin)
    """
    if not origin:
        return True, ""
    
    # Add https:// prefix if missing
    if not origin.startswith(("http://", "https://")):
        origin = "https://" + origin
    
    try:
        parsed = urllib.parse.urlparse(origin)
        if not all([parsed.scheme, parsed.netloc]):
            return False, "Invalid CORS origin format. Must contain a scheme (http/https) and hostname."
            
        return True, origin
    except Exception as e:
        return False, f"CORS origin parsing error: {str(e)}"


def check_headers(url: str, cookies: Optional[str] = None, custom_cors: Optional[str] = None, 
                  verify_ssl: bool = True, timeout: int = DEFAULT_TIMEOUT, 
                  specific_headers: Optional[list] = None, skip_additional: bool = False) -> None:
    """
    Check and analyze security headers for a given URL.
    
    Args:
        url: Target URL to check
        cookies: Optional cookie string 
        custom_cors: Optional expected CORS value
        verify_ssl: Whether to verify SSL certificates
        timeout: Request timeout in seconds
    """
    # Validate URL
    url_valid, url_result = validate_url(url)
    if not url_valid:
        print(Fore.RED + f"Error: {url_result}" + Style.RESET_ALL)
        return
    url = url_result
    
    # Validate CORS origin if provided
    if custom_cors:
        cors_valid, cors_result = validate_cors_origin(custom_cors)
        if not cors_valid:
            print(Fore.RED + f"Error: {cors_result}" + Style.RESET_ALL)
            return
        custom_cors = cors_result
    
    # Prepare headers
    headers = {
        "User-Agent": DEFAULT_USER_AGENT
    }
    
    # Process cookies if provided
    if cookies:
        cookie_dict = parse_cookie_string(cookies)
        if cookie_dict:
            # We don't want to modify the original cookie string provided by user
            # Instead we'll use it as-is for the "Cookie" header
            headers["Cookie"] = cookies
    
    # Add Origin header for CORS testing if provided
    if custom_cors:
        headers["Origin"] = custom_cors
    
    # Disable SSL warnings if verification is disabled
    if not verify_ssl:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        print(Fore.YELLOW + "Warning: SSL certificate verification disabled!" + Style.RESET_ALL)
    
    try:
        print(f"Checking security headers for: {url}")
        print(f"Timeout: {timeout} seconds")
        
        response = requests.get(
            url, 
            headers=headers, 
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False  # Don't follow redirects automatically
        )
        
        # Check if there's a redirect
        if response.status_code in (301, 302, 303, 307, 308):
            redirect_url = response.headers.get('Location', '')
            print(Fore.YELLOW + f"Redirect detected: {response.status_code} -> {redirect_url}" + Style.RESET_ALL)
            print(Fore.YELLOW + "To follow redirects, run the tool against the redirect URL directly." + Style.RESET_ALL)
        
        response_headers = response.headers
        
        print("\nResponse Status Code:", response.status_code)
        print("\nReceived Headers:")
        # Get all security header names (case-insensitive) for green highlighting
        security_header_names = [h.lower() for h in SECURITY_HEADERS.keys()]
        
        for key, value in response_headers.items():
            # Determine if this is a security header that should be highlighted
            is_security_header = key.lower() in security_header_names
            
            # Check if the header value appears to be properly configured
            is_properly_configured = False
            
            if is_security_header:
                # Evaluate common security headers based on their values
                if key.lower() == "strict-transport-security" and "max-age" in value.lower():
                    is_properly_configured = True
                elif key.lower() == "content-security-policy" and not key.lower().endswith("report-only"):
                    is_properly_configured = True
                elif key.lower() == "x-frame-options" and value.upper() in ["DENY", "SAMEORIGIN"]:
                    is_properly_configured = True
                elif key.lower() == "x-content-type-options" and value.lower() == "nosniff":
                    is_properly_configured = True
                elif key.lower() == "referrer-policy" and value.lower() in ["no-referrer", "strict-origin-when-cross-origin"]:
                    is_properly_configured = True
                elif key.lower() == "permissions-policy" and len(value) > 5:  # Basic check that it's not empty
                    is_properly_configured = True
                elif key.lower() == "cache-control" and any(x in value.lower() for x in ["no-store", "no-cache", "must-revalidate"]):
                    is_properly_configured = True
                elif key.lower() == "set-cookie" and all(x in value for x in ["Secure", "HttpOnly"]):
                    is_properly_configured = True
                elif key.lower() == "access-control-allow-origin" and value != "*":
                    is_properly_configured = True
            
            # Mask sensitive data in cookies
            if key.lower() == "set-cookie":
                # Only show security-related parts of cookies, mask values
                masked_value = re.sub(r'=([^;])+', '=[MASKED]', value)
                if is_properly_configured:
                    print(Fore.GREEN + f"{key}: {masked_value}" + Style.RESET_ALL)
                else:
                    print(f"{key}: {masked_value}")
            else:
                # Print with green highlight if it's a properly configured security header
                if is_security_header and is_properly_configured:
                    print(Fore.GREEN + f"{key}: {value}" + Style.RESET_ALL)
                else:
                    print(f"{key}: {value}")
        
        print("\nSecurity Check Results:")
        
        # Filter headers if specific ones were requested
        headers_to_check = SECURITY_HEADERS
        if specific_headers:
            headers_to_check = {header: SECURITY_HEADERS[header] for header in specific_headers 
                              if header in SECURITY_HEADERS}
            print(f"Checking {len(headers_to_check)} specific header(s): {', '.join(headers_to_check.keys())}")
        
        for header, recommendation in headers_to_check.items():
            header_lower = header.lower()
            
            # Check if header exists (case-insensitive)
            header_exists = False
            header_value = ""
            for resp_header, resp_value in response_headers.items():
                if resp_header.lower() == header_lower:
                    header_exists = True
                    header_value = resp_value
                    break
            
            if not header_exists:
                print(Fore.RED + f"[!] {header} - {recommendation}" + Style.RESET_ALL)
            
            # Special checks for specific headers
            elif header == "Strict-Transport-Security" and "max-age" not in header_value.lower():
                print(Fore.RED + f"[!] {header} - Incorrectly configured. {recommendation}" + Style.RESET_ALL)
            
            elif header == "Set-Cookie":
                # Check for secure cookies flag
                if "Secure" not in header_value:
                    print(Fore.RED + f"[!] {header} - Secure flag missing in cookies. {recommendation}" + Style.RESET_ALL)
                # Check for HttpOnly flag
                elif "HttpOnly" not in header_value:
                    print(Fore.RED + f"[!] {header} - HttpOnly flag missing in cookies. {recommendation}" + Style.RESET_ALL)
                # Check for SameSite attribute
                elif "SameSite" not in header_value:
                    print(Fore.RED + f"[!] {header} - SameSite attribute missing in cookies. {recommendation}" + Style.RESET_ALL)
                else:
                    print(Fore.GREEN + f"[+] {header} is properly configured." + Style.RESET_ALL)
            
            elif header == "Access-Control-Allow-Origin":
                if custom_cors and header_value != custom_cors:
                    print(Fore.RED + f"[!] {header} - Expected '{custom_cors}' but received '{header_value}'. {recommendation}" + Style.RESET_ALL)
                elif header_value == "*":
                    print(Fore.RED + f"[!] {header} - Wildcard '*' is insecure. {recommendation}" + Style.RESET_ALL)
                else:
                    print(Fore.GREEN + f"[+] {header} is properly configured." + Style.RESET_ALL)
            
            elif header == "Content-Security-Policy":
                # Check if it's only report-only mode
                if not header_exists and "content-security-policy-report-only" in [h.lower() for h in response_headers.keys()]:
                    print(Fore.YELLOW + f"[!] {header} - Only Content-Security-Policy-Report-Only is set. Consider implementing enforced CSP." + Style.RESET_ALL)
                else:
                    print(Fore.GREEN + f"[+] {header} is properly configured." + Style.RESET_ALL)
            
            else:
                print(Fore.GREEN + f"[+] {header} is properly configured." + Style.RESET_ALL)
        
        # Additional checks for other security issues
        # Only run if checking all headers or if specific headers include any additional check headers
        # Skip if skip_additional flag is set
        if not skip_additional and (not specific_headers or any(header in ["X-XSS-Protection", "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"] for header in specific_headers)):
            print("\nAdditional Security Checks:")
            
            # Check for X-XSS-Protection header
            if not specific_headers or "X-XSS-Protection" in specific_headers:
                xss_protection = response_headers.get("X-XSS-Protection", "")
                if xss_protection == "0":
                    print(Fore.GREEN + "[+] X-XSS-Protection is correctly disabled (modern browsers use CSP instead)." + Style.RESET_ALL)
                elif xss_protection:
                    print(Fore.YELLOW + f"[!] X-XSS-Protection is set to '{xss_protection}'. Consider disabling it ('0') and using CSP instead." + Style.RESET_ALL)
            
            # Check for Server header information leakage
            if not specific_headers or "Server" in specific_headers:
                if "Server" in response_headers:
                    server_header = response_headers["Server"]
                    if server_header and len(server_header) > 1:
                        print(Fore.YELLOW + f"[!] Server header reveals information: '{server_header}'. Consider removing or genericizing." + Style.RESET_ALL)
            
            # Check for X-Powered-By information leakage
            if not specific_headers or "X-Powered-By" in specific_headers:
                if "X-Powered-By" in response_headers:
                    powered_by = response_headers["X-Powered-By"]
                    print(Fore.YELLOW + f"[!] X-Powered-By header reveals information: '{powered_by}'. Consider removing." + Style.RESET_ALL)
                    
            # Check for ASP.NET version information leakage
            if "X-AspNet-Version" in response_headers:
                aspnet_version = response_headers["X-AspNet-Version"]
                print(Fore.YELLOW + f"[!] X-AspNet-Version header reveals framework version: '{aspnet_version}'. Consider removing." + Style.RESET_ALL)
                
            if "X-AspNetMvc-Version" in response_headers:
                aspnetmvc_version = response_headers["X-AspNetMvc-Version"]
                print(Fore.YELLOW + f"[!] X-AspNetMvc-Version header reveals framework version: '{aspnetmvc_version}'. Consider removing." + Style.RESET_ALL)
            
            # Check for HSTS preload eligibility if HSTS is enabled
            if "Strict-Transport-Security" in response_headers:
                hsts_header = response_headers["Strict-Transport-Security"]
                if "includeSubDomains" not in hsts_header:
                    print(Fore.YELLOW + "[!] HSTS header does not include 'includeSubDomains' directive. Consider adding for better security." + Style.RESET_ALL)
                if "preload" not in hsts_header:
                    print(Fore.YELLOW + "[!] HSTS header does not include 'preload' directive. Consider adding for HSTS preloading eligibility." + Style.RESET_ALL)
                    
                # Check for adequate max-age value
                max_age_match = re.search(r'max-age=(\d+)', hsts_header)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 10886400:  # 126 days
                        print(Fore.YELLOW + f"[!] HSTS max-age ({max_age} seconds) is less than recommended minimum of 126 days (10886400 seconds)." + Style.RESET_ALL)
            
            # Check for Feature-Policy/Permissions-Policy
            if "Feature-Policy" in response_headers and "Permissions-Policy" in response_headers:
                print(Fore.YELLOW + "[!] Both Feature-Policy and Permissions-Policy headers are present. Feature-Policy is deprecated, consider using only Permissions-Policy." + Style.RESET_ALL)
            elif "Feature-Policy" in response_headers and "Permissions-Policy" not in response_headers:
                print(Fore.YELLOW + "[!] Feature-Policy header is deprecated. Consider using Permissions-Policy instead." + Style.RESET_ALL)
            
            # Check for Cross-Origin-Resource-Policy
            if "Cross-Origin-Resource-Policy" not in response_headers:
                print(Fore.YELLOW + "[!] Cross-Origin-Resource-Policy header is missing. Consider setting it to 'same-origin', 'same-site', or 'cross-origin'." + Style.RESET_ALL)
            
            # Check for Cross-Origin-Embedder-Policy
            if "Cross-Origin-Embedder-Policy" not in response_headers:
                print(Fore.YELLOW + "[!] Cross-Origin-Embedder-Policy header is missing. Consider setting it to 'require-corp' for enhanced security isolation." + Style.RESET_ALL)
            
            # Check for Cross-Origin-Opener-Policy
            if "Cross-Origin-Opener-Policy" not in response_headers:
                print(Fore.YELLOW + "[!] Cross-Origin-Opener-Policy header is missing. Consider setting it to 'same-origin' to isolate browsing context." + Style.RESET_ALL)
            
            # Check for Cache-Control no-cache vs no-store
            if "Cache-Control" in response_headers:
                cache_header = response_headers["Cache-Control"]
                if "no-cache" in cache_header and "no-store" not in cache_header:
                    print(Fore.YELLOW + "[!] Cache-Control uses 'no-cache' but not 'no-store'. For sensitive data, consider adding 'no-store'." + Style.RESET_ALL)
            
            # Check for Public-Key-Pins header (deprecated)
            if "Public-Key-Pins" in response_headers:
                print(Fore.YELLOW + "[!] Public-Key-Pins header is deprecated and may not be supported by browsers. Consider removing." + Style.RESET_ALL)
            
            # Check for X-DNS-Prefetch-Control
            if "X-DNS-Prefetch-Control" not in response_headers:
                print(Fore.YELLOW + "[!] X-DNS-Prefetch-Control header is missing. Consider setting to 'off' to prevent privacy leakage or 'on' for performance." + Style.RESET_ALL)
            
            # Check for CSP implementation
            if "Content-Security-Policy" in response_headers:
                csp = response_headers["Content-Security-Policy"]
                
                # Check for unsafe CSP directives
                if "unsafe-inline" in csp:
                    print(Fore.YELLOW + "[!] Content-Security-Policy contains 'unsafe-inline', which weakens XSS protections." + Style.RESET_ALL)
                if "unsafe-eval" in csp:
                    print(Fore.YELLOW + "[!] Content-Security-Policy contains 'unsafe-eval', which weakens XSS protections." + Style.RESET_ALL)
                
                # Check if default-src is defined
                if "default-src" not in csp:
                    print(Fore.YELLOW + "[!] Content-Security-Policy should define 'default-src' as a fallback." + Style.RESET_ALL)
                
                # Check if report-uri/report-to is defined
                if "report-uri" not in csp and "report-to" not in csp:
                    print(Fore.YELLOW + "[!] Content-Security-Policy should include 'report-uri' or 'report-to' for violation reporting." + Style.RESET_ALL)
            
            # Check if security.txt is available
            if url.startswith(("http://", "https://")):
                try:
                    # Extract domain without path
                    parsed_url = urllib.parse.urlparse(url)
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    
                    # Check both locations for security.txt as per RFC 9116
                    well_known_url = f"{base_url}/.well-known/security.txt"
                    root_url = f"{base_url}/security.txt"
                    
                    # Try the .well-known location first
                    sec_txt_response = requests.get(well_known_url, timeout=timeout//2, verify=verify_ssl)
                    if sec_txt_response.status_code != 200:
                        # Try the root location
                        sec_txt_response = requests.get(root_url, timeout=timeout//2, verify=verify_ssl)
                    
                    if sec_txt_response.status_code == 200:
                        print(Fore.GREEN + "[+] security.txt file found. Good practice for security researchers to contact you." + Style.RESET_ALL)
                    else:
                        print(Fore.YELLOW + "[!] security.txt file not found. Consider adding one as per RFC 9116." + Style.RESET_ALL)
                except requests.RequestException:
                    # Silently ignore any errors when checking for security.txt
                    pass
        
    except requests.exceptions.SSLError as e:
        print(Fore.RED + f"SSL Error: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + "Try running with --no-verify if you want to ignore SSL certificate issues" + Style.RESET_ALL)
    
    except requests.exceptions.ConnectionError as e:
        print(Fore.RED + f"Connection Error: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + "Check if the URL is correct and the server is reachable" + Style.RESET_ALL)
    
    except requests.exceptions.Timeout as e:
        print(Fore.RED + f"Timeout Error: Request timed out after {timeout} seconds" + Style.RESET_ALL)
        print(Fore.YELLOW + "Try increasing the timeout with --timeout parameter" + Style.RESET_ALL)
    
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Request Error: {e}" + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"Unexpected error: {e}" + Style.RESET_ALL)


def main():
    """Main function to handle command line arguments and run the tool."""
    parser = argparse.ArgumentParser(
        description="HTTP Header Security Checker",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("url", nargs="?", 
                        help="URL to check (if not specified, will prompt for input)")
    
    parser.add_argument("-c", "--cookies", 
                        help="Cookies to include in the request (format: name1=value1; name2=value2)")
    
    parser.add_argument("-o", "--origin", 
                        help="Expected CORS origin value for testing")
    
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL certificate verification")
    
    parser.add_argument("-H", "--header", action="append", dest="headers",
                        help="Specific header(s) to check (can be used multiple times). If not specified, all security headers will be checked")
    
    parser.add_argument("-l", "--list-headers", action="store_true",
                        help="List all available security headers that can be checked")
    
    parser.add_argument("-p", "--profile", choices=list(CHECK_PROFILES.keys()),
                        help="Use a predefined check profile (simple: critical headers only, cookies: cookie-related only, cors: CORS-related only, all: all headers, all_without_additional: all headers without additional checks)")
    
    parser.add_argument("--skip-additional", action="store_true",
                        help="Skip additional security checks beyond the main headers")
    
    args = parser.parse_args()
    
    # If user just wants to list available headers
    if args.list_headers:
        print("Available security headers to check:")
        for idx, header in enumerate(SECURITY_HEADERS.keys(), 1):
            print(f"{idx}. {header}")
        print("\nAvailable check profiles:")
        print("  simple: Critical headers only (1,2,3,4,7,9)")
        print("  cookies: Cookie-related headers only")
        print("  cors: CORS-related headers only")
        print("  all: All headers with additional security checks")
        print("  all_without_additional: All headers without additional security checks")
        sys.exit(0)
    
    url = args.url
    cookies = args.cookies
    custom_cors = args.origin
    verify_ssl = not args.no_verify
    timeout = args.timeout
    specific_headers = args.headers
    profile = args.profile
    skip_additional = args.skip_additional
    
    # If a profile was selected, convert to specific headers
    if profile:
        profile_indices = CHECK_PROFILES[profile]
        # Empty list means all headers
        if not profile_indices:
            specific_headers = None
            # If all_without_additional profile was selected, set skip_additional
            if profile == "all_without_additional":
                skip_additional = True
        else:
            header_list = list(SECURITY_HEADERS.keys())
            specific_headers = [header_list[idx-1] for idx in profile_indices if 1 <= idx <= len(header_list)]
            print(f"Using '{profile}' profile: {', '.join(specific_headers)}")
    
    # If URL not provided as argument, prompt for it
    if not url:
        url = input("Enter the URL to check: ").strip()
    
    # If cookies not provided as argument, prompt for it
    if cookies is None:  # Check for None because empty string is valid
        cookies = input("Enter cookies (if any, else press Enter to skip): ").strip()
        cookies = cookies if cookies else None
    
    # If CORS origin not provided as argument, prompt for it
    if custom_cors is None:  # Check for None because empty string is valid
        custom_cors = input("Enter expected CORS value (if any, else press Enter to skip): ").strip()
        custom_cors = custom_cors if custom_cors else None
    
    # If specific headers not provided, ask if user wants to check specific headers
    if specific_headers is None and not profile:
        print("\nCheck options:")
        print("1. All headers with additional checks (comprehensive)")
        print("2. All headers without additional checks")
        print("3. Simple check (critical headers only)")
        print("4. Custom headers (specify which to check)")
        
        check_option = input("Select an option (1-4, default: 1): ").strip()
        
        if check_option == "2":
            # All headers but skip additional checks
            skip_additional = True
            print("Checking all security headers without additional security checks")
        elif check_option == "3":
            # Use simple profile
            profile_indices = CHECK_PROFILES["simple"]
            header_list = list(SECURITY_HEADERS.keys())
            specific_headers = [header_list[idx-1] for idx in profile_indices if 1 <= idx <= len(header_list)]
            print(f"Using simple check profile: {', '.join(specific_headers)}")
        elif check_option == "4":
            print("\nAvailable headers:")
            for idx, header in enumerate(SECURITY_HEADERS.keys(), 1):
                print(f"{idx}. {header}")
            
            header_input = input("Enter header numbers separated by comma (e.g., 1,3,5): ").strip()
            if header_input:
                try:
                    # Convert input numbers to actual header names
                    header_indices = [int(x.strip()) for x in header_input.split(',')]
                    header_list = list(SECURITY_HEADERS.keys())
                    specific_headers = []
                    for idx in header_indices:
                        if 1 <= idx <= len(header_list):
                            specific_headers.append(header_list[idx-1])
                        else:
                            print(f"Warning: Invalid header number {idx}, skipping")
                except ValueError:
                    print("Invalid input format. Checking all headers.")
                    specific_headers = None
            
            # Ask about additional checks
            run_additional = input("Include additional security checks? (y/n, default: y): ").strip().lower()
            if run_additional == 'n':
                skip_additional = True
    
    # Run the security check
    check_headers(url, cookies, custom_cors, verify_ssl, timeout, specific_headers, skip_additional)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
