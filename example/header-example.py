#!/usr/bin/env python3
"""
HTTP Security Headers Scanner Example
------------------------------------
Example script demonstrating how to use the HTTP Header Checker module
programmatically or from the command line.
"""

import sys
import argparse
from hhchecker.header_checker import check_headers


def check_security_headers(
    url, 
    cookies=None, 
    timeout=10, 
    verify_ssl=True, 
    specific_headers=None,
    skip_additional=False
):
    """
    Check the security headers of a website.
    
    Args:
        url: Target URL to check
        cookies: Optional cookie string
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        specific_headers: Optional list of specific headers to check
        skip_additional: Whether to skip additional security checks
    """
    print(f"Starting HTTP security header analysis on {url}...")
    
    # Sample headers to check - critical headers for web security
    if specific_headers is None:
        specific_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]
    
    # Run the header check
    check_headers(
        url=url,
        cookies=cookies,
        verify_ssl=verify_ssl,
        timeout=timeout,
        specific_headers=specific_headers,
        skip_additional=skip_additional
    )


def main():
    """Main function to handle command line arguments."""
    parser = argparse.ArgumentParser(
        description="HTTP Security Headers Scanner Example",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("url", help="Target URL to check")
    parser.add_argument("-c", "--cookies", 
                      help="Cookies to include in the request (format: name1=value1; name2=value2)",
                      default=None)
    parser.add_argument("-t", "--timeout", 
                      help="Request timeout in seconds",
                      type=int, default=10)
    parser.add_argument("--no-verify", 
                      help="Disable SSL certificate verification",
                      action="store_true")
    parser.add_argument("--check-all", 
                      help="Check all security headers (not just critical ones)",
                      action="store_true")
    parser.add_argument("--skip-additional", 
                      help="Skip additional security checks beyond the main headers",
                      action="store_true")
    
    args = parser.parse_args()
    
    try:
        # If check_all is True, we'll pass None to check all headers
        specific_headers = None if args.check_all else [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]
        
        check_security_headers(
            url=args.url,
            cookies=args.cookies,
            timeout=args.timeout,
            verify_ssl=not args.no_verify,
            specific_headers=specific_headers,
            skip_additional=args.skip_additional
        )
        return 0
    
    except KeyboardInterrupt:
        print("\nCheck cancelled by user.")
        return 1
    except Exception as e:
        print(f"Error: {str(e)}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
