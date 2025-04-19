#!/usr/bin/env python3
"""
CORS Security Scanner Example
----------------------------
Example script demonstrating how to use the CORS Checker module
programmatically or from the command line.
"""

import sys
import argparse
from hhchecker.cors_checker import CORSChecker


def scan_website(url, verbose=False, workers=1):
    """
    Scan a website for CORS vulnerabilities.
    
    Args:
        url: Target URL to scan
        verbose: Enable verbose output
        workers: Number of concurrent workers
        
    Returns:
        Number of vulnerabilities found
    """
    print(f"Starting CORS security scan on {url}...")
    
    # Create custom origins to test
    custom_origins = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        "https://subdomain.example.com",
        "example.com.attacker.com"
    ]
    
    # Initialize the CORS checker
    cors_checker = CORSChecker(
        url=url,
        custom_origins=custom_origins,
        verbose=verbose,
        max_workers=workers
    )
    
    # Run all tests
    results = cors_checker.run_all_tests()
    
    # Return the number of vulnerabilities found
    return len(results["vulnerabilities"])


def main():
    """Main function to handle command line arguments."""
    parser = argparse.ArgumentParser(
        description="CORS Security Scanner Example",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-v", "--verbose", 
                      help="Enable verbose output", 
                      action="store_true")
    parser.add_argument("-w", "--workers", 
                      help="Number of concurrent workers",
                      type=int, default=1)
    
    args = parser.parse_args()
    
    try:
        vuln_count = scan_website(
            url=args.url,
            verbose=args.verbose,
            workers=args.workers
        )
        
        print(f"\nScan completed: Found {vuln_count} CORS vulnerabilities.")
        return vuln_count
    
    except KeyboardInterrupt:
        print("\nScan cancelled by user.")
        return 1
    except Exception as e:
        print(f"Error: {str(e)}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
