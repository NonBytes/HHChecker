#!/usr/bin/env python3
"""
Command-line interface for HHChecker Toolkit.
Provides a unified entry point for all the HHChecker tools.
"""

import sys
import argparse
from typing import List, Optional
from colorama import Fore, Style, init

from hhchecker import __version__
from hhchecker.cors_checker import CORSChecker
from hhchecker.header_checker import check_headers
from hhchecker.utils.common import print_banner, parse_comma_separated

# Initialize colorama
init(autoreset=True)


def create_parser() -> argparse.ArgumentParser:
    """
    Create the main command-line argument parser for HHChecker.
    
    Returns:
        ArgumentParser object with all commands and options configured
    """
    # Main parser
    parser = argparse.ArgumentParser(
        description=f"HHChecker Cybersecurity Assessment Toolkit v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  hhchecker cors-check https://example.com\n"
            "  hhchecker header-check https://example.com --cookies \"session=123\"\n"
        )
    )
    
    parser.add_argument('--version', action='version', 
                        version=f'%(prog)s {__version__}')
    
    # Create subparsers for different tools
    subparsers = parser.add_subparsers(title='commands', dest='command',
                                     help='Tool to run')
    
    # CORS Checker subcommand
    cors_parser = subparsers.add_parser('cors-check', 
                                      help='Check CORS configuration for security issues')
    cors_parser.add_argument('url', help='Target URL to test')
    cors_parser.add_argument('-o', '--origins', 
                           help='Custom origins to test (comma-separated)')
    cors_parser.add_argument('-m', '--methods', 
                           help='Custom HTTP methods to test (comma-separated)')
    cors_parser.add_argument('-H', '--headers', 
                           help='Custom headers to test (comma-separated)')
    cors_parser.add_argument('-v', '--verbose', 
                           help='Enable verbose output', action='store_true')
    cors_parser.add_argument('-j', '--json', 
                           help='Output JSON format only', action='store_true')
    cors_parser.add_argument('-t', '--timeout', 
                           help='Request timeout in seconds', type=int, default=10)
    cors_parser.add_argument('-d', '--delay', 
                           help='Delay between requests in seconds', 
                           type=float, default=0.5)
    cors_parser.add_argument('-w', '--workers', 
                           help='Maximum number of concurrent workers', 
                           type=int, default=1)
    cors_parser.add_argument('--no-verify-ssl', 
                           help='Disable SSL certificate verification', 
                           action='store_true')
    cors_parser.add_argument('--user-agents', 
                           help='File containing user agents to rotate', default=None)
    
    # HTTP Header Checker subcommand
    header_parser = subparsers.add_parser('header-check', 
                                        help='Check HTTP security headers')
    header_parser.add_argument('url', help='Target URL to check')
    header_parser.add_argument('-c', '--cookies', 
                             help='Cookies to include in the request (format: name1=value1; name2=value2)')
    header_parser.add_argument('-t', '--timeout', type=int, default=10,
                             help='Request timeout in seconds')
    header_parser.add_argument('--no-verify', action='store_true',
                             help='Disable SSL certificate verification')
    header_parser.add_argument('-H', '--header', action='append', dest='headers',
                             help='Specific header(s) to check (can be used multiple times)')
    header_parser.add_argument('-l', '--list-headers', action='store_true',
                             help='List all available security headers that can be checked')
    header_parser.add_argument('-p', '--profile', 
                             choices=['simple', 'cookies', 'server_info', 'all', 'all_without_additional'],
                             help='Use a predefined check profile')
    header_parser.add_argument('--skip-additional', action='store_true',
                             help='Skip additional security checks beyond the main headers')
    
    return parser


def handle_cors_check(args: argparse.Namespace) -> int:
    """
    Handle the CORS checker command.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Exit code
    """
    # Process custom inputs
    custom_origins = parse_comma_separated(args.origins) if args.origins else None
    custom_methods = parse_comma_separated(args.methods) if args.methods else None
    custom_headers = parse_comma_separated(args.headers) if args.headers else None
    
    # Load user agents from file if specified
    user_agents = None
    if args.user_agents:
        try:
            with open(args.user_agents, 'r') as f:
                user_agents = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Failed to load user agents file: {e}{Style.RESET_ALL}")
    
    print_banner("CORS Configuration Checker", "standard")
    print(f"Target: {args.url}")
    
    try:
        checker = CORSChecker(
            args.url, 
            custom_origins=custom_origins,
            custom_methods=custom_methods,
            custom_headers=custom_headers,
            verbose=args.verbose,
            timeout=args.timeout,
            delay=args.delay,
            user_agents=user_agents,
            verify_ssl=not args.no_verify_ssl,
            max_workers=args.workers
        )
        
        results = checker.run_all_tests()
        
        if args.json:
            print(json.dumps(results, indent=2))
        
        # Return number of vulnerabilities as exit code
        return len(results["vulnerabilities"])
    
    except ValueError as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        return 1
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")
        return 2


def handle_header_check(args: argparse.Namespace) -> int:
    """
    Handle the HTTP header checker command.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Exit code
    """
    from hhchecker.header_checker import SECURITY_HEADERS, CHECK_PROFILES
    
    # If user just wants to list available headers
    if args.list_headers:
        print("Available security headers to check:")
        for idx, header in enumerate(SECURITY_HEADERS.keys(), 1):
            print(f"{idx}. {header}")
        print("\nAvailable check profiles:")
        print("  simple: Critical headers only (1,2,3,4,7)")
        print("  cookies: Cookie-related headers only")
        print("  server_info: Server technology and fingerprinting checks")
        print("  all: All headers with additional security checks")
        print("  all_without_additional: All headers without additional security checks")
        return 0
    
    print_banner("HTTP Header Security Checker", "standard")
    
    # Process profile to extract specific headers
    specific_headers = args.headers
    skip_additional = args.skip_additional
    
    if args.profile:
        profile_indices = CHECK_PROFILES[args.profile]
        # Empty list means all headers
        if not profile_indices:
            specific_headers = None
            # If all_without_additional profile was selected, set skip_additional
            if args.profile == "all_without_additional":
                skip_additional = True
        else:
            header_list = list(SECURITY_HEADERS.keys())
            specific_headers = [header_list[idx-1] for idx in profile_indices if 1 <= idx <= len(header_list)]
            print(f"Using '{args.profile}' profile: {', '.join(specific_headers)}")
    
    try:
        # Run the header check
        check_headers(
            url=args.url,
            cookies=args.cookies,
            verify_ssl=not args.no_verify,
            timeout=args.timeout,
            specific_headers=specific_headers,
            skip_additional=skip_additional
        )
        return 0
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 130
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main entry point for the HHChecker CLI.
    
    Args:
        argv: Command line arguments (uses sys.argv if None)
        
    Returns:
        Exit code
    """
    parser = create_parser()
    args = parser.parse_args(argv)
    
    if not args.command:
        print_banner("HHChecker Cybersecurity Assessment Toolkit", "double")
        print(f"Version: {__version__}")
        print("For usage information, run: hhchecker --help")
        print("\nAvailable commands:")
        print("  cors-check    - Test CORS configurations for security issues")
        print("  header-check  - Check HTTP security headers")
        return 0
    
    # Execute the appropriate command
    if args.command == 'cors-check':
        return handle_cors_check(args)
    elif args.command == 'header-check':
        return handle_header_check(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    import json
    sys.exit(main())