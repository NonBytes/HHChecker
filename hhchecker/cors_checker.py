#!/usr/bin/env python3
"""
CORS Configuration Checker
--------------------------
A tool to test Cross-Origin Resource Sharing (CORS) configurations of web applications
and identify potential security vulnerabilities.

Enhanced with additional security features, improved error handling, and automatic URL prefix handling.
"""

import requests
import argparse
import sys
import json
import time
import logging
import random
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urlparse
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor

# Initialize colorama for cross-platform colored terminal output
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('cors_checker.log')
    ]
)
logger = logging.getLogger('cors_checker')

class CORSChecker:
    """Class to test CORS configurations and identify security issues."""
    
    def __init__(
        self, 
        url: str, 
        custom_origins: Optional[List[str]] = None, 
        custom_headers: Optional[List[str]] = None, 
        custom_methods: Optional[List[str]] = None, 
        verbose: bool = False,
        timeout: int = 10,
        delay: float = 0.5,
        user_agents: Optional[List[str]] = None,
        verify_ssl: bool = True,
        max_workers: int = 1
    ):
        """
        Initialize the CORS Checker with configuration parameters.
        
        Args:
            url: Target URL to test
            custom_origins: List of origins to test against the target
            custom_headers: List of headers to include in CORS requests
            custom_methods: List of HTTP methods to test
            verbose: Enable verbose output
            timeout: Request timeout in seconds
            delay: Delay between requests to avoid rate limiting
            user_agents: List of user agents to rotate through
            verify_ssl: Whether to verify SSL certificates
            max_workers: Maximum number of concurrent workers for testing
        """
        # Add URL prefix if missing
        url = self.ensure_url_prefix(url)
        
        if not self.validate_url(url):
            raise ValueError(f"Invalid URL format: {url}")
            
        self.target_url = url
        self.verbose = verbose
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.max_workers = max_workers
        
        # Default user agents for request rotation
        self.user_agents = user_agents or [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59"
        ]
        
        # Test values
        self.domain = self._get_domain(url)
        
        self.test_origins = custom_origins or [
            "https://evil.com",
            "https://attacker.com",
            "null",
            f"https://subdomain.{self.domain}",
            f"{self.domain}.attacker.com",
            f"https://{self.domain.replace('.', 'a')}.com",
            "*",
            f"https://{self.domain}",  # Same domain, different protocol
            f"https://evil-{self.domain}",  # Prefixed domain
            f"https://{self.domain}-evil.com"  # Suffixed domain
        ]
        
        self.test_methods = custom_methods or [
            "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"
        ]
        
        self.test_headers = custom_headers or [
            "X-Custom-Header",
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "Cookie",
            "X-CSRF-Token",
            "X-API-Key",
            "Accept",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers"
        ]
        
        self.results = {
            "url": url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "origin_tests": [],
            "preflight_tests": [],
            "wildcard_tests": [],
            "credentials_tests": [],
            "vulnerabilities": []
        }

    @staticmethod
    def ensure_url_prefix(url: str) -> str:
        """
        Ensure the URL has a proper http:// or https:// prefix.
        If missing, https:// will be added by default.
        
        Args:
            url: URL to check and modify if needed
            
        Returns:
            str: URL with proper prefix
        """
        if not url:
            return url
            
        # Strip whitespace
        url = url.strip()
        
        # Check if URL already has a scheme
        if "://" in url:
            return url
            
        # Check if URL starts with //
        if url.startswith("//"):
            return "https:" + url
            
        # Default to https://
        return "https://" + url

    @staticmethod
    def validate_url(url: str) -> bool:
        """
        Validate URL format to ensure it's properly structured.
        
        Args:
            url: URL to validate
            
        Returns:
            bool: True if URL is valid, False otherwise
        """
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except Exception:
            return False

    def _get_domain(self, url: str) -> str:
        """
        Extract the base domain from a URL.
        
        Args:
            url: URL to extract domain from
            
        Returns:
            str: Extracted domain name
        """
        parsed = urlparse(url)
        domain_parts = parsed.netloc.split('.')
        if len(domain_parts) > 2:
            return '.'.join(domain_parts[-2:])
        return parsed.netloc
    
    def _get_random_user_agent(self) -> str:
        """Get a random user agent from the available list."""
        return random.choice(self.user_agents)
    
    def _print_info(self, message: str) -> None:
        """Print informational message if verbose is enabled."""
        if self.verbose:
            logger.info(message)
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {message}")
    
    def _print_test(self, message: str) -> None:
        """Print test message."""
        logger.info(f"TEST: {message}")
        print(f"{Fore.CYAN}[TEST]{Style.RESET_ALL} {message}")
    
    def _print_finding(self, message: str) -> None:
        """Print a finding message."""
        logger.warning(f"FINDING: {message}")
        print(f"{Fore.YELLOW}[FINDING]{Style.RESET_ALL} {message}")
    
    def _print_vulnerability(self, message: str) -> None:
        """Print vulnerability message."""
        logger.critical(f"VULNERABILITY: {message}")
        print(f"{Fore.RED}[VULNERABILITY]{Style.RESET_ALL} {message}")
    
    def _print_header(self, title: str) -> None:
        """Print a section header."""
        print(f"\n{Fore.GREEN}{'=' * 10} {title} {'=' * 10}{Style.RESET_ALL}")
    
    def _make_request(
        self, 
        method: str, 
        url: str, 
        headers: Dict[str, str]
    ) -> requests.Response:
        """
        Make HTTP request with configured parameters and error handling.
        
        Args:
            method: HTTP method to use
            url: URL to request
            headers: Headers to include in request
            
        Returns:
            Response object
            
        Raises:
            Exception: If request fails
        """
        # Add a random user agent if not specified
        if 'User-Agent' not in headers:
            headers['User-Agent'] = self._get_random_user_agent()
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            # Add delay to avoid rate limiting
            time.sleep(self.delay)
            return response
        except requests.RequestException as e:
            error_msg = str(e)
            # Sanitize error message to avoid potential sensitive info disclosure
            if self.verbose:
                logger.error(f"Request error: {error_msg}")
            else:
                # Less detailed error for non-verbose mode
                error_type = type(e).__name__
                logger.error(f"Request error ({error_type}). Use --verbose for details.")
            raise
    
    def _test_origin(self, test_origin: str) -> Dict[str, Any]:
        """
        Test a single origin for CORS configuration.
        
        Args:
            test_origin: Origin to test
            
        Returns:
            Dict containing test results
        """
        self._print_test(f"Testing origin: {test_origin}")
        
        headers = {
            "Origin": test_origin
        }
        
        try:
            response = self._make_request("GET", self.target_url, headers)
            acao_header = response.headers.get("Access-Control-Allow-Origin")
            acac_header = response.headers.get("Access-Control-Allow-Credentials")
            
            result = {
                "origin": test_origin,
                "status_code": response.status_code,
                "acao": acao_header,
                "acac": acac_header
            }
            
            # Check if the origin is reflected
            if acao_header == test_origin:
                self._print_finding(f"Origin '{test_origin}' is reflected in ACAO header")
                result["reflected"] = True
                
                # Check if credentials are also allowed (high risk)
                if acac_header and acac_header.lower() == "true":
                    self._print_vulnerability(f"Origin '{test_origin}' is reflected with credentials allowed!")
                    result["credentials_allowed"] = True
                    self.results["vulnerabilities"].append({
                        "type": "permissive_cors_with_credentials",
                        "origin": test_origin,
                        "details": "Origin is reflected with credentials allowed, which can lead to sensitive data exposure"
                    })
            else:
                result["reflected"] = False
            
            # Check for wildcard
            if acao_header == "*":
                self._print_finding("Wildcard (*) ACAO detected")
                
                if acac_header and acac_header.lower() == "true":
                    self._print_vulnerability("Configuration error: Wildcard origin with credentials (browsers will block this)")
                    self.results["vulnerabilities"].append({
                        "type": "invalid_wildcard_config",
                        "details": "Wildcard ACAO with credentials is an invalid configuration that browsers will block"
                    })
            
            # Add other checks as needed
            if self.verbose:
                sanitized_headers = {k: v for k, v in response.headers.items()}
                self._print_info(f"Response headers: {json.dumps(sanitized_headers, indent=2)}")
            
            return result
                
        except Exception as e:
            self._print_info(f"Error testing origin {test_origin}: {str(e)}")
            return {
                "origin": test_origin,
                "error": str(e)
            }
    
    def _test_preflight(self, test_origin: str, test_method: str) -> Dict[str, Any]:
        """
        Test a preflight request with specific origin and method.
        
        Args:
            test_origin: Origin to test
            test_method: HTTP method to test
            
        Returns:
            Dict containing test results
        """
        if test_method in ["GET", "HEAD"]:
            return None  # Skip simple methods
            
        self._print_test(f"Testing preflight: Origin={test_origin}, Method={test_method}")
        
        headers = {
            "Origin": test_origin,
            "Access-Control-Request-Method": test_method,
            "Access-Control-Request-Headers": "Content-Type, Authorization"
        }
        
        try:
            response = self._make_request("OPTIONS", self.target_url, headers)
            
            acao_header = response.headers.get("Access-Control-Allow-Origin")
            acam_header = response.headers.get("Access-Control-Allow-Methods")
            acah_header = response.headers.get("Access-Control-Allow-Headers")
            acac_header = response.headers.get("Access-Control-Allow-Credentials")
            
            result = {
                "origin": test_origin,
                "method": test_method,
                "status_code": response.status_code,
                "acao": acao_header,
                "acam": acam_header,
                "acah": acah_header,
                "acac": acac_header
            }
            
            if acao_header == test_origin:
                self._print_finding(f"Preflight: Origin '{test_origin}' is reflected in ACAO header")
                result["reflected"] = True
                
                if acam_header and test_method in [m.strip() for m in acam_header.split(",")]:
                    self._print_finding(f"Method '{test_method}' is allowed for origin '{test_origin}'")
                    result["method_allowed"] = True
                
                if acac_header and acac_header.lower() == "true":
                    self._print_vulnerability(f"Preflight allows credentials for origin '{test_origin}'")
                    result["credentials_allowed"] = True
                    self.results["vulnerabilities"].append({
                        "type": "permissive_preflight_with_credentials",
                        "origin": test_origin,
                        "method": test_method,
                        "details": "Preflight allows credentials for potentially dangerous origin"
                    })
            
            if self.verbose:
                sanitized_headers = {k: v for k, v in response.headers.items()}
                self._print_info(f"Preflight response headers: {json.dumps(sanitized_headers, indent=2)}")
            
            return result
                
        except Exception as e:
            self._print_info(f"Error testing preflight for origin {test_origin}, method {test_method}: {str(e)}")
            return {
                "origin": test_origin,
                "method": test_method,
                "error": str(e)
            }
    
    def run_basic_cors_test(self) -> None:
        """Test basic CORS implementation with various origins."""
        self._print_header("Basic CORS Implementation Tests")
        
        if self.max_workers > 1:
            # Parallel execution
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                results = list(executor.map(self._test_origin, self.test_origins))
                for result in results:
                    if result:  # Filter out None results
                        self.results["origin_tests"].append(result)
        else:
            # Sequential execution
            for test_origin in self.test_origins:
                result = self._test_origin(test_origin)
                if result:
                    self.results["origin_tests"].append(result)
    
    def run_preflight_test(self) -> None:
        """Test CORS preflight configurations with various methods."""
        self._print_header("CORS Preflight Request Tests")
        
        test_cases = []
        for origin in self.test_origins:
            for method in self.test_methods:
                if method not in ["GET", "HEAD"]:  # Skip simple methods
                    test_cases.append((origin, method))
        
        if self.max_workers > 1:
            # Parallel execution
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                results = list(executor.map(
                    lambda x: self._test_preflight(x[0], x[1]), 
                    test_cases
                ))
                for result in results:
                    if result:  # Filter out None results
                        self.results["preflight_tests"].append(result)
        else:
            # Sequential execution
            for origin, method in test_cases:
                result = self._test_preflight(origin, method)
                if result:
                    self.results["preflight_tests"].append(result)
    
    def test_null_origin(self) -> None:
        """Test specifically for null origin acceptance."""
        self._print_header("Null Origin Test")
        
        headers = {
            "Origin": "null"
        }
        
        try:
            response = self._make_request("GET", self.target_url, headers)
            acao_header = response.headers.get("Access-Control-Allow-Origin")
            acac_header = response.headers.get("Access-Control-Allow-Credentials")
            
            result = {
                "status_code": response.status_code,
                "acao": acao_header,
                "acac": acac_header
            }
            
            if acao_header == "null":
                self._print_vulnerability("Server accepts 'null' origin, which can be exploited via sandbox iframes, data URLs, etc.")
                result["vulnerable"] = True
                self.results["vulnerabilities"].append({
                    "type": "null_origin_accepted",
                    "details": "Server accepts 'null' origin which can be exploited via sandbox iframes or local HTML files"
                })
            else:
                result["vulnerable"] = False
                
            self.results["wildcard_tests"].append(result)
            
        except Exception as e:
            self._print_info(f"Error testing null origin: {str(e)}")
            self.results["wildcard_tests"].append({
                "error": str(e)
            })
    
    def test_credentials_with_multiple_origins(self) -> None:
        """Test if credentials are allowed with multiple origins."""
        self._print_header("Credentials With Multiple Origins Test")
        
        for test_origin in self.test_origins:
            if test_origin == "*":  # Skip wildcard as it's tested elsewhere
                continue
                
            headers = {
                "Origin": test_origin,
                "Cookie": "test=value",  # Include a test cookie
                "Authorization": "Bearer test-token"  # Include test auth header
            }
            
            try:
                response = self._make_request("GET", self.target_url, headers)
                acao_header = response.headers.get("Access-Control-Allow-Origin")
                acac_header = response.headers.get("Access-Control-Allow-Credentials")
                
                result = {
                    "origin": test_origin,
                    "status_code": response.status_code,
                    "acao": acao_header,
                    "acac": acac_header
                }
                
                if acao_header and acac_header and acac_header.lower() == "true":
                    if test_origin not in ["https://" + self.domain]:  # Not same domain
                        self._print_vulnerability(f"Credentials allowed with non-same-site origin: {test_origin}")
                        result["vulnerable"] = True
                        self.results["vulnerabilities"].append({
                            "type": "credentials_with_foreign_origin",
                            "origin": test_origin,
                            "details": "Credentials are allowed with a non-same-site origin, risking sensitive data exposure"
                        })
                
                self.results["credentials_tests"].append(result)
                
            except Exception as e:
                self._print_info(f"Error testing credentials with origin {test_origin}: {str(e)}")
                self.results["credentials_tests"].append({
                    "origin": test_origin,
                    "error": str(e)
                })
    
    def test_http_header_exposure(self) -> None:
        """Test for exposure of sensitive HTTP headers through ACAO."""
        self._print_header("HTTP Header Exposure Test")
        
        for test_header in self.test_headers:
            headers = {
                "Origin": "https://evil.com",
                "Access-Control-Request-Headers": test_header
            }
            
            try:
                response = self._make_request("OPTIONS", self.target_url, headers)
                acah_header = response.headers.get("Access-Control-Allow-Headers")
                
                if acah_header and test_header.lower() in [h.strip().lower() for h in acah_header.split(",")]:
                    if test_header.lower() in ["authorization", "cookie", "x-api-key"]:
                        self._print_vulnerability(f"Sensitive header '{test_header}' is exposed in ACAH")
                        self.results["vulnerabilities"].append({
                            "type": "sensitive_header_exposure",
                            "header": test_header,
                            "details": f"Sensitive header '{test_header}' is exposed in Access-Control-Allow-Headers"
                        })
            except Exception as e:
                self._print_info(f"Error testing header exposure for {test_header}: {str(e)}")
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate and return a summary report.
        
        Returns:
            Dict containing the complete test results
        """
        self._print_header("CORS Assessment Report")
        
        # Count vulnerabilities
        vuln_count = len(self.results["vulnerabilities"])
        
        if vuln_count > 0:
            print(f"\n{Fore.RED}Found {vuln_count} CORS vulnerabilities:{Style.RESET_ALL}")
            for i, vuln in enumerate(self.results["vulnerabilities"]):
                print(f"{i+1}. {vuln['type']}: {vuln['details']}")
        else:
            print(f"\n{Fore.GREEN}No CORS vulnerabilities found. The configuration appears to be secure.{Style.RESET_ALL}")
        
        # Export results to JSON with timestamp in filename
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"cors_results_{timestamp}.json"
        
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\nDetailed results have been saved to {Fore.CYAN}{filename}{Style.RESET_ALL}")
        
        return self.results
        
    def run_all_tests(self) -> Dict[str, Any]:
        """
        Run all CORS tests.
        
        Returns:
            Dict containing the complete test results
        """
        self.run_basic_cors_test()
        self.run_preflight_test()
        self.test_null_origin()
        self.test_credentials_with_multiple_origins()
        self.test_http_header_exposure()
        return self.generate_report()


def main() -> int:
    """
    Main function to parse arguments and run the CORS tests.
    
    Returns:
        int: Number of vulnerabilities found (used as exit code)
    """
    parser = argparse.ArgumentParser(
        description="CORS Configuration Checker",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("url", help="Target URL to test (http:// or https:// prefix will be added if missing)")
    parser.add_argument("-o", "--origins", help="Custom origins to test (comma-separated)", default="")
    parser.add_argument("-m", "--methods", help="Custom HTTP methods to test (comma-separated)", default="")
    parser.add_argument("-H", "--headers", help="Custom headers to test (comma-separated)", default="")
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
    parser.add_argument("-j", "--json", help="Output JSON format only", action="store_true")
    parser.add_argument("-t", "--timeout", help="Request timeout in seconds", type=int, default=10)
    parser.add_argument("-d", "--delay", help="Delay between requests in seconds", type=float, default=0.5)
    parser.add_argument("-w", "--workers", help="Maximum number of concurrent workers", type=int, default=1)
    parser.add_argument("--no-verify-ssl", help="Disable SSL certificate verification", action="store_true")
    parser.add_argument("--user-agents", help="File containing user agents to rotate", default=None)
    args = parser.parse_args()
    
    # Process custom inputs
    custom_origins = args.origins.split(",") if args.origins else None
    custom_methods = args.methods.split(",") if args.methods else None
    custom_headers = args.headers.split(",") if args.headers else None
    
    # Load user agents from file if specified
    user_agents = None
    if args.user_agents:
        try:
            with open(args.user_agents, 'r') as f:
                user_agents = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.warning(f"Failed to load user agents file: {e}")
    
    print(f"{Fore.GREEN}CORS Configuration Checker{Style.RESET_ALL}")
    
    # Add prefix if missing and notify user
    original_url = args.url
    url_with_prefix = CORSChecker.ensure_url_prefix(args.url)
    
    if original_url != url_with_prefix:
        print(f"URL prefix added: {Fore.YELLOW}{original_url}{Style.RESET_ALL} → {Fore.GREEN}{url_with_prefix}{Style.RESET_ALL}")
    
    print(f"Target: {url_with_prefix}")
    
    try:
        checker = CORSChecker(
            url_with_prefix, 
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
        logger.exception("Unexpected error occurred")
        return 2

if __name__ == "__main__":
    sys.exit(main())
