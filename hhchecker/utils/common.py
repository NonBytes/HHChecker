"""
Common utilities for HHChecker toolkit.
"""

import re
import os
import sys
import json
import urllib.parse
from typing import Dict, List, Tuple, Any, Optional
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def validate_url(url: str) -> Tuple[bool, str]:
    """
    Validate URL format and structure.
    
    Args:
        url: URL string to validate
        
    Returns:
        Tuple of (is_valid, error_message_or_normalized_url)
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


def save_json_report(data: Dict[str, Any], prefix: str = "report") -> str:
    """
    Save data to a JSON file with timestamp.
    
    Args:
        data: Dictionary data to save
        prefix: Filename prefix
        
    Returns:
        Filename where data was saved
    """
    import time
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp}.json"
    
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        return filename
    except Exception as e:
        print(f"{Fore.RED}Error saving report: {str(e)}{Style.RESET_ALL}")
        return ""


def get_temp_dir() -> str:
    """
    Get a suitable temporary directory for the current platform.
    
    Returns:
        Path to temporary directory
    """
    if sys.platform.startswith('win'):
        return os.environ.get('TEMP', os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Temp'))
    else:
        return '/tmp'


def print_banner(text: str, style: str = "standard"):
    """
    Print a styled banner text.
    
    Args:
        text: Text to display in the banner
        style: Banner style: "standard", "minimal", or "double"
    """
    width = min(80, max(40, len(text) + 10))
    
    if style == "minimal":
        print(f"\n{Fore.CYAN}{text}{Style.RESET_ALL}\n")
    elif style == "double":
        top_border = "╔" + "═" * (width - 2) + "╗"
        bottom_border = "╚" + "═" * (width - 2) + "╝"
        print(f"\n{Fore.CYAN}{top_border}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{' ' * ((width - 2 - len(text)) // 2)}{Fore.GREEN}{text}{Fore.CYAN}{' ' * ((width - 1 - len(text)) // 2)}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{bottom_border}{Style.RESET_ALL}\n")
    else:  # standard
        top_border = "+" + "-" * (width - 2) + "+"
        bottom_border = "+" + "-" * (width - 2) + "+"
        print(f"\n{Fore.CYAN}{top_border}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}|{' ' * ((width - 2 - len(text)) // 2)}{Fore.GREEN}{text}{Fore.CYAN}{' ' * ((width - 1 - len(text)) // 2)}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{bottom_border}{Style.RESET_ALL}\n")


def format_finding(message: str, level: str = "info") -> str:
    """
    Format a finding message with appropriate colors.
    
    Args:
        message: The finding message to format
        level: Severity level (info, low, medium, high, critical)
        
    Returns:
        Formatted message string
    """
    level = level.lower()
    
    if level == "critical":
        return f"{Fore.RED}[CRITICAL] {message}{Style.RESET_ALL}"
    elif level == "high":
        return f"{Fore.RED}[HIGH] {message}{Style.RESET_ALL}"
    elif level == "medium":
        return f"{Fore.YELLOW}[MEDIUM] {message}{Style.RESET_ALL}"
    elif level == "low":
        return f"{Fore.CYAN}[LOW] {message}{Style.RESET_ALL}"
    else:  # info
        return f"{Fore.BLUE}[INFO] {message}{Style.RESET_ALL}"


def parse_comma_separated(value: str) -> List[str]:
    """
    Parse a comma-separated string into a list, handling whitespace.
    
    Args:
        value: Comma-separated string
        
    Returns:
        List of individual values with whitespace removed
    """
    if not value:
        return []
    
    return [item.strip() for item in value.split(',') if item.strip()]
