#!/usr/bin/env python3
"""
Main entry point for running the HHChecker package directly.
Example: python -m hhchecker
"""

import sys
from hhchecker.cli import main

if __name__ == "__main__":
    sys.exit(main())
