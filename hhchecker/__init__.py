"""
HHChecker: Cybersecurity Assessment Toolkit
---------------------------------------------

A comprehensive toolkit for assessing web application security configurations,
including CORS implementations and HTTP security headers.
"""

__version__ = '0.1.0'
__author__ = 'NonBytes'

from hhchecker.cors_checker import CORSChecker
from hhchecker.header_checker import check_headers

__all__ = ['CORSChecker', 'check_headers']
