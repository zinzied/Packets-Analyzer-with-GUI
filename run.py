#!/usr/bin/env python3
"""
Run script for Network Packet Analyzer
This script is a simple wrapper to start the application.
"""

import sys
import os
import logging

# Configure logging
logging.basicConfig(
    filename='packet_analyzer.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the application
from main import main

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.exception("Unhandled exception:")
        print(f"Error: {str(e)}")
        sys.exit(1)
