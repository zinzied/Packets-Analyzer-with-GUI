#!/usr/bin/env python3
"""
Network Packet Analyzer - Main Entry Point
This script launches the Network Packet Analyzer application.
"""

import sys
from PyQt5 import QtWidgets
from gui.main_window import MainWindow

def main():
    """Main entry point for the application."""
    app = QtWidgets.QApplication(sys.argv)
    
    # Set application-wide style
    with open("gui/styles/dark_theme.qss", "r") as style_file:
        app.setStyleSheet(style_file.read())
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
