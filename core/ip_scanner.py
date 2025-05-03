#!/usr/bin/env python3
"""
IP Scanner Module
This module provides functionality for scanning IP addresses on a network.
"""

import scapy.all as scapy
import psutil
import logging
import threading
from PyQt5.QtCore import QObject, pyqtSignal

class IPScanner(QObject):
    """
    A class for scanning IP addresses on a network.
    
    This class provides functionality to scan a range of IP addresses
    and discover active devices on the network.
    """
    
    # Define signals
    scan_progress = pyqtSignal(int, int)  # current, total
    scan_complete = pyqtSignal(list)  # list of results
    scan_error = pyqtSignal(str)  # error message
    
    def __init__(self):
        """Initialize the IPScanner."""
        super().__init__()
        self.scanning = False
        self.scanner_thread = None
        
    def get_network_adapters(self):
        """
        Get a list of available network adapters.
        
        Returns:
            dict: A dictionary of network adapters
        """
        try:
            return psutil.net_if_addrs()
        except Exception as e:
            logging.error(f"Error getting network adapters: {str(e)}")
            self.scan_error.emit(f"Error getting network adapters: {str(e)}")
            return {}
            
    def start_scan(self, ip_range, timeout=5, verbose=False):
        """
        Start scanning IP addresses in a separate thread.
        
        Args:
            ip_range (str): The IP range to scan (e.g., '192.168.1.0/24')
            timeout (int): The timeout for ARP requests in seconds
            verbose (bool): Whether to print verbose output
        """
        if self.scanning:
            return
            
        self.scanning = True
        self.scanner_thread = threading.Thread(
            target=self._scan_network,
            args=(ip_range, timeout, verbose)
        )
        self.scanner_thread.daemon = True
        self.scanner_thread.start()
        
    def stop_scan(self):
        """Stop the IP scan."""
        self.scanning = False
        if self.scanner_thread and self.scanner_thread.is_alive():
            self.scanner_thread.join(timeout=1.0)
            
    def _scan_network(self, ip_range, timeout, verbose):
        """
        Internal method to scan a network using ARP requests.
        
        Args:
            ip_range (str): The IP range to scan (e.g., '192.168.1.0/24')
            timeout (int): The timeout for ARP requests in seconds
            verbose (bool): Whether to print verbose output
        """
        try:
            # Create ARP request
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            # Send ARP request and get responses
            logging.info(f"Scanning IP range: {ip_range}")
            
            # Get the number of IPs to scan for progress reporting
            ip_network = scapy.utils.ltoa(arp_request.pdst)
            if isinstance(ip_network, list):
                total_ips = len(ip_network)
            else:
                # If it's a CIDR notation, calculate the number of IPs
                if '/' in ip_range:
                    network_bits = int(ip_range.split('/')[1])
                    total_ips = 2 ** (32 - network_bits)
                else:
                    total_ips = 1
                    
            # Emit initial progress
            self.scan_progress.emit(0, total_ips)
            
            # Send packets and get responses
            answered_list = scapy.srp(
                arp_request_broadcast,
                timeout=timeout,
                verbose=verbose,
                retry=2
            )[0]
            
            # Process results
            clients = []
            for i, element in enumerate(answered_list):
                client_dict = {
                    "ip": element[1].psrc,
                    "mac": element[1].hwsrc,
                    "hostname": self._get_hostname(element[1].psrc)
                }
                clients.append(client_dict)
                
                # Emit progress
                self.scan_progress.emit(i + 1, total_ips)
                
                # Check if scanning was stopped
                if not self.scanning:
                    break
                    
            # Emit final progress and results
            self.scan_progress.emit(total_ips, total_ips)
            self.scan_complete.emit(clients)
            logging.info(f"Scan completed. Found {len(clients)} devices.")
            
        except Exception as e:
            error_msg = f"Error during IP scanning: {str(e)}"
            logging.error(error_msg)
            self.scan_error.emit(error_msg)
            
        finally:
            self.scanning = False
            
    def _get_hostname(self, ip):
        """
        Try to resolve the hostname for an IP address.
        
        Args:
            ip (str): The IP address to resolve
            
        Returns:
            str: The hostname if resolved, otherwise an empty string
        """
        try:
            import socket
            return socket.getfqdn(ip)
        except Exception:
            return ""
