#!/usr/bin/env python3
"""
Network Packet Sniffer Module
This module provides functionality for capturing and processing network packets.
"""

import threading
import logging
import scapy.all as scapy
from PyQt5.QtCore import QObject, pyqtSignal

class PacketSniffer(QObject):
    """
    A class for capturing and processing network packets.

    This class provides functionality to start and stop packet sniffing,
    apply filters, and process captured packets.
    """

    # Define signals
    packet_captured = pyqtSignal(object)
    sniffing_started = pyqtSignal()
    sniffing_stopped = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self):
        """Initialize the PacketSniffer."""
        super().__init__()
        self.sniffing = False
        self.sniffer_thread = None
        self.interface = None
        self.filter_str = ""
        self.packet_count = 0
        self.max_packets = 0  # 0 means no limit
        self.timeout = None  # None means no timeout

    def set_interface(self, interface):
        """Set the network interface to capture packets from."""
        self.interface = interface

    def set_filter(self, filter_str):
        """Set the BPF filter string."""
        self.filter_str = filter_str

    def set_max_packets(self, count):
        """Set the maximum number of packets to capture."""
        self.max_packets = count

    def set_timeout(self, seconds):
        """Set the timeout for packet capture in seconds."""
        self.timeout = seconds

    def start(self):
        """Start packet sniffing in a separate thread."""
        if self.sniffing:
            return

        self.sniffing = True
        self.packet_count = 0
        self.sniffer_thread = threading.Thread(target=self._sniff_packets)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        self.sniffing_started.emit()

    def stop(self):
        """Stop packet sniffing."""
        self.sniffing = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1.0)
        self.sniffing_stopped.emit()

    def _sniff_packets(self):
        """Internal method to sniff packets using scapy."""
        try:
            kwargs = {
                'prn': self._process_packet,
                'store': False,
                'stop_filter': lambda x: not self.sniffing
            }

            if self.filter_str:
                kwargs['filter'] = self.filter_str

            if self.interface:
                kwargs['iface'] = self.interface

            if self.timeout:
                kwargs['timeout'] = self.timeout

            if self.max_packets > 0:
                kwargs['count'] = self.max_packets

            scapy.sniff(**kwargs)

        except Exception as e:
            self.error_occurred.emit(f"Error during packet sniffing: {str(e)}")
            logging.error(f"Error during packet sniffing: {str(e)}")
        finally:
            self.sniffing = False
            self.sniffing_stopped.emit()

    def _process_packet(self, packet):
        """Process a captured packet and emit a signal."""
        if not self.sniffing:
            return

        self.packet_count += 1
        self.packet_captured.emit(packet)

        # Stop if we've reached the maximum number of packets
        if self.max_packets > 0 and self.packet_count >= self.max_packets:
            self.stop()

    @staticmethod
    def get_available_interfaces():
        """Get a list of available network interfaces."""
        try:
            # First try using psutil which is more reliable across platforms
            import psutil
            adapters = psutil.net_if_addrs()
            return list(adapters.keys())
        except Exception as e:
            logging.error(f"Error getting network interfaces with psutil: {str(e)}")
            try:
                # Fall back to scapy's method
                interfaces = scapy.get_if_list()
                return interfaces
            except Exception as e:
                logging.error(f"Error getting network interfaces with scapy: {str(e)}")
                return []

    @staticmethod
    def check_npcap_installed():
        """Check if Npcap is installed."""
        try:
            # Try a simple scapy operation that requires Npcap
            test = scapy.Ether()
            return True
        except Exception:
            return False
