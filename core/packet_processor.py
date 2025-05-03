#!/usr/bin/env python3
"""
Packet Processor Module
This module provides functionality for processing and analyzing network packets.
"""

import scapy.all as scapy
import logging
from datetime import datetime

class PacketProcessor:
    """
    A class for processing and analyzing network packets.
    
    This class provides functionality to extract information from packets,
    categorize them by protocol, and perform protocol-specific analysis.
    """
    
    # Protocol definitions
    PROTOCOLS = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        2: 'IGMP',
        89: 'OSPF',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        58: 'IPv6-ICMP',
    }
    
    # Protocol colors with good contrast
    COLORS = {
        'TCP': '#ADD8E6',      # Light blue
        'UDP': '#FFB6C1',      # Light pink
        'ARP': '#90EE90',      # Light green
        'ICMP': '#FFD700',     # Light orange
        'DNS': '#E6E6FA',      # Light purple
        'HTTP': '#FF6347',     # Light red
        'HTTPS': '#B0E0E6',    # Light cyan
        'DHCP': '#FFA07A',     # Light salmon
        'SMTP': '#98FB98',     # Pale green
        'FTP': '#FFDAB9',      # Peach
        'SSH': '#D8BFD8',      # Thistle
        'TELNET': '#F0E68C',   # Khaki
        'OTHER': '#D3D3D3'     # Light gray
    }
    
    def __init__(self):
        """Initialize the PacketProcessor."""
        self.packet_count = 0
        self.protocol_stats = {}
        self.ip_stats = {}
        self.port_stats = {}
        self.packet_sizes = []
        self.start_time = None
        self.end_time = None
        
    def reset_stats(self):
        """Reset all statistics."""
        self.packet_count = 0
        self.protocol_stats = {}
        self.ip_stats = {}
        self.port_stats = {}
        self.packet_sizes = []
        self.start_time = None
        self.end_time = None
        
    def process_packet(self, packet):
        """
        Process a packet and update statistics.
        
        Args:
            packet: A scapy packet object
            
        Returns:
            dict: A dictionary containing packet information
        """
        if self.start_time is None:
            self.start_time = datetime.now()
            
        self.end_time = datetime.now()
        self.packet_count += 1
        
        # Extract basic packet information
        packet_info = self._extract_packet_info(packet)
        
        # Update statistics
        self._update_protocol_stats(packet_info)
        self._update_ip_stats(packet_info)
        self._update_port_stats(packet_info)
        self.packet_sizes.append(packet_info['length'])
        
        return packet_info
        
    def _extract_packet_info(self, packet):
        """
        Extract information from a packet.
        
        Args:
            packet: A scapy packet object
            
        Returns:
            dict: A dictionary containing packet information
        """
        packet_info = {
            'time': packet.time,
            'summary': packet.summary(),
            'length': len(packet),
            'protocol': 'OTHER',
            'src': None,
            'dst': None,
            'sport': None,
            'dport': None,
            'payload': None,
            'flags': None,
            'ttl': None,
            'id': None,
            'chksum': None,
            'type': None,
            'color': self.COLORS['OTHER']
        }
        
        # Extract protocol information
        if packet.haslayer(scapy.ARP):
            packet_info['protocol'] = 'ARP'
            packet_info['src'] = packet[scapy.ARP].psrc
            packet_info['dst'] = packet[scapy.ARP].pdst
            packet_info['type'] = 'Request' if packet[scapy.ARP].op == 1 else 'Reply'
            packet_info['color'] = self.COLORS['ARP']
            
        elif packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            packet_info['src'] = ip_layer.src
            packet_info['dst'] = ip_layer.dst
            packet_info['ttl'] = ip_layer.ttl
            packet_info['id'] = ip_layer.id
            packet_info['chksum'] = ip_layer.chksum
            
            proto = ip_layer.proto
            packet_info['protocol'] = self.PROTOCOLS.get(proto, f'IP Protocol {proto}')
            
            if packet.haslayer(scapy.TCP):
                tcp_layer = packet[scapy.TCP]
                packet_info['sport'] = tcp_layer.sport
                packet_info['dport'] = tcp_layer.dport
                packet_info['flags'] = self._get_tcp_flags(tcp_layer)
                
                # Check for HTTP/HTTPS
                if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                    if packet.haslayer(scapy.Raw) and b'HTTP' in bytes(packet[scapy.Raw]):
                        packet_info['protocol'] = 'HTTP'
                        packet_info['color'] = self.COLORS['HTTP']
                    else:
                        packet_info['protocol'] = 'TCP'
                        packet_info['color'] = self.COLORS['TCP']
                elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                    packet_info['protocol'] = 'HTTPS'
                    packet_info['color'] = self.COLORS['HTTPS']
                # Check for other common protocols
                elif tcp_layer.dport == 22 or tcp_layer.sport == 22:
                    packet_info['protocol'] = 'SSH'
                    packet_info['color'] = self.COLORS['SSH']
                elif tcp_layer.dport == 23 or tcp_layer.sport == 23:
                    packet_info['protocol'] = 'TELNET'
                    packet_info['color'] = self.COLORS['TELNET']
                elif tcp_layer.dport == 21 or tcp_layer.sport == 21:
                    packet_info['protocol'] = 'FTP'
                    packet_info['color'] = self.COLORS['FTP']
                elif tcp_layer.dport == 25 or tcp_layer.sport == 25:
                    packet_info['protocol'] = 'SMTP'
                    packet_info['color'] = self.COLORS['SMTP']
                else:
                    packet_info['protocol'] = 'TCP'
                    packet_info['color'] = self.COLORS['TCP']
                    
                if packet.haslayer(scapy.Raw):
                    packet_info['payload'] = bytes(packet[scapy.Raw])
                    
            elif packet.haslayer(scapy.UDP):
                udp_layer = packet[scapy.UDP]
                packet_info['sport'] = udp_layer.sport
                packet_info['dport'] = udp_layer.dport
                
                # Check for DNS
                if udp_layer.dport == 53 or udp_layer.sport == 53:
                    if packet.haslayer(scapy.DNS):
                        packet_info['protocol'] = 'DNS'
                        packet_info['color'] = self.COLORS['DNS']
                    else:
                        packet_info['protocol'] = 'UDP'
                        packet_info['color'] = self.COLORS['UDP']
                # Check for DHCP
                elif (udp_layer.dport == 67 or udp_layer.sport == 67 or 
                      udp_layer.dport == 68 or udp_layer.sport == 68):
                    packet_info['protocol'] = 'DHCP'
                    packet_info['color'] = self.COLORS['DHCP']
                else:
                    packet_info['protocol'] = 'UDP'
                    packet_info['color'] = self.COLORS['UDP']
                    
                if packet.haslayer(scapy.Raw):
                    packet_info['payload'] = bytes(packet[scapy.Raw])
                    
            elif packet.haslayer(scapy.ICMP):
                packet_info['protocol'] = 'ICMP'
                packet_info['type'] = packet[scapy.ICMP].type
                packet_info['color'] = self.COLORS['ICMP']
                
        return packet_info
        
    def _get_tcp_flags(self, tcp_layer):
        """
        Get TCP flags as a string.
        
        Args:
            tcp_layer: A scapy TCP layer
            
        Returns:
            str: A string representation of the TCP flags
        """
        flags = []
        if tcp_layer.flags & 0x01:  # FIN
            flags.append('FIN')
        if tcp_layer.flags & 0x02:  # SYN
            flags.append('SYN')
        if tcp_layer.flags & 0x04:  # RST
            flags.append('RST')
        if tcp_layer.flags & 0x08:  # PSH
            flags.append('PSH')
        if tcp_layer.flags & 0x10:  # ACK
            flags.append('ACK')
        if tcp_layer.flags & 0x20:  # URG
            flags.append('URG')
        if tcp_layer.flags & 0x40:  # ECE
            flags.append('ECE')
        if tcp_layer.flags & 0x80:  # CWR
            flags.append('CWR')
            
        return ' '.join(flags)
        
    def _update_protocol_stats(self, packet_info):
        """Update protocol statistics."""
        protocol = packet_info['protocol']
        if protocol in self.protocol_stats:
            self.protocol_stats[protocol] += 1
        else:
            self.protocol_stats[protocol] = 1
            
    def _update_ip_stats(self, packet_info):
        """Update IP address statistics."""
        src = packet_info['src']
        dst = packet_info['dst']
        
        if src:
            if src in self.ip_stats:
                self.ip_stats[src]['sent'] += 1
                self.ip_stats[src]['bytes_sent'] += packet_info['length']
            else:
                self.ip_stats[src] = {
                    'sent': 1,
                    'received': 0,
                    'bytes_sent': packet_info['length'],
                    'bytes_received': 0
                }
                
        if dst:
            if dst in self.ip_stats:
                self.ip_stats[dst]['received'] += 1
                self.ip_stats[dst]['bytes_received'] += packet_info['length']
            else:
                self.ip_stats[dst] = {
                    'sent': 0,
                    'received': 1,
                    'bytes_sent': 0,
                    'bytes_received': packet_info['length']
                }
                
    def _update_port_stats(self, packet_info):
        """Update port statistics."""
        sport = packet_info['sport']
        dport = packet_info['dport']
        
        if sport:
            key = f"{packet_info['protocol']}:{sport}"
            if key in self.port_stats:
                self.port_stats[key] += 1
            else:
                self.port_stats[key] = 1
                
        if dport:
            key = f"{packet_info['protocol']}:{dport}"
            if key in self.port_stats:
                self.port_stats[key] += 1
            else:
                self.port_stats[key] = 1
                
    def get_protocol_stats(self):
        """Get protocol statistics."""
        return self.protocol_stats
        
    def get_ip_stats(self):
        """Get IP address statistics."""
        return self.ip_stats
        
    def get_port_stats(self):
        """Get port statistics."""
        return self.port_stats
        
    def get_packet_size_stats(self):
        """Get packet size statistics."""
        if not self.packet_sizes:
            return {
                'min': 0,
                'max': 0,
                'avg': 0,
                'total': 0
            }
            
        return {
            'min': min(self.packet_sizes),
            'max': max(self.packet_sizes),
            'avg': sum(self.packet_sizes) / len(self.packet_sizes),
            'total': sum(self.packet_sizes)
        }
        
    def get_duration(self):
        """Get the duration of the capture in seconds."""
        if self.start_time is None or self.end_time is None:
            return 0
            
        return (self.end_time - self.start_time).total_seconds()
        
    def get_packet_rate(self):
        """Get the packet rate in packets per second."""
        duration = self.get_duration()
        if duration == 0:
            return 0
            
        return self.packet_count / duration
        
    def get_bandwidth(self):
        """Get the bandwidth in bytes per second."""
        duration = self.get_duration()
        if duration == 0:
            return 0
            
        return sum(self.packet_sizes) / duration
