#!/usr/bin/env python3
"""
Filters Module
This module provides functionality for filtering packets.
"""

import re
import logging

class PacketFilter:
    """
    A class for filtering packets based on various criteria.
    
    This class provides functionality to filter packets by IP address,
    port, protocol, and other criteria.
    """
    
    def __init__(self):
        """Initialize the PacketFilter."""
        self.filters = {}
        
    def add_filter(self, filter_type, filter_value):
        """
        Add a filter.
        
        Args:
            filter_type (str): The type of filter (e.g., 'src_ip', 'dst_ip', 'protocol')
            filter_value: The value to filter by
            
        Returns:
            bool: True if the filter was added successfully, False otherwise
        """
        if not filter_value:
            return False
            
        self.filters[filter_type] = filter_value
        return True
        
    def remove_filter(self, filter_type):
        """
        Remove a filter.
        
        Args:
            filter_type (str): The type of filter to remove
            
        Returns:
            bool: True if the filter was removed successfully, False otherwise
        """
        if filter_type in self.filters:
            del self.filters[filter_type]
            return True
        return False
        
    def clear_filters(self):
        """Clear all filters."""
        self.filters = {}
        
    def get_filter_string(self):
        """
        Get a BPF filter string based on the current filters.
        
        Returns:
            str: A BPF filter string
        """
        filter_parts = []
        
        # Source IP filter
        if 'src_ip' in self.filters:
            filter_parts.append(f"src host {self.filters['src_ip']}")
            
        # Destination IP filter
        if 'dst_ip' in self.filters:
            filter_parts.append(f"dst host {self.filters['dst_ip']}")
            
        # Protocol filter
        if 'protocol' in self.filters:
            proto = self.filters['protocol']
            if proto.lower() in ['tcp', 'udp', 'icmp', 'arp']:
                filter_parts.append(proto.lower())
            else:
                try:
                    # Try to convert to a protocol number
                    proto_num = int(proto)
                    filter_parts.append(f"proto {proto_num}")
                except ValueError:
                    logging.warning(f"Invalid protocol filter: {proto}")
                    
        # Source port filter
        if 'src_port' in self.filters:
            filter_parts.append(f"src port {self.filters['src_port']}")
            
        # Destination port filter
        if 'dst_port' in self.filters:
            filter_parts.append(f"dst port {self.filters['dst_port']}")
            
        # Combine filter parts with 'and'
        if filter_parts:
            return ' and '.join(filter_parts)
        else:
            return ""
            
    def matches(self, packet_info):
        """
        Check if a packet matches the current filters.
        
        Args:
            packet_info (dict): A dictionary containing packet information
            
        Returns:
            bool: True if the packet matches the filters, False otherwise
        """
        # If no filters are set, all packets match
        if not self.filters:
            return True
            
        # Check each filter
        for filter_type, filter_value in self.filters.items():
            if filter_type == 'src_ip':
                if packet_info.get('src') != filter_value:
                    return False
                    
            elif filter_type == 'dst_ip':
                if packet_info.get('dst') != filter_value:
                    return False
                    
            elif filter_type == 'protocol':
                if filter_value.lower() not in packet_info.get('protocol', '').lower():
                    return False
                    
            elif filter_type == 'src_port':
                if packet_info.get('sport') != int(filter_value):
                    return False
                    
            elif filter_type == 'dst_port':
                if packet_info.get('dport') != int(filter_value):
                    return False
                    
            elif filter_type == 'contains':
                payload = packet_info.get('payload')
                if not payload or filter_value.encode() not in payload:
                    return False
                    
            elif filter_type == 'regex':
                try:
                    pattern = re.compile(filter_value)
                    payload = packet_info.get('payload')
                    if not payload or not pattern.search(payload.decode('utf-8', errors='ignore')):
                        return False
                except Exception:
                    return False
                    
        # If all filters passed, the packet matches
        return True
