#!/usr/bin/env python3
"""
Export Module
This module provides functionality for exporting packet data to various formats.
"""

import json
import csv
import logging
import scapy.all as scapy

class PacketExporter:
    """
    A class for exporting packet data to various formats.
    
    This class provides functionality to export packet data to CSV, JSON,
    and PCAP formats.
    """
    
    def __init__(self):
        """Initialize the PacketExporter."""
        pass
        
    def export_to_csv(self, packets, filename):
        """
        Export packet data to a CSV file.
        
        Args:
            packets (list): A list of scapy packet objects
            filename (str): The name of the CSV file to create
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for i, packet in enumerate(packets):
                    row = self._packet_to_csv_row(i + 1, packet)
                    writer.writerow(row)
                    
            logging.info(f"Exported {len(packets)} packets to {filename}")
            return True
            
        except Exception as e:
            logging.error(f"Error exporting to CSV: {str(e)}")
            return False
            
    def export_to_json(self, packets, filename):
        """
        Export packet data to a JSON file.
        
        Args:
            packets (list): A list of scapy packet objects
            filename (str): The name of the JSON file to create
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            packets_data = []
            for packet in packets:
                packet_data = self._packet_to_json_dict(packet)
                packets_data.append(packet_data)
                
            with open(filename, 'w') as jsonfile:
                json.dump(packets_data, jsonfile, indent=4)
                
            logging.info(f"Exported {len(packets)} packets to {filename}")
            return True
            
        except Exception as e:
            logging.error(f"Error exporting to JSON: {str(e)}")
            return False
            
    def export_to_pcap(self, packets, filename):
        """
        Export packet data to a PCAP file.
        
        Args:
            packets (list): A list of scapy packet objects
            filename (str): The name of the PCAP file to create
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            scapy.wrpcap(filename, packets)
            logging.info(f"Exported {len(packets)} packets to {filename}")
            return True
            
        except Exception as e:
            logging.error(f"Error exporting to PCAP: {str(e)}")
            return False
            
    def _packet_to_csv_row(self, index, packet):
        """
        Convert a packet to a CSV row.
        
        Args:
            index (int): The packet index
            packet: A scapy packet object
            
        Returns:
            dict: A dictionary representing a CSV row
        """
        row = {
            'No.': index,
            'Time': packet.time,
            'Source': 'Unknown',
            'Destination': 'Unknown',
            'Protocol': 'Unknown',
            'Length': len(packet),
            'Info': packet.summary()
        }
        
        if packet.haslayer(scapy.IP):
            row['Source'] = packet[scapy.IP].src
            row['Destination'] = packet[scapy.IP].dst
            
            proto = packet[scapy.IP].proto
            if proto == 6:
                row['Protocol'] = 'TCP'
            elif proto == 17:
                row['Protocol'] = 'UDP'
            elif proto == 1:
                row['Protocol'] = 'ICMP'
            else:
                row['Protocol'] = f'IP Protocol {proto}'
                
        elif packet.haslayer(scapy.ARP):
            row['Source'] = packet[scapy.ARP].psrc
            row['Destination'] = packet[scapy.ARP].pdst
            row['Protocol'] = 'ARP'
            
        return row
        
    def _packet_to_json_dict(self, packet):
        """
        Convert a packet to a JSON dictionary.
        
        Args:
            packet: A scapy packet object
            
        Returns:
            dict: A dictionary representing the packet
        """
        packet_dict = {
            'time': packet.time,
            'summary': packet.summary(),
            'length': len(packet),
            'layers': {}
        }
        
        # Add layer-specific information
        for layer in packet.layers():
            layer_name = layer.__name__
            layer_data = {}
            
            # Get all fields for this layer
            if packet.haslayer(layer):
                layer_obj = packet.getlayer(layer)
                for field in layer_obj.fields:
                    # Convert field value to string to ensure JSON serialization
                    value = layer_obj.fields[field]
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='replace')
                        except Exception:
                            value = str(value)
                    layer_data[field] = value
                    
            packet_dict['layers'][layer_name] = layer_data
            
        # Add raw data if available
        if packet.haslayer(scapy.Raw):
            try:
                raw_data = bytes(packet[scapy.Raw])
                packet_dict['raw'] = raw_data.hex()
                
                # Try to decode as UTF-8
                try:
                    packet_dict['raw_text'] = raw_data.decode('utf-8', errors='replace')
                except Exception:
                    pass
                    
            except Exception:
                pass
                
        return packet_dict
