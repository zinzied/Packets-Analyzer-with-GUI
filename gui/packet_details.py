#!/usr/bin/env python3
"""
Packet Details Widget Module
This module provides a widget for displaying detailed information about a packet.
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTreeWidget, 
    QTreeWidgetItem, QTextEdit, QTabWidget, QLabel
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor

import scapy.all as scapy
import binascii

class PacketDetailsWidget(QWidget):
    """
    A widget for displaying detailed information about a packet.
    
    This widget provides a tree view of the packet structure and a hex view
    of the packet data.
    """
    
    def __init__(self, parent=None):
        """Initialize the PacketDetailsWidget."""
        super().__init__(parent)
        
        # Initialize variables
        self.current_packet = None
        
        # Set up the UI
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface."""
        # Create main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Create tree view tab
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(["Field", "Value"])
        self.tree_widget.setColumnWidth(0, 300)
        self.tab_widget.addTab(self.tree_widget, "Packet Structure")
        
        # Create hex view tab
        self.hex_widget = QWidget()
        hex_layout = QHBoxLayout(self.hex_widget)
        
        # Create hex view
        self.hex_text = QTextEdit()
        self.hex_text.setReadOnly(True)
        self.hex_text.setFont(QFont("Courier New", 10))
        hex_layout.addWidget(self.hex_text)
        
        # Create ASCII view
        self.ascii_text = QTextEdit()
        self.ascii_text.setReadOnly(True)
        self.ascii_text.setFont(QFont("Courier New", 10))
        hex_layout.addWidget(self.ascii_text)
        
        self.tab_widget.addTab(self.hex_widget, "Hex View")
        
        # Create raw view tab
        self.raw_text = QTextEdit()
        self.raw_text.setReadOnly(True)
        self.raw_text.setFont(QFont("Courier New", 10))
        self.tab_widget.addTab(self.raw_text, "Raw Data")
        
        # Add tab widget to layout
        layout.addWidget(self.tab_widget)
        
    def show_packet(self, packet):
        """
        Show detailed information about a packet.
        
        Args:
            packet: A scapy packet object
        """
        if not packet:
            self.clear()
            return
            
        self.current_packet = packet
        
        # Update tree view
        self.update_tree_view()
        
        # Update hex view
        self.update_hex_view()
        
        # Update raw view
        self.update_raw_view()
        
    def update_tree_view(self):
        """Update the tree view with the current packet's structure."""
        self.tree_widget.clear()
        
        if not self.current_packet:
            return
            
        # Add packet summary as root item
        root_item = QTreeWidgetItem([self.current_packet.summary()])
        self.tree_widget.addTopLevelItem(root_item)
        
        # Add each layer
        for layer in self.current_packet.layers():
            layer_name = layer.__name__
            layer_item = QTreeWidgetItem([layer_name])
            root_item.addChild(layer_item)
            
            # Get the layer object
            layer_obj = self.current_packet.getlayer(layer)
            
            # Add fields for this layer
            for field in layer_obj.fields:
                value = layer_obj.fields[field]
                
                # Format the value
                if isinstance(value, bytes):
                    try:
                        value_str = value.decode('utf-8', errors='replace')
                    except Exception:
                        value_str = binascii.hexlify(value).decode('ascii')
                else:
                    value_str = str(value)
                    
                field_item = QTreeWidgetItem([field, value_str])
                layer_item.addChild(field_item)
                
        # Expand the root item
        root_item.setExpanded(True)
        
    def update_hex_view(self):
        """Update the hex view with the current packet's data."""
        self.hex_text.clear()
        self.ascii_text.clear()
        
        if not self.current_packet:
            return
            
        # Get raw packet data
        raw_data = bytes(self.current_packet)
        
        # Format hex view
        hex_text = ""
        ascii_text = ""
        
        for i in range(0, len(raw_data), 16):
            # Get current chunk
            chunk = raw_data[i:i+16]
            
            # Format offset
            offset = f"{i:08x}"
            
            # Format hex values
            hex_values = ""
            for j in range(16):
                if i + j < len(raw_data):
                    hex_values += f"{raw_data[i+j]:02x} "
                else:
                    hex_values += "   "
                    
                # Add extra space after 8 bytes
                if j == 7:
                    hex_values += " "
                    
            # Format ASCII values
            ascii_values = ""
            for j in range(16):
                if i + j < len(raw_data):
                    byte = raw_data[i+j]
                    if 32 <= byte <= 126:  # Printable ASCII
                        ascii_values += chr(byte)
                    else:
                        ascii_values += "."
                else:
                    ascii_values += " "
                    
            # Add line to hex view
            hex_text += f"{offset}  {hex_values}\n"
            
            # Add line to ASCII view
            ascii_text += f"{ascii_values}\n"
            
        # Set text
        self.hex_text.setText(hex_text)
        self.ascii_text.setText(ascii_text)
        
    def update_raw_view(self):
        """Update the raw view with the current packet's data."""
        self.raw_text.clear()
        
        if not self.current_packet:
            return
            
        # Show packet in raw format
        self.raw_text.setText(self.current_packet.show(dump=True))
        
    def clear(self):
        """Clear all views."""
        self.current_packet = None
        self.tree_widget.clear()
        self.hex_text.clear()
        self.ascii_text.clear()
        self.raw_text.clear()
