#!/usr/bin/env python3
"""
Packet List Widget Module
This module provides a widget for displaying a list of captured packets.
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView, QMenu, QAction
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QBrush

import time
from datetime import datetime

class PacketListWidget(QTableWidget):
    """
    A widget for displaying a list of captured packets.

    This widget provides a table view of captured packets with columns for
    packet number, time, source, destination, protocol, length, and info.
    """

    def __init__(self, parent=None):
        """Initialize the PacketListWidget."""
        super().__init__(parent)

        # Initialize variables
        self.packets = []  # List of scapy packet objects
        self.packet_infos = []  # List of packet info dictionaries
        self.filtered_indices = []  # List of indices of packets that match the filter
        self.marked_packets = set()  # Set of indices of marked packets
        self.time_format = "absolute"  # Time display format
        self.first_packet_time = None  # Time of the first packet (for relative time)

        # Set up the table
        self.setup_table()

        # Set up context menu
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def setup_table(self):
        """Set up the table columns and properties."""
        # Set column headers
        self.setColumnCount(7)
        self.setHorizontalHeaderLabels([
            "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"
        ])

        # Set column widths
        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)  # No.
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Time
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Source
        self.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Destination
        self.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Protocol
        self.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Length
        self.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)  # Info

        # Set selection behavior
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

        # Set sorting enabled
        self.setSortingEnabled(True)

        # Set alternating row colors
        self.setAlternatingRowColors(True)

    def add_packet(self, packet, packet_info):
        """
        Add a packet to the list.

        Args:
            packet: A scapy packet object
            packet_info: A dictionary containing packet information
        """
        # Store the packet and info
        self.packets.append(packet)
        self.packet_infos.append(packet_info)

        # Get the packet index
        packet_index = len(self.packets) - 1

        # Store the first packet time for relative time calculations
        if self.first_packet_time is None and packet_info['time'] is not None:
            self.first_packet_time = packet_info['time']

        # Add a row to the table
        self.add_packet_row(packet_index)

        # Add to filtered indices if no filter is applied
        if not self.filtered_indices:
            self.filtered_indices.append(packet_index)

    def add_packet_row(self, packet_index):
        """
        Add a row to the table for the packet at the given index.

        Args:
            packet_index: The index of the packet in the packets list
        """
        # Get packet info
        packet_info = self.packet_infos[packet_index]

        # Insert a new row
        row = self.rowCount()
        self.insertRow(row)

        # Set row data
        self.set_row_data(row, packet_index, packet_info)

    def set_row_data(self, row, packet_index, packet_info):
        """
        Set the data for a row in the table.

        Args:
            row: The row index in the table
            packet_index: The index of the packet in the packets list
            packet_info: A dictionary containing packet information
        """
        # Create items for each column
        no_item = QTableWidgetItem(str(packet_index + 1))
        no_item.setData(Qt.UserRole, packet_index)  # Store packet index for reference

        # Format time based on time_format
        if self.time_format == "absolute" and packet_info['time'] is not None:
            time_str = datetime.fromtimestamp(packet_info['time']).strftime('%H:%M:%S.%f')[:-3]
        elif self.time_format == "relative" and packet_info['time'] is not None and self.first_packet_time is not None:
            time_str = f"{packet_info['time'] - self.first_packet_time:.6f}"
        else:
            time_str = ""

        time_item = QTableWidgetItem(time_str)

        # Other columns
        source_item = QTableWidgetItem(str(packet_info['src']) if packet_info['src'] else "")
        dest_item = QTableWidgetItem(str(packet_info['dst']) if packet_info['dst'] else "")
        protocol_item = QTableWidgetItem(str(packet_info['protocol']))
        length_item = QTableWidgetItem(str(packet_info['length']))
        info_item = QTableWidgetItem(str(packet_info['summary']))

        # Set items in the table
        self.setItem(row, 0, no_item)
        self.setItem(row, 1, time_item)
        self.setItem(row, 2, source_item)
        self.setItem(row, 3, dest_item)
        self.setItem(row, 4, protocol_item)
        self.setItem(row, 5, length_item)
        self.setItem(row, 6, info_item)

        # Set background color based on protocol
        if 'color' in packet_info:
            color = QColor(packet_info['color'])
            for col in range(self.columnCount()):
                self.item(row, col).setBackground(QBrush(color))

        # Set foreground color to black for better contrast
        for col in range(self.columnCount()):
            self.item(row, col).setForeground(QBrush(QColor("#000000")))

        # If this packet is marked, set a different background color
        if packet_index in self.marked_packets:
            for col in range(self.columnCount()):
                self.item(row, col).setBackground(QBrush(QColor("#FF9999")))

    def clear(self):
        """Clear all packets from the list."""
        self.setRowCount(0)
        self.packets = []
        self.packet_infos = []
        self.filtered_indices = []
        self.marked_packets = set()
        self.first_packet_time = None

    def get_packet(self, row_index):
        """
        Get the packet at the given row index.

        Args:
            row_index: The row index in the table

        Returns:
            The scapy packet object at the given row
        """
        if 0 <= row_index < self.rowCount():
            item = self.item(row_index, 0)
            if item:
                packet_index = item.data(Qt.UserRole)
                if 0 <= packet_index < len(self.packets):
                    return self.packets[packet_index]
        return None

    def get_all_packets(self):
        """
        Get all packets.

        Returns:
            A list of all scapy packet objects
        """
        return self.packets

    def get_filtered_packets(self):
        """
        Get all packets that match the current filter.

        Returns:
            A list of scapy packet objects that match the filter
        """
        return [self.packets[i] for i in self.filtered_indices]

    def apply_filter(self, filter_str):
        """
        Apply a display filter to the packet list.

        Args:
            filter_str: The filter string to apply
        """
        if not filter_str:
            self.clear_filter()
            return

        # Clear the table
        self.setRowCount(0)

        # Clear filtered indices
        self.filtered_indices = []

        # Apply filter to each packet
        for i, packet_info in enumerate(self.packet_infos):
            # Simple string matching for now
            # In a real implementation, this would use a proper filter parser
            if (filter_str.lower() in str(packet_info).lower() or
                filter_str.lower() in packet_info['summary'].lower()):
                self.filtered_indices.append(i)
                self.add_packet_row(i)

    def clear_filter(self):
        """Clear the display filter."""
        # Clear the table
        self.setRowCount(0)

        # Reset filtered indices to include all packets
        self.filtered_indices = list(range(len(self.packets)))

        # Add all packets to the table
        for i in self.filtered_indices:
            self.add_packet_row(i)

    def set_time_format(self, format_type):
        """
        Set the time display format.

        Args:
            format_type: The time format to use ('absolute' or 'relative')
        """
        if format_type in ["absolute", "relative"]:
            self.time_format = format_type

            # Update all rows with the new time format
            for row in range(self.rowCount()):
                packet_index = self.item(row, 0).data(Qt.UserRole)
                packet_info = self.packet_infos[packet_index]

                # Update the time column
                if self.time_format == "absolute" and packet_info['time'] is not None:
                    time_str = datetime.fromtimestamp(packet_info['time']).strftime('%H:%M:%S.%f')[:-3]
                elif self.time_format == "relative" and packet_info['time'] is not None and self.first_packet_time is not None:
                    time_str = f"{packet_info['time'] - self.first_packet_time:.6f}"
                else:
                    time_str = ""

                self.item(row, 1).setText(time_str)

    def mark_packet(self, row_index):
        """
        Mark or unmark a packet.

        Args:
            row_index: The row index in the table
        """
        if 0 <= row_index < self.rowCount():
            item = self.item(row_index, 0)
            if item:
                packet_index = item.data(Qt.UserRole)

                # Toggle marked state
                if packet_index in self.marked_packets:
                    self.marked_packets.remove(packet_index)

                    # Reset background color based on protocol
                    packet_info = self.packet_infos[packet_index]
                    color = QColor(packet_info['color'])
                    for col in range(self.columnCount()):
                        self.item(row_index, col).setBackground(QBrush(color))

                else:
                    self.marked_packets.add(packet_index)

                    # Set marked background color
                    for col in range(self.columnCount()):
                        self.item(row_index, col).setBackground(QBrush(QColor("#FF9999")))

    def show_context_menu(self, position):
        """
        Show context menu for the packet list.

        Args:
            position: The position where the context menu should be shown
        """
        menu = QMenu()

        # Get the row under the cursor
        row = self.rowAt(position.y())
        if row >= 0:
            # Add actions for a specific packet
            mark_action = QAction("Mark/Unmark Packet", self)
            mark_action.triggered.connect(lambda: self.mark_packet(row))
            menu.addAction(mark_action)

            follow_tcp_action = QAction("Follow TCP Stream", self)
            follow_tcp_action.triggered.connect(lambda: self.follow_tcp_stream(row))
            menu.addAction(follow_tcp_action)

            menu.addSeparator()

        # Add general actions
        clear_action = QAction("Clear All Packets", self)
        clear_action.triggered.connect(self.clear)
        menu.addAction(clear_action)

        # Show the menu
        menu.exec_(self.mapToGlobal(position))

    def follow_tcp_stream(self, row_index):
        """
        Follow TCP stream for the packet at the given row.

        Args:
            row_index: The row index in the table
        """
        # This would be implemented in the main window
        # We would emit a signal here that the main window would connect to
        pass

    def count(self):
        """
        Get the number of packets in the list.

        Returns:
            int: The number of packets in the list
        """
        return len(self.filtered_indices)
