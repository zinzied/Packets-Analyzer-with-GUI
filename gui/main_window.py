#!/usr/bin/env python3
"""
Main Window Module
This module provides the main application window for the Network Packet Analyzer.
"""

import os
import sys
import logging
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QAction, QFileDialog, QMessageBox, QTabWidget, QLabel,
    QComboBox, QLineEdit, QPushButton, QStatusBar, QToolBar,
    QInputDialog
)
from PyQt5.QtCore import Qt, QSettings

from gui.packet_list import PacketListWidget
from gui.packet_details import PacketDetailsWidget
from gui.dialogs import (
    FilterDialog, ScanDialog, StatisticsDialog, 
    PreferencesDialog, AboutDialog
)

from core.packet_sniffer import PacketSniffer
from core.packet_processor import PacketProcessor
from core.ip_scanner import IPScanner

from utils.export import PacketExporter
from utils.filters import PacketFilter

class MainWindow(QMainWindow):
    """
    Main application window for the Network Packet Analyzer.
    
    This class provides the main GUI for the application, including
    menus, toolbars, and the main packet list and details views.
    """
    
    def __init__(self):
        """Initialize the main window."""
        super().__init__()
        
        # Initialize components
        self.packet_sniffer = PacketSniffer()
        self.packet_processor = PacketProcessor()
        self.ip_scanner = IPScanner()
        self.packet_exporter = PacketExporter()
        self.packet_filter = PacketFilter()
        
        # Initialize settings
        self.settings = QSettings("NetworkPacketAnalyzer", "PacketAnalyzer")
        
        # Initialize UI
        self.init_ui()
        
        # Connect signals
        self.connect_signals()
        
        # Check if Npcap is installed
        if not PacketSniffer.check_npcap_installed():
            self.show_npcap_warning()
            
    def init_ui(self):
        """Initialize the user interface."""
        # Set window properties
        self.setWindowTitle("Network Packet Analyzer")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)
        
        # Create splitter for resizable panels
        self.splitter = QSplitter(Qt.Vertical)
        
        # Create packet list widget
        self.packet_list = PacketListWidget()
        
        # Create packet details widget
        self.packet_details = PacketDetailsWidget()
        
        # Add widgets to splitter
        self.splitter.addWidget(self.packet_list)
        self.splitter.addWidget(self.packet_details)
        
        # Set initial splitter sizes
        self.splitter.setSizes([600, 200])
        
        # Add splitter to main layout
        main_layout.addWidget(self.splitter)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Create status labels
        self.status_label = QLabel("Ready")
        self.packet_count_label = QLabel("Packets: 0")
        self.filter_status_label = QLabel("Filter: None")
        
        # Add labels to status bar
        self.status_bar.addWidget(self.status_label, 1)
        self.status_bar.addPermanentWidget(self.filter_status_label)
        self.status_bar.addPermanentWidget(self.packet_count_label)
        
        # Create menus
        self.create_menus()
        
        # Create toolbar
        self.create_toolbar()
        
        # Load settings
        self.load_settings()
        
    def create_menus(self):
        """Create application menus."""
        # File menu
        file_menu = self.menuBar().addMenu("&File")
        
        open_action = QAction("&Open Capture File...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_capture_file)
        file_menu.addAction(open_action)
        
        save_action = QAction("&Save Capture As...", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.save_capture_file)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        export_submenu = file_menu.addMenu("&Export Packets")
        
        export_csv_action = QAction("Export as &CSV...", self)
        export_csv_action.triggered.connect(lambda: self.export_packets("csv"))
        export_submenu.addAction(export_csv_action)
        
        export_json_action = QAction("Export as &JSON...", self)
        export_json_action.triggered.connect(lambda: self.export_packets("json"))
        export_submenu.addAction(export_json_action)
        
        file_menu.addSeparator()
        
        preferences_action = QAction("&Preferences...", self)
        preferences_action.triggered.connect(self.show_preferences)
        file_menu.addAction(preferences_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Alt+F4")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Capture menu
        capture_menu = self.menuBar().addMenu("&Capture")
        
        self.start_action = QAction("&Start Capture", self)
        self.start_action.setShortcut("F5")
        self.start_action.triggered.connect(self.start_capture)
        capture_menu.addAction(self.start_action)
        
        self.stop_action = QAction("S&top Capture", self)
        self.stop_action.setShortcut("F6")
        self.stop_action.triggered.connect(self.stop_capture)
        self.stop_action.setEnabled(False)
        capture_menu.addAction(self.stop_action)
        
        capture_menu.addSeparator()
        
        self.restart_action = QAction("&Restart Capture", self)
        self.restart_action.setShortcut("F7")
        self.restart_action.triggered.connect(self.restart_capture)
        capture_menu.addAction(self.restart_action)
        
        capture_menu.addSeparator()
        
        capture_options_action = QAction("Capture &Options...", self)
        capture_options_action.triggered.connect(self.show_capture_options)
        capture_menu.addAction(capture_options_action)
        
        # Edit menu
        edit_menu = self.menuBar().addMenu("&Edit")
        
        find_packet_action = QAction("&Find Packet...", self)
        find_packet_action.setShortcut("Ctrl+F")
        find_packet_action.triggered.connect(self.find_packet)
        edit_menu.addAction(find_packet_action)
        
        edit_menu.addSeparator()
        
        mark_packet_action = QAction("&Mark Packet", self)
        mark_packet_action.setShortcut("Ctrl+M")
        mark_packet_action.triggered.connect(self.mark_packet)
        edit_menu.addAction(mark_packet_action)
        
        edit_menu.addSeparator()
        
        clear_action = QAction("&Clear All Packets", self)
        clear_action.triggered.connect(self.clear_packets)
        edit_menu.addAction(clear_action)
        
        # View menu
        view_menu = self.menuBar().addMenu("&View")
        
        self.theme_submenu = view_menu.addMenu("&Theme")
        
        dark_theme_action = QAction("&Dark Theme", self)
        dark_theme_action.triggered.connect(lambda: self.change_theme("dark"))
        self.theme_submenu.addAction(dark_theme_action)
        
        light_theme_action = QAction("&Light Theme", self)
        light_theme_action.triggered.connect(lambda: self.change_theme("light"))
        self.theme_submenu.addAction(light_theme_action)
        
        view_menu.addSeparator()
        
        self.toolbar_action = QAction("Show &Toolbar", self)
        self.toolbar_action.setCheckable(True)
        self.toolbar_action.setChecked(True)
        self.toolbar_action.triggered.connect(self.toggle_toolbar)
        view_menu.addAction(self.toolbar_action)
        
        self.statusbar_action = QAction("Show &Status Bar", self)
        self.statusbar_action.setCheckable(True)
        self.statusbar_action.setChecked(True)
        self.statusbar_action.triggered.connect(self.toggle_statusbar)
        view_menu.addAction(self.statusbar_action)
        
        view_menu.addSeparator()
        
        time_display_submenu = view_menu.addMenu("&Time Display Format")
        
        absolute_time_action = QAction("&Absolute Time", self)
        absolute_time_action.triggered.connect(lambda: self.set_time_format("absolute"))
        time_display_submenu.addAction(absolute_time_action)
        
        relative_time_action = QAction("&Relative Time", self)
        relative_time_action.triggered.connect(lambda: self.set_time_format("relative"))
        time_display_submenu.addAction(relative_time_action)
        
        # Analyze menu
        analyze_menu = self.menuBar().addMenu("&Analyze")
        
        filter_action = QAction("&Display Filter...", self)
        filter_action.setShortcut("Ctrl+D")
        filter_action.triggered.connect(self.show_filter_dialog)
        analyze_menu.addAction(filter_action)
        
        analyze_menu.addSeparator()
        
        follow_stream_action = QAction("&Follow TCP Stream", self)
        follow_stream_action.triggered.connect(self.follow_tcp_stream)
        analyze_menu.addAction(follow_stream_action)
        
        analyze_menu.addSeparator()
        
        statistics_submenu = analyze_menu.addMenu("&Statistics")
        
        protocol_stats_action = QAction("&Protocol Hierarchy", self)
        protocol_stats_action.triggered.connect(lambda: self.show_statistics("protocol"))
        statistics_submenu.addAction(protocol_stats_action)
        
        endpoints_action = QAction("&Endpoints", self)
        endpoints_action.triggered.connect(lambda: self.show_statistics("endpoints"))
        statistics_submenu.addAction(endpoints_action)
        
        conversations_action = QAction("&Conversations", self)
        conversations_action.triggered.connect(lambda: self.show_statistics("conversations"))
        statistics_submenu.addAction(conversations_action)
        
        io_graph_action = QAction("&IO Graph", self)
        io_graph_action.triggered.connect(lambda: self.show_statistics("io_graph"))
        statistics_submenu.addAction(io_graph_action)
        
        # Tools menu
        tools_menu = self.menuBar().addMenu("&Tools")
        
        scan_network_action = QAction("&Scan Network...", self)
        scan_network_action.triggered.connect(self.show_scan_dialog)
        tools_menu.addAction(scan_network_action)
        
        # Help menu
        help_menu = self.menuBar().addMenu("&Help")
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)
        
    def create_toolbar(self):
        """Create application toolbar."""
        self.toolbar = QToolBar("Main Toolbar")
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QtCore.QSize(24, 24))
        self.addToolBar(self.toolbar)
        
        # Add actions to toolbar
        self.toolbar.addAction(self.start_action)
        self.toolbar.addAction(self.stop_action)
        self.toolbar.addAction(self.restart_action)
        self.toolbar.addSeparator()
        
        # Add interface selector
        self.toolbar.addWidget(QLabel("Interface: "))
        self.interface_selector = QComboBox()
        self.interface_selector.setMinimumWidth(200)
        self.toolbar.addWidget(self.interface_selector)
        
        # Populate interface selector
        self.populate_interface_selector()
        
        self.toolbar.addSeparator()
        
        # Add filter input
        self.toolbar.addWidget(QLabel("Filter: "))
        self.filter_input = QLineEdit()
        self.filter_input.setMinimumWidth(300)
        self.filter_input.returnPressed.connect(self.apply_filter)
        self.toolbar.addWidget(self.filter_input)
        
        filter_button = QPushButton("Apply")
        filter_button.clicked.connect(self.apply_filter)
        self.toolbar.addWidget(filter_button)
        
        clear_filter_button = QPushButton("Clear")
        clear_filter_button.clicked.connect(self.clear_filter)
        self.toolbar.addWidget(clear_filter_button)
        
    def populate_interface_selector(self):
        """Populate the interface selector with available network interfaces."""
        self.interface_selector.clear()
        interfaces = PacketSniffer.get_available_interfaces()
        for interface in interfaces:
            self.interface_selector.addItem(interface)
            
    def connect_signals(self):
        """Connect signals to slots."""
        # Connect packet sniffer signals
        self.packet_sniffer.packet_captured.connect(self.process_packet)
        self.packet_sniffer.sniffing_started.connect(self.on_sniffing_started)
        self.packet_sniffer.sniffing_stopped.connect(self.on_sniffing_stopped)
        self.packet_sniffer.error_occurred.connect(self.show_error)
        
        # Connect IP scanner signals
        self.ip_scanner.scan_progress.connect(self.update_scan_progress)
        self.ip_scanner.scan_complete.connect(self.on_scan_complete)
        self.ip_scanner.scan_error.connect(self.show_error)
        
        # Connect packet list signals
        self.packet_list.itemSelectionChanged.connect(self.on_packet_selected)
        
    def load_settings(self):
        """Load application settings."""
        # Load window geometry
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
            
        # Load window state
        state = self.settings.value("windowState")
        if state:
            self.restoreState(state)
            
        # Load theme
        theme = self.settings.value("theme", "dark")
        self.change_theme(theme)
        
        # Load toolbar visibility
        toolbar_visible = self.settings.value("toolbar_visible", "true") == "true"
        self.toolbar.setVisible(toolbar_visible)
        self.toolbar_action.setChecked(toolbar_visible)
        
        # Load statusbar visibility
        statusbar_visible = self.settings.value("statusbar_visible", "true") == "true"
        self.status_bar.setVisible(statusbar_visible)
        self.statusbar_action.setChecked(statusbar_visible)
        
        # Load time format
        time_format = self.settings.value("time_format", "absolute")
        self.set_time_format(time_format)
        
    def save_settings(self):
        """Save application settings."""
        # Save window geometry
        self.settings.setValue("geometry", self.saveGeometry())
        
        # Save window state
        self.settings.setValue("windowState", self.saveState())
        
        # Save theme
        self.settings.setValue("theme", self.current_theme)
        
        # Save toolbar visibility
        self.settings.setValue("toolbar_visible", str(self.toolbar.isVisible()))
        
        # Save statusbar visibility
        self.settings.setValue("statusbar_visible", str(self.status_bar.isVisible()))
        
        # Save time format
        self.settings.setValue("time_format", self.current_time_format)
        
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop capture if running
        if self.packet_sniffer.sniffing:
            self.stop_capture()
            
        # Save settings
        self.save_settings()
        
        # Accept the event
        event.accept()
        
    def change_theme(self, theme):
        """Change the application theme."""
        self.current_theme = theme
        
        # Load the theme stylesheet
        stylesheet_path = f"gui/styles/{theme}_theme.qss"
        if os.path.exists(stylesheet_path):
            with open(stylesheet_path, "r") as f:
                self.setStyleSheet(f.read())
                
    def toggle_toolbar(self):
        """Toggle toolbar visibility."""
        self.toolbar.setVisible(not self.toolbar.isVisible())
        self.toolbar_action.setChecked(self.toolbar.isVisible())
        
    def toggle_statusbar(self):
        """Toggle status bar visibility."""
        self.status_bar.setVisible(not self.status_bar.isVisible())
        self.statusbar_action.setChecked(self.status_bar.isVisible())
        
    def set_time_format(self, format_type):
        """Set the time display format."""
        self.current_time_format = format_type
        self.packet_list.set_time_format(format_type)
        
    def start_capture(self):
        """Start packet capture."""
        # Get selected interface
        interface = self.interface_selector.currentText()
        if not interface:
            self.show_error("No interface selected")
            return
            
        # Get filter string
        filter_str = self.filter_input.text()
        
        # Configure packet sniffer
        self.packet_sniffer.set_interface(interface)
        self.packet_sniffer.set_filter(filter_str)
        
        # Clear existing packets if needed
        self.clear_packets()
        
        # Reset packet processor
        self.packet_processor.reset_stats()
        
        # Start capture
        self.packet_sniffer.start()
        
    def stop_capture(self):
        """Stop packet capture."""
        self.packet_sniffer.stop()
        
    def restart_capture(self):
        """Restart packet capture."""
        self.stop_capture()
        self.start_capture()
        
    def clear_packets(self):
        """Clear all captured packets."""
        self.packet_list.clear()
        self.packet_details.clear()
        self.packet_processor.reset_stats()
        self.update_status("Cleared all packets")
        self.update_packet_count(0)
        
    def process_packet(self, packet):
        """Process a captured packet."""
        # Process the packet
        packet_info = self.packet_processor.process_packet(packet)
        
        # Add to packet list
        self.packet_list.add_packet(packet, packet_info)
        
        # Update status
        self.update_packet_count(self.packet_list.count())
        self.update_status(f"Captured: {packet_info['protocol']} packet from {packet_info['src']} to {packet_info['dst']}")
        
    def on_packet_selected(self):
        """Handle packet selection."""
        selected_items = self.packet_list.selectedItems()
        if selected_items:
            # Get the selected packet
            packet_index = self.packet_list.row(selected_items[0])
            packet = self.packet_list.get_packet(packet_index)
            
            # Show packet details
            self.packet_details.show_packet(packet)
            
    def on_sniffing_started(self):
        """Handle sniffing started event."""
        self.start_action.setEnabled(False)
        self.stop_action.setEnabled(True)
        self.update_status("Packet capture started")
        
    def on_sniffing_stopped(self):
        """Handle sniffing stopped event."""
        self.start_action.setEnabled(True)
        self.stop_action.setEnabled(False)
        self.update_status("Packet capture stopped")
        
    def update_status(self, message):
        """Update status bar message."""
        self.status_label.setText(message)
        
    def update_packet_count(self, count):
        """Update packet count in status bar."""
        self.packet_count_label.setText(f"Packets: {count}")
        
    def update_filter_status(self, filter_str):
        """Update filter status in status bar."""
        if filter_str:
            self.filter_status_label.setText(f"Filter: {filter_str}")
        else:
            self.filter_status_label.setText("Filter: None")
            
    def apply_filter(self):
        """Apply display filter."""
        filter_str = self.filter_input.text()
        self.update_filter_status(filter_str)
        
        # Apply filter to packet list
        self.packet_list.apply_filter(filter_str)
        
    def clear_filter(self):
        """Clear display filter."""
        self.filter_input.clear()
        self.update_filter_status("")
        
        # Clear filter from packet list
        self.packet_list.clear_filter()
        
    def open_capture_file(self):
        """Open a capture file."""
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Open Capture File",
            "",
            "PCAP Files (*.pcap *.pcapng);;All Files (*)",
            options=options
        )
        
        if file_name:
            try:
                import scapy.all as scapy
                
                # Clear existing packets
                self.clear_packets()
                
                # Read packets from file
                packets = scapy.rdpcap(file_name)
                
                # Process each packet
                for packet in packets:
                    self.process_packet(packet)
                    
                self.update_status(f"Loaded {len(packets)} packets from {file_name}")
                
            except Exception as e:
                self.show_error(f"Error loading capture file: {str(e)}")
                
    def save_capture_file(self):
        """Save captured packets to a file."""
        if self.packet_list.count() == 0:
            self.show_error("No packets to save")
            return
            
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Save Capture As",
            "",
            "PCAP Files (*.pcap);;All Files (*)",
            options=options
        )
        
        if file_name:
            try:
                # Get all packets
                packets = self.packet_list.get_all_packets()
                
                # Save to file
                self.packet_exporter.export_to_pcap(packets, file_name)
                
                self.update_status(f"Saved {len(packets)} packets to {file_name}")
                
            except Exception as e:
                self.show_error(f"Error saving capture file: {str(e)}")
                
    def export_packets(self, format_type):
        """Export packets to a file."""
        if self.packet_list.count() == 0:
            self.show_error("No packets to export")
            return
            
        options = QFileDialog.Options()
        
        if format_type == "csv":
            file_name, _ = QFileDialog.getSaveFileName(
                self,
                "Export Packets as CSV",
                "",
                "CSV Files (*.csv);;All Files (*)",
                options=options
            )
            
            if file_name:
                try:
                    # Get all packets
                    packets = self.packet_list.get_all_packets()
                    
                    # Export to CSV
                    self.packet_exporter.export_to_csv(packets, file_name)
                    
                    self.update_status(f"Exported {len(packets)} packets to {file_name}")
                    
                except Exception as e:
                    self.show_error(f"Error exporting packets: {str(e)}")
                    
        elif format_type == "json":
            file_name, _ = QFileDialog.getSaveFileName(
                self,
                "Export Packets as JSON",
                "",
                "JSON Files (*.json);;All Files (*)",
                options=options
            )
            
            if file_name:
                try:
                    # Get all packets
                    packets = self.packet_list.get_all_packets()
                    
                    # Export to JSON
                    self.packet_exporter.export_to_json(packets, file_name)
                    
                    self.update_status(f"Exported {len(packets)} packets to {file_name}")
                    
                except Exception as e:
                    self.show_error(f"Error exporting packets: {str(e)}")
                    
    def show_capture_options(self):
        """Show capture options dialog."""
        # This would be implemented in a separate dialog class
        pass
        
    def find_packet(self):
        """Show find packet dialog."""
        # This would be implemented in a separate dialog class
        pass
        
    def mark_packet(self):
        """Mark the selected packet."""
        selected_items = self.packet_list.selectedItems()
        if selected_items:
            self.packet_list.mark_packet(self.packet_list.row(selected_items[0]))
            
    def follow_tcp_stream(self):
        """Follow TCP stream for the selected packet."""
        selected_items = self.packet_list.selectedItems()
        if not selected_items:
            self.show_error("No packet selected")
            return
            
        packet_index = self.packet_list.row(selected_items[0])
        packet = self.packet_list.get_packet(packet_index)
        
        # Check if it's a TCP packet
        import scapy.all as scapy
        if not packet.haslayer(scapy.TCP):
            self.show_error("Selected packet is not a TCP packet")
            return
            
        # Get all packets
        all_packets = self.packet_list.get_all_packets()
        
        # Find all packets in the same TCP stream
        stream_packets = []
        
        for pkt in all_packets:
            if pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.TCP):
                if ((pkt[scapy.IP].src == packet[scapy.IP].src and
                     pkt[scapy.IP].dst == packet[scapy.IP].dst and
                     pkt[scapy.TCP].sport == packet[scapy.TCP].sport and
                     pkt[scapy.TCP].dport == packet[scapy.TCP].dport) or
                    (pkt[scapy.IP].src == packet[scapy.IP].dst and
                     pkt[scapy.IP].dst == packet[scapy.IP].src and
                     pkt[scapy.TCP].sport == packet[scapy.TCP].dport and
                     pkt[scapy.TCP].dport == packet[scapy.TCP].sport)):
                    stream_packets.append(pkt)
                    
        # Show the stream in a new dialog
        # This would be implemented in a separate dialog class
        
    def show_filter_dialog(self):
        """Show filter dialog."""
        dialog = FilterDialog(self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            filter_str = dialog.get_filter()
            self.filter_input.setText(filter_str)
            self.apply_filter()
            
    def show_scan_dialog(self):
        """Show network scan dialog."""
        dialog = ScanDialog(self, self.ip_scanner)
        dialog.exec_()
        
    def update_scan_progress(self, current, total):
        """Update scan progress."""
        # This would be handled by the ScanDialog
        pass
        
    def on_scan_complete(self, results):
        """Handle scan complete event."""
        # This would be handled by the ScanDialog
        pass
        
    def show_statistics(self, stat_type):
        """Show statistics dialog."""
        dialog = StatisticsDialog(self, self.packet_processor, stat_type)
        dialog.exec_()
        
    def show_preferences(self):
        """Show preferences dialog."""
        dialog = PreferencesDialog(self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            # Apply preferences
            pass
            
    def show_about_dialog(self):
        """Show about dialog."""
        dialog = AboutDialog(self)
        dialog.exec_()
        
    def show_error(self, message):
        """Show error message."""
        QMessageBox.critical(self, "Error", message)
        
    def show_npcap_warning(self):
        """Show warning if Npcap is not installed."""
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Npcap Required")
        msg.setText("Npcap is required to use this application")
        msg.setInformativeText(
            "This application requires Npcap to capture and analyze network packets. "
            "Please download and install Npcap from https://npcap.com before using this application."
        )
        
        # Add buttons
        download_button = msg.addButton("Download Npcap", QMessageBox.ActionRole)
        exit_button = msg.addButton("Exit", QMessageBox.RejectRole)
        continue_button = msg.addButton("Continue Anyway", QMessageBox.AcceptRole)
        
        msg.exec_()
        
        # Handle button clicks
        if msg.clickedButton() == download_button:
            import webbrowser
            webbrowser.open("https://npcap.com/dist/npcap-1.79.exe")
        elif msg.clickedButton() == exit_button:
            sys.exit()
