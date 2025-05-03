#!/usr/bin/env python3
"""
Dialogs Module
This module provides various dialog windows for the Network Packet Analyzer.
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QCheckBox, QTabWidget, QRadioButton,
    QGroupBox, QFormLayout, QSpinBox, QDialogButtonBox, QProgressBar,
    QListWidget, QListWidgetItem, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QTextEdit, QWidget
)
from PyQt5.QtCore import Qt, QSettings, pyqtSignal

import os
import psutil
from utils.visualization import PacketVisualization

class FilterDialog(QDialog):
    """
    A dialog for creating and applying display filters.
    """
    
    def __init__(self, parent=None):
        """Initialize the FilterDialog."""
        super().__init__(parent)
        
        self.setWindowTitle("Display Filter")
        self.setMinimumWidth(500)
        
        # Initialize variables
        self.filter_str = ""
        
        # Set up the UI
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Create filter input section
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.filter_input = QLineEdit()
        filter_layout.addWidget(self.filter_input)
        
        layout.addLayout(filter_layout)
        
        # Create filter builder section
        builder_group = QGroupBox("Filter Builder")
        builder_layout = QVBoxLayout(builder_group)
        
        # Protocol selector
        protocol_layout = QHBoxLayout()
        protocol_layout.addWidget(QLabel("Protocol:"))
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["Any", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS"])
        protocol_layout.addWidget(self.protocol_combo)
        
        builder_layout.addLayout(protocol_layout)
        
        # IP filter section
        ip_layout = QFormLayout()
        
        self.src_ip_input = QLineEdit()
        ip_layout.addRow("Source IP:", self.src_ip_input)
        
        self.dst_ip_input = QLineEdit()
        ip_layout.addRow("Destination IP:", self.dst_ip_input)
        
        builder_layout.addLayout(ip_layout)
        
        # Port filter section
        port_layout = QFormLayout()
        
        self.src_port_input = QLineEdit()
        port_layout.addRow("Source Port:", self.src_port_input)
        
        self.dst_port_input = QLineEdit()
        port_layout.addRow("Destination Port:", self.dst_port_input)
        
        builder_layout.addLayout(port_layout)
        
        # Content filter section
        content_layout = QFormLayout()
        
        self.content_input = QLineEdit()
        content_layout.addRow("Contains:", self.content_input)
        
        builder_layout.addLayout(content_layout)
        
        # Add builder to main layout
        layout.addWidget(builder_group)
        
        # Add buttons
        button_layout = QHBoxLayout()
        
        build_button = QPushButton("Build Filter")
        build_button.clicked.connect(self.build_filter)
        button_layout.addWidget(build_button)
        
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self.clear_filter)
        button_layout.addWidget(clear_button)
        
        button_layout.addStretch()
        
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        layout.addLayout(button_layout)
        
    def build_filter(self):
        """Build a filter string from the input fields."""
        filter_parts = []
        
        # Protocol filter
        protocol = self.protocol_combo.currentText()
        if protocol != "Any":
            filter_parts.append(protocol.lower())
            
        # IP filters
        src_ip = self.src_ip_input.text().strip()
        if src_ip:
            filter_parts.append(f"src host {src_ip}")
            
        dst_ip = self.dst_ip_input.text().strip()
        if dst_ip:
            filter_parts.append(f"dst host {dst_ip}")
            
        # Port filters
        src_port = self.src_port_input.text().strip()
        if src_port:
            filter_parts.append(f"src port {src_port}")
            
        dst_port = self.dst_port_input.text().strip()
        if dst_port:
            filter_parts.append(f"dst port {dst_port}")
            
        # Content filter
        content = self.content_input.text().strip()
        if content:
            # Content filter is not part of BPF syntax, so we'll handle it separately
            # in the application code
            filter_parts.append(f"contains {content}")
            
        # Combine filter parts with 'and'
        if filter_parts:
            self.filter_str = " and ".join(filter_parts)
            self.filter_input.setText(self.filter_str)
            
    def clear_filter(self):
        """Clear all filter fields."""
        self.protocol_combo.setCurrentIndex(0)
        self.src_ip_input.clear()
        self.dst_ip_input.clear()
        self.src_port_input.clear()
        self.dst_port_input.clear()
        self.content_input.clear()
        self.filter_input.clear()
        self.filter_str = ""
        
    def get_filter(self):
        """Get the filter string."""
        return self.filter_input.text()


class ScanDialog(QDialog):
    """
    A dialog for scanning the network for active devices.
    """
    
    def __init__(self, parent=None, ip_scanner=None):
        """Initialize the ScanDialog."""
        super().__init__(parent)
        
        self.setWindowTitle("Network Scanner")
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)
        
        # Initialize variables
        self.ip_scanner = ip_scanner
        self.scan_results = []
        
        # Set up the UI
        self.setup_ui()
        
        # Connect signals
        if self.ip_scanner:
            self.ip_scanner.scan_progress.connect(self.update_progress)
            self.ip_scanner.scan_complete.connect(self.on_scan_complete)
            self.ip_scanner.scan_error.connect(self.on_scan_error)
            
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Create scan options section
        options_group = QGroupBox("Scan Options")
        options_layout = QFormLayout(options_group)
        
        # Network adapter selector
        self.adapter_combo = QComboBox()
        self.populate_adapter_combo()
        options_layout.addRow("Network Adapter:", self.adapter_combo)
        
        # IP range input
        self.ip_range_input = QLineEdit()
        options_layout.addRow("IP Range:", self.ip_range_input)
        
        # Timeout input
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(5)
        options_layout.addRow("Timeout (seconds):", self.timeout_spin)
        
        # Verbose checkbox
        self.verbose_check = QCheckBox("Verbose Output")
        options_layout.addRow("", self.verbose_check)
        
        layout.addWidget(options_group)
        
        # Create progress section
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(QLabel("Progress:"))
        
        self.progress_bar = QProgressBar()
        progress_layout.addWidget(self.progress_bar)
        
        layout.addLayout(progress_layout)
        
        # Create results section
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Hostname"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        results_layout.addWidget(self.results_table)
        
        layout.addWidget(results_group)
        
        # Create buttons
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        button_layout.addStretch()
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
    def populate_adapter_combo(self):
        """Populate the adapter combo box with available network adapters."""
        self.adapter_combo.clear()
        
        try:
            adapters = psutil.net_if_addrs()
            for adapter_name in adapters:
                self.adapter_combo.addItem(adapter_name)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"Error getting network adapters: {str(e)}")
            
    def start_scan(self):
        """Start the network scan."""
        if not self.ip_scanner:
            QtWidgets.QMessageBox.warning(self, "Error", "IP scanner not initialized")
            return
            
        # Get scan options
        ip_range = self.ip_range_input.text().strip()
        if not ip_range:
            QtWidgets.QMessageBox.warning(self, "Error", "Please enter an IP range")
            return
            
        timeout = self.timeout_spin.value()
        verbose = self.verbose_check.isChecked()
        
        # Clear results
        self.results_table.setRowCount(0)
        self.scan_results = []
        
        # Update UI
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        
        # Start scan
        self.ip_scanner.start_scan(ip_range, timeout, verbose)
        
    def stop_scan(self):
        """Stop the network scan."""
        if self.ip_scanner:
            self.ip_scanner.stop_scan()
            
        # Update UI
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
    def update_progress(self, current, total):
        """Update the progress bar."""
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)
            
    def on_scan_complete(self, results):
        """Handle scan complete event."""
        self.scan_results = results
        
        # Update results table
        self.results_table.setRowCount(len(results))
        for i, result in enumerate(results):
            self.results_table.setItem(i, 0, QTableWidgetItem(result['ip']))
            self.results_table.setItem(i, 1, QTableWidgetItem(result['mac']))
            self.results_table.setItem(i, 2, QTableWidgetItem(result.get('hostname', '')))
            
        # Update UI
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100)
        
    def on_scan_error(self, error_msg):
        """Handle scan error event."""
        QtWidgets.QMessageBox.warning(self, "Scan Error", error_msg)
        
        # Update UI
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)


class StatisticsDialog(QDialog):
    """
    A dialog for displaying packet statistics.
    """
    
    def __init__(self, parent=None, packet_processor=None, stat_type="protocol"):
        """Initialize the StatisticsDialog."""
        super().__init__(parent)
        
        self.setWindowTitle("Packet Statistics")
        self.setMinimumWidth(800)
        self.setMinimumHeight(600)
        
        # Initialize variables
        self.packet_processor = packet_processor
        self.stat_type = stat_type
        self.visualizer = PacketVisualization()
        
        # Set up the UI
        self.setup_ui()
        
        # Show statistics
        self.show_statistics()
        
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs based on stat_type
        if self.stat_type == "protocol":
            self.create_protocol_tab()
        elif self.stat_type == "endpoints":
            self.create_endpoints_tab()
        elif self.stat_type == "conversations":
            self.create_conversations_tab()
        elif self.stat_type == "io_graph":
            self.create_io_graph_tab()
        else:
            # Default to protocol tab
            self.create_protocol_tab()
            
        layout.addWidget(self.tab_widget)
        
        # Add buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
    def create_protocol_tab(self):
        """Create the protocol statistics tab."""
        protocol_tab = QWidget()
        tab_layout = QVBoxLayout(protocol_tab)
        
        # Create splitter
        splitter = QSplitter(Qt.Vertical)
        
        # Create chart widget
        chart_widget = QWidget()
        chart_layout = QVBoxLayout(chart_widget)
        chart_layout.addWidget(QLabel("Protocol Distribution"))
        
        # Add chart placeholder (will be replaced in show_statistics)
        self.protocol_chart_placeholder = QWidget()
        chart_layout.addWidget(self.protocol_chart_placeholder)
        
        splitter.addWidget(chart_widget)
        
        # Create table widget
        self.protocol_table = QTableWidget()
        self.protocol_table.setColumnCount(2)
        self.protocol_table.setHorizontalHeaderLabels(["Protocol", "Count"])
        self.protocol_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        splitter.addWidget(self.protocol_table)
        
        # Set initial splitter sizes
        splitter.setSizes([300, 300])
        
        tab_layout.addWidget(splitter)
        
        self.tab_widget.addTab(protocol_tab, "Protocol Hierarchy")
        
    def create_endpoints_tab(self):
        """Create the endpoints statistics tab."""
        endpoints_tab = QWidget()
        tab_layout = QVBoxLayout(endpoints_tab)
        
        # Create splitter
        splitter = QSplitter(Qt.Vertical)
        
        # Create chart widget
        chart_widget = QWidget()
        chart_layout = QVBoxLayout(chart_widget)
        chart_layout.addWidget(QLabel("Top IP Traffic"))
        
        # Add chart placeholder (will be replaced in show_statistics)
        self.endpoints_chart_placeholder = QWidget()
        chart_layout.addWidget(self.endpoints_chart_placeholder)
        
        splitter.addWidget(chart_widget)
        
        # Create table widget
        self.endpoints_table = QTableWidget()
        self.endpoints_table.setColumnCount(5)
        self.endpoints_table.setHorizontalHeaderLabels(["IP Address", "Packets Sent", "Packets Received", "Bytes Sent", "Bytes Received"])
        self.endpoints_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        splitter.addWidget(self.endpoints_table)
        
        # Set initial splitter sizes
        splitter.setSizes([300, 300])
        
        tab_layout.addWidget(splitter)
        
        self.tab_widget.addTab(endpoints_tab, "Endpoints")
        
    def create_conversations_tab(self):
        """Create the conversations statistics tab."""
        conversations_tab = QWidget()
        tab_layout = QVBoxLayout(conversations_tab)
        
        # Create table widget
        self.conversations_table = QTableWidget()
        self.conversations_table.setColumnCount(5)
        self.conversations_table.setHorizontalHeaderLabels(["Source", "Destination", "Protocol", "Packets", "Bytes"])
        self.conversations_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        tab_layout.addWidget(self.conversations_table)
        
        self.tab_widget.addTab(conversations_tab, "Conversations")
        
    def create_io_graph_tab(self):
        """Create the IO graph tab."""
        io_graph_tab = QWidget()
        tab_layout = QVBoxLayout(io_graph_tab)
        
        # Create chart widget
        chart_layout = QVBoxLayout()
        chart_layout.addWidget(QLabel("Packet Activity Over Time"))
        
        # Add chart placeholder (will be replaced in show_statistics)
        self.io_graph_placeholder = QWidget()
        chart_layout.addWidget(self.io_graph_placeholder)
        
        tab_layout.addLayout(chart_layout)
        
        self.tab_widget.addTab(io_graph_tab, "IO Graph")
        
    def show_statistics(self):
        """Show statistics based on the selected type."""
        if not self.packet_processor:
            return
            
        if self.stat_type == "protocol":
            self.show_protocol_stats()
        elif self.stat_type == "endpoints":
            self.show_endpoints_stats()
        elif self.stat_type == "conversations":
            self.show_conversations_stats()
        elif self.stat_type == "io_graph":
            self.show_io_graph()
            
    def show_protocol_stats(self):
        """Show protocol statistics."""
        protocol_stats = self.packet_processor.get_protocol_stats()
        
        # Update table
        self.protocol_table.setRowCount(len(protocol_stats))
        for i, (protocol, count) in enumerate(protocol_stats.items()):
            self.protocol_table.setItem(i, 0, QTableWidgetItem(protocol))
            self.protocol_table.setItem(i, 1, QTableWidgetItem(str(count)))
            
        # Create chart
        if protocol_stats:
            chart = self.visualizer.create_protocol_distribution_chart(protocol_stats)
            
            # Replace placeholder with chart
            layout = self.protocol_chart_placeholder.parent().layout()
            layout.replaceWidget(self.protocol_chart_placeholder, chart)
            self.protocol_chart_placeholder.hide()
            self.protocol_chart_placeholder = chart
            
    def show_endpoints_stats(self):
        """Show endpoints statistics."""
        ip_stats = self.packet_processor.get_ip_stats()
        
        # Update table
        self.endpoints_table.setRowCount(len(ip_stats))
        for i, (ip, stats) in enumerate(ip_stats.items()):
            self.endpoints_table.setItem(i, 0, QTableWidgetItem(ip))
            self.endpoints_table.setItem(i, 1, QTableWidgetItem(str(stats['sent'])))
            self.endpoints_table.setItem(i, 2, QTableWidgetItem(str(stats['received'])))
            self.endpoints_table.setItem(i, 3, QTableWidgetItem(str(stats['bytes_sent'])))
            self.endpoints_table.setItem(i, 4, QTableWidgetItem(str(stats['bytes_received'])))
            
        # Create chart
        if ip_stats:
            chart = self.visualizer.create_traffic_flow_chart(ip_stats)
            
            # Replace placeholder with chart
            layout = self.endpoints_chart_placeholder.parent().layout()
            layout.replaceWidget(self.endpoints_chart_placeholder, chart)
            self.endpoints_chart_placeholder.hide()
            self.endpoints_chart_placeholder = chart
            
    def show_conversations_stats(self):
        """Show conversations statistics."""
        # This would require additional processing to generate conversation statistics
        # For now, we'll just show a placeholder
        self.conversations_table.setRowCount(0)
        
    def show_io_graph(self):
        """Show IO graph."""
        # Get packet times and sizes
        packet_infos = self.packet_processor.packet_infos if hasattr(self.packet_processor, 'packet_infos') else []
        
        if packet_infos:
            timestamps = [info['time'] for info in packet_infos if 'time' in info]
            packet_sizes = [info['length'] for info in packet_infos if 'length' in info]
            
            if timestamps and packet_sizes:
                chart = self.visualizer.create_time_series_chart(timestamps, packet_sizes)
                
                # Replace placeholder with chart
                layout = self.io_graph_placeholder.parent().layout()
                layout.replaceWidget(self.io_graph_placeholder, chart)
                self.io_graph_placeholder.hide()
                self.io_graph_placeholder = chart


class PreferencesDialog(QDialog):
    """
    A dialog for setting application preferences.
    """
    
    def __init__(self, parent=None):
        """Initialize the PreferencesDialog."""
        super().__init__(parent)
        
        self.setWindowTitle("Preferences")
        self.setMinimumWidth(500)
        
        # Initialize settings
        self.settings = QSettings("NetworkPacketAnalyzer", "PacketAnalyzer")
        
        # Set up the UI
        self.setup_ui()
        
        # Load current settings
        self.load_settings()
        
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Create appearance tab
        appearance_tab = QWidget()
        appearance_layout = QVBoxLayout(appearance_tab)
        
        # Theme selection
        theme_group = QGroupBox("Theme")
        theme_layout = QVBoxLayout(theme_group)
        
        self.dark_theme_radio = QRadioButton("Dark Theme")
        theme_layout.addWidget(self.dark_theme_radio)
        
        self.light_theme_radio = QRadioButton("Light Theme")
        theme_layout.addWidget(self.light_theme_radio)
        
        appearance_layout.addWidget(theme_group)
        
        # UI elements visibility
        visibility_group = QGroupBox("Show/Hide UI Elements")
        visibility_layout = QVBoxLayout(visibility_group)
        
        self.toolbar_check = QCheckBox("Show Toolbar")
        visibility_layout.addWidget(self.toolbar_check)
        
        self.statusbar_check = QCheckBox("Show Status Bar")
        visibility_layout.addWidget(self.statusbar_check)
        
        appearance_layout.addWidget(visibility_group)
        
        self.tab_widget.addTab(appearance_tab, "Appearance")
        
        # Create capture tab
        capture_tab = QWidget()
        capture_layout = QVBoxLayout(capture_tab)
        
        # Time display format
        time_group = QGroupBox("Time Display Format")
        time_layout = QVBoxLayout(time_group)
        
        self.absolute_time_radio = QRadioButton("Absolute Time")
        time_layout.addWidget(self.absolute_time_radio)
        
        self.relative_time_radio = QRadioButton("Relative Time")
        time_layout.addWidget(self.relative_time_radio)
        
        capture_layout.addWidget(time_group)
        
        # Capture options
        options_group = QGroupBox("Capture Options")
        options_layout = QFormLayout(options_group)
        
        self.promiscuous_check = QCheckBox("Promiscuous Mode")
        options_layout.addRow("", self.promiscuous_check)
        
        self.max_packets_spin = QSpinBox()
        self.max_packets_spin.setRange(0, 1000000)
        self.max_packets_spin.setSpecialValueText("No Limit")
        options_layout.addRow("Maximum Packets:", self.max_packets_spin)
        
        self.capture_timeout_spin = QSpinBox()
        self.capture_timeout_spin.setRange(0, 3600)
        self.capture_timeout_spin.setSpecialValueText("No Timeout")
        options_layout.addRow("Capture Timeout (seconds):", self.capture_timeout_spin)
        
        capture_layout.addWidget(options_group)
        
        self.tab_widget.addTab(capture_tab, "Capture")
        
        layout.addWidget(self.tab_widget)
        
        # Add buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.save_settings)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
    def load_settings(self):
        """Load current settings."""
        # Theme
        theme = self.settings.value("theme", "dark")
        if theme == "dark":
            self.dark_theme_radio.setChecked(True)
        else:
            self.light_theme_radio.setChecked(True)
            
        # UI elements visibility
        toolbar_visible = self.settings.value("toolbar_visible", "true") == "true"
        self.toolbar_check.setChecked(toolbar_visible)
        
        statusbar_visible = self.settings.value("statusbar_visible", "true") == "true"
        self.statusbar_check.setChecked(statusbar_visible)
        
        # Time display format
        time_format = self.settings.value("time_format", "absolute")
        if time_format == "absolute":
            self.absolute_time_radio.setChecked(True)
        else:
            self.relative_time_radio.setChecked(True)
            
        # Capture options
        promiscuous = self.settings.value("promiscuous_mode", "true") == "true"
        self.promiscuous_check.setChecked(promiscuous)
        
        max_packets = int(self.settings.value("max_packets", "0"))
        self.max_packets_spin.setValue(max_packets)
        
        capture_timeout = int(self.settings.value("capture_timeout", "0"))
        self.capture_timeout_spin.setValue(capture_timeout)
        
    def save_settings(self):
        """Save settings and close the dialog."""
        # Theme
        theme = "dark" if self.dark_theme_radio.isChecked() else "light"
        self.settings.setValue("theme", theme)
        
        # UI elements visibility
        self.settings.setValue("toolbar_visible", str(self.toolbar_check.isChecked()))
        self.settings.setValue("statusbar_visible", str(self.statusbar_check.isChecked()))
        
        # Time display format
        time_format = "absolute" if self.absolute_time_radio.isChecked() else "relative"
        self.settings.setValue("time_format", time_format)
        
        # Capture options
        self.settings.setValue("promiscuous_mode", str(self.promiscuous_check.isChecked()))
        self.settings.setValue("max_packets", str(self.max_packets_spin.value()))
        self.settings.setValue("capture_timeout", str(self.capture_timeout_spin.value()))
        
        # Accept the dialog
        self.accept()


class AboutDialog(QDialog):
    """
    A dialog for displaying information about the application.
    """
    
    def __init__(self, parent=None):
        """Initialize the AboutDialog."""
        super().__init__(parent)
        
        self.setWindowTitle("About Network Packet Analyzer")
        self.setFixedSize(500, 300)
        
        # Set up the UI
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Add application name
        app_name_label = QLabel("Network Packet Analyzer")
        app_name_label.setAlignment(Qt.AlignCenter)
        font = app_name_label.font()
        font.setPointSize(16)
        font.setBold(True)
        app_name_label.setFont(font)
        layout.addWidget(app_name_label)
        
        # Add version
        version_label = QLabel("Version 2.0.0")
        version_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_label)
        
        layout.addSpacing(20)
        
        # Add description
        description = (
            "Network Packet Analyzer is a tool for capturing and analyzing network packets. "
            "It provides a graphical user interface for viewing packet details, filtering packets, "
            "and generating statistics about network traffic."
        )
        description_label = QLabel(description)
        description_label.setWordWrap(True)
        description_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(description_label)
        
        layout.addSpacing(20)
        
        # Add copyright
        copyright_label = QLabel("© 2023 Network Packet Analyzer Team")
        copyright_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(copyright_label)
        
        layout.addSpacing(20)
        
        # Add close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button, alignment=Qt.AlignCenter)
