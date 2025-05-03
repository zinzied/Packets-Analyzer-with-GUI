#!/usr/bin/env python3
"""
Visualization Module
This module provides functionality for visualizing packet data.
"""

import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np
from PyQt5.QtWidgets import QSizePolicy

class PacketVisualization:
    """
    A class for visualizing packet data.
    
    This class provides functionality to create various visualizations
    of packet data, such as protocol distribution, traffic flow, etc.
    """
    
    def __init__(self):
        """Initialize the PacketVisualization."""
        pass
        
    def create_protocol_distribution_chart(self, protocol_stats):
        """
        Create a protocol distribution chart.
        
        Args:
            protocol_stats (dict): A dictionary of protocol statistics
            
        Returns:
            FigureCanvas: A matplotlib figure canvas
        """
        fig = Figure(figsize=(6, 4), dpi=100)
        canvas = FigureCanvas(fig)
        canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        ax = fig.add_subplot(111)
        
        protocols = list(protocol_stats.keys())
        counts = list(protocol_stats.values())
        
        # Sort by count in descending order
        sorted_indices = np.argsort(counts)[::-1]
        protocols = [protocols[i] for i in sorted_indices]
        counts = [counts[i] for i in sorted_indices]
        
        # Use a colorful palette
        colors = plt.cm.viridis(np.linspace(0, 1, len(protocols)))
        
        # Create the pie chart
        wedges, texts, autotexts = ax.pie(
            counts,
            labels=protocols,
            autopct='%1.1f%%',
            startangle=90,
            colors=colors
        )
        
        # Make the labels and percentages more readable
        for text in texts:
            text.set_fontsize(9)
        for autotext in autotexts:
            autotext.set_fontsize(9)
            autotext.set_color('white')
            
        ax.set_title('Protocol Distribution')
        ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        
        fig.tight_layout()
        
        return canvas
        
    def create_traffic_flow_chart(self, ip_stats, top_n=10):
        """
        Create a traffic flow chart.
        
        Args:
            ip_stats (dict): A dictionary of IP statistics
            top_n (int): The number of top IPs to show
            
        Returns:
            FigureCanvas: A matplotlib figure canvas
        """
        fig = Figure(figsize=(8, 6), dpi=100)
        canvas = FigureCanvas(fig)
        canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        ax = fig.add_subplot(111)
        
        # Calculate total traffic for each IP
        ip_traffic = {}
        for ip, stats in ip_stats.items():
            total_bytes = stats['bytes_sent'] + stats['bytes_received']
            ip_traffic[ip] = total_bytes
            
        # Sort IPs by total traffic in descending order
        sorted_ips = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)
        
        # Take the top N IPs
        top_ips = sorted_ips[:top_n]
        
        # Extract data for the chart
        ips = [ip for ip, _ in top_ips]
        sent = [ip_stats[ip]['bytes_sent'] for ip in ips]
        received = [ip_stats[ip]['bytes_received'] for ip in ips]
        
        # Create the stacked bar chart
        x = np.arange(len(ips))
        width = 0.35
        
        ax.bar(x, sent, width, label='Sent (bytes)', color='#4CAF50')
        ax.bar(x, received, width, bottom=sent, label='Received (bytes)', color='#2196F3')
        
        ax.set_title('Top IP Traffic')
        ax.set_xlabel('IP Address')
        ax.set_ylabel('Bytes')
        ax.set_xticks(x)
        ax.set_xticklabels(ips, rotation=45, ha='right')
        ax.legend()
        
        fig.tight_layout()
        
        return canvas
        
    def create_packet_size_histogram(self, packet_sizes):
        """
        Create a packet size histogram.
        
        Args:
            packet_sizes (list): A list of packet sizes
            
        Returns:
            FigureCanvas: A matplotlib figure canvas
        """
        fig = Figure(figsize=(6, 4), dpi=100)
        canvas = FigureCanvas(fig)
        canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        ax = fig.add_subplot(111)
        
        # Create the histogram
        n, bins, patches = ax.hist(
            packet_sizes,
            bins=20,
            color='#4CAF50',
            alpha=0.7,
            edgecolor='black'
        )
        
        ax.set_title('Packet Size Distribution')
        ax.set_xlabel('Packet Size (bytes)')
        ax.set_ylabel('Frequency')
        
        # Add mean and median lines
        if packet_sizes:
            mean = np.mean(packet_sizes)
            median = np.median(packet_sizes)
            
            ax.axvline(mean, color='red', linestyle='dashed', linewidth=1, label=f'Mean: {mean:.1f}')
            ax.axvline(median, color='blue', linestyle='dashed', linewidth=1, label=f'Median: {median:.1f}')
            ax.legend()
            
        fig.tight_layout()
        
        return canvas
        
    def create_time_series_chart(self, timestamps, packet_sizes):
        """
        Create a time series chart of packet activity.
        
        Args:
            timestamps (list): A list of packet timestamps
            packet_sizes (list): A list of packet sizes
            
        Returns:
            FigureCanvas: A matplotlib figure canvas
        """
        fig = Figure(figsize=(8, 4), dpi=100)
        canvas = FigureCanvas(fig)
        canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        ax = fig.add_subplot(111)
        
        # Convert timestamps to relative time in seconds
        if timestamps:
            start_time = min(timestamps)
            relative_times = [(t - start_time) for t in timestamps]
            
            # Create the scatter plot
            ax.scatter(relative_times, packet_sizes, alpha=0.5, color='#4CAF50')
            
            # Add a trend line
            if len(relative_times) > 1:
                z = np.polyfit(relative_times, packet_sizes, 1)
                p = np.poly1d(z)
                ax.plot(relative_times, p(relative_times), "r--", alpha=0.8)
                
            ax.set_title('Packet Activity Over Time')
            ax.set_xlabel('Time (seconds)')
            ax.set_ylabel('Packet Size (bytes)')
            
        fig.tight_layout()
        
        return canvas
