# 🌐 Network Packet Analyzer with GUI

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.6+-blue.svg" alt="Python 3.6+">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-lightgrey.svg" alt="Platform">
</div>

<p align="center">
  A powerful, modern network packet analyzer with a sleek graphical interface for real-time packet capture, analysis, and visualization.
</p>

## ✨ Overview

This application is a comprehensive network packet sniffer with a graphical user interface (GUI) built using PyQt5. It captures and analyzes network packets in real-time, displaying relevant information such as source and destination IP addresses, protocols, and payload data. The application features a modern dark/light theme interface, advanced filtering capabilities, and powerful visualization tools.

![Network Packet Analyzer Screenshot](https://via.placeholder.com/800x450.png?text=Network+Packet+Analyzer+Screenshot)

## 🚀 Key Features

- 🖥️ **Modern GUI Interface**: User-friendly interface with dark and light themes
- 🔍 **Real-time Packet Capture**: Capture packets from any network interface
- 🔎 **Advanced Filtering**: Filter packets by IP, protocol, port, and content
- 📊 **Data Visualization**: View protocol distribution, traffic flow, and packet activity charts
- 🔬 **Detailed Packet Analysis**: Examine packet structure, hex view, and raw data
- 🌐 **Network Scanning**: Discover active devices on your network
- 📁 **Import/Export**: Save and load packet captures in various formats (PCAP, CSV, JSON)
- 📈 **Statistics**: Generate comprehensive statistics about network traffic
- 🔄 **TCP Stream Following**: Reconstruct and analyze TCP conversations
- 🔔 **Alerts**: Set up notifications for suspicious network activity

## 📋 Requirements

- Python 3.6 or higher
- PyQt5
- Scapy
- Matplotlib
- Psutil
- Npcap (Windows) or libpcap (Linux/macOS)

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Install Packet Capture Library

- **Windows**: Download and install [Npcap](https://npcap.com/dist/npcap-1.79.exe)
- **Linux**: `sudo apt-get install libpcap-dev`
- **macOS**: `brew install libpcap`

### 4. Run the Application

```bash
python run.py
```

## 💻 Usage Guide

### Capturing Packets

1. Select a network interface from the dropdown menu
2. Optionally set filters for specific traffic
3. Click the "Start Capture" button
4. View packets in real-time as they're captured
5. Click "Stop Capture" when finished

### Filtering Packets

Use the filter bar to apply BPF (Berkeley Packet Filter) expressions:

- `tcp` - Show only TCP packets
- `udp port 53` - Show only DNS traffic
- `host 192.168.1.1` - Show traffic to/from a specific host
- `src host 192.168.1.1` - Show only outgoing traffic from a host

### Analyzing Packets

- Click on any packet in the list to view its details
- Use the tabs to switch between structure view, hex view, and raw data
- Right-click on packets for additional options
- Use the "Follow TCP Stream" feature to reconstruct conversations

### Network Scanning

1. Go to Tools → Scan Network
2. Enter an IP range (e.g., 192.168.1.0/24)
3. Click "Start Scan" to discover devices

## 🔍 GUI Components

- **Main Toolbar**: Quick access to common functions
- **Interface Selector**: Choose which network interface to monitor
- **Filter Bar**: Apply display filters to captured packets
- **Packet List**: View captured packets with color-coding by protocol
- **Packet Details**: Examine the structure and content of selected packets
- **Status Bar**: View capture statistics and application status

## 🔄 How It Works

1. **Initialization**: The application loads and sets up the GUI components
2. **Packet Capture**: When started, a background thread captures packets using Scapy
3. **Processing**: Each packet is processed, analyzed, and displayed in the list
4. **Visualization**: Statistics are calculated and visualized in real-time
5. **Analysis**: Users can interact with packets to view details and perform analysis

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [Scapy](https://scapy.net/) for packet manipulation
- [PyQt5](https://www.riverbankcomputing.com/software/pyqt/) for the GUI framework
- [Matplotlib](https://matplotlib.org/) for data visualization
