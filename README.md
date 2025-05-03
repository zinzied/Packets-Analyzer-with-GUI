# 🌐 Network Packet Analyzer with GUI

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.6+-blue.svg" alt="Python 3.6+">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/GUI-PyQt5-orange.svg" alt="GUI: PyQt5">
  <img src="https://img.shields.io/badge/Network-Scapy-red.svg" alt="Network: Scapy">
</div>

<p align="center">
  <b>🔍 A powerful, modern network packet analyzer with a sleek graphical interface for real-time packet capture, analysis, and visualization 📊</b>
</p>

<div align="center">
  <sub>Built with ❤️ for network professionals, security researchers, and curious minds</sub>
</div>

<br>

<p align="center">
  <img src="https://via.placeholder.com/800x450.png?text=Network+Packet+Analyzer+Screenshot" alt="Network Packet Analyzer Screenshot">
</p>

## ✨ Overview

This application is a comprehensive network packet sniffer with a graphical user interface (GUI) built using PyQt5. It captures and analyzes network packets in real-time, displaying relevant information such as source and destination IP addresses, protocols, and payload data. The application features a modern dark/light theme interface, advanced filtering capabilities, and powerful visualization tools.

> 💡 **Perfect for**: Network troubleshooting, security analysis, protocol understanding, and network monitoring

## 🚀 Key Features

- 🖥️ **Modern GUI Interface**: User-friendly interface with dark and light themes for comfortable viewing in any environment
- 🔍 **Real-time Packet Capture**: Capture packets from any network interface with live updates as traffic flows
- 🔎 **Advanced Filtering**: Filter packets by source/destination IP, protocol, port, and content with intuitive controls
- 📊 **Data Visualization**: View protocol distribution, traffic flow, and packet activity charts for better insights
- 🔬 **Detailed Packet Analysis**: Examine packet structure, hex view, and raw data with color-coded formatting
- 🌐 **Network Scanning**: Discover active devices on your network with detailed information about each host
- 📁 **Import/Export**: Save and load packet captures in various formats (PCAP, CSV, JSON) for sharing and documentation
- 📈 **Statistics**: Generate comprehensive statistics about network traffic patterns and protocol usage
- 🔄 **TCP Stream Following**: Reconstruct and analyze TCP conversations to understand application-level protocols
- 🔔 **Alerts**: Set up notifications for suspicious network activity or specific traffic patterns
- 🎨 **Customizable Interface**: Adjust the layout and appearance to suit your workflow and preferences
- 🔒 **Secure Analysis**: Perform all analysis locally without sending data to external servers

## 📋 Requirements

| Requirement | Version/Details |
|-------------|----------------|
| 🐍 Python | 3.6 or higher |
| 🖼️ PyQt5 | For the graphical interface |
| 📡 Scapy | For packet capture and analysis |
| 📊 Matplotlib | For data visualization |
| 💻 Psutil | For system and network information |
| 🔌 Npcap/libpcap | Packet capture library for your OS |

## 🔧 Installation

### 1. Clone the Repository 📥

```bash
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer
```

### 2. Install Dependencies 📦

```bash
pip install -r requirements.txt
```

### 3. Install Packet Capture Library 🔌

<details>
<summary><b>Windows</b> 🪟</summary>
<p>

1. Download and install [Npcap](https://npcap.com/dist/npcap-1.79.exe)
2. During installation, select "Install Npcap in WinPcap API-compatible Mode"

</p>
</details>

<details>
<summary><b>Linux</b> 🐧</summary>
<p>

```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev

# Fedora
sudo dnf install libpcap-devel

# Arch Linux
sudo pacman -S libpcap
```

</p>
</details>

<details>
<summary><b>macOS</b> 🍎</summary>
<p>

```bash
brew install libpcap
```

</p>
</details>

### 4. Run the Application 🚀

```bash
python run.py
```

## 💻 Usage Guide

### 🔍 Capturing Packets

1. Select a network interface from the dropdown menu
   - The interface list shows IP addresses and connection status
   - Active interfaces are highlighted for easy identification
2. Optionally set filters for specific traffic
   - Use the filter bar or the advanced filter dialog
3. Click the "Start Capture" button or press F5
4. View packets in real-time as they're captured
   - Packets are color-coded by protocol type
   - The status bar shows capture statistics
5. Click "Stop Capture" or press F6 when finished

### 🔎 Filtering Packets

Use the filter bar to apply BPF (Berkeley Packet Filter) expressions:

| Filter Example | Description |
|----------------|-------------|
| `tcp` | Show only TCP packets |
| `udp port 53` | Show only DNS traffic |
| `host 192.168.1.1` | Show traffic to/from a specific host |
| `src host 192.168.1.1` | Show only outgoing traffic from a host |
| `dst port 80 or dst port 443` | Show only web traffic (HTTP/HTTPS) |
| `icmp` | Show only ICMP packets (ping, etc.) |
| `arp` | Show only ARP packets |

> 💡 **Pro Tip**: Use the Filter Dialog (Ctrl+D) to build complex filters with a user-friendly interface

### 🔬 Analyzing Packets

- Click on any packet in the list to view its details
  - The packet structure is displayed in a hierarchical tree view
  - Fields are explained with descriptions and values
- Use the tabs to switch between views:
  - **Structure View**: Hierarchical breakdown of packet layers
  - **Hex View**: Raw packet data in hexadecimal format
  - **Raw Data**: Complete packet dump with all details
- Right-click on packets for additional options:
  - Mark important packets for later reference
  - Follow TCP/UDP streams
  - Copy packet information
  - Export selected packets

### 🌐 Network Scanning

1. Go to Tools → Scan Network
2. Select a network interface to scan from
3. Enter an IP range (e.g., 192.168.1.0/24)
   - The application can suggest a range based on your current IP
4. Set scan options (timeout, verbosity)
5. Click "Start Scan" to discover devices
6. View results showing:
   - IP addresses
   - MAC addresses
   - Hostnames (when available)
   - Device status

### 📊 Viewing Statistics

1. Go to Analyze → Statistics
2. Choose from various statistical views:
   - **Protocol Hierarchy**: Distribution of protocols in pie chart
   - **Endpoints**: Traffic by IP address
   - **Conversations**: Traffic between pairs of IP addresses
   - **IO Graph**: Packet activity over time
3. Export statistics as images or data files

## 🎛️ GUI Components

<details>
<summary>Expand to see detailed GUI components</summary>

- **Main Toolbar**: Quick access to common functions
  - Start/Stop/Restart capture buttons
  - Interface selector dropdown
  - Quick filter input
  - Theme toggle

- **Interface Selector**: Choose which network interface to monitor
  - Shows interface name, IP address, and status
  - Highlights active interfaces
  - Provides detailed tooltips with interface information

- **Filter Bar**: Apply display filters to captured packets
  - Supports Berkeley Packet Filter (BPF) syntax
  - Provides autocomplete suggestions
  - Shows filter validation status

- **Packet List**: View captured packets with color-coding by protocol
  - Sortable columns (time, size, protocol, etc.)
  - Color-coded by protocol type for easy identification
  - Shows packet number, timestamp, source/destination, protocol, size, and info

- **Packet Details**: Examine the structure and content of selected packets
  - Tree view of packet layers and fields
  - Hex view with byte representation
  - Raw data view with complete packet information

- **Status Bar**: View capture statistics and application status
  - Packet count
  - Capture duration
  - Capture rate (packets/second)
  - Filter status
  - Selected interface

</details>

## 🔄 How It Works

1. **Initialization**: The application loads and sets up the GUI components
   - Loads user preferences and settings
   - Detects available network interfaces
   - Initializes the packet capture engine

2. **Packet Capture**: When started, a background thread captures packets using Scapy
   - Packets are captured in promiscuous mode (sees all traffic)
   - Filtering is applied at capture time for efficiency
   - Real-time processing ensures minimal delay

3. **Processing**: Each packet is processed, analyzed, and displayed in the list
   - Protocol detection identifies the type of packet
   - Header information is extracted and formatted
   - Payload data is decoded when possible
   - Color-coding is applied based on protocol

4. **Visualization**: Statistics are calculated and visualized in real-time
   - Protocol distribution charts show traffic composition
   - Time-series graphs show traffic patterns
   - Endpoint statistics show active hosts

5. **Analysis**: Users can interact with packets to view details and perform analysis
   - Detailed inspection of packet structure
   - Stream reassembly for protocol analysis
   - Export capabilities for further processing

## 🛠️ Troubleshooting

<details>
<summary><b>Common Issues and Solutions</b></summary>

### No interfaces appear in the dropdown

- **Windows**: Make sure Npcap is installed correctly
- **Linux/macOS**: Ensure you have the necessary permissions (try running with sudo)
- **All platforms**: Check if your network adapters are enabled

### Cannot capture packets

- Ensure you have administrator/root privileges
- Check if another application is using the network interface
- Verify that the selected interface is connected to a network

### Application crashes during capture

- Update to the latest version of the application
- Check system resources (memory, CPU usage)
- Try capturing with a more specific filter to reduce packet volume

### Missing protocol information

- Some protocols may require additional plugins or decoders
- Encrypted traffic will not show payload details
- Check if the protocol is supported in the current version

</details>

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

- 🐛 **Report bugs**: Open an issue describing the bug and how to reproduce it
- 💡 **Suggest features**: Have an idea? Share it in the issues section
- 🔧 **Submit code**: Fork the repository, make changes, and submit a pull request
- 📚 **Improve documentation**: Help make the documentation more clear and comprehensive
- 🌐 **Add protocol support**: Implement parsers for additional network protocols

Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting changes.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Scapy](https://scapy.net/) for powerful packet manipulation capabilities
- [PyQt5](https://www.riverbankcomputing.com/software/pyqt/) for the robust GUI framework
- [Matplotlib](https://matplotlib.org/) for beautiful data visualization
- [Npcap](https://npcap.com/) for Windows packet capture functionality
- [Psutil](https://github.com/giampaolo/psutil) for system and process utilities

## 📚 Further Reading

- [Wireshark Documentation](https://www.wireshark.org/docs/) - Great resource for understanding network protocols
- [Scapy Documentation](https://scapy.readthedocs.io/) - Learn more about the packet manipulation library
- [TCP/IP Illustrated](https://en.wikipedia.org/wiki/TCP/IP_Illustrated) - Comprehensive guide to network protocols

---

<div align="center">
  <sub>Made with ❤️ by network enthusiasts</sub>
</div>
