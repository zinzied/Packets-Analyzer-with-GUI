import scapy.all as scapy
import logging
from PyQt5 import QtWidgets, QtCore, QtGui
import psutil
import threading
import json
import csv

# Set up logging
logging.basicConfig(filename='packet_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

class PacketSnifferApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.check_npcap_installed()
        self.initUI()
        self.sniffer_thread = None
        self.sniffing = False
        self.details_windows = []  # Store references to detail windows
        self.captured_packets = []  # Store captured packets
        self.packet_comments = {}  # Store packet comments

    def check_npcap_installed(self):
        """Check if Npcap is installed and show a message if it's not."""
        try:
            # Try a simple scapy operation that requires Npcap
            test = scapy.Ether()
            # If no exception is raised, Npcap is likely installed
        except Exception:
            msg = QtWidgets.QMessageBox()
            msg.setIcon(QtWidgets.QMessageBox.Warning)
            msg.setWindowTitle("Npcap Required")
            msg.setText("Npcap is required to use this application")
            msg.setInformativeText("This application requires Npcap to capture and analyze network packets. "
                                  "Please download and install Npcap from https://npcap.com before using this application.")
            msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
            
            # Add buttons to download or exit
            download_button = msg.addButton("Download Npcap", QtWidgets.QMessageBox.ActionRole)
            exit_button = msg.addButton("Exit", QtWidgets.QMessageBox.RejectRole)
            
            msg.exec_()
            
            # Handle button clicks
            if msg.clickedButton() == download_button:
                import webbrowser
                webbrowser.open("https://npcap.com/dist/npcap-1.79.exe")
                sys.exit()
            elif msg.clickedButton() == exit_button:
                sys.exit()

    def initUI(self):
        self.setWindowTitle('Network Packet Analyzer')
        self.resize(800, 600)

        # Apply a style sheet for a modern look with better text visibility
        self.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                color: #e0e0e0;
                font-family: Arial;
                font-size: 14px;
            }
            QMenuBar {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border-bottom: 1px solid #404040;
            }
            QMenuBar::item:selected {
                background-color: #4CAF50;
                color: white;
            }
            QMenu {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #404040;
            }
            QMenu::item:selected {
                background-color: #4CAF50;
                color: white;
            }
            QLineEdit {
                background-color: #3d3d3d;
                color: #e0e0e0;
                padding: 5px;
                border: 1px solid #505050;
                border-radius: 4px;
            }
            QLineEdit:focus {
                border: 1px solid #4CAF50;
            }
            QLabel {
                color: #e0e0e0;
                font-weight: bold;
            }
            QListWidget {
                background-color: #1e1e1e;
                alternate-background-color: #2d2d2d;
                border: 1px solid #404040;
                border-radius: 4px;
                color: #e0e0e0;
            }
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #333333;
            }
            QListWidget::item:selected {
                background-color: #4CAF50;
                color: white;
            }
            QListWidget::item:hover {
                background-color: #383838;
            }
        """)

        # Create main layout
        main_layout = QtWidgets.QVBoxLayout()

        # Create menu bar
        menubar = QtWidgets.QMenuBar(self)

        # File menu
        file_menu = menubar.addMenu('File')
        
        save_action = QtWidgets.QAction('Save Packets', self)
        save_action.setShortcut('Ctrl+S')
        save_action.triggered.connect(self.save_packets)
        file_menu.addAction(save_action)

        load_action = QtWidgets.QAction('Load Packets', self)
        load_action.setShortcut('Ctrl+O')
        load_action.triggered.connect(self.load_packets)
        file_menu.addAction(load_action)

        export_action = QtWidgets.QAction('Export Packets', self)
        export_action.setShortcut('Ctrl+E')
        export_action.triggered.connect(self.export_packets)
        file_menu.addAction(export_action)

        # Capture menu
        capture_menu = menubar.addMenu('Capture')
        
        self.start_action = QtWidgets.QAction('Start Sniffing', self)
        self.start_action.setShortcut('F5')
        self.start_action.triggered.connect(self.start_sniffing)
        capture_menu.addAction(self.start_action)

        self.stop_action = QtWidgets.QAction('Stop Sniffing', self)
        self.stop_action.setShortcut('F6')
        self.stop_action.triggered.connect(self.stop_sniffing)
        self.stop_action.setEnabled(False)
        capture_menu.addAction(self.stop_action)

        clear_action = QtWidgets.QAction('Clear Packets', self)
        clear_action.triggered.connect(self.clear_packets)
        capture_menu.addAction(clear_action)

        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        scan_action = QtWidgets.QAction('Scan IPs', self)
        scan_action.triggered.connect(self.scan_ips)
        tools_menu.addAction(scan_action)

        stats_action = QtWidgets.QAction('Protocol Statistics', self)
        stats_action.triggered.connect(self.show_protocol_statistics)
        tools_menu.addAction(stats_action)

        follow_action = QtWidgets.QAction('Follow Stream', self)
        follow_action.triggered.connect(self.follow_stream)
        tools_menu.addAction(follow_action)

        # Create filter section
        filter_layout = QtWidgets.QHBoxLayout()
        
        self.src_ip_label = QtWidgets.QLabel('Source IP Filter:')
        self.src_ip_input = QtWidgets.QLineEdit(self)
        self.protocol_label = QtWidgets.QLabel('Protocol Filter:')
        self.protocol_input = QtWidgets.QLineEdit(self)
        
        filter_layout.addWidget(self.src_ip_label)
        filter_layout.addWidget(self.src_ip_input)
        filter_layout.addWidget(self.protocol_label)
        filter_layout.addWidget(self.protocol_input)

        # Create packet list
        self.packet_list = QtWidgets.QListWidget(self)
        self.packet_list.itemClicked.connect(self.show_packet_details)

        # Add widgets to main layout
        main_layout.setMenuBar(menubar)
        main_layout.addLayout(filter_layout)
        main_layout.addWidget(self.packet_list)
        
        self.setLayout(main_layout)

    def start_sniffing(self):
        if self.sniffing:
            return

        self.sniffing = True
        self.start_action.setEnabled(False)  # Use start_action instead of start_button
        self.stop_action.setEnabled(True)   # Use stop_action instead of stop_button

        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_action.setEnabled(True)   # Use start_action instead of start_button
        self.stop_action.setEnabled(False)   # Use stop_action instead of stop_button

    def process_packet(self, packet):
        """Process and color-code packets based on their protocol."""
        item = QtWidgets.QListWidgetItem(str(packet.summary()))
        
        # Define protocol colors with good contrast
        COLORS = {
            'TCP': '#ADD8E6',      # Light blue
            'UDP': '#FFB6C1',      # Light pink
            'ARP': '#90EE90',      # Light green
            'ICMP': '#FFD700',     # Light orange
            'DNS': '#E6E6FA',      # Light purple
            'HTTP': '#FF6347',     # Light red
            'HTTPS': '#B0E0E6',    # Light cyan
            'OTHER': '#D3D3D3'     # Light gray
        }

        # Set black text color for all packets
        item.setForeground(QtGui.QColor('#000000'))

        # Color-code based on protocol
        if packet.haslayer(scapy.ARP):
            item.setBackground(QtGui.QColor(COLORS['ARP']))
        elif packet.haslayer(scapy.IP):
            if packet.haslayer(scapy.TCP):
                if packet.haslayer(scapy.Raw) and (b'HTTP' in bytes(packet[scapy.Raw])):
                    item.setBackground(QtGui.QColor(COLORS['HTTP']))
                elif packet[scapy.TCP].dport == 443 or packet[scapy.TCP].sport == 443:
                    item.setBackground(QtGui.QColor(COLORS['HTTPS']))
                else:
                    item.setBackground(QtGui.QColor(COLORS['TCP']))
            elif packet.haslayer(scapy.UDP):
                if packet.haslayer(scapy.DNS):
                    item.setBackground(QtGui.QColor(COLORS['DNS']))
                else:
                    item.setBackground(QtGui.QColor(COLORS['UDP']))
            elif packet.haslayer(scapy.ICMP):
                item.setBackground(QtGui.QColor(COLORS['ICMP']))
            else:
                item.setBackground(QtGui.QColor(COLORS['OTHER']))
        else:
            item.setBackground(QtGui.QColor(COLORS['OTHER']))

        # Add tooltip with packet details
        item.setToolTip(f"Protocol: {packet.summary()}\nLength: {len(packet)} bytes")

        self.packet_list.addItem(item)
        self.captured_packets.append(packet)
        logging.info(packet.summary())

    def sniff_packets(self):
        filter_str = ""
        if self.src_ip_input.text():
            filter_str += f"src host {self.src_ip_input.text()} "
        if self.protocol_input.text():
            if filter_str:
                filter_str += "and "
            filter_str += f"proto {self.protocol_input.text()}"

        scapy.sniff(filter=filter_str, prn=self.process_packet, stop_filter=lambda x: not self.sniffing)

    def clear_packets(self):
        self.packet_list.clear()
        self.captured_packets.clear()

    def show_packet_details(self, item):
        packet_summary = item.text()
        packet_index = self.packet_list.row(item)
        packet = self.captured_packets[packet_index]

        details_window = QtWidgets.QWidget()
        details_window.setWindowTitle('Packet Details')
        details_window.resize(600, 400)

        layout = QtWidgets.QVBoxLayout()
        details_text = QtWidgets.QTextEdit()
        details_text.setReadOnly(True)
        details_text.setText(packet.show(dump=True))

        layout.addWidget(details_text)
        details_window.setLayout(layout)
        details_window.show()
        self.details_windows.append(details_window)

    def scan_ips(self):
        adapters = self.get_network_adapters()
        selected_adapter = self.select_network_adapter(adapters)
        if not selected_adapter:
            print("No network adapter selected.")
            return
        ip_range, ok = QtWidgets.QInputDialog.getText(self, 'IP Range', 'Enter the IP range to scan (e.g., 192.168.1.1/24):')
        if ok:
            scan_results = self.scan_network(ip_range)
            self.display_scan_results(scan_results)

    def get_network_adapters(self):
        adapters = psutil.net_if_addrs()
        return adapters

    def select_network_adapter(self, adapters):
        items = list(adapters.keys())
        item, ok = QtWidgets.QInputDialog.getItem(self, 'Select Network Adapter', 'Network Adapter:', items, 0, False)
        if ok and item:
            return item
        return None

    def scan_network(self, ip_range):
        print(f"Scanning IP range: {ip_range}")
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=True)[0]  # Increased timeout and enabled verbose
        clients = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients.append(client_dict)
        print(f"Scan results: {clients}")
        return clients

    def display_scan_results(self, clients):
        result_window = QtWidgets.QWidget()
        result_window.setWindowTitle('Scan Results')
        result_window.resize(400, 300)
        layout = QtWidgets.QVBoxLayout()
        result_list = QtWidgets.QListWidget()
        for client in clients:
            result_list.addItem(f"IP: {client['ip']} - MAC: {client['mac']}")
        result_list.itemClicked.connect(self.add_ip_to_filter)
        layout.addWidget(result_list)
        result_window.setLayout(layout)
        result_window.show()
        self.details_windows.append(result_window)

    def add_ip_to_filter(self, item):
        ip = item.text().split(' - ')[0].replace('IP: ', '')
        self.src_ip_input.setText(ip)

    def save_packets(self):
        options = QtWidgets.QFileDialog.Options()
        file_name, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Packets", "", "PCAP Files (*.pcap);;All Files (*)", options=options)
        if file_name:
            scapy.wrpcap(file_name, self.captured_packets)
            print(f"Packets saved to {file_name}")

    def load_packets(self):
        options = QtWidgets.QFileDialog.Options()
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Load Packets", "", "PCAP Files (*.pcap);;All Files (*)", options=options)
        if file_name:
            self.captured_packets = scapy.rdpcap(file_name)
            self.packet_list.clear()
            for packet in self.captured_packets:
                self.packet_list.addItem(str(packet.summary()))
            print(f"Packets loaded from {file_name}")

    def show_protocol_statistics(self):
        protocol_counts = {}
        for packet in self.captured_packets:
            if packet.haslayer(scapy.IP):
                proto = packet[scapy.IP].proto
                if proto == 6:
                    protocol = 'TCP'
                elif proto == 17:
                    protocol = 'UDP'
                else:
                    protocol = f'IP Protocol {proto}'
            elif packet.haslayer(scapy.ARP):
                protocol = 'ARP'
            else:
                protocol = 'Other'

            if protocol in protocol_counts:
                protocol_counts[protocol] += 1
            else:
                protocol_counts[protocol] = 1

        stats_window = QtWidgets.QWidget()
        stats_window.setWindowTitle('Protocol Statistics')
        stats_window.resize(400, 300)

        layout = QtWidgets.QVBoxLayout()
        stats_list = QtWidgets.QListWidget()
        for protocol, count in protocol_counts.items():
            stats_list.addItem(f"{protocol}: {count} packets")

        layout.addWidget(stats_list)
        stats_window.setLayout(layout)
        stats_window.show()
        self.details_windows.append(stats_window)

    def follow_stream(self):
        selected_item = self.packet_list.currentItem()
        if not selected_item:
            QtWidgets.QMessageBox.warning(self, "No Packet Selected", "Please select a packet to follow its stream.")
            return

        packet_index = self.packet_list.row(selected_item)
        packet = self.captured_packets[packet_index]

        if not packet.haslayer(scapy.IP) or not (packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP)):
            QtWidgets.QMessageBox.warning(self, "Invalid Packet", "Selected packet is not a TCP or UDP packet.")
            return

        stream_packets = []
        if packet.haslayer(scapy.TCP):
            stream_filter = f"tcp and host {packet[scapy.IP].src} and host {packet[scapy.IP].dst} and port {packet[scapy.TCP].sport} and port {packet[scapy.TCP].dport}"
        elif packet.haslayer(scapy.UDP):
            stream_filter = f"udp and host {packet[scapy.IP].src} and host {packet[scapy.IP].dst} and port {packet[scapy.UDP].sport} and port {packet[scapy.UDP].dport}"

        for pkt in self.captured_packets:
            if pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.TCP) and scapy.IP in pkt and scapy.TCP in pkt:
                if (pkt[scapy.IP].src == packet[scapy.IP].src and pkt[scapy.IP].dst == packet[scapy.IP].dst and
                    pkt[scapy.TCP].sport == packet[scapy.TCP].sport and pkt[scapy.TCP].dport == packet[scapy.TCP].dport) or \
                   (pkt[scapy.IP].src == packet[scapy.IP].dst and pkt[scapy.IP].dst == packet[scapy.IP].src and
                    pkt[scapy.TCP].sport == packet[scapy.TCP].dport and pkt[scapy.TCP].dport == packet[scapy.TCP].sport):
                    stream_packets.append(pkt)
            elif pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.UDP) and scapy.IP in pkt and scapy.UDP in pkt:
                if (pkt[scapy.IP].src == packet[scapy.IP].src and pkt[scapy.IP].dst == packet[scapy.IP].dst and
                    pkt[scapy.UDP].sport == packet[scapy.UDP].sport and pkt[scapy.UDP].dport == packet[scapy.UDP].dport) or \
                   (pkt[scapy.IP].src == packet[scapy.IP].dst and pkt[scapy.IP].dst == packet[scapy.IP].src and
                    pkt[scapy.UDP].sport == packet[scapy.UDP].dport and pkt[scapy.UDP].dport == packet[scapy.UDP].sport):
                    stream_packets.append(pkt)

        stream_window = QtWidgets.QWidget()
        stream_window.setWindowTitle('Follow Stream')
        stream_window.resize(600, 400)

        layout = QtWidgets.QVBoxLayout()
        stream_text = QtWidgets.QTextEdit()
        stream_text.setReadOnly(True)
        stream_content = "\n\n".join([pkt.show(dump=True) for pkt in stream_packets])
        stream_text.setText(stream_content)

        layout.addWidget(stream_text)
        stream_window.setLayout(layout)
        stream_window.show()
        self.details_windows.append(stream_window)

    def export_packets(self):
        options = QtWidgets.QFileDialog.Options()
        file_name, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export Packets", "", "CSV Files (*.csv);;JSON Files (*.json);;All Files (*)", options=options)
        if file_name:
            if file_name.endswith('.csv'):
                self.export_packets_to_csv(file_name)
            elif file_name.endswith('.json'):
                self.export_packets_to_json(file_name)

    def export_packets_to_csv(self, file_name):
        with open(file_name, 'w', newline='') as csvfile:
            fieldnames = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for i, packet in enumerate(self.captured_packets):
                if packet.haslayer(scapy.IP):
                    src = packet[scapy.IP].src
                    dst = packet[scapy.IP].dst
                    proto = packet[scapy.IP].proto
                    length = len(packet)
                    info = packet.summary()
                    if proto == 6:
                        protocol = 'TCP'
                    elif proto == 17:
                        protocol = 'UDP'
                    else:
                        protocol = f'IP Protocol {proto}'
                elif packet.haslayer(scapy.ARP):
                    src = packet[scapy.ARP].psrc
                    dst = packet[scapy.ARP].pdst
                    protocol = 'ARP'
                    length = len(packet)
                    info = packet.summary()
                else:
                    src = 'Unknown'
                    dst = 'Unknown'
                    protocol = 'Other'
                    length = len(packet)
                    info = packet.summary()

                writer.writerow({'No.': i + 1, 'Time': packet.time, 'Source': src, 'Destination': dst, 'Protocol': protocol, 'Length': length, 'Info': info})

    def export_packets_to_json(self, file_name):
        packets_data = []
        for packet in self.captured_packets:
            packet_data = {
                'time': packet.time,
                'summary': packet.summary(),
                'show': packet.show(dump=True)
            }
            packets_data.append(packet_data)

        with open(file_name, 'w') as jsonfile:
            json.dump(packets_data, jsonfile, indent=4)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    window = PacketSnifferApp()
    window.show()
    sys.exit(app.exec_())