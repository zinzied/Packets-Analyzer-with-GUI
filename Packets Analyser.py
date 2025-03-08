import scapy.all as scapy
import logging
from PyQt5 import QtWidgets, QtCore, QtGui
import psutil
import threading

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

        # Apply a style sheet for a modern look
        self.setStyleSheet("""
            QWidget {
                background-color: #2e2e2e;
                color: #ffffff;
                font-family: Arial;
                font-size: 14px;
            }
            QPushButton {
                background-color: #4CAF50;
                border: none;
                color: white;
                padding: 10px 24px;
                text-align: center;
                text-decoration: none;
                font-size: 14px;
                margin: 4px 2px;
                border-radius: 12px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            QLabel {
                font-weight: bold;
            }
            QListWidget {
                background-color: #1e1e1e;
                border: 1px solid #ccc;
                border-radius: 4px;
                color: #ffffff;  # Ensure text color is white for better contrast
            }
            QListWidget::item {
                color: #ffffff;  # Ensure text color is white for better contrast
            }
        """)

        self.src_ip_label = QtWidgets.QLabel('Source IP Filter:')
        self.src_ip_input = QtWidgets.QLineEdit(self)

        self.protocol_label = QtWidgets.QLabel('Protocol Filter (6 for TCP, 17 for UDP):')
        self.protocol_input = QtWidgets.QLineEdit(self)

        self.start_button = QtWidgets.QPushButton('Start Sniffing', self)
        self.start_button.setIcon(QtGui.QIcon('icons/start.png'))
        self.start_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.start_button.clicked.connect(self.start_sniffing)

        self.stop_button = QtWidgets.QPushButton('Stop Sniffing', self)
        self.stop_button.setIcon(QtGui.QIcon('icons/stop.png'))
        self.stop_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)

        self.clear_button = QtWidgets.QPushButton('Clear Packets', self)
        self.clear_button.setIcon(QtGui.QIcon('icons/clear.png'))
        self.clear_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.clear_button.clicked.connect(self.clear_packets)

        self.scan_button = QtWidgets.QPushButton('Scan IPs', self)
        self.scan_button.setIcon(QtGui.QIcon('icons/scan.png'))
        self.scan_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.scan_button.clicked.connect(self.scan_ips)

        self.save_button = QtWidgets.QPushButton('Save Packets', self)
        self.save_button.setIcon(QtGui.QIcon('icons/save.png'))
        self.save_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.save_button.clicked.connect(self.save_packets)

        self.load_button = QtWidgets.QPushButton('Load Packets', self)
        self.load_button.setIcon(QtGui.QIcon('icons/load.png'))
        self.load_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.load_button.clicked.connect(self.load_packets)

        self.packet_list = QtWidgets.QListWidget(self)
        self.packet_list.itemClicked.connect(self.show_packet_details)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.src_ip_label)
        layout.addWidget(self.src_ip_input)
        layout.addWidget(self.protocol_label)
        layout.addWidget(self.protocol_input)
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.clear_button)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.save_button)
        layout.addWidget(self.load_button)
        layout.addWidget(self.packet_list)
        self.setLayout(layout)

    def start_sniffing(self):
        if self.sniffing:
            return

        self.sniffing = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def process_packet(self, packet):
        item = QtWidgets.QListWidgetItem(str(packet.summary()))
        if packet.haslayer(scapy.ARP):
            item.setBackground(QtGui.QColor('#FFD700'))  # Gold for ARP
        elif packet.haslayer(scapy.IP):
            if packet[scapy.IP].proto == 6:  # TCP
                item.setBackground(QtGui.QColor('#ADD8E6'))  # Light Blue for TCP
            elif packet[scapy.IP].proto == 17:  # UDP
                item.setBackground(QtGui.QColor('#90EE90'))  # Light Green for UDP
            else:
                item.setBackground(QtGui.QColor('#FFFFFF'))  # White for other IP packets
        else:
            item.setBackground(QtGui.QColor('#D3D3D3'))  # Light Gray for other packets

        item.setForeground(QtGui.QColor('#000000'))  # Ensure text color is black for better contrast
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

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    window = PacketSnifferApp()
    window.show()
    sys.exit(app.exec_())