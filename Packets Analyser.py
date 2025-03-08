import scapy.all as scapy
import logging
from PyQt5 import QtWidgets, QtCore, QtGui
import psutil

# Set up logging
logging.basicConfig(filename='packet_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

class PacketSnifferApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.check_npcap_installed()
        self.initUI()
        self.sniffer_thread = None
        self.details_windows = []  # Store references to detail windows

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
        # Rest of your initUI code remains unchanged
        self.setWindowTitle('Network Packet Analyzer')
        self.resize(800, 600)
        
        # ... rest of your existing initUI code ...

        self.src_ip_label = QtWidgets.QLabel('Source IP Filter:')
        self.src_ip_input = QtWidgets.QLineEdit(self)

        self.protocol_label = QtWidgets.QLabel('Protocol Filter (6 for TCP, 17 for UDP):')
        self.protocol_input = QtWidgets.QLineEdit(self)

        self.start_button = QtWidgets.QPushButton('Start Sniffing', self)
        self.start_button.clicked.connect(self.start_sniffing)

        self.stop_button = QtWidgets.QPushButton('Stop Sniffing', self)
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)

        self.clear_button = QtWidgets.QPushButton('Clear Packets', self)
        self.clear_button.clicked.connect(self.clear_packets)

        self.scan_button = QtWidgets.QPushButton('Scan IPs', self)
        self.scan_button.clicked.connect(self.scan_ips)

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
        layout.addWidget(self.packet_list)
        self.setLayout(layout)

    def start_sniffing(self):
        # Implement start sniffing logic
        pass

    def stop_sniffing(self):
        # Implement stop sniffing logic
        pass

    def clear_packets(self):
        self.packet_list.clear()

    def show_packet_details(self, item):
        # Implement packet details display logic
        pass

    def scan_ips(self):
        adapters = self.get_network_adapters()
        selected_adapter = self.select_network_adapter(adapters)
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
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        clients = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients.append(client_dict)
        return clients

    def display_scan_results(self, clients):
        result_window = QtWidgets.QWidget()
        result_window.setWindowTitle('Scan Results')
        result_window.resize(400, 300)
        layout = QtWidgets.QVBoxLayout()
        result_list = QtWidgets.QListWidget()
        for client in clients:
            result_list.addItem(f"IP: {client['ip']} - MAC: {client['mac']}")
        layout.addWidget(result_list)
        result_window.setLayout(layout)
        result_window.show()
        self.details_windows.append(result_window)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    window = PacketSnifferApp()
    window.show()
    sys.exit(app.exec_())