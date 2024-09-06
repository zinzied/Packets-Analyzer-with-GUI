import scapy.all as scapy
import logging
from PyQt5 import QtWidgets, QtCore, QtGui

# Set up logging
logging.basicConfig(filename='packet_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

class PacketSnifferApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.sniffer_thread = None
        self.details_windows = []  # Store references to detail windows

    def initUI(self):
        self.setWindowTitle('Network Packet Analyzer')
        self.resize(800, 600)

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
        layout.addWidget(self.packet_list)
     
        self.setLayout(layout)

    def start_sniffing(self):
        src_ip_filter = self.src_ip_input.text()
        protocol_filter = self.protocol_input.text()
        protocol_filter = int(protocol_filter) if protocol_filter.isdigit() else None

        self.sniffer_thread = SnifferThread(src_ip_filter, protocol_filter, self.packet_list)
        self.sniffer_thread.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def stop_sniffing(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread = None

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def clear_packets(self):
        self.packet_list.clear()

    def show_packet_details(self, item):
        details_window = QtWidgets.QWidget()
        details_window.setWindowTitle('Packet Details')

        details_text = QtWidgets.QTextEdit(details_window)
        details_text.setReadOnly(True)
        details_text.setText(item.text())

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(details_text)
        details_window.setLayout(layout)

        self.details_windows.append(details_window)  # Keep a reference to the window
        details_window.show()

class SnifferThread(QtCore.QThread):
    def __init__(self, src_ip_filter, protocol_filter, packet_list):
        super().__init__()
        self.src_ip_filter = src_ip_filter
        self.protocol_filter = protocol_filter
        self.packet_list = packet_list
        self.running = True

    def run(self):
        scapy.sniff(store=False, prn=self.packet_callback, stop_filter=self.stop_filter)

    def stop(self):
        self.running = False

    def stop_filter(self, packet):
        return not self.running

    def packet_callback(self, packet):
        if packet.haslayer(scapy.IP):
           src_ip = packet[scapy.IP].src
           dst_ip = packet[scapy.IP].dst
           protocol = packet[scapy.IP].proto

           if self.src_ip_filter and src_ip != self.src_ip_filter:
              return
           if self.protocol_filter and protocol != self.protocol_filter:
              return

           packet_info = f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}"
           item = QtWidgets.QListWidgetItem(packet_info)
        
        # Rest of the method remains the same...
        else:
        # Handle non-IP packets if needed
           packet_info = "Non-IP packet received"
           item = QtWidgets.QListWidgetItem(packet_info)
           item.setBackground(QtGui.QColor('lightgrey'))

           self.packet_list.addItem(item)
           logging.info(packet_info)
           scapy.wrpcap('captured_packets.pcap', packet, append=True)

        if packet.haslayer(scapy.TCP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                payload_info = f"TCP Payload: {decoded_payload}"
                payload_item = QtWidgets.QListWidgetItem(payload_info)
                payload_item.setBackground(QtGui.QColor('lightblue'))
                self.packet_list.addItem(payload_item)
                logging.info(payload_info)
            except (IndexError, UnicodeDecodeError):
                error_info = "Unable to decode TCP payload."
                error_item = QtWidgets.QListWidgetItem(error_info)
                error_item.setBackground(QtGui.QColor('lightblue'))
                self.packet_list.addItem(error_item)
                logging.info(error_info)
        elif packet.haslayer(scapy.UDP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                payload_info = f"UDP Payload: {decoded_payload}"
                payload_item = QtWidgets.QListWidgetItem(payload_info)
                payload_item.setBackground(QtGui.QColor('lightgreen'))
                self.packet_list.addItem(payload_item)
                logging.info(payload_info)
            except (IndexError, UnicodeDecodeError):
                error_info = "Unable to decode UDP payload."
                error_item = QtWidgets.QListWidgetItem(error_info)
                error_item.setBackground(QtGui.QColor('lightgreen'))
                self.packet_list.addItem(error_item)
                logging.info(error_info)
if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    ex = PacketSnifferApp()
    ex.show()
    sys.exit(app.exec_())