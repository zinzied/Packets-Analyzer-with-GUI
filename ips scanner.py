import scapy.all as scapy
import psutil

def get_network_adapters():
    adapters = psutil.net_if_addrs()
    return adapters

def select_network_adapter(adapters):
    print("Available network adapters:")
    for i, adapter in enumerate(adapters.keys()):
        print(f"{i}: {adapter}")
    choice = int(input("Select a network adapter by number: "))
    return list(adapters.keys())[choice]

def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients.append(client_dict)
    return clients

def display_results(clients):
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------")
    for client in clients:
        print(f"{client['ip']}\t\t{client['mac']}")

if __name__ == "__main__":
    adapters = get_network_adapters()
    selected_adapter = select_network_adapter(adapters)
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.1/24): ")
    scan_results = scan_network(ip_range)
    display_results(scan_results)