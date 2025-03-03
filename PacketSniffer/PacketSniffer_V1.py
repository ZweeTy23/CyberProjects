import scapy.all as scapy

def sniffing(interface):
    scapy.sniff(
        iface = interface, 
        store = False,
        prn = process_packet)

def process_packet(packet):
    print(packet)

sniffing('Wi-Fi')