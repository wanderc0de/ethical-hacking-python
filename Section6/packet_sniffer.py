import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("Disovered http request:")
        print("URL: {}".format(packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path))

    if packet.haslayer(scapy.IP):
        print("Source IP: {}".format(packet[scapy.IP].src))
        print("Destination IP: {}".format(packet[scapy.IP].dst))

    if packet.haslayer(scapy.TCP):
        tcp_layer = packet[scapy.TCP]
        print("Source port: {}".format(tcp_layer.sport))
        print("Destination port: {}".format(tcp_layer.dport))
        print("Sequence Number: {}".format(tcp_layer.seq))
    elif packet.haslayer(scapy.UDP):
        udp_layer = packet[scapy.UDP]
        print("Source port: {}".format(udp_layer.sport))
        print("Destination port: {}".format(udp_layer.dport))

    if packet.haslayer(scapy.Raw):
            print("PAYLOAD: {}".format(packet[scapy.Raw].load))


sniff("eth0")