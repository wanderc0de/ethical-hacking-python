import scapy.all as scapy
import json
import optparse
import ipaddress

''' Scapy ARP class
hwtype     : XShortField                         = 1               (1)
ptype      : XShortEnumField                     = 2048            (2048)
hwlen      : FieldLenField                       = None            (None)
plen       : FieldLenField                       = None            (None)
op         : ShortEnumField                      = 1               (1)
hwsrc      : MultipleTypeField                   = '00:0c:29:1d:20:8f' (None)
psrc       : MultipleTypeField                   = '192.168.1.77'  (None)
hwdst      : MultipleTypeField                   = '00:00:00:00:00:00' (None)
pdst       : MultipleTypeField                   = '0.0.0.0'       (None)
    Scapy Ether class
dst        : DestMACField                        = 'ff:ff:ff:ff:ff:ff' (None)
src        : SourceMACField                      = '00:0c:29:1d:20:8f' (None)
type       : XShortEnumField                     = 36864           (36864)
'''

def scan(ip_addr):
    # Create an ARP packet
    arp_request = scapy.ARP(pdst=ip_addr)
    # can also assign class members like this: arp_request.pdst = ip_addr
    # Create a broadcast packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # default dst mac is ff:ff:ff:ff:ff:ff but must set here
    print("[+] ARP packet created:", arp_request.summary())
    print("[+] Broadcast packet:", broadcast.summary())
    # Construct final packet
    arp_broadcast = broadcast/arp_request
    print("[+] Final packet:", arp_broadcast.summary())
    # Send packet and receive
    answered = scapy.srp(arp_broadcast, timeout=TIMEOUT, verbose=False)[0] # answered will be the first index of this result
    # Get the data we want
    hosts = {"hosts": dict()}
    for element in answered:
        # The answer is in index 1 of the element. Each element split by Ether and ARP packets b/c we built an Ether/ARP final packet
        packet = element[1]
        hosts["hosts"][packet.psrc] = packet.hwsrc

    print("[+] Discovered hosts: ")
    print(json.dumps(hosts, sort_keys=True, indent=4))

def get_arguments():
    options = parser.parse_args()[0]
    return options.address, options.range_val

def inspect_input(address, range_val):
    # reference globals
    global use_range

    if not address:
        parser.error("Missing IPv4 address. For help, use -h or --help.")
    if not "/" in address:
        try:
            ipaddress.ip_address(address)
        except ValueError as e:
            parser.error("Invalid IPv4 address. " + e)
    if not range_val:
        return
    if range_val and "/" in address:
        # Doesn't cause for an error, just let user know range will be ignored
        print("[WARN] CIDR Notation detected. Range argument will be ignored!")
        use_range = False
        return
    if range_val:
        try:
            int(range_val)
        except:
            parser.error("The range must be a positive integer greater than 0.")
    if range_val and int(range_val) < 1:
        parser.error("The range must be a positive integer greater than 0.")
    else:
        use_range = True

# Constants
TIMEOUT = 1
HELP_ADDR = "The network address (IPv4) to scan. If CIDR notation specified, any range arguments will be ignored"
HELP_RNG = "The number of addresses to send packets to (i.e., 3 -> 10.10.1.1, 10.10.1.2, 10.10.1.3)"

# Track range option
use_range = False

# Customize a parser
parser = optparse.OptionParser()
parser.add_option("-a", "--address", dest="address", help=HELP_ADDR)
parser.add_option("-r", "--range", dest="range_val", help=HELP_RNG)

address, range_val = get_arguments()
inspect_input(address, range_val)

if use_range:
    for i in range(0, int(range_val)):
        # get the final value in the address
        addr_split = address.split(".")
        final_octet = int(addr_split[3])
        # increment the final value
        final_octet += i
        # create a new address with the first 3 octects of the address
        next_addr_split = addr_split[0:3]
        # add the newly calculate final octet
        next_addr_split.append(str(final_octet))
        # turn back to a string
        next_addr = ".".join(next_addr_split)
        scan(next_addr)
else:
    scan(address)