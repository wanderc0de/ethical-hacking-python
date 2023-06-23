import subprocess, optparse, getmac, macaddress

def help():
    print("USAGE:")
    print("  Arguments: interface OR help (-h, --help), mac address")
    print("  Example: python mac_changer.py eth0 00:55:33:A3:21")

def change_mac(interface, mac):
    # Run native commands
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", mac])
    subprocess.call(["ifconfig", interface, "up"])

def get_arguments():
    # Capture input
    options, arguments = parser.parse_args()
    return options.interface, options.mac

def inspect_input(interface, mac):
    # If variables are None
    if not interface:
        parser.error("Missing interface. For help, use -h or --help")
    if not mac:
        parser.error("Missing mac address. For help, use -h or --help")
    # Test for valid interface
    if (getmac.get_mac_address(interface) == None):
        parser.error("Interface '{}' does not have a mac address.".format(interface))
        quit()
    # Test for a valid mac address
    try:
        macaddress.EUI48(mac)
    except ValueError as e:
        parser.error(e)
        quit()

def show_result(interface, mac):
    current_mac = getmac.get_mac_address(interface)

    if (current_mac != mac):
        print("[-] Failed to change mac address for {}".format(interface))
    else:
        print("[+] Successfully changed the mac address for {}".format(interface))


# Constants
HELP_INT = "The network interface that you want to modify."
HELP_MAC = "The desired mac address."

# Customize a parser
parser = optparse.OptionParser()
parser.add_option("-i", "--interface", dest="interface", help=HELP_INT)
parser.add_option("-m", "--mac", dest="mac", help=HELP_MAC)

# Get the input params
interface, mac = get_arguments()

# Inspect the input
inspect_input(interface, mac)

print("[+] Updating {} with mac address {}".format(interface, mac))

# Change the mac address
change_mac(interface, mac)

# Display results
show_result(interface, mac)

# this machine's original mac: 00:0c:29:1d:20:8f
