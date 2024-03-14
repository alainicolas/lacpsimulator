from scapy.all import *
from scapy.contrib.lacp import LACP, SlowProtocol
import time, sys, netifaces as ni, threading

# Initialize the LACP packet counter and port numbers
lacp_packet_count = {}
interface_port_numbers = {}
mute_output = False  # Default value for output

# Function to get the MAC address of an interface
def get_mac_address(iface):
    try:
        return ni.ifaddresses(iface)[ni.AF_LINK][0]['addr']
    except ValueError:
        if not mute_output:
            print(f"The specified interface {iface} is not valid or does not exist.")
        sys.exit(1)

# Function to send a LACP response
def send_lacp_response(packet, iface, src_mac):
    global lacp_packet_count  # Use the global variable for the packet counter

    if not packet.haslayer(LACP):
        return

    actor_state = 0x3f
    #actor_state = 0x3f
    actor_port_number = interface_port_numbers[iface]  # Retrieve the actor port number for this interface/thread

    response = Ether(dst=packet[Ether].dst, src=src_mac) / SlowProtocol(subtype=1)
    response /= LACP(
        version=1,
        actor_type=1,
        actor_length=20,
        actor_system_priority=0xffff,
        actor_system="aa:bb:cc:aa:bb:cc",
        actor_key=0x005d,
        actor_port_priority=0xff,
        actor_port_number=actor_port_number,  # Use the dynamically assigned port number
        actor_state=actor_state,
        partner_type=2,
        partner_length=20,
        partner_system_priority=packet[LACP].actor_system_priority,
        partner_system=packet[LACP].actor_system,
        partner_key=packet[LACP].actor_key,
        partner_port_priority=packet[LACP].actor_port_priority,
        partner_port_number=packet[LACP].actor_port_number,
        partner_state=packet[LACP].actor_state,
        collector_type=3,
        collector_length=16,
        collector_max_delay=0
    )
    sendp(response, iface=iface, verbose=0)  # verbose=0 to disable verbose mode

# Function to handle each captured packet
def handle_packet(packet, iface, src_mac):
    global lacp_packet_count  # Use the global variable for the packet counter

    if packet.haslayer(LACP):
        if iface not in lacp_packet_count:
            lacp_packet_count[iface] = 0
        lacp_packet_count[iface] += 1  # Increment the counter for each LACP packet received
        if not mute_output:
            print(f"LACP packet received on {iface}, sending response... (Counter: {lacp_packet_count[iface]})")
        time.sleep(1)
        send_lacp_response(packet, iface, src_mac)

# Function to start packet capture on an interface
def start_sniffing(iface, port_number):
    src_mac = get_mac_address(iface)  # Get the MAC address of the interface
    interface_port_numbers[iface] = port_number  # Assign a unique port number to this interface/thread
    if not mute_output:
        print(f"Listening on interface {iface} for LACP packets...")
    sniff(iface=iface, prn=lambda packet: handle_packet(packet, iface, src_mac), filter="ether proto 0x8809", store=0)

# Check for the mute parameter and interfaces from command line arguments
if "-mute" in sys.argv:
    mute_output = True
    sys.argv.remove("-mute")

if len(sys.argv) < 3:
    print("Usage: python3 script.py [-mute] <interface1_name> <interface2_name>")
    sys.exit(1)

# Start capturing on each interface in a separate thread with a unique actor port number
port_number = 0x0003  # Start with port number 0x0001
for iface in sys.argv[1:]:
    threading.Thread(target=start_sniffing, args=(iface, port_number)).start()
    port_number += 1  # Increment the port number for the next interface/thread
