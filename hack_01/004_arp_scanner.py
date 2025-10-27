# === Network Scanner using Scapy ===
#
# Description:
# This script discovers active hosts on the local network by sending ARP requests.
#
# How it works:
# 1.  It crafts an Ethernet frame with a broadcast destination MAC address (FF:FF:FF:FF:FF:FF),
#     ensuring the packet is sent to all devices on the local network segment.
# 2.  It creates an ARP "who-has" request, asking for the MAC address of every IP address
#     within the specified `ip_range`.
# 3.  The Ethernet and ARP layers are combined into a single packet.
# 4.  The `srp` (Send and Receive Packet) function from Scapy sends the packet on layer 2
#     and collects the replies.
# 5.  The script then iterates through the answered packets, extracting the IP address (psrc)
#     and MAC address (src) from each reply.
# 6.  Finally, it prints the discovered IP and MAC address pairs.
#
# Dependencies:
# - scapy
#
# Usage:
# - You may need to run this script with root/administrator privileges to send raw packets.
# - Change the `ip_range` variable to match your network's subnet.
# - Change the `iface` parameter to your active network interface name (e.g., "eth0", "en0", "Wi-Fi").
from scapy.all import Ether, ARP, srp

if __name__ == "__main__":
    # Define the broadcast MAC address to send the packet to all devices
    broadcast = "FF:FF:FF:FF:FF:FF"
    ether_layer = Ether(dst=broadcast)

    # Define the IP range to scan (e.g., 192.168.1.1/24 for the entire subnet)
    ip_range = "192.168.1.1/24"
    arp_layer = ARP(pdst=ip_range)

    # Combine the layers into a single packet
    packet = ether_layer / arp_layer

    # Send the packet and capture the responses.
    # 'ans' is a list of answered packets, 'unans' is for unanswered ones.
    # timeout=2 sets a 2-second wait time for responses.
    # verbose=False cleans up the output.
    ans, unans = srp(packet, iface="eth0", timeout=2, verbose=False)

    print("Discovered devices on the network:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")

    # Iterate through the list of responses
    for snd, rcv in ans:
        # Extract the source IP (psrc) and source MAC (src) from the received packet (rcv)
        ip = rcv[ARP].psrc
        mac = rcv[Ether].src
        print(f"{ip}\t\t{mac}")