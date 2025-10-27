# === Scapy ICMP Echo Request (Ping) Script ===
#
# Description:
# This script sends a single ICMP Echo Request (commonly known as a "ping")
# to a specified destination IP address and displays the response if one is received.
#
# How it works:
# 1.  It creates an IP packet layer, specifying only the destination address.
#     Scapy will automatically fill in the source IP address based on the network
#     interface used for sending.
# 2.  It creates an ICMP Echo Request layer.
# 3.  It stacks the IP and ICMP layers to form a complete packet.
# 4.  It uses the `sr()` function (Send and Receive) to send the packet at Layer 3
#     and wait for a response.
# 5.  If a response is received, the script uses `.show()` to display a detailed
#     summary of both the sent packet and the received reply.
# 6.  If no response is received within the timeout, it prints a notification message.
#
# Dependencies:
# - scapy
#
# Usage:
# - This script must be run with root/administrator privileges to send raw packets.
# - Ensure the `iface` parameter in the `sr()` function matches your active
#   network interface (e.g., "eth0", "en0", "Wi-Fi").
from scapy.all import IP, ICMP, sr

if __name__ == "__main__":
    # Define the destination IP address for the ping
    dest_ip = "1.1.1.1"

    # Create the IP layer.
    # The source IP (src) is omitted; Scapy will automatically set it.
    ip_layer = IP(dst=dest_ip)

    # Create the ICMP "echo-request" layer
    icmp_req = ICMP()

    # Combine the layers into a single packet
    packet = ip_layer / icmp_req

    # Show the packet that will be sent
    print("--- Packet to be sent ---")
    packet.show()
    print("-------------------------\n")

    # Send the packet and wait for a response.
    # 'answered' is a list of (sent, received) packet pairs.
    # 'unanswered' contains packets that did not get a reply.
    answered, unanswered = sr(packet, iface="eth0", timeout=3, verbose=False)

    # Check if we received any responses
    if answered:
        print("--- Response Received ---")
        # .show() on a list of answered packets provides a nice summary
        answered.show()
        print("-------------------------")
    else:
        print("--- No response received from", dest_ip, "---")