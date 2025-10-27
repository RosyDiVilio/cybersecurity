# === Scapy IP Packet Inspector ===
#
# Description:
# This script demonstrates how to create a basic IP packet object using Scapy
# and inspect its fields and properties. It does not send any packets over the network.
#
# How it works:
# 1.  It imports the `IP` layer and the `ls` function from the Scapy library.
# 2.  It defines a destination IP address.
# 3.  It creates an instance of the `IP` layer, setting the destination (`dst`) field.
# 4.  It uses the `ls()` function to list all the fields available in the IP layer,
#     showing their default values and the one that was set.
# 5.  It demonstrates how to access a specific field's value directly (e.g., `ip_layer.dst`).
# 6.  It calls the `.summary()` method to get a short, human-readable summary of the packet.
#
# Dependencies:
# - scapy
#
# Usage:
# - Run the script directly. No special permissions are needed as it only creates
#   an object in memory and does not perform any network operations.
from scapy.all import ls, IP

if __name__ == "__main__":
    # Define a valid destination IP address
    dest_ip = "1.1.1.1"

    # Create an IP layer object with the specified destination
    ip_layer = IP(dst=dest_ip)

    # Use ls() to display all fields of the IP layer.
    # The ls() function prints directly to the console.
    print("--- Listing all fields of the IP layer ---")
    ls(ip_layer)
    print("------------------------------------------\n")

    # Access and print specific fields of the packet
    print("--- Accessing specific fields ---")
    print(f"Destination Address: {ip_layer.dst}")
    
    # The .summary() method provides a one-line description of the packet
    print(f"Packet Summary: {ip_layer.summary()}")
    print("---------------------------------")