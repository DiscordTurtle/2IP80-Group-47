
# ARP/DNS spoofing tool - Final project - Group 47

A fully-fledged poisoning/spoofing linux tool for ARP and DNS using Scapy and Netfilterqueue.




## Authors

- [Cristian Fildan](https://github.com/DiscordTurtle)
- [Kamyar Khodayari Rostam Abad](https://github.com/kamyarkhodayari)


## How to run the tool

Firstly, clone the project via the link below:

```bash
  git clone https://github.com/DiscordTurtle/2IP80-Group-47.git
```

Make sure that you have python3 and related dependencies installed on your system. Then you need to install Scapy and Netfilterqueue. You may need to install some dependencies listed for netfilterqueue.

```bash
  pip install scapy
  pip install netfilterqueue
```

That's it! You can start using the ARP spoofing tool by typing:

```bash
  python3 arp_spoofing.py
```
You can start using DNS spoofing tool by typing:

```bash
  python3 dns_spoofing.py
```

## Documentation

ARP spoofing tool automatically enables IP Forwarding on your OS.\
While this tool is running, you can see the number of packets being sent to the victim every `2` seconds. You can customize this sleep time in the code by changing the variable `sleep` in `arp_spoofing.py`.

Please note that for using the DNS spoofing tool, you need the ARP spoofer running on another terminal.\
This tool will automatically handle the `iptables` rules for you, and it flushes the `iptable` after it's terminated.\
Input the domain name you want to poision with this format: `your-domain.com.` (No www, [dot] at the end).

