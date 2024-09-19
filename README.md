# McSniff
Packet sniffer and interpreter... you know for research purposes

### Reasoning
I wanted to literally dig into the payloads, frames, packets etc. of what's actually going back and forth over a network. Understanding the breakdown of the structure, byte-for-byte was a good learning experience. 

I know, I know, I can just use scapy or use WireShark and dig into them, but where's the fun in that!?

### Notes 
1. Example below of how to do the same in scapy
2. For a deep dive into ethernet frames, see [this great resource](https://www.freecodecamp.org/news/the-complete-guide-to-the-ethernet-protocol/)

## Features and functionality
Broken down into the OSI model layers, this tool can process/dump/inspect the following:
### L2 - Data Link Layer
* Ethernet frame(s)
* ARP/RARP packet(s)?
  * Contention as technically not but also L2.5 depending who you ask lol

### L3 - Network Layer
* IPv4 packet(s)
* IPv6 packet(s)
* ICMP/ICMPv6 packets(s)

### L4 - Transport Layer
* TCP segment(s)
* UDP datagram(s)

## Run
```bash
sudo python McSniff.py
```

### Run whilst working on script
```bash
while true; clear; echo 'Running...'; do sudo timeout 20 python McSniff.py; echo 'Sleeping...'; sleep 5; done
```

## Further reading/docs
1. [Python struct formatting](https://docs.python.org/3/library/struct.html#format-characters)
2. [Python socket docs](https://docs.python.org/3/library/socket.html)
3. [Ethernet frame Wiki](https://en.wikipedia.org/wiki/Ethernet_frame)
4. [EtherType Wiki](https://en.wikipedia.org/wiki/EtherType)
5. [IPv4 packet structure Wiki](https://en.wikipedia.org/wiki/IPv4#Packet_structure)
6. [IP protocol numbers Wiki](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)


## Example from scapy
```python
from scapy.all import sniff
sniff(iface="eth0", prn=lambda x: x.show())
```