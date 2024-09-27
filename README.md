# McSniff
Packet sniffer and interpreter... you know for research purposes

### Reasoning
I wanted to literally dig into the payloads, frames, packets etc. of what's actually going back and forth over a network. Understanding the breakdown of the structure, byte-for-byte was a good learning experience. 

I know, I know, I can just use scapy or use WireShark and dig into them, but where's the fun in that!?

### Notes 
1. Example below of how to do the same in scapy
2. For a deep dive into ethernet frames, see [this great resource](https://www.freecodecamp.org/news/the-complete-guide-to-the-ethernet-protocol/)

## Features and functionality
### Tool features
* Listen on different interfaces
* Track statistics (start/end time, counts of frames/packets/etc.)
* All the `things` listed below under `OSI layers`

### OSI layers
Broken down into the OSI model layers, this tool can process/dump/inspect the following:
#### L2 - Data Link Layer
* Ethernet frame(s)
* ARP/RARP packet(s)?
  * Contention as technically not but also L2.5 depending who you ask lol

#### L3 - Network Layer
* IPv4 packet(s)
* IPv6 packet(s)
* ICMP packets(s)
* ICMPv6 packets(s)
* IGMP packet(s)

#### L4 - Transport Layer
* TCP segment(s)
* UDP datagram(s)

## Run
### TL;DR
Minimum input required is the interface to listen on
```bash
sudo python McSniff.py <interface>

# example
sudo python McSniff.py eth0
```
### Help
Using the `-h` flag will output the below for all options and params that can be supplied
```
~ sudo python McSniff.py -h
usage: McSniff.py [-h] [-p] [-s] [-t] [-2 [{ETH,ARP,RARP} ...]] [-3 [{IPv4,IPv6,ICMP,ICMPv6,IGMP} ...]] [-4 [{TCP,UDP} ...]] interface

Network analyser (packet sniffer)... for you know, research purposes ;)

positional arguments:
  interface             interface to analyse, run 'ip link' to list

options:
  -h, --help            show this help message and exit
  -p, --payload         dump payload output
  -s, --stats           enable and show statistics for what's been processed
  -t, --https           include dumps even for 443 port payloads (encrypted traffic)
  -2 [{ETH,ARP,RARP} ...], --level2 [{ETH,ARP,RARP} ...]
                        OSI level 2 filter, by default listens for all, supply no args to ignore level
  -3 [{IPv4,IPv6,ICMP,ICMPv6,IGMP} ...], --level3 [{IPv4,IPv6,ICMP,ICMPv6,IGMP} ...]
                        OSI level 3 filter, by default listens for all, supply no args to ignore level
  -4 [{TCP,UDP} ...], --level4 [{TCP,UDP} ...]
                        OSI level 4 filter, by default listens for all, supply no args to ignore level

```

### Examples
What you supply when toggling the levels is what you get, i.e. you supply only `IPv4` you get only `IPv4`. Also a little bit of common sense is required, for example if you specify nothing for `-3` you won't get anything for `L4 (TCP/UDP)` as it's nested within L3!

#### Capture only frames, don't look deeper
```bash
sudo python McSniff.py eth0 -2 ETH
```

#### Capture only IPv4 and IPv6, ignoring ARP/RARP, ICMP etc.
```bash
sudo python McSniff.py eth0 -2 ETH -3 IPv4 IPv6
```

#### Capture only IPv6 UDP packets, dump payload and enable statistics
```bash
sudo python McSniff.py eth0 -2 ETH -3 IPv6 -4 UDP -p -s
```

### Run whilst working on script
```bash
while true; clear; echo 'Running...'; do sudo timeout 20 python McSniff.py eth0; echo 'Sleeping...'; sleep 5; done
```

## Triggering payloads
### L2
```bash
# eth - be connected to a network

# arp
sudo arping <destination>

# rarp - not really seen, can happen during boot but DCHP superseeded it
```

### L3
```bash
# ICMP (v4)
ping -4 <destination>
ping -4 google.co.uk

# ICMPv6 - need to have IPv6 enabled on interface ofc
ping -6 <destination>
ping -6 google.co.uk
```

### L4
```bash
# TCP - unsecure HTTP requests are great as you can see the payload, HTTPS is encrypted so you can't see payload (unless you have the certs to decrypt)
curl http://<destination>

# -k means ignore certs/verification, connect anyway
curl -k http://httpforever.com/

# UDP - DNS requests are easiest to trigger
dig <host>
dig google.co.uk

# to force the query to a specific name server, specify the @ flag
dig @<name server like 1.1.1.1> <host>
dig @1.1.1.1 google.co.uk
```

## Further reading/docs
1. [Python struct formatting](https://docs.python.org/3/library/struct.html#format-characters)
2. [Python socket docs](https://docs.python.org/3/library/socket.html)
3. [Ethernet frame Wiki](https://en.wikipedia.org/wiki/Ethernet_frame)
4. [EtherType Wiki](https://en.wikipedia.org/wiki/EtherType)
5. [IPv4 packet structure Wiki](https://en.wikipedia.org/wiki/IPv4#Packet_structure)
6. [IP protocol numbers Wiki](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
7. [UDP structure Wiki](https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure)
8. [TCP strcuture Wiki](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure)
9. [Ping (ICMP/ICMPv6) structure Wiki](https://en.wikipedia.org/wiki/Ping_(networking_utility)#Message_format)
10. [ARP structure Wiki](https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure)

## Example from scapy
```python
from scapy.all import sniff
sniff(iface="eth0", prn=lambda x: x.show())
```