# mcsniff
packet sniffer and interpreter... you know for research purposes

### Reasoning
I wanted to literally dig into the payloads, frames, packets etc. of what's actually going back and forth over a network. Understanding the breakdown of the structure, byte-for-byte was a good learning experience. 

I know, I know, I can just use scapy or use WireShark and dig into them, but where's the fun in that!?

### Notes 
1. Example below of how to do the same in scapy
2. For a deep dive into ethernet frames, see [this great resource](https://www.freecodecamp.org/news/the-complete-guide-to-the-ethernet-protocol/)

## Features and functionality
1. Ethernet frame processing
2. ...?

## Run
```bash
sudo python McSniff.py
```

## Example from scapy
```python
from scapy.all import sniff
sniff(iface="eth0", prn=lambda x: x.show())
```