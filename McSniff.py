from scapy.all import sniff


sniff(iface="eth0", prn=lambda x: x.show())
