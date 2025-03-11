# PacketSniffer
This Python project is a network packet sniffer that captures and analyses live network traffic using the Scapy library. The script listens for incoming packets and decodes key protocol details, displaying information about Ethernet, IP, TCP, UDP, and ICMP layers.

For each captured packet, the tool logs:

Ethernet Frame: Source and destination MAC addresses, protocol type
IPv4 Packet: Version, TTL, source and destination IP addresses, protocol number
TCP/UDP Packets: Ports, sequence numbers, flags, and packet lengths
ICMP Packets: Type, code, and related fields
It’s a great way to monitor network activity, troubleshoot connections, and understand packet structures. The script runs on Windows (with Npcap) and requires administrator privileges for full packet capture capabilities.
