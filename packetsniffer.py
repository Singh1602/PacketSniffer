import socket
import struct
import textwrap
from datetime import datetime
from scapy.all import *

def main():
    print('Starting packet capture...\n')
    
    try:
        
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print('\nPacket capture stopped.')

def packet_callback(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f'\nPacket captured at {timestamp}')
    
    # Ethernet Layer
    if Ether in packet:
        print(f'Ethernet Frame:')
        print(f'Destination MAC: {packet[Ether].dst}')
        print(f'Source MAC: {packet[Ether].src}')
        print(f'Protocol: {packet[Ether].type}')
    
    # IP Layer
    if IP in packet:
        print(f'IPv4 Packet:')
        print(f'Version: {packet[IP].version}')
        print(f'Header Length: {packet[IP].ihl}')
        print(f'TTL: {packet[IP].ttl}')
        print(f'Protocol: {packet[IP].proto}')
        print(f'Source IP: {packet[IP].src}')
        print(f'Target IP: {packet[IP].dst}')
        
        # ICMP
        if ICMP in packet:
            print('ICMP Packet:')
            print(f'Type: {packet[ICMP].type}')
            print(f'Code: {packet[ICMP].code}')
        
        # TCP
        elif TCP in packet:
            print('TCP Packet:')
            print(f'Source Port: {packet[TCP].sport}')
            print(f'Destination Port: {packet[TCP].dport}')
            print(f'Sequence: {packet[TCP].seq}')
            print(f'Acknowledgment: {packet[TCP].ack}')
            print(f'Flags: {packet[TCP].flags}')
        
        # UDP
        elif UDP in packet:
            print('UDP Packet:')
            print(f'Source Port: {packet[UDP].sport}')
            print(f'Destination Port: {packet[UDP].dport}')
            print(f'Length: {packet[UDP].len}')

def setup_instructions():
    print("""
    Before running this script, please:
    1. Install Scapy: pip install scapy
    2. Install Npcap from: https://npcap.com/#download
    3. Run this script as administrator
    
    Note: This script requires administrator privileges to capture packets.
    """)

if __name__ == '__main__':
    setup_instructions()
    main()

