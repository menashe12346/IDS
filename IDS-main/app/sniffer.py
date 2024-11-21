"""
This module is responsible for sniffing packets from the network.
The Sniffer class uses the Scapy library to sniff packets from the network.
"""
from scapy.sendrecv import sniff
from scapy.all import rdpcap


class Sniffer:

    def __init__(self, analyzer):
        self.analyzer = analyzer

    def sniff(self):
        # Sniff packets indefinitely
        while True:
            sniff(prn=self.analyzer.analyze, store=0)

    def analyze_pcap(self, pcap_file):
        # Load the PCAP file and analyze each packet
        packets = rdpcap(pcap_file)
        for packet in packets:
            self.analyzer.analyze(packet)
