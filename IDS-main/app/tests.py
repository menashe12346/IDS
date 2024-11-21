"""
This class contains unit tests for the Memory Leak Analyzer.
"""
import unittest
from scapy.all import wrpcap, IP, TCP, UDP, DNS, DNSQR, Raw
from Database import Database
from analyzer import Analyzer
from sniffer import Sniffer
import random
import os

class TestMemoryLeakAnalyzer(unittest.TestCase):

    def setUp(self):
        """Set up the test environment by initializing the database, analyzer, and sniffer."""
        self.db = Database()
        self.analyzer = Analyzer(self.db, INTERNAL_IP_RANGE="192.168.0.0/16", VOLUME_THRESHOLD=1500)
        self.sniffer = Sniffer(self.analyzer)
        self.pcap_files = []  # List to keep track of pcap files for cleanup

    def test_privileged_port_packet(self):
        """Test to ensure the analyzer DOES trigger an alert for packets with destination port of 0 or above 1024."""

        # Generate a random port that is either 0 or greater than 1024
        random_port = random.choice([0, random.randint(1025, 65535)])

        # Create a TCP packet with a valid checksum and a source IP within the internal IP range
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=random_port) / Raw(load="Test")

        # Save the packet to a pcap file
        test_pcap = "test_packet.pcap"
        wrpcap(test_pcap, packet)
        self.pcap_files.append(test_pcap)  # Track the created file

        # Analyze the pcap file using the Sniffer class
        self.sniffer.analyze_pcap(test_pcap)

        # Check if any alerts have been triggered
        alerts = self.db.get_alerts()

        # Filter alerts related to 'Destination port out of range'
        port_alerts = [alert for alert in alerts if "ALERT: Destination port out of range" in alert]

        # Assert that an alert is triggered for destination port of 0 or greater than 1024
        self.assertTrue(len(port_alerts) > 0,
                        f"No 'Destination port out of range' alert triggered for port {random_port} outside the range 0 to 1024.")

    def test_invalid_checksum_packet(self):
        """Test to ensure the analyzer detects packets with an invalid checksum."""

        # Create a TCP packet with an invalid checksum
        packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80, chksum=0x1234) / Raw(
            load="Test data")

        # Save the packet to a pcap file
        test_pcap = "test_invalid_checksum.pcap"
        wrpcap(test_pcap, packet)
        self.pcap_files.append(test_pcap)  # Track the created file

        # Analyze the pcap file using the Sniffer class
        self.sniffer.analyze_pcap(test_pcap)

        # Check if any alerts have been triggered
        alerts = self.db.get_alerts()

        # Assert that an alert for the invalid checksum is triggered
        self.assertTrue(any("ALERT: Checksum verification failed" in alert for alert in alerts),
                        "No alert triggered for a packet with an invalid checksum.")

    def test_syn_fin_flags_packet(self):
        """Test to ensure the analyzer detects packets with both SYN and FIN flags set."""

        # Generate a random port between 0 and 1024
        random_port = random.randint(0, 1024)

        # Create a TCP packet with SYN and FIN flags both set
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=random_port, flags="SF") / Raw(load="Test")

        # Save the packet to a pcap file
        test_pcap = "test_syn_fin_packet.pcap"
        wrpcap(test_pcap, packet)
        self.pcap_files.append(test_pcap)  # Track the created file

        # Analyze the pcap file using the Sniffer class
        self.sniffer.analyze_pcap(test_pcap)

        # Check if any alerts have been triggered
        alerts = self.db.get_alerts()

        # Assert that an alert for the unusual flags (SYN + FIN) is triggered
        self.assertTrue(any("ALERT: Unusual flags set in the packet" in alert for alert in alerts),
                        "No alert triggered for a packet with both SYN and FIN flags set.")

    def test_long_domain_dns_query(self):
        """Test to ensure the analyzer detects DNS queries with a domain name longer than 20 characters."""

        # Create a DNS query packet with a domain name longer than 20 characters
        long_domain = "averylongdomainnamethatexceeds20.com"
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=12345, dport=53) / \
                 DNS(rd=1, qd=DNSQR(qname=long_domain))

        # Save the packet to a pcap file
        test_pcap = "test_dns_long_domain.pcap"
        wrpcap(test_pcap, packet)
        self.pcap_files.append(test_pcap)  # Track the created file

        # Analyze the pcap file using the Sniffer class
        self.sniffer.analyze_pcap(test_pcap)

        # Check if any alerts have been triggered
        alerts = self.db.get_alerts()

        # Assert that an alert for the long domain name is triggered
        self.assertTrue(any("ALERT: DNS request for suspicious domain" in alert for alert in alerts),
                        "No alert triggered for a DNS query with a domain name longer than 20 characters.")

    def tearDown(self):
        """Clean up after each test."""
        # Clear the database
        self.db.clear_all()

        # Remove all pcap files created during the test
        for pcap_file in self.pcap_files:
            if os.path.exists(pcap_file):
                os.remove(pcap_file)

if __name__ == "__main__":
    unittest.main()
