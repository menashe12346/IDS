"""
This module is responsible for analyzing the packets and checking if they meet the requirements
"""
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP
from scapy.layers.http import HTTP
from scapy.packet import *

from Database import Database


class Analyzer:
    def __init__(self, db, INTERNAL_IP_RANGE, VOLUME_THRESHOLD = 1500):
        self.INTERNAL_IP_RANGE = INTERNAL_IP_RANGE
        self.AUTHORIZED_TCP_IPS = set()  # When creating a connection, add to the authorized TCP IPs
        self.AUTHORIZED_SERVER_IPS = set()  # When sent a DNS request, add to the authorized server IPs
        self.UNAUTHORIZED_SERVER_IPS = set()  # Server IPs that didn't send a DNS response
        self.VOLUME_THRESHOLD = VOLUME_THRESHOLD

        self.protocol_count = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        self.total_bytes = 0
        self.db = db

    def analyze(self, packet):
        if packet.haslayer(IP):
            # Extracting the tuple-5 flow identifiers:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            if ip_src is None or ip_dst is None:
                return  # Skip the packet if src or dst IP is not valid

            # Default values for port_src and port_dst (set to None for non-TCP/UDP protocols)
            port_src = None
            port_dst = None

            protocol = packet[IP].proto
            protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(protocol, 'Other')

            # Handling TCP and UDP layers
            if packet.haslayer(TCP):
                port_src = packet[TCP].sport
                port_dst = packet[TCP].dport
            elif packet.haslayer(UDP):
                port_src = packet[UDP].sport
                port_dst = packet[UDP].dport

            # Update protocol count
            if protocol_name in self.protocol_count:
                self.protocol_count[protocol_name] += 1
            else:
                self.protocol_count['Other'] += 1  # Ensure "Other" is incremented if not TCP/UDP/ICMP

            packet_size = len(packet)

            # Update total traffic size
            self.total_bytes += packet_size

            # Create a tuple for the flow
            flow_id = (ip_src, port_src, ip_dst, port_dst, protocol_name)

            # Insert statistics into the database
            self.db.insert_statistic(flow_id, packet_size, protocol_name)

            if len(packet) > self.VOLUME_THRESHOLD:
                self.db.insert_alert(
                    f"ALERT: High volume detected in packet - Byte Count: {len(packet)} - Packet: {packet}")

            # Analyze the network layer
            self.network_layer_validation(packet)

            # Analyze DNS packets
            if packet.haslayer(DNS):
                self.dns_analyzer(packet)

            # Analyze transport layer (TCP/UDP)
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                self.transport_layer_validation(packet)

            # Analyze HTTP traffic
            if packet.haslayer(HTTP):
                self.http_analyzer(packet)

            # Analyze HTTPS traffic (port 443)
            elif packet.haslayer(TCP) and packet[TCP].dport == 443:
                self.https_analyzer(packet)

            # Analyze FTP traffic (ports 20, 21)
            elif packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 20):
                self.ftp_analyzer(packet)

    # This method is used to analyze the HTTP packets and check if they meet the requirements
    # Things to consider:
    # - leak of sensitive information through HTTP requests
    # - Long URL size
    # - HTTP headers
    # - didn't send any DNS request before sending the HTTP request
    def http_analyzer(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == 80:
            # Extract the raw data from the packet
            raw_data = packet[Raw].load.decode(errors="ignore")

            if packet.dst not in self.AUTHORIZED_SERVER_IPS:
                self.db.insert_alert(f"ALERT: Didn't do a DNS request before sending an HTTP request - Packet: {packet}")

            if "GET" in raw_data or "POST" in raw_data:  # HTTP Request detection
                lines = raw_data.split("\r\n")
                request_line = lines[0]  # Request line (e.g., GET /path HTTP/1.1)
                url = request_line.split(' ')[1]  # URL is the second part of the request line
                url_size = len(url)

                # Check if the URL size meets the requirement
                if url_size > 512:
                    self.db.insert_alert(f"ALERT: URL size exceeds 512 bytes - Packet: {packet}")

                # Check for HTTP headers
                header_dict = {}
                for header in lines[1:]:
                    if ": " in header:
                        key, value = header.split(": ", 1)
                        header_dict[key] = value
                if "Host" not in header_dict:
                    self.db.insert_alert(f"ALERT: Host header is missing - Packet: {packet}")
                if "User-Agent" not in header_dict:
                    self.db.insert_alert(f"ALERT: User-Agent header is missing - Packet: {packet}")

            # Check for HTTP headers or sensitive information
            if "HTTP" in raw_data:

                # Check for common sensitive data leaks
                if "Authorization" in raw_data:
                    self.db.insert_alert(f"ALERT: Sensitive Data Detected: Authorization Header Found")
                if "password" in raw_data:
                    self.db.insert_alert(f"ALERT: Sensitive Data Detected: Password Found")
                if "token" in raw_data:
                    self.db.insert_alert(f"ALERT: Sensitive Data Detected: Token Found")

        else:
            self.db.insert_alert(f"ALERT: Unauthorized port in destination - Packet: {packet}")


    # This method is used to analyze the DNS packets and check if they meet the requirements
    # Things to consider:
    # - DNS requests to unauthorized ports
    # - DNS headers
    # - DNS tunneling
    # - DNS requests have a domain name with more than 20 characters
    # - DNS requests for suspicious domains or not known domains names
    def dns_analyzer(self, packet):
        if DNS in packet:
            dns_layer = packet[DNS]

            # Check if DNS packet is a query
            if dns_layer.qr == 0:

                # Extract the domain name from the DNS request
                domain_name = dns_layer.qd.qname.decode().strip('.')
                domain_parts = domain_name.split('.')

                # Check if the domain name has more than one part
                if len(domain_parts) > 1:
                    name_size = len(domain_parts[0])  # Size of the name part before the TLD

                    # Check if the size of the domain name meets the requirement
                    if name_size > 20:
                        self.db.insert_alert(f"ALERT: DNS request for suspicious domain {domain_name} - Packet: {packet}")

                if len(dns_layer) > 200:
                    self.db.insert_alert(f"ALERT: DNS tunneling detected - Packet: {packet}")

                # Check if DNS request is using an unauthorized port
                if packet[UDP].dport != 53:
                    if packet.haslayer(UDP):
                        self.db.insert_alert(
                            f"ALERT: DNS request to unauthorized port {packet[UDP].dport} - Packet: {packet}")
                    elif packet.haslayer(TCP):  # Handle rare cases where DNS might use TCP
                        self.db.insert_alert(
                            f"ALERT: DNS request to unauthorized port {packet[TCP].dport} - Packet: {packet}")

                # Check if DNS request is using an unauthorized protocol
                if packet[IP].proto != 17:
                    self.db.insert_alert(f"ALERT: DNS request using unauthorized protocol {packet[IP].proto} - Packet: {packet}")

                # Check if DNS request is for a suspicious domain
                if dns_layer.qd.qname not in {".com", ".net", ".org", ".edu", ".gov"}:
                    self.db.insert_alert(f"ALERT: DNS request for suspicious domain {dns_layer.qd.qname} - Packet: {packet}")

                # Check for DNS headers
                if dns_layer.ra != 0:
                    self.db.insert_alert(f"ALERT: RA flag is set in DNS query - Packet: {packet}")

                if dns_layer.z != 0:
                    self.db.insert_alert(f"ALERT: Z flag is set in DNS query - Packet: {packet}")

                if dns_layer.rcode != 0:
                    self.db.insert_alert(f"ALERT: RCODE flag is set in DNS query - Packet: {packet}")

                if dns_layer.tc != 0:
                    self.db.insert_alert(f"ALERT: TC flag is set in DNS query - Packet: {packet}")

                if dns_layer.qdcount < 1 or dns_layer.qdcount > 4:
                    self.db.insert_alert(f"ALERT: Invalid QDCOUNT in DNS query - Packet: {packet}")

                if dns_layer.ancount != 0:
                    self.db.insert_alert(f"ALERT: ANCOUNT flag is set in DNS query - Packet: {packet}")

                if dns_layer.nscount != 0:
                    self.db.insert_alert(f"ALERT: NSCOUNT flag is set in DNS query - Packet: {packet}")

                if dns_layer.arcount != 0:
                    self.db.insert_alert(f"ALERT: ARCOUNT flag is set in DNS query - Packet: {packet}")

            # Check if DNS packet is a response
            if dns_layer.qr == 1:
                # Add to the authorized IPs when receiving a DNS response
                self.AUTHORIZED_SERVER_IPS.add(packet[IP].src)

    # This method is used to analyze the HTTPS packets and check if they meet the requirements
    # Things to consider:
    # - didn't send any DNS request before sending the HTTPS request
    def https_analyzer(self, packet):
        if packet.haslayer(TCP) and packet[TCP].dport == 443:

            if packet.dst not in self.AUTHORIZED_SERVER_IPS:
                self.db.insert_alert(f"ALERT: Didn't do a DNS request before sending an HTTPS request - Packet: {packet}")

        else:
            self.db.insert_alert(f"ALERT: Unauthorized port in destination - Packet: {packet}")

    # This method is used to analyze the FTP packets and check if they meet the requirements
    # Things to consider:
    # - leak of sensitive information through FTP requests
    # - FTP headers
    def ftp_analyzer(self, packet):
        if packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 20):
            # Extract the raw data from the packet
            raw_data = packet[Raw].load.decode(errors="ignore")

            if "USER" in raw_data or "PASS" in raw_data:
                self.db.insert_alert(f"ALERT: Sensitive Data Detected: FTP Credentials Found - Packet: {packet}")

    # This method is used to analyze the packets in the network layer and check if they meet the requirements
    # Things to consider:
    # - Source IP address is in the internal IP range
    # - Destination IP address is in the unauthorized IP addresses
    # - Verify the checksum of the packet
    def network_layer_validation(self, ip_layer_packet):
        # If INTERNAL_IP_RANGE is not set, skip this validation
        if not self.INTERNAL_IP_RANGE:
            return

        if ip_layer_packet.chksum is not None:
            self.db.insert_alert(f"ALERT: Checksum verification failed - Packet: {ip_layer_packet}")

        if not ip_layer_packet.src.startswith(self.INTERNAL_IP_RANGE) and not ip_layer_packet.dst.startswith(
                self.INTERNAL_IP_RANGE):
            self.db.insert_alert(f"ALERT: Source IP address is not in internal IP range - Packet: {ip_layer_packet}")

        if ip_layer_packet.dst in self.UNAUTHORIZED_SERVER_IPS or ip_layer_packet.src in self.UNAUTHORIZED_SERVER_IPS:
            self.db.insert_alert(f"ALERT: Unauthorized IP address in destination - Packet: {ip_layer_packet}")

    # This method is used to analyze the packets in the transport layer and check if they meet the requirements
    # The packets here are from inside the internal network to the outside network
    # Things to consider:
    # - Source port within the range
    # - Destination port within the range
    # - Verify the checksum of the packet
    # - Check for anomalies in the flags of the packet (like SYN, ACK, FIN, etc.)
    def transport_layer_validation(self, transport_layer_packet):
        if transport_layer_packet.haslayer(TCP) or transport_layer_packet.haslayer(UDP):
            is_tcp = transport_layer_packet.haslayer(TCP)
            if TCP in transport_layer_packet:
                transport_layer = transport_layer_packet[TCP]
            else:
                transport_layer = transport_layer_packet[UDP]

            if transport_layer.chksum is not None:
                self.db.insert_alert(f"ALERT: Checksum verification failed - Packet: {transport_layer_packet}")

            if 1024 < transport_layer.sport or transport_layer.sport > 65535:
                self.db.insert_alert(f"ALERT: Source port out of range - Packet: {transport_layer_packet}")

            if transport_layer.dport >= 1024 or transport_layer.dport == 0:
                self.db.insert_alert(f"ALERT: Destination port out of range - Packet: {transport_layer_packet}")

            if is_tcp:
                # Check for anomalies in the flags of the packet
                self.tcp_flags_validation(transport_layer_packet)

                flag_string = transport_layer_packet.sprintf('%TCP.flags%')

                # add to the authorized TCP IPs when creating a connection
                if "S" in flag_string:
                    self.AUTHORIZED_TCP_IPS.add(transport_layer_packet[IP].dst)

                # check if the destination IP is in the authorized TCP IPs
                if self.AUTHORIZED_TCP_IPS is not None:
                    if transport_layer_packet[IP].dst not in self.AUTHORIZED_TCP_IPS:
                        self.db.insert_alert(f"ALERT: Unauthorized IP in destination - Packet: {transport_layer_packet}")

                # remove from the authorized TCP IPs when closing the connection
                if "F" in flag_string:
                    if transport_layer_packet[IP].dst in self.AUTHORIZED_TCP_IPS:
                        self.AUTHORIZED_TCP_IPS.remove(transport_layer_packet[IP].dst)

    # This method is used to analyze the flags of the TCP packets and check if they meet the requirements
    # Things to consider:
    # - Unusual flags set in the packet
    # - Missing flags in the packet
    # - No flags set in the packet
    def tcp_flags_validation(self, transport_layer_packet):
        if TCP in transport_layer_packet:
            tcp_layer = transport_layer_packet[TCP]
            flags = tcp_layer.flags
            flag_string = transport_layer_packet.sprintf('%TCP.flags%')

            if flags == 0:
                self.db.insert_alert(f"ALERT: No flags set in the packet - Packet: {transport_layer_packet}")

            elif flags & 0x3F == 0x3F:
                self.db.insert_alert(f"ALERT: All flags set in the packet - Packet: {transport_layer_packet}")

            elif "S" in flag_string and "F" in flag_string:
                self.db.insert_alert(f"ALERT: Unusual flags set in the packet - Packet: {transport_layer_packet}")

            elif "S" in flag_string and "A" in flag_string and "R" in flag_string:
                self.db.insert_alert(f"ALERT: Unusual flags set in the packet - Packet: {transport_layer_packet}")

            elif "S" in flag_string and "R" in flag_string:
                self.db.insert_alert(f"ALERT: Unusual flags set in the packet - Packet: {transport_layer_packet}")

            elif "S" in flag_string and "P" in flag_string and "U" in flag_string:
                self.db.insert_alert(f"ALERT: Unusual flags set in the packet - Packet: {transport_layer_packet}")

            elif "F" in flag_string and "A" not in flag_string:
                self.db.insert_alert(f"ALERT: Unusual flags set in the packet - Packet: {transport_layer_packet}")

            elif "R" in flag_string and "A" not in flag_string:
                self.db.insert_alert(f"ALERT: Unusual flags set in the packet - Packet: {transport_layer_packet}")

            elif "A" in flag_string and "U" in flag_string and "F" in flag_string:
                self.db.insert_alert(f"ALERT: Unusual flags set in the packet - Packet: {transport_layer_packet}")

            elif "A" in flag_string and "P" in flag_string and "F" in flag_string:
                self.db.insert_alert(f"ALERT: Unusual flags set in the packet - Packet: {transport_layer_packet}")

            elif "U" in flag_string and "P" in flag_string:
                self.db.insert_alert(f"ALERT: Unusual flags set in the packet - Packet: {transport_layer_packet}")
