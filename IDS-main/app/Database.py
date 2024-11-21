"""
Database class
This class is used as the database.
It stores the statistics of the packets and the alerts.
The statistics are stored in a dictionary where the key is the tuple-5 flow identifier and the value is a dictionary
containing the number of packets, the number of bytes, and the protocol of the flow.
The alerts are stored in a list.
"""

from collections import defaultdict


class Database:
    def __init__(self):
        self.statistics = defaultdict(lambda: {"packets": 0, "bytes": 0, "protocol": None})
        self.total_bytes = 0
        self.byte_history = []
        self.total_packets = 0
        self.alerts = []

    def get_statistic_of_key(self, key):
        return self.statistics.get(key)

    def insert_statistic(self, key, number_of_bytes, protocol):
        self.statistics[key]["packets"] += 1
        self.statistics[key]["bytes"] += number_of_bytes
        self.statistics[key]["protocol"] = protocol
        self.total_bytes += number_of_bytes
        self.total_packets += 1

        self.byte_history.append(self.total_bytes)

    def get_total_bytes(self):
        return self.total_bytes

    def get_total_packets(self):
        return self.total_packets

    def get_byte_history(self):
        return self.byte_history

    def get_statistics(self):
        return self.statistics

    def get_alerts(self):
        return self.alerts

    def get_protocol_distribution(self):
        protocol_distribution = defaultdict(int)
        for stat in self.statistics.values():
            protocol_distribution[stat["protocol"]] += stat["packets"]
        return protocol_distribution

    def insert_alert(self, alert):
        self.alerts.append(alert)

    def clear_alerts(self):
        self.alerts.clear()

    def clear_statistics(self):
        self.statistics.clear()

    def clear_all(self):
        self.clear_alerts()
        self.clear_statistics()
        self.total_bytes = 0
        self.total_packets = 0
        self.byte_history.clear()

