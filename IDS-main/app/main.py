"""
This file starts the network monitoring system.
"""
import argparse

from app.Database import Database
from app.analyzer import Analyzer
from app.sniffer import Sniffer
from app.GUI import GUI
from threading import Thread
import tkinter as tk

# Constants
VOLUME_THRESHOLD = 1500  # Threshold for total bytes in a flow(0.5 MB)


def main():
    parser = argparse.ArgumentParser(description="Network Monitoring System")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip-range", type=str, help="Internal IP Range (e.g., 192.168.0.0/16)")
    group.add_argument("--pcap", type=str, help="Path to a PCAP file for offline analysis")

    args = parser.parse_args()

    global INTERNAL_IP_RANGE
    INTERNAL_IP_RANGE = args.ip_range

    root = tk.Tk()
    db = Database()

    # initialize the analyzer
    analyzer = Analyzer(db, INTERNAL_IP_RANGE, VOLUME_THRESHOLD)

    app = GUI(root, db)
    app.set_analyzer(analyzer)

    # initialize the sniffer
    sniffer = Sniffer(analyzer)

    # start the sniffer
    if args.pcap:
        # If a PCAP file is provided:
        sniffer_thread = Thread(target=sniffer.analyze_pcap, args=(args.pcap,))
        sniffer_thread.start()
    elif args.ip_range:
        # use live sniffing based on IP range:
        sniffer_thread = Thread(target=sniffer.sniff)
        sniffer_thread.start()

    root.mainloop()

if __name__ == "__main__":
    main()