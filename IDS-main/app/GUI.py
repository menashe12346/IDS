"""
This module is responsible for the user interface.
"""

import tkinter as tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt


class GUI:
    def __init__(self, root, db):
        self.root = root
        self.root.title("Intrusion Detection System ")
        self.db = db
        self.analyzer = None
        self.create_ui()

    def create_ui(self):
        self.label = tk.Label(self.root, text="Intrusion Detection System", font=("Arial", 16))
        self.label.pack(pady=10)

        self.traffic_frame = tk.Frame(self.root)
        self.traffic_frame.pack(side=tk.LEFT, padx=20)

        self.alert_frame = tk.Frame(self.root)
        self.alert_frame.pack(side=tk.RIGHT, padx=20)

        self.fig, (self.ax_protocols, self.ax_traffic) = plt.subplots(2, 1, figsize=(6, 8))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.traffic_frame)
        self.canvas.get_tk_widget().pack()

        self.alert_label = tk.Label(self.alert_frame, text="Alerts", font=("Arial", 14))
        self.alert_label.pack(pady=5)

        self.alert_text_frame = tk.Frame(self.alert_frame)
        self.alert_text_frame.pack(pady=10, padx=10)

        self.alert_text = tk.Text(self.alert_text_frame, width=60, height=25, font=("Arial", 10), wrap="word", spacing3=8)
        self.alert_text.pack(side=tk.LEFT)

        self.alert_scrollbar = tk.Scrollbar(self.alert_text_frame, command=self.alert_text.yview)
        self.alert_text.config(yscrollcommand=self.alert_scrollbar.set)
        self.alert_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def update_ui(self):
        """ Update the UI with data from the database (updated by the analyzer) """
        protocol_data = self.db.get_protocol_distribution()
        byte_history = self.db.get_byte_history()

        # Define colors for the protocols (expand if necessary)
        colors = ['#ff7f0e', '#1f77b4', '#2ca02c', '#d62728']  # TCP, UDP, ICMP, Other

        # Update protocol distribution (bar chart)
        self.ax_protocols.clear()
        self.ax_protocols.bar(protocol_data.keys(), protocol_data.values(), color=colors)
        self.ax_protocols.set_title("Protocol Distribution", fontsize=14)
        self.ax_protocols.set_ylabel("Packet Count", fontsize=12)
        self.ax_protocols.tick_params(axis='x', labelsize=10)
        self.ax_protocols.tick_params(axis='y', labelsize=10)

        # Update total traffic over time (line chart)
        self.ax_traffic.clear()
        self.ax_traffic.plot(byte_history, label="Total Bytes Over Time", color='#1f77b4')
        self.ax_traffic.set_title("Total Traffic (Bytes)", fontsize=14)
        self.ax_traffic.set_xlabel("Time", fontsize=12)
        self.ax_traffic.set_ylabel("Bytes", fontsize=12)
        self.ax_traffic.tick_params(axis='x', labelsize=10)
        self.ax_traffic.tick_params(axis='y', labelsize=10)

        # Adjust layout to prevent overlapping
        self.fig.tight_layout()

        # Redraw the canvas
        self.canvas.draw()

    def update_alerts(self):
        """ Update the alert list with new alerts from the database """
        alerts = self.db.get_alerts()

        # Clear the current content of the Text widget
        self.alert_text.delete("1.0", tk.END)

        # Insert each alert with a clickable tag
        for idx, alert in enumerate(alerts):
            # Create a unique tag for each alert
            tag = f"alert_{idx}"

            # Insert the alert and tag it
            self.alert_text.insert(tk.END, f"{alert}\n\n", tag)

            # Bind a click event to the tag
            self.alert_text.tag_bind(tag, "<Button-1>", lambda event, a=alert: self.show_alert_details(a))

    def show_alert_details(self, alert):
        """ Open a new window with detailed information about the selected alert """
        # Create a new window for alert details
        detail_window = tk.Toplevel(self.root)
        detail_window.title("Alert Details")

        # Explanation for the alert
        explanation = self.get_alert_explanation(alert)

        # Add a label to the new window with the detailed explanation
        label = tk.Label(detail_window, text=explanation, wraplength=400, font=("Arial", 12))
        label.pack(padx=20, pady=20)

    def get_alert_explanation(self, alert):
        """ Return detailed explanation based on the alert content """
        if "Checksum verification failed" in alert:
            return ("This alert indicates that the checksum of the packet is invalid, meaning the packet "
                    "might be corrupted or tampered with during transmission. This can cause memory "
                    "leak issues if the system fails to handle such corrupted packets properly.")
        elif "DNS request for suspicious domain" in alert:
            return ("This alert indicates that the system detected a DNS request to a suspicious domain. "
                    "It could be related to a phishing attempt or malware trying to exfiltrate data.")
        elif "Source port out of range" in alert:
            return ("This alert indicates that the packet's source port is outside the allowed range. "
                    "This could mean the packet is either malformed or part of suspicious activity.")
        elif "Destination port out of range" in alert:
            return ("This alert indicates that the destination port is outside the expected range. "
                    "This could indicate that the packet is malformed or an attempt to communicate on a "
                    "non-standard port.")
        elif "LLMNRQuery" in alert:
            return ("LLMNR queries are used for local network name resolution. These alerts can be "
                    "potentially exploited for attacks, and if the system mishandles these queries, "
                    "it may lead to a memory leak.")
        else:
            return ("This is a generic alert. It could indicate suspicious or malformed network activity. "
                    "Memory leaks can occur if such packets are not handled correctly.")

    def set_analyzer(self, analyzer):
        """ Link the Analyzer to the UI for updating the display """
        self.analyzer = analyzer
        self.schedule_update()

    def schedule_update(self):
        """ Schedule periodic UI updates based on data from the Analyzer """
        if self.analyzer:
            self.update_ui()
            self.update_alerts()

        # Re-schedule the update every 1 second
        self.root.after(1000, self.schedule_update)
