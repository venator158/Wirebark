import tkinter as tk
from tkinter import ttk
from scapy.all import (
    sniff, Ether, IP, IPv6, ARP, DNS, UDP, TCP
)

# Mapping for IP protocol numbers to names
ip_protocol_map = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP"
}

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        # We'll store both the parsed info and the raw scapy packet
        self.captured_packets = []
        # Current filter text
        self.current_filter = ""
        self.sniffing = False

        self.create_widgets()
    
    def create_widgets(self):
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_button = tk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.filter_entry = tk.Entry(control_frame)
        self.filter_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        self.filter_button = tk.Button(control_frame, text="Apply Filter", command=self.apply_filter)
        self.filter_button.pack(side=tk.LEFT, padx=5)
        
        # New "Go to Last" button
        self.go_last_button = tk.Button(control_frame, text="Go to Last", command=self.go_to_last)
        self.go_last_button.pack(side=tk.LEFT, padx=5)
        
        # Main Treeview: Source IP, Destination IP, Protocol, Summary
        self.tree = ttk.Treeview(self.root, columns=("Src IP", "Dst IP", "Protocol", "Summary"), show="headings")
        self.tree.heading("Src IP", text="Source IP")
        self.tree.heading("Dst IP", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Summary", text="Packet Summary")
        
        self.tree.column("Src IP", width=140)
        self.tree.column("Dst IP", width=140)
        self.tree.column("Protocol", width=120)
        self.tree.column("Summary", width=400)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Double-click a row to see packet details
        self.tree.bind("<Double-1>", self.on_double_click)

    def go_to_last(self):
        """Scroll the treeview so that the last item is visible."""
        children = self.tree.get_children()
        if children:
            last_item = children[-1]
            self.tree.see(last_item)

    def on_double_click(self, event):
        """Open a new window showing detailed info about the selected packet."""
        selected = self.tree.selection()
        if not selected:
            return
        
        item_id = selected[0]
        index_str = self.tree.item(item_id, 'text')
        if not index_str.isdigit():
            return
        
        index = int(index_str)
        info, raw_packet = self.captured_packets[index]

        detail_win = tk.Toplevel(self.root)
        detail_win.title("Packet Details")

        tk.Label(detail_win, text=f"Source MAC: {info.get('src_mac','N/A')}").pack(anchor="w", padx=5, pady=2)
        tk.Label(detail_win, text=f"Destination MAC: {info.get('dst_mac','N/A')}").pack(anchor="w", padx=5, pady=2)
        tk.Label(detail_win, text=f"Source IP: {info.get('src_ip','N/A')}").pack(anchor="w", padx=5, pady=2)
        tk.Label(detail_win, text=f"Destination IP: {info.get('dst_ip','N/A')}").pack(anchor="w", padx=5, pady=2)
        tk.Label(detail_win, text=f"Protocol: {info.get('protocol','Unknown')}").pack(anchor="w", padx=5, pady=2)

        text_frame = tk.Frame(detail_win)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        detail_text = tk.Text(text_frame, wrap="none", yscrollcommand=scrollbar.set)
        detail_text.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=detail_text.yview)

        scapy_details = raw_packet.show(dump=True)
        detail_text.insert(tk.END, scapy_details)
        detail_text.config(state=tk.DISABLED)

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        # Clear existing data
        self.captured_packets.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.sniff_packets()
    
    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
    
    def sniff_packets(self):
        if self.sniffing:
            sniff(prn=self.handle_new_packet, store=False, count=10)
            self.root.after(1000, self.sniff_packets)

    def handle_new_packet(self, packet):
        """Called each time a packet is captured. Store and display if it matches the current filter."""
        info = self.get_packet_info(packet)
        self.captured_packets.append((info, packet))

        if self.packet_matches_filter(info, self.current_filter):
            index = len(self.captured_packets) - 1
            self.tree.insert(
                "", tk.END,
                text=str(index),
                values=(info['src_ip'], info['dst_ip'], info['protocol'], info['summary'])
            )

    def apply_filter(self):
        """User clicked 'Apply Filter'. Re-display only matching packets."""
        self.current_filter = self.filter_entry.get().strip().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for idx, (info, raw_pkt) in enumerate(self.captured_packets):
            if self.packet_matches_filter(info, self.current_filter):
                self.tree.insert(
                    "", tk.END,
                    text=str(idx),
                    values=(info['src_ip'], info['dst_ip'], info['protocol'], info['summary'])
                )

    def packet_matches_filter(self, info, filter_text):
        """
        If there's exactly one token, only check the Protocol field.
        If multiple tokens, check if ALL tokens appear in the combined fields.
        """
        if not filter_text:
            return True

        tokens = filter_text.split()
        
        if len(tokens) == 1:
            return tokens[0] in info.get('protocol', '').lower()
        
        fields = [
            info.get('src_mac', '').lower(),
            info.get('dst_mac', '').lower(),
            info.get('src_ip', '').lower(),
            info.get('dst_ip', '').lower(),
            info.get('protocol', '').lower(),
            info.get('summary', '').lower()
        ]
        combined = " ".join(fields)
        return all(token in combined for token in tokens)

    def get_packet_info(self, packet):
        """Identify IP addresses, MAC addresses, protocol, etc."""
        info = {}
        if Ether in packet:
            info['src_mac'] = packet[Ether].src
            info['dst_mac'] = packet[Ether].dst
        else:
            info['src_mac'] = "N/A"
            info['dst_mac'] = "N/A"
        
        if ARP in packet:
            info['protocol'] = "ARP"
            info['src_ip'] = packet[ARP].psrc
            info['dst_ip'] = packet[ARP].pdst
        elif IPv6 in packet:
            info['protocol'] = "IPv6"
            info['src_ip'] = packet[IPv6].src
            info['dst_ip'] = packet[IPv6].dst
        elif IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            if DNS in packet:
                info['protocol'] = "DNS"
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                if sport == 5353 or dport == 5353:
                    info['protocol'] = "mDNS"
                elif sport == 1900 or dport == 1900:
                    info['protocol'] = "SSDP"
                elif sport == 137 or dport == 137:
                    info['protocol'] = "NBNS"
                elif sport == 5355 or dport == 5355:
                    info['protocol'] = "LLMNR"
                else:
                    ip_proto = packet[IP].proto
                    info['protocol'] = ip_protocol_map.get(ip_proto, f"UDP({ip_proto})")
            elif TCP in packet:
                ip_proto = packet[IP].proto
                info['protocol'] = ip_protocol_map.get(ip_proto, f"TCP({ip_proto})")
            else:
                ip_proto = packet[IP].proto
                info['protocol'] = ip_protocol_map.get(ip_proto, f"IP({ip_proto})")
        else:
            info['protocol'] = "Unknown"
            info['src_ip'] = "N/A"
            info['dst_ip'] = "N/A"
        
        info['summary'] = packet.summary()
        return info

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
