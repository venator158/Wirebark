import tkinter as tk
from tkinter import ttk
import socket
import struct
import threading

# ------------------
# Mapping dictionaries
# ------------------
ethertype_map = {
    0x0800: 'IP',
    0x0806: 'ARP',
    0x86DD: 'IPv6'
}

ip_protocol_map = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}

# ------------------
# Global Control Variables
# ------------------
paused = False

# ------------------
# GUI Functions
# ------------------
def toggle_pause():
    """Toggle pause/resume of UI updates."""
    global paused
    paused = not paused
    if paused:
        pause_button.config(text="Resume")
    else:
        pause_button.config(text="Pause")

def scroll_to_end():
    """Scroll the log text widget to the bottom."""
    log_text.see(tk.END)

# ------------------
# Packet Processing Function
# ------------------
def update_packet_list(packet):
    # If paused, skip updating the UI
    if paused:
        return

    # Ensure packet has at least an Ethernet header
    if len(packet) < 14:
        return

    # Parse Ethernet header (first 14 bytes)
    eth_header = struct.unpack('!6s6sH', packet[:14])
    dst_mac = ':'.join('%02x' % b for b in eth_header[0])
    src_mac = ':'.join('%02x' % b for b in eth_header[1])
    eth_proto = eth_header[2]
    
    # Map Ethernet type to a protocol name (or use hex if unknown)
    proto_str = ethertype_map.get(eth_proto, hex(eth_proto))
    ip_protocol = None
    details_str = (f"Ethernet Frame:\n"
                   f"  Source MAC: {src_mac}\n"
                   f"  Destination MAC: {dst_mac}\n"
                   f"  Protocol: {proto_str}\n")
    
    # If it's an IP packet, parse the IP header
    if eth_proto == 0x0800 and len(packet) >= 34:
        ip_header = packet[14:34]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        ip_protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        # Map IP protocol number to a protocol name
        proto_str = ip_protocol_map.get(ip_protocol, "IP")
        details_str += (f"IP Packet:\n"
                        f"  Version: {version}\n"
                        f"  Header Length: {ihl} ({iph_length} bytes)\n"
                        f"  TTL: {ttl}\n"
                        f"  IP Protocol: {ip_protocol} ({proto_str})\n"
                        f"  Source IP: {src_ip}\n"
                        f"  Destination IP: {dst_ip}\n")
    # If it's an ARP packet, parse the ARP header
    elif eth_proto == 0x0806 and len(packet) >= 42:
        arp_header = packet[14:42]
        arp = struct.unpack('!HHBBH6s4s6s4s', arp_header)
        htype, ptype, hlen, plen, opcode, sender_mac, sender_ip, target_mac, target_ip = arp
        sender_mac_str = ':'.join('%02x' % b for b in sender_mac)
        target_mac_str = ':'.join('%02x' % b for b in target_mac)
        sender_ip_str = socket.inet_ntoa(sender_ip)
        target_ip_str = socket.inet_ntoa(target_ip)
        proto_str = "ARP"
        details_str += (f"ARP Packet:\n"
                        f"  Hardware Type: {htype}\n"
                        f"  Protocol Type: {hex(ptype)}\n"
                        f"  Hardware Size: {hlen}\n"
                        f"  Protocol Size: {plen}\n"
                        f"  Opcode: {opcode}\n"
                        f"  Sender MAC: {sender_mac_str}\n"
                        f"  Sender IP: {sender_ip_str}\n"
                        f"  Target MAC: {target_mac_str}\n"
                        f"  Target IP: {target_ip_str}\n")
    
    details_str += "-" * 40 + "\n"
    
    # ------------------
    # Filtering: determine whether to show this packet
    # ------------------
    current_filter = filter_var.get()
    show = False
    if current_filter == "All":
        show = True
    # Filter based on Ethernet-level protocols (ARP, IPv6, etc.)
    elif current_filter in ethertype_map.values():
        show = (proto_str == current_filter)
    # Filter based on IP protocols (TCP, UDP, ICMP)
    elif current_filter in ip_protocol_map.values():
        show = (ip_protocol is not None and ip_protocol_map.get(ip_protocol, "") == current_filter)
    else:
        show = True

    # Update the GUI in the main thread
    def update_gui():
        if show:
            tree.insert("", tk.END, values=(src_mac, dst_mac, proto_str))
            log_text.insert(tk.END, details_str)
            # Only auto-scroll if scrollbar is at the bottom (i.e. yview returns (a,1.0))
            if log_text.yview()[1] == 1.0:
                log_text.see(tk.END)
    root.after(0, update_gui)

# ------------------
# Packet Sniffing Function
# ------------------
def sniff_packets():
    # Create a raw socket (requires elevated privileges)
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    # Optionally bind to a specific interface (uncomment and set interface name if needed)
    # raw_socket.bind(("eth0", 0))
    while True:
        packet, _ = raw_socket.recvfrom(65535)
        update_packet_list(packet)

def start_sniffing():
    t = threading.Thread(target=sniff_packets, daemon=True)
    t.start()

# ------------------
# GUI Setup
# ------------------
root = tk.Tk()
root.title("Python Packet Sniffer")

# Filter selection frame
filter_frame = tk.Frame(root)
filter_frame.pack(fill=tk.X, padx=5, pady=5)
tk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
# Filter options: include both Ethernet-level and IP-level protocols
filter_options = ["All", "IP", "ARP", "TCP", "UDP", "ICMP"]
filter_var = tk.StringVar(master=root)
filter_var.set("All")
filter_menu = tk.OptionMenu(filter_frame, filter_var, *filter_options)
filter_menu.pack(side=tk.LEFT)

# Control buttons: Pause/Resume and Go to Last
control_frame = tk.Frame(root)
control_frame.pack(fill=tk.X, padx=5, pady=5)
pause_button = tk.Button(control_frame, text="Pause", command=toggle_pause)
pause_button.pack(side=tk.LEFT, padx=5)
go_to_last_button = tk.Button(control_frame, text="↓ Go to Last", command=scroll_to_end)
go_to_last_button.pack(side=tk.LEFT, padx=5)

# Treeview for packet summary
tree = ttk.Treeview(root, columns=("Source MAC", "Destination MAC", "Protocol"), show="headings")
for col in ("Source MAC", "Destination MAC", "Protocol"):
    tree.heading(col, text=col)
    tree.column(col, width=200)
tree.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

# Text widget for detailed packet info with vertical scrollbar
log_frame = tk.Frame(root)
log_frame.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
scrollbar = tk.Scrollbar(log_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
log_text = tk.Text(log_frame, height=15, yscrollcommand=scrollbar.set)
log_text.pack(expand=True, fill=tk.BOTH)
scrollbar.config(command=log_text.yview)

# Button to start sniffing
start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack(pady=5)

root.mainloop()
