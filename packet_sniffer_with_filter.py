import tkinter as tk
from tkinter import ttk
import socket
import struct
import threading
import re

# ------------------
# Mapping dictionaries for display purposes
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
# Custom Filter Function
# ------------------
def packet_matches_filter(packet_info, filter_expr):
    """
    Evaluates a filter expression against the packet_info dictionary.
    Supports:
      - ip.addr==<ip>  (checks if src_ip or dst_ip equals the given IP)
      - protocol keywords (tcp, udp, icmp, arp, ip)
      - regex conditions starting with 're:'
      - Combining conditions with && (and) and || (or)
    """
    if not filter_expr.strip():
        return True  # no filter set

    # Split on '||' for OR clauses
    or_clauses = filter_expr.split("||")
    for clause in or_clauses:
        clause = clause.strip()
        if not clause:
            continue
        # Each clause is a series of conditions combined with &&
        and_conditions = clause.split("&&")
        clause_match = True
        for cond in and_conditions:
            cond = cond.strip()
            if not cond:
                continue

            # ip.addr condition: support both '=' and '=='
            if cond.startswith("ip.addr"):
                m = re.match(r"ip\.addr\s*={1,2}\s*(\S+)", cond, re.IGNORECASE)
                if m:
                    ip_val = m.group(1)
                    # Check if either src_ip or dst_ip equals ip_val
                    if packet_info.get("src_ip", "") != ip_val and packet_info.get("dst_ip", "") != ip_val:
                        clause_match = False
                        break
                else:
                    clause_match = False
                    break
            # Otherwise, check for protocol keywords
            elif cond.lower() in ["tcp", "udp", "icmp", "arp", "ip"]:
                if packet_info.get("protocol", "").lower() != cond.lower():
                    clause_match = False
                    break
            # If condition starts with 're:', treat remainder as regex applied to full details
            elif cond.startswith("re:"):
                pattern = cond[3:].strip()
                if not re.search(pattern, packet_info.get("details", ""), re.IGNORECASE):
                    clause_match = False
                    break
            else:
                # Fallback: try a simple substring search (case insensitive) in the details string
                if cond.lower() not in packet_info.get("details", "").lower():
                    clause_match = False
                    break
        if clause_match:
            return True  # At least one OR clause matched
    return False

# ------------------
# GUI Functions
# ------------------
def toggle_pause():
    global paused
    paused = not paused
    if paused:
        pause_button.config(text="Resume")
    else:
        pause_button.config(text="Pause")

def scroll_to_end():
    log_text.see(tk.END)

# ------------------
# Packet Processing Function
# ------------------
def update_packet_list(packet):
    # If paused, do not update the UI
    if paused:
        return

    # Make sure we have enough bytes for Ethernet header
    if len(packet) < 14:
        return

    # Parse Ethernet header (first 14 bytes)
    eth_header = struct.unpack('!6s6sH', packet[:14])
    dst_mac = ':'.join('%02x' % b for b in eth_header[0])
    src_mac = ':'.join('%02x' % b for b in eth_header[1])
    eth_proto = eth_header[2]
    
    # Default protocol string from Ethernet mapping (or hex)
    proto_str = ethertype_map.get(eth_proto, hex(eth_proto))
    ip_protocol = None
    details_str = (f"Ethernet Frame:\n"
                   f"  Source MAC: {src_mac}\n"
                   f"  Destination MAC: {dst_mac}\n"
                   f"  Protocol: {proto_str}\n")
    
    # Initialize packet_info dictionary with common fields
    packet_info = {
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "protocol": proto_str,
        "details": details_str
    }
    
    # If it's an IP packet, try to parse IP header (need at least 34 bytes)
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
        packet_info.update({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto_str,
            "details": details_str
        })
    # If it's an ARP packet, parse ARP header (need at least 42 bytes)
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
        packet_info.update({
            "src_ip": sender_ip_str,
            "dst_ip": target_ip_str,
            "protocol": proto_str,
            "details": details_str
        })

    details_str += "-" * 40 + "\n"
    packet_info["details"] = details_str

    # ------------------
    # Filtering: custom filter takes precedence if provided.
    # ------------------
    custom_filter_expr = custom_filter_entry.get().strip()
    show = False
    if custom_filter_expr:
        show = packet_matches_filter(packet_info, custom_filter_expr)
    else:
        # Fallback to the dropdown filter (simple protocol filtering)
        current_filter = dropdown_filter.get()
        if current_filter == "All":
            show = True
        elif current_filter in ethertype_map.values():
            show = (packet_info.get("protocol", "") == current_filter)
        elif current_filter in ip_protocol_map.values():
            show = (packet_info.get("protocol", "").upper() == current_filter.upper())
        else:
            show = True

    # Update the GUI (safely from the main thread)
    def update_gui():
        if show:
            tree.insert("", tk.END, values=(src_mac, dst_mac, packet_info.get("protocol", "")))
            log_text.insert(tk.END, details_str)
            # Auto-scroll only if already at bottom
            if log_text.yview()[1] == 1.0:
                log_text.see(tk.END)
    root.after(0, update_gui)

# ------------------
# Packet Sniffing Function
# ------------------
def sniff_packets():
    # Create a raw socket (requires elevated privileges)
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    # Optionally, bind to a specific interface if needed:
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

# Filter selection frame (dropdown and custom filter)
filter_frame = tk.Frame(root)
filter_frame.pack(fill=tk.X, padx=5, pady=5)
tk.Label(filter_frame, text="Dropdown Filter:").pack(side=tk.LEFT, padx=5)
dropdown_filter = tk.StringVar(master=root)
dropdown_filter.set("All")
filter_options = ["All", "IP", "ARP", "TCP", "UDP", "ICMP"]
filter_menu = tk.OptionMenu(filter_frame, dropdown_filter, *filter_options)
filter_menu.pack(side=tk.LEFT, padx=5)

tk.Label(filter_frame, text="Custom Filter:").pack(side=tk.LEFT, padx=5)
custom_filter_entry = tk.Entry(filter_frame, width=40)
custom_filter_entry.pack(side=tk.LEFT, padx=5)
# (Leave empty to use dropdown filter)

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
