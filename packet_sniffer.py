import tkinter as tk
from tkinter import ttk
import socket
import struct

# Function to parse and display packet data
def update_packet_list(packet):
    eth_header = struct.unpack('!6s6sH', packet[:14])
    src_mac = ':'.join('%02x' % b for b in eth_header[1])
    dst_mac = ':'.join('%02x' % b for b in eth_header[0])
    proto = eth_header[2]
    
    tree.insert("", tk.END, values=(src_mac, dst_mac, hex(proto)))

# Function to start sniffing
def start_sniffing():
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    raw_socket.bind(("wlp45s0", 0))  # Replace with your interface
    while True:
        packet, _ = raw_socket.recvfrom(65535)
        print(packet)  # Debugging output
        update_packet_list(packet)

# GUI Setup
root = tk.Tk()
root.title("Python Packet Sniffer")

tree = ttk.Treeview(root, columns=("Source MAC", "Destination MAC", "Protocol"), show="headings")

for col in ("Source MAC", "Destination MAC", "Protocol"):
    tree.heading(col, text=col)
    tree.column(col, width=200)

tree.pack(expand=True, fill=tk.BOTH)

start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack()

root.mainloop()
