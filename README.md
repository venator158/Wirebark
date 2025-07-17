
#  Wirebark  
**Python-Based Packet Sniffer with ARP Spoofing and GUI**

Wirebark is a lightweight network analysis tool built with Python. It features ARP spoofing capabilities and a user-friendly GUI for real-time packet sniffing and analysis. Built using **Scapy** for low-level packet operations and **Tkinter** for the interface, Wirebark is ideal for learning about network traffic, ARP spoofing, and packet inspection.

---

##  Features

-  **Targeted or Broadcast ARP Spoofing**  
  Intercept traffic from a specific IP or the entire local network.

-  **Live Packet Sniffing**  
  Capture and inspect packets in real time.

-  **Wireshark-style Filtering**  
  Apply filters to focus on relevant packets.

-  **GUI Interface**  
  Simple and intuitive interface built with Tkinter.

-  **Traffic Analysis**  
  View packet-level details including source, destination, protocols, and more.

---

##  Installation

### Prerequisites

- Python 3.x
- [Scapy](https://pypi.org/project/scapy/)
- [Tkinter](https://docs.python.org/3/library/tkinter.html)

Install dependencies via pip:

```bash
git clone sudo python3 wirebark.py
cd Wirebark
pip install scapy argparse netifaces
```

> Tkinter comes pre-installed with most Python distributions. If not, install via your OS package manager.

---

##  Usage

Run Wirebark with root privileges (required for packet sniffing and ARP spoofing):

```bash
sudo python3 wirebark.py
```

### How to Use

1. Select a network interface.
2. (Optional) Enter a target IP for ARP spoofing, or leave blank to spoof the entire network.
3. Start sniffing and view live traffic in the GUI.
4. Use filter input to isolate specific packet types (e.g., `TCP`, `UDP`, `ARP`).
5. For easy use and access from terminal, pack using pyinstaller and move the executable to /usr/local/bin
```bash
pip install pyinstaller
```
```bash
pyinstaller --onefile --distpath /tmp/dist --workpath /tmp/build --name wirebark wirebark.py
```
```bash
sudo mv /tmp/dist/wirebark /usr/local/bin/
```
```bash
sudo chmod +x /usr/local/bin/wirebark
```
to run the application in GUI mode use
```bash
sudo wirebark
```
---

##  Legal Notice

This tool is intended for educational and authorized security testing purposes **only**. Unauthorized use on networks you do not own or have explicit permission to test is illegal and unethical.

---

##  Project Structure

```
.
├── wirebark.py      # Main script with GUI, ARP spoofing, and sniffer
```

---
