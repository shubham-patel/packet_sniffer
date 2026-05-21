# Packet Sniffer

A Python tool that sniffs HTTP traffic on a network interface and extracts URLs and potential credentials from unencrypted HTTP requests. Designed to be combined with ARP Spoofing to monitor another device's traffic.

> **Disclaimer:** For educational purposes and authorized testing only. Only use on networks and devices you own or have explicit permission to monitor. Packet sniffing on unauthorized networks is illegal. The author is not responsible for any misuse.

---

## How it works

1. Listens on a network interface for HTTP traffic using Scapy
2. Logs every HTTP request URL
3. Inspects the raw payload of each packet for credential keywords (`username`, `password`, `login`, etc.)
4. Prints any matching data to the console

## Requirements

```bash
pip install -r requirements.txt
```

> **Note:** Linux only. Requires root privileges.

## Usage

Edit the interface at the bottom of `packet_sniffer.py` if needed (default: `eth0`):

```python
sniff("eth0")
```

Then run:

```bash
sudo python3 packet_sniffer.py
```

**Combine with [arp_spoofer](https://github.com/shubham-patel/arp_spoofer)** in a separate terminal to intercept another device's HTTP traffic.

---

## Part of [H-Tools](https://github.com/shubham-patel/H-Tools)

Built during B.Tech studies. H-Tools bundles this and other networking/security utilities in a single CLI menu.
