import sys
from datetime import datetime
from scapy.all import *
import socket

dnsReq_filter = 'udp dst port 53'

def open_pcap(file):
    try:
        packets = rdpcap(file)
        return packets
    except:
        return False

def sniff_pcap(file, filter=None):
    try:
        if filter is None:
            packets = sniff(offline=file)
        else:
            packets = sniff(offline=file, filter=filter)
        return packets
    except Exception as e:
        print('[!] {0}'.format(str(e)))
        return False


if __name__ == '__main__':

    pacotes = sniff_pcap(file=sys.argv[1], filter=dnsReq_filter)
    if not pacotes:
        print('[!] Error while reading the pcap file')
        exit()
    print(pacotes)

    domain_list = []
    for p in pacotes:
        entry = p.summary().split('"')[1]
        if entry not in domain_list:
            domain_list.append(entry)

    for domain in domain_list:
        newDomain = str(domain)[2:-2]
        print(newDomain)
        try:
            print(socket.gethostbyname(newDomain))
        except Exception as e:
            print(e)