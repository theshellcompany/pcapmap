import argparse
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader


def main():
    ip_network = nx.DiGraph()
    file_name = args.pcap
    file_path = Path.cwd() / file_name

    if Path.is_file(file_path):
        # read the pcap
        for (
            pkt_data,
            pkt_metadata,
        ) in RawPcapReader(args.pcap):
            ether_pkt = Ether(pkt_data)
            if "type" not in ether_pkt.fields:
                # LLC frames will have 'len' instead of 'type', we disregard those
                continue

            if ether_pkt.type != 0x0800:
                # disregard non-IPv4 packets
                continue

            ip_pkt = ether_pkt[IP]
            if ip_pkt.proto != 6:
                # ignore non-TCP packet
                continue

            ip_network.add_edge(ip_pkt.src, ip_pkt.dst)

    nx.draw(ip_network, with_labels=True)
    plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PCAP mapper")
    parser.add_argument("pcap", metavar="<pcap file name>", help="pcap file to parse")
    args = parser.parse_args()
    main()
