"""
File: packet_sniffer.py
Author: Brian Chiang
Created on: 2024-11-23

Description:
San Jose State University
CMPE 148 - Python tool to sniff and analyze packets
Extra Credit Project from Professor Mark Ammar rayes, Ph. D.
Project Title:
"Network Packet Sniffer in Python"

Objective:
Create a Python program that captures and analyzes packets on your local network, providing hands-on experience with networking concepts such as protocols, headers, and data encapsulation.

Key Features:
 - Packet Capture: Use a library like scapy or socket to capture live network packets.
 - Protocol Parsing: Identify and display the types of protocols (e.g., TCP, UDP, ICMP) found in captured packets.
 - Header Analysis: Extract and display key header fields, such as source and destination IP addresses, port numbers, and flags.
 - Filtering: Implement filtering to show specific types of packets, such as HTTP or DNS traffic.
 - Logging: Save captured packets or their key details to a file for further analysis.

Dependencies:
  - Python3
        Installation depends on system ('sudo apt update && sudo apt install python3' for ubuntu)
  - Scapy
        Install using pip install scapy within a virtual environment or pipx for global (in newer python versions)
  - pyshark
        Python wrapper for tshark, can be installed using pip install pyshark
  - Matplotlib
        Used for data visualization

Setup:
    1. Once all independencies are installed, activate the virtual environment to use them if necessary.
    2. If you intend to collect packets instead of simply analyzing them, then you need root permissions:
        "sudo {path to python interpreter} packet_sniffer.py"
       Otherwise, you can simply just call 'python packet_sniffer.py' to analyze an existing .pcap file.
        
"""
import pyshark
import sys
from scapy.all import *
import matplotlib.pyplot as plt
from datetime import datetime

latency_threshold = 0.75 #ms
def capture_packets_with_scapy(interface, count):
    """Capture packets using Scapy."""
    try:
        return sniff(iface=interface, count=count)
    except Exception as e:
        print(f"Error capturing packets with Scapy: {e}")
        return []


def capture_packets_with_tshark(interface, count):
    """Capture packets using Pyshark (Tshark)."""
    try:
        return pyshark.LiveCapture(interface=interface).sniff(timeout=count)
    except Exception as e:
        print(f"Error capturing packets with Tshark: {e}")
        return []


def analyze_packet(packet):
    """Analyze individual packet."""
    try:
        summary = packet.summary() if hasattr(packet, "summary") else "N/A"
        return summary
    except Exception as e:
        return f"Error analyzing packet: {e}"


def filter_packets_by_protocol(packets, protocol):
    """Filter packets by protocol (e.g., TCP, DNS)."""
    return [pkt for pkt in packets if protocol.upper() in pkt.summary()]


def analyze_latency(packets):
    """Analyze packet latency."""
    timestamps = [float(pkt.time) for pkt in packets if hasattr(pkt, 'time')]
    latencies = [j - i for i, j in zip(timestamps[:-1], timestamps[1:])]
    print("Packet Latencies (seconds):", latencies)
    high_latency = [(i, latency) for i, latency in enumerate(latencies) if latency > latency_threshold]
    for idx, latency in high_latency:
        print(f"High latency detected between packets {idx} and {idx + 1}: {latency:.3f}s") #print float to 3 decimal point precision


def detect_retransmissions(packets):
    """Detect TCP retransmissions."""
    for pkt in packets:
        if 'TCP' in pkt.summary() and 'retransmission' in pkt.summary().lower():
            print(f"Retransmission detected: {pkt.summary()}")
        else:
            print(f"No Retransmission Detected")


def track_connections(packets):
    """Track and count active connections."""
    connections = {}
    for pkt in packets:
        if 'IP' in pkt and 'TCP' in pkt:
            conn_tuple = (pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport)
            connections[conn_tuple] = connections.get(conn_tuple, 0) + 1
    for conn, count in connections.items():
        print(f"Connection {conn}: {count} packets")


def visualize_protocol_usage(packets):
    """Visualize protocol usage with fallback for unrecognized layers."""
    protocol_counts = {}
    
    for pkt in packets:
        # Attempt to get the highest_layer
        protocol = getattr(pkt, 'highest_layer', None)
        
        if not protocol or protocol == "Unknown":
            # Fallback: Manually deduce the protocol
            try:
                last_layer=pkt.getlayer(len(pkt.layers()))
                if last_layer:
                    protocol = last_layer.name if hasattr(last_layer, 'name') else "Unknown"  # Use the last layer as the protocol
                else:
                    protocol="Unknown"
            except AttributeError:
                protocol = "Attribute Error in Visualization"
            except Exception as e:
                print(f"Error extracting protocol: {e}")
        
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

    # Display the result
    print(f"Protocol counts: {protocol_counts}")

    # Plotting
    plt.bar(protocol_counts.keys(), protocol_counts.values())
    plt.title("Protocol Usage")
    plt.ylabel("Count")
    plt.xlabel("Protocol")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('protocol_usage.jpg')
    print("Figure saved to protocol_usage.jpg")

def log_packets(packets, log_file):
    """Log packet details to a file."""
    with open(log_file, "w") as file:
        for pkt in packets:
            file.write(analyze_packet(pkt) + "\n")
    print(f"Packets logged to {log_file}")


def main():
    print("Network Packet Analyzer")
    print("1. Capture packets with Scapy")
    print("2. Capture packets with Tshark")
    print("3. Analyze a PCAP file")
    print("4. Exit Program")
    choice = input("Choose an option: ")

    packets = []
    if choice == "1":
        interface = input("Enter interface (e.g., eth0): ")
        count = int(input("Enter number of packets to capture: "))
        packets = capture_packets_with_scapy(interface, count)
    elif choice == "2":
        interface = input("Enter interface (e.g., eth0): ")
        count = int(input("Enter timeout in seconds for capture: "))
        packets = capture_packets_with_tshark(interface, count)
    elif choice == "3":
        pcap_file = input("Enter the path to the PCAP file: ")
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
    elif choice == "4":
        print("Terminating Program...")
        sys.exit(0)
    else:
        print("Invalid choice")
        return

    if not packets:
        print("No packets captured or loaded.")
        return

    while True:
        print("\nChoose Troubleshooting Analysis:")
        print("1. Latency Analysis")
        print("2. Protocol Error Detection (TCP retransmissions)")
        print("3. Connection Tracking")
        print("4. Protocol Usage Visualization")
        print("5. Filter Packets by Protocol")
        print("6. Log Packets to File")
        print("7. Exit Program")

        analysis_choice = input("Choose an analysis option: ")

        if analysis_choice == "1":
            analyze_latency(packets)
        elif analysis_choice == "2":
            detect_retransmissions(packets)
        elif analysis_choice == "3":
            track_connections(packets)
        elif analysis_choice == "4":
            visualize_protocol_usage(packets)
        elif analysis_choice == "5":
            protocol = input("Enter protocol to filter (e.g., HTTP, DNS): ")
            filtered_packets = filter_packets_by_protocol(packets, protocol)
            for pkt in filtered_packets:
                print(analyze_packet(pkt))
        elif analysis_choice == "6":
            log_file = input("Enter log file name (e.g., packets.log): ")
            log_packets(packets, log_file)
        elif analysis_choice == "7":
            print("Terminating Program")
            sys.exit(0)
        else:
            print("Invalid analysis choice.")


if __name__ == "__main__":
    main()
