# packet_sniffer
CMPE 148 Extra Credit Assignment

Contains 2 Deliverables:

1. Wireshark Lab (wireshark_lab.py)
Considered the first iteration of this, the script simply set times and dates to fire a certain number of pings to given domains. By configuring these values beforehand, you could automate the testing and collection of pinging various domains at different points in time, storing them into a .pcap file for interpretation. The script also created a histogram using matplotlib and saving them as an image that can be viewed after running.

2. Packet Sniffer (packet_sniffer.py)
The actual extra credit assignment. This script does not actually create .pcap files on its own but can still log packets and then has many more applications for analysis of these packets. These include:
1. Latency Analysis
2. TCP Retransmissions
3. Connection Tracking
4. Protocol Usage Visualization (Not fully flushed out)
5. Packet Filtering
6. Exporting packet log to a file

Dependencies and instructions to run also exist within the packet_sniffer.py file.
