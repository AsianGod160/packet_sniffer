#!/usr/bin/env python3
"""
File: wireshark_script.py
Author: Brian Chiang
Created on: 2024-11-06

Description:
"""

# sudo apt update && sudo apt install tshark
# sudo usermod -aG wireshark $USER
# sudo dpkg-reconfigure wireshark-common
# sudo chmod +x /usr/bin/dumpcap
# tshark -i eth0

import subprocess
import re
import matplotlib.pyplot as plt
import sys
from datetime import datetime
from time import sleep

times = [
        datetime(2024, 11, 7, 2, 30, 0),
        datetime(2024, 11, 7, 5, 00, 0), 
        datetime(2024, 11, 7, 7, 30, 0), 
        datetime(2024, 11, 7, 9, 00, 0), 
        datetime(2024, 11, 7, 11, 30, 0), 
        datetime(2024, 11, 7, 13, 30, 0), 
        datetime(2024, 11, 7, 17, 30, 0), 
        datetime(2024, 11, 7, 21, 00, 0), 
        datetime(2024, 11, 8, 00, 00, 0), 
        datetime(2024, 11, 8, 3, 00, 0), 
        ]


domains = ["stanford.edu", "ox.ac.uk", "mit.edu", "canada.ca", "ethz.ch"]  # Replace with your domain of choice
def get_ping_rtt(domain, count=100):
    print(f"Pinging {domain}")
    # Run ping command
    ping_command = ["ping", "-c", str(count), domain]
    result = subprocess.run(ping_command, capture_output=True, text=True)
    
    # Extract RTT values using regex
    rtt_times = []
    #print(result.stdout)
    for line in result.stdout.splitlines():
        match = re.search(r'time=([\d.]+) ms', line)
        if match:
            rtt_times.append(float(match.group(1)))
    
    return rtt_times, result.stdout

def get_tracert(domain):
    print(f"Tracing route {domain}")
    # Run tracert command
    trace_command = ["tracepath", domain]
    result = subprocess.run(trace_command, capture_output=True, text=True)
    return result.stdout

def plot_rtt_histogram(rtt_times, domain):
    # Plot histogram list
    print(f"{domain}: {sorted(rtt_times)}")
    plt.cla()
    plt.hist(rtt_times, bins='auto', edgecolor='black')
    plt.title(f"Round-Trip Time (RTT) Histogram ({domain})")
    plt.xlabel("RTT (ms)")
    plt.ylabel("Frequency")
    plt.savefig(f'{domain[0: domain.rfind('.')]}.jpg')

if __name__ == "__main__":
    arr = []
    data_dict = {d: [] for d in domains}
    times.sort()

    count = 1
    with open("output.txt", 'w') as file:
        for time in times:
            while datetime.now() < time:
                print(f"Waiting for {time}")
                sys.stdout.flush()
                sleep(300)

            file.write(f'-------------{time}-----------------\n')
            for d in domains:
                tshark_out_file = f"capture_output_{str(d)}({str(count)}).pcap"
                tshark_monitor_command = ["tshark","-a", "duration:300", "-i", "eth0", "-w", f"{tshark_out_file}"]
                process = subprocess.Popen(tshark_monitor_command)
                sleep(1) # Let shark breathe
                # Get round trip times and output from pings, add data to dictionary and store output to output.txt
                round_trip_times, out = get_ping_rtt(d)
                data_dict[d] += round_trip_times
                file.write(out + "\n")
                out = get_tracert(d)
                file.write(out + "\n\n\n")
                process.terminate() # Ping should already have returned
                process.wait() #ZOMBIE
            count = count + 1

        for d in domains:
            plot_rtt_histogram(data_dict[d], d)
# Run asynchronously: nohup ./wireshark_script.py > stdout.txt 2>&1 &
# Monitor live (tail) output: tail -f stdout.txt