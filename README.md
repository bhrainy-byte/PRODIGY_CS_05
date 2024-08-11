# Network Packet Analyzer

# Overview

The Advanced Packet Sniffer is a Python-based tool designed to capture and analyze network traffic. It offers two main functionalities:
Live Capture: Capture packets in real-time from a specified network interface.
Analyze Existing pcap Files: Analyze pre-captured pcap files to extract and log packet information.
The tool provides detailed insights into network packets, including source and destination IP addresses, ports, protocol type, packet length, and more. It also visually differentiates packet details using color coding for better clarity.

# Features
Live Packet Capture: Capture packets directly from a network interface.

Pcap File Analysis: Analyze packets from an existing pcap file.

Color-Coded Output: Visually differentiate between packet details such as source IP, destination IP, ports, etc.

Protocol Support: Handles common protocols like TCP, UDP, HTTP, HTTPS, and FTP.

CSV Export: Save captured or analyzed packet data to a CSV file for further analysis.

# Prerequisites
For Live Packet Capture

Npcap: The tool requires Npcap to be installed on your system for live packet capture functionality. You can download and install it from Npcap's official website.

# Python Libraries
Python 3.x

Scapy

Colorama

argparse

csv

# Usage
 Running the Tool:

Clone the repository and navigate to the project directory:

git clone https://github.com/bhrainy-byte/PRODIGY_CS_05/edit/advanced-packet-sniffer.git

 cd advanced-packet-sniffer


 # Run the script:
 
 python packet_sniffer.py


# Command-Line Arguments
-o, --output: Specify the output CSV file (default is captured_packets.csv).

-c, --count: Specify the number of packets to capture (0 for infinite).

-f, --filter: Apply a BPF filter expression to capture specific packets.

# Mode Selection

When you run the script, you'll be prompted to choose between live capture and analyzing an existing pcap file:

Live Capture: Enter the network interface to sniff on (e.g., eth0 on Linux or Ethernet on Windows).
Analyze pcap File: Enter the path to the pcap file you wish to analyze.


# Troubleshoot 

# Common Errors
"Error opening adapter": Ensure Npcap is correctly installed and that you have the necessary permissions to capture packets.
"Interface validation failed": Double-check the network interface name and ensure it's valid.


