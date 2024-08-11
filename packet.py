#!/usr/bin/env python3

import argparse
import sys
import logging
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP
import datetime
import signal
import csv
from colorama import init, Fore, Style

# Initialize colorama
init()

class PacketSniffer:
    def __init__(self, interface=None, output_file='captured_packets.csv', packet_count=0, filter_expression=None, pcap_file=None):
        self.interface = interface
        self.output_file = output_file
        self.packet_count = packet_count
        self.filter_expression = filter_expression
        self.pcap_file = pcap_file
        self.packets_captured = 0
        self.start_time = None
        self.csv_writer = None
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def start_csv(self):
        self.csv_file = open(self.output_file, 'w', newline='')
        self.csv_writer = csv.writer(self.csv_file)
        # Header names for the CSV
        self.csv_writer.writerow(['Timestamp', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Length', 'Info', 'Payload'])

    def stop_csv(self):
        if self.csv_file:
            self.csv_file.close()

    def packet_callback(self, packet):
        self.packets_captured += 1

        if IP in packet:
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            length = len(packet)
            info = ""
            payload = bytes(packet[IP].payload).hex()  # Capture payload in hexadecimal format

            src_port = None  # Initialize to avoid reference before assignment
            dst_port = None  # Initialize to avoid reference before assignment

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                info = f"TCP {src_port} -> {dst_port}"
                if packet.haslayer(HTTP):
                    info += f" HTTP {packet[HTTP].Method.decode() if packet[HTTP].Method else ''}"
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                info = f"UDP {src_port} -> {dst_port}"

            # Logging with color for source and destination IPs and displaying payload
            if src_port is not None and dst_port is not None:
                logging.info(f"Packet Captured: {Fore.GREEN}{src_ip}{Style.RESET_ALL}:{Fore.BLUE}{src_port}{Style.RESET_ALL} -> {Fore.RED}{dst_ip}{Style.RESET_ALL}:{Fore.YELLOW}{dst_port}{Style.RESET_ALL} | {protocol} | {length} bytes | Payload: {payload}")
            else:
                logging.info(f"Packet Captured: {Fore.GREEN}{src_ip}{Style.RESET_ALL} -> {Fore.RED}{dst_ip}{Style.RESET_ALL} | {protocol} | {length} bytes | Payload: {payload}")

            # Write to CSV with no color
            self.csv_writer.writerow([timestamp, src_ip, src_port if src_port else '', dst_ip, dst_port if dst_port else '', protocol, length, info, payload])

        if self.packet_count and self.packets_captured >= self.packet_count:
            raise KeyboardInterrupt

    def validate_interface(self, interface):
        try:
            sniff(iface=interface, count=1)  # Attempt to capture a single packet to validate the interface
            return True
        except Exception as e:
            logging.error(f"Interface validation failed: {e}")
            return False

    def capture_live(self):
        if not self.validate_interface(self.interface):
            logging.error(f"Invalid network interface: {self.interface}")
            sys.exit(1)

        self.start_time = datetime.datetime.now()
        logging.info(f"Starting packet capture on interface {self.interface}")
        logging.info(f"Capturing {self.packet_count if self.packet_count > 0 else 'infinite'} packets")
        logging.info(f"Filter: {self.filter_expression if self.filter_expression else 'None'}")
        logging.info("Press Ctrl+C to stop the capture")

        # Color guide
        print("\nColor Guide:")
        print(f"{Fore.GREEN}Source IP{Style.RESET_ALL}: The IP address where the packet originated.")
        print(f"{Fore.RED}Destination IP{Style.RESET_ALL}: The IP address where the packet is going.")
        print(f"{Fore.BLUE}Source Port{Style.RESET_ALL}: The port number on the source IP address.")
        print(f"{Fore.YELLOW}Destination Port{Style.RESET_ALL}: The port number on the destination IP address.")
        print("Colors may not appear in all environments. Check terminal settings if colors are not visible.\n")

        self.start_csv()

        try:
            sniff(iface=self.interface, prn=self.packet_callback, filter=self.filter_expression, store=0)
        except KeyboardInterrupt:
            logging.info("\nPacket capture stopped by user.")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        finally:
            self.stop_csv()
            self.print_summary()

    def analyze_pcap(self, pcap_file):
        logging.info(f"Analyzing pcap file: {pcap_file}")
        self.start_csv()

        # Color guide
        print("\nColor Guide:")
        print(f"{Fore.GREEN}Source IP{Style.RESET_ALL}: The IP address where the packet originated.")
        print(f"{Fore.RED}Destination IP{Style.RESET_ALL}: The IP address where the packet is going.")
        print(f"{Fore.BLUE}Source Port{Style.RESET_ALL}: The port number on the source IP address.")
        print(f"{Fore.YELLOW}Destination Port{Style.RESET_ALL}: The port number on the destination IP address.")
        print("Colors may not appear in all environments. Check terminal settings if colors are not visible.\n")

        try:
            packets = rdpcap(pcap_file)
            for packet in packets:
                self.packet_callback(packet)
        except Exception as e:
            logging.error(f"An error occurred while analyzing pcap: {e}")
        finally:
            self.stop_csv()
            self.print_summary()

    def print_summary(self):
        if self.start_time is None:
            logging.error("Capture was not started or already completed.")
            return

        duration = datetime.datetime.now() - self.start_time
        logging.info(f"\nCapture Summary:")
        logging.info(f"Duration: {duration}")
        logging.info(f"Packets captured: {self.packets_captured}")
        logging.info(f"Output file: {self.output_file}")

def signal_handler(sig, frame):
    logging.info("\nCapture interrupted by user. Cleaning up...")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer")
    parser.add_argument("-o", "--output", default="captured_packets.csv", help="Output file for captured packets")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-f", "--filter", help="BPF filter expression")

    args = parser.parse_args()

    # Prompt user for choice
    print("Choose mode:")
    print("1. Live Capture")
    print("2. Analyze Existing pcap File")
    choice = input("Enter 1 or 2: ").strip()

    if choice == '1':
        interface = input("Enter the network interface to sniff on: ").strip()
        sniffer = PacketSniffer(interface=interface, output_file=args.output, packet_count=args.count, filter_expression=args.filter)
        sniffer.capture_live()
    elif choice == '2':
        pcap_file = input("Enter the path to the pcap file: ").strip()
        sniffer = PacketSniffer(output_file=args.output, pcap_file=pcap_file)
        sniffer.analyze_pcap(pcap_file)
    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()
