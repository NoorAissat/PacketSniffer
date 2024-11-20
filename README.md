# Packet Sniffer

This is a Python-based packet sniffer designed to capture and analyze HTTP requests on a specified network interface. It identifies potential username and password credentials transmitted over unencrypted HTTP traffic. The script uses the Scapy library for packet capture and Colorama for color-coded output, making it easier to identify sensitive data.

## Features
- Captures HTTP requests and extracts host and path information.
- Detects and prints possible username/password pairs from raw packet data.
- Supports real-time packet sniffing on a specified network interface.

