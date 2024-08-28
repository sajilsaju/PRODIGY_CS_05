## PRODIGY_CS_05
# Network Packet Analyzer
## Overview
The Network Packet Analyzer is a simple packet sniffing tool developed in Python. It captures and analyzes network packets to provide insights into the traffic flowing through a network interface. The tool displays key information such as source and destination IP addresses, protocols (TCP, UDP, ICMP), and payload data. This project is intended for educational purposes, focusing on understanding network communication and packet analysis.

## Features
- Captures live network packets on a specified network interface.
- Displays detailed information about each packet, including:
  - Source and destination IP addresses.
  - Protocol type (TCP, UDP, ICMP).
  - Source and destination ports (for TCP/UDP).
  - Payload data.
- Provides real-time monitoring of network traffic.
- Ensures ethical use with a focus on learning and research purposes only.

## Tools and Technologies Used
- Python: Programming language used for developing the tool.
- Scapy: A powerful Python library for network packet manipulation and analysis.

## Installation

### 1. Clone the repository:
git clone https://github.com/sajilsaju/PRODIGY_CS_05.git

### 2. Install Dependencies:
- Ensure you have Python installed (version 3.x is recommended).
- Install the required Python libraries using pip:
   - pip install scapy
### 3. Run the Script:
Run the script with root privileges to capture network packets:
 - sudo python3 network_packet_analyzer.py

### 4. Specify the Network Interface:
- When prompted, enter the network interface you wish to monitor (eth0 for Ethernet, wlan0 for Wi-Fi).

## Usage
- Start the Tool: Run the script as described above.
- Monitor the Output: The tool will display real-time information about the captured packets.
- Stop the Tool: To stop the packet sniffing, press Ctrl + C.

## Ethical Considerations
- This tool should be used strictly for educational and research purposes.
- Ensure you have proper authorization before capturing network traffic.
- Unauthorized network sniffing may violate laws and privacy rights.
