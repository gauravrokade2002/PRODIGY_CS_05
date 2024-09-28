# PRODIGY_CS_05
#PACKET SNIFFER
#gauravrokade2002

packet sniffer for educational purposes is a great way to learn about network protocols and traffic analysis. Below is a basic example of a packet sniffer using Python and the scapy library. This script will capture packets, and display relevant information including source and destination IP addresses, protocols, and payload data.

Requirements
Python: Ensure you have Python installed.

Scapy: Install Scapy using pip.

pip install scapy


Explanation

PacketSnifferApp: This class encapsulates the GUI and packet sniffing logic.

__init__: Initializes the GUI components.
packet_callback: Processes and displays packet information. Checks for the stop condition and limits the number of packets.
sniff_packets: Starts sniffing packets in a separate thread.
start_sniffing and stop_sniffing: Control the sniffing process, including updating the GUI and managing threading.
tkinter Components:

ScrolledText: A text area for displaying packet data.
Button: Buttons to start and stop packet sniffing.
Threading: The sniff_packets method runs in a separate thread to keep the GUI responsive while capturing packets.

packet_callback(packet): This function is called for each packet captured. It checks if the packet has an IP layer and extracts 
information such as source and destination IP addresses and protocol type.

sniff(prn=packet_callback, store=0): This function starts capturing packets and calls packet_callback for each one. store=0 prevents storing packets in memory.

Ethical Use
Legal Compliance: Ensure you have permission to sniff traffic on the network you are monitoring. Unauthorized packet sniffing can be illegal and unethical.

Educational Purposes: Use the tool for learning and debugging on your network or a controlled environment where you have consent.

Privacy: Do not use the sniffer to capture sensitive information or for malicious purposes.




Explanation
MAX_PACKETS: Define the maximum number of packets to capture before stopping.

STOP_CONDITION: Define a condition to stop capturing based on the payload content.

packet_count: A counter to track the number of packets captured.

packet_callback(packet): Updates to the callback function to check for the stop condition and count packets. If either the MAX_PACKETS is reached or the STOP_CONDITION is met, the function returns True, which stops the sniffing.

stop_filter=lambda x: packet_callback(x): This lambda function is used with sniff() to stop packet capture based on the callback function’s return value.


