#gauravmahadurokade 
#gauravrokade2002
import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff
import threading

# Define a maximum number of packets to capture
MAX_PACKETS = 10
STOP_CONDITION = "specific_payload_string"

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        # Set up the GUI layout
        self.text_area = scrolledtext.ScrolledText(root, width=100, height=30)
        self.text_area.pack(padx=10, pady=10)

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.RIGHT, padx=5, pady=5)

        self.sniff_thread = None
        self.stop_event = threading.Event()
        self.packet_count = 0

    def packet_callback(self, packet):
        if self.stop_event.is_set():
            return True
        
        # Collect packet information
        packet_info = f"Packet: {packet.summary()}\n"
        
        if packet.haslayer('IP'):
            ip_layer = packet.getlayer('IP')
            packet_info += f"Source IP: {ip_layer.src}\n"
            packet_info += f"Destination IP: {ip_layer.dst}\n"
            packet_info += f"Protocol: {ip_layer.proto}\n"
            
            if packet.haslayer('TCP'):
                tcp_layer = packet.getlayer('TCP')
                packet_info += f"Source Port: {tcp_layer.sport}\n"
                packet_info += f"Destination Port: {tcp_layer.dport}\n"
                payload = str(tcp_layer.payload)
                packet_info += f"Payload (Raw Data): {payload}\n"
                
                if STOP_CONDITION in payload:
                    packet_info += f"Stop condition met: '{STOP_CONDITION}' found in payload.\n"
                    self.stop_event.set()
                    return True

            if packet.haslayer('UDP'):
                udp_layer = packet.getlayer('UDP')
                packet_info += f"Source Port: {udp_layer.sport}\n"
                packet_info += f"Destination Port: {udp_layer.dport}\n"
                payload = str(udp_layer.payload)
                packet_info += f"Payload (Raw Data): {payload}\n"
                
                if STOP_CONDITION in payload:
                    packet_info += f"Stop condition met: '{STOP_CONDITION}' found in payload.\n"
                    self.stop_event.set()
                    return True
                
            packet_info += "-" * 50 + "\n"
        else:
            packet_info += "Non-IP packet\n"

        self.text_area.insert(tk.END, packet_info)
        self.text_area.yview(tk.END)

        # Increment packet count
        self.packet_count += 1
        if self.packet_count >= MAX_PACKETS:
            self.text_area.insert(tk.END, f"Captured {MAX_PACKETS} packets. Stopping...\n")
            self.stop_event.set()
            return True

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=0, stop_filter=lambda x: self.stop_event.is_set())

    def start_sniffing(self):
        self.stop_event.clear()
        self.packet_count = 0
        self.text_area.delete(1.0, tk.END)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.stop_event.set()
        self.sniff_thread.join()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
