from scapy.all import sniff, wrpcap, conf
from scapy.error import Scapy_Exception
import pandas as pd
import os
import sys

# Force Scapy to look for the Npcap driver if present
conf.use_pcap = True

def capture_packets(interface=None, packet_count=20):
    """
    Captures packets and returns a summary.
    Saves a .pcap file in the evidence folder.
    Attempts Layer 2 (Npcap) first, falls back to Layer 3 (Socket) if needed.
    """
    packets = None
    
    # Save Evidence Directory
    if not os.path.exists("evidence"):
        os.makedirs("evidence")
    pcap_path = f"evidence/capture_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.pcap"

    try:
        # ATTEMPT 1: Standard Layer 2 Sniffing (Requires Npcap/Root)
        # This is the best mode as it captures Ethernet headers (MAC addresses)
        packets = sniff(count=packet_count, timeout=10)
        
    except (Scapy_Exception, OSError, ImportError) as e:
        # ATTEMPT 2: Fallback to Layer 3 (IP Only)
        # This works without Npcap but only sees IP traffic (no MAC addresses)
        print(f"Warning: Standard L2 sniffing failed ({e}). Switching to L3 socket.")
        try:
            from scapy.arch.windows import NativeSniffer
            conf.use_pcap = False
            conf.L3socket = conf.L3socket # Force use of native L3 socket
            packets = sniff(count=packet_count, timeout=10)
        except Exception as e2:
            raise Exception(f"Packet capture failed completely. Ensure you are running as ADMIN. Original error: {e}")

    # If capture succeeded, save and parse
    if packets:
        wrpcap(pcap_path, packets)
        
        summary = []
        for pkt in packets:
            # Safely extract fields based on layer availability
            src = "Unknown"
            dst = "Unknown"
            proto = "Unknown"

            # Check for IP Layer (Layer 3)
            if pkt.haslayer('IP'):
                src = pkt['IP'].src
                dst = pkt['IP'].dst
                proto = pkt['IP'].proto
            # Fallback to Ethernet Layer (Layer 2) if IP not present
            elif pkt.haslayer('Ether'):
                src = pkt['Ether'].src
                dst = pkt['Ether'].dst
            
            summary.append({"Source": src, "Destination": dst, "Protocol": proto})
            
        return pd.DataFrame(summary), pcap_path
    
    return pd.DataFrame(), "No packets captured"