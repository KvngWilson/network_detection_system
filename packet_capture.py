"""
Network packet capture and traffic analysis module.

This module provides classes for capturing network packets using Scapy
and analyzing traffic patterns to extract features for threat detection.
"""

from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue

class PacketCapture:
  """
  Captures network packets in a separate thread.
  
  Attributes:
      packet_queue: Queue containing captured packets
      stop_capture: Event to signal capture thread to stop
  """
  
  def __init__(self):
    self.packet_queue = queue.Queue()
    self.stop_capture = threading.Event()
    
  def packet_callback(self, packet):
    """
    Callback function for processing captured packets.
    Filters for IP and TCP packets only.
    
    Args:
        packet: Scapy packet object
    """
    if IP in packet and TCP in packet:
      self.packet_queue.put(packet)
      
  def start_capture(self, interface="eth0"):
    """
    Start packet capture on specified interface in a separate thread.
    
    Args:
        interface: Network interface to capture from (default: eth0)
    """
    def capture_thread():
      try:
        sniff(iface=interface,
              prn=self.packet_callback,
              store=0,
              stop_filter=lambda _: self.stop_capture.is_set())
      except ValueError as e:
        print(f"Error: {e}")
        print("To see available interfaces, run: ip link show")
        self.stop_capture.set()
    
    self.capture_thread = threading.Thread(target=capture_thread)
    self.capture_thread.start()
    
  def stop(self):
    """Stop packet capture and wait for capture thread to finish."""
    self.stop_capture.set()
    self.capture_thread.join()
    
class TrafficAnalyzer:
  """
  Analyzes network traffic and extracts features for threat detection.
  
  Maintains flow statistics and extracts relevant features from packets
  including packet rates, byte rates, and TCP characteristics.
  """
  
  def __init__(self):
    self.connections = defaultdict(list)
    self.flow_stats = defaultdict(lambda: {
      "packet_count": 0,
      "byte_count": 0,
      "start_time": None,
      "last_time": None
    })
    
  def analyze_packet(self, packet):
    """
    Analyze a packet and extract flow features.
    
    Args:
        packet: Scapy packet object with IP and TCP layers
        
    Returns:
        Dictionary of extracted features or None if packet invalid
    """
    if IP in packet and TCP in packet:
      ip_src = packet[IP].src
      ip_dst = packet[IP].dst
      port_src = packet[TCP].sport
      port_dst = packet[TCP].dport
      
      flow_key = (ip_src, ip_dst, port_src, port_dst)
      
      # Update flow stats
      stats = self.flow_stats[flow_key]
      stats["packet_count"] += 1
      stats["byte_count"] += len(packet)
      current_time = packet.time
      
      if not stats["start_time"]:
        stats["start_time"] = current_time
      stats["last_time"] = current_time
      
      return self.extract_features(packet, stats)
  
  def extract_features(self, packet, stats):
    """
    Extract numerical features from packet and flow statistics.
    
    Args:
        packet: Scapy packet object
        stats: Flow statistics dictionary
        
    Returns:
        Dictionary of feature values for threat detection
    """
    duration = stats["last_time"] - stats["start_time"]
    # Avoid division by zero for first packet or same timestamp
    if duration == 0:
      duration = 0.001  # Use small value instead of zero
    
    return {
      "packet_size": len(packet),
      "flow_duration": duration,
      "packet_rate": stats["packet_count"] / duration,
      "byte_rate": stats["byte_count"] / duration,
      "tcp_flags": packet[TCP].flags,
      "window_size": packet[TCP].window
    }