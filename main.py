"""
Network Intrusion Detection System (IDS) main module.

This module orchestrates all IDS components including packet capture,
traffic analysis, threat detection, and alert generation.
"""

import queue
from scapy.all import IP, TCP, UDP
from packet_capture import PacketCapture, TrafficAnalyzer
from detection_engine import DetectionEngine
from alert_system import AlertSystem
from config_loader import Config

class IntrusionDetectionSystem:
  """
  Main IDS orchestrator that coordinates all detection components.
  
  Attributes:
      config: Configuration loader instance
      packet_capture: Network packet capture component
      traffic_analyzer: Traffic analysis component
      detection_engine: Threat detection engine
      alert_system: Alert logging system
      interface: Network interface to monitor
  """
  
  def __init__(self, interface=None, config_path="config.json"):
    # Load configuration
    self.config = Config(config_path)
    
    # Initialize components with configuration
    self.packet_capture = PacketCapture()
    self.traffic_analyzer = TrafficAnalyzer()
    self.detection_engine = DetectionEngine(self.config)
    
    log_file = self.config.get('alert_system.log_file', 'ids_alerts.log')
    threshold = self.config.get('alert_system.high_confidence_threshold', 0.8)
    self.alert_system = AlertSystem(log_file, threshold)
    
    # Use interface from parameter or config
    self.interface = interface or self.config.get('interface', 'enp2s0')
    self.queue_timeout = self.config.get('capture.queue_timeout', 1.0)
    
    print(f"IDS will monitor interface: {self.interface}")
    
  def start(self):
    print(f"Starting IDS on interface {self.interface}")
    self.packet_capture.start_capture(self.interface)
    
    while True:
      try:
        packet = self.packet_capture.packet_queue.get(timeout=1.0)
        
        # Only process packets with IP and TCP layers
        if IP not in packet or TCP not in packet:
          continue
          
        features = self.traffic_analyzer.analyze_packet(packet)
        
        if features:
          threats = self.detection_engine.detect_threats(features)
          
          for threat in threats:
            packet_info = {
              "source_ip": packet[IP].src,
              "dest_ip": packet[IP].dst,
              "source_port": packet[TCP].sport,
              "dest_port": packet[TCP].dport
            }
            self.alert_system.generate_alert(threat, packet_info)
      
      except queue.Empty:
        continue
      except KeyboardInterrupt:
        print("\nStopping IDS...")
        self.packet_capture.stop()
        break
      except Exception as e:
        print(f"Error processing packet: {e}")
        continue

if __name__ == "__main__":
  ids = IntrusionDetectionSystem()
  ids.start()