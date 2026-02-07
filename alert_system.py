"""
Alert system for logging and managing security threat notifications.

This module provides logging functionality for detected threats with
configurable severity levels and output formatting.
"""

import logging
import json
from datetime import datetime

class AlertSystem:
  """
  Manages alert generation and logging for detected threats.
  
  Attributes:
      logger: Python logger instance for alert output
      high_confidence_threshold: Threshold for critical alerts
  """
  
  def __init__(self, log_file="ids_alerts.log", high_confidence_threshold=0.8):
    self.logger = logging.getLogger("IDS_AlertSystem")
    self.logger.setLevel(logging.INFO)
    self.high_confidence_threshold = high_confidence_threshold
    
    """
    Generate and log an alert for a detected threat.
    
    Args:
        threat: Dictionary containing threat type, confidence, and details
        packet_info: Dictionary with packet information (IPs, ports)
    """
    handler = logging.FileHandler(log_file)
    formatter = logging.Formatter(
      "%(asctime)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    self.logger.addHandler(handler)
  
  def generate_alert(self, threat, packet_info):
    alert = {
      "timestamp": datetime.now().isoformat(),
      "threat": threat["type"],
      "source_ip": packet_info.get("source_ip"),
      "dest_ip": packet_info.get("dest_ip"),
      "confidence": threat.get("confidence", 0.0),
      "details": threat
    }
    
    self.logger.warning(json.dumps(alert))
    
    if threat.get("confidence", 0.0) > self.high_confidence_threshold:
      self.logger.critical(f"High confidence threat detected: {json.dumps(alert)}")