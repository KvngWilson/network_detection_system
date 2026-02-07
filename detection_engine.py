"""
Threat detection engine using signature-based and anomaly-based methods.

This module implements both rule-based pattern matching and machine learning
(Isolation Forest) for detecting network security threats.
"""

from sklearn.ensemble import IsolationForest
import numpy as np

class DetectionEngine:
  """
  Detects security threats using signature rules and anomaly detection.
  
  Attributes:
      anomaly_detector: Isolation Forest model for anomaly detection
      signature_rules: Dictionary of rule-based detection patterns
      is_trained: Whether the anomaly detector has been trained
  """
  
  def __init__(self, config=None):
    # Load configuration
    contamination = 0.1 if config is None else config.get('anomaly_detection.contamination', 0.1)
    random_state = 42 if config is None else config.get('anomaly_detection.random_state', 42)
    self.anomaly_threshold = -0.5 if config is None else config.get('anomaly_detection.threshold', -0.5)
    
    self.anomaly_detector = IsolationForest(contamination=contamination, random_state=random_state)
    self.signature_rules = self.load_signature_rules(config)
    self.training_data = []
    self.is_trained = False
  
  def load_signature_rules(self, config=None):
    # Get thresholds from config or use defaults
    if config:
      syn_size = config.get('signature_rules.syn_flood.packet_size_threshold', 100)
      syn_rate = config.get('signature_rules.syn_flood.packet_rate_threshold', 50)
      port_size = config.get('signature_rules.port_scan.packet_size_threshold', 60)
      port_rate = config.get('signature_rules.port_scan.packet_rate_threshold', 100)
      syn_enabled = config.get('signature_rules.syn_flood.enabled', True)
      port_enabled = config.get('signature_rules.port_scan.enabled', True)
    else:
      syn_size, syn_rate = 100, 50
      port_size, port_rate = 60, 100
      syn_enabled, port_enabled = True, True
    
    rules = {}
    
    if syn_enabled:
      rules["syn_flood"] = {
        "condition": lambda features: (
          features["packet_size"] < syn_size and
          features["packet_rate"] > syn_rate
        )
      }
    
    if port_enabled:
      rules["port_scan"] = {
        "condition": lambda features: (
          features["packet_size"] < port_size and
          features["packet_rate"] > port_rate
        )
      }
    
    return rules  
  
  def train_anomaly_detector(self, normal_traffic_data):
    """Train the anomaly detector with normal traffic patterns"""
    self.anomaly_detector.fit(normal_traffic_data)
    self.is_trained = True
    print(f"Anomaly detector trained with {len(normal_traffic_data)} samples")
    
  def detect_threats(self, features):
    """
    Detect threats using both signature and anomaly-based methods.
    
    Args:
        features: Dictionary of packet/flow features
        
    Returns:
        List of detected threats with type, confidence, and details
    """
    threats = []
    
    # Signature-based detection
    for rule_name, rule in self.signature_rules.items():
      if rule["condition"](features):
        threats.append({
          "type": "signature",
          "rule": rule_name,
          "confidence": 1.0
        })
        
    # Anomaly-based detection (only if trained)
    if self.is_trained:
      feature_vector = np.array([[
         features["packet_size"],
         features["packet_rate"],
         features["byte_rate"]
      ]])
      
      anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
      if anomaly_score < self.anomaly_threshold:
        threats.append({
          "type": "anomaly",
          "score": anomaly_score,
          "confidence": min(1.0, abs(anomaly_score))
        })
      
    return threats
  