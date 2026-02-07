#!/usr/bin/env python3
"""
Example: Using trained anomaly detector with the IDS

This example shows how to integrate a trained anomaly detector
into the main IDS system.
"""

import numpy as np
import pickle
from detection_engine import DetectionEngine
from alert_system import AlertSystem
from config_loader import Config

def example_1_basic_training():
    """Example 1: Basic training with synthetic data"""
    print("Example 1: Training with synthetic normal traffic data")
    print("-" * 50)
    
    config = Config()
    detection_engine = DetectionEngine(config)
    
    # Generate synthetic normal traffic (packet_size, packet_rate, byte_rate)
    normal_traffic = np.random.randn(100, 3) * [100, 10, 5000] + [500, 20, 50000]
    
    # Ensure positive values
    normal_traffic = np.abs(normal_traffic)
    
    print(f"Generated {len(normal_traffic)} synthetic samples")
    print(f"Training anomaly detector...")
    
    detection_engine.train_anomaly_detector(normal_traffic)
    
    print(f"✓ Training complete!")
    print(f"  is_trained: {detection_engine.is_trained}")
    print()


def example_2_load_trained_model():
    """Example 2: Load previously trained model"""
    print("Example 2: Loading previously trained model")
    print("-" * 50)
    
    config = Config()
    detection_engine = DetectionEngine(config)
    
    # Try to load saved model
    try:
        with open("anomaly_detector_model.pkl", 'rb') as f:
            detection_engine.anomaly_detector = pickle.load(f)
            detection_engine.is_trained = True
        
        print("✓ Successfully loaded pre-trained model")
        print(f"  is_trained: {detection_engine.is_trained}")
    except FileNotFoundError:
        print("No pre-trained model found.")
        print("Run: sudo python train_anomaly_detector.py")
    print()


def example_3_test_detection():
    """Example 3: Test the trained detector with sample features"""
    print("Example 3: Testing detection on sample features")
    print("-" * 50)
    
    config = Config()
    detection_engine = DetectionEngine(config)
    
    # Train with normal traffic baseline
    normal_traffic = np.random.randn(100, 3) * [100, 5, 3000] + [500, 15, 30000]
    normal_traffic = np.abs(normal_traffic)
    detection_engine.train_anomaly_detector(normal_traffic)
    
    # Test with normal traffic feature
    normal_features = {
        "packet_size": 500,
        "packet_rate": 15,
        "byte_rate": 30000,
        "tcp_flags": 16,
        "window_size": 65535
    }
    
    # Test with anomalous traffic (small packets, high rate = SYN flood)
    anomalous_features = {
        "packet_size": 50,      # Small packet
        "packet_rate": 200,     # Very high rate
        "byte_rate": 10000,     # Low byte rate
        "tcp_flags": 2,         # SYN flag
        "window_size": 65535
    }
    
    print("Testing normal traffic:")
    threats = detection_engine.detect_threats(normal_features)
    print(f"  Threats detected: {len(threats)}")
    for threat in threats:
        print(f"    - {threat}")
    
    print()
    print("Testing anomalous traffic (SYN flood):")
    threats = detection_engine.detect_threats(anomalous_features)
    print(f"  Threats detected: {len(threats)}")
    for threat in threats:
        print(f"    - {threat}")
    print()


def example_4_integration():
    """Example 4: Full integration with IDS"""
    print("Example 4: Full IDS integration")
    print("-" * 50)
    
    config = Config()
    detection_engine = DetectionEngine(config)
    alert_system = AlertSystem()
    
    # Train detector
    normal_traffic = np.random.randn(500, 3) * [150, 20, 5000] + [600, 25, 50000]
    normal_traffic = np.abs(normal_traffic)
    detection_engine.train_anomaly_detector(normal_traffic)
    
    # Simulate detected threat
    threat = {
        "type": "signature",
        "rule": "syn_flood",
        "confidence": 0.95
    }
    
    packet_info = {
        "source_ip": "192.168.1.100",
        "dest_ip": "192.168.1.1",
        "source_port": 54321,
        "dest_port": 80
    }
    
    print("Generating alert for detected threat:")
    alert_system.generate_alert(threat, packet_info)
    print(f"✓ Alert logged to: {alert_system.logger.handlers[0].baseFilename}")
    print()


if __name__ == "__main__":
    print()
    print("=" * 60)
    print("ANOMALY DETECTOR USAGE EXAMPLES")
    print("=" * 60)
    print()
    
    example_1_basic_training()
    example_2_load_trained_model()
    example_3_test_detection()
    example_4_integration()
    
    print("=" * 60)
    print("For production training, run:")
    print("  sudo ./venv/bin/python train_anomaly_detector.py -i enp2s0 -d 600")
    print("=" * 60)
