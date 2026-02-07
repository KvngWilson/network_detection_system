#!/usr/bin/env python3
"""
Training script for anomaly detector using captured network traffic.

This script captures normal traffic patterns and trains the Isolation Forest
model to establish a baseline for anomaly detection.
"""

import numpy as np
import time
import queue
from scapy.all import IP, TCP
from packet_capture import PacketCapture, TrafficAnalyzer
from detection_engine import DetectionEngine
from config_loader import Config
import pickle
import argparse

def train_anomaly_detector(interface, duration=300, config_path="config.json"):
    """
    Collect normal traffic data and train the anomaly detector.
    
    Args:
        interface: Network interface to capture from (e.g., 'enp2s0', 'wlp3s0')
        duration: How long to capture traffic in seconds (default: 5 minutes)
        config_path: Path to configuration file
        
    Returns:
        DetectionEngine: Trained detection engine
    """
    
    print("=" * 60)
    print("ANOMALY DETECTOR TRAINING")
    print("=" * 60)
    print(f"Interface: {interface}")
    print(f"Duration: {duration} seconds (~{duration/60:.1f} minutes)")
    print()
    print("Starting packet capture...")
    print("Make sure your network has normal, typical traffic patterns.")
    print("-" * 60)
    
    # Initialize components
    config = Config(config_path)
    packet_capture = PacketCapture()
    traffic_analyzer = TrafficAnalyzer()
    detection_engine = DetectionEngine(config)
    
    # Start capturing packets
    packet_capture.start_capture(interface)
    
    features_list = []
    start_time = time.time()
    packet_count = 0
    
    try:
        while time.time() - start_time < duration:
            try:
                # Get packet from queue
                packet = packet_capture.packet_queue.get(timeout=1.0)
                
                # Check for IP and TCP
                if IP not in packet or TCP not in packet:
                    continue
                
                # Analyze packet
                features = traffic_analyzer.analyze_packet(packet)
                
                if features:
                    # Extract feature vector: [packet_size, packet_rate, byte_rate]
                    feature_vector = [
                        features["packet_size"],
                        features["packet_rate"],
                        features["byte_rate"]
                    ]
                    features_list.append(feature_vector)
                    packet_count += 1
                    
                    # Progress update every 50 packets
                    if packet_count % 50 == 0:
                        elapsed = time.time() - start_time
                        print(f"[{elapsed:.1f}s] Captured {packet_count} packets...")
                        
            except queue.Empty:
                continue
    
    except KeyboardInterrupt:
        print("\nTraining interrupted by user.")
    
    finally:
        # Stop packet capture
        packet_capture.stop()
    
    elapsed = time.time() - start_time
    print("-" * 60)
    print(f"Capture complete in {elapsed:.1f} seconds")
    print(f"Total packets captured: {packet_count}")
    
    if len(features_list) < 10:
        print("ERROR: Not enough samples for training (need at least 10)")
        return None
    
    # Convert to numpy array for training
    training_data = np.array(features_list)
    
    print()
    print("Training anomaly detector...")
    print(f"Training samples: {len(training_data)}")
    print(f"Feature dimensions: {training_data.shape}")
    
    # Train the detector
    detection_engine.train_anomaly_detector(training_data)
    
    # Save training statistics
    print()
    print("Training Statistics:")
    print(f"  Min packet size: {training_data[:, 0].min():.0f} bytes")
    print(f"  Max packet size: {training_data[:, 0].max():.0f} bytes")
    print(f"  Avg packet size: {training_data[:, 0].mean():.0f} bytes")
    print(f"  Min packet rate: {training_data[:, 1].min():.2f} pps")
    print(f"  Max packet rate: {training_data[:, 1].max():.2f} pps")
    print(f"  Avg packet rate: {training_data[:, 1].mean():.2f} pps")
    print(f"  Min byte rate: {training_data[:, 2].min():.0f} bps")
    print(f"  Max byte rate: {training_data[:, 2].max():.0f} bps")
    print(f"  Avg byte rate: {training_data[:, 2].mean():.0f} bps")
    
    # Save the trained model
    model_file = "anomaly_detector_model.pkl"
    try:
        with open(model_file, 'wb') as f:
            pickle.dump(detection_engine.anomaly_detector, f)
        print()
        print(f"✓ Model saved to: {model_file}")
    except Exception as e:
        print(f"Warning: Could not save model: {e}")
    
    print()
    print("=" * 60)
    print("TRAINING COMPLETE!")
    print("=" * 60)
    print()
    print("The anomaly detector is now trained and ready to use.")
    print()
    print("To use the trained model:")
    print("  1. Copy the trained detection_engine instance, or")
    print("  2. Load the saved model file: anomaly_detector_model.pkl")
    
    return detection_engine


def load_trained_model(model_file="anomaly_detector_model.pkl"):
    """
    Load a previously trained anomaly detector model.
    
    Args:
        model_file: Path to saved model file
        
    Returns:
        Trained Isolation Forest model or None if not found
    """
    import os
    
    if not os.path.exists(model_file):
        print(f"Error: Model file not found: {model_file}")
        return None
    
    try:
        with open(model_file, 'rb') as f:
            model = pickle.load(f)
        print(f"✓ Loaded trained model from: {model_file}")
        return model
    except Exception as e:
        print(f"Error loading model: {e}")
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train anomaly detector with normal network traffic"
    )
    parser.add_argument(
        "-i", "--interface",
        default="enp2s0",
        help="Network interface to capture from (default: enp2s0)"
    )
    parser.add_argument(
        "-d", "--duration",
        type=int,
        default=300,
        help="Training duration in seconds (default: 300 = 5 minutes)"
    )
    parser.add_argument(
        "-c", "--config",
        default="config.json",
        help="Path to configuration file (default: config.json)"
    )
    
    args = parser.parse_args()
    
    print()
    print("WARNING: This script requires root/sudo privileges for packet capture!")
    print()
    
    # Train the detector
    trained_engine = train_anomaly_detector(
        interface=args.interface,
        duration=args.duration,
        config_path=args.config
    )
    
    if trained_engine:
        print("\nTraining successful! Ready to detect anomalies.")
