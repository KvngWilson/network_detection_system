"""
Unit tests for Network Intrusion Detection System
"""

import unittest
import numpy as np
from detection_engine import DetectionEngine
from alert_system import AlertSystem
from config_loader import Config
import os
import json
import tempfile

class TestDetectionEngine(unittest.TestCase):
    """Test cases for DetectionEngine"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.engine = DetectionEngine()
    
    def test_signature_detection_syn_flood(self):
        """Test SYN flood detection"""
        features = {
            "packet_size": 50,
            "packet_rate": 100,
            "byte_rate": 5000,
            "flow_duration": 1.0,
            "tcp_flags": 2,
            "window_size": 65535
        }
        threats = self.engine.detect_threats(features)
        
        # Should detect syn_flood
        self.assertTrue(any(t["type"] == "signature" for t in threats))
        syn_threats = [t for t in threats if t.get("rule") == "syn_flood"]
        self.assertTrue(len(syn_threats) > 0)
    
    def test_no_detection_normal_traffic(self):
        """Test that normal traffic doesn't trigger alerts"""
        features = {
            "packet_size": 1000,
            "packet_rate": 10,
            "byte_rate": 10000,
            "flow_duration": 1.0,
            "tcp_flags": 16,
            "window_size": 65535
        }
        threats = self.engine.detect_threats(features)
        
        # Should not detect signature-based threats
        signature_threats = [t for t in threats if t["type"] == "signature"]
        self.assertEqual(len(signature_threats), 0)
    
    def test_anomaly_detection_training(self):
        """Test anomaly detector training"""
        # Generate synthetic normal traffic
        normal_data = np.random.randn(100, 3) * 100 + [500, 20, 10000]
        
        self.engine.train_anomaly_detector(normal_data)
        self.assertTrue(self.engine.is_trained)
    
    def test_signature_rules_loaded(self):
        """Test that signature rules are loaded"""
        self.assertIsNotNone(self.engine.signature_rules)
        self.assertIn("syn_flood", self.engine.signature_rules)
        self.assertIn("port_scan", self.engine.signature_rules)

class TestConfigLoader(unittest.TestCase):
    """Test cases for Config loader"""
    
    def test_load_default_config(self):
        """Test loading default configuration"""
        config = Config("nonexistent_file.json")
        
        self.assertEqual(config.get('interface'), 'eth0')
        self.assertEqual(config.get('anomaly_detection.contamination'), 0.1)
    
    def test_get_nested_config(self):
        """Test getting nested configuration values"""
        config = Config()
        
        threshold = config.get('alert_system.high_confidence_threshold')
        self.assertIsNotNone(threshold)
        self.assertEqual(threshold, 0.8)
    
    def test_save_and_load_config(self):
        """Test saving and loading configuration"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_file = f.name
        
        try:
            config = Config(temp_file)
            config.config['interface'] = 'wlan0'
            config.save()
            
            # Load again and verify
            config2 = Config(temp_file)
            self.assertEqual(config2.get('interface'), 'wlan0')
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

class TestAlertSystem(unittest.TestCase):
    """Test cases for AlertSystem"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_log = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.temp_log.close()
        self.alert_system = AlertSystem(self.temp_log.name)
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_log.name):
            os.remove(self.temp_log.name)
    
    def test_generate_alert(self):
        """Test alert generation"""
        threat = {
            "type": "signature",
            "rule": "syn_flood",
            "confidence": 1.0
        }
        packet_info = {
            "source_ip": "192.168.1.100",
            "dest_ip": "192.168.1.1",
            "source_port": 12345,
            "dest_port": 80
        }
        
        self.alert_system.generate_alert(threat, packet_info)
        
        # Check that log file was created
        self.assertTrue(os.path.exists(self.temp_log.name))
        
        # Check log content
        with open(self.temp_log.name, 'r') as f:
            content = f.read()
            self.assertIn("syn_flood", content)
            self.assertIn("192.168.1.100", content)
    
    def test_high_confidence_alert(self):
        """Test high confidence alert logging"""
        threat = {
            "type": "signature",
            "rule": "port_scan",
            "confidence": 0.95
        }
        packet_info = {
            "source_ip": "10.0.0.5",
            "dest_ip": "10.0.0.1"
        }
        
        self.alert_system.generate_alert(threat, packet_info)
        
        with open(self.temp_log.name, 'r') as f:
            content = f.read()
            self.assertIn("CRITICAL", content)
            self.assertIn("High confidence threat", content)

if __name__ == '__main__':
    unittest.main()
