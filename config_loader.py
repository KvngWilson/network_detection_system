import json
import os

class Config:
    """Configuration loader for IDS system"""
    
    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self.config = self.load_config()
    
    def load_config(self):
        """Load configuration from JSON file"""
        if not os.path.exists(self.config_path):
            return self.get_default_config()
        
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
            print("Using default configuration")
            return self.get_default_config()
    
    def get_default_config(self):
        """Return default configuration"""
        return {
            "interface": "eth0",
            "anomaly_detection": {
                "contamination": 0.1,
                "threshold": -0.5,
                "random_state": 42
            },
            "signature_rules": {
                "syn_flood": {
                    "enabled": True,
                    "packet_size_threshold": 100,
                    "packet_rate_threshold": 50
                },
                "port_scan": {
                    "enabled": True,
                    "packet_size_threshold": 60,
                    "packet_rate_threshold": 100
                }
            },
            "alert_system": {
                "log_file": "ids_alerts.log",
                "high_confidence_threshold": 0.8
            },
            "capture": {
                "queue_timeout": 1.0,
                "capture_filter": ""
            }
        }
    
    def get(self, key, default=None):
        """Get configuration value by key"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        
        return value
    
    def save(self):
        """Save current configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
