# Network Intrusion Detection System (IDS)

A Python-based Network Intrusion Detection System that monitors network traffic and detects potential security threats using both signature-based and anomaly-based detection methods.

## Features

- **Real-time Packet Capture**: Captures and analyzes network packets using Scapy
- **Dual Detection Methods**:
  - **Signature-based Detection**: Rule-based pattern matching for known attack signatures
  - **Anomaly-based Detection**: Machine learning (Isolation Forest) for detecting unusual traffic patterns
- **Traffic Analysis**: Extracts and analyzes network flow features including packet rates, byte rates, and TCP characteristics
- **Alert System**: Logs detected threats with configurable severity levels

## Architecture

The system consists of four main components:

1. **PacketCapture** (`packet_capture.py`): Captures network packets in a separate thread
2. **TrafficAnalyzer** (`packet_capture.py`): Extracts features from captured packets and maintains flow statistics
3. **DetectionEngine** (`detection_engine.py`): Detects threats using signature rules and ML-based anomaly detection
4. **AlertSystem** (`alert_system.py`): Generates and logs security alerts
5. **IntrusionDetectionSystem** (`main.py`): Orchestrates all components

## Requirements

- Python 3.8+
- Root/Administrator privileges (required for packet capture)
- Linux/Unix system recommended

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd detection
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure you have proper permissions for packet capture:
```bash
# Linux - add user to appropriate group or use sudo
sudo usermod -a -G wireshark $USER
```

## Usage

### Basic Usage

Run the IDS on the default interface (eth0):
```bash
sudo python main.py
```

### Specifying Network Interface

To monitor a specific network interface:
```python
from main import IntrusionDetectionSystem

ids = IntrusionDetectionSystem(interface="wlan0")
ids.start()
```

### Training the Anomaly Detector

Before running the IDS, you should train the anomaly detector with normal traffic data:
```python
from detection_engine import DetectionEngine
import numpy as np

engine = DetectionEngine()
# Load your normal traffic data
normal_data = np.array([...])  # Features: [packet_size, packet_rate, byte_rate]
engine.train_anomaly_detector(normal_data)
```

## Detection Methods

### Signature-Based Rules

Currently includes detection for:
- **SYN Flood**: Small packets (<100 bytes) with high packet rate (>50 pps)
- **Port Scan**: Very small packets (<60 bytes) with very high packet rate (>100 pps)

Add custom rules in `detection_engine.py`:
```python
def load_signature_rules(self):
    return {
        "rule_name": {
            "condition": lambda features: (
                # Your condition here
            )
        }
    }
```

### Anomaly-Based Detection

Uses Isolation Forest algorithm to detect traffic patterns that deviate from normal behavior. Features analyzed:
- Packet size
- Packet rate
- Byte rate
- TCP flags
- Window size

## Alert System

Alerts are logged to `ids_alerts.log` in JSON format:
```json
{
    "timestamp": "2026-02-06T10:30:45.123456",
    "threat": "signature",
    "source_ip": "192.168.1.100",
    "dest_ip": "192.168.1.1",
    "confidence": 1.0,
    "details": {...}
}
```

High-confidence threats (>0.8) are logged as CRITICAL level.

## Configuration

Create a `config.json` file to customize detection parameters:
```json
{
    "interface": "eth0",
    "anomaly_contamination": 0.1,
    "anomaly_threshold": -0.5,
    "log_file": "ids_alerts.log"
}
```

## Security Considerations

- **Root Privileges**: Packet capture requires elevated privileges. Run with caution.
- **Performance**: Real-time packet analysis can be CPU-intensive on high-traffic networks.
- **False Positives**: Tune detection thresholds based on your network environment.

## Limitations

- Currently only analyzes TCP/IP traffic
- Anomaly detector requires training on normal traffic before deployment
- No encrypted traffic analysis (HTTPS/TLS payload inspection)

## Future Enhancements

- [ ] Add UDP and ICMP protocol support
- [ ] Implement deep packet inspection
- [ ] Add web dashboard for real-time monitoring
- [ ] Support for multiple interfaces simultaneously
- [ ] Database integration for alert storage
- [ ] Automated response mechanisms

## Troubleshooting

### Permission Denied Error
```bash
# Run with sudo
sudo python main.py
```

### Interface Not Found
```bash
# List available interfaces
ip link show

# Or use:
ifconfig
```

### No Packets Captured
- Verify interface is up and has traffic
- Check firewall rules
- Ensure proper permissions

## License

See LICENSE file for details.

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Unauthorized network monitoring may be illegal in your jurisdiction.
