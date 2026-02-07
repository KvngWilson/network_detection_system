# Anomaly Detector Training Guide

The Isolation Forest anomaly detector needs to be trained on normal traffic patterns to effectively distinguish between normal and anomalous behavior.

## Quick Start

### 1. Train with Default Settings (5 minutes, current interface)

```bash
cd ~/Desktop/detection
source venv/bin/activate
sudo ./venv/bin/python train_anomaly_detector.py
```

### 2. Train with Custom Settings

```bash
# 10 minutes on specific interface
sudo ./venv/bin/python train_anomaly_detector.py -i enp2s0 -d 600

# Specify config file
sudo ./venv/bin/python train_anomaly_detector.py -c config.json
```

## Available Options

```
-i, --interface     Network interface (default: enp2s0)
-d, --duration      Training duration in seconds (default: 300 = 5 min)
-c, --config        Config file path (default: config.json)
```

## How Training Works

### Process

1. **Start Packet Capture** - Captures packets from the specified interface
2. **Extract Features** - For each packet, extracts:
   - Packet size (bytes)
   - Packet rate (packets/second)
   - Byte rate (bytes/second)
3. **Build Training Set** - Accumulates feature vectors from normal traffic
4. **Train Model** - Fits Isolation Forest on the normal traffic patterns
5. **Save Model** - Saves trained model to `anomaly_detector_model.pkl`

### Feature Vector

Each training sample contains 3 features:

```python
[packet_size, packet_rate, byte_rate]
```

**Example values for normal traffic:**
- packet_size: 200-600 bytes
- packet_rate: 10-50 pps (packets/second)
- byte_rate: 30,000-80,000 bps (bytes/second)

## Examples

### Example 1: View Training Examples

```bash
./venv/bin/python anomaly_detector_examples.py
```

This runs 4 examples:
1. Training with synthetic data
2. Loading pre-trained model
3. Testing detection
4. Full IDS integration

### Example 2: Python API

```python
from detection_engine import DetectionEngine
from config_loader import Config
import numpy as np

# Initialize
config = Config()
engine = DetectionEngine(config)

# Generate or load normal traffic data (must be shape (n_samples, 3))
normal_data = np.random.randn(100, 3) * [100, 10, 5000] + [500, 20, 50000]
normal_data = np.abs(normal_data)

# Train
engine.train_anomaly_detector(normal_data)

# Check status
print(f"Is trained: {engine.is_trained}")

# Test detection
features = {
    "packet_size": 50,
    "packet_rate": 200,
    "byte_rate": 5000,
    "tcp_flags": 2,
    "window_size": 65535
}
threats = engine.detect_threats(features)
print(f"Detected {len(threats)} threats")
```

### Example 3: Load Pre-trained Model

```python
import pickle
from detection_engine import DetectionEngine
from config_loader import Config

config = Config()
engine = DetectionEngine(config)

# Load saved model
with open('anomaly_detector_model.pkl', 'rb') as f:
    engine.anomaly_detector = pickle.load(f)
    engine.is_trained = True

print("Model loaded and ready!")
```

## Training Data Requirements

### Minimum
- **At least 10 samples** (1 packet minimum)
- Captures should be **representative** of your network
- Should include **normal, regular traffic patterns**

### Recommended
- **500-1000 samples** (5-10 minutes of typical traffic)
- Captures during **regular business hours**
- Include **various network activities** (web browsing, file transfers, etc.)
- **Multiple training sessions** for robustness

### Best Practice
- Train on **different days/times** to capture variations
- Train on **peak and off-peak traffic**
- Combine multiple training sessions

## Configuration

### Anomaly Thresholds

In `config.json`:

```json
{
  "anomaly_detection": {
    "contamination": 0.1,      // Expected % of anomalies (10%)
    "threshold": -0.5,         // Anomaly score threshold
    "random_state": 42         // For reproducibility
  }
}
```

**Tuning parameters:**
- Lower `contamination` → stricter detection (fewer false positives)
- Lower `threshold` → more sensitive (more detections)

## Workflow

### Step 1: Initial Training

```bash
sudo ./venv/bin/python train_anomaly_detector.py -d 300
```

This trains on 5 minutes of normal traffic.

### Step 2: Verify Training

Check the output statistics:
```
Training Statistics:
  Min packet size: 40 bytes
  Max packet size: 1500 bytes
  Avg packet size: 452 bytes
  Min packet rate: 2.50 pps
  Max packet rate: 89.30 pps
  Avg packet rate: 23.45 pps
  ...
```

### Step 3: Save and Use

The trained model is automatically saved to `anomaly_detector_model.pkl`

### Step 4: Run IDS with Trained Model

```bash
# Modify main.py or detection_engine.py to load the model
# Then run:
sudo ./venv/bin/python main.py
```

## Advanced: Integration with Main IDS

To use training in production:

1. **Train offline** on normal network traffic
2. **Save the model** (automatically created as `anomaly_detector_model.pkl`)
3. **Load on startup** - Modify `main.py`:

```python
import pickle

class IntrusionDetectionSystem:
    def __init__(self, interface=None, config_path="config.json"):
        # ... existing code ...
        
        # Load pre-trained model if available
        try:
            with open('anomaly_detector_model.pkl', 'rb') as f:
                self.detection_engine.anomaly_detector = pickle.load(f)
                self.detection_engine.is_trained = True
            print("✓ Loaded pre-trained anomaly detector")
        except FileNotFoundError:
            print("⚠ No pre-trained model found.")
            print("  Run: sudo python train_anomaly_detector.py")
```

## Troubleshooting

### Problem: "Not enough samples"
**Solution**: Increase training duration with `-d` flag
```bash
sudo ./venv/bin/python train_anomaly_detector.py -d 600
```

### Problem: "No packets captured"
**Solution**: Verify interface and network traffic
```bash
# Check available interfaces
ip link show

# Monitor traffic on interface
sudo tcpdump -i enp2s0
```

### Problem: False positives (too many alerts)
**Solution**: Retrain with more normal traffic samples
```bash
# Train for longer duration (10 minutes)
sudo ./venv/bin/python train_anomaly_detector.py -d 600

# Adjust config.json threshold
# Increase threshold (e.g., -0.3) for less sensitivity
```

### Problem: Not detecting anomalies
**Solution**: Retrain with appropriate normal traffic
```bash
# Make sure to capture typical network patterns
sudo ./venv/bin/python train_anomaly_detector.py -d 900
```

## Testing Training

To verify your training worked:

```bash
# Run examples
./venv/bin/python anomaly_detector_examples.py

# Run tests
./venv/bin/python -m pytest test_ids.py::TestDetectionEngine::test_anomaly_detection_training -v
```

## Performance Metrics

After training, you'll see:

```
Training Statistics:
  Min/Max/Avg packet_size
  Min/Max/Avg packet_rate  
  Min/Max/Avg byte_rate
```

Use these to understand your normal traffic baseline. Values significantly outside these ranges indicate anomalies.

## Files Created/Modified

- `train_anomaly_detector.py` - Main training script
- `anomaly_detector_examples.py` - Example usage code
- `anomaly_detector_model.pkl` - Saved trained model (created after training)

## Next Steps

1. Train the anomaly detector on your network
2. Test with example data: `./venv/bin/python anomaly_detector_examples.py`
3. Integrate trained model into main IDS
4. Monitor alerts and tune if needed
5. Retrain periodically as traffic patterns change

---

For more details, see [README.md](README.md) and the docstrings in `detection_engine.py`.
