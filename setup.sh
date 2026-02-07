#!/bin/bash
# Quick setup script for Network Intrusion Detection System

echo "==================================="
echo "IDS Setup Script"
echo "==================================="

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

echo "✓ Python 3 found"

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "Installing dependencies..."
pip install -r requirements.txt

echo ""
echo "==================================="
echo "Setup Complete!"
echo "==================================="
echo ""
echo "To use the IDS:"
echo "1. Activate the virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Run the IDS (requires sudo):"
echo "   sudo venv/bin/python main.py"
echo ""
echo "3. Run tests:"
echo "   python -m pytest test_ids.py -v"
echo ""
echo "4. Deactivate when done:"
echo "   deactivate"
echo ""
