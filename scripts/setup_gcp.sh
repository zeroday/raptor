#!/bin/bash
# Quick setup script for RAPTOR on Google Cloud (Compute Engine or Cloud Shell)
# Usage: bash setup_gcp.sh
#
# 💰 Cost Tip: Use SPOT instances for 60-90% cost savings!
#   gcloud compute instances create raptor-vm \
#     --zone=us-central1-a \
#     --machine-type=e2-standard-4 \
#     --provisioning-model=SPOT \
#     --instance-termination-action=STOP \
#     --image-family=ubuntu-2204-lts \
#     --image-project=ubuntu-os-cloud \
#     --boot-disk-size=50GB

set -e

echo "🦅 RAPTOR Google Cloud Setup"
echo "============================"
echo ""

# Check if running on Google Cloud
if [ -f /etc/google_instance_id ] || [ -n "$CLOUD_SHELL" ]; then
    echo "✓ Detected Google Cloud environment"
else
    echo "⚠️  Not running on Google Cloud, but continuing anyway..."
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Installing Python3..."
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv
fi

# Check Git
if ! command -v git &> /dev/null; then
    echo "Installing Git..."
    sudo apt install -y git
fi

# Clone RAPTOR if not already present
if [ ! -d "raptor" ]; then
    echo "Cloning RAPTOR repository..."
    git clone https://github.com/gadievron/raptor.git
    cd raptor/raptor
else
    cd raptor/raptor 2>/dev/null || cd .
fi

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate and install dependencies
echo "Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install semgrep

# Install optional tools (with user confirmation)
echo ""
read -p "Install optional tools? (AFL++, GDB, CodeQL) [y/N]: " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Installing optional tools..."
    sudo apt update
    sudo apt install -y afl++ gdb binutils build-essential
    
    # CodeQL (manual download)
    read -p "Download CodeQL CLI? (~500MB) [y/N]: " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        CODEQL_VERSION="v2.15.5"
        CODEQL_URL="https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/codeql-linux64.zip"
        echo "Downloading CodeQL ${CODEQL_VERSION}..."
        wget -q "$CODEQL_URL" -O /tmp/codeql.zip
        unzip -q /tmp/codeql.zip -d ~/
        rm /tmp/codeql.zip
        echo "export PATH=\$PATH:~/codeql" >> ~/.bashrc
        echo "✓ CodeQL installed to ~/codeql"
    fi
fi

# Check API key
echo ""
if [ -z "$ANTHROPIC_API_KEY" ] && [ -z "$OPENAI_API_KEY" ]; then
    echo "⚠️  No LLM API key detected!"
    echo "Set one with:"
    echo "  export ANTHROPIC_API_KEY=your_key_here"
    echo "  # OR"
    echo "  export OPENAI_API_KEY=your_key_here"
    echo ""
    echo "For Google Cloud Secret Manager:"
    echo "  export ANTHROPIC_API_KEY=\$(gcloud secrets versions access latest --secret=anthropic-api-key)"
else
    echo "✓ API key detected"
fi

# Final instructions
echo ""
echo "✅ Setup complete!"
echo ""
echo "To use RAPTOR:"
echo "  1. Activate virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  2. Set API key (if not already set):"
echo "     export ANTHROPIC_API_KEY=your_key_here"
echo ""
echo "  3. Run RAPTOR:"
echo "     python raptor.py agentic --repo /path/to/code"
echo ""
echo "For more options, see: python raptor.py --help"
echo ""
