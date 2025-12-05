# Running RAPTOR on Google Cloud

Yes, you can absolutely run RAPTOR on Google Cloud instead of using the DevContainer locally! This is especially useful for Chromebooks or systems with limited resources.

**💰 Cost Savings Tip:** This guide defaults to **SPOT instances** (preemptible VMs) which are **60-90% cheaper** than regular instances. Perfect for batch security scanning jobs!

## Google Cloud Options

### Option 1: Cloud Shell (Free, Quick Start) ⚡

**Best for:** Quick testing, learning, small scans

**Limitations:**
- 5GB persistent disk (may be tight for CodeQL databases)
- Limited to 20 hours/week
- No root access (some tools may not work)
- No `rr` debugger support (requires privileged mode)

**Setup:**
```bash
# 1. Open Google Cloud Shell (https://shell.cloud.google.com)
# 2. Clone RAPTOR
git clone https://github.com/gadievron/raptor.git
cd raptor/raptor

# 3. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
pip install semgrep

# 5. Set API key
export ANTHROPIC_API_KEY=your_key_here

# 6. Run RAPTOR
python raptor.py scan --repo /path/to/code
```

**What works:**
- ✅ Static analysis (Semgrep)
- ✅ CodeQL (if you download CLI)
- ✅ LLM analysis
- ✅ Web scanning
- ❌ Binary fuzzing (AFL++ needs root)
- ❌ Crash analysis with `rr` (needs privileged mode)

---

### Option 2: Compute Engine VM (Recommended) 🚀

**Best for:** Full RAPTOR capabilities, production use

**Advantages:**
- Full root access
- Persistent storage (as much as you need)
- All features work
- **SPOT instances save 60-90% on compute costs** (default recommendation)

**Setup:**

1. **Create a VM instance (SPOT/preemptible by default for cost savings):**
```bash
# Using gcloud CLI - SPOT instance (60-90% cheaper!)
gcloud compute instances create raptor-vm \
  --zone=us-central1-a \
  --machine-type=e2-standard-4 \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB \
  --boot-disk-type=pd-standard \
  --provisioning-model=SPOT \
  --instance-termination-action=STOP
```

**Note:** SPOT instances can be interrupted, but with `--instance-termination-action=STOP`, your VM will be stopped (not deleted) and can be restarted. All your data and RAPTOR installation persist on the disk.

2. **SSH into the VM:**
```bash
gcloud compute ssh raptor-vm --zone=us-central1-a
```

3. **Install RAPTOR:**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and build tools
sudo apt install -y python3 python3-pip python3-venv git build-essential

# Clone RAPTOR
git clone https://github.com/gadievron/raptor.git
cd raptor/raptor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install semgrep

# Install optional tools as needed
sudo apt install -y afl++ gdb binutils

# For CodeQL (download manually)
wget https://github.com/github/codeql-cli-binaries/releases/download/v2.15.5/codeql-linux64.zip
unzip codeql-linux64.zip
export PATH=$PATH:$(pwd)/codeql

# Set API key
export ANTHROPIC_API_KEY=your_key_here
```

4. **Test it:**
```bash
python raptor.py --help
```

**Cost estimate (SPOT instances - default):**
- e2-standard-4 SPOT (4 vCPU, 16GB RAM): **~$0.05/hour** (60-90% savings!)
- e2-standard-4 Regular: ~$0.15/hour (only if you need guaranteed availability)
- Storage: ~$0.17/GB/month (persists even when VM is stopped)

**Cost comparison for 8-hour scan:**
- SPOT instance: ~$0.40
- Regular instance: ~$1.20
- **Savings: ~$0.80 per scan (67% cheaper)**

---

### Option 3: Cloud Workstations (New, Managed) 💼

**Best for:** Development environment with IDE access

**Advantages:**
- Pre-configured development environment
- VS Code/Cursor access via browser
- Persistent storage
- Easy to start/stop

**Setup:**
1. Create a Cloud Workstation in Google Cloud Console
2. Choose Ubuntu image
3. Install RAPTOR same as Compute Engine
4. Access via browser-based IDE

**Cost:** Similar to Compute Engine, but with management overhead

---

### Option 4: Cloud Run Jobs (For Batch Processing) 📦

**Best for:** Automated scanning, CI/CD integration

**Limitations:**
- Containerized (need to build Docker image)
- No persistent storage between runs
- Time limits (up to 24 hours)

**Setup:**
1. Create Dockerfile based on `.devcontainer/Dockerfile`
2. Build and push to Container Registry
3. Create Cloud Run Job
4. Trigger via API or schedule

---

## Recommended Setup for Chromebook

**For most users, I recommend:**

1. **Start with Cloud Shell** (free, quick)
   - Test basic functionality
   - See if it meets your needs

2. **Upgrade to Compute Engine SPOT instance** (recommended for cost savings):
   - Full fuzzing capabilities
   - Crash analysis with `rr`
   - Large codebase analysis
   - Persistent storage
   - **60-90% cheaper than regular instances**
   
   ```bash
   # SPOT instance (default - saves 60-90% on compute costs)
   gcloud compute instances create raptor-vm \
     --zone=us-central1-a \
     --machine-type=e2-standard-4 \
     --provisioning-model=SPOT \
     --instance-termination-action=STOP \
     --image-family=ubuntu-2204-lts \
     --image-project=ubuntu-os-cloud \
     --boot-disk-size=50GB
   ```
   
   **If you need guaranteed availability** (no interruptions), use regular instances:
   ```bash
   # Regular instance (more expensive, but no interruptions)
   gcloud compute instances create raptor-vm \
     --zone=us-central1-a \
     --machine-type=e2-standard-4 \
     --image-family=ubuntu-2204-lts \
     --image-project=ubuntu-os-cloud \
     --boot-disk-size=50GB
   ```

## Cost Optimization Tips

1. **Use SPOT instances by default** (60-90% cheaper than regular instances)
   - SPOT instances can be interrupted, but with `--instance-termination-action=STOP`, your work is preserved
   - All data persists on disk - just restart the VM if interrupted
   - Perfect for batch jobs like security scanning

2. **Use Google Cloud Storage (GCS) for durable storage** (87% cheaper than VM disk!)
   - Sync RAPTOR outputs to GCS for durability and accessibility
   - Survives VM interruptions and deletions
   - Access results from any device (including Chromebook)
   - See `docs/GCS_STORAGE.md` for complete guide
   ```bash
   # Quick sync after scan
   export RAPTOR_GCS_BUCKET=gs://your-bucket-name
   ./scripts/sync_to_gcs.sh
   ```

2. **Use GCS for long-term storage** (87% cheaper: ~$0.020/GB/month vs ~$0.17/GB/month)
   - Sync results to GCS, then delete from VM disk
   - See `docs/GCS_STORAGE.md` for setup

3. **Stop VMs when not in use** (only pay for storage, ~$0.17/GB/month)
   ```bash
   gcloud compute instances stop raptor-vm --zone=us-central1-a
   gcloud compute instances start raptor-vm --zone=us-central1-a  # When needed
   ```

4. **Use smaller machine types** for basic scanning (e2-standard-2 SPOT: ~$0.025/hour)
   ```bash
   --machine-type=e2-standard-2 --provisioning-model=SPOT
   ```

5. **Clean up CodeQL databases** regularly (auto-cleanup after 7 days)
   ```bash
   find codeql_dbs/ -type d -mtime +7 -exec rm -rf {} +
   # Or sync to GCS first, then delete locally
   ./scripts/sync_to_gcs.sh && find codeql_dbs/ -type d -mtime +7 -exec rm -rf {} +
   ```

6. **Use Cloud Shell** for quick tests (free tier, no compute costs)

7. **Handle SPOT interruptions gracefully:**
   - Use `--instance-termination-action=STOP` (not DELETE) to preserve data
   - **Sync to GCS before long scans** for extra durability
   - Save work frequently to disk (RAPTOR auto-saves to `out/` directory)
   - Restart VM if interrupted: `gcloud compute instances start raptor-vm --zone=us-central1-a`
   - Restore from GCS if needed: `gsutil -m rsync -r gs://your-bucket/out/ ./out/`
   - For long-running scans, consider breaking into smaller chunks

## Transferring Files

**From Chromebook to Cloud VM:**
```bash
# Using gcloud
gcloud compute scp local-file.txt raptor-vm:~/ --zone=us-central1-a

# Or use Cloud Shell's file upload feature
```

**From Cloud VM to Chromebook:**
```bash
# Download results
gcloud compute scp raptor-vm:~/raptor/out/ ./ --zone=us-central1-a --recurse
```

## Security Considerations

1. **API Keys:** Store in Secret Manager, not in code
   ```bash
   # Store secret
   echo -n "your-api-key" | gcloud secrets create anthropic-api-key --data-file=-
   
   # Use in VM
   export ANTHROPIC_API_KEY=$(gcloud secrets versions access latest --secret="anthropic-api-key")
   ```

2. **Firewall Rules:** Restrict SSH access to your IP
3. **IAM:** Use service accounts with minimal permissions

## Troubleshooting

**Issue: SPOT instance was interrupted**
- Solution: This is normal! Your data is safe on disk
```bash
# Check if VM is stopped
gcloud compute instances describe raptor-vm --zone=us-central1-a | grep status

# Restart the VM
gcloud compute instances start raptor-vm --zone=us-central1-a

# SSH back in and continue where you left off
gcloud compute ssh raptor-vm --zone=us-central1-a
```
- **Tip:** RAPTOR saves all results to `out/` directory, so you won't lose scan results
- **Tip:** For very long scans, consider breaking into smaller chunks or using regular instances

**Issue: "No space left on device"**
- Solution: Increase disk size or clean up old databases
```bash
# Check disk usage
df -h
# Clean old CodeQL databases
find codeql_dbs/ -type d -mtime +7 -exec rm -rf {} +
# Increase disk size (requires stopping VM first)
gcloud compute disks resize raptor-vm --size=100GB --zone=us-central1-a
```

**Issue: AFL++ not working**
- Solution: Ensure VM has root access and proper permissions
```bash
sudo sysctl -w kernel.core_pattern=core
```

**Issue: CodeQL slow**
- Solution: Increase VM RAM (CodeQL uses 8GB by default)
- Or reduce RAM usage in config:
```python
CODEQL_RAM_MB = 4096  # Use 4GB instead of 8GB
```

## Next Steps

1. Choose your Google Cloud option
2. Set up billing (free tier available)
3. Create VM or use Cloud Shell
4. Follow installation steps above
5. Start scanning!

For questions or issues, check the main RAPTOR documentation or GitHub issues.
