# Using Google Cloud Storage (GCS) for Durable Storage

Yes! You can absolutely use Google Cloud Storage (GCS) for more durable storage of RAPTOR outputs. This is especially important when using SPOT instances, which can be interrupted.

## Why Use GCS?

**Benefits:**
- ✅ **Durability**: 99.999999999% (11 nines) durability
- ✅ **Survives VM interruptions**: SPOT instances can be stopped, but GCS persists
- ✅ **Accessible from anywhere**: Download results from any device
- ✅ **Cost-effective**: ~$0.020/GB/month (Standard storage)
- ✅ **Versioning**: Keep history of scans
- ✅ **Lifecycle policies**: Auto-archive old results

**Cost comparison:**
- VM disk storage: ~$0.17/GB/month
- GCS Standard: ~$0.020/GB/month (87% cheaper!)
- GCS Nearline (30+ days): ~$0.010/GB/month (94% cheaper!)

---

## Quick Setup

### 1. Create a GCS Bucket

```bash
# Set your project and bucket name
export PROJECT_ID=your-project-id
export BUCKET_NAME=raptor-results-$(date +%s)

# Create bucket
gsutil mb -p $PROJECT_ID -l us-central1 gs://$BUCKET_NAME

# Set lifecycle policy (optional - auto-archive after 90 days)
cat > lifecycle.json <<EOF
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "SetStorageClass", "storageClass": "NEARLINE"},
        "condition": {"age": 90}
      }
    ]
  }
}
EOF
gsutil lifecycle set lifecycle.json gs://$BUCKET_NAME
```

### 2. Install gsutil (if not already installed)

```bash
# On the VM
sudo apt install -y gsutil
# OR use Cloud SDK
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
gcloud init
```

### 3. Sync RAPTOR Outputs to GCS

**Option A: Manual sync after scans**
```bash
# After running RAPTOR
gsutil -m rsync -r out/ gs://$BUCKET_NAME/out/
gsutil -m rsync -r codeql_dbs/ gs://$BUCKET_NAME/codeql_dbs/
```

**Option B: Automatic sync script** (see `scripts/sync_to_gcs.sh`)

**Option C: Mount GCS as filesystem** (see below)

---

## Automatic Sync Script

Use the provided script to automatically sync outputs:

```bash
# Make executable
chmod +x scripts/sync_to_gcs.sh

# Set bucket name
export RAPTOR_GCS_BUCKET=gs://your-bucket-name

# Run sync (after RAPTOR scan)
./scripts/sync_to_gcs.sh
```

The script:
- Syncs `out/` directory (all scan results)
- Syncs `codeql_dbs/` directory (CodeQL databases)
- Uses parallel uploads for speed (`-m` flag)
- Preserves timestamps and permissions
- Skips already-uploaded files

---

## Mount GCS as Filesystem (Advanced)

For seamless integration, mount GCS as a local filesystem:

### Using gcsfuse

```bash
# Install gcsfuse
export GCSFUSE_REPO=gcsfuse-`lsb_release -c -s`
echo "deb http://packages.cloud.google.com/apt $GCSFUSE_REPO main" | sudo tee /etc/apt/sources.list.d/gcsfuse.list
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
sudo apt-get update
sudo apt-get install -y gcsfuse

# Create mount point
sudo mkdir -p /mnt/gcs-raptor
sudo chown $USER:$USER /mnt/gcs-raptor

# Mount bucket
gcsfuse --implicit-dirs $BUCKET_NAME /mnt/gcs-raptor

# Use as RAPTOR output directory
export RAPTOR_OUT_DIR=/mnt/gcs-raptor/out
python raptor.py agentic --repo /path/to/code
```

**Note:** gcsfuse has some limitations:
- Slower than local disk (network latency)
- Not recommended for CodeQL databases (large files)
- Better for final results than working directories

---

## Recommended Architecture

### Hybrid Approach (Best Performance + Durability)

1. **Work on local disk** (fast)
   ```bash
   # RAPTOR writes to local disk
   python raptor.py agentic --repo /path/to/code
   ```

2. **Sync to GCS periodically** (durable)
   ```bash
   # After scan completes
   ./scripts/sync_to_gcs.sh
   ```

3. **Clean up local disk** (save space)
   ```bash
   # Keep only recent results locally
   find out/ -type d -mtime +7 -exec rm -rf {} +
   ```

### Full GCS Approach (Maximum Durability)

1. **Mount GCS for outputs**
   ```bash
   gcsfuse $BUCKET_NAME /mnt/gcs-raptor
   export RAPTOR_OUT_DIR=/mnt/gcs-raptor/out
   ```

2. **Keep CodeQL databases local** (they're large and frequently accessed)
   ```bash
   # CodeQL databases stay on local disk
   # Only sync final results to GCS
   ```

---

## Integration with SPOT Instances

### Setup Script for SPOT VMs

```bash
#!/bin/bash
# setup_raptor_gcs.sh

# Set your bucket
export RAPTOR_GCS_BUCKET=gs://your-bucket-name

# Install gsutil
sudo apt install -y gsutil

# Download sync script
curl -o sync_to_gcs.sh https://raw.githubusercontent.com/gadievron/raptor/main/scripts/sync_to_gcs.sh
chmod +x sync_to_gcs.sh

# Create startup script to restore from GCS
cat > restore_from_gcs.sh <<'EOF'
#!/bin/bash
if [ -n "$RAPTOR_GCS_BUCKET" ]; then
    echo "Restoring previous results from GCS..."
    gsutil -m rsync -r $RAPTOR_GCS_BUCKET/out/ out/ || true
    gsutil -m rsync -r $RAPTOR_GCS_BUCKET/codeql_dbs/ codeql_dbs/ || true
fi
EOF
chmod +x restore_from_gcs.sh

# Add to .bashrc
echo "export RAPTOR_GCS_BUCKET=$RAPTOR_GCS_BUCKET" >> ~/.bashrc
```

### Handling SPOT Interruptions

1. **Before interruption**: Results are synced to GCS
2. **After restart**: Restore from GCS
   ```bash
   ./restore_from_gcs.sh
   ```

3. **Continue work**: RAPTOR can resume from where it left off

---

## Cost Optimization

### Storage Classes

Choose the right storage class based on access patterns:

| Storage Class | Cost/GB/Month | Use Case |
|--------------|---------------|-----------|
| **Standard** | $0.020 | Frequently accessed results |
| **Nearline** | $0.010 | Results accessed <1x/month |
| **Coldline** | $0.004 | Archive (90+ days old) |
| **Archive** | $0.0012 | Long-term archive (365+ days) |

### Lifecycle Policies

Auto-transition to cheaper storage:

```json
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "SetStorageClass", "storageClass": "NEARLINE"},
        "condition": {"age": 30}
      },
      {
        "action": {"type": "SetStorageClass", "storageClass": "COLDLINE"},
        "condition": {"age": 90}
      },
      {
        "action": {"type": "SetStorageClass", "storageClass": "ARCHIVE"},
        "condition": {"age": 365}
      }
    ]
  }
}
```

Apply:
```bash
gsutil lifecycle set lifecycle.json gs://$BUCKET_NAME
```

### Cleanup Old Results

```bash
# Delete results older than 90 days
gsutil -m rm -r gs://$BUCKET_NAME/out/scan_*$(date -d '90 days ago' +%Y%m%d)*
```

---

## Accessing Results from Chromebook

### Download Results

```bash
# Download specific scan
gsutil -m cp -r gs://$BUCKET_NAME/out/scan_myrepo_20241204/ ./

# Download all results
gsutil -m rsync -r gs://$BUCKET_NAME/out/ ./raptor-results/
```

### View in Browser

```bash
# Make results publicly viewable (if desired)
gsutil iam ch allUsers:objectViewer gs://$BUCKET_NAME

# Access via: https://console.cloud.google.com/storage/browser/$BUCKET_NAME
```

### Stream Results

```bash
# Stream SARIF file
gsutil cat gs://$BUCKET_NAME/out/scan_myrepo_20241204/combined.sarif | jq .
```

---

## Security Best Practices

### 1. Use IAM Instead of Public Access

```bash
# Grant access to specific user
gsutil iam ch user:your-email@example.com:objectViewer gs://$BUCKET_NAME

# Use service account for VM
gcloud iam service-accounts create raptor-sa
gsutil iam ch serviceAccount:raptor-sa@$PROJECT_ID.iam.gserviceaccount.com:objectAdmin gs://$BUCKET_NAME
```

### 2. Encrypt Sensitive Results

```bash
# Enable bucket encryption
gsutil encryption set on gs://$BUCKET_NAME

# Or use customer-managed keys
gsutil encryption set -k projects/$PROJECT_ID/locations/global/keyRings/raptor-keys/cryptoKeys/raptor-key gs://$BUCKET_NAME
```

### 3. Access Logs

```bash
# Enable access logging
gsutil logging set on -b gs://access-logs gs://$BUCKET_NAME
```

---

## Example Workflow

```bash
# 1. Create bucket
export BUCKET_NAME=raptor-results-$(date +%s)
gsutil mb -p $PROJECT_ID gs://$BUCKET_NAME
export RAPTOR_GCS_BUCKET=gs://$BUCKET_NAME

# 2. Run RAPTOR (outputs to local disk)
python raptor.py agentic --repo /path/to/code

# 3. Sync to GCS
./scripts/sync_to_gcs.sh

# 4. Verify upload
gsutil ls -r gs://$BUCKET_NAME/out/

# 5. Download to Chromebook
gsutil -m rsync -r gs://$BUCKET_NAME/out/ ./raptor-results/
```

---

## Troubleshooting

**Issue: "Access Denied"**
```bash
# Check permissions
gsutil iam get gs://$BUCKET_NAME

# Grant access
gsutil iam ch user:your-email@example.com:objectAdmin gs://$BUCKET_NAME
```

**Issue: "Slow uploads"**
```bash
# Use parallel uploads (already in sync script)
gsutil -m rsync -r out/ gs://$BUCKET_NAME/out/

# Or increase parallelism
gsutil -m -o GSUtil:parallel_composite_upload_threshold=150M rsync -r out/ gs://$BUCKET_NAME/out/
```

**Issue: "Out of space on VM"**
```bash
# Sync to GCS first
./scripts/sync_to_gcs.sh

# Then clean local disk
rm -rf out/scan_*$(date -d '7 days ago' +%Y%m%d)*
```

---

## Next Steps

1. Create your GCS bucket
2. Set `RAPTOR_GCS_BUCKET` environment variable
3. Use `scripts/sync_to_gcs.sh` after each scan
4. Set up lifecycle policies for cost optimization
5. Download results to your Chromebook when needed

For more information, see:
- [GCS Documentation](https://cloud.google.com/storage/docs)
- [gsutil Documentation](https://cloud.google.com/storage/docs/gsutil)
- [gcsfuse Documentation](https://cloud.google.com/storage/docs/gcs-fuse)
