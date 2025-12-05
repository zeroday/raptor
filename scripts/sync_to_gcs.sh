#!/bin/bash
# Sync RAPTOR outputs to Google Cloud Storage
# Usage: ./sync_to_gcs.sh [bucket-name]
#
# Environment variables:
#   RAPTOR_GCS_BUCKET - GCS bucket name (gs://bucket-name)
#   RAPTOR_OUT_DIR - RAPTOR output directory (default: ./out)
#   RAPTOR_CODEQL_DB_DIR - CodeQL databases directory (default: ./codeql_dbs)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🦅 RAPTOR GCS Sync"
echo "==================="
echo ""

# Get bucket name
if [ -n "$1" ]; then
    BUCKET_NAME="$1"
elif [ -n "$RAPTOR_GCS_BUCKET" ]; then
    BUCKET_NAME="$RAPTOR_GCS_BUCKET"
else
    echo -e "${RED}Error: No bucket specified${NC}"
    echo ""
    echo "Usage:"
    echo "  ./sync_to_gcs.sh gs://your-bucket-name"
    echo ""
    echo "Or set environment variable:"
    echo "  export RAPTOR_GCS_BUCKET=gs://your-bucket-name"
    echo "  ./sync_to_gcs.sh"
    exit 1
fi

# Ensure bucket name starts with gs://
if [[ ! "$BUCKET_NAME" =~ ^gs:// ]]; then
    BUCKET_NAME="gs://$BUCKET_NAME"
fi

# Get directories
OUT_DIR="${RAPTOR_OUT_DIR:-./out}"
CODEQL_DB_DIR="${RAPTOR_CODEQL_DB_DIR:-./codeql_dbs}"

# Check if gsutil is installed
if ! command -v gsutil &> /dev/null; then
    echo -e "${RED}Error: gsutil not found${NC}"
    echo ""
    echo "Install with:"
    echo "  sudo apt install -y gsutil"
    echo "  # OR"
    echo "  curl https://sdk.cloud.google.com | bash"
    exit 1
fi

# Check if bucket exists
if ! gsutil ls "$BUCKET_NAME" &> /dev/null; then
    echo -e "${YELLOW}Warning: Bucket $BUCKET_NAME does not exist${NC}"
    read -p "Create it now? [y/N]: " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        PROJECT_ID=$(gcloud config get-value project 2>/dev/null || echo "")
        if [ -z "$PROJECT_ID" ]; then
            echo -e "${RED}Error: No GCP project configured${NC}"
            echo "Run: gcloud config set project YOUR_PROJECT_ID"
            exit 1
        fi
        echo "Creating bucket $BUCKET_NAME..."
        gsutil mb -p "$PROJECT_ID" -l us-central1 "$BUCKET_NAME"
        echo -e "${GREEN}✓ Bucket created${NC}"
    else
        echo "Exiting..."
        exit 1
    fi
fi

# Sync outputs
echo "Syncing RAPTOR outputs to $BUCKET_NAME..."
echo ""

# Sync out/ directory
if [ -d "$OUT_DIR" ] && [ "$(ls -A $OUT_DIR 2>/dev/null)" ]; then
    echo -e "${GREEN}Syncing outputs...${NC}"
    gsutil -m rsync -r -C "$OUT_DIR" "$BUCKET_NAME/out/" || {
        echo -e "${RED}Error syncing outputs${NC}"
        exit 1
    }
    echo -e "${GREEN}✓ Outputs synced${NC}"
else
    echo -e "${YELLOW}No outputs directory found at $OUT_DIR${NC}"
fi

# Sync CodeQL databases (optional, can be large)
if [ -d "$CODEQL_DB_DIR" ] && [ "$(ls -A $CODEQL_DB_DIR 2>/dev/null)" ]; then
    echo ""
    read -p "Sync CodeQL databases? (can be large, 500MB-2GB+) [y/N]: " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Syncing CodeQL databases...${NC}"
        gsutil -m rsync -r -C "$CODEQL_DB_DIR" "$BUCKET_NAME/codeql_dbs/" || {
            echo -e "${YELLOW}Warning: Error syncing CodeQL databases (may be too large)${NC}"
        }
        echo -e "${GREEN}✓ CodeQL databases synced${NC}"
    else
        echo -e "${YELLOW}Skipping CodeQL databases${NC}"
    fi
fi

# Summary
echo ""
echo "✅ Sync complete!"
echo ""
echo "Results available at:"
echo "  $BUCKET_NAME/out/"
if [ -d "$CODEQL_DB_DIR" ] && [ "$(ls -A $CODEQL_DB_DIR 2>/dev/null)" ]; then
    echo "  $BUCKET_NAME/codeql_dbs/"
fi
echo ""
echo "Download with:"
echo "  gsutil -m rsync -r $BUCKET_NAME/out/ ./raptor-results/"
echo ""
