#!/bin/bash
# Restore RAPTOR outputs from Google Cloud Storage
# Usage: ./restore_from_gcs.sh [bucket-name]
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

echo "🦅 RAPTOR GCS Restore"
echo "====================="
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
    echo "  ./restore_from_gcs.sh gs://your-bucket-name"
    echo ""
    echo "Or set environment variable:"
    echo "  export RAPTOR_GCS_BUCKET=gs://your-bucket-name"
    echo "  ./restore_from_gcs.sh"
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
    echo -e "${RED}Error: Bucket $BUCKET_NAME does not exist or is not accessible${NC}"
    exit 1
fi

# Restore outputs
echo "Restoring RAPTOR outputs from $BUCKET_NAME..."
echo ""

# Restore out/ directory
if gsutil ls "$BUCKET_NAME/out/" &> /dev/null; then
    echo -e "${GREEN}Restoring outputs...${NC}"
    mkdir -p "$OUT_DIR"
    gsutil -m rsync -r "$BUCKET_NAME/out/" "$OUT_DIR/" || {
        echo -e "${YELLOW}Warning: Some files may not have restored${NC}"
    }
    echo -e "${GREEN}✓ Outputs restored${NC}"
else
    echo -e "${YELLOW}No outputs found in $BUCKET_NAME/out/${NC}"
fi

# Restore CodeQL databases (optional)
if gsutil ls "$BUCKET_NAME/codeql_dbs/" &> /dev/null; then
    echo ""
    read -p "Restore CodeQL databases? (can be large, 500MB-2GB+) [y/N]: " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Restoring CodeQL databases...${NC}"
        mkdir -p "$CODEQL_DB_DIR"
        gsutil -m rsync -r "$BUCKET_NAME/codeql_dbs/" "$CODEQL_DB_DIR/" || {
            echo -e "${YELLOW}Warning: Error restoring CodeQL databases${NC}"
        }
        echo -e "${GREEN}✓ CodeQL databases restored${NC}"
    else
        echo -e "${YELLOW}Skipping CodeQL databases${NC}"
    fi
fi

# Summary
echo ""
echo "✅ Restore complete!"
echo ""
echo "Results available at:"
echo "  $OUT_DIR"
if [ -d "$CODEQL_DB_DIR" ] && [ "$(ls -A $CODEQL_DB_DIR 2>/dev/null)" ]; then
    echo "  $CODEQL_DB_DIR"
fi
echo ""
