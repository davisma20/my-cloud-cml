#!/bin/bash
# CML AMI Build Script
# This script builds a CML AMI using Packer

set -e

# Default values
CML_VERSION="2.8.1-14"
AWS_REGION="us-east-2"
INSTANCE_TYPE="c5.2xlarge"
SOURCE_AMI="ami-0a0e4ef95325270c9"  # DevNet Expert AMI
CML_PACKAGE_PATH=""
CML_S3_BUCKET=""
CML_S3_KEY=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --cml-version)
      CML_VERSION="$2"
      shift 2
      ;;
    --region)
      AWS_REGION="$2"
      shift 2
      ;;
    --instance-type)
      INSTANCE_TYPE="$2"
      shift 2
      ;;
    --source-ami)
      SOURCE_AMI="$2"
      shift 2
      ;;
    --cml-package)
      CML_PACKAGE_PATH="$2"
      shift 2
      ;;
    --s3-bucket)
      CML_S3_BUCKET="$2"
      shift 2
      ;;
    --s3-key)
      CML_S3_KEY="$2"
      shift 2
      ;;
    --help)
      echo "Usage: $0 [options]"
      echo "Options:"
      echo "  --cml-version VALUE    CML version to install (default: $CML_VERSION)"
      echo "  --region VALUE         AWS region for building (default: $AWS_REGION)"
      echo "  --instance-type VALUE  EC2 instance type (default: $INSTANCE_TYPE)"
      echo "  --source-ami VALUE     Source AMI ID (default: $SOURCE_AMI)"
      echo "  --cml-package PATH     Path to local CML package"
      echo "  --s3-bucket VALUE      S3 bucket containing CML package"
      echo "  --s3-key VALUE         S3 key for CML package"
      echo "  --help                 Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

echo "=========================================================="
echo "Building CML AMI with the following settings:"
echo "=========================================================="
echo "CML Version:    $CML_VERSION"
echo "AWS Region:     $AWS_REGION"
echo "Instance Type:  $INSTANCE_TYPE"
echo "Source AMI:     $SOURCE_AMI"
echo "CML Package:    $CML_PACKAGE_PATH"
echo "S3 Bucket:      $CML_S3_BUCKET"
echo "S3 Key:         $CML_S3_KEY"
echo "=========================================================="

# If a local CML package is specified, upload it to the tmp directory
if [ -n "$CML_PACKAGE_PATH" ] && [ -f "$CML_PACKAGE_PATH" ]; then
  echo "Using local CML package: $CML_PACKAGE_PATH"
  PACKAGE_NAME=$(basename "$CML_PACKAGE_PATH")
  cp "$CML_PACKAGE_PATH" "/tmp/$PACKAGE_NAME"
  echo "Copied package to /tmp/$PACKAGE_NAME"
fi

# Build Packer variables
PACKER_VARS=(
  "-var=aws_region=$AWS_REGION"
  "-var=instance_type=$INSTANCE_TYPE"
  "-var=source_ami=$SOURCE_AMI"
  "-var=cml_version=$CML_VERSION"
)

# Add S3 variables if provided
if [ -n "$CML_S3_BUCKET" ] && [ -n "$CML_S3_KEY" ]; then
  PACKER_VARS+=("-var=cml_s3_bucket=$CML_S3_BUCKET")
  PACKER_VARS+=("-var=cml_s3_key=$CML_S3_KEY")
fi

# Check if Packer is installed
if ! command -v packer &> /dev/null; then
  echo "Error: Packer is not installed. Please install Packer first."
  echo "Visit: https://www.packer.io/downloads"
  exit 1
fi

# Initialize Packer plugins
echo "Initializing Packer plugins..."
packer init cml-controller.pkr.hcl

# Run Packer build
echo "Starting Packer build..."
PACKER_LOG=1 packer build "${PACKER_VARS[@]}" cml-controller.pkr.hcl

# Check build result
if [ $? -eq 0 ]; then
  echo "=========================================================="
  echo "Packer build completed successfully!"
  echo "Check manifest.json for the AMI ID"
  
  # Extract AMI ID from manifest
  if [ -f "manifest.json" ]; then
    AMI_ID=$(jq -r '.builds[-1].artifact_id' manifest.json | cut -d':' -f2)
    echo "AMI ID: $AMI_ID"
    echo ""
    echo "To use this AMI in Terraform, update your variables:"
    echo "aws_cml_ami = \"$AMI_ID\""
  fi
  echo "=========================================================="
else
  echo "Packer build failed."
  exit 1
fi
