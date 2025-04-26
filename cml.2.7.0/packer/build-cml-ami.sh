#!/bin/bash
# Build script for CML AMI using Packer with SSM access

set -e

# Parse command line arguments
REGION="us-east-2"
INSTANCE_TYPE="c5.2xlarge"
DEBUG=false

while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --region)
      REGION="$2"
      shift 2
      ;;
    --instance-type)
      INSTANCE_TYPE="$2"
      shift 2
      ;;
    --debug)
      DEBUG=true
      shift
      ;;
    --help)
      echo "Usage: $0 [options]"
      echo ""
      echo "Options:"
      echo "  --region REGION        AWS region to build in (default: us-east-2)"
      echo "  --instance-type TYPE   EC2 instance type to use (default: c5.2xlarge)"
      echo "  --debug                Enable debug logging for Packer"
      echo "  --help                 Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Make sure AWS SSM is properly configured
echo "Checking AWS SSM profile availability..."
if ! aws iam get-instance-profile --instance-profile-name AmazonSSMRoleForInstancesQuickSetup &>/dev/null; then
  echo "Warning: AmazonSSMRoleForInstancesQuickSetup instance profile not found."
  echo "The build may fail without the proper SSM profile."
  echo "You may need to create this profile first with proper permissions."
  echo "Continue anyway? (y/n)"
  read -r response
  if [[ "$response" != "y" ]]; then
    echo "Build canceled."
    exit 1
  fi
fi

# Initialize Packer configuration
echo "Initializing Packer..."
packer init cml-simple.pkr.hcl

# Build options
BUILD_OPTS=(-var "region=${REGION}" -var "instance_type=${INSTANCE_TYPE}")

# Add debug logging if requested
if [[ "$DEBUG" == "true" ]]; then
  BUILD_OPTS+=(-debug)
fi

# Start the build
echo "Starting Packer build in region ${REGION} with instance type ${INSTANCE_TYPE}..."
packer build "${BUILD_OPTS[@]}" cml-simple.pkr.hcl

echo "Build complete! Check above for the AMI ID."
