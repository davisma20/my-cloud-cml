#!/bin/bash
set -e

# Build and Deploy Network-Validated CML AMI
# This script automates the process of:
# 1. Building the CML network-validated AMI with Packer
# 2. Updating the Terraform configuration with the new AMI ID
# 3. Optionally deploying the infrastructure with Terraform

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKER_DIR="${PROJECT_ROOT}/packer"
TFVARS_FILE="${PACKER_DIR}/network_validated_ami.auto.tfvars"

echo -e "${BLUE}CML Network-Validated AMI Builder and Deployer${NC}"
echo -e "${BLUE}==============================================${NC}"
echo

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"
if ! command -v packer &> /dev/null; then
    echo -e "${RED}Error: Packer is not installed. Please install Packer first.${NC}"
    echo "Visit: https://www.packer.io/downloads"
    exit 1
fi

if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install AWS CLI first.${NC}"
    echo "Visit: https://aws.amazon.com/cli/"
    exit 1
fi

if ! command -v terraform &> /dev/null; then
    echo -e "${YELLOW}Warning: Terraform is not installed. You won't be able to deploy the infrastructure.${NC}"
    echo "Visit: https://www.terraform.io/downloads"
fi

# Check AWS credentials
echo -e "${YELLOW}Checking AWS credentials...${NC}"
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}Error: AWS credentials not configured or not valid.${NC}"
    echo "Run 'aws configure' to set up your AWS credentials."
    exit 1
fi
echo -e "${GREEN}AWS credentials verified.${NC}"
echo

# Build the AMI with Packer
echo -e "${YELLOW}Building CML network-validated AMI with Packer...${NC}"
echo "This may take 30+ minutes. Please be patient."
echo

cd "${PACKER_DIR}"
AMI_JSON_OUTPUT=$(packer build -machine-readable cml-network-validated.pkr.hcl)
AMI_ID=$(echo "${AMI_JSON_OUTPUT}" | grep 'artifact,0,id' | cut -d: -f2)

if [ -z "${AMI_ID}" ]; then
    echo -e "${RED}Error: Failed to extract AMI ID from Packer output.${NC}"
    exit 1
fi

echo -e "${GREEN}Successfully built AMI: ${AMI_ID}${NC}"
echo

# Update the Terraform variables file
echo -e "${YELLOW}Updating Terraform configuration with new AMI ID...${NC}"
sed -i '' "s/cml_ami = \"ami-[a-z0-9]*\"/cml_ami = \"${AMI_ID}\"/" "${TFVARS_FILE}" 2>/dev/null || sed -i "s/cml_ami = \"ami-[a-z0-9]*\"/cml_ami = \"${AMI_ID}\"/" "${TFVARS_FILE}"
echo -e "${GREEN}Updated AMI ID in ${TFVARS_FILE}${NC}"
echo

# Create symlink to auto.tfvars in project root for Terraform to find it
echo -e "${YELLOW}Creating symlink to Terraform variables file...${NC}"
ln -sf "${TFVARS_FILE}" "${PROJECT_ROOT}/network_validated_ami.auto.tfvars"
echo -e "${GREEN}Created symlink in project root.${NC}"
echo

# Prompt for Terraform deployment
echo -e "${YELLOW}Do you want to deploy the infrastructure with Terraform now? (y/n)${NC}"
read -r DEPLOY

if [[ "${DEPLOY}" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Deploying infrastructure with Terraform...${NC}"
    cd "${PROJECT_ROOT}"
    terraform init
    terraform apply -auto-approve
    
    echo -e "${GREEN}Infrastructure deployment completed.${NC}"
    echo -e "${YELLOW}CML instance IP:${NC} $(terraform output -raw public_ip)"
    echo -e "${YELLOW}Access the CML GUI at:${NC} https://$(terraform output -raw public_ip)/login"
    echo
    echo -e "${BLUE}Running post-deployment validation checks...${NC}"
    echo -e "${YELLOW}To manually validate after deployment, SSH to the instance and run:${NC}"
    echo "ssh -i your-key.pem ubuntu@$(terraform output -raw public_ip) 'sudo /provision/post_launch_validation.sh'"
else
    echo -e "${BLUE}Skipping Terraform deployment.${NC}"
    echo -e "${YELLOW}To deploy later, run:${NC}"
    echo "cd ${PROJECT_ROOT}"
    echo "terraform init"
    echo "terraform apply"
fi

echo
echo -e "${GREEN}Process completed successfully!${NC}"
echo -e "${BLUE}Your network-validated CML AMI (${AMI_ID}) is ready to use.${NC}"
