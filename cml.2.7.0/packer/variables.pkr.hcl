// General settings
variable "aws_region" {
  type        = string
  default     = "us-east-2"
  description = "AWS region for building the AMI"
}

variable "instance_type" {
  type        = string
  default     = "c5.2xlarge"
  description = "Instance type to use for building the AMI"
}

variable "source_ami" {
  type        = string
  description = "The source AMI ID for the Ubuntu base image (ensure region matches)"
  # Ubuntu Server 22.04 LTS (HVM), SSD Volume Type - Hardened
  # default = "ami-08c18c49bdb7f38f7"
  # Ubuntu Server 20.04 LTS (HVM), SSD Volume Type - Via SSM Parameter 2025-04-16
  default = "ami-014d2a8190b1bdeb4"
}

variable "ssh_username" {
  type        = string
  default     = "ubuntu"
  description = "SSH username for the source AMI"
}

// CML specific settings
variable "cml_version" {
  type        = string
  default     = "2.8.1-14"
  description = "CML version to install"
}

variable "cml_package_url" {
  type        = string
  default     = ""
  description = "URL to download CML package (leave empty to use local file or S3)"
}

variable "cml_s3_bucket" {
  type        = string
  default     = ""
  description = "S3 bucket containing CML package (optional)"
}

variable "cml_s3_key" {
  type        = string
  default     = ""
  description = "S3 key for CML package (optional)"
}

// AMI settings
variable "ami_name_prefix" {
  type        = string
  default     = "cml-controller"
  description = "Prefix for the AMI name"
}

variable "ami_description" {
  type        = string
  description = "Description for the created AMI"
  # default     = "Cisco CML 2.7.0 on Ubuntu 22.04 LTS - Built with Packer"
  default = "Cisco CML 2.7.0 on Ubuntu 20.04 LTS - Built with Packer"
}

variable "ami_tags" {
  type        = map(string)
  description = "Tags to apply to the created AMI"
  default = {
    "Name"        = "CML 2.7.0 AMI (Packer)"
    "OS"          = "Ubuntu"
    "OS_Version"  = "20.04 LTS"
    "Base_AMI_ID" = "ami-014d2a8190b1bdeb4"
  }
}

variable "volume_size" {
  type        = number
  default     = 50
  description = "Root volume size in GB"
}

variable "volume_type" {
  type        = string
  default     = "gp3"
  description = "Root volume type"
}

variable "encrypt_boot" {
  type        = bool
  default     = true
  description = "Whether to encrypt the boot volume"
}
