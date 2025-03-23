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
  default     = "ami-0a0e4ef95325270c9" // Ubuntu 20.04 DevNet Expert AMI
  description = "Source AMI ID to use as base"
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
  default     = "Cisco Modeling Labs Controller"
  description = "Description for the AMI"
}

variable "ami_tags" {
  type        = map(string)
  default     = {
    OS_Version    = "Ubuntu 20.04"
    Release       = "Latest"
    Base_AMI_Name = "DevNet-Expert-Ubuntu-20.04"
  }
  description = "Tags to apply to the AMI"
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
