#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

# Common variables

variable "cfg_file" {
  type        = string
  description = "Name of the YAML config file to use"
  default     = "config.yml"
}

variable "cfg_extra_vars" {
  type        = string
  description = "Optional path or string containing extra config data"
  default     = null
}

# Declare the variable automatically set by network_validated_ami.auto.tfvars
variable "cml_ami_id" {
  description = "AMI ID for the CML controller, typically set by the Packer build process via an .auto.tfvars file."
  type        = string
  default     = "" # Default to empty string if not set by auto.tfvars
}

# AWS related vars

variable "aws_access_key" {
  type        = string
  description = "AWS access key / credential for the provisioning user"
  default     = "notset"
}

variable "aws_secret_key" {
  type        = string
  description = "AWS secret key matching the access key"
  default     = "notset"
}

# Azure related vars

variable "azure_subscription_id" {
  type        = string
  description = "Azure subscription ID"
  default     = "notset"
}

variable "azure_tenant_id" {
  type        = string
  description = "Azure tenant ID"
  default     = "notset"
}

# Variables typically set by packer/network_validated_ami.auto.tfvars

variable "aws_region" {
  type        = string
  description = "The AWS region where resources will be deployed. Set via .tfvars."
}

variable "cml_instance_type" {
  type        = string
  description = "The EC2 instance type for the CML controller. Set via .tfvars."
}

variable "enable_enhanced_monitoring" {
  type        = bool
  description = "Flag to enable enhanced CloudWatch monitoring for CML instance. Set via .tfvars."
}

variable "validate_network_on_boot" {
  type        = bool
  description = "Flag to run network validation checks on CML instance boot. Set via .tfvars."
}

variable "ami_id_override" {
  description = "Optional: Specify a custom AMI ID to override the default lookup within the deploy module. Leave empty to use the module's default."
  type        = string
  default     = ""
}
