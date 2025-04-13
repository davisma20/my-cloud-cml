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
  description = "extra variable definitions, typically empty"
  default     = null
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

variable "cml_ami" {
  type        = string
  description = "The AMI ID for the CML controller instance. Set via .tfvars."
}

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
