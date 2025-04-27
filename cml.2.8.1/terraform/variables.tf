// variables.tf for CML 2.8.1 AWS deployment

variable "aws_region" {
  description = "AWS region to deploy CML."
  type        = string
}

variable "cml_ami_id" {
  description = "AMI ID for CML 2.8.1 built by Packer."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type for CML."
  type        = string
  default     = "m5.large"
}
// Add more variables as needed
