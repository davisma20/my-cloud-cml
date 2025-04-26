#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  raw_cfg = yamldecode(
    fileexists(var.cfg_file) ? file(var.cfg_file) : (fileexists("terraform.tfvars") ? file("terraform.tfvars") : "{}")
  )

  aws_config = merge(
    {
      region       = "us-east-2"
      profile      = "absdevmaster"
      ami_id       = ""
      storage_size = 100 # Match Packer build volume size
    },
    lookup(local.raw_cfg, "aws", {}),
    var.ami_id_override == "" && var.cml_ami_id != "" ? { ami_id = var.cml_ami_id } : {},
    var.ami_id_override != "" ? { ami_id = var.ami_id_override } : {}
  )

  cfg = merge(
    { for k, v in local.raw_cfg : k => v if k != "aws" },
    { aws = local.aws_config },
    {
      secrets = module.secrets.secrets
    }
  )

  extras = var.cfg_extra_vars == null ? "" : (
    fileexists(var.cfg_extra_vars) ? file(var.cfg_extra_vars) : var.cfg_extra_vars
  )

  extras_with_ami = <<-EOT
    %{if var.cml_ami != ""}export AWS_CUSTOM_AMI="${var.cml_ami}"%{endif}
    ${lookup(local.raw_cfg, "extras", "")}
  EOT
}

provider "aws" {
  region  = local.aws_config.region
  # profile = "absdevmaster" # Rely on default credential chain (should pick up SSO)
}

# Variable for Packer-built CML AMI ID
variable "cml_ami" {
  description = "AMI ID for the CML instance, created by Packer"
  type        = string
  default     = "" # Will be overridden by the value in network_validated_ami.auto.tfvars
}

module "secrets" {
  source = "./modules/secrets"
  cfg    = local.raw_cfg
}

module "deploy" {
  source                = "./modules/deploy"
  cfg                   = local.cfg
  extras                = local.extras_with_ami
  azure_subscription_id = var.azure_subscription_id
  azure_tenant_id       = var.azure_tenant_id
}

# Enable CML2 provider for interaction with CML
provider "cml2" {
  address        = "https://${module.deploy.public_ip}"
  username       = "admin"  # Default admin username for CML
  password       = "admin"  # Default initial password for CML
  skip_verify    = true
  dynamic_config = true
}

# Enable the ready module to check CML readiness
# module "ready" {
#   source = "./modules/readyness"
#   depends_on = [
#     module.deploy.public_ip
#   ]
# }

output "cml_controller_instance_id" {
  description = "The instance ID of the CML controller (relayed from deploy module)"
  value       = module.deploy.cml_controller_instance_id
}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

# resource "aws_instance" "cml_cloudinit_test" {
#   ami                    = module.deploy.ami_id
#   instance_type          = module.deploy.instance_type
#   key_name               = module.deploy.key_name
#   subnet_id              = module.deploy.public_subnet_id
#   vpc_security_group_ids = [module.deploy.sg_tf_id]
#   iam_instance_profile   = module.deploy.cml_ssm_profile
#   user_data = file("${path.module}/cloud-init-test.yaml")
# 
#   tags = {
#     Name = "cml-cloudinit-test"
#   }
# }
# 
# resource "aws_instance" "ubuntu_cloudinit_test" {
#   ami                    = data.aws_ami.ubuntu.id
#   instance_type          = module.deploy.instance_type
#   key_name               = module.deploy.key_name
#   subnet_id              = module.deploy.public_subnet_id
#   vpc_security_group_ids = [module.deploy.sg_tf_id]
#   iam_instance_profile   = module.deploy.cml_ssm_profile
#   user_data = file("${path.module}/cloud-init-test.yaml")
# 
#   tags = {
#     Name = "ubuntu-cloudinit-test"
#   }
# }
