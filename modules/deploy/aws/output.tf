#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

output "public_ip" {
  value = local.cml_enable ? aws_instance.cml_controller[0].public_ip : null
}

output "workstation_ip" {
  value = local.workstation_enable ? aws_instance.devnet_workstation[0].public_ip : null
}

output "sas_token" {
  value = "undefined"
}

output "cml_controller_instance_id" {
  description = "The instance ID of the CML controller"
  value       = local.cml_enable ? aws_instance.cml_controller[0].id : null
}

output "public_subnet_id" {
  value = aws_subnet.public_subnet.id
}

output "sg_tf_id" {
  value = aws_security_group.sg_tf.id
}

output "key_name" {
  value = var.options.cfg.common.key_name
}

output "ami_id" {
  value = local.custom_ami != "" ? local.custom_ami : var.cfg.aws.ami_id
}

output "instance_type" {
  value = var.cfg.aws.flavor
}

output "cml_ssm_profile" {
  value = aws_iam_instance_profile.cml_ssm_profile.name
}
