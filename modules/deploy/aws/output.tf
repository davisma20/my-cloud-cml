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
