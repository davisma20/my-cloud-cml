#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

output "public_ip" {
  value = (
    (var.cfg.target == "aws") ?
    module.aws[0].public_ip :
    (var.cfg.target == "azure" ?
      module.azure[0].public_ip :
      "127.0.0.1"
    )
  )
}

output "cml_controller_instance_id" {
  description = "The instance ID of the CML controller (relayed from aws module)"
  value = (
    (var.cfg.target == "aws") ?
    module.aws[0].cml_controller_instance_id :
    null # Or handle other targets appropriately if needed
  )
}

output "public_subnet_id" {
  value = (
    (var.cfg.target == "aws") ?
    module.aws[0].public_subnet_id :
    null
  )
}

output "sg_tf_id" {
  value = (
    (var.cfg.target == "aws") ?
    module.aws[0].sg_tf_id :
    null
  )
}

output "key_name" {
  value = (
    (var.cfg.target == "aws") ?
    module.aws[0].key_name :
    null
  )
}

output "ami_id" {
  value = (
    (var.cfg.target == "aws") ?
    module.aws[0].ami_id :
    null
  )
}

output "instance_type" {
  value = (
    (var.cfg.target == "aws") ?
    module.aws[0].instance_type :
    null
  )
}

output "cml_ssm_profile" {
  value = module.aws[0].cml_ssm_profile
}
