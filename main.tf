#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  raw_cfg = yamldecode(file(var.cfg_file))
  cfg = merge(
    {
      for k, v in local.raw_cfg : k => v if k != "secret"
    },
    {
      secrets = module.secrets.secrets
    }
  )
  extras = var.cfg_extra_vars == null ? "" : (
    fileexists(var.cfg_extra_vars) ? file(var.cfg_extra_vars) : var.cfg_extra_vars
  )
}

module "secrets" {
  source = "./modules/secrets"
  cfg    = local.raw_cfg
}

module "deploy" {
  source                = "./modules/deploy"
  cfg                   = local.cfg
  extras                = local.extras
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
module "ready" {
  source = "./modules/readyness"
  depends_on = [
    module.deploy.public_ip
  ]
}
