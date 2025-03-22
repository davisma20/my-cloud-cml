#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

output "cml2info" {
  value = {
    "address" : module.deploy.public_ip
    "del" : nonsensitive("ssh -p1122 ${local.cfg.secrets.sys.username}@${module.deploy.public_ip} /provision/del.sh")
    "url" : "https://${module.deploy.public_ip}"
    "version" : module.ready.state.version
  }
}

output "cml2secrets" {
  value     = local.cfg.secrets
  sensitive = true
}

output "devnet_workstation" {
  value = {
    "address" : module.deploy.workstation_ip
    "rdp_url" : "rdp://${module.deploy.workstation_ip}:3389"
    "rdp_username" : "admin"
    "rdp_password" : nonsensitive("1234QWer!")
  }
  description = "DevNet workstation connection information"
}

output "deployment_summary" {
  value = <<-EOT
    
    =================================================================
    DEPLOYMENT COMPLETE - SUMMARY
    =================================================================
    
    CML DEPLOYMENT:
    - URL: https://${module.deploy.public_ip}
    - Username: ${local.cfg.secrets.app.username}
    - Password: [Available in Terraform state]
    - SSH: ssh -p1122 ${local.cfg.secrets.sys.username}@${module.deploy.public_ip}
    
    DEVNET WORKSTATION:
    - IP Address: ${module.deploy.workstation_ip}
    - RDP: ${module.deploy.workstation_ip}:3389
    - Username: admin
    - Password: 1234QWer!
    
    CONNECTIVITY VERIFICATION:
    - From DevNet workstation to CML: ping ${module.deploy.public_ip}
    - Web access to CML from workstation: https://${module.deploy.public_ip}
    
    =================================================================
  EOT
}
