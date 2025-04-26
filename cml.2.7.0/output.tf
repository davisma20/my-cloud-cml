#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

output "cml_controller" {
  value = {
    "address" : module.deploy.public_ip
    "url" : "https://${module.deploy.public_ip}"
    "alt_url" : "https://${module.deploy.public_ip}:443"
    "alt_address_url" : "https://${module.deploy.public_ip}"
    "ssh" : "ssh -p 1122 sysadmin@${module.deploy.public_ip}"
    "username" : "admin"
  }
}

output "cml2secrets" {
  value     = local.cfg.secrets
  sensitive = true
}

output "devnet_workstation" {
  value = {
    "address" : try(module.deploy.module.aws[0].aws_instance.devnet_workstation[0].public_ip, "N/A")
    "rdp_url" : try("rdp://${module.deploy.module.aws[0].aws_instance.devnet_workstation[0].public_ip}:3389", "N/A")
    "username" : "admin"
    "rdp_password" : "1234QWer!"
  }
  description = "DevNet workstation connection information"
}

output "deployment_summary" {
  value = <<-EOT
    
    ====== DEPLOYMENT SUMMARY ======
    
    CML Controller:
    - URL: https://${module.deploy.public_ip}
    - SSH: ssh -p 1122 sysadmin@${module.deploy.public_ip}
    - Username: admin
    
    DevNet Workstation:
    - RDP: rdp://${try(module.deploy.module.aws[0].aws_instance.devnet_workstation[0].public_ip, "N/A")}:3389
    - Username: admin
    - Password: 1234QWer!
    
    Use the verify_connectivity.sh script from the DevNet workstation to confirm connectivity to CML.
  EOT
}
