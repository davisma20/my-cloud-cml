# CML AMI Network Diagnostics & Troubleshooting (April 2025)

## Current State
- SSH diagnostics fail on new AMI instances due to likely cloud-init or SSH misconfiguration.
- Security groups and NACLs are correct; root cause is inside the AMI (user/key/sshd/cloud-init).
- Diagnostic shell provisioners have been added to the Packer build to check:
  - cloud-init presence and status
  - SSH service status
  - Existence of /home/ubuntu/.ssh/authorized_keys
  - User info and relevant logs
  - Basic network diagnostics (ip addr, ip route, ping, metadata curl)

## Troubleshooting Workflow
1. **Destroy**: Clean up all AWS resources (terraform destroy).
2. **Packer Build**: Build the AMI with diagnostics enabled.
3. **Review Logs**: Carefully check Packer output for any errors in the diagnostic blocks.
4. **Fix & Repeat**: If diagnostics fail, fix issues in Packer/cloud-init/bootstrap scripts and repeat.
5. **Deploy & Validate**: If diagnostics pass, deploy with Terraform and run validation.

## Network-Related Best Practices
- Always use DHCP for the primary interface in netplan.
- Do not hardcode static IPs in the AMI.
- Ensure outbound HTTP/HTTPS is allowed for SSM and diagnostics.
- Confirm metadata service is reachable from instance.

## Example Diagnostic Provisioner
```hcl
provisioner "shell" {
  inline = [
    "ip addr show",
    "ip route",
    "ping -c 3 8.8.8.8 || echo 'Ping to 8.8.8.8 failed'",
    "curl -s http://169.254.169.254/latest/meta-data/ || echo 'Metadata service unavailable'"
  ]
}
```

## See Also
- [validators/network_diagnostics.py](../validators/network_diagnostics.py)
- [cml-2.7.0.pkr.hcl](./cml-2.7.0.pkr.hcl)
- [run_validation.py](../run_validation.py)

---
_Last updated: 2025-04-20_
