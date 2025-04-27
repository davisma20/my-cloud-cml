# Terraform Automation for Cisco Modeling Labs (CML) 2.8.1

## Overview
This guide describes how to automate the creation and management of CML labs, nodes, and topologies using the [CiscoDevNet/terraform-provider-cml2](https://github.com/CiscoDevNet/terraform-provider-cml2).

## Provider Details
- **Provider:** CiscoDevNet/terraform-provider-cml2
- **Status:** Beta, supports CML 2.6+ (compatible with 2.8.1)
- **Features:**
  - Automate labs, nodes, links, groups, users, and lifecycle management
  - Data sources for images, groups, system state, etc.
- **Authentication:**
  - Recommended: Use JWT token from CML UI
  - Supported: Username/password
- **Installation:**
  - Build from source with Go (`go install`)
  - See the GitHub repo for full build and usage instructions

## Example Usage
```
provider "cml2" {
  address  = "https://<your-cml-host>"
  username = var.cml_username    # or use token = var.cml_token
  password = var.cml_password
  insecure = true               # if using self-signed certs
}

resource "cml2_lab" "example" {
  title = "Terraform Lab"
}

resource "cml2_node" "router1" {
  lab_id   = cml2_lab.example.id
  label    = "router1"
  node_definition = "iosv"
  x = 100
  y = 100
}
```

## Best Practices
- Use Terraform for AWS infrastructure and CML topology automation.
- Securely handle credentials (prefer JWT token).
- Monitor the [GitHub repo](https://github.com/CiscoDevNet/terraform-provider-cml2) for updates.

## References
- [terraform-provider-cml2 GitHub](https://github.com/CiscoDevNet/terraform-provider-cml2)
- [CML 2.8.1 Documentation](https://developer.cisco.com/docs/modeling-labs/2-8/)
