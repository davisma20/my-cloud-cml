# CML to DevNet Workstation Connectivity Guide

*Last Updated: March 22, 2025*

This guide provides instructions for verifying and troubleshooting connectivity between your CML instance and the DevNet Expert workstation.

## Prerequisites

- CML 2.8.1-14 successfully deployed in AWS
- DevNet Expert workstation deployed and accessible via RDP
- Both instances in the same VPC with appropriate security group rules

## Security Group Requirements

Ensure the security groups for both instances allow the following:

1. **CML Instance Security Group:**
   - Inbound from DevNet Workstation CIDR on ports 22 (SSH), 80 (HTTP), 443 (HTTPS), 8080 (HTTP Alternate)
   - Outbound to DevNet Workstation CIDR on all ports

2. **DevNet Workstation Security Group:**
   - Inbound from CML Instance CIDR on all ports
   - Outbound to CML Instance CIDR on all ports

## Verifying Connectivity

### From DevNet Workstation to CML

1. Connect to the DevNet Workstation via RDP using the admin credentials
2. Open a terminal and run the following commands:

```bash
# Ping the CML instance
ping <cml-private-ip> -c 4

# Test SSH connectivity (default port 1122)
nc -zv <cml-private-ip> 1122

# Test HTTPS connectivity for web interface
nc -zv <cml-private-ip> 443

# Attempt to access the CML web interface
curl -k -I https://<cml-private-ip>
```

### From CML to DevNet Workstation

You can test connectivity from the CML instance to the DevNet workstation using AWS SSM:

```bash
# Send SSM command to ping DevNet workstation
aws ssm send-command --document-name "AWS-RunShellScript" \
  --parameters 'commands=["ping <devnet-workstation-private-ip> -c 4"]' \
  --instance-ids <cml-instance-id> \
  --region <your-region>
```

## Establishing SSH Access

For direct SSH access from the DevNet workstation to CML:

1. On the DevNet workstation, create an SSH key pair:
   ```bash
   ssh-keygen -t rsa -b 4096 -f ~/.ssh/cml_key
   ```

2. Copy the public key to the CML instance:
   ```bash
   # From your local machine, using SSM to add the key
   aws ssm send-command --document-name "AWS-RunShellScript" \
     --parameters 'commands=["echo \"<public-key-content>\" >> /home/sysadmin/.ssh/authorized_keys"]' \
     --instance-ids <cml-instance-id> \
     --region <your-region>
   ```

3. Connect via SSH from the DevNet workstation:
   ```bash
   ssh -p 1122 sysadmin@<cml-private-ip> -i ~/.ssh/cml_key
   ```

## Setting Up Lab Examples

The DevNet Expert workstation includes tools to interact with CML labs. Here's how to set up a basic lab example:

1. Install the CML Python client on the DevNet workstation:
   ```bash
   pip install virl2-client
   ```

2. Create a basic Python script to connect to CML:
   ```python
   from virl2_client import ClientLibrary

   # Connect to the CML controller
   client = ClientLibrary("https://<cml-private-ip>", "admin", "<cml-admin-password>", ssl_verify=False)
   
   # Get and print lab information
   labs = client.all_labs()
   print(f"Found {len(labs)} labs")
   
   # Create a new lab
   new_lab = client.create_lab("DevNet Example Lab")
   print(f"Created new lab with ID: {new_lab.id}")
   ```

## Troubleshooting Connectivity Issues

If you encounter connectivity issues between the CML instance and DevNet workstation:

1. **Verify network connectivity:**
   - Check that both instances are in the same VPC
   - Ensure security groups allow required traffic

2. **Check CML service status:**
   - Use the commands in the [Service Monitoring Guide](SERVICE_MONITORING.md) to verify CML services are running

3. **Review routing and network interfaces:**
   - Check route tables and network interfaces for both instances
   - Ensure proper subnet routing is configured

4. **Review AWS Security Group rules:**
   - Verify inbound and outbound rules on both security groups
   - Ensure CIDR ranges are correctly specified

## Additional Resources

- [CML API Documentation](https://developer.cisco.com/docs/modeling-labs/)
- [CML Python Client Documentation](https://github.com/CiscoDevNet/virl2-client)
- [DevNet Expert Lab Examples](https://github.com/CiscoDevNet/devnet-expert-labs)
