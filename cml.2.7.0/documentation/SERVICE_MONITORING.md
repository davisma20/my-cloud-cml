# CML Service Monitoring Guide

*Last Updated: March 22, 2025*

This document provides instructions for monitoring the status of CML services during and after installation in AWS environments.

## Key CML Services

The following services are critical for CML operation:

1. **cml_install.service** - Handles the initial installation of the CML package
2. **cml.service** - The main CML service that runs after successful installation
3. **virl2-uwsgi.service** - Handles the web interface API
4. **virl2-nginx.service** - Provides the web server for the CML interface

## Monitoring Services via AWS SSM

### Check Service Status

```bash
# Check the status of the installation service
aws ssm send-command --document-name "AWS-RunShellScript" \
  --parameters 'commands=["systemctl status cml_install.service"]' \
  --instance-ids <your-instance-id> \
  --region <your-region>

# Check the command output
aws ssm get-command-invocation \
  --command-id <command-id-from-previous-output> \
  --instance-id <your-instance-id> \
  --region <your-region>
```

### View Service Logs

```bash
# View logs for the installation service
aws ssm send-command --document-name "AWS-RunShellScript" \
  --parameters 'commands=["journalctl -u cml_install.service"]' \
  --instance-ids <your-instance-id> \
  --region <your-region>

# View logs for the main CML service
aws ssm send-command --document-name "AWS-RunShellScript" \
  --parameters 'commands=["journalctl -u cml.service"]' \
  --instance-ids <your-instance-id> \
  --region <your-region>
```

## Checking Package Installation

```bash
# Check if the CML package is installed
aws ssm send-command --document-name "AWS-RunShellScript" \
  --parameters 'commands=["dpkg -l | grep cml2"]' \
  --instance-ids <your-instance-id> \
  --region <your-region>

# Check installed files
aws ssm send-command --document-name "AWS-RunShellScript" \
  --parameters 'commands=["ls -la /usr/local/bin/virl*"]' \
  --instance-ids <your-instance-id> \
  --region <your-region>
```

## Verifying Network Connectivity

```bash
# Check if the web server is running and listening on port 443
aws ssm send-command --document-name "AWS-RunShellScript" \
  --parameters 'commands=["ss -tulpn | grep :443"]' \
  --instance-ids <your-instance-id> \
  --region <your-region>

# Check firewall settings
aws ssm send-command --document-name "AWS-RunShellScript" \
  --parameters 'commands=["ufw status"]' \
  --instance-ids <your-instance-id> \
  --region <your-region>
```

## Installation Progress Tracking

The CML installation can take 5-10 minutes to complete. You can track its progress by:

1. Checking the status of the installation service
2. Monitoring system logs for installation progress
3. Verifying that the CML service starts automatically after installation

## Accessing CML After Installation

Once the installation is complete and the CML service is running, you can access the web interface at:

```
https://<your-instance-ip>
```

Default credentials are:
- Username: admin
- Password: See your configuration or auto-generated in AWS SSM Parameter Store

## CML Version 2.8.1-14 Specifics

For CML version 2.8.1-14 installations:

1. The package format is `.deb` (not `.pkg` as in older versions)
2. The installation path is typically `/root/cml2_2.8.1-14_amd64.deb`
3. After successful installation, the package will be listed in dpkg as `cml2`

## Troubleshooting

If you encounter issues with the CML services, refer to the [Troubleshooting Guide](TROUBLESHOOTING.md) for detailed resolution steps.
