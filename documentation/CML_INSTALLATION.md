# CML Installation Improvements

This document describes improvements made to the CML installation process to address common installation issues.

## Background

The original CML installation process sometimes failed due to several issues:

1. **Escape sequence errors** in the systemd service file (`cml_install.service`)
2. **Improper handling of non-interactive commands** like wireshark-common configuration
3. **Insufficient logging** making it difficult to diagnose installation failures
4. **Timeout issues** during the installation process

## Implementation Details

### Improved Installation Service

We've created a more robust `cml_install.service` file that:

- Adds comprehensive logging to `/var/log/cml_install.log` with timestamps
- Properly escapes all commands to avoid systemd parsing errors
- Uses non-interactive installation methods to prevent hanging
- Has a generous timeout (30 minutes) to ensure completion
- Properly creates the `/etc/.virl2_unconfigured` flag file to trigger the initial setup process

### Enhanced Installation Fix Script

The `cml_install_fix.sh` script has been updated to:

- Replace the problematic service file with our improved version
- Better handle the case where the service file doesn't exist
- Add proper waiting for the service to complete
- Ensure the first-time configuration flag is set
- Provide more detailed status information

## Troubleshooting

If you encounter CML installation issues:

1. **Check the installation logs**:
   ```
   cat /var/log/cml_install.log
   ```

2. **View the systemd service status**:
   ```
   systemctl status cml_install.service
   ```

3. **View journal logs for the service**:
   ```
   journalctl -u cml_install.service
   ```

4. **Verify first-time setup flag exists**:
   ```
   ls -la /etc/.virl2_unconfigured
   ```

5. **Check if the CML package is installed**:
   ```
   dpkg -l | grep cml2
   ```

## Common Issues

### Authentication Failures

If you can access the CML GUI but cannot log in:

1. Check which users exist in the database:
   ```
   sudo sqlite3 /var/local/virl2/config/controller.db "SELECT id, username FROM user;"
   ```

2. Note that the default user might be "cml2" rather than "admin"

3. If needed, reset the password directly (replace with actual commands for your CML version)

### Uncompleted Installation

If the CML services are not running correctly:

1. Verify the CML package is installed:
   ```
   dpkg -l | grep cml2
   ```

2. Restart the controller service:
   ```
   systemctl restart virl2-controller
   ```

## References

- [CML 2.8 Documentation](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/cisco-modeling-labs/cisco-modeling-labs-2-8/admin/b_admin_guide_2-8.html)
