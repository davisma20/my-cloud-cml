# CML 2.8.1 Release Notes Summary

- **Base OS:** Ubuntu 24.04 (upgrade from 20.04 in 2.7.x)
- **CML-Free Tier:** No-cost, up to 5 nodes, reversion for expired licenses
- **Smart Annotations:** Tag-based grouping and visualization in UI
- **UI Improvements:** Annotation rotation, VNC text paste, disk usage monitoring
- **LDAP Group Support:** Assign resource groups via LDAP (Enterprise only)
- **Custom MAC Address:** Per-interface and OUI override
- **FMCv/FTDv Images:** Official support, new supplemental ISO
- **Cloud Deployments:** AWS and Azure BETA toolchain
- **Upgrade Path:** In-place upgrades for some 2.x, not 1.x

## Migration Implications
- All scripts/images must support Ubuntu 24.04
- New features may require extra documentation/validation
- Folder required for Cisco downloads (images, ISOs, etc.)
- AWS scripts should be reviewed for BETA toolchain
