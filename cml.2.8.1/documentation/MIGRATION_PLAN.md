# CML 2.8.1 Migration and Build Plan

## Objective
Migrate and modernize the CML 2.7.0 build system to support CML 2.8.1, following best practices for modularity, security, and maintainability.

## Steps

1. **Review Official Documentation**
   - [CML 2.8.1 Installation Guide](https://developer.cisco.com/docs/modeling-labs/2-8/cml-installation-guide/)
   - [CML 2.8.1 Release Notes](https://developer.cisco.com/docs/modeling-labs/2-8/cml-release-notes/)
   - [CML 2.8.1 User Guide](https://developer.cisco.com/docs/modeling-labs/2-8/cml-users-guide/)
   - [CML 2.8.1 Admin Guide](https://developer.cisco.com/docs/modeling-labs/2-8/cml-administrators-guide/)

2. **Emulate and Improve Folder Structure**
   - Use the `cml.2.7.0` structure as a template.
   - Only migrate necessary, organized files—avoid clutter.
   - Structure example:
     ```
     cml.2.8.1/
     ├── packer/
     ├── terraform/
     ├── documentation/
     ├── validations/
     └── README.md
     ```

3. **Copy/Adapt Packer & Terraform Files**
   - Update for CML 2.8.1 package locations and install steps.
   - Modularize and clarify scripts/configs.

4. **Summarize & Document CML 2.8.1 Changes**
   - Create markdown docs for migration notes, install steps, and release changes.

5. **Test & Validate**
   - Run Packer and Terraform builds.
   - Validate deployments using updated scripts.

6. **Commit & Push**
   - Commit changes incrementally with clear messages.
   - Ensure .gitignore excludes all logs/secrets.

---

**Next:**
- Evaluate the official CML 2.8.1 documentation and summarize key changes.
- Scaffold the new `cml.2.8.1/` directory and begin migrating/adapting files as outlined above.
