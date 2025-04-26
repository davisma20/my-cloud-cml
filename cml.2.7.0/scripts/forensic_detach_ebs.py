from validators.forensic_validator import ForensicEbsValidator

if __name__ == "__main__":
    validator = ForensicEbsValidator(
        ssm_instance_id="i-0008416fc47ed613e",
        ssm_region="us-east-2",
        ssm_profile="absdevmaster"
    )
    result = validator.detach_ebs_via_ssm(device="/dev/nvme1n1p1", mount_point="/mnt/forensic-ebs")
    print("\n=== Detach (Unmount) Command Output ===")
    print(result["stdout"])
    print(result["stderr"])
