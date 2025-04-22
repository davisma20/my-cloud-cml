from validators.forensic_validator import ForensicEbsValidator

if __name__ == "__main__":
    validator = ForensicEbsValidator(
        ssm_instance_id="i-0008416fc47ed613e",
        ssm_region="us-east-2",
        ssm_profile="absdevmaster"
    )
    result = validator.mount_and_analyze_ebs(device="/dev/nvme1n1p1", mount_point="/mnt/forensic-ebs")
    print("\n=== Mount Command Output ===")
    print(result["mount_result"]["stdout"])
    print(result["mount_result"]["stderr"])
    print("\n=== Log Analysis Summary ===")
    for log, scan in result["log_summary"].items():
        print(f"\n--- {log} ---")
        if scan["exists"]:
            for match in scan["matches"]:
                print(f"Line {match['line']}: {match['content']}")
        elif scan["error"]:
            print(f"Error: {scan['error']}")
        else:
            print("No log or no matches found.")
