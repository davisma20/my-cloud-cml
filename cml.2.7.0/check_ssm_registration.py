#!/usr/bin/env python3
"""
check_ssm_registration.py

Checks SSM registration status for specified EC2 instance IDs.
"""
import boto3

# Always use us-east-2 as default region unless overridden
REGION = "us-east-2"

# List your CML instance IDs here
INSTANCE_IDS = [
    "i-0bcaf461ec352f206",  # cml-cloudinit-test
    "i-0a27a8e7b11e8fa83",  # cml-controller-7f767e19
]

def main():
    ssm = boto3.client("ssm", region_name=REGION)
    paginator = ssm.get_paginator("describe_instance_information")
    found = {iid: False for iid in INSTANCE_IDS}

    print(f"--- SSM Registration Status in {REGION} ---\n")
    for page in paginator.paginate():
        for info in page["InstanceInformationList"]:
            iid = info["InstanceId"]
            if iid in INSTANCE_IDS:
                found[iid] = True
                print(f"InstanceId: {iid}")
                print(f"  PingStatus: {info['PingStatus']}")
                print(f"  LastPingDateTime: {info['LastPingDateTime']}")
                print(f"  AgentVersion: {info['AgentVersion']}")
                print(f"  Platform: {info['PlatformName']} {info['PlatformVersion']}")
                print(f"  IsLatestVersion: {info['IsLatestVersion']}")
                print()
    for iid, is_found in found.items():
        if not is_found:
            print(f"InstanceId: {iid} is NOT registered with SSM in region {REGION}.")

if __name__ == "__main__":
    main()
