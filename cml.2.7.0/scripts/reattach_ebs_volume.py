import boto3
import time

INSTANCE_ID = "i-090ade0d33ada3804"  # Target CML instance
VOLUME_ID = "vol-09617368f501d8ad4"  # 100GB forensic EBS volume
DEVICE_NAME = "/dev/nvme1n1"       # Default device name for CML
REGION = "us-east-2"
PROFILE = "absdevmaster"


def wait_for_instance_state(ec2, instance_id, state="stopped", timeout=300):
    for _ in range(timeout // 5):
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        current = resp["Reservations"][0]["Instances"][0]["State"]["Name"]
        if current == state:
            return True
        time.sleep(5)
    return False

def wait_for_volume_state(ec2, volume_id, state="available", timeout=120):
    for _ in range(timeout // 5):
        resp = ec2.describe_volumes(VolumeIds=[volume_id])
        current = resp["Volumes"][0]["State"]
        if current == state:
            return True
        time.sleep(5)
    return False

def main():
    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    ec2 = session.client("ec2")

    print(f"Waiting for instance {INSTANCE_ID} to be stopped...")
    if not wait_for_instance_state(ec2, INSTANCE_ID, state="stopped"):
        print("Instance did not reach 'stopped' state in time.")
        return

    print(f"Waiting for volume {VOLUME_ID} to be available...")
    if not wait_for_volume_state(ec2, VOLUME_ID, state="available"):
        print("Volume did not reach 'available' state in time.")
        return

    print(f"Attaching volume {VOLUME_ID} to instance {INSTANCE_ID} as {DEVICE_NAME}...")
    ec2.attach_volume(
        VolumeId=VOLUME_ID,
        InstanceId=INSTANCE_ID,
        Device=DEVICE_NAME
    )
    print("Attach request sent. Waiting for 'in-use' state...")
    if wait_for_volume_state(ec2, VOLUME_ID, state="in-use"):
        print("Volume successfully attached!")
    else:
        print("Volume did not reach 'in-use' state in time.")

if __name__ == "__main__":
    main()
