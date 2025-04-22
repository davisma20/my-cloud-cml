import os
import logging
import subprocess
from typing import Dict, List
import boto3
import time
from botocore.exceptions import ClientError

def scan_log_for_errors(log_path: str, keywords: List[str] = None, max_lines: int = 1000) -> Dict:
    """
    Scans a log file for errors/warnings and returns summary lines.
    """
    if keywords is None:
        keywords = ["error", "fail", "fatal", "panic", "warn", "traceback"]
    results = {"matches": [], "path": log_path, "exists": False}
    if not os.path.isfile(log_path):
        return results
    results["exists"] = True
    try:
        with open(log_path, "r", errors="replace") as f:
            lines = f.readlines()[-max_lines:]
            for idx, line in enumerate(lines):
                l = line.lower()
                if any(k in l for k in keywords):
                    results["matches"].append({"line": idx+1, "content": line.strip()})
    except Exception as e:
        results["error"] = str(e)
    return results

class ForensicEbsValidator:
    """
    Forensic validator for analyzing logs from a mounted EBS root volume.
    Also provides utilities to identify attached EBS volumes and partitions.
    Now supports remote forensic analysis via AWS SSM.
    """
    def __init__(self, mount_point: str = None, logger=None, ssm_instance_id=None, ssm_region=None, ssm_profile=None):
        self.mount_point = mount_point
        self.logger = logger or logging.getLogger("ForensicEbsValidator")
        self.log_files = [
            "var/log/cloud-init.log",
            "var/log/cloud-init-output.log",
            "var/log/amazon/ssm/amazon-ssm-agent.log",
            "var/log/syslog",
            "var/log/messages"
        ]
        self.summary = {}
        self.ssm_instance_id = ssm_instance_id
        self.ssm_region = ssm_region
        self.ssm_profile = ssm_profile
        if ssm_instance_id and ssm_region:
            if ssm_profile:
                self.ssm_client = boto3.Session(profile_name=ssm_profile).client('ssm', region_name=ssm_region)
            else:
                self.ssm_client = boto3.client('ssm', region_name=ssm_region)
        else:
            self.ssm_client = None

    def run_ssm_command(self, commands, comment="ForensicValidator", timeout=60):
        """
        Runs a command on the remote instance via SSM and returns output.
        """
        if not self.ssm_client or not self.ssm_instance_id:
            self.logger.error("SSM client or instance ID not set.")
            return None
        try:
            response = self.ssm_client.send_command(
                InstanceIds=[self.ssm_instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": commands},
                Comment=comment
            )
            command_id = response['Command']['CommandId']
            # Wait for command to finish
            for _ in range(timeout):
                time.sleep(2)
                invocation = self.ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=self.ssm_instance_id
                )
                if invocation['Status'] in ["Success", "Failed", "TimedOut", "Cancelled"]:
                    break
            stdout = invocation.get('StandardOutputContent', '')
            stderr = invocation.get('StandardErrorContent', '')
            status = invocation.get('Status', '')
            return {"stdout": stdout, "stderr": stderr, "status": status}
        except ClientError as e:
            self.logger.error(f"SSM command error: {e}")
            return None

    def identify_ebs_volumes(self):
        """
        Identifies attached EBS volumes and partitions using 'lsblk', 'fdisk -l', or '/proc/partitions'.
        Supports SSM remote execution if configured.
        Returns a list of dicts with device info.
        """
        devices = []
        if self.ssm_client:
            # Try lsblk via SSM
            result = self.run_ssm_command(["lsblk -o NAME,SIZE,TYPE,MOUNTPOINT"])
            if result and result["status"] == "Success":
                self.logger.info("lsblk output (SSM):\n" + result["stdout"])
                for line in result["stdout"].strip().split("\n")[1:]:
                    fields = line.split()
                    if len(fields) >= 4:
                        devices.append({
                            "name": fields[0],
                            "size": fields[1],
                            "type": fields[2],
                            "mountpoint": fields[3] if len(fields) > 3 else ""
                        })
                return devices
            # Try fdisk -l via SSM
            result = self.run_ssm_command(["sudo fdisk -l"])
            if result and result["status"] == "Success":
                self.logger.info("fdisk -l output (SSM):\n" + result["stdout"])
                devices.append({"fdisk_output": result["stdout"]})
                return devices
            # Try /proc/partitions via SSM
            result = self.run_ssm_command(["cat /proc/partitions"])
            if result and result["status"] == "Success":
                self.logger.info("/proc/partitions output (SSM):\n" + result["stdout"])
                for line in result["stdout"].strip().split("\n")[2:]:
                    fields = line.split()
                    if len(fields) == 4:
                        devices.append({
                            "major": fields[0],
                            "minor": fields[1],
                            "blocks": fields[2],
                            "name": fields[3]
                        })
                return devices
            self.logger.warning("All SSM device discovery methods failed.")
            return devices
        # Local fallback (original logic)
        try:
            try:
                result = subprocess.run(["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT"], capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    self.logger.info("lsblk output:\n" + result.stdout)
                    for line in result.stdout.strip().split("\n")[1:]:
                        fields = line.split()
                        if len(fields) >= 4:
                            devices.append({
                                "name": fields[0],
                                "size": fields[1],
                                "type": fields[2],
                                "mountpoint": fields[3] if len(fields) > 3 else ""
                            })
                    return devices
            except FileNotFoundError:
                self.logger.warning("lsblk not found, trying fdisk -l")
            try:
                result = subprocess.run(["sudo", "fdisk", "-l"], capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    self.logger.info("fdisk -l output:\n" + result.stdout)
                    devices.append({"fdisk_output": result.stdout})
                    return devices
            except FileNotFoundError:
                self.logger.warning("fdisk not found, falling back to /proc/partitions")
            try:
                with open("/proc/partitions", "r") as f:
                    partitions = f.readlines()
                self.logger.info("/proc/partitions output:\n" + ''.join(partitions))
                for line in partitions[2:]:
                    fields = line.split()
                    if len(fields) == 4:
                        devices.append({
                            "major": fields[0],
                            "minor": fields[1],
                            "blocks": fields[2],
                            "name": fields[3]
                        })
            except Exception as e:
                self.logger.error(f"Error reading /proc/partitions: {e}")
        except Exception as e:
            self.logger.error(f"Error identifying EBS volumes: {e}")
        return devices

    def run(self):
        self.logger.info(f"Starting forensic analysis at mount point: {self.mount_point if self.mount_point else '[SSM Mode]'}")
        device_info = self.identify_ebs_volumes()
        self.summary['device_info'] = device_info
        # If SSM, also scan logs remotely
        if self.ssm_client:
            for rel_path in self.log_files:
                full_path = f"/{rel_path}" if not rel_path.startswith("/") else rel_path
                cmd = f"tail -100 {full_path}"
                result = self.run_ssm_command([cmd])
                scan = {"exists": False, "matches": [], "error": None}
                if result and result["status"] == "Success" and result["stdout"]:
                    scan["exists"] = True
                    lines = result["stdout"].splitlines()
                    for idx, line in enumerate(lines):
                        l = line.lower()
                        if any(k in l for k in ["error", "fail", "fatal", "panic", "warn", "traceback"]):
                            scan["matches"].append({"line": idx+1, "content": line.strip()})
                elif result and result["stderr"]:
                    scan["error"] = result["stderr"]
                self.summary[rel_path] = scan
            return self.summary
        # Local fallback (original logic)
        for rel_path in self.log_files:
            abs_path = os.path.join(self.mount_point, rel_path)
            result = scan_log_for_errors(abs_path)
            self.summary[rel_path] = result
            if result["exists"]:
                self.logger.info(f"Scanned {rel_path}: {len(result['matches'])} matches found.")
            else:
                self.logger.warning(f"Log file not found: {rel_path}")
        return self.summary

    def format_summary(self) -> str:
        lines = ["\n=== Forensic EBS Log Analysis Summary ==="]
        for log, result in self.summary.items():
            if log == 'device_info':
                lines.append("\n--- Device Info ---")
                for device in result:
                    for key, value in device.items():
                        lines.append(f"{key}: {value}")
                continue
            if not result["exists"]:
                lines.append(f"[MISSING] {log}")
                continue
            lines.append(f"\n--- {log} ---")
            if result.get("error"):
                lines.append(f"[ERROR] {result['error']}")
                continue
            if not result["matches"]:
                lines.append("No errors/warnings found.")
            else:
                for match in result["matches"][:10]:
                    lines.append(f"Line {match['line']}: {match['content']}")
                if len(result["matches"]) > 10:
                    lines.append(f"... ({len(result['matches'])} total matches)")
        return "\n".join(lines)

    def save_results(self, output_path: str):
        import json
        with open(output_path, "w") as f:
            json.dump(self.summary, f, indent=2)
        self.logger.info(f"Saved forensic analysis results to {output_path}")

    def mount_and_analyze_ebs(self, device="/dev/nvme1n1p1", mount_point="/mnt/forensic-ebs"): 
        """
        Mounts an EBS partition via SSM and analyzes its logs.
        Returns the results of the log scan.
        """
        if not self.ssm_client:
            self.logger.error("SSM client not configured.")
            return None
        # 1. Mount the device
        cmds = [
            f"sudo mkdir -p {mount_point}",
            f"sudo mount {device} {mount_point}",
            f"ls -l {mount_point}/var/log"
        ]
        mount_result = self.run_ssm_command(cmds, comment="Mount forensic EBS and list logs")
        self.logger.info(f"Mount and log listing output (SSM):\n{mount_result['stdout']}\n{mount_result['stderr']}")
        # 2. Scan logs on the mounted volume
        log_files = [
            f"{mount_point}/var/log/cloud-init.log",
            f"{mount_point}/var/log/cloud-init-output.log",
            f"{mount_point}/var/log/amazon/ssm/amazon-ssm-agent.log",
            f"{mount_point}/var/log/syslog",
            f"{mount_point}/var/log/messages"
        ]
        log_summary = {}
        for log_path in log_files:
            cmd = f"tail -100 {log_path}"
            result = self.run_ssm_command([cmd], comment=f"Scan {log_path}")
            scan = {"exists": False, "matches": [], "error": None}
            if result and result["status"] == "Success" and result["stdout"]:
                scan["exists"] = True
                lines = result["stdout"].splitlines()
                for idx, line in enumerate(lines):
                    l = line.lower()
                    if any(k in l for k in ["error", "fail", "fatal", "panic", "warn", "traceback"]):
                        scan["matches"].append({"line": idx+1, "content": line.strip()})
            elif result and result["stderr"]:
                scan["error"] = result["stderr"]
            log_summary[log_path] = scan
        return {"mount_result": mount_result, "log_summary": log_summary}

    def detach_ebs_via_ssm(self, device="/dev/nvme1n1p1", mount_point="/mnt/forensic-ebs"): 
        """
        Unmounts and detaches an EBS partition via SSM.
        Returns the output of the unmount command.
        """
        if not self.ssm_client:
            self.logger.error("SSM client not configured.")
            return None
        cmds = [
            f"sudo umount {mount_point}",
            f"lsblk"
        ]
        unmount_result = self.run_ssm_command(cmds, comment="Unmount forensic EBS and show block devices")
        self.logger.info(f"Unmount output (SSM):\n{unmount_result['stdout']}\n{unmount_result['stderr']}")
        return unmount_result
