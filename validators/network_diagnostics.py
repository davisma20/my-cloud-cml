import subprocess
import time

class NetworkDiagnostics:
    """
    Modular class for running comprehensive network and SSM diagnostics via SSH or SSM.
    """
    @staticmethod
    def diagnostic_commands():
        return [
            ("==== ip addr show ====", "ip addr show"),
            ("==== ip route ====", "ip route"),
            ("==== ip rule ====", "ip rule"),
            ("==== ss -tulpen ====", "ss -tulpen"),
            ("==== arp -a ====", "arp -a"),
            ("==== /etc/resolv.conf ====", "cat /etc/resolv.conf"),
            ("==== ping 8.8.8.8 ====", "ping -c 3 8.8.8.8"),
            ("==== curl http://169.254.169.254/latest/meta-data/ ====", "curl -s http://169.254.169.254/latest/meta-data/"),
            ("==== netstat -nr ====", "netstat -nr || true"),
            ("==== tc qdisc show ====", "tc qdisc show || true"),
            ("==== dmesg | grep -i network ====", "dmesg | grep -i network || true"),
            ("==== systemctl status networking ====", "systemctl status networking || true"),
            ("==== /etc/network/interfaces ====", "cat /etc/network/interfaces || true"),
            ("==== /etc/netplan/*.yaml ====", "cat /etc/netplan/*.yaml 2>/dev/null || true"),
            ("==== SSM Agent Status ====", "sudo systemctl status amazon-ssm-agent"),
            ("==== SSM Agent Log ====", "sudo tail -n 50 /var/log/amazon/ssm/amazon-ssm-agent.log"),
            ("==== SSM Agent Region Config ====" , "cat /etc/amazon/ssm/amazon-ssm-agent.json | grep region || true"),
            ("==== SSM Agent Snap Status ====", "systemctl status snap.amazon-ssm-agent.amazon-ssm-agent.service || true"),
            ("==== SSM Agent Snap Log ====", "sudo tail -n 50 /var/snap/amazon-ssm-agent/common/amazon-ssm-agent.log || true"),
        ]

    @classmethod
    def run_over_ssh(cls, ssh_key, public_ip, username="ubuntu"):
        """
        Run all SSH diagnostics as a single function. If any SSH command fails to connect or authenticate,
        exit the script immediately and bypass all subsequent SSH diagnostics.
        """
        for label, cmd in cls.diagnostic_commands():
            print(f"\n{label}")
            ssh_cmd = [
                "ssh", "-i", ssh_key,
                f"{username}@{public_ip}",
                "sh", "-c", f'"{cmd}"'
            ]
            try:
                result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    print(result.stderr)
                    print(f"[FATAL] SSH command failed: {cmd}. Exiting diagnostics.")
                    import sys
                    sys.exit(1)
                print(result.stdout)
                if result.stderr:
                    print(result.stderr)
            except Exception as e:
                print(f"[FATAL] SSH connection or command error: {e}. Exiting diagnostics.")
                import sys
                sys.exit(1)

    @classmethod
    def run_over_ssm(cls, ssm_client, instance_id, region="us-east-2"):
        for label, cmd in cls.diagnostic_commands():
            print(f"\n{label}")
            response = ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [cmd]},
            )
            command_id = response["Command"]["CommandId"]
            # Wait for command invocation to exist and complete
            timeout = 60  # seconds
            interval = 2  # seconds
            elapsed = 0
            result = None
            while elapsed < timeout:
                try:
                    result = ssm_client.get_command_invocation(
                        CommandId=command_id,
                        InstanceId=instance_id
                    )
                    if result["Status"] in ["Success", "Failed", "Cancelled", "TimedOut"]:
                        break
                except ssm_client.exceptions.InvocationDoesNotExist:
                    pass  # Not ready yet
                except Exception as e:
                    print(f"[ERROR] While polling SSM command: {e}")
                time.sleep(interval)
                elapsed += interval
            if not result:
                print("[ERROR] SSM command invocation did not return a result in time.")
                continue
            print(result.get("StandardOutputContent", ""))
            if result.get("StandardErrorContent"):
                print(result["StandardErrorContent"])
