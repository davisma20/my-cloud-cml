// Packer HCL for CML 2.8.1 AWS Build

variable "source_ami" {
  type        = string
  default     = "ami-0a60b027285c0d4c5" // Ubuntu 24.04 LTS for us-east-2
  description = "Base AMI ID for the build."
}

variable "region" {
  type    = string
  default = "us-east-2" // Adjust as needed
}

variable "cml_bucket" {
  type    = string
  default = "cml-ova-import"
}

source "amazon-ebs" "ubuntu-cml" {
  ami_name      = "cml-2-8-1-aws-{{timestamp}}"
  instance_type = "c5.2xlarge"
  region        = var.region
  source_ami    = var.source_ami
  communicator  = "ssh"
  ssh_username  = "ubuntu"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 100
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  tags = {
    Name        = "CML-2.8.1-AMI"
    Environment = "Production"
    Builder     = "Packer"
    BuildDate   = formatdate("YYYY-MM-DD", timestamp())
  }

  # Attach temporary IAM policy for S3/SSM access (matches 2.7.0 pattern)
  temporary_iam_instance_profile_policy_document {
    Version = "2012-10-17"
    Statement {
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject"
      ]
      Resource = [
        "arn:aws:s3:::${var.cml_bucket}/*",
        "arn:aws:s3:::${var.cml_bucket}"
      ]
    }
    Statement {
      Action = [
        "ssm:UpdateInstanceInformation",
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel",
        "ec2messages:AcknowledgeMessage",
        "ec2messages:DeleteMessage",
        "ec2messages:FailMessage",
        "ec2messages:GetEndpoint",
        "ec2messages:GetMessages",
        "ec2messages:SendReply"
      ]
      Effect   = "Allow"
      Resource = ["*"]
    }
  }
}

build {
  sources = ["source.amazon-ebs.ubuntu-cml"]

  # Download CML 2.8.1 ISOs and reference platform files from S3, matching 2.7.0 pattern
  provisioner "shell" {
    environment_vars = [
      "AWS_REGION=${var.region}",
      "CML_BUCKET=${var.cml_bucket}"
    ]
    inline = [
      "echo '==== DEBUG: Installing AWS CLI v2 (bundled) ===='",
      "curl -sSL \"https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip\" -o \"/tmp/awscliv2.zip\"",
      "sudo apt-get update && sudo apt-get install -y unzip",
      "unzip -q /tmp/awscliv2.zip -d /tmp",
      "sudo /tmp/aws/install",
      "export PATH=$PATH:/usr/local/bin",
      "aws --version",
      "echo '==== DEBUG: Running S3 download provisioner for CML 2.8.1 ===='",
      "DOWNLOADS=/home/ubuntu/my-cloud-cml/cml.2.8.1/CISCO_DOWNLOADS",
      "mkdir -p $DOWNLOADS",
      "aws s3 cp s3://$CML_BUCKET/cml-2.8.1/ $DOWNLOADS/ --recursive",
      "ls -la $DOWNLOADS"
    ]
  }

  provisioner "shell" {
    script = "provision_cml2.8.1.sh"
  }

  provisioner "shell" {
    inline = [
      "echo 'Validating repository and GPG setup...'",
      "if ! sudo apt-get update -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowDowngradeToInsecureRepositories=true; then echo 'APT update failed, attempting key repair...'; sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32 871920D1991BC93C && sudo apt-get update; fi",
      "echo 'Repository/GPG validation complete.'"
    ]
  }

  provisioner "shell" {
    inline = [
      "echo 'Checking for software-properties-common...'",
      "if dpkg -s software-properties-common >/dev/null 2>&1; then echo 'software-properties-common already installed.'; else echo 'Installing software-properties-common...'; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common; fi"
    ]
  }

  provisioner "shell" {
    script = "ssm_install.sh"
  }

  provisioner "shell" {
    inline = [
      "echo 'Checking cloud-final.service network dependency...'",
      "if [ ! -f /etc/systemd/system/cloud-final.service.d/wait-for-network.conf ]; then echo 'Adding NetworkManager dependency for cloud-final.service...'; sudo mkdir -p /etc/systemd/system/cloud-final.service.d; echo -e '[Unit]\nAfter=NetworkManager-wait-online.service\nRequires=NetworkManager-wait-online.service' | sudo tee /etc/systemd/system/cloud-final.service.d/wait-for-network.conf > /dev/null; sudo systemctl daemon-reload; else echo 'Network dependency already present.'; fi"
    ]
  }

  provisioner "shell" {
    inline = [
      "echo '==== DEBUG: Dumping cloud-init and SSH diagnostics ===='",
      "which cloud-init || (echo 'cloud-init not installed!' && exit 1)",
      "sudo systemctl status cloud-init || (echo 'cloud-init service not running!' && exit 1)",
      "sudo systemctl status ssh || (echo 'ssh service not running!' && exit 1)",
      "sudo cat /etc/passwd",
      "sudo ls -l /home/ubuntu/.ssh/ || echo '/home/ubuntu/.ssh/ missing'",
      "sudo cat /home/ubuntu/.ssh/authorized_keys || echo 'No authorized_keys found'",
      "sudo cat /var/log/cloud-init.log | tail -n 50",
      "sudo cat /var/log/cloud-init-output.log | tail -n 50"
    ]
  }

  provisioner "shell" {
    inline = [
      "echo '==== DEBUG: Network diagnostics before AMI creation ===='",
      "ip addr show",
      "ip route",
      "ping -c 3 8.8.8.8 || echo 'Ping to 8.8.8.8 failed'",
      "curl -s http://169.254.169.254/latest/meta-data/ || echo 'Metadata service unavailable'"
    ]
  }

  provisioner "shell" {
    inline = [
      "echo 'Cleaning up system...'",
      "sudo apt-get clean",
      "sudo rm -rf /var/lib/apt/lists/*",
      "sudo rm -f /home/ubuntu/.bash_history",
      "sudo rm -f /root/.bash_history",
      "sudo cloud-init clean",
      "echo 'CML 2.8.1 AMI preparation complete!'"
    ]
  }

  post-processor "manifest" {
    output     = "packer-manifest.json"
    strip_path = true
  }
}
