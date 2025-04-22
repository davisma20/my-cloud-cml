#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

# --- Data Sources --- #
data "aws_region" "current" {}

data "http" "myip" {
  url = "http://ipv4.icanhazip.com" # Service to get public IP
}

# --- Locals --- #
locals {
  workstation_enable = var.options.cfg.aws.workstation.enable
  cml_enable = true  # Enable CML controller
  num_computes = var.options.cfg.cluster.enable_cluster ? var.options.cfg.cluster.number_of_compute_nodes : 0
  compute_hostnames = [
    for i in range(1, local.num_computes + 1) :
    format("%s-%d", var.options.cfg.cluster.compute_hostname_prefix, i)
  ]

  # Late binding required as the token is only known within the module.
  # (Azure specific)
  vars = "export CML_CLOUD_PROVIDER=aws"

  # Create a properly structured object for the template
  cml_config_controller = templatefile("${path.module}/../data/virl2-base-config.yml", {
    hostname      = var.options.cfg.common.controller_hostname,
    is_controller = true
    is_compute    = !var.options.cfg.cluster.enable_cluster || var.options.cfg.cluster.allow_vms_on_controller
    cfg = {
      common = var.options.cfg.common
      aws = var.options.cfg.aws
      cluster = var.options.cfg.cluster
      secrets = {
        # Explicitly structure the secrets as expected by the template
        app = {
          username = lookup(var.options.cfg.secrets, "app", {username = "admin", secret = "dummy_password"}).username
          secret = lookup(var.options.cfg.secrets, "app", {username = "admin", secret = "dummy_password"}).secret
        }
        sys = {
          username = lookup(var.options.cfg.secrets, "sys", {username = "sysadmin", secret = "dummy_password"}).username
          secret = lookup(var.options.cfg.secrets, "sys", {username = "sysadmin", secret = "dummy_password"}).secret
        }
        cluster = {
          secret = lookup(var.options.cfg.secrets, "cluster", {secret = "dummy_cluster_secret"}).secret
        }
        smartlicense_token = {
          secret = lookup(var.options.cfg.secrets, "smartlicense_token", {secret = "your-smart-licensing-token"}).secret
        }
      }
    }
  })

  cml_config_compute = [for compute_hostname in local.compute_hostnames : templatefile("${path.module}/../data/virl2-base-config.yml", {
    hostname      = compute_hostname,
    is_controller = false,
    is_compute    = true,
    cfg = {
      common = var.options.cfg.common
      aws = var.options.cfg.aws
      cluster = var.options.cfg.cluster
      secrets = {
        # Explicitly structure the secrets as expected by the template
        app = {
          username = lookup(var.options.cfg.secrets, "app", {username = "admin", secret = "dummy_password"}).username
          secret = lookup(var.options.cfg.secrets, "app", {username = "admin", secret = "dummy_password"}).secret
        }
        sys = {
          username = lookup(var.options.cfg.secrets, "sys", {username = "sysadmin", secret = "dummy_password"}).username
          secret = lookup(var.options.cfg.secrets, "sys", {username = "sysadmin", secret = "dummy_password"}).secret
        }
        cluster = {
          secret = lookup(var.options.cfg.secrets, "cluster", {secret = "dummy_cluster_secret"}).secret
        }
        smartlicense_token = {
          secret = lookup(var.options.cfg.secrets, "smartlicense_token", {secret = "your-smart-licensing-token"}).secret
        }
      }
    }
  })]

  cloud_config = templatefile("${path.module}/../data/cloud-config.txt", {
    vars          = local.vars
    cml_config    = local.cml_config_controller
    cfg           = var.options.cfg
    cml           = var.options.cml
    common        = var.options.common
    copyfile      = var.options.copyfile
    del           = var.options.del
    interface_fix = var.options.interface_fix
    license       = var.options.license
    reliable_install = var.options.reliable_install
    extras        = var.options.extras
    hostname      = var.options.cfg.common.controller_hostname
    path          = path.module
    custom_scripts_yaml = "" # Add default empty value to prevent destroy error
  })

  cloud_config_compute = [for i in range(0, local.num_computes) : templatefile("${path.module}/../data/cloud-config.txt", {
    vars          = local.vars
    cml_config    = local.cml_config_compute[i]
    cfg           = var.options.cfg
    cml           = var.options.cml
    common        = var.options.common
    copyfile      = var.options.copyfile
    del           = var.options.del
    interface_fix = var.options.interface_fix
    license       = "empty"
    reliable_install = var.options.reliable_install
    extras        = var.options.extras
    hostname      = local.compute_hostnames[i]
    path          = path.module
  })]

  main_vpc   = length(var.options.cfg.aws.vpc_id) > 0 ? data.aws_vpc.selected[0] : aws_vpc.main_vpc[0]
  main_gw_id = length(var.options.cfg.aws.gw_id) > 0 ? var.options.cfg.aws.gw_id : aws_internet_gateway.public_igw[0].id

  cml_ingress = [
    {
      "description" : "allow SSH",
      "from_port" : 1122,
      "to_port" : 1122,
      "protocol" : "tcp",
      "cidr_blocks" : var.options.cfg.common.allowed_ipv4_subnets,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow CML termserver",
      "from_port" : 22,
      "to_port" : 22,
      "protocol" : "tcp",
      "cidr_blocks" : var.options.cfg.common.allowed_ipv4_subnets,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow Cockpit",
      "from_port" : 9090,
      "to_port" : 9090,
      "protocol" : "tcp",
      "cidr_blocks" : var.options.cfg.common.allowed_ipv4_subnets,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow HTTP",
      "from_port" : 80,
      "to_port" : 80,
      "protocol" : "tcp",
      "cidr_blocks" : var.options.cfg.common.allowed_ipv4_subnets,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow HTTPS",
      "from_port" : 443,
      "to_port" : 443,
      "protocol" : "tcp",
      "cidr_blocks" : var.options.cfg.common.allowed_ipv4_subnets,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    }
  ]

  cml_patty_range = [
    {
      "description" : "allow PATty TCP",
      "from_port" : 2000,
      "to_port" : 7999,
      "protocol" : "tcp",
      "cidr_blocks" : var.options.cfg.common.allowed_ipv4_subnets,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow PATty UDP",
      "from_port" : 2000,
      "to_port" : 7999,
      "protocol" : "udp",
      "cidr_blocks" : var.options.cfg.common.allowed_ipv4_subnets,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    }
  ]

  custom_scripts_yaml = yamlencode([
    for script in var.cfg.app.customize : {
      path        = "/provision/${script}"
      owner       = "root:root"
      permissions = "0644"
      content     = file("${path.module}/../data/${script}")
    }
  ])

  cml_config_yaml = try(yamlencode(var.options.cml), yamlencode({})) # Add try for destroy phase

  # Extract custom AMI from extras if provided
  custom_ami_regex = "export AWS_CUSTOM_AMI=\"([^\"]+)\""
  custom_ami = length(regexall(local.custom_ami_regex, var.options.extras)) > 0 ? regex(local.custom_ami_regex, var.options.extras)[0] : ""
}

# --- SSM IAM Resources --- #
resource "aws_iam_role" "cml_ssm_role" {
  name = "cml-ssm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cml_ssm_core" {
  role       = aws_iam_role.cml_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "cml_ssm_profile" {
  name = "cml-ssm-profile"
  role = aws_iam_role.cml_ssm_role.name
}

resource "aws_security_group" "sg_tf" {
  name        = "tf-sg-cml-${var.options.rand_id}"
  description = "CML required ports inbound/outbound"
  tags = {
    Name = "tf-sg-cml-${var.options.rand_id}"
  }
  vpc_id = local.main_vpc.id
  egress = [
    {
      "description" : "any",
      "from_port" : 0,
      "to_port" : 0,
      "protocol" : "-1",
      "cidr_blocks" : [
        "0.0.0.0/0"
      ],
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    }
  ]
  ingress = var.options.cfg.common.enable_patty ? concat(local.cml_ingress, local.cml_patty_range) : local.cml_ingress
}

resource "aws_security_group" "sg_tf_cluster_int" {
  name        = "tf-sg-cml-cluster-int-${var.options.rand_id}"
  description = "Allowing all IPv6 traffic on the cluster interface"
  tags = {
    Name = "tf-sg-cml-cluster-int-${var.options.rand_id}"
  }
  vpc_id = local.main_vpc.id
  egress = [
    {
      "description" : "any",
      "from_port" : 0,
      "to_port" : 0,
      "protocol" : "-1",
      "cidr_blocks" : [],
      "ipv6_cidr_blocks" : ["::/0"],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    }
  ]
  ingress = [
    {
      "description" : "any",
      "from_port" : 0,
      "to_port" : 0,
      "protocol" : "-1",
      "cidr_blocks" : [],
      "ipv6_cidr_blocks" : ["::/0"],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    }
  ]
}

#----------------- if VPC ID was provided, select it --------------------------
data "aws_vpc" "selected" {
  id    = var.options.cfg.aws.vpc_id
  count = length(var.options.cfg.aws.vpc_id) > 0 ? 1 : 0
}

#------------------- non-default VPC configuration ----------------------------
resource "aws_vpc" "main_vpc" {
  count                            = length(var.options.cfg.aws.vpc_id) > 0 ? 0 : 1
  cidr_block                       = var.options.cfg.aws.public_vpc_ipv4_cidr
  assign_generated_ipv6_cidr_block = true
  tags = {
    Name = "CML-vpc-${var.options.rand_id}"
  }
}

#------------------- public subnet, IGW and routing ---------------------------
resource "aws_internet_gateway" "public_igw" {
  count  = length(var.options.cfg.aws.gw_id) > 0 ? 0 : 1
  vpc_id = local.main_vpc.id
  tags   = { "Name" = "CML-igw-${var.options.rand_id}" }
}

resource "aws_subnet" "public_subnet" {
  availability_zone       = var.options.cfg.aws.availability_zone
  cidr_block              = cidrsubnet(var.options.cfg.aws.public_vpc_ipv4_cidr, 8, 0)
  vpc_id                  = local.main_vpc.id
  map_public_ip_on_launch = true
  tags                    = { "Name" = "CML-public-${var.options.rand_id}" }
}

resource "aws_route_table" "for_public_subnet" {
  vpc_id = local.main_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = local.main_gw_id
  }
  tags = { "Name" = "CML-public-rt-${var.options.rand_id}" }
}

resource "aws_route_table_association" "public_subnet" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.for_public_subnet.id
}

#------------- compute subnet, NAT GW, routing and interfaces -----------------

resource "aws_subnet" "compute_nat_subnet" {
  availability_zone = var.options.cfg.aws.availability_zone
  cidr_block        = cidrsubnet(var.options.cfg.aws.public_vpc_ipv4_cidr, 8, 1)
  vpc_id            = local.main_vpc.id
  tags              = { "Name" = "CML-compute-nat-${var.options.rand_id}" }
  count             = var.options.cfg.cluster.enable_cluster ? 1 : 0
}

resource "aws_eip" "nat_eip" {
  tags = {
    Name = "CML-compute-nat-gw-eip-${var.options.rand_id}"
  }
  count = var.options.cfg.cluster.enable_cluster ? 1 : 0
}

resource "aws_nat_gateway" "compute_nat_gw" {
  allocation_id = aws_eip.nat_eip[0].id # Allocate an EIP 
  subnet_id     = aws_subnet.public_subnet.id
  count         = var.options.cfg.cluster.enable_cluster ? 1 : 0
  tags = {
    Name = "CML-compute-nat-gw-${var.options.rand_id}"
  }
  # Ensure creation after EIP and subnet resources exist
  depends_on = [
    aws_eip.nat_eip,
    aws_subnet.compute_nat_subnet
  ]
}

resource "aws_route_table" "compute_route_table" {
  vpc_id = local.main_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.compute_nat_gw[0].id
  }
  tags = {
    Name = "CML-cluster-rt-${var.options.rand_id}"
  }
  count = var.options.cfg.cluster.enable_cluster ? 1 : 0
}

resource "aws_route_table_association" "compute_subnet_assoc" {
  subnet_id      = aws_subnet.compute_nat_subnet[0].id
  route_table_id = aws_route_table.compute_route_table[0].id
  count          = var.options.cfg.cluster.enable_cluster ? 1 : 0
}

resource "aws_network_interface" "nat_int_cml_compute" {
  subnet_id       = aws_subnet.compute_nat_subnet[0].id
  security_groups = [aws_security_group.sg_tf.id]
  tags            = { Name = "CML-compute-${count.index + 1}-nat-int-${var.options.rand_id}" }
  count           = local.num_computes
}

#-------------------- cluster subnet and interface ----------------------------

resource "aws_subnet" "cluster_subnet" {
  availability_zone               = var.options.cfg.aws.availability_zone
  cidr_block                      = cidrsubnet(var.options.cfg.aws.public_vpc_ipv4_cidr, 8, 255)
  ipv6_cidr_block                 = cidrsubnet(local.main_vpc.ipv6_cidr_block, 8, 1)
  vpc_id                          = local.main_vpc.id
  tags                            = { "Name" = "CML-cluster-${var.options.rand_id}" }
  count                           = var.options.cfg.cluster.enable_cluster ? 1 : 0
  assign_ipv6_address_on_creation = true
}

resource "aws_network_interface" "cluster_int_cml" {
  subnet_id       = aws_subnet.cluster_subnet[0].id
  security_groups = [aws_security_group.sg_tf_cluster_int.id]
  tags            = { Name = "CML-controller-cluster-int-${var.options.rand_id}" }
  count           = var.options.cfg.cluster.enable_cluster ? 1 : 0
}

resource "aws_network_interface" "cluster_int_cml_compute" {
  subnet_id       = aws_subnet.cluster_subnet[0].id
  security_groups = [aws_security_group.sg_tf_cluster_int.id]
  tags            = { Name = "CML-compute-${count.index + 1}-cluster-int-${var.options.rand_id}" }
  count           = local.num_computes
}

#------------------ IPv6 multicast support for CML clustering -----------------

resource "aws_ec2_transit_gateway" "transit_gateway" {
  description                     = "CML Transit Gateway"
  multicast_support               = "enable"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support                     = "disable"
  vpn_ecmp_support                = "disable"
  tags = {
    Name = "CML-tgw-${var.options.rand_id}"
  }
  count = var.options.cfg.cluster.enable_cluster ? 1 : 0
}

resource "aws_ec2_transit_gateway_multicast_domain" "cml_mcast_domain" {
  transit_gateway_id              = aws_ec2_transit_gateway.transit_gateway[0].id
  igmpv2_support                  = "enable"
  auto_accept_shared_associations = "enable"
  tags = {
    Name = "CML-mcast-domain-${var.options.rand_id}"
  }
  count = var.options.cfg.cluster.enable_cluster ? 1 : 0
}

resource "aws_ec2_transit_gateway_vpc_attachment" "vpc_attachment" {
  transit_gateway_id = aws_ec2_transit_gateway.transit_gateway[0].id
  vpc_id             = local.main_vpc.id
  subnet_ids         = [aws_subnet.cluster_subnet[0].id]
  ipv6_support       = "enable"
  tags = {
    Name = "CML-tgw-vpc-attachment-${var.options.rand_id}"
  }
  count = var.options.cfg.cluster.enable_cluster ? 1 : 0
}

resource "aws_ec2_transit_gateway_multicast_domain_association" "cml_association" {
  transit_gateway_attachment_id       = aws_ec2_transit_gateway_vpc_attachment.vpc_attachment[count.index].id
  transit_gateway_multicast_domain_id = aws_ec2_transit_gateway_multicast_domain.cml_mcast_domain[count.index].id
  subnet_id                           = aws_subnet.cluster_subnet[count.index].id
  count                               = var.options.cfg.cluster.enable_cluster ? 1 : 0
}

resource "aws_ec2_transit_gateway_multicast_group_member" "cml_controller_int" {
  group_ip_address                    = "ff02::fb"
  network_interface_id                = aws_network_interface.cluster_int_cml[count.index].id
  transit_gateway_multicast_domain_id = aws_ec2_transit_gateway_multicast_domain_association.cml_association[count.index].transit_gateway_multicast_domain_id
  count                               = var.options.cfg.cluster.enable_cluster ? 1 : 0
}

resource "aws_ec2_transit_gateway_multicast_group_member" "cml_compute_int" {
  group_ip_address                    = "ff02::fb"
  network_interface_id                = aws_network_interface.cluster_int_cml_compute[count.index].id
  transit_gateway_multicast_domain_id = aws_ec2_transit_gateway_multicast_domain_association.cml_association[0].transit_gateway_multicast_domain_id
  count                               = local.num_computes
}

resource "aws_instance" "cml_controller" {
  count               = local.cml_enable ? 1 : 0
  instance_type        = var.cfg.aws.flavor
  ami                  = local.custom_ami != "" ? local.custom_ami : var.cfg.aws.ami_id
  iam_instance_profile = aws_iam_instance_profile.cml_ssm_profile.name
  key_name             = var.options.cfg.common.key_name
  subnet_id            = aws_subnet.public_subnet.id
  
  # Security enhancements
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = var.options.cfg.common.security.require_imdsv2 ? "required" : "optional"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = var.cfg.aws.storage_size
    volume_type = "gp3"
    encrypted   = var.options.cfg.aws.enable_ebs_encryption
    delete_on_termination = true
  }

  vpc_security_group_ids = [aws_security_group.sg_tf.id]

  tags = {
    Name = "cml-controller-${var.options.rand_id}"
  }

  # Use a shell-based user_data script, just like the devnet workstation
  user_data = <<-EOF
#!/bin/bash
# Log startup
 echo "CML Controller started at $(date)" > /var/log/cml-controller-setup.log

# Ensure SSM agent is running
if command -v systemctl > /dev/null && systemctl list-unit-files | grep -q amazon-ssm-agent; then
  systemctl enable amazon-ssm-agent
  systemctl start amazon-ssm-agent
  echo "SSM agent started" >> /var/log/cml-controller-setup.log
fi

# (Optional) Add any CML controller-specific setup here

# Apply security hardening measures (if enabled)
if [ "${var.options.cfg.common.security.setup_ufw_firewall}" = "true" ]; then
  echo "Configuring UFW firewall..." >> /var/log/cml-controller-setup.log
  apt-get update && apt-get install -y ufw
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp    # SSH
  ufw allow 80/tcp    # HTTP
  ufw allow 443/tcp   # HTTPS
  echo "y" | ufw enable
fi

if [ "${var.options.cfg.common.security.configure_fail2ban}" = "true" ]; then
  echo "Configuring fail2ban..." >> /var/log/cml-controller-setup.log
  apt-get update && apt-get install -y fail2ban
  cat <<FAILCONF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 600
bantime = 3600
FAILCONF
  systemctl enable fail2ban
  systemctl start fail2ban
fi

if [ "${var.options.cfg.common.security.enable_auto_updates}" = "true" ]; then
  echo "Configuring automatic security updates..." >> /var/log/cml-controller-setup.log
  apt-get update && apt-get install -y unattended-upgrades
  cat <<AUTOCONF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOCONF
fi

echo "CML controller security hardening completed at $(date)" >> /var/log/cml-controller-setup.log
EOF

  depends_on = [
    aws_internet_gateway.public_igw,
    aws_subnet.public_subnet
  ]
}

resource "aws_eip" "cml_controller_eip" {
  count = local.cml_enable ? 1 : 0
  domain = "vpc"
  tags = {
    Name = "CML-controller-eip-${var.options.rand_id}"
  }
}

resource "aws_eip_association" "cml_controller_eip_assoc" {
  count                = local.cml_enable ? 1 : 0
  instance_id          = aws_instance.cml_controller[0].id
  allocation_id        = aws_eip.cml_controller_eip[0].id
  depends_on           = [aws_instance.cml_controller]
}

resource "aws_instance" "cml_compute" {
  count               = local.num_computes
  instance_type        = var.options.cfg.aws.flavor_compute
  ami                  = data.aws_ami.ubuntu.id
  iam_instance_profile = aws_iam_instance_profile.cml_ssm_profile.name
  key_name             = var.options.cfg.common.key_name
  subnet_id            = aws_subnet.public_subnet.id
  
  # Security enhancements
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # Forcing optional for SSM compatibility
    http_put_response_hop_limit = 1
  }

  vpc_security_group_ids = [aws_security_group.sg_tf.id]
  tags = {
    Name = "CML-compute-${count.index + 1}-${var.options.rand_id}"
  }
  ebs_optimized        = "true"
  depends_on           = [aws_instance.cml_controller, aws_route_table_association.compute_subnet_assoc]
  dynamic "instance_market_options" {
    for_each = var.options.cfg.aws.spot_instances.use_spot_for_computes ? [1] : []
    content {
      market_type = "spot"
      spot_options {
        instance_interruption_behavior = "stop"
        spot_instance_type             = "persistent"
      }
    }
  }
  root_block_device {
    volume_size = var.options.cfg.cluster.compute_disk_size
    volume_type = "gp3"
    encrypted   = var.options.cfg.aws.enable_ebs_encryption
  }
  network_interface {
    network_interface_id = aws_network_interface.nat_int_cml_compute[count.index].id
    device_index         = 0
  }
  network_interface {
    network_interface_id = aws_network_interface.cluster_int_cml_compute[count.index].id
    device_index         = 1
  }
  user_data = data.cloudinit_config.cml_compute[count.index].rendered
}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Owner ID of Canonical
}

data "cloudinit_config" "cml_controller" {
  gzip          = true
  base64_encode = true

  # Part 1: Base cloud-config from file
  part {
    content_type = "text/cloud-config"
    content      = local.cloud_config # Rendered template from cloud-config.txt
    filename     = "cloud-config.txt"
  }

  # Part 2: CML base config generated from template
  part {
    content_type = "text/plain" # Treated as a file to be written by cloud-init
    content      = local.cml_config_controller
    filename     = "/etc/virl2-base-config.yml"
  }

  # Part 3: Optional user extras
  part {
    content_type = "text/cloud-config"
    content      = var.options.extras
    merge_type   = "list(append)+dict(recurse_array)+str()"
  }

  # Part 4: Write the internal validator script
  part {
    content_type = "text/cloud-config"
    content = yamlencode({
      write_files = [
        {
          path        = "/usr/local/bin/run_validation.py"
          permissions = "0644"
          owner       = "root:root"
          content     = file("${path.module}/../../../run_validation.py")
        }
      ]
    })
    filename = "write-validator.yaml"
  }

  # Part 5: Make validator executable and run it
  part {
    content_type = "text/cloud-config"
    content = yamlencode({
      runcmd = [
        "echo 'Making internal validator script executable...'",
        "chmod +x /usr/local/bin/run_validation.py",
        "echo 'Running internal validator script...'",
        "(/usr/bin/python3 /usr/local/bin/run_validation.py >> /var/log/cloud-init-validator.log 2>&1) || echo 'Validator script failed, check /var/log/cloud-init-validator.log'"
      ]
    })
    filename = "run-validator.yaml"
  }
}

data "cloudinit_config" "cml_compute" {
  gzip          = true
  base64_encode = true
  count         = local.num_computes

  part {
    filename     = "cloud-config.yaml"
    content_type = "text/cloud-config"

    content = local.cloud_config_compute[count.index]
  }
}

# Security group for the devnet workstation
resource "aws_security_group" "sg_workstation" {
  count       = local.workstation_enable ? 1 : 0
  name        = "tf-sg-workstation-${var.options.rand_id}"
  description = "Devnet workstation security group"
  vpc_id      = local.main_vpc.id

  # Allow HTTP/HTTPS outbound for internet access
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    description = "allow HTTP outbound"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    description = "allow HTTPS outbound"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Remove SSH ingress for security (optional, comment out if SSH is not needed)
  # ingress {
  #   from_port   = 22
  #   to_port     = 22
  #   protocol    = "tcp"
  #   description = "allow SSH"
  #   cidr_blocks = var.options.cfg.common.allowed_ipv4_subnets
  # }

  # Allow RDP
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    description = "allow RDP"
    cidr_blocks = var.options.cfg.common.allowed_ipv4_subnets
  }

  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "devnet-workstation-sg-${var.options.rand_id}"
  }
}

# Allow the workstation to access CML
resource "aws_security_group_rule" "allow_workstation_to_cml" {
  count                    = local.workstation_enable && local.cml_enable ? 1 : 0
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  security_group_id        = aws_security_group.sg_tf.id
  source_security_group_id = aws_security_group.sg_workstation[0].id
  description             = "Allow all traffic from devnet workstation"
}

# Devnet workstation instance
resource "aws_instance" "devnet_workstation" {
  count               = local.workstation_enable ? 1 : 0
  instance_type        = var.options.cfg.aws.workstation.instance_type
  ami                  = var.options.cfg.aws.workstation.ami
  iam_instance_profile = aws_iam_instance_profile.cml_ssm_profile.name
  key_name             = var.options.cfg.common.key_name
  subnet_id            = aws_subnet.public_subnet.id
  
  # Security enhancements
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = var.options.cfg.common.security.require_imdsv2 ? "required" : "optional"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = 50  # Minimum size required for the AMI
    volume_type           = "gp3"
    encrypted             = var.options.cfg.aws.enable_ebs_encryption
    delete_on_termination = true
  }
  vpc_security_group_ids = [
    aws_security_group.sg_workstation[0].id
  ]

  tags = {
    Name = "devnet-workstation-${var.options.rand_id}"
  }
  
  # Extended user data script with security hardening
  user_data = <<-EOF
#!/bin/bash
echo "DevNet Expert workstation started at $(date)" > /var/log/devnet-setup.log

# Ensure RDP is running
if command -v systemctl > /dev/null && systemctl list-unit-files | grep -q xrdp; then
  systemctl enable xrdp
  systemctl start xrdp
  echo "XRDP service started" >> /var/log/devnet-setup.log
fi

# Apply security hardening measures
if [ "${var.options.cfg.common.security.setup_ufw_firewall}" = "true" ]; then
  echo "Configuring UFW firewall..." >> /var/log/devnet-setup.log
  apt-get update && apt-get install -y ufw
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 3389/tcp  # RDP
  ufw allow 22/tcp    # SSH
  echo "y" | ufw enable
fi

if [ "${var.options.cfg.common.security.configure_fail2ban}" = "true" ]; then
  echo "Configuring fail2ban..." >> /var/log/devnet-setup.log
  apt-get update && apt-get install -y fail2ban
  cat <<FAILCONF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 600
bantime = 3600

[rdp-brute]
enabled = true
filter = rdp-brute
port = 3389
logpath = /var/log/auth.log
maxretry = 5
findtime = 600
bantime = 3600
FAILCONF
  
  # Create custom RDP filter
  cat <<RDPFILTER > /etc/fail2ban/filter.d/rdp-brute.conf
[Definition]
failregex = ^.*sshd.*: Failed .* from <HOST>
ignoreregex =
RDPFILTER

  systemctl enable fail2ban
  systemctl start fail2ban
fi

if [ "${var.options.cfg.common.security.enable_auto_updates}" = "true" ]; then
  echo "Configuring automatic security updates..." >> /var/log/devnet-setup.log
  apt-get update && apt-get install -y unattended-upgrades
  cat <<AUTOCONF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOCONF
fi

echo "DevNet workstation security hardening completed at $(date)" >> /var/log/devnet-setup.log
EOF

  depends_on = [
    aws_internet_gateway.public_igw,
    aws_subnet.public_subnet
  ]
}
