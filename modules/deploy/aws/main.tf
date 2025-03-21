#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  workstation_enable = true  # Force enable workstation
  cml_enable = false  # Disable CML controller
  num_computes = var.options.cfg.cluster.enable_cluster ? var.options.cfg.cluster.number_of_compute_nodes : 0
  compute_hostnames = [
    for i in range(1, local.num_computes + 1) :
    format("%s-%d", var.options.cfg.cluster.compute_hostname_prefix, i)
  ]

  # Late binding required as the token is only known within the module.
  # (Azure specific)
  vars = templatefile("${path.module}/../data/vars.sh", {
    cfg = merge(
      var.options.cfg,
      # Need to have this as it's referenced in the template (Azure specific)
      { sas_token = "undefined" }
    )
    }
  )

  cml_config_controller = templatefile("${path.module}/../data/virl2-base-config.yml", {
    hostname      = var.options.cfg.common.controller_hostname,
    is_controller = true
    is_compute    = !var.options.cfg.cluster.enable_cluster || var.options.cfg.cluster.allow_vms_on_controller
    cfg = merge(
      var.options.cfg,
      # Need to have this as it's referenced in the template (Azure specific)
      { sas_token = "undefined" }
    )
    }
  )

  cml_config_compute = [for compute_hostname in local.compute_hostnames : templatefile("${path.module}/../data/virl2-base-config.yml", {
    hostname      = compute_hostname,
    is_controller = false,
    is_compute    = true,
    cfg = merge(
      var.options.cfg,
      # Need to have this as it's referenced in the template.
      # (Azure specific)
      { sas_token = "undefined" }
    )
    }
  )]

  # Ensure there's no tabs in the template file! Also ensure that the list of
  # reference platforms has no single quotes in the file names or keys (should
  # be reasonable, but you never know...)
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
    extras        = var.options.extras
    hostname      = var.options.cfg.common.controller_hostname
    path          = path.module
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
      "to_port" : 1122
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
      "to_port" : 22
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
      "to_port" : 9090
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
      "to_port" : 80
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
      "to_port" : 443
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
      "to_port" : 7999
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
      "to_port" : 7999
      "protocol" : "udp",
      "cidr_blocks" : var.options.cfg.common.allowed_ipv4_subnets,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    }
  ]
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
      "to_port" : 0
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
      "to_port" : 0
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
      "to_port" : 0
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

resource "aws_network_interface" "pub_int_cml" {
  subnet_id       = aws_subnet.public_subnet.id
  security_groups = [aws_security_group.sg_tf.id]
  tags            = { Name = "CML-controller-pub-int-${var.options.rand_id}" }
}

resource "aws_eip" "server_eip" {
  network_interface = aws_network_interface.pub_int_cml.id
  tags              = { "Name" = "CML-controller-eip-${var.options.rand_id}", "device" = "server" }
  depends_on        = [aws_instance.cml_controller]
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
  allocation_id = aws_eip.nat_eip[0].id // Allocate an EIP 
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
  instance_type        = var.options.cfg.aws.flavor
  ami                  = data.aws_ami.ubuntu.id
  iam_instance_profile = var.options.cfg.aws.profile
  key_name             = var.options.cfg.common.key_name
  
  timeouts {
    create = "10m"
  }

  root_block_device {
    volume_size = var.options.cfg.common.disk_size
    volume_type = "gp3"
    encrypted   = var.options.cfg.aws.enable_ebs_encryption
  }
  network_interface {
    network_interface_id = aws_network_interface.pub_int_cml.id
    device_index         = 0
  }
  dynamic "network_interface" {
    for_each = var.options.cfg.cluster.enable_cluster ? [1] : []
    content {
      network_interface_id = aws_network_interface.cluster_int_cml[0].id
      device_index         = 1
    }
  }
  user_data = data.cloudinit_config.cml_controller.rendered
  depends_on           = [aws_route_table_association.public_subnet]
  dynamic "instance_market_options" {
    for_each = var.options.cfg.aws.spot_instances.use_spot_for_controller ? [1] : []
    content {
      market_type = "spot"
      spot_options {
        instance_interruption_behavior = "stop"
        spot_instance_type             = "persistent"
      }
    }
  }
  tags                 = { Name = "CML-controller-${var.options.rand_id}" }
  ebs_optimized        = "true"
  count                = local.cml_enable ? 1 : 0
}

resource "aws_instance" "cml_compute" {
  instance_type        = var.options.cfg.aws.flavor_compute
  ami                  = data.aws_ami.ubuntu.id
  iam_instance_profile = var.options.cfg.aws.profile
  key_name             = var.options.cfg.common.key_name
  tags                 = { Name = "CML-compute-${count.index + 1}-${var.options.rand_id}" }
  ebs_optimized        = "true"
  count                = local.cml_enable ? local.num_computes : 0
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
  base64_encode = true # always true if gzip is true

  part {
    filename     = "cloud-config.yaml"
    content_type = "text/cloud-config"
    content      = local.cloud_config
  }
}

data "cloudinit_config" "cml_compute" {
  gzip          = true
  base64_encode = true # always true if gzip is true
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

  # Allow SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    description = "allow SSH"
    cidr_blocks = var.options.cfg.common.allowed_ipv4_subnets
  }

  # Allow RDP
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    description = "allow RDP"
    cidr_blocks = var.options.cfg.common.allowed_ipv4_subnets
  }

  # Allow outbound HTTPS for updates and downloads
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "allow HTTPS outbound"
  }
  
  # Allow outbound HTTP for updates and downloads
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "allow HTTP outbound"
  }
  
  # Allow outbound DNS
  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "allow DNS outbound"
  }
  
  # Allow NTP
  egress {
    from_port   = 123
    to_port     = 123
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "allow NTP outbound"
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
  ami                  = "ami-0a0e4ef95325270c9"  # Use the correct imported DevNet Expert AMI
  iam_instance_profile = var.options.cfg.aws.profile
  key_name             = var.options.cfg.common.key_name
  subnet_id            = aws_subnet.public_subnet.id
  
  # Require IMDSv2 (more secure metadata service access)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # Require IMDSv2 tokens
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
    encrypted   = true  # Enable encryption for the root volume
    delete_on_termination = true
  }

  vpc_security_group_ids = [
    aws_security_group.sg_workstation[0].id
  ]

  tags = {
    Name = "devnet-workstation-${var.options.rand_id}"
  }
  
  # Enhanced security setup for DevNet workstation
  user_data = <<-EOF
              #!/bin/bash
              
              # Log startup
              echo "DevNet Expert workstation started at $(date)" > /var/log/devnet-setup-complete.log
              
              # Ensure RDP is enabled and running
              if command -v systemctl > /dev/null && systemctl list-unit-files | grep -q xrdp; then
                systemctl enable xrdp
                systemctl start xrdp
                echo "XRDP service started" >> /var/log/devnet-setup-complete.log
              fi
              
              # Security hardening
              
              # 1. Update all packages
              apt-get update && apt-get upgrade -y
              
              # 2. Configure firewall
              if command -v ufw > /dev/null; then
                ufw default deny incoming
                ufw default allow outgoing
                ufw allow 22/tcp  # SSH
                ufw allow 3389/tcp  # RDP
                ufw --force enable
                echo "UFW firewall configured" >> /var/log/devnet-setup-complete.log
              fi
              
              # 3. Set up automatic security updates
              apt-get install -y unattended-upgrades
              echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
              echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
              echo "Automatic updates configured" >> /var/log/devnet-setup-complete.log
              
              # 4. Set password complexity requirements
              if [ -f /etc/pam.d/common-password ]; then
                sed -i 's/password.*pam_unix.so.*/password        requisite                       pam_unix.so minlen=12 sha512 shadow remember=5/' /etc/pam.d/common-password
                echo "Password complexity requirements set" >> /var/log/devnet-setup-complete.log
              fi
              
              # 5. Configure login failure detection and banning
              apt-get install -y fail2ban
              cat <<FAIL2BAN > /etc/fail2ban/jail.local
              [sshd]
              enabled = true
              port = 22
              filter = sshd
              logpath = /var/log/auth.log
              maxretry = 5
              bantime = 3600
              
              [xrdp]
              enabled = true
              port = 3389
              filter = xrdp
              logpath = /var/log/xrdp-sesman.log
              maxretry = 5
              bantime = 3600
              FAIL2BAN
              
              # Create filter for XRDP
              mkdir -p /etc/fail2ban/filter.d
              cat <<XRDPFILTER > /etc/fail2ban/filter.d/xrdp.conf
              [Definition]
              failregex = ^.*authentication failed.*user=.+.*from IP=<HOST>.*$
              ignoreregex =
              XRDPFILTER
              
              systemctl enable fail2ban
              systemctl restart fail2ban
              echo "Fail2ban configured for SSH and RDP protection" >> /var/log/devnet-setup-complete.log
              
              # 6. Disable unnecessary services
              systemctl disable bluetooth.service || true
              systemctl disable cups.service || true
              echo "Disabled unnecessary services" >> /var/log/devnet-setup-complete.log
              
              # 7. Set secure SSH configuration
              if [ -f /etc/ssh/sshd_config ]; then
                sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
                sed -i 's/#MaxAuthTries.*/MaxAuthTries 5/' /etc/ssh/sshd_config
                sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
                echo "Secured SSH configuration" >> /var/log/devnet-setup-complete.log
                systemctl restart sshd
              fi
              
              echo "Security hardening completed at $(date)" >> /var/log/devnet-setup-complete.log
              
              # Create security validation script
              cat <<'VALIDATE' > /home/admin/validate_security.sh
#!/bin/bash
# Security validation script
echo "==============================================="
echo "DevNet Workstation Security Validation Report"
echo "==============================================="
echo "Generated: $(date)"
echo

# Check if volume is encrypted
echo "### Volume Encryption Status ###"
if lsblk -o NAME,TYPE,MOUNTPOINT,SIZE,FSTYPE,MODEL,LABEL,UUID,RO,RM,PARTTYPE,PARTUUID | grep -q "crypt"; then
  echo "[PASS] Root volume appears to be encrypted"
else
  echo "[WARN] Root volume encryption not detected"
fi
echo

# Check IMDSv2 requirement
echo "### IMDSv2 Status ###"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
if [ -n "$TOKEN" ]; then
  echo "[PASS] IMDSv2 token retrieved successfully"
  INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)
  echo "       Instance ID: $INSTANCE_ID"
else
  echo "[WARN] Failed to retrieve IMDSv2 token"
fi
echo

# Check firewall status
echo "### Firewall Status ###"
if command -v ufw > /dev/null; then
  UFW_STATUS=$(ufw status)
  if echo "$UFW_STATUS" | grep -q "Status: active"; then
    echo "[PASS] UFW firewall is active"
    echo "$UFW_STATUS" | grep -E 'Status:|To |22/tcp|3389/tcp'
  else
    echo "[FAIL] UFW firewall is not active"
  fi
else
  echo "[FAIL] UFW firewall is not installed"
fi
echo

# Check fail2ban status
echo "### Fail2Ban Status ###"
if command -v fail2ban-client > /dev/null; then
  FAIL2BAN_STATUS=$(fail2ban-client status)
  if echo "$FAIL2BAN_STATUS" | grep -q "Number of jail:"; then
    echo "[PASS] Fail2ban is active"
    echo "Jails:"
    fail2ban-client status | grep "Jail list" | sed 's/`- Jail list://'
  else
    echo "[FAIL] Fail2ban is not active"
  fi
else
  echo "[FAIL] Fail2ban is not installed"
fi
echo

# Check SSH configuration
echo "### SSH Configuration ###"
if [ -f /etc/ssh/sshd_config ]; then
  ROOT_LOGIN=$(grep "^PermitRootLogin" /etc/ssh/sshd_config)
  PASS_AUTH=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config)
  MAX_AUTH=$(grep "^MaxAuthTries" /etc/ssh/sshd_config)
  
  echo "[INFO] SSH Configuration:"
  echo "  $ROOT_LOGIN"
  echo "  $PASS_AUTH"
  echo "  $MAX_AUTH"
  
  if [[ "$ROOT_LOGIN" == *"no"* ]]; then
    echo "[PASS] Root login is disabled"
  else
    echo "[FAIL] Root login is not disabled"
  fi
  
  if [[ "$PASS_AUTH" == *"no"* ]]; then
    echo "[PASS] Password authentication is disabled"
  else
    echo "[WARN] Password authentication is not disabled"
  fi
else
  echo "[FAIL] SSH config file not found"
fi
echo

# Check automatic updates
echo "### Automatic Updates ###"
if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
  echo "[PASS] Unattended upgrades are configured"
  cat /etc/apt/apt.conf.d/20auto-upgrades
else
  echo "[FAIL] Unattended upgrades are not configured"
fi
echo

# Check password policies
echo "### Password Policies ###"
if grep -q "pam_unix.so.*minlen=12" /etc/pam.d/common-password; then
  echo "[PASS] Password complexity requirements are set"
  grep "pam_unix.so" /etc/pam.d/common-password
else
  echo "[FAIL] Password complexity requirements are not set"
fi
echo

# Check memory limits
echo "### System Hardening ###"
if ! systemctl is-enabled bluetooth.service > /dev/null 2>&1; then
  echo "[PASS] Bluetooth service is disabled"
else
  echo "[WARN] Bluetooth service is enabled"
fi

if ! systemctl is-enabled cups.service > /dev/null 2>&1; then
  echo "[PASS] CUPS service is disabled"
else
  echo "[WARN] CUPS service is enabled"
fi
echo

echo "==============================================="
echo "End of Security Validation Report"
echo "==============================================="
VALIDATE

              chmod +x /home/admin/validate_security.sh
              echo "Security validation script installed at /home/admin/validate_security.sh" >> /var/log/devnet-setup-complete.log

              # Run the validation after 5 minutes (allowing time for all security features to apply)
              cat <<CRONVAL > /etc/cron.d/security-validation
@reboot root sleep 300 && /home/admin/validate_security.sh > /home/admin/security_validation_report.txt 2>&1
CRONVAL

              chmod 644 /etc/cron.d/security-validation
              echo "Security validation script will run 5 minutes after each reboot" >> /var/log/devnet-setup-complete.log
              EOF
}
