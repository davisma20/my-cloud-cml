# DevNet Workstation EC2 Instance for CML Access

resource "aws_instance" "devnet_workstation" {
  ami           = var.devnet_ami_id
  instance_type = var.devnet_instance_type
  subnet_id     = var.subnet_id
  vpc_security_group_ids = var.security_group_ids
  key_name      = var.key_name

  tags = {
    Name = "DevNet-Workstation"
  }
}

output "devnet_workstation_public_ip" {
  value = aws_instance.devnet_workstation.public_ip
}
