// outputs.tf for CML 2.8.1 AWS deployment

output "cml_instance_public_ip" {
  description = "The public IP address of the CML server."
  value       = aws_instance.cml_server.public_ip
}
// Add more outputs as needed
