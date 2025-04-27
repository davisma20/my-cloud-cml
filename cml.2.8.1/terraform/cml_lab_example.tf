# Example: Automate CML Lab and Node Creation with terraform-provider-cml2

provider "cml2" {
  address  = var.cml_address
  username = var.cml_username # Or use token = var.cml_token
  password = var.cml_password
  insecure = true # Set to true for self-signed certs
}

resource "cml2_lab" "demo" {
  title = "Terraform Demo Lab"
}

resource "cml2_node" "router1" {
  lab_id          = cml2_lab.demo.id
  label           = "router1"
  node_definition = "iosv"
  x               = 100
  y               = 100
}

resource "cml2_node" "router2" {
  lab_id          = cml2_lab.demo.id
  label           = "router2"
  node_definition = "iosv"
  x               = 200
  y               = 100
}

resource "cml2_link" "r1_r2" {
  lab_id   = cml2_lab.demo.id
  node_a   = cml2_node.router1.id
  adapter_a = 0
  node_b   = cml2_node.router2.id
  adapter_b = 0
}

resource "cml2_lifecycle" "lab_lifecycle" {
  lab_id = cml2_lab.demo.id
  state  = "STARTED"
}

output "cml_lab_id" {
  value = cml2_lab.demo.id
}
output "router1_id" {
  value = cml2_node.router1.id
}
output "router2_id" {
  value = cml2_node.router2.id
}
