# Example tfvars file for CML deployment
# Copy to terraform.tfvars and fill in real values for your environment

options = {
  cfg = {
    aws = {
      flavor = "c5.2xlarge"
      ami_id = "ami-xxxxxxxx"
      enable_ebs_encryption = true
      # ...add all other required AWS config fields
    }
    common = {
      disk_size = 50
      controller_hostname = "cml-controller"
      # ...add all other required common config fields
    }
    cluster = {
      enable_cluster = false
      number_of_compute_nodes = 0
      # ...add all other cluster config fields
    }
    # ...add other config sections as needed
  }
  # ...add other options fields as needed
}

cfg = {
  aws = {
    flavor = "c5.2xlarge"
    ami_id = "ami-xxxxxxxx"
    enable_ebs_encryption = true
    # ...add all other required AWS config fields
  }
  common = {
    disk_size = 50
    controller_hostname = "cml-controller"
    # ...add all other required common config fields
  }
  cluster = {
    enable_cluster = false
    number_of_compute_nodes = 0
    # ...add all other cluster config fields
  }
  # ...add other config sections as needed
}
