# 
# This file is used to retrieve existing secrets from AWS Secrets Manager
#

data "aws_secretsmanager_secret" "app" {
  name = "cml/cml-devnet/app"
}

data "aws_secretsmanager_secret_version" "app" {
  secret_id = data.aws_secretsmanager_secret.app.id
}

data "aws_secretsmanager_secret" "sys" {
  name = "cml/cml-devnet/sys"
}

data "aws_secretsmanager_secret_version" "sys" {
  secret_id = data.aws_secretsmanager_secret.sys.id
}

data "aws_secretsmanager_secret" "cluster" {
  name = "cml/cml-devnet/cluster"
}

data "aws_secretsmanager_secret_version" "cluster" {
  secret_id = data.aws_secretsmanager_secret.cluster.id
}

data "aws_secretsmanager_secret" "smartlicense_token" {
  name = "cml/cml-devnet/smartlicense_token"
}

data "aws_secretsmanager_secret_version" "smartlicense_token" {
  secret_id = data.aws_secretsmanager_secret.smartlicense_token.id
}
