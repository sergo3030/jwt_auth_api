locals {
  git_branch = lookup(var.git_branches, var.environment, "development")
}

data "amazon-ami" "python-linux" {
  owners      = ["795940035805"]
  region      = "eu-central-1"
  most_recent = true
  filters = {
    name = "python_linux_*"
  }
}

source "amazon-ebs" "bonfire_auth" {
  ami_name      = "bonfire_auth_${var.app_version}"
  instance_type = "t2.micro"
  region        = "eu-central-1"
  source_ami    = data.amazon-ami.python-linux.id
  ssh_username  = "ec2-user"
  tags = {
    Deployer     = "PackerImageBuilder",
    App          = "BonfireAuth",
    Environement = "${var.environment}"
  }
}

build {
  sources = ["source.amazon-ebs.bonfire_auth"]
  provisioner "shell" {
    inline = [
      "sudo yum install git -y",
      "cd /home/ec2-user",
      "git clone https://${var.git_username}:${var.git_pat}@github.com/sergo3030/jwt_auth_api.git",
      "cd jwt_auth_api/",
      "git checkout ${local.git_branch}",
      "git pull",
      "pip-3 install -r requirements.txt"
    ]
  }
}
