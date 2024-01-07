variable "app_version" {
  type        = string
  description = "Version of the application."
  default     = "1.0.0"
}

variable "git_username" {
  type        = string
  description = "GitHub username that performs git clone."
  sensitive   = true
  default     = "sergo3030"
}

variable "git_pat" {
  type        = string
  description = "Private Access Token of the GitHub user"
  sensitive   = true
  default     = "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"
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
    Deployer = "PackerImageBuilder",
    App      = "BonfireAuth",
    Version  = "${var.app_version}"
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
      "git checkout development",
      "export APP_WORKDIR='pwd'"
    ]
  }
}
