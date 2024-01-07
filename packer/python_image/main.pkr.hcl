variable "linux_alpine_ami" {
  type        = string
  description = "Amazon Linux AMI."
  default     = "ami-024f768332f080c5e"
}

variable "python_version" {
  type        = string
  description = "Python version."
  default     = "3.9.16"
}

source "amazon-ebs" "python-linux" {
  ami_name      = "python_linux_${var.python_version}"
  instance_type = "t2.micro"
  region        = "eu-central-1"
  source_ami    = "${var.linux_alpine_ami}"
  ssh_username  = "ec2-user"
  tags = {
    Deployer = "PackerImageBuilder",
    App      = "Python",
    Version  = "${var.python_version}"
  }
}

build {
  sources = ["source.amazon-ebs.python-linux"]
  provisioner "shell" {
    inline = [
      "sudo yum update -y",
      "sudo yum install python3-${var.python_version} -y",
      "sudo yum install python3-pip -y"
    ]
  }
}