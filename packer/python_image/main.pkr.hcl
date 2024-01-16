source "amazon-ebs" "python-linux" {
  ami_name      = "python_linux_${var.python_version}"
  instance_type = "t2.micro"
  region        = "eu-central-1"
  source_ami    = "${var.linux_alpine_ami}"
  ssh_username  = "ec2-user"
  tags = {
    Deployer = "PackerImageBuilder",
    App      = "Python"
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