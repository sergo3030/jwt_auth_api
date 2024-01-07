variable "git_branches" {
  type        = map(string)
  description = "Mapping between infrastructure evironment and Github repository branches."
  default = {
    "development" = "development"
    "integration" = "integration"
    "production"  = "main"
  }
}

variable "environment" {
  type        = string
  description = "Working environement relevant resources are deployed to."
  validation {
    condition     = contains(["development", "integration", "production"], var.environment)
    error_message = "Valid values for var: environment are (development, integration, production)."
  }
}

locals {
  git_branch = lookup(var.git_branches, var.environment, "development")
}

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "sg_asg_http" {
  name   = "asg-allow-http"
  vpc_id = data.aws_vpc.default.id
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.sg_alb_http.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "sg_asg_ssh" {
  name   = "asg-allow-ssh"
  vpc_id = data.aws_vpc.default.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["77.137.64.254/32"]
  }
}

resource "aws_security_group" "sg_alb_http" {
  name   = "alb-allow-http"
  vpc_id = data.aws_vpc.default.id
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_alb_target_group" "auth_instances" {
  name        = "auth-service-alb-tg"
  port        = 8080
  protocol    = "TCP"
  target_type = "instance"
  vpc_id      = data.aws_vpc.default.id
}

data "aws_ami" "bonfire_auth_linux" {
  owners      = ["795940035805"]
  most_recent = true
  filter {
    name   = "name"
    values = ["bonfire_auth_*"]
  }
}

resource "aws_launch_template" "auth_service" {
  name                   = "auth-service-lt"
  image_id               = data.aws_ami.bonfire_auth_linux.id
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.sg_asg_http.id, aws_security_group.sg_asg_ssh.id]
  tag_specifications {
    resource_type = "instance"
    tags = {
      App          = "BonfireAuth"
      Environement = "${var.environment}"
      Version      = "latest"
    }
  }
  user_data = filebase64("C:\\Users\\user\\Desktop\\jwt_auth_api\\terraform\\user_data.sh")
}

resource "aws_autoscaling_group" "auth_service" {
  name                = "auth-service-asg"
  desired_capacity    = 2
  min_size            = 1
  max_size            = 3
  health_check_type   = "ELB"
  vpc_zone_identifier = toset(data.aws_subnets.default.ids)
  target_group_arns   = [aws_alb_target_group.auth_instances.arn]
  launch_template {
    id      = aws_launch_template.auth_service.id
    version = "$Latest"
  }
  tag {
    key                 = "App"
    value               = "BonfireAuth"
    propagate_at_launch = true
  }
  tag {
    key                 = "Environement"
    value               = var.environment
    propagate_at_launch = true
  }
  tag {
    key                 = "Version"
    value               = "latest"
    propagate_at_launch = true
  }
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_lb" "auth_service" {
  name               = "auth-service-alb"
  load_balancer_type = "application"
  subnets            = toset(data.aws_subnets.default.ids)
  security_groups    = [aws_security_group.sg_alb_http.id]
  tags = {
    App          = "BonfireAuth"
    Environement = "${var.environment}"
    Version      = "latest"
  }
}

resource "aws_lb_listener" "auth_service" {
  load_balancer_arn = aws_lb.auth_service.arn
  port              = "8080"
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.auth_instances.arn
  }
}