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