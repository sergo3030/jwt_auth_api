output "application_image" {
  value = aws_launch_template.auth_service.image_id
  description = "The AMI ID of the provisioned instances."
}