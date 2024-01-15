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

variable "app_version" {
  type        = string
  description = "Version of the application."
  default     = "1.0.0"
}

variable "git_username" {
  type        = string
  description = "GitHub username that performs git clone."
  sensitive   = true
}

variable "git_pat" {
  type        = string
  description = "Private Access Token of the GitHub user"
  sensitive   = true
}