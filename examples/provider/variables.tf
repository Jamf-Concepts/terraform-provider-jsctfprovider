variable "jsc_username" {
  description = "JSC username (email) for authentication"
  type        = string
  sensitive   = true
}

variable "jsc_password" {
  description = "JSC password for authentication"
  type        = string
  sensitive   = true
}

variable "jsc_customerid" {
  description = "JSC customer ID (optional - will auto-discover if set to 'empty')"
  type        = string
  default     = "empty"
}

variable "jsc_applicationid" {
  description = "Application ID for PAG resources (optional)"
  type        = string
  default     = ""
}

variable "jsc_applicationsecret" {
  description = "Application secret for PAG resources (optional)"
  type        = string
  sensitive   = true
  default     = ""
}
