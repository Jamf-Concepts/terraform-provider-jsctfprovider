terraform {
  required_providers {
    jsc = {
      source  = "jsctf"
      version = "1.0.0"
    }

  }
}


provider "jsc" {
  # Configure provider authentication
  # NOTE: Only local email accounts are supported. SSO/SAML not supported.
  #
  # Credentials should be provided via terraform.tfvars (see terraform.tfvars.example)
  # or environment variables (JSC_USERNAME, JSC_PASSWORD, etc.)

  username   = var.jsc_username
  password   = var.jsc_password
  customerid = var.jsc_customerid # Optional - set to "empty" to auto-discover

  # Optional: PAG resources configuration
  applicationid     = var.jsc_applicationid
  applicationsecret = var.jsc_applicationsecret

  # Optional: Protect resources configuration
  protectclientid       = var.jsc_protectclientid
  protectclientpassword = var.jsc_protectclientpassword
  protectdomainname     = var.jsc_protectdomainname
}
