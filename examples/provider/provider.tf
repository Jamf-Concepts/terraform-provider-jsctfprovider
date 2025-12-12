terraform {
  required_providers {
    jsc = {
      source  = "jsctf"
      version = "1.0.0"
    }

  }
}


provider "jsc" {
  # Configure provider-specific settings if needed
  # Only local email accounts are supported. No SSO or SAML
  username              = "example@example.com"
  password              = "example"
  customerid            = "993ae0ee-4bd8-4325-bc5d-1db0ea45b4f6" //optional
  applicationid         = "pagappid"                             //for PAG resources
  applicationsecret     = "pagappsecret"
  protectclientid       = "protectclientid" //for Protect resources
  protectclientpassword = "protectclientpassword"
  protectdomainname     = "protectdomain.protect.jamfcloud.com"
}
