resource "jsc_entra_idp" "entra_connection" {
  name = "Entra IdP"
}

# Retrieve the consent URL after terraform apply:
#   terraform output entra_consent_url
# Visit the URL in a browser to complete Microsoft OAuth consent.
# Then run: terraform refresh
# The state attribute will update to "APPROVED" once consent is complete.
output "entra_idp_state" {
  value = jsc_entra_idp.entra_connection.state
}

output "entra_consent_url" {
  value     = jsc_entra_idp.entra_connection.consent_url
  sensitive = true
}
