resource "jsc_entra_idp" "entra_connection" {
  name = "Entra IdP"
}

# After terraform apply, visit the consent URL printed to the console.
# Then run: terraform refresh
# The state attribute will update to "APPROVED" once consent is complete.
output "entra_idp_state" {
  value = jsc_entra_idp.entra_connection.state
}
