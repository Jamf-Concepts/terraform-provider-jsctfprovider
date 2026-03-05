# Example: Create a Google Workspace IdP connection for RADAR
#
# This resource creates an identity provider connection to Google Workspace,
# enabling user and group sync for risk-based policies in Jamf Security Cloud.
#
# IMPORTANT: After creation, an administrator must visit the consent_url in a
# browser to authorize RADAR access to Google Workspace directory data.

resource "jsc_google_idp" "example" {
  name = "Google Workspace - Production"
}

# Output the consent URL for the admin to complete OAuth authorization
output "google_idp_consent_url" {
  value       = jsc_google_idp.example.consent_url
  description = "Visit this URL to authorize RADAR access to Google Workspace"
  sensitive   = true
}

# Output the connection state (INITIAL until consent is completed, then APPROVED)
output "google_idp_state" {
  value       = jsc_google_idp.example.state
  description = "Current state of the Google IdP connection"
}
