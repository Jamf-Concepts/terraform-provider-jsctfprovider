resource "jsc_swiftconnect" "swiftconnect_integration" {
  base_url       = "https://api.swiftconnect.io"
  application_id = "your-swiftconnect-application-id"
  origo_uuid     = "your-origo-uuid"

  # Optional
  organization_uuid    = "your-organization-uuid"
  risk_level_enabled   = true
  risk_level_threshold = "HIGH"
}
