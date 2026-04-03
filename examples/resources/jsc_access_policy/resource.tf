# Route SwiftConnect provisioning server traffic through JSC ZTNA
resource "jsc_access_policy" "swiftconnect_access_policy" {
  name      = "SwiftConnect Provisioning"
  type      = "ENTERPRISE"
  hostnames = ["provisioning.swiftconnect.io"]

  routingtype = "CUSTOM"
  routingid   = "a7d2" # Nearest Data Center — obtain from jsc_pag_vpnroutes datasource

  assignmentallusers = true

  securityriskcontrolenabled   = true
  securityriskcontrolthreshold = "HIGH"
}

# Template-based (SaaS app)
data "jsc_app_template" "okta" {
  name = "Okta"
}

resource "jsc_access_policy" "okta" {
  name            = "Okta Access"
  app_template_id = data.jsc_app_template.okta.id
  routingtype     = "DIRECT"

  assignmentallusers = true
}
