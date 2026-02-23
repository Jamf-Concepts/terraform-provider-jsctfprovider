# Route SwiftConnect provisioning server traffic through JSC ZTNA
resource "jsc_app" "swiftconnect_access_policy" {
  name      = "SwiftConnect Provisioning"
  type      = "ENTERPRISE"
  hostnames = ["provisioning.swiftconnect.io"]

  routingtype = "CUSTOM"
  routingid   = "a7d2" # Nearest Data Center — obtain from jsc_pag_vpnroutes datasource

  assignmentallusers = true

  securityriskcontrolenabled   = true
  securityriskcontrolthreshold = "HIGH"
}
