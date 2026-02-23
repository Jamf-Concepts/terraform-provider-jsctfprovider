# Helpdesk-style admin for SwiftConnect operators
resource "jsc_admin" "swiftconnect_helpdesk" {
  name     = "SwiftConnect Helpdesk"
  username = "sc-helpdesk@customer.com"

  roles       = ["WRITE_ADMIN"]
  permissions = ["DEVICES", "ACCESS"]
}
