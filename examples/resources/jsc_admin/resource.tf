# Read-only admin with specific permissions
resource "jsc_admin" "readonly_helpdesk" {
  name     = "Helpdesk Read-Only"
  username = "helpdesk-ro@customer.com"

  # Empty roles = read-only
  roles       = []
  permissions = ["DEVICES", "ACCESS", "AUDIT_LOGS"]
}

# Super admin (permissions auto-granted)
resource "jsc_admin" "super_admin" {
  name     = "Super Administrator"
  username = "admin@customer.com"

  roles = ["SUPER_ADMIN"]
  # Permissions not needed - auto-granted by SUPER_ADMIN role
}
