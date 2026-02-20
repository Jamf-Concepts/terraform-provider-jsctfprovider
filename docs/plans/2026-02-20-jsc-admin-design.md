# jsc_admin Resource Design

**Date**: 2026-02-20
**Status**: Approved

## Goal

Add a `jsc_admin` Terraform resource that creates, reads, and deletes JSC admin accounts with configurable roles and permissions.

## Context

Part of the SwiftConnect Mini Onboarder. The primary use case is provisioning a helpdesk-style admin account for SwiftConnect operators — `WRITE_ADMIN` role with `DEVICES` and `ACCESS` permissions — so they can view device reports and clear security issues without modifying policy.

## Design

**Package**: `endpoints/admin/`
**Resource name**: `jsc_admin`
**Auth**: `auth.MakeRequest()` — session auth, customerId auto-injected

### Endpoints

| Operation | Method | Endpoint |
|---|---|---|
| Create | POST | `/gate/admin-service/v4/customers/{customerid}/admins` |
| Read | GET | `/gate/admin-service/v4/customers/{customerid}/admins/{id}` |
| Delete | DELETE | `/gate/admin-service/v4/customers/{customerid}/admins/{id}` → 204 |

Update = delete + create. PUT endpoint inferred from bundle but not confirmed via DevTools.

### URL construction

`{customerid}` is replaced automatically by `auth.MakeRequest()`.
`{id}` (adminId) is interpolated via `fmt.Sprintf` using `d.Id()`.

### Schema

| Field | Type | Required | Default | JSON path |
|---|---|---|---|---|
| `name` | string | yes | — | `profile.name` |
| `username` | string | yes | — | `authentication.username` |
| `roles` | list(string) | yes | — | `authorization.roles` |
| `permissions` | list(string) | yes | — | `authorization.permissions` |
| `sso_enabled` | bool | optional | `false` | `authentication.sso.enabled` |
| `notification_categories` | list(string) | optional | `[]` | `notificationSettings.subscribedNotificationCategories` |

### SwiftConnect helpdesk example

```hcl
resource "jsc_admin" "swiftconnect_helpdesk" {
  name        = "SwiftConnect Helpdesk"
  username    = "sc-helpdesk@customer.com"
  roles       = ["WRITE_ADMIN"]
  permissions = ["DEVICES", "ACCESS"]
}
```

### Known role values (from bundle)

`MAGIC`, `SUPER_ADMIN`, `WRITE_ADMIN`, `GLOBAL_ADMIN`

### Known permission values (observed)

`CHANGE_PASSWORD_IN_RADAR`, `SKU1_REPORTS`, `SKU2_REPORTS`, `USER_SUMMARY`, `VIEW_REPORTS`, `REPORTS`, `SECURE_REPORTS`, `DATA_REPORTS`, `CONTENT_REPORTS`, `EXTEND_REPORTS`, `AUDIT_LOGS`, `USER_FILTER`, `DATA_MANAGEMENT`, `SECURITY`, `DEVICES`, `SETTINGS`, `ACCESS`
