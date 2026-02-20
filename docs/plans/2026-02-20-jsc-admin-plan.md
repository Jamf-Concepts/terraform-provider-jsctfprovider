# jsc_admin Resource Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `jsc_admin` Terraform resource that manages JSC admin accounts with configurable roles, permissions, and authentication settings.

**Architecture:** New package `endpoints/admin/` using `auth.MakeRequest()` for session auth. `{customerid}` in URLs is auto-replaced by `auth.MakeRequest()`. The adminId (`d.Id()`) is interpolated via `fmt.Sprintf` for read/delete. Update is delete+create (PUT inferred but not confirmed).

**Tech Stack:** Go, Terraform Plugin SDK v2, `auth.MakeRequest()` for all API calls

---

### Task 1: Create the resource package and file

**Files:**
- Create: `endpoints/admin/resource_admin.go`

**Step 1: Create the directory**

```bash
mkdir -p /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider/endpoints/admin
```

**Step 2: Write the resource file**

Create `endpoints/admin/resource_admin.go` with this exact content:

```go
// Copyright 2025, Jamf Software LLC.
package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"jsctfprovider/internal/auth"
)

type adminProfile struct {
	Name string `json:"name"`
}

type adminSSO struct {
	Enabled bool `json:"enabled"`
}

type adminAuthentication struct {
	Username string   `json:"username"`
	SSO      adminSSO `json:"sso"`
}

type adminAuthorization struct {
	Permissions []string `json:"permissions"`
	Roles       []string `json:"roles"`
}

type adminNotificationSettings struct {
	SubscribedNotificationCategories []string `json:"subscribedNotificationCategories"`
}

type adminRequest struct {
	Profile              adminProfile              `json:"profile"`
	Authentication       adminAuthentication       `json:"authentication"`
	Authorization        adminAuthorization        `json:"authorization"`
	NotificationSettings adminNotificationSettings `json:"notificationSettings"`
}

type adminResponse struct {
	ID                   string                   `json:"id"`
	Profile              adminProfile             `json:"profile"`
	Authentication       adminAuthentication      `json:"authentication"`
	Authorization        adminAuthorization       `json:"authorization"`
	NotificationSettings adminNotificationSettings `json:"notificationSettings"`
}

// ResourceAdmin returns the schema.Resource for jsc_admin.
func ResourceAdmin() *schema.Resource {
	return &schema.Resource{
		Create: resourceAdminCreate,
		Read:   resourceAdminRead,
		Update: resourceAdminUpdate,
		Delete: resourceAdminDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Display name for the admin account.",
			},
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Username (email address) for the admin account.",
			},
			"roles": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Required:    true,
				Description: "Roles assigned to the admin. Known values: WRITE_ADMIN, SUPER_ADMIN, GLOBAL_ADMIN, MAGIC.",
			},
			"permissions": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Required:    true,
				Description: "Permissions granted to the admin. E.g. DEVICES, ACCESS, SETTINGS, SECURITY.",
			},
			"sso_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether SSO is enabled for this admin account. Defaults to false (local auth).",
			},
			"notification_categories": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "Notification categories to subscribe to. Known values: SECURITY, MOBILE_DATA, SERVICE_MANAGEMENT.",
			},
		},
	}
}

func buildAdminRequest(d *schema.ResourceData) adminRequest {
	return adminRequest{
		Profile: adminProfile{
			Name: d.Get("name").(string),
		},
		Authentication: adminAuthentication{
			Username: d.Get("username").(string),
			SSO:      adminSSO{Enabled: d.Get("sso_enabled").(bool)},
		},
		Authorization: adminAuthorization{
			Roles:       toStringSlice(d.Get("roles").([]interface{})),
			Permissions: toStringSlice(d.Get("permissions").([]interface{})),
		},
		NotificationSettings: adminNotificationSettings{
			SubscribedNotificationCategories: toStringSlice(d.Get("notification_categories").([]interface{})),
		},
	}
}

func toStringSlice(in []interface{}) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = v.(string)
	}
	return out
}

func resourceAdminCreate(d *schema.ResourceData, m interface{}) error {
	payload, err := json.Marshal(buildAdminRequest(d))
	if err != nil {
		return fmt.Errorf("failed to marshal jsc_admin payload: %v", err)
	}

	req, err := http.NewRequest("POST", "https://radar.wandera.com/gate/admin-service/v4/customers/{customerid}/admins", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to build jsc_admin create request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_admin create request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create jsc_admin: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_admin create response: %v", err)
	}

	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse jsc_admin create response: %v", err)
	}

	if response.ID == "" {
		return fmt.Errorf("jsc_admin was created but API returned an empty ID")
	}

	d.SetId(response.ID)
	return nil
}

func resourceAdminRead(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/admin-service/v4/customers/{customerid}/admins/%s", d.Id()), nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_admin read request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_admin read request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to read jsc_admin: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_admin read response: %v", err)
	}

	var response adminResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse jsc_admin read response: %v", err)
	}

	d.Set("name", response.Profile.Name)
	d.Set("username", response.Authentication.Username)
	d.Set("sso_enabled", response.Authentication.SSO.Enabled)
	d.Set("roles", response.Authorization.Roles)
	d.Set("permissions", response.Authorization.Permissions)
	d.Set("notification_categories", response.NotificationSettings.SubscribedNotificationCategories)

	return nil
}

func resourceAdminUpdate(d *schema.ResourceData, m interface{}) error {
	if err := resourceAdminDelete(d, m); err != nil {
		return err
	}
	return resourceAdminCreate(d, m)
}

func resourceAdminDelete(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://radar.wandera.com/gate/admin-service/v4/customers/{customerid}/admins/%s", d.Id()), nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_admin delete request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_admin delete request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete jsc_admin: %s", resp.Status)
	}

	d.SetId("")
	return nil
}
```

**Step 3: Commit**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
git add endpoints/admin/resource_admin.go
git commit -m "feat: add jsc_admin resource for admin account management"
```

---

### Task 2: Register in main.go

**Files:**
- Modify: `main.go`

**Step 1: Add the import**

In the `import` block, add (alphabetical order, before `activationprofiles`):

```go
"jsctfprovider/endpoints/admin"
```

**Step 2: Add to ResourcesMap**

```go
"jsc_admin": admin.ResourceAdmin(),
```

**Step 3: Commit**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
git add main.go
git commit -m "feat: register jsc_admin in provider ResourcesMap"
```

---

### Task 3: Add example and docs

**Files:**
- Create: `examples/resources/jsc_admin/resource.tf`
- Create: `docs/resources/admin.md`

**Step 1: Create the example**

```bash
mkdir -p /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider/examples/resources/jsc_admin
```

Write `examples/resources/jsc_admin/resource.tf`:

```hcl
# Helpdesk-style admin for SwiftConnect operators
resource "jsc_admin" "swiftconnect_helpdesk" {
  name     = "SwiftConnect Helpdesk"
  username = "sc-helpdesk@customer.com"

  roles       = ["WRITE_ADMIN"]
  permissions = ["DEVICES", "ACCESS"]
}
```

**Step 2: Write the docs page**

Write `docs/resources/admin.md`:

```markdown
---
page_title: "jsc_admin Resource - jsc"
subcategory: ""
description: |-
  Manages a JSC admin account with configurable roles and permissions.
---

# jsc_admin (Resource)

Manages a JSC admin account. Used in the SwiftConnect Mini Onboarder to provision a helpdesk-style operator account that can view device reports and clear security issues without the ability to modify policy.

## Notes

- Update is implemented as delete + recreate (PUT endpoint inferred but not confirmed via API traffic capture)
- A 404 on read causes Terraform to mark the resource as destroyed and recreate on next `apply`
- Known roles: `WRITE_ADMIN`, `SUPER_ADMIN`, `GLOBAL_ADMIN`, `MAGIC`
- `SUPER_ADMIN` stacks on top of `WRITE_ADMIN` — a super admin has both roles
- For a helpdesk-style account: use `WRITE_ADMIN` with limited permissions (`DEVICES`, `ACCESS`)

## Example Usage

```hcl
resource "jsc_admin" "swiftconnect_helpdesk" {
  name     = "SwiftConnect Helpdesk"
  username = "sc-helpdesk@customer.com"

  roles       = ["WRITE_ADMIN"]
  permissions = ["DEVICES", "ACCESS"]
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) Display name for the admin account.
- `permissions` (List of String) Permissions granted to the admin. Known values: `DEVICES`, `ACCESS`, `SETTINGS`, `SECURITY`, `REPORTS`, `AUDIT_LOGS`, and others.
- `roles` (List of String) Roles assigned to the admin. Known values: `WRITE_ADMIN`, `SUPER_ADMIN`, `GLOBAL_ADMIN`, `MAGIC`.
- `username` (String) Username (email address) for the admin account.

### Optional

- `notification_categories` (List of String) Notification categories to subscribe to. Known values: `SECURITY`, `MOBILE_DATA`, `SERVICE_MANAGEMENT`.
- `sso_enabled` (Boolean) Whether SSO is enabled for this admin account. Defaults to `false` (local auth).

### Read-Only

- `id` (String) The ID of this resource.
```

**Step 3: Commit**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
git add examples/resources/jsc_admin/resource.tf docs/resources/admin.md
git commit -m "docs: add example and registry docs for jsc_admin"
```

---

### Task 4: Push branch and open PR

**Step 1: Push**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
git push -u origin resource/jsc-admin
```

**Step 2: Open the PR**

```bash
gh pr create \
  --title "feat: add jsc_admin resource for admin account management" \
  --body "$(cat <<'EOF'
## Summary

Adds the `jsc_admin` Terraform resource to the JSC provider.

This resource manages JSC admin accounts with configurable roles and permissions. It is part of the SwiftConnect Mini Onboarder — used to provision a helpdesk-style operator account so SwiftConnect admins can view device reports and clear security issues that may block enrollment, without the ability to modify policy.

## Schema

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | yes | Display name |
| `username` | string | yes | Email address |
| `roles` | list(string) | yes | e.g. `["WRITE_ADMIN"]` |
| `permissions` | list(string) | yes | e.g. `["DEVICES", "ACCESS"]` |
| `sso_enabled` | bool | no | Default `false` |
| `notification_categories` | list(string) | no | Default `[]` |

## SwiftConnect helpdesk use case

```hcl
resource "jsc_admin" "swiftconnect_helpdesk" {
  name     = "SwiftConnect Helpdesk"
  username = "sc-helpdesk@customer.com"

  roles       = ["WRITE_ADMIN"]
  permissions = ["DEVICES", "ACCESS"]
}
```

## API notes

- Endpoints confirmed via Chrome DevTools live traffic capture
- `{customerid}` in URL paths is replaced automatically by `auth.MakeRequest()`
- The adminId (`d.Id()`) is used for read and delete via `fmt.Sprintf`
- Update = delete + recreate (PUT endpoint inferred from bundle but not confirmed — can be added once verified)
- 404 on read clears resource ID; Terraform recreates on next apply

## Files changed

- `endpoints/admin/resource_admin.go` — new resource
- `main.go` — import + ResourcesMap registration
- `examples/resources/jsc_admin/resource.tf` — example usage
- `docs/resources/admin.md` — registry documentation
- `docs/plans/2026-02-20-jsc-admin-design.md` — design doc
- `docs/plans/2026-02-20-jsc-admin-plan.md` — implementation plan

## Test plan

- [ ] `go build ./...` passes cleanly
- [ ] `terraform plan` shows expected create
- [ ] `terraform apply` creates the admin account in a test JSC tenant
- [ ] Admin appears in the JSC UI with correct role and permissions
- [ ] `terraform destroy` removes the account cleanly (204 response)
- [ ] Modifying any field triggers delete + recreate
- [ ] `sso_enabled = true` reflects correctly on read

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

**Do NOT merge.** This PR is for team review.
