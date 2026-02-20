# jsc_app Resource Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `jsc_app` Terraform resource that manages ZTNA per-app routing entries in JSC via the traffic-routing-service gateway API.

**Architecture:** New package `endpoints/ztna_app/` following the flat-schema pattern of `jsc_pag_ztnaapp`. Uses `auth.MakeRequest()` for session auth (not PAG JWT). Update is delete+create. Structs defined locally in the package.

**Tech Stack:** Go, Terraform Plugin SDK v2, `auth.MakeRequest()` for all API calls

---

### Task 1: Create the resource package and file

**Files:**
- Create: `endpoints/ztna_app/resource_ztnaapp.go`

**Step 1: Create the package directory**

```bash
mkdir -p /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider/endpoints/ztna_app
```

**Step 2: Write the resource file**

Create `endpoints/ztna_app/resource_ztnaapp.go` with this exact content:

```go
// Copyright 2025, Jamf Software LLC.
package ztna_app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"jsctfprovider/internal/auth"
)

// Structs for request/response marshalling

type ztnaAppInclusions struct {
	AllUsers bool     `json:"allUsers"`
	Groups   []string `json:"groups"`
}

type ztnaAppAssignments struct {
	Inclusions ztnaAppInclusions `json:"inclusions"`
}

type ztnaAppRouting struct {
	Type                string `json:"type"`
	RouteId             string `json:"routeId,omitempty"`
	DnsIpResolutionType string `json:"dnsIpResolutionType,omitempty"`
}

type ztnaAppRiskControls struct {
	Enabled              bool   `json:"enabled"`
	LevelThreshold       string `json:"levelThreshold"`
	NotificationsEnabled bool   `json:"notificationsEnabled"`
}

type ztnaAppDohIntegration struct {
	Blocking             bool `json:"blocking"`
	NotificationsEnabled bool `json:"notificationsEnabled"`
}

type ztnaAppDeviceMgmtAccess struct {
	Enabled              bool `json:"enabled"`
	NotificationsEnabled bool `json:"notificationsEnabled"`
}

type ztnaAppSecurity struct {
	RiskControls                ztnaAppRiskControls     `json:"riskControls"`
	DohIntegration              ztnaAppDohIntegration   `json:"dohIntegration"`
	DeviceManagementBasedAccess ztnaAppDeviceMgmtAccess `json:"deviceManagementBasedAccess"`
}

type ztnaAppRequest struct {
	Name         string             `json:"name"`
	Type         string             `json:"type"`
	CategoryName string             `json:"categoryName"`
	Hostnames    []string           `json:"hostnames"`
	BareIps      []string           `json:"bareIps"`
	Assignments  ztnaAppAssignments `json:"assignments"`
	Routing      ztnaAppRouting     `json:"routing"`
	Security     ztnaAppSecurity    `json:"security"`
}

type ztnaAppResponse struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Type         string             `json:"type"`
	CategoryName string             `json:"categoryName"`
	Hostnames    []string           `json:"hostnames"`
	BareIps      []string           `json:"bareIps"`
	Assignments  ztnaAppAssignments `json:"assignments"`
	Routing      ztnaAppRouting     `json:"routing"`
	Security     ztnaAppSecurity    `json:"security"`
}

// ResourceZTNAApp returns the schema.Resource for jsc_app.
func ResourceZTNAApp() *schema.Resource {
	return &schema.Resource{
		Create: resourceZTNAAppCreate,
		Read:   resourceZTNAAppRead,
		Update: resourceZTNAAppUpdate,
		Delete: resourceZTNAAppDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the ZTNA App. Must be unique across the tenant.",
			},
			"type": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "ENTERPRISE",
				Description: "The app type. Use ENTERPRISE for SwiftConnect routing.",
			},
			"categoryname": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "Uncategorized",
				Description: "Category name for the app.",
			},
			"hostnames": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "List of hostnames to route through this ZTNA policy.",
			},
			"bareips": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "List of bare IPs in IPv4 CIDR notation.",
			},
			"routingtype": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "CUSTOM",
				Description: "Routing type. CUSTOM routes via a specific VPN route; DIRECT routes without a relay.",
			},
			"routingid": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The VPN route ID. Required when routingtype is CUSTOM. Obtain from jsc_pag_vpnroutes datasource.",
			},
			"routingdnstype": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "IPv6",
				Description: "DNS IP resolution type. IPv4 or IPv6. Ignored when routingtype is DIRECT.",
			},
			"assignmentallusers": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Assign this ZTNA app policy to all users.",
			},
			"assignmentgroups": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "List of group IDs to assign this ZTNA app policy to.",
			},
			"securityriskcontrolenabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable device risk controls for this app policy.",
			},
			"securityriskcontrolthreshold": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "HIGH",
				Description: "Risk level threshold for access. Valid values: HIGH, MEDIUM, LOW.",
			},
			"securityriskcontrolnotifications": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Enable notifications for risk control events.",
			},
			"securitydohintegrationblocking": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable DNS-over-HTTPS blocking for this app policy.",
			},
			"securitydohintegrationnotifications": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Enable notifications for DoH integration events.",
			},
			"securitydevicemanagementbasedaccessenabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable device management based access control.",
			},
			"securitydevicemanagementbasedaccessnotifications": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable notifications for device management based access events.",
			},
		},
	}
}

func buildZTNAAppRequest(d *schema.ResourceData) ztnaAppRequest {
	hostnames := toStringSlice(d.Get("hostnames").([]interface{}))
	bareips := toStringSlice(d.Get("bareips").([]interface{}))
	groups := toStringSlice(d.Get("assignmentgroups").([]interface{}))

	routingdnstype := d.Get("routingdnstype").(string)
	if d.Get("routingtype").(string) == "DIRECT" {
		routingdnstype = ""
	}

	return ztnaAppRequest{
		Name:         d.Get("name").(string),
		Type:         d.Get("type").(string),
		CategoryName: d.Get("categoryname").(string),
		Hostnames:    hostnames,
		BareIps:      bareips,
		Assignments: ztnaAppAssignments{
			Inclusions: ztnaAppInclusions{
				AllUsers: d.Get("assignmentallusers").(bool),
				Groups:   groups,
			},
		},
		Routing: ztnaAppRouting{
			Type:                d.Get("routingtype").(string),
			RouteId:             d.Get("routingid").(string),
			DnsIpResolutionType: routingdnstype,
		},
		Security: ztnaAppSecurity{
			RiskControls: ztnaAppRiskControls{
				Enabled:              d.Get("securityriskcontrolenabled").(bool),
				LevelThreshold:       d.Get("securityriskcontrolthreshold").(string),
				NotificationsEnabled: d.Get("securityriskcontrolnotifications").(bool),
			},
			DohIntegration: ztnaAppDohIntegration{
				Blocking:             d.Get("securitydohintegrationblocking").(bool),
				NotificationsEnabled: d.Get("securitydohintegrationnotifications").(bool),
			},
			DeviceManagementBasedAccess: ztnaAppDeviceMgmtAccess{
				Enabled:              d.Get("securitydevicemanagementbasedaccessenabled").(bool),
				NotificationsEnabled: d.Get("securitydevicemanagementbasedaccessnotifications").(bool),
			},
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

func resourceZTNAAppCreate(d *schema.ResourceData, m interface{}) error {
	app := buildZTNAAppRequest(d)

	payload, err := json.Marshal(app)
	if err != nil {
		return fmt.Errorf("failed to marshal jsc_app payload: %v", err)
	}

	req, err := http.NewRequest("POST", "https://radar.wandera.com/gate/traffic-routing-service/v1/apps", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to build jsc_app create request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_app create request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create jsc_app: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_app create response: %v", err)
	}

	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse jsc_app create response: %v", err)
	}

	if response.ID == "" {
		return fmt.Errorf("jsc_app was created but API returned an empty ID")
	}

	d.SetId(response.ID)
	return nil
}

func resourceZTNAAppRead(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/traffic-routing-service/v1/apps/%s", d.Id()), nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_app read request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_app read request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to read jsc_app: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_app read response: %v", err)
	}

	var response ztnaAppResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse jsc_app read response: %v", err)
	}

	d.Set("name", response.Name)
	d.Set("type", response.Type)
	d.Set("categoryname", response.CategoryName)
	d.Set("hostnames", response.Hostnames)
	d.Set("bareips", response.BareIps)
	d.Set("assignmentallusers", response.Assignments.Inclusions.AllUsers)
	d.Set("assignmentgroups", response.Assignments.Inclusions.Groups)
	d.Set("routingtype", response.Routing.Type)
	d.Set("routingid", response.Routing.RouteId)
	d.Set("routingdnstype", response.Routing.DnsIpResolutionType)
	d.Set("securityriskcontrolenabled", response.Security.RiskControls.Enabled)
	d.Set("securityriskcontrolthreshold", response.Security.RiskControls.LevelThreshold)
	d.Set("securityriskcontrolnotifications", response.Security.RiskControls.NotificationsEnabled)
	d.Set("securitydohintegrationblocking", response.Security.DohIntegration.Blocking)
	d.Set("securitydohintegrationnotifications", response.Security.DohIntegration.NotificationsEnabled)
	d.Set("securitydevicemanagementbasedaccessenabled", response.Security.DeviceManagementBasedAccess.Enabled)
	d.Set("securitydevicemanagementbasedaccessnotifications", response.Security.DeviceManagementBasedAccess.NotificationsEnabled)

	return nil
}

func resourceZTNAAppUpdate(d *schema.ResourceData, m interface{}) error {
	if err := resourceZTNAAppDelete(d, m); err != nil {
		return err
	}
	return resourceZTNAAppCreate(d, m)
}

func resourceZTNAAppDelete(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://radar.wandera.com/gate/traffic-routing-service/v1/apps/%s", d.Id()), nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_app delete request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_app delete request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete jsc_app: %s", resp.Status)
	}

	d.SetId("")
	return nil
}
```

**Step 3: Verify it compiles (if Go is available)**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
go build ./...
```

Expected: no output, exit 0.

**Step 4: Commit**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
git add endpoints/ztna_app/resource_ztnaapp.go
git commit -m "feat: add jsc_app resource for ZTNA per-app traffic routing"
```

---

### Task 2: Register the resource in main.go

**Files:**
- Modify: `main.go`

**Step 1: Add the import**

In the `import` block, add (keep alphabetical order):

```go
ztnaapp "jsctfprovider/endpoints/ztna_app"
```

**Step 2: Add to ResourcesMap**

```go
"jsc_app": ztnaapp.ResourceZTNAApp(),
```

**Step 3: Verify it compiles (if Go is available)**

```bash
go build ./...
```

**Step 4: Commit**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
git add main.go
git commit -m "feat: register jsc_app in provider ResourcesMap"
```

---

### Task 3: Add example .tf file and docs

**Files:**
- Create: `examples/resources/jsc_app/resource.tf`
- Create: `docs/resources/app.md`

**Step 1: Create the example**

```bash
mkdir -p /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider/examples/resources/jsc_app
```

Write `examples/resources/jsc_app/resource.tf`:

```hcl
# Route SwiftConnect provisioning server traffic through JSC ZTNA
resource "jsc_app" "swiftconnect_access_policy" {
  name      = "SwiftConnect Provisioning"
  type      = "ENTERPRISE"
  hostnames = ["provisioning.swiftconnect.io"]

  routingtype = "CUSTOM"
  routingid   = "a7d2" # Nearest Data Center — obtain from jsc_pag_vpnroutes datasource

  assignmentallusers = true

  securityriskcontrolenabled    = true
  securityriskcontrolthreshold  = "HIGH"
}
```

**Step 2: Write the docs page**

Write `docs/resources/app.md`:

```markdown
---
page_title: "jsc_app Resource - jsc"
subcategory: ""
description: |-
  Manages a ZTNA per-app routing policy in JSC via the traffic-routing-service API.
---

# jsc_app (Resource)

Manages a ZTNA per-app routing policy in JSC. Traffic to the configured hostnames or IPs is routed through JSC's network, subject to the configured security controls.

Used in the SwiftConnect Mini Onboarder to route traffic to SwiftConnect provisioning servers, ensuring devices must pass posture checks before reaching SwiftConnect infrastructure.

## Relationship to jsc_ztna and jsc_pag_ztnaapp

- `jsc_ztna` targets the older `/api/app-definitions` endpoint
- `jsc_pag_ztnaapp` targets the PAG API (`api.wandera.com/ztna/v1/apps`) using PAG JWT auth
- `jsc_app` targets the modern gateway API (`/gate/traffic-routing-service/v1/apps`) using standard session auth — this is what the JSC UI calls today

## Notes

- Update is implemented as delete + recreate (no confirmed PUT endpoint)
- A 404 on read causes Terraform to mark the resource as destroyed and recreate on next `apply`
- When `routingtype = "DIRECT"`, `routingid` and `routingdnstype` are ignored
- `routingid` values can be obtained from the `jsc_pag_vpnroutes` datasource

## Example Usage

```hcl
resource "jsc_app" "swiftconnect_access_policy" {
  name      = "SwiftConnect Provisioning"
  type      = "ENTERPRISE"
  hostnames = ["provisioning.swiftconnect.io"]

  routingtype = "CUSTOM"
  routingid   = "a7d2"

  assignmentallusers = true

  securityriskcontrolenabled   = true
  securityriskcontrolthreshold = "HIGH"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) The name of the ZTNA App. Must be unique across the tenant.

### Optional

- `assignmentgroups` (List of String) List of group IDs to assign this ZTNA app policy to.
- `assignmentallusers` (Boolean) Assign this ZTNA app policy to all users. Default: `false`.
- `bareips` (List of String) List of bare IPs in IPv4 CIDR notation.
- `categoryname` (String) Category name for the app. Default: `Uncategorized`.
- `hostnames` (List of String) List of hostnames to route through this ZTNA policy.
- `routingdnstype` (String) DNS IP resolution type. `IPv4` or `IPv6`. Ignored when `routingtype` is `DIRECT`. Default: `IPv6`.
- `routingid` (String) The VPN route ID. Required when `routingtype` is `CUSTOM`. Obtain from `jsc_pag_vpnroutes` datasource.
- `routingtype` (String) Routing type. `CUSTOM` routes via a specific VPN route; `DIRECT` routes without a relay. Default: `CUSTOM`.
- `securitydevicemanagementbasedaccessenabled` (Boolean) Enable device management based access control. Default: `false`.
- `securitydevicemanagementbasedaccessnotifications` (Boolean) Enable notifications for device management based access events. Default: `false`.
- `securitydohintegrationblocking` (Boolean) Enable DNS-over-HTTPS blocking. Default: `false`.
- `securitydohintegrationnotifications` (Boolean) Enable notifications for DoH integration events. Default: `true`.
- `securityriskcontrolenabled` (Boolean) Enable device risk controls for this app policy. Default: `false`.
- `securityriskcontrolnotifications` (Boolean) Enable notifications for risk control events. Default: `true`.
- `securityriskcontrolthreshold` (String) Risk level threshold for access. `HIGH`, `MEDIUM`, or `LOW`. Default: `HIGH`.
- `type` (String) The app type. Use `ENTERPRISE` for SwiftConnect routing. Default: `ENTERPRISE`.

### Read-Only

- `id` (String) The ID of this resource.
```

**Step 3: Commit**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
git add examples/resources/jsc_app/resource.tf docs/resources/app.md
git commit -m "docs: add example and registry docs for jsc_app"
```

---

### Task 4: Push branch and open PR

**Step 1: Push the branch**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
git push -u origin resource/jsc-app
```

**Step 2: Open the PR**

```bash
gh pr create \
  --title "feat: add jsc_app resource for ZTNA per-app traffic routing" \
  --body "$(cat <<'EOF'
## Summary

Adds the `jsc_app` Terraform resource to the JSC provider.

This resource manages ZTNA per-app routing policies via the traffic-routing-service gateway API. It is part of the SwiftConnect Mini Onboarder — used to route traffic to SwiftConnect provisioning servers through JSC ZTNA, ensuring devices must pass posture checks (e.g. jailbreak detection) before reaching SwiftConnect infrastructure.

## Relationship to existing resources

| Resource | Endpoint | Auth | Status |
|---|---|---|---|
| `jsc_ztna` | `radar.wandera.com/api/app-definitions` | Session | Existing — older API |
| `jsc_pag_ztnaapp` | `api.wandera.com/ztna/v1/apps` | PAG JWT | Existing — PAG-specific |
| `jsc_app` | `radar.wandera.com/gate/traffic-routing-service/v1/apps` | Session | **New — modern gateway API** |

`jsc_app` is not a replacement for `jsc_ztna` — they target different APIs. However, **Dan/Ryan: is `jsc_ztna`'s `/api/app-definitions` endpoint still valid, or should it be deprecated in favour of `jsc_app`?**

## Schema

Full parity with `jsc_pag_ztnaapp` schema (flat field naming convention). Key fields for SwiftConnect use case:

| Field | Type | Notes |
|---|---|---|
| `name` | string | Required, must be unique |
| `type` | string | Default `ENTERPRISE` |
| `hostnames` | list(string) | SwiftConnect provisioning server hostnames |
| `routingtype` | string | `CUSTOM` or `DIRECT`, default `CUSTOM` |
| `routingid` | string | VPN route ID — use `jsc_pag_vpnroutes` datasource |
| `assignmentallusers` | bool | Default `false` |
| `securityriskcontrolenabled` | bool | Default `false` |
| `securityriskcontrolthreshold` | string | `HIGH`/`MEDIUM`/`LOW`, default `HIGH` |

## API notes

- Endpoint confirmed via Chrome DevTools live traffic capture
- Update = delete + recreate (no confirmed PUT endpoint)
- 404 on read clears resource ID — Terraform will recreate on next apply

## Files changed

- `endpoints/ztna_app/resource_ztnaapp.go` — new resource
- `main.go` — import + ResourcesMap registration
- `examples/resources/jsc_app/resource.tf` — example usage
- `docs/resources/app.md` — registry documentation
- `docs/plans/2026-02-19-jsc-app-design.md` — design doc
- `docs/plans/2026-02-19-jsc-app-plan.md` — implementation plan

## Test plan

- [ ] `go build ./...` passes cleanly
- [ ] `terraform plan` with example config shows expected create
- [ ] `terraform apply` creates the routing policy in a test JSC tenant
- [ ] Hostnames appear correctly routed in the JSC UI
- [ ] `terraform destroy` removes the policy cleanly (204 response)
- [ ] Modifying any field triggers delete + recreate
- [ ] `routingtype = "DIRECT"` omits `routeId` and `dnsIpResolutionType` from the request

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

**Do NOT merge.** This PR is for team review.
