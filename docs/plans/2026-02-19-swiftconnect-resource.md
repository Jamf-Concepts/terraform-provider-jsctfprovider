# jsc_swiftconnect Resource Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `jsc_swiftconnect` Terraform resource that creates, reads, and deletes a SwiftConnect physical access integration in a JSC tenant.

**Architecture:** New package `endpoints/physical_access/` following the existing provider pattern. CRUD is implemented via `auth.MakeRequest()` which auto-injects `customerId` and auth headers. Update is delete+create (no confirmed PUT endpoint). The v1/v2 API asymmetry is handled by storing the integration `id` (from POST response) as the Terraform resource ID — used only for delete.

**Tech Stack:** Go, Terraform Plugin SDK v2, `auth.MakeRequest()` for all API calls

---

### Task 1: Create the branch

**Files:**
- No file changes — git only

**Step 1: Create and check out the feature branch**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
git checkout -b resource/jsc-swiftconnect
```

Expected: `Switched to a new branch 'resource/jsc-swiftconnect'`

---

### Task 2: Create the resource package and file

**Files:**
- Create: `endpoints/physical_access/resource_physicalaccess.go`

**Step 1: Create the package directory**

```bash
mkdir -p /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider/endpoints/physical_access
```

**Step 2: Write the resource file**

Create `endpoints/physical_access/resource_physicalaccess.go` with this content:

```go
// Copyright 2025, Jamf Software LLC.
package physical_access

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"jsctfprovider/internal/auth"
)

// ResourceSwiftConnect returns the schema.Resource for the jsc_swiftconnect resource.
func ResourceSwiftConnect() *schema.Resource {
	return &schema.Resource{
		Create: resourceSwiftConnectCreate,
		Read:   resourceSwiftConnectRead,
		Update: resourceSwiftConnectUpdate,
		Delete: resourceSwiftConnectDelete,

		Schema: map[string]*schema.Schema{
			"base_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The SwiftConnect API base URL (e.g. https://api.swiftconnect.io).",
			},
			"application_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The SwiftConnect application ID.",
			},
			"origo_uuid": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Origo UUID provided by SwiftConnect.",
			},
			"organization_uuid": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "The SwiftConnect organization UUID. Optional.",
			},
			"risk_level_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether risk level enforcement is enabled for credential issuance.",
			},
			"risk_level_threshold": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "HIGH",
				Description: "Risk level threshold required for credential issuance. Valid values: HIGH, MEDIUM, LOW.",
			},
		},
	}
}

func resourceSwiftConnectCreate(d *schema.ResourceData, m interface{}) error {
	payload, err := json.Marshal(map[string]interface{}{
		"baseUrl":            d.Get("base_url").(string),
		"applicationId":      d.Get("application_id").(string),
		"origoUuid":          d.Get("origo_uuid").(string),
		"organizationUuid":   d.Get("organization_uuid").(string),
		"riskLevelEnabled":   d.Get("risk_level_enabled").(bool),
		"riskLevelThreshold": d.Get("risk_level_threshold").(string),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal SwiftConnect payload: %v", err)
	}

	req, err := http.NewRequest("POST", "https://radar.wandera.com/gate/physical-access-service/v1/integrations/{customerid}", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to build SwiftConnect create request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("SwiftConnect create request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create SwiftConnect integration: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read SwiftConnect create response: %v", err)
	}

	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse SwiftConnect create response: %v", err)
	}

	d.SetId(response.ID)
	return nil
}

func resourceSwiftConnectRead(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/physical-access-service/v1/integrations/{customerid}", nil)
	if err != nil {
		return fmt.Errorf("failed to build SwiftConnect read request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("SwiftConnect read request failed: %v", err)
	}
	defer resp.Body.Close()

	// 404 means the integration doesn't exist — tell Terraform to recreate it
	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to read SwiftConnect integration: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read SwiftConnect read response: %v", err)
	}

	var response struct {
		ID                 string `json:"id"`
		BaseURL            string `json:"baseUrl"`
		ApplicationID      string `json:"applicationId"`
		OrigoUUID          string `json:"origoUuid"`
		OrganizationUUID   string `json:"organizationUuid"`
		RiskLevelEnabled   bool   `json:"riskLevelEnabled"`
		RiskLevelThreshold string `json:"riskLevelThreshold"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse SwiftConnect read response: %v", err)
	}

	d.Set("base_url", response.BaseURL)
	d.Set("application_id", response.ApplicationID)
	d.Set("origo_uuid", response.OrigoUUID)
	d.Set("organization_uuid", response.OrganizationUUID)
	d.Set("risk_level_enabled", response.RiskLevelEnabled)
	d.Set("risk_level_threshold", response.RiskLevelThreshold)

	return nil
}

func resourceSwiftConnectUpdate(d *schema.ResourceData, m interface{}) error {
	if err := resourceSwiftConnectDelete(d, m); err != nil {
		return err
	}
	return resourceSwiftConnectCreate(d, m)
}

func resourceSwiftConnectDelete(d *schema.ResourceData, m interface{}) error {
	// Delete uses v2 endpoint with the integration id (not customerId)
	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://radar.wandera.com/gate/physical-access-service/v2/integrations/%s", d.Id()), nil)
	if err != nil {
		return fmt.Errorf("failed to build SwiftConnect delete request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("SwiftConnect delete request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete SwiftConnect integration: %s", resp.Status)
	}

	d.SetId("")
	return nil
}
```

**Step 3: Verify it compiles**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
go build ./...
```

Expected: no output, exit 0. Any errors indicate a typo or import issue.

**Step 4: Commit**

```bash
git add endpoints/physical_access/resource_physicalaccess.go
git commit -m "feat: add jsc_swiftconnect resource for physical access integration"
```

---

### Task 3: Register the resource in main.go

**Files:**
- Modify: `main.go`

**Step 1: Add the import**

In the `import` block, add:

```go
physicalaccess "jsctfprovider/endpoints/physical_access"
```

**Step 2: Add to ResourcesMap**

In the `ResourcesMap` block inside `main()`, add:

```go
"jsc_swiftconnect": physicalaccess.ResourceSwiftConnect(),
```

**Step 3: Verify it compiles**

```bash
go build ./...
```

Expected: no output, exit 0.

**Step 4: Commit**

```bash
git add main.go
git commit -m "feat: register jsc_swiftconnect in provider ResourcesMap"
```

---

### Task 4: Add example .tf file (required for docs generation)

**Files:**
- Create: `examples/resources/jsc_swiftconnect/resource.tf`

**Step 1: Create the example**

```bash
mkdir -p examples/resources/jsc_swiftconnect
```

Create `examples/resources/jsc_swiftconnect/resource.tf`:

```hcl
resource "jsc_swiftconnect" "swiftconnect_integration" {
  base_url         = "https://api.swiftconnect.io"
  application_id   = "your-swiftconnect-application-id"
  origo_uuid       = "your-origo-uuid"
  organization_uuid = "your-organization-uuid"  # optional

  risk_level_enabled   = true
  risk_level_threshold = "HIGH"
}
```

**Step 2: Commit**

```bash
git add examples/resources/jsc_swiftconnect/resource.tf
git commit -m "docs: add jsc_swiftconnect example resource"
```

---

### Task 5: Generate and commit docs

**Files:**
- Create: `docs/resources/swiftconnect.md`

**Step 1: Run the doc generator**

```bash
go generate ./...
```

Expected: creates/updates `docs/resources/swiftconnect.md` with schema table auto-populated from `Description` fields.

If `go generate` is unavailable locally, manually create `docs/resources/swiftconnect.md`:

```markdown
---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "jsc_swiftconnect Resource - jsc"
subcategory: ""
description: |-
  Configures a SwiftConnect physical access integration for a JSC tenant.
---

# jsc_swiftconnect (Resource)

Configures a SwiftConnect physical access credential issuance integration for a JSC tenant.
This is a singleton resource — only one integration is supported per tenant.

## Notes

- The `id` returned by the API is stored as the Terraform resource ID and is required for deletion.
- The API uses a v1 endpoint for create/read and a v2 endpoint for delete. This asymmetry is handled internally.
- A 404 on read causes Terraform to mark the resource as destroyed and recreate on next apply.

## Example Usage

```hcl
resource "jsc_swiftconnect" "swiftconnect_integration" {
  base_url         = "https://api.swiftconnect.io"
  application_id   = "your-swiftconnect-application-id"
  origo_uuid       = "your-origo-uuid"
  organization_uuid = "your-organization-uuid"

  risk_level_enabled   = true
  risk_level_threshold = "HIGH"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `application_id` (String) The SwiftConnect application ID.
- `base_url` (String) The SwiftConnect API base URL (e.g. https://api.swiftconnect.io).
- `origo_uuid` (String) The Origo UUID provided by SwiftConnect.

### Optional

- `organization_uuid` (String) The SwiftConnect organization UUID. Optional.
- `risk_level_enabled` (Boolean) Whether risk level enforcement is enabled for credential issuance.
- `risk_level_threshold` (String) Risk level threshold required for credential issuance. Valid values: HIGH, MEDIUM, LOW.

### Read-Only

- `id` (String) The ID of this resource.
```

**Step 2: Commit**

```bash
git add docs/resources/swiftconnect.md
git commit -m "docs: add generated docs for jsc_swiftconnect"
```

---

### Task 6: Push branch and open PR

**Step 1: Push the branch**

```bash
git push -u origin resource/jsc-swiftconnect
```

**Step 2: Open the PR via gh CLI**

```bash
gh pr create \
  --title "feat: add jsc_swiftconnect resource for SwiftConnect physical access integration" \
  --body "$(cat <<'EOF'
## Summary

Adds the `jsc_swiftconnect` Terraform resource to the JSC provider.

This resource configures a SwiftConnect physical access credential issuance integration for a JSC tenant. It is part of the SwiftConnect Mini Onboarder — a modular Terraform workflow that auto-configures JSC for SwiftConnect-led deals, enabling device posture checks (jailbreak detection) as a prerequisite for credential issuance.

### What this resource does
- **Creates** a SwiftConnect integration via `POST /gate/physical-access-service/v1/integrations/{customerId}`
- **Reads** the current integration state via `GET /gate/physical-access-service/v1/integrations/{customerId}` — a 404 signals no integration exists and Terraform will recreate it
- **Deletes** via `DELETE /gate/physical-access-service/v2/integrations/{id}` — note the intentional v1/v2 API asymmetry; the integration `id` (from the POST response) is stored as the Terraform resource ID

### Schema
| Field | Type | Required | Notes |
|---|---|---|---|
| `base_url` | string | yes | SwiftConnect API base URL |
| `application_id` | string | yes | SwiftConnect application ID |
| `origo_uuid` | string | yes | Origo UUID |
| `organization_uuid` | string | no | Optional org UUID |
| `risk_level_enabled` | bool | no | Default: false |
| `risk_level_threshold` | string | no | HIGH/MEDIUM/LOW, default: HIGH |

### API notes
- Singleton resource — one integration per JSC tenant
- No `PUT` endpoint confirmed; update is implemented as delete+create (consistent with existing provider resources)
- Endpoints discovered via Chrome DevTools live traffic capture (API is undocumented)

## Test plan
- [ ] `go build ./...` passes cleanly
- [ ] `terraform plan` with example config shows expected create
- [ ] `terraform apply` creates the integration in a test JSC tenant
- [ ] `terraform destroy` removes it cleanly
- [ ] Modifying any field triggers delete+create (no in-place update)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

**Do NOT merge.** This PR is for team review.

---

### API Reference (for reviewers)

Endpoints discovered via Chrome DevTools traffic capture on `radar.wandera.com`:

| Operation | Method | Endpoint |
|---|---|---|
| Create | POST | `/gate/physical-access-service/v1/integrations/{customerId}` |
| Read | GET | `/gate/physical-access-service/v1/integrations/{customerId}` |
| Delete | DELETE | `/gate/physical-access-service/v2/integrations/{integrationId}` |

Request body:
```json
{
  "baseUrl": "https://api.swiftconnect.io",
  "applicationId": "...",
  "origoUuid": "...",
  "organizationUuid": "...",
  "riskLevelEnabled": false,
  "riskLevelThreshold": "HIGH"
}
```
