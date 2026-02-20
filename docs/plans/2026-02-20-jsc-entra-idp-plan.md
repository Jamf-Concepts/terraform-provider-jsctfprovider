# jsc_entra_idp Resource Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `jsc_entra_idp` Terraform resource that creates an Entra (Azure AD) IdP connection in JSC, printing the OAuth consent URL to the console without storing it in state.

**Architecture:** New package `endpoints/entra_idp/`. Two-step create: POST the connection, then POST to consent-transactions to generate the OAuth URL. The URL is printed via `fmt.Println` and discarded — never written to state. Read filters the connections list by ID (no single-resource GET). Update is delete+create.

**Tech Stack:** Go, Terraform Plugin SDK v2, `auth.MakeRequest()` for all API calls

---

### Task 1: Create the resource package and file

**Files:**
- Create: `endpoints/entra_idp/resource_entraidp.go`

**Step 1: Create the directory**

```bash
mkdir -p /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider/endpoints/entra_idp
```

**Step 2: Write the resource file**

Create `endpoints/entra_idp/resource_entraidp.go` with this exact content:

```go
// Copyright 2025, Jamf Software LLC.
package entra_idp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"jsctfprovider/internal/auth"
)

type entraConnection struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	State string `json:"state"`
}

type entraConsentResponse struct {
	ConsentURL string `json:"consentUrl"`
}

// ResourceEntraIdp returns the schema.Resource for jsc_entra_idp.
func ResourceEntraIdp() *schema.Resource {
	return &schema.Resource{
		Create: resourceEntraIdpCreate,
		Read:   resourceEntraIdpRead,
		Update: resourceEntraIdpUpdate,
		Delete: resourceEntraIdpDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Display name for the Entra IdP connection.",
			},
			"state": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Current state of the IdP connection. INITIAL until Microsoft OAuth consent is completed, then APPROVED.",
			},
		},
	}
}

func resourceEntraIdpCreate(d *schema.ResourceData, m interface{}) error {
	// Step 1: Create the Entra connection
	payload, err := json.Marshal(map[string]string{
		"type": "AZURE_END_USER",
		"name": d.Get("name").(string),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal jsc_entra_idp payload: %v", err)
	}

	req, err := http.NewRequest("POST", "https://radar.wandera.com/gate/identity-service/v1/connections", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to build jsc_entra_idp create request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_entra_idp create request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create jsc_entra_idp connection: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_entra_idp create response: %v", err)
	}

	var connection entraConnection
	if err := json.Unmarshal(body, &connection); err != nil {
		return fmt.Errorf("failed to parse jsc_entra_idp create response: %v", err)
	}

	if connection.ID == "" {
		return fmt.Errorf("jsc_entra_idp was created but API returned an empty ID")
	}

	d.SetId(connection.ID)

	// Step 2: Trigger the consent transaction to generate the OAuth URL.
	// The URL is printed to the console for the admin to complete manually.
	// It is NOT stored in Terraform state to avoid persisting OAuth tokens.
	consentReq, err := http.NewRequest("POST",
		fmt.Sprintf("https://radar.wandera.com/gate/identity-service/v1/connections/%s/consent-transactions", connection.ID),
		bytes.NewBuffer([]byte("{}")))
	if err != nil {
		return fmt.Errorf("failed to build consent transaction request: %v", err)
	}

	consentResp, err := auth.MakeRequest(consentReq)
	if err != nil {
		return fmt.Errorf("consent transaction request failed: %v", err)
	}
	defer consentResp.Body.Close()

	if consentResp.StatusCode != http.StatusOK && consentResp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create consent transaction: %s", consentResp.Status)
	}

	consentBody, err := ioutil.ReadAll(consentResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read consent transaction response: %v", err)
	}

	var consentResult entraConsentResponse
	if err := json.Unmarshal(consentBody, &consentResult); err != nil {
		return fmt.Errorf("failed to parse consent transaction response: %v", err)
	}

	// Print the consent URL for the admin. This is intentionally not stored in state.
	fmt.Println("==============================================")
	fmt.Println("jsc_entra_idp: Microsoft OAuth consent required.")
	fmt.Println("Visit the following URL to complete IdP setup:")
	fmt.Println("")
	fmt.Println(consentResult.ConsentURL)
	fmt.Println("")
	fmt.Println("After completing consent, run: terraform refresh")
	fmt.Println("==============================================")

	return nil
}

func resourceEntraIdpRead(d *schema.ResourceData, m interface{}) error {
	// No single-resource GET — must filter the connections list by ID.
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/identity-service/v1/connections", nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_entra_idp read request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_entra_idp read request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to list IdP connections: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_entra_idp list response: %v", err)
	}

	var connections []entraConnection
	if err := json.Unmarshal(body, &connections); err != nil {
		return fmt.Errorf("failed to parse jsc_entra_idp list response: %v", err)
	}

	for _, c := range connections {
		if c.ID == d.Id() {
			d.Set("name", c.Name)
			d.Set("state", c.State)
			return nil
		}
	}

	// Not found in list — resource has been deleted outside Terraform
	d.SetId("")
	return nil
}

func resourceEntraIdpUpdate(d *schema.ResourceData, m interface{}) error {
	if err := resourceEntraIdpDelete(d, m); err != nil {
		return err
	}
	return resourceEntraIdpCreate(d, m)
}

func resourceEntraIdpDelete(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("DELETE",
		fmt.Sprintf("https://radar.wandera.com/gate/identity-service/v1/connections/%s", d.Id()),
		nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_entra_idp delete request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_entra_idp delete request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete jsc_entra_idp: %s", resp.Status)
	}

	d.SetId("")
	return nil
}
```

**Step 3: Commit**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
git add endpoints/entra_idp/resource_entraidp.go
git commit -m "feat: add jsc_entra_idp resource for Entra Azure AD IdP connection"
```

---

### Task 2: Register in main.go

**Files:**
- Modify: `main.go`

**Step 1: Add the import**

In the `import` block, add (alphabetical order, after `admin` and before `activationprofiles`):

```go
entraidp "jsctfprovider/endpoints/entra_idp"
```

**Step 2: Add to ResourcesMap**

```go
"jsc_entra_idp": entraidp.ResourceEntraIdp(),
```

**Step 3: Commit**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
git add main.go
git commit -m "feat: register jsc_entra_idp in provider ResourcesMap"
```

---

### Task 3: Add example and docs

**Files:**
- Create: `examples/resources/jsc_entra_idp/resource.tf`
- Create: `docs/resources/entra_idp.md`

**Step 1: Create the example**

```bash
mkdir -p /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider/examples/resources/jsc_entra_idp
```

Write `examples/resources/jsc_entra_idp/resource.tf`:

```hcl
resource "jsc_entra_idp" "entra_connection" {
  name = "Entra IdP"
}

# After terraform apply, visit the consent URL printed to the console.
# Then run: terraform refresh
# The state attribute will update to "APPROVED" once consent is complete.
output "entra_idp_state" {
  value = jsc_entra_idp.entra_connection.state
}
```

**Step 2: Write the docs page**

Write `docs/resources/entra_idp.md`:

```markdown
---
page_title: "jsc_entra_idp Resource - jsc"
subcategory: ""
description: |-
  Manages an Entra (Azure AD) identity provider connection in JSC.
---

# jsc_entra_idp (Resource)

Manages an Entra (Azure AD) identity provider connection in JSC. Used to configure end-user authentication via Azure AD for ZTNA app access.

## OAuth Consent Requirement

Entra IdP connections require a manual consent step that cannot be automated. During `terraform apply`, the resource:

1. Creates the Entra connection in JSC
2. Triggers a consent transaction to generate a Microsoft OAuth URL
3. **Prints the URL to the console** — visit it in a browser to grant consent
4. After completing consent, run `terraform refresh` to update the `state` attribute to `APPROVED`

The consent URL is **not stored in Terraform state** to avoid persisting OAuth tokens in state backends.

## Notes

- Update is implemented as delete + recreate — a new consent URL will be printed
- If the connection is deleted outside Terraform, the next `terraform plan` will detect drift and offer to recreate it
- Connection states: `INITIAL` → `PENDING` → `APPROVING` → `APPROVED` | `DENIED`

## Example Usage

```hcl
resource "jsc_entra_idp" "entra_connection" {
  name = "Entra IdP"
}

output "entra_idp_state" {
  value = jsc_entra_idp.entra_connection.state
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) Display name for the Entra IdP connection.

### Read-Only

- `id` (String) The ID of this resource.
- `state` (String) Current state of the IdP connection. `INITIAL` until Microsoft OAuth consent is completed, then `APPROVED`.
```

**Step 3: Commit**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
git add examples/resources/jsc_entra_idp/resource.tf docs/resources/entra_idp.md
git commit -m "docs: add example and registry docs for jsc_entra_idp"
```

---

### Task 4: Push branch and open PR

**Step 1: Push**

```bash
cd /Users/josh.sepos/repos/jamf-concepts/terraform-provider-jsctfprovider
git push -u origin resource/jsc-entra-idp
```

**Step 2: Open the PR**

```bash
gh pr create \
  --title "feat: add jsc_entra_idp resource for Entra Azure AD IdP connection" \
  --body "$(cat <<'EOF'
## Summary

Adds the `jsc_entra_idp` Terraform resource to the JSC provider.

This resource configures an Entra (Azure AD) identity provider connection in JSC for end-user authentication. It uses the same `/gate/identity-service/v1/connections` endpoint as the existing `jsc_oktaidp`, but with `type: "AZURE_END_USER"` and an additional consent transaction step.

## The OAuth consent flow

Entra connections require a two-step create:

1. `POST /gate/identity-service/v1/connections` → creates connection, returns `id`
2. `POST /gate/identity-service/v1/connections/{id}/consent-transactions` → generates Microsoft OAuth URL

The `consentUrl` is **printed to the console during `terraform apply`** and intentionally not stored in Terraform state. Storing OAuth tokens in state (which is often plaintext in shared backends) would be a security risk.

After `terraform apply`, the admin visits the URL to complete consent. The `state` attribute updates from `INITIAL` to `APPROVED` after `terraform refresh`.

## Schema

| Field | Type | Notes |
|---|---|---|
| `name` | string | Required — display name |
| `state` | string | Computed — `INITIAL` until consent complete, then `APPROVED` |

## Console output during apply

```
==============================================
jsc_entra_idp: Microsoft OAuth consent required.
Visit the following URL to complete IdP setup:

https://login.microsoftonline.com/...

After completing consent, run: terraform refresh
==============================================
```

## Implementation notes

- Read uses `GET /gate/identity-service/v1/connections` (list) filtered by ID — no single-resource GET on this endpoint
- Update = delete + recreate (new consent URL printed on each recreate)
- `{customerid}` auto-injected as query param by `auth.MakeRequest()` — consistent with all other resources

## Files changed

- `endpoints/entra_idp/resource_entraidp.go` — new resource
- `main.go` — import + ResourcesMap registration
- `examples/resources/jsc_entra_idp/resource.tf` — example usage with state output
- `docs/resources/entra_idp.md` — registry documentation
- `docs/plans/2026-02-20-jsc-entra-idp-design.md` — design doc
- `docs/plans/2026-02-20-jsc-entra-idp-plan.md` — implementation plan

## Test plan

- [ ] `go build ./...` passes cleanly
- [ ] `terraform apply` creates the connection in a test JSC tenant
- [ ] Consent URL is printed to the console (not visible in `terraform show` or state file)
- [ ] Visiting the consent URL in a browser transitions connection to `APPROVED`
- [ ] `terraform refresh` updates `state` to `APPROVED`
- [ ] `terraform destroy` removes the connection cleanly (204 response)
- [ ] `terraform plan` after out-of-band deletion shows drift and offers to recreate

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

**Do NOT merge.** This PR is for team review.
