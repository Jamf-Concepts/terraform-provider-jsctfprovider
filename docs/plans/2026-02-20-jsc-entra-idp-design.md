# jsc_entra_idp Resource Design

**Date**: 2026-02-20
**Status**: Approved

## Goal

Add a `jsc_entra_idp` Terraform resource that creates an Entra (Azure AD) identity provider connection in JSC, outputting the Microsoft OAuth consent URL to the console without storing it in Terraform state.

## Context

Part of the SwiftConnect Mini Onboarder. Entra IdP enables end-user authentication via Azure AD for ZTNA app access. The existing `jsc_oktaidp` resource handles Okta; this resource handles Entra using the same identity-service endpoint with `type: "AZURE_END_USER"`.

## The OAuth Constraint

Entra connections require a two-step create:
1. Create the connection → JSC returns a connection `id`
2. Trigger a consent transaction → JSC returns a `consentUrl` (Microsoft OAuth URL)

An admin must visit `consentUrl` in a browser to grant consent. Only then does the connection state transition from `INITIAL` → `APPROVED`. This step cannot be automated by Terraform.

## Security Decision

The `consentUrl` contains embedded OAuth tokens and **must not be stored in Terraform state**. State files are often stored in shared backends (S3, Terraform Cloud) and are plaintext. The URL is printed to the console during `terraform apply` — visible to whoever runs the apply — and then discarded.

## Design

**Package**: `endpoints/entra_idp/`
**Resource name**: `jsc_entra_idp`
**Auth**: `auth.MakeRequest()` — session auth

### Endpoints

| Operation | Method | Endpoint |
|---|---|---|
| Create step 1 | POST | `/gate/identity-service/v1/connections` |
| Create step 2 | POST | `/gate/identity-service/v1/connections/{id}/consent-transactions` |
| Read | GET | `/gate/identity-service/v1/connections` (list, filter by id) |
| Delete | DELETE | `/gate/identity-service/v1/connections/{id}` → 204 |

### Schema

| Field | Type | Required | Stored in state | Notes |
|---|---|---|---|---|
| `name` | string | yes | yes | Connection display name |
| `state` | string | computed | yes | Connection state — not sensitive |

### Create flow

1. POST body: `{"type": "AZURE_END_USER", "name": "<name>"}`
2. Store `id` via `d.SetId()`
3. POST to `/connections/{id}/consent-transactions` (empty body)
4. Parse `consentUrl` from response
5. `fmt.Println` the URL with instructions — do NOT call `d.Set("consent_url", ...)`
6. Return nil

### Read flow

GET `/gate/identity-service/v1/connections` returns a list. Filter by `d.Id()` to find our connection. If not found → `d.SetId("")`. If found → `d.Set("state", connection.State)`.

### Console output (during apply)

```
==============================================
jsc_entra_idp: Microsoft OAuth consent required
Visit the following URL to complete IdP setup:

<consentUrl>

After completing consent, run: terraform refresh
==============================================
```

### Update strategy

Delete + create (same as all other resources). A new consent transaction will be triggered — a new URL will be printed.

### Connection states (from bundle)

`INITIAL` → `PENDING` → `APPROVING` → `APPROVED` | `DENIED`
