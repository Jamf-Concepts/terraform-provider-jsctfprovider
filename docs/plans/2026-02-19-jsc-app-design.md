# jsc_app Resource Design

**Date**: 2026-02-19
**Status**: Approved

## Goal

Add a `jsc_app` Terraform resource that manages ZTNA per-app routing entries in JSC via the traffic-routing-service gateway API.

## Context

Part of the SwiftConnect Mini Onboarder — used to create an access policy that routes traffic to SwiftConnect provisioning servers through JSC ZTNA. This ensures devices must pass posture checks before reaching SwiftConnect infrastructure.

## Why not use jsc_ztna?

`jsc_ztna` targets the older `/api/app-definitions` endpoint. The JSC UI uses `/gate/traffic-routing-service/v1/apps` (confirmed via DevTools). `jsc_app` targets the modern endpoint and is not a replacement for `jsc_ztna` — they coexist. Dan/Ryan should comment on whether `jsc_ztna` is still valid.

## Why not use jsc_pag_ztnaapp?

`jsc_pag_ztnaapp` uses PAG JWT auth (`auth.MakePAGRequest`) against `api.wandera.com/ztna/v1/apps`. `jsc_app` uses session auth (`auth.MakeRequest`) against the gateway API. Different auth model, different base URL — separate resources.

## Design

**Package**: `endpoints/ztna_app/`
**Resource name**: `jsc_app`
**Auth**: `auth.MakeRequest()` — auto-injects customerId + session cookie
**Update strategy**: delete + create (consistent with all existing resources, no confirmed PUT)

### Endpoints

| Operation | Method | Endpoint |
|---|---|---|
| Create | POST | `/gate/traffic-routing-service/v1/apps` |
| Read | GET | `/gate/traffic-routing-service/v1/apps/{id}` |
| Delete | DELETE | `/gate/traffic-routing-service/v1/apps/{id}` → 204 |

### Schema (flat, matching jsc_pag_ztnaapp convention)

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `name` | string | yes | — | Must be unique across tenant |
| `type` | string | optional | `"ENTERPRISE"` | Fixed for SwiftConnect |
| `hostnames` | list(string) | optional | — | Hostnames to route |
| `bareips` | list(string) | optional | — | IPv4 CIDR notation |
| `categoryname` | string | optional | `"Uncategorized"` | |
| `routingtype` | string | optional | `"CUSTOM"` | `CUSTOM` or `DIRECT` |
| `routingid` | string | optional | — | Required when routingtype=CUSTOM |
| `routingdnstype` | string | optional | `"IPv6"` | Omitted when routingtype=DIRECT |
| `assignmentallusers` | bool | optional | `false` | |
| `assignmentgroups` | list(string) | optional | — | Group IDs |
| `securityriskcontrolenabled` | bool | optional | `false` | |
| `securityriskcontrolthreshold` | string | optional | `"HIGH"` | HIGH / MEDIUM / LOW |
| `securityriskcontrolnotifications` | bool | optional | `true` | |
| `securitydohintegrationblocking` | bool | optional | `false` | |
| `securitydohintegrationnotifications` | bool | optional | `true` | |
| `securitydevicemanagementbasedaccessenabled` | bool | optional | `false` | |
| `securitydevicemanagementbasedaccessnotifications` | bool | optional | `false` | |

### Structs

Defined locally in the `ztna_app` package (same shape as `pag_ztna_app` structs but not shared — separate packages, separate concern).
