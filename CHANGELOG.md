# Changelog

## Unreleased

- Fixed `jsc_uemc` read treating an empty RADAR config list as a hard error; now clears the resource ID so Terraform recreates it when the config was deleted out-of-band (e.g. by a tenant wipe outside Terraform)

## v0.1.8

- Fixed `jsc_ap` `idptype` causing perpetual replace on case-only diffs
- Fixed `jsc_uemc` create/read errors to surface the actual API response body

## v0.1.7

- Improved RADAR auth error handling to surface real authentication failures instead of masking them
- Fixed provider source/version references in examples
- CI now reads Go version from `go.mod` instead of a hardcoded pin
- Added HashiCorp Registry link to README
- Dependency and GitHub Actions updates

## v0.1.6

- Added `jsc_app_template` data source and `appTemplateId` support in `jsc_access_policy`
- Added `jsc_groupedgws` data source for grouped dedicated gateways
- Fixed `jsc_ap` update behavior and API compatibility
- Fixed 500 error when deleting hostname mappings with AAAA records
- Fixed `jsc_access_policy` to use PUT for updates and added `groupOverrides` support
- Fixed routes and groups data sources to use correct API endpoints/parameters
- Prevented `routingdnstype` drift when `routingtype` is `DIRECT`
- Added mutex to hostname mapping to prevent parallel-creation race condition
- Marked `jsc_admin` username as immutable (ForceNew) and `jsc_uemc` clientsecret as sensitive
- Refactored secure policy handling and added new threat categories
- Removed debug logging/output statements
- Dependency and Go version updates

## v0.1.5

- Added import support and a data source for activation profiles
- Added "list all" data sources for resource discovery
- Added import support across resources with complete Read functions
- Added `jsc_secure_policy` singleton resource
- Added `jsc_idp_connection` data source
- Removed deprecated Protect resources from the provider
- Fixed duplicate import left over from a merge conflict
- Dependency updates

## v0.1.4

- Renamed `jsc_app` resource to `jsc_access_policy`
- Added `jsc_entra_idp` resource for Entra (Azure AD) IdP connections
- Added `jsc_admin` resource for admin account management, with full CRUD lifecycle
- Added `jsc_app` resource for ZTNA per-app traffic routing
- Added `jsc_swiftconnect` resource for physical access integration
- Fixed `jsc_entra_idp` to clear `consent_url` from state once approved, and marked it as sensitive/computed
- Fixed request body preservation on retries in `MakeRequest`
- Removed hardcoded credentials from examples in favor of `.tfvars`, and removed credential logging from auth
- Dependency updates

## v0.1.3

- Added Jamf ID (Auth0) authentication as a fallback login flow for the provider
- Fixed an error-variable bug after JSON unmarshalling

## v0.1.2

- Dependency and GitHub Actions updates only (no functional changes)

## v0.1.1

- Added support for network relay
- Reworked `.goreleaser.yml` for v2 compatibility
- Completed OSS compliance work: copyright headers, sanitized example secrets, added required OSS files
- Fixed clear-text logging of sensitive information and added missing workflow permissions
- Added Dependabot config for GitHub Actions and Go modules
- Dependency updates

## v0.1.0

- Reverted an in-progress deprecation change to restore prior provider behavior
- Fixed Go version and GPG secrets configuration in the release workflow
