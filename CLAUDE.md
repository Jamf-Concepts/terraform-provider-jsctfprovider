# CLAUDE.md

This file provides guidance to Agentic tools when working with code in this repository.

## Build Commands

```bash
# Build the provider binary
go build -o terraform-provider-jsctf

# Generate documentation (requires terraform CLI)
go generate ./...

```

## Local Development Setup

Add to `~/.terraformrc` for dev overrides (skip `terraform init`):
```hcl
provider_installation {
  dev_overrides {
    "jsctf" = "/path/to/terraform-provider-jsctfprovider"
  }
}
```

## Architecture

This is a Terraform provider for Jamf Security Cloud (JSC) built with `terraform-plugin-sdk/v2`.

### Authentication Model

Three separate authentication methods exist, each for different API backends:

| Method | Credentials | Request Function | Resource Prefix |
|--------|-------------|------------------|-----------------|
| Radar API | username/password | `auth.MakeRequest()` | `jsc_` (default) |
| PAG (Public API Gateway) | applicationid/applicationsecret | `auth.MakePAGRequest()` | `jsc_pag_` |
| Protect | protectclientid/protectclientpassword | `auth.MakeProtectRequest()` | `jsc_protect_` |

Authentication state is stored in package-level variables in `internal/auth/auth.go`. The Radar API also supports Jamf ID as a fallback authentication flow.

### Code Structure

- `main.go` - Provider definition, schema, and resource/datasource registration
- `internal/auth/` - Authentication logic and HTTP request wrappers with retry support
- `endpoints/<name>/` - Resource and datasource implementations, one directory per feature

### Adding a New Resource

1. Create a new directory under `endpoints/`
2. Implement `Resource<Name>()` returning `*schema.Resource` with CRUD functions
3. Register in `main.go` under `ResourcesMap` or `DataSourcesMap`
4. Create HTTP requests and use the appropriate `auth.Make*Request()` function
5. Add example in `examples/resources/jsc_<name>/resource.tf`
6. Create docs by running `go generate ./...`


## Git Workflow

### Branching

Always create a separate branch for each feature or fix:
- Features: `feature/<name>` or `resource/<name>`
- Bug fixes: `fix/<description>`

Never commit directly to `main`.

### Pull Request Requirements

Every PR must include:
1. **Clear explanation** - Describe what the change does and why
2. **Manual test validation** - Build the provider locally and test against the API
3. **Code maintainer approval** - Required before merging

### Commit Messages

Use conventional commit format:
```
feat: add new resource for X
fix: correct Y behavior in Z
```
