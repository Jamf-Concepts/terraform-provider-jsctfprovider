Example TF for JSC

## Building

`go build -o terraform-provider-jsctf`

## Configuring

Add `~/.terraformrc` for dev overrides. Example config

```provider_installation {

  dev_overrides {
        "jsctf" = "/Users/userpath/golang/jsctfprovider"
}
```

## Auth

N.b. Any resource or datasource types prefixed with "pag" (Public API Gateway) require Risk API credentials (API ID and secret) from RADAR.
Any resource with the prefix "protect" requires a client ID and client password (sic) from the Protect for macOS console.
All other resources use JSC's username:password.

## Docs

Make a change and use terraform docs to make it nice

```
go generate ./...

```

## Running

Create a `main.tf`. You will not need to `terraform init` when using the above overrides.

```
terraform {
  required_providers {
    jsc = {
      source  = "jsctf"
      version = "1.0.0"
    }
  }
}

provider "jsc" {
  username = "email@company.com"
  password = "password"
  customerid = "customerid"
  applicationid     = "example"
  applicationsecret = "T(examaples@d#Ejt#"

}

resource "jsc_oktaidp" "my_okta_config" {
  name = "abc"
  orgdomain = "abc.test.com"
  clientid = "0oaal7sr2ZeAQVEji5d6"

}

resource "jsc_ap" "myaptry"{
name = "thisisanactivationprofile"
oktaconnectionid = jsc_oktaidp.my_okta_config.clientid
datapolicy = false
privateaccess = true
threatdefence = true
depends_on = [
    jsc_oktaidp.my_okta_config
  ]
}

output "mintedapcode" {
  value = jsc_ap.myaptry.id
}

resource "jsc_uemc" "my_uemc_config" {
  domain = "https://terraform.jamfcloud.com/"
  clientid = "1b752ccb-eaee-4250-a202-a5d1d091053c"
  clientsecret = "bvaKmX7voLbvk7uEWm9ET3-GcST8-rPjpVxAjhniNNBCHRKSdx9EvRGKZmHp66jB"
}

resource "jsc_blockpage" "myblockpage" {
  description = "I am the new description for the block page"
  title = "I am a new title here"
  type = "block" //supported block, secureBlock, cap, deviceRisk, or deviceManagement
}

resource "jsc_ztna" "myztnaapp"{
  name = "testztna"
  routeid = "b2fa"
  hostnames = ["example1.com", "example2.com"]
}

data "jsc_routes" "jscroute001" {
 name = "Japan"
}

output "route_shared" {
  value = data.jsc_routes.jscroute001.shared
}
output "route_dc" {
  value = data.jsc_routes.jscroute001.datacenter
}
output "route_name" {
  value = data.jsc_routes.jscroute001.name
}

output "route_routeid" {
  value = data.jsc_routes.jscroute001.id
}
```
