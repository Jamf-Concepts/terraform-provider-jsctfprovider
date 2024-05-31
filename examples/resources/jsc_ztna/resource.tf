resource "jsc_ztna" "myztnaapp" {
  name      = "testztnaapp10"
  routeid   = "abc1"
  hostnames = ["example122.com", "example222.com"]
}