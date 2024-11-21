resource "jsc_pag_ztnaapp" "testztnaapp" {
  name           = "testPAG222"
  routingdnstype = "IPv4"
  routingtype    = "CUSTOM"
  routingid      = "4042"
  hostnames      = ["test234234.com", "test223423423423.com"]
  //securityriskcontrolthreshold = "HIGH"

}
