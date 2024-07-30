resource "jsc_hostnamemapping" "testmappingresource" {
  hostname = "ping123.me"
  a        = ["192.168.0.1", "192.168.0.2"]
  aaaa     = ["ff::"]
}
