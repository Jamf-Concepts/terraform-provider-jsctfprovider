resource "jsc_secure_policy" "posture" {
  # Raise OS_OUTDATED_OS_LOW (Vulnerable OS - Minor / N-1) from MEDIUM to HIGH
  # so that N-1 OS devices fail the SwiftConnect posture gate and cannot receive
  # physical access credentials.
  os_outdated_os_low_severity = "HIGH"
}
