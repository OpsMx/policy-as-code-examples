package opsmx.sonarscan

deny[msg] {
status := input.report


status != "OK"
msg :="Sonar Status Failed"
}
