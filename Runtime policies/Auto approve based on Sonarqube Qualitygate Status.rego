# Sample Runtime policy
# Automatically approves approval gate if the sonarqube quality gate status is OK

package pipeline.SonarQubeQualityGate
deny[msg] {
    some i
   qualityGate = input.SONARQUBE.output[i].qualityGate;
   qualityGate != "OK";
   msg = sprintf("Failed - Sonarqube  Project  QualityGate Status is '%v'  ",[qualityGate])
}
