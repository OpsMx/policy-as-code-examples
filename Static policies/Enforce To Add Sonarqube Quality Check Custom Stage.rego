# This policy enforce users to add a sonarqube quality gate status check custom stage 
# for a pipeline name starting with "Development".
# This is a static policy.
# Custom stage is available in OpsMx custom stages repo.

package opa.spinnaker.pipelines



deny["No Sonarqube Quality Gate Status Check Stage found"] {
startswith(input.new.name,"Development")
count(input.new.stages)>0
SonarqualityStages := [d | d = input.new.stages[_].type; startswith(d,"Sonarqube")]
count(SonarqualityStages) == 0
}
