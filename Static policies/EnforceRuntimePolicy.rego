# Static Policy to ensure that runtime policy is present as the 1st stage
# "/v1/data/opsmx/blackoutwindow" should be replaced with the appropriate runtime policy path


package opa.spinnaker.pipelines

deny["A blackout window policy should be enforced in all prod pipelines "] {
           count(input.new.stages)>0
           startswith(input.new.name,"prod")
           runtimePolicy := [d | d = input.new.stages[_].parameters.policypath; d == "/v1/data/opsmx/blackoutwindow" ]
           policyStages := [d | d = input.new.stages[_].type; d == "policy" ]
           z := count(runtimePolicy) + count(policyStages) 
           z  !=  2
}

#Enforces that there should be a deploy stage in the pipeline

deny["No deploy Stage found."] {
           startswith(input.new.name,"prod")
           count(input.new.stages)>1
           deployStages := [d | d = input.new.stages[_].type; startswith(d,"deploy")]
           runtimePolicy := [d | d = input.new.stages[_].type; d == "policy" ]
           count(runtimePolicy) > 0
           count(deployStages) == 0
}
