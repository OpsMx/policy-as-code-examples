# This policy checks if specific stages are present in a prod pipeline

package opa.spinnaker.pipelines

deny["No Manual Judgement Stages"] {
   count(input.new.stages)>0
   startswith(input.new.name,"prod")
   manualStages := [d | d = input.new.stages[_].type; d == "manualJudgment"]
   count(manualStages) == 0
   }
deny["No deploy Stage"] {
   startswith(input.new.name,"prod")
   count(input.new.stages)>0
   deployStages := [d | d = input.new.stages[_].type; startswith(d,"deploy")]
   count(deployStages) == 0
}
