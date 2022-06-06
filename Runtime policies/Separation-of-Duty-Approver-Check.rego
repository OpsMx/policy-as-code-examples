#Sox Separation of Duty Check  to ensure that the same approver is not approving all approvals in the pipeline
package opsmx.spinnaker.pipeline_soc2 

import future.keywords.in 

trigger_user = input.trigger.user
judgement_users = [input.stages[idx].context.lastModifiedBy | input.stages[idx].type == "manualJudgment" ; input.stages[idx].status == "SUCCEEDED"]

deny["No user can judge more than one stage"]{
  some i
  temp_user1 = judgement_users[i]
  some j
  j != i
  temp_user2 = judgement_users[j]
  temp_user1 == temp_user2
}