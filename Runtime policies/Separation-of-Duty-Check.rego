#SoX Separation of Duty Check to Ensure Person Approving the Deployment to production is not same as person triggering the pipeline

package opsmx.spinnaker.pipeline_soc1 

import future.keywords.in

trigger_user = input.trigger.user
judgement_users = [input.stages[idx].context.lastModifiedBy | input.stages[idx].type == "manualJudgment" ; input.stages[idx].status == "SUCCEEDED"]
deny["Triggering user cannot be the Approver"] {
  trigger_user in judgement_users
}