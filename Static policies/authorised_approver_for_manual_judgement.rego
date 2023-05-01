#Fails the stage if the manual judgement stage is not approved by authorised users
#Authorised users should be added to "allowed_users" array
package opsmx.spinnaker.pipeline_approver_authz
import future.keywords.in
allowed_users = ["hanumesh.kumar@opsmx.io"]
#allowed_users = []

judgement_users = [input.stages[i].context.lastModifiedBy | input.stages[i].type == "manualJudgment"  ; input.stages[i].status == "SUCCEEDED"]

deny["Unauthorizd Approver for manual judgement stage"]{
  authorized_approvers= [judgement_users[i] | judgement_users[i] in allowed_users]
  number_of_approvers= count(authorized_approvers)
  number_of_approvers <= 0
}
