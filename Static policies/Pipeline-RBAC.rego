package opsmx.spinnaker.pipeline_rbac
import future.keywords.in

allowed_user_groups = ["demo-admin", "super-admingroup","admin"]

current_user = input.pipeline.user.name
current_user_roles= input.pipeline.user.groups

default allowance_flag = false

deny[msg]{
  accepted_roles = [current_user_roles[i] | current_user_roles[i] in allowed_user_groups]
  number_of_accepted_roles = count(accepted_roles)
  
  number_of_accepted_roles <= 0
  
  msg = sprintf("Current User: %v is not a member of user groups allowed to make changes.", [current_user])
}