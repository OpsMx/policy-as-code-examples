# Unauthorized users should not be able to Edit/Save an existing spinnaker application which is already created
#Authorised user groups should be saved in "allowed_user_groups" array

package opsmx.spinnaker.authorization
import future.keywords.in

allowed_user_groups = ["ninjateam", "admin"]
#allowed_user_groups = []

  #current_user = input.app.job[0].userDetails.name
  current_user_roles= input.app.job[0].application.userDetails.groups
  accepted_roles = [current_user_roles[i] | current_user_roles[i] in allowed_user_groups]
  number_of_accepted_roles = count(accepted_roles)

deny["user does not have the permission to save"] {
  number_of_accepted_roles <= 0
  input.app.job[_].type=="updateApp" 
 }{
  number_of_accepted_roles <= 0
  input.app.job[_].type=="createApp"
}
appHasWritePermissions {
  count(input.app.job[0].application.permissions.WRITE) > 0
}