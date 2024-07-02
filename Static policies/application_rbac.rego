# Unauthorized users should not be able to create or update or delete spinnaker applications.
# Authorised user groups should be saved in "allowed_user_groups" array

package opsmx.spinnaker.authorization
import future.keywords.in

allowed_user_groups = ["ninjateam", "admin"]
#allowed_user_groups = []

restricted_tasks = ["updateApp", "createApp", "deleteApp"]

  current_user_roles= input.app.job[0].application.userDetails.groups
  accepted_roles = [current_user_roles[i] | current_user_roles[i] in allowed_user_groups]
  number_of_accepted_roles = count(accepted_roles)

deny["User does not have permission to perform this operation"] {
  number_of_accepted_roles <= 0
  not(appHasWritePermissions)
  input.app.job[_].type in restricted_tasks
 }

appHasWritePermissions {
  count(input.app.job[0].application.permissions.WRITE) > 0
}