# Static Policy to enforce assigning roles when creating an application
# Once enforced, it is not possible to create an application that is visible to all
# by mistake

package opsmx.spinnaker.authorization

deny["Permissions must be specified"] {
   not(appHasWritePermissions)
   input.app.job[_].type=="updateApp"
 }{
   not(appHasWritePermissions)
   input.app.job[_].type=="createApp"
}
appHasWritePermissions {
  count(input.app.job[0].application.permissions.WRITE) > 0
}
