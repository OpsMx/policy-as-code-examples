# Static Policy to restrict image source while a pipeline being saved:
# IF
# application named "sampleapp"
# deploying to an account "production"
# pipeline name that does NOT start with a prefix 'prod'
# THEN
# The image, if present MUST start with "docker.opsmx.com"
#
# Other applications/pipelines can be saved without these restrictions
package opa.spinnaker.pipelines.new
deny[msg] {
    count(input.new.stages)>0
    input.new.application == "sampleapp"
    input.new.stages[_].account == "production" 
    not startswith(input.new.name,"prod")
    images := input.new.stages[_].manifests[_].spec.template.spec.containers[_].image
    not startswith(images, "docker.opsmx.com/")
    msg := sprintf("[%v] being deployed to be from docker.opsmx.com", [images])
 }
