
# This Dynamic policy verifies if the image is coming from a trusted registry

package kubernetes.admission                                                

deny[msg] {  
   some i
   input.stages[i].type == "deployManifest"
   input.stages[i].context.manifests[_].kind == "Pod"
   image := input.stages[i].context.manifests[_].spec.containers[_].image
   not startswith(image, "opsmx.io/")  
   msg := sprintf("image '%v' comes from untrusted registry", [image])        
}

deny[msg] {  
   some i
   input.stages[i].type == "deployManifest"
   input.stages[i].context.manifests[_].kind == "Deployment"
   image := input.stages[i].context.manifests[_].spec.template.spec.containers[_].image
   not startswith(image, "opsmx.io/")  
   msg := sprintf("image '%v' comes from untrusted registry", [image])        
}
