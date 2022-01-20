#This policy validates if specific labels are present in kubernetes resources

package kubernetes.admission                                                

deny[msg] {  
   some i
   label := input.stages[i].context.manifests[_].spec.template.metadata.labels
   not label.app
   msg := "Every resource must have a appname label"        
}

deny[msg] {  
   some i
   label := input.stages[i].context.manifests[_].spec.template.metadata.labels
   not label.costcenter
   msg := "Every resource must have a appncostcenter label"        
}