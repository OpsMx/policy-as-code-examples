#This policy will check if there is a manual approval before the deployment for  certain critical cloud accounts
package opa.spinnaker.pipelines.deploy_validation
import future.keywords.in

#critical_deploy_accounts=["qa-account", "dev-account", "prod-account", "staging-account"]
critical_deploy_accounts=["staging-account"]

deny[msg]{
  deploy_stages = [input.pipeline.stages[idx].type | startswith(input.pipeline.stages[idx].type, "deploy")]
  count(deploy_stages) > 0

  some stage_idx
  stage_type = input.pipeline.stages[stage_idx].type
  stage_name = input.pipeline.stages[stage_idx].name
  startswith(stage_type, "deploy")
  
  account_name = input.pipeline.stages[stage_idx].account
  account_name in critical_deploy_accounts

  requisite_stage_refId = input.pipeline.stages[stage_idx].requisiteStageRefIds
  requisite_stage_type_map = {input.pipeline.stages[neighbor].type | input.pipeline.stages[neighbor].refId ==
                    requisite_stage_refId[_]}
                    
  not "manualJudgment" in requisite_stage_type_map
  
  msg := sprintf("Stage %v with account:%v is not preceeded by a manual judgement stage", [stage_name, account_name])
}