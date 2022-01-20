# This policy checks the JIRA to ensure that there are no open high priority issues
# Policy fails if the jira is having Highest priority issue

package jiraapprovalpolicy

deny[msg] {
    some i
    jiraId = input.JIRA.output[i].jiraId;
    status = input.JIRA.output[i].status;
    priority = input.JIRA.output[i].priority;
    status != "Done";
    priority ="Highest"
    msg = sprintf("for jira id '%v' status is '%v' and priority is '%v' ",[jiraId,status,priority])

} 
