# This policy validates the Jenkins build status.
# Policy fails if the Jenkins build fails.

package pipeline.jiraapprovalpolicy

deny[msg] {
    some i
    result = input.JENKINS.output[i].result;
    buildId = input.JENKINS.output[i].buildId;
    
    result != "SUCCESS";
    msg = sprintf("for buildId '%v' result is '%v' ",[buildId,result])

}
