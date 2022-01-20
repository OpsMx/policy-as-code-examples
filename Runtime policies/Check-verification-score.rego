# Policy fails if the verification score is below 70
# To know more about verification click https://www.opsmx.com/autopilot-overview/continuous-verification/

package opa.pipelines.verificationcheck

deny[msg] {
    score := input.verfication.score
    score < 70
    msg := sprintf("verification score is %d. At least 70 is needed to promote", [score])
}
