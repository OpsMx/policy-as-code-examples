
# This runtime policy Checks Sonarcube parameters such as  reliability rating,
# security rating and bugs 
  
package pipeline.SonarQubeNew


ReliabilityRating {
some i;
RRating = input.SONARQUBE.output[i].reliabilityRating;
contains(RRating,"E")
}

SecurityRating {
some i;
SRating = input.SONARQUBE.output[i].securityRating;
contains(SRating,"E")
}

Bugs {
some i;
bugs = input.SONARQUBE.output[i].bugs;
bugsN=to_number(bugs)
bugsN>100
}

deny["Reliability Rating is E for at least one project "]{ReliabilityRating}
deny["Security Rating is E for at least one project"]{SecurityRating}
deny["Bugs are >100 for at least one project"]{Bugs}
  
