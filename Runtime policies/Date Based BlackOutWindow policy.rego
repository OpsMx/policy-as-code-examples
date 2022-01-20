# This policy verifies the deployment is not happening during a blackout window.
# The blackout window can be configured by changing year, month, day conditions

package opa.pipelines.datetimeslot

# convert to nanoseconds
startTime := input.startTime * 1000000
tz = "America/Los_Angeles"
  
deny["Pipeline has no start time"] {
   startTime == 0
}
  
deny["No deploys between 01st - 28th Feb 2021"] {
   [year, month, day] := time.date(time.now_ns())
   year == 2021
   month == 02
   day >= 01
   day < 28
 }
