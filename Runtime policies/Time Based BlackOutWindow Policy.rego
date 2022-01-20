# This policy verifies the deployment is not happening during a blackout window.
# The blackout window can be configured by changing hour

package opa.pipelines.datetimeslot

 deny["Pipeline has no start time"] {
     startTime := input.startTime
     startTime == 0
 }
  weekday {
     day := time.weekday(time.now_ns())
     day != "Saturday"
     day != "Sunday"
  }
   
  deny["No deployments allowed between 09am - 04pm on weekdays"] {
     [hour, minute, second] := time.clock([time.now_ns(), tz])
     tz = "Africa/Lagos"
     
     hour >= 9
     hour < 16
     weekday
   }
