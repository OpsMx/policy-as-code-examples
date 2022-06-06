#This policy checks for prohibited ports & wild cards in Ingress of one or more AWS security groups. Use "*" to check for all security groups.

package aws.sg.ingress_validate

import input as aws
import future.keywords.in

# List of ports that should not appear in rules
bad_ports = [23, 69, 87, 111, 21]

# Security Groups to be evaluated
#groups_of_interest = ["sg-027aa09921d88a259", "sg-0d705687514abb090"]
#groups_of_interest = ["sg-027aa09921d88a2591"]
groups_of_interest = ["*"] 

security_groups = [aws.SecurityGroups[idx] | aws.SecurityGroups[idx].GroupId in groups_of_interest]

# Test CIDR IP Address for all groups

deny[msg]{
  "*" in groups_of_interest
  overall_security_groups = aws.SecurityGroups
  some i
  gid = overall_security_groups[i].GroupId
  gname = overall_security_groups[i].GroupName
  overall_security_groups[i].IpPermissions[j].IpRanges[k].CidrIp == "0.0.0.0/0"
  msg := sprintf("Security Group %v:%v contains wildcard as CidrIP", [gid,gname])
}

deny[msg]{
  not "*" in groups_of_interest
  some i
  gid = security_groups[i].GroupId
  gname = security_groups[i].GroupName
  security_groups[i].IpPermissions[j].IpRanges[k].CidrIp == "0.0.0.0/0"
  msg := sprintf("Security Group %v:%v contains wildcard as CidrIP", [gid,gname])
}

# Test Wildcard Ports

deny[msg]{ 
  "*" in groups_of_interest
  overall_security_groups = aws.SecurityGroups
  some i
  gid = overall_security_groups[i].GroupId
  gname = overall_security_groups[i].GroupName
  IpPermissionSetLengthTotal = count(overall_security_groups[i].IpPermissions)
  IpPermissionSet = [overall_security_groups[i].IpPermissions[j].ToPort | overall_security_groups[i].IpPermissions[j].IpProtocol != "-1"]
  IpPermissionSetLengthWithPort = count(IpPermissionSet)

  IpPermissionSetLengthWithPort != IpPermissionSetLengthTotal
  
  msg := sprintf("Security Group %v:%v allows wildcard ports", [gid,gname])
}

deny[msg]{ 
  not "*" in groups_of_interest
  some i
  gid = security_groups[i].GroupId
  gname = security_groups[i].GroupName
  IpPermissionSetLengthTotal = count(security_groups[i].IpPermissions)
  IpPermissionSet = [security_groups[i].IpPermissions[j].ToPort | security_groups[i].IpPermissions[j].IpProtocol != "-1"]
  IpPermissionSetLengthWithPort = count(IpPermissionSet)

  IpPermissionSetLengthWithPort != IpPermissionSetLengthTotal
  
  msg := sprintf("Security Group %v:%v allows wildcard ports", [gid,gname])
}


# Test Prohibited Ports

deny[msg]{
  "*" in groups_of_interest
  overall_security_groups = aws.SecurityGroups
  some i
  gid = overall_security_groups[i].GroupId
  gname = overall_security_groups[i].GroupName
  
  some j
  from = overall_security_groups[i].IpPermissions[j].FromPort
  to = overall_security_groups[i].IpPermissions[j].ToPort
  
  some k
  prohibited = {bad_ports[k] | bad_ports[k] >= from; bad_ports[k] <= to}
  count(prohibited) > 0
  msg := sprintf("Prohibited port %v is allowed in security group %v:%v",[prohibited, gid, gname])
}

deny[msg]{
  not "*" in groups_of_interest
  some i
  gid = security_groups[i].GroupId
  gname = security_groups[i].GroupName
  
  some j
  from = security_groups[i].IpPermissions[j].FromPort
  to = security_groups[i].IpPermissions[j].ToPort
  
  some k
  prohibited = {bad_ports[k] | bad_ports[k] >= from; bad_ports[k] <= to}
  count(prohibited) > 0
  msg := sprintf("Prohibited port %v is allowed in security group %v:%v",[prohibited, gid, gname])
}