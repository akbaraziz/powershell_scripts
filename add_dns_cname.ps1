# Script author: Akbar Aziz
# Script site: https://github.com/akbaraziz/bash_scripts
# Script date: 06/19/2020
# Script ver: 1.0
# Script tested on OS: Windows Server 2016
# Script purpose: Add a DNS CNAME

#--------------------------------------------------

#Example
#Add-DnsServerResourceRecordCName -ZoneName corp.ad -HostNameAlias "webapp25.corp.ad" -Name "finance"

Add-DnsServerResourceRecordCName -ZoneName @@{DOMAIN_NAME }@@ -HostNameAlias @@{HOSTNAME }@@.@@ { DOMAIN_NAME }@@ -Name @@{alias }@@