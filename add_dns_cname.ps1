#Example
#Add-DnsServerResourceRecordCName -ZoneName corp.ad -HostNameAlias "webapp25.corp.ad" -Name "finance"

Add-DnsServerResourceRecordCName -ZoneName @@{DOMAIN_NAME}@@ -HostNameAlias @@{HOSTNAME}@@.@@{DOMAIN_NAME}@@ -Name @@{alias}@@