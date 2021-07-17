# Example
#Add-DnsServerResourceRecordA -Name reddeerprint01 -ZoneName corp.ad -IPv4Address 192.168.2.56

Add-DnsServerResourceRecordA -Name @@{HOSTNAME}@@ -ZoneName @@{DOMAIN_NAME}@@ -IPv4Address @@{IP_ADDR}@@