# Uninstall the DataDog Agent
(Get-WmiObject -Class Win32_Product -Filter "Name='Datadog Agent'" -ComputerName . ).Uninstall()

# Delete Directory
Remove-Item 'C:\ProgramData\Datadog' -Recurse