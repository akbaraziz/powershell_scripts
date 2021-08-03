cls
$directoyPath="C:\Temp";
if(!(Test-Path -path $directoyPath))  
{  
    New-Item -ItemType directory -Path $directoyPath
    Write-Host "Folder path has been created successfully at: " $directoyPath
               
}
else
{
Write-Host "The given folder path $directoyPath already exists";
}

# Download and Install Agent
$source = 'https://s3.amazonaws.com/ddagent-windows-stable/datadog-agent-7-latest.amd64.msi'
# Destination to save the file
$destination = 'c:\temp\datadog-agent-7-latest.amd64.msi'
# Install the DataDog Agent for Windows
Invoke-WebRequest -Uri $source -OutFile $destination
