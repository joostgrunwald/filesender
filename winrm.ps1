# configure_winrm.ps1
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
Restart-Service WinRM

# Setup Wazuh Agent
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.1-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='10.0.0.4' WAZUH_AGENT_NAME='winagent' 

# Start Wazuh Agent
NET START WazuhSvc

# Install SYSMON

# Download Sysmon
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile $env:tmp\Sysmon.zip
Expand-Archive -Path $env:tmp\Sysmon.zip -DestinationPath $env:tmp\Sysmon

# Create Sysmon configuration file (sysconfig.xml)
$SysmonConfig = @"
<Sysmon schemaversion="4.10">
   <HashAlgorithms>md5</HashAlgorithms>
   <EventFiltering>
      <!--SYSMON EVENT ID 1 : PROCESS CREATION-->
      <ProcessCreate onmatch="include">
         <Image condition="contains">mimikatz.exe</Image>
      </ProcessCreate>
      <!--SYSMON EVENT ID 2 : FILE CREATION TIME RETROACTIVELY CHANGED IN THE FILESYSTEM-->
      <FileCreateTime onmatch="include" />
      <!--SYSMON EVENT ID 3 : NETWORK CONNECTION INITIATED-->
      <NetworkConnect onmatch="include" />
      <!--SYSMON EVENT ID 5 : PROCESS ENDED-->
      <ProcessTerminate onmatch="include" />
      <!--SYSMON EVENT ID 6 : DRIVER LOADED INTO KERNEL-->
      <DriverLoad onmatch="include" />
      <!--SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS-->
      <ImageLoad onmatch="include" />
      <!--SYSMON EVENT ID 8 : REMOTE THREAD CREATED-->
      <CreateRemoteThread onmatch="include">
         <SourceImage condition="contains">mimikatz.exe</SourceImage>
      </CreateRemoteThread>
      <!--SYSMON EVENT ID 9 : RAW DISK ACCESS-->
      <RawAccessRead onmatch="include" />
      <!--SYSMON EVENT ID 10 : INTER-PROCESS ACCESS-->
      <ProcessAccess onmatch="include">
         <SourceImage condition="contains">mimikatz.exe</SourceImage>
      </ProcessAccess>
      <!--SYSMON EVENT ID 11 : FILE CREATED-->
      <FileCreate onmatch="include" />
      <!--SYSMON EVENT ID 12 & 13 & 14 : REGISTRY MODIFICATION-->
      <RegistryEvent onmatch="include" />
      <!--SYSMON EVENT ID 15 : ALTERNATE DATA STREAM CREATED-->
      <FileCreateStreamHash onmatch="include" />
      <PipeEvent onmatch="include" />
   </EventFiltering>
</Sysmon>
"@

$SysmonConfigPath = "$env:tmp\Sysmon\sysconfig.xml"
$SysmonConfig | Out-File -FilePath $SysmonConfigPath -Encoding utf8

# Install Sysmon with configuration
Start-Process -FilePath "$env:tmp\Sysmon\Sysmon64.exe" -ArgumentList "-accepteula -i $SysmonConfigPath" -Wait

# Update Wazuh local conf to also parse malware detections and sysmon detections
# Define the file path and the content to add
$WazuhConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$WindowsDefenderConfig = @"
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
"@

$SysmonLogConfig = @"
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
"@

# Read the content of the ossec.conf file
$fileContent = Get-Content -Path $WazuhConfigPath

# Find the position of the closing </ossec_config> tag
$closingTagPosition = $fileContent.IndexOf('</ossec_config>')

# If the closing tag exists, insert the new configurations before it
if ($closingTagPosition -ne -1) {
    $beforeClosingTag = $fileContent[0..($closingTagPosition - 1)]
    $afterClosingTag = $fileContent[($closingTagPosition)..($fileContent.Length - 1)]
    
    # Combine the content with the new configurations before the closing tag
    $newContent = $beforeClosingTag + $WindowsDefenderConfig + $SysmonLogConfig + $afterClosingTag
    
    # Write the modified content back to the file
    Set-Content -Path $WazuhConfigPath -Value $newContent
    Write-Host "Windows Defender and Sysmon config added successfully."
} else {
    Write-Host "Closing </ossec_config> tag not found in the file."
}

Restart-Service -Name WazuhSvc
