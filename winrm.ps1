# configure_winrm.ps1
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
Restart-Service WinRM

# Setup Wazuh Agent
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.1-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='10.0.0.4' WAZUH_AGENT_NAME='winagent' 

# Start Wazuh Agent
NET START WazuhSvc

# Update Wazuh local conf to also parse malware detections
# Define the file path and the content to add
$WazuhConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$WindowsDefenderConfig = @"
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
"@

# Read the content of the ossec.conf file
$fileContent = Get-Content -Path $WazuhConfigPath

# Find the position of the closing </ossec_config> tag
$closingTagPosition = $fileContent.IndexOf('</ossec_config>')

# If the closing tag exists, insert the new configuration before it
if ($closingTagPosition -ne -1) {
    $beforeClosingTag = $fileContent[0..($closingTagPosition - 1)]
    $afterClosingTag = $fileContent[($closingTagPosition)..($fileContent.Length - 1)]
    
    # Combine the content with the new configuration before the closing tag
    $newContent = $beforeClosingTag + $WindowsDefenderConfig + $afterClosingTag
    
    # Write the modified content back to the file
    Set-Content -Path $WazuhConfigPath -Value $newContent
    Write-Host "Windows Defender config added successfully."
} else {
    Write-Host "Closing </ossec_config> tag not found in the file."
}

Restart-Service -Name WazuhSvc
