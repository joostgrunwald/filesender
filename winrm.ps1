# Define log file location
$logFile = "C:\winrm-setup.log"

# Redirect all output to the log file
#Start-Transcript -Path $logFile -Append

# Function to log messages with timestamps
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "$timestamp - $message"
    Write-Host $logEntry
    $logEntry | Out-File -FilePath $logFile -Append
}

# Function to check if the script is running as Administrator
function Is-Admin {
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
    return $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Log if running as admin or not
if (Is-Admin) {
    Log-Message "The script is running with Administrator privileges." | Tee-Object -FilePath $logFile
} else {
    Log-Message "The script is NOT running with Administrator privileges." | Tee-Object -FilePath $logFile
}

# Log script start
Log-Message "Script started."

# Configure WinRM
try {
    Log-Message "Configuring WinRM..."
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
    Restart-Service WinRM
    Log-Message "WinRM configured successfully."
} catch {
    Log-Message "Error configuring WinRM: $_"
}

# Setup Wazuh Agent
try {
    Log-Message "Downloading Wazuh agent..."
    $timestamp = Get-Date -Format "yyyy-MM-dd-HH.mm"  # Get the current date and time in the desired format
    $uri = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.1-1.msi"
    $outFile = "$env:tmp\wazuh-agent"
    $managerIP = "10.0.1.6"
    $agentName = "winendpoint-$timestamp"
    
    Invoke-WebRequest -Uri $uri -OutFile $outFile
    Log-Message "Installing Wazuh agent..."
    msiexec.exe /i $outFile /q WAZUH_MANAGER=$managerIP WAZUH_AGENT_NAME=$agentName
    NET START WazuhSvc
    Log-Message "Wazuh agent installed and started successfully."
} catch {
    Log-Message "Error installing or starting Wazuh agent: $_"
}

# Install Sysmon
try {
    Log-Message "Downloading Sysmon..."
    Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile $env:tmp\Sysmon.zip
    Log-Message "Extracting Sysmon..."
    Expand-Archive -Path $env:tmp\Sysmon.zip -DestinationPath $env:tmp\Sysmon

    # Create Sysmon configuration file (sysconfig.xml)
    $SysmonConfig = @"
<Sysmon schemaversion="4.10">
   <HashAlgorithms>md5</HashAlgorithms>
   <EventFiltering>
      <ProcessCreate onmatch="include">
         <Image condition="contains">mimikatz.exe</Image>
      </ProcessCreate>
      <FileCreateTime onmatch="include" />
      <NetworkConnect onmatch="include" />
      <ProcessTerminate onmatch="include" />
      <DriverLoad onmatch="include" />
      <ImageLoad onmatch="include" />
      <CreateRemoteThread onmatch="include">
         <SourceImage condition="contains">mimikatz.exe</SourceImage>
      </CreateRemoteThread>
      <RawAccessRead onmatch="include" />
      <ProcessAccess onmatch="include">
         <SourceImage condition="contains">mimikatz.exe</SourceImage>
      </ProcessAccess>
      <FileCreate onmatch="include" />
      <RegistryEvent onmatch="include" />
      <FileCreateStreamHash onmatch="include" />
      <PipeEvent onmatch="include" />
   </EventFiltering>
</Sysmon>
"@
    $SysmonConfigPath = "$env:tmp\Sysmon\sysconfig.xml"
    $SysmonConfig | Out-File -FilePath $SysmonConfigPath -Encoding utf8
    Log-Message "Installing Sysmon..."
    Start-Process -FilePath "$env:tmp\Sysmon\Sysmon64.exe" -ArgumentList "-accepteula -i $SysmonConfigPath" -Wait
    Log-Message "Sysmon installed successfully."
} catch {
    Log-Message "Error installing Sysmon: $_"
}

# Update Wazuh local config to parse malware and Sysmon logs
try {
    Log-Message "Updating Wazuh configuration to include Windows Defender and Sysmon logs..."

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
    $closingTagPosition = $fileContent.IndexOf('</ossec_config>')

    if ($closingTagPosition -ne -1) {
        $beforeClosingTag = $fileContent[0..($closingTagPosition - 1)]
        $afterClosingTag = $fileContent[($closingTagPosition)..($fileContent.Length - 1)]
        $newContent = $beforeClosingTag + $WindowsDefenderConfig + $SysmonLogConfig + $afterClosingTag
        Set-Content -Path $WazuhConfigPath -Value $newContent
        Log-Message "Windows Defender and Sysmon config added successfully."
    } else {
        Log-Message "Error: Closing </ossec_config> tag not found in the Wazuh config file."
    }

    Restart-Service -Name WazuhSvc
    Log-Message "Wazuh service restarted successfully."
} catch {
    Log-Message "Error updating Wazuh configuration: $_"
}

# Install 7zip
try {
    Log-Message "Downloading 7-Zip installer..."
    $installerUrl = "https://www.7-zip.org/a/7z1900-x64.exe"
    $installerPath = "$env:TEMP\7z1900-x64.exe"
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath

    Log-Message "Installing 7-Zip..."
    Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait
    Log-Message "7-Zip installation completed."

    # Clean up installer
    Remove-Item -Path $installerPath -Force
    Log-Message "7-Zip installer file removed."
} catch {
    Log-Message "Error installing 7-Zip: $_"
}

Log-Message "Starting wazuh once more"
NET START WazuhSvc

Start-Sleep -Seconds 30

# Simulate an APT
try {
    Log-Message "Downloading APTSimulator package..."
    $downloadUrl = "https://github.com/NextronSystems/APTSimulator/releases/download/v0.9.4/APTSimulator_pw_apt.zip"
    $downloadPath = "$env:TEMP\APTSimulator_pw_apt.zip"
    $extractPath = "$env:TEMP\APTSimulator"
    $sevenZipPath = "C:\Program Files\7-Zip\7z.exe"
    $zipPassword = "apt"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath

    Log-Message "Extracting APTSimulator package..."
    Start-Process -FilePath $sevenZipPath -ArgumentList "x", $downloadPath, "-o$extractPath", "-p$zipPassword" -Wait

    # Add antivirus exception
    Log-Message "Adding APTSimulator to antivirus exclusions..."
    Add-MpPreference -ExclusionPath $extractPath

    # Run APTSimulator
    $batchFile = "$extractPath\APTSimulator\APTSimulator.bat"
    Log-Message "Running APTSimulator.bat as administrator..."
    Start-Process -FilePath $batchFile -ArgumentList "-b" -Verb RunAs

    Log-Message "APT simulation completed."
} catch {
    Log-Message "Error during APT simulation: $_"
}

Log-Message "Starting wazuh once more"
NET START WazuhSvc

# End logging
Log-Message "Script completed."
