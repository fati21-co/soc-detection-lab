param(
    [string]$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip",
    [string]$SysmonConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",
    [string]$WorkDir = "C:\Users\Public\sysmon"
)

Write-Host "[*] Installation Sysmon..." -ForegroundColor Cyan
New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
$zipPath = Join-Path $WorkDir "Sysmon.zip"
$exePath = Join-Path $WorkDir "Sysmon64.exe"
$configPath = Join-Path $WorkDir "sysmonconfig.xml"

Invoke-WebRequest -Uri $SysmonUrl -OutFile $zipPath -UseBasicParsing
Expand-Archive -Path $zipPath -DestinationPath $WorkDir -Force
Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $configPath -UseBasicParsing

Write-Host "[*] Installation Sysmon avec config..."
& $exePath -accepteula -i $configPath
Write-Host "[+] Sysmon installé."
