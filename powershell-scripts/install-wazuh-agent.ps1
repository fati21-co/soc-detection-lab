param(
    [string]$WazuhManagerIP = "192.168.100.50",  
    [string]$WazuhAgentUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.4.0-1.msi",
    [string]$WorkDir = "C:\Users\Public\wazuh"
)

Write-Host "[*] Installation Wazuh agent..." -ForegroundColor Cyan
New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
$installer = Join-Path $WorkDir "wazuh-agent.msi"

Invoke-WebRequest -Uri $WazuhAgentUrl -OutFile $installer -UseBasicParsing
Start-Process msiexec.exe -ArgumentList "/i `"$installer`" /qn" -Wait

$agentAuthPath = "C:\Program Files\ossec-agent\agent-auth.exe"
if (Test-Path $agentAuthPath) {
    Write-Host "[*] Enregistrement auprès du manager $WazuhManagerIP ..."
    & $agentAuthPath -m $WazuhManagerIP
    Write-Host "[+] Agent enregistré." -ForegroundColor Green
} else {
    Write-Warning "agent-auth introuvable; vérifie installation Wazuh."
}
