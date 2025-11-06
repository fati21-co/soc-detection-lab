# Edite ces variables avant exécution
$calderaServer = "http://192.168.100.96:8888"
$wazuhManager = "192.168.100.50"

.\deploy-sandcat.ps1 -CalderaServer $calderaServer -OutPath "C:\Users\Public\sandcat.exe"
Start-Sleep -Seconds 5

.\install-sysmon.ps1
Start-Sleep -Seconds 5

.\install-wazuh-agent.ps1 -WazuhManagerIP $wazuhManager
