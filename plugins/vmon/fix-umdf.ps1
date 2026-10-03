$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Path "C:\Windows\System32\UMDF" -Force | Out-Null
Copy-Item "C:\Users\vboxuser\AppData\Local\Temp\vmon-drv\MttVDD.dll" "C:\Windows\System32\UMDF\MttVDD.dll" -Force
Write-Output "copied: $(Test-Path 'C:\Windows\System32\UMDF\MttVDD.dll')"
pnputil /restart-device "ROOT\DISPLAY\0000" 2>&1 | Select-Object -Last 2 | Out-String | Write-Output
