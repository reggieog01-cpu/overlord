Write-Output "--- device node ---"
Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'ROOT\DISPLAY*' } | Select-Object Status, FriendlyName, InstanceId | Format-List | Out-String | Write-Output
Write-Output "--- class entries (UmdfService) ---"
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' -ErrorAction SilentlyContinue |
  Where-Object { $_.PSChildName -match '^\d+$' } |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{ Key=$_.PSChildName; Desc=$p.DriverDesc; UmdfService=$p.UmdfService; MatchingDeviceId=$p.MatchingDeviceId }
  } | Format-Table -AutoSize | Out-String | Write-Output
Write-Output "--- Services\MttVDD ---"
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\MttVDD') { Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\MttVDD' | Out-String | Write-Output } else { Write-Output 'MISSING' }
Write-Output "--- System32\UMDF ---"
Get-ChildItem 'C:\Windows\System32\UMDF' -ErrorAction SilentlyContinue | Select-Object Name, Length | Format-Table | Out-String | Write-Output
Write-Output "--- WUDFHost ---"
Get-Process WUDFHost -ErrorAction SilentlyContinue | Select-Object Id, StartTime | Format-Table | Out-String | Write-Output
