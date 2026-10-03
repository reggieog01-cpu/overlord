$ErrorActionPreference = 'Continue'
Write-Output "=== full VDD cleanup v2 ==="
pnputil /enum-devices /class Display 2>&1 | Select-String 'ROOT\\' | ForEach-Object {
    $id = ($_ -replace '.*:\s*','').Trim()
    if ($id) {
        Write-Output "removing $id"
        pnputil /remove-device "$id" 2>&1 | Select-Object -Last 1 | Write-Output
    }
}
pnputil /delete-driver oem5.inf /uninstall /force 2>&1 | Select-Object -Last 1 | Write-Output
# remove stale UMDF service registration if present
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\MttVDD') {
    Remove-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\MttVDD' -Recurse -Force
    Write-Output "removed stale MttVDD service key"
}
Write-Output "=== clean ==="
