$paths = @('C:\VirtualDisplayDriver', 'C:\Program Files\VirtualDisplayDriver', 'C:\Users\vboxuser\AppData\Local\Temp')
foreach ($p in $paths) {
    if (Test-Path $p) {
        Write-Output "== $p =="
        Get-ChildItem $p -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'vdd|mtt' } | Select-Object Name, Length, LastWriteTime | Format-Table | Out-String | Write-Output
    }
}
