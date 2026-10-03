Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Screen]::AllScreens | ForEach-Object {
    Write-Output ("{0} | primary={1} | bounds={2}" -f $_.DeviceName, $_.Primary, $_.Bounds)
}
