Write-Output "--- recent WUDF/PnP errors ---"
$cut = (Get-Date).AddMinutes(-120)
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$cut} -MaxEvents 200 -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'WUDFRd|MttVDD' } |
  Select-Object -First 10 TimeCreated, Id, @{n='Msg';e={$_.Message.Substring(0, [Math]::Min(160, $_.Message.Length))}} |
  Format-List | Out-String | Write-Output
Write-Output "--- device state ---"
Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'ROOT\DISPLAY*' } | Select-Object Status, FriendlyName, Problem, ProblemDescription | Format-List | Out-String | Write-Output
