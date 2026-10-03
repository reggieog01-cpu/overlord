Add-Type -AssemblyName System.Drawing
$b = New-Object System.Drawing.Bitmap 1920, 120
$g = [System.Drawing.Graphics]::FromImage($b)
$g.CopyFromScreen(0, 835, 0, 0, $b.Size)
$path = "C:\Users\vboxuser\AppData\Local\Temp\taskbar-shot.png"
$b.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
Write-Output "saved $path"
