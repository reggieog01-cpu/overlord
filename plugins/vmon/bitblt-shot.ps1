Add-Type -AssemblyName System.Drawing
$b = New-Object System.Drawing.Bitmap 800, 600
$g = [System.Drawing.Graphics]::FromImage($b)
$g.CopyFromScreen(1920, 0, 0, 0, $b.Size)
$path = "C:\Users\vboxuser\AppData\Local\Temp\vdd-shot.png"
$b.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
# measure non-black pixels
$nonBlack = 0
for ($y = 0; $y -lt 600; $y += 10) {
    for ($x = 0; $x -lt 800; $x += 10) {
        $p = $b.GetPixel($x, $y)
        if ($p.R -ne 0 -or $p.G -ne 0 -or $p.B -ne 0) { $nonBlack++ }
    }
}
Write-Output "saved $path; non-black samples: $nonBlack / 4800"
