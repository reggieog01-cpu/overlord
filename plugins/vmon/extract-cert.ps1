$sig = Get-AuthenticodeSignature 'C:\Users\vboxuser\Desktop\xfill\rmm\plugins\vmon\native\driver\MttVDD.dll'
$sig.SignerCertificate | Select-Object Subject, Thumbprint
[IO.File]::WriteAllBytes('C:\Users\vboxuser\Desktop\xfill\rmm\plugins\vmon\native\driver\signpath.cer', $sig.SignerCertificate.Export('Cert'))
Write-Output "cert exported"
