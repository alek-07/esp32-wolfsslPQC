# PowerShell one-liner to convert ca-cert.pem
Get-Content -Raw ca-cert.pem | 
    Out-String | 
    ForEach-Object { ($_ -replace "`r", "") -split "`n" } | 
    ForEach-Object { '"{0}\n"' -f $_ } > ca-cert.txt
