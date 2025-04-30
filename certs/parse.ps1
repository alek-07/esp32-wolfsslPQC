Get-ChildItem -Filter *.pem | ForEach-Object {
    $inputFile = $_.FullName
    $outputFile = "$($_.BaseName).txt"

    Get-Content -Raw $inputFile |
        Out-String |
        ForEach-Object { ($_ -replace "`r", "") -split "`n" } |
        ForEach-Object { '"{0}\n"' -f $_ } > $outputFile
}
