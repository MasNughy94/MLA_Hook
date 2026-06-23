param(
    [string]$OutDir = "$PSScriptRoot\prebuilt"
)

$ABIS = @("arm64-v8a")
$BASE_URL = "https://raw.githubusercontent.com/shadow3aaa/dobby-api/master/prebuilt/android"

foreach ($abi in $ABIS) {
    $abiDir = Join-Path $OutDir $abi
    $null = New-Item -ItemType Directory -Path $abiDir -Force

    $files = @("libdobby.so", "libdobby.a")
    foreach ($file in $files) {
        $url = "$BASE_URL/$abi/$file"
        $outFile = Join-Path $abiDir $file
        Write-Host "Downloading $url -> $outFile"
        Invoke-WebRequest -Uri $url -OutFile $outFile -UseBasicParsing
    }
}

Write-Host "Done. Prebuilt libraries downloaded to $OutDir"
