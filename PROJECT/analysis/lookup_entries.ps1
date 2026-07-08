$corpusPath = 'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\analysis\corpus_summary.json'
$samples = @(
    '12eb65e862c413254ae49d2eba76eea2.mt.dec',
    '17f4dd5419fdea6aff836f46154d274a.mt.dec',
    '18f286461b12e92d9e16b27c07854a7c.mt.dec',
    '1a4fb9f36cd34d0eb0ca22000e54f8a5.mt.dec',
    '1c1ac35710f3a4276a942a776e911a85.mt.dec',
    '1c4ed1eebdb4b8af5c2658f4151aa529.mt.dec',
    '1c7efa501c5305fb7062cdcbf148c4a9.mt.dec',
    '5d32bc6cd0fe4c5862f9dc81fae30287.mt.dec',
    '706e2519eb827875ccc7e9a99710dee2.mt.dec',
    '9e9d089b115c25b344696dde0e768a8b.mt.dec',
    'a3d5e1c645fb44f7528754730f2f72af.mt.dec',
    'add52d9cc1ea27c69511fdfef03cc9a4.mt.dec',
    'd9550977c287c5d2ae4f482ceab1b24f.mt.dec',
    'f6e4841aaca00c603a576037adb688a0.mt.dec'
)
foreach ($s in $samples) {
    $pat = '"file": "' + $s + '"'
    $result = Select-String -Path $corpusPath -Pattern $pat -SimpleMatch -Context 0,5
    if ($result) {
        $entryLine = $result.Context.PostContext | Where-Object { $_ -match '"entries": (\d+)' }
        if ($entryLine) {
            $m = [regex]::Match($entryLine, '"entries": (\d+)')
            Write-Output "$s -> entries=$($m.Groups[1].Value)"
        }
    }
}
