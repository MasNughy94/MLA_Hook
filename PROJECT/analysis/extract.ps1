$clusterPath = 'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\analysis\cluster_report.json'
$corpusPath = 'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\analysis\corpus_summary.json'

Write-Host 'Building corpus lookup...'
$entriesLookup = @{}
$reader = [System.IO.StreamReader]::new($corpusPath)
$currentFile = $null
$currentEntries = $null
while ($reader.Peek() -ge 0) {
    $line = $reader.ReadLine()
    if ($line -match '"file": "([a-f0-9.]+\.mt\.dec)"') { $currentFile = $Matches[1] }
    if ($line -match '"entries": (\d+)') { $currentEntries = [int]$Matches[1] }
    if ($currentFile -and $currentEntries) { $entriesLookup[$currentFile] = $currentEntries; $currentFile = $null; $currentEntries = $null }
}
$reader.Close()
Write-Host ('Corpus entries loaded: ' + $entriesLookup.Count)

Write-Host 'Processing cluster report...'
$reader = [System.IO.StreamReader]::new($clusterPath)
$clusterIdx = 0
$inCluster = $false
$currentCluster = $null

while ($reader.Peek() -ge 0) {
    $line = $reader.ReadLine().Trim()
    
    if ($line -match '"num_members": (\d+)') {
        if ($currentCluster) {
            # Output previous cluster
            $sampleEntries = @()
            foreach ($s in $currentCluster.samples) { $sampleEntries += $entriesLookup[$s] }
            if ($sampleEntries.Count -gt 0) {
                $minEntry = ($sampleEntries | Measure-Object -Minimum).Minimum
                $maxEntry = ($sampleEntries | Measure-Object -Maximum).Maximum
                $entryRange = "$minEntry..$maxEntry"
            } else { $entryRange = 'N/A' }
            $tagStr = $currentCluster.tags -join ', '
            Write-Host '---'
            Write-Host ('Cluster #' + $currentCluster.idx + ': ' + $currentCluster.num_members + ' files x ' + $currentCluster.num_tags + ' tags = ' + ($currentCluster.num_members * $currentCluster.num_tags) + ' cluster-size')
            Write-Host ('Entry range for samples: ' + $entryRange)
            Write-Host 'Sample filenames (first 3) / entries:'
            for ($i = 0; $i -lt [Math]::Min(3, $currentCluster.samples.Count); $i++) {
                $ent = if ($entriesLookup.ContainsKey($currentCluster.samples[$i])) { $entriesLookup[$currentCluster.samples[$i]] } else { '?' }
                Write-Host ('  ' + $currentCluster.samples[$i] + ' -> entries=' + $ent)
            }
            Write-Host 'All tags: [' + $tagStr + ']'
        }
        
        $numMembers = [int]$Matches[1]
        $clusterIdx++
        $currentCluster = @{idx=$clusterIdx; num_members=$numMembers; num_tags=0; tags=@(); samples=@()}
        $inCluster = $true
    }
    
    if ($currentCluster) {
        if ($line -match '"num_tags": (\d+)') { $currentCluster.num_tags = [int]$Matches[1] }
        
        if ($line -match '"sample_members"') { $sampling = $true; continue }
        if ($line -match '"tags"') { $sampling = $false; $tagging = $true; continue }
        if ($line -eq ']') { $sampling = $false; $tagging = $false }
        
        if ($sampling -and $line -match '"(.+\.mt\.dec)"') {
            if ($currentCluster.samples.Count -lt 10) { $currentCluster.samples += $Matches[1] }
        }
        if ($tagging -and $line -match '"(0x[0-9a-f]+)"') {
            $currentCluster.tags += $Matches[1]
        }
    }
}

# Output last cluster
if ($currentCluster) {
    $sampleEntries = @()
    foreach ($s in $currentCluster.samples) { $sampleEntries += $entriesLookup[$s] }
    if ($sampleEntries.Count -gt 0) {
        $minEntry = ($sampleEntries | Measure-Object -Minimum).Minimum
        $maxEntry = ($sampleEntries | Measure-Object -Maximum).Maximum
        $entryRange = "$minEntry..$maxEntry"
    } else { $entryRange = 'N/A' }
    $tagStr = $currentCluster.tags -join ', '
    Write-Host '---'
    Write-Host ('Cluster #' + $currentCluster.idx + ': ' + $currentCluster.num_members + ' files x ' + $currentCluster.num_tags + ' tags = ' + ($currentCluster.num_members * $currentCluster.num_tags))
    Write-Host ('Entry range for samples: ' + $entryRange)
    Write-Host 'Sample filenames (first 3) / entries:'
    for ($i = 0; $i -lt [Math]::Min(3, $currentCluster.samples.Count); $i++) {
        $ent = if ($entriesLookup.ContainsKey($currentCluster.samples[$i])) { $entriesLookup[$currentCluster.samples[$i]] } else { '?' }
        Write-Host ('  ' + $currentCluster.samples[$i] + ' -> entries=' + $ent)
    }
    Write-Host 'All tags: [' + $tagStr + ']'
}

$reader.Close()
