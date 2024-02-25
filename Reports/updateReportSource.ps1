$files = get-childitem -path "E:\projects\stonkBot\History\oiData" -recurse

$entryCount = 0

$megaMerge = @()
foreach ($file in $files) {
    write-host "Processing file: $file.Name"
    $thisFile = Get-Content -Path $file.fullName | ConvertFrom-Json

    foreach ($entry in $thisFile) {
        $megaMerge += $entry
        $entryCount++
    }
}

write-host "Merged file contains: $($megaMerge.Count) entries.  Sum of read files is $entryCount entries."
$megaMerge | ConvertTo-Json | Out-File -FilePath "E:\projects\stonkbot\Reports\oiReportData.json" -force
write-host "done!"