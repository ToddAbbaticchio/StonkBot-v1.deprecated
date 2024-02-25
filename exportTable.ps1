[cmdletbinding()]
param(
    [ValidateSet(1,2,3)][string]$dbTable = $(Read-Host -Prompt "Enter StonkBot table to export:`n1 - Historical Data`n2 - OIRatio Data`n3 - GEX Data`n"),
    $query
)

function Get-DBData {
    [cmdletbinding()]
    param (
        $table,
        $query
    )
    
    if (!$query) { $query = "SELECT * FROM $table" }
    $dbReturn = Invoke-SqLiteQuery -SqLiteConnection $dbCon -query $query
    return $dbReturn
}

switch ($dbTable) {
    1 { $table = "HISTORY_DATA" }
    2 { $table = "HISTORY_OI" }
    3 { $table = "HISTORY_GEX" }
}

if ($(hostname) -eq "sparevilestyle") {
    $global:dbCon = new-sqliteconnection -datasource "Z:\DB_StonkBot.db"
    $exportPath = "C:\users\SparePC\Desktop\$table-$((get-date).toString("MM-dd"))-export.csv"
}
else {
    $global:sbPath = "E:\projects\stonkbot"
    $global:dbCon = new-sqliteconnection -datasource "$sbPath\DB_StonkBot.db"
    $exportPath = "$sbPath\misc\$table-$((get-date).toString("MM-dd"))-export.csv"
}

try {
    $tableData = Get-DBData -table $table -query $query
    $tableData | export-csv -path $exportPath
    Write-Host "Exported StonkBot $table to: $exportPath" -ForegroundColor Green
    start-sleep -seconds 2
}
catch {
    Write-Error "Error exporting table: $($_.Exception.Message)"
}