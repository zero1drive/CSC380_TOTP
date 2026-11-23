
# Generate acceptance_summary.csv from results.csv

$inputFile = Join-Path $PSScriptRoot "results.csv"
$outputFile = Join-Path $PSScriptRoot "acceptance_summary.csv"

if (-not (Test-Path $inputFile)) {
    Write-Error "results.csv was not found in the project folder."
    exit 1
}

$results = Import-Csv $inputFile

if ($results.Count -eq 0) {
    Write-Error "results.csv contains no experiment records."
    exit 1
}

$summary = $results |
    Group-Object window, clock_offset_s |
    ForEach-Object {
        $rows = $_.Group
        $accepted = @(
            $rows | Where-Object { $_.accepted -eq "1" }
        ).Count

        [PSCustomObject]@{
            window = [int]$rows[0].window
            clock_offset_s = [int]$rows[0].clock_offset_s
            accepted_trials = $accepted
            total_trials = $rows.Count
            acceptance_percent = [math]::Round(
                ($accepted / $rows.Count) * 100, 2
            )
        }
    } |
    Sort-Object window, clock_offset_s

$summary | Export-Csv $outputFile -NoTypeInformation

Write-Host "Summary created successfully: $outputFile"
Write-Host "Summary rows: $($summary.Count)"
Write-Host "CSV data rows: $($results.Count)"

$summary | Format-Table -AutoSize
