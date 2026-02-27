param([string]$InputFile, [string]$OutputFile)

$content = Get-Content $InputFile -Raw

# Remove JavaScript block
$content = $content -replace '(?s)<script>.*?</script>', ''

# Update CSS for details/summary elements
$oldCss = @'
        /\* Expandable operations \*/
        \.op-row \{ cursor: pointer; \}
        \.op-row:hover \{ background: #e6f2ff; \}
        \.op-row td:first-child \{ font-weight: 500; \}
        \.expand-icon \{ display: inline-block; width: 20px; color: #0078d4; font-weight: bold; font-family: monospace; \}
        \.op-details \{ background: #fafafa; \}
        \.op-details td \{ padding: 0; \}
        \.detail-table \{ margin: 0; box-shadow: none; border: 1px solid #e1e1e1; \}
        \.detail-table th \{ background: #605e5c; font-size: 12px; padding: 8px 12px; \}
        \.detail-table td \{ font-size: 13px; padding: 8px 12px; \}
'@

$newCss = @'
        /* Expandable operations using HTML5 details/summary */
        .op-section { background: white; margin: 5px 0; border: 1px solid #e1e1e1; border-radius: 4px; }
        .op-summary { padding: 12px 15px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; background: #f5f5f5; }
        .op-summary:hover { background: #e6f2ff; }
        .op-name { font-weight: 500; }
        details[open] .op-summary { background: #e1e1e1; }
        .detail-table { margin: 0; box-shadow: none; border: none; border-top: 1px solid #e1e1e1; width: 100%; }
        .detail-table th { background: #605e5c; font-size: 12px; padding: 8px 12px; text-align: left; }
        .detail-table td { font-size: 13px; padding: 8px 12px; border-bottom: 1px solid #edebe9; }
'@

$content = $content -replace '(?s)/\* Expandable operations \*/.*?\.detail-table td \{ font-size: 13px; padding: 8px 12px; \}', $newCss

# Remove expand/collapse buttons
$content = $content -replace '(?s)<p style="margin-bottom:10px;">.*?</p>', '<p style="color:#605e5c;font-size:13px;margin-bottom:15px;">Click any operation to expand/collapse details</p>'

# Convert table rows to details/summary structure
# Match operation rows and their detail rows
$pattern = '(?s)<tr class="op-row"[^>]*>\s*<td><span class="expand-icon"[^>]*>\+</span>\s*([^<]+)</td>\s*<td>(<span class="badge badge-count">\d+</span>)</td>\s*</tr>\s*<tr class="op-details"[^>]*>\s*<td colspan="2">\s*(<table class="detail-table">.*?</table>)\s*</td>\s*</tr>'

$content = [regex]::Replace($content, $pattern, {
    param($m)
    $opName = $m.Groups[1].Value.Trim()
    $badge = $m.Groups[2].Value
    $detailTable = $m.Groups[3].Value
    @"
        <details class="op-section">
            <summary class="op-summary">
                <span class="op-name">$opName</span>
                $badge
            </summary>
            $detailTable
        </details>
"@
})

# Remove the table wrapper around operations
$content = $content -replace '<table>\s*<tr><th>Operation</th><th>Count</th></tr>', ''
$content = $content -replace '(?s)(</details>\s*)\s*</table>(\s*</div>\s*<div class="section">\s*<h2>Current Privileged)', '$1$2'

$content | Set-Content $OutputFile -NoNewline
Write-Host "Created SharePoint-compatible report: $OutputFile"
