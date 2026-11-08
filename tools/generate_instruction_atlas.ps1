param(
    [string]$Catalog = (Join-Path $PSScriptRoot '..\docs\instruction-atlas.csv'),
    [string]$Output = (Join-Path $PSScriptRoot '..\docs\assets\instruction-status.svg')
)

$items = Import-Csv -LiteralPath $Catalog
$colors = @{ Broad = '#22c55e'; Partial = '#65a30d'; Initial = '#d97706'; Planned = '#334155' }
$width = 1200
$height = 660
$builder = [Text.StringBuilder]::new()

function Escape([string]$value) { [Security.SecurityElement]::Escape($value) }
function Add([string]$value) { [void]$builder.AppendLine($value) }

function Split-Columns($groups, [int]$columnCount) {
    $columns = @(for ($index = 0; $index -lt $columnCount; ++$index) {
        [pscustomobject]@{ Groups = [Collections.ArrayList]::new(); Count = 0 }
    })
    foreach ($group in ($groups | Sort-Object Count -Descending)) {
        $column = $columns | Sort-Object Count | Select-Object -First 1
        [void]$column.Groups.Add($group)
        $column.Count += $group.Count
    }
    $columns
}

function Draw-Panel($panelItems, [int]$x, [int]$y, [int]$panelWidth, [int]$panelHeight,
                    [string]$heading, [int]$columnCount) {
    Add "<text x=`"$x`" y=`"$($y - 9)`" class=`"panelTitle`">$(Escape $heading) ($($panelItems.Count))</text>"
    Add "<rect x=`"$x`" y=`"$y`" width=`"$panelWidth`" height=`"$panelHeight`" fill=`"#111827`" stroke=`"#475569`"/>"
    $groups = $panelItems | Group-Object Family
    $columns = Split-Columns $groups $columnCount
    $total = [math]::Max(($columns | Measure-Object Count -Sum).Sum, 1)
    $cursorX = $x
    foreach ($column in $columns) {
        $columnWidth = if ($column -eq $columns[-1]) { $x + $panelWidth - $cursorX } else { [math]::Round($panelWidth * $column.Count / $total) }
        $cursorY = $y
        foreach ($group in ($column.Groups | Sort-Object Count -Descending)) {
            $tileHeight = if ($group -eq $column.Groups[-1]) { $y + $panelHeight - $cursorY } else { [math]::Round($panelHeight * $group.Count / $column.Count) }
            $innerX = $cursorX + 2
            $innerY = $cursorY + 17
            $innerWidth = [math]::Max($columnWidth - 4, 1)
            $innerHeight = [math]::Max($tileHeight - 19, 1)
            $cellColumns = [math]::Max([math]::Ceiling([math]::Sqrt($group.Count * $innerWidth / [math]::Max($innerHeight, 1))), 1)
            $cellRows = [math]::Ceiling($group.Count / $cellColumns)
            $cellWidth = $innerWidth / $cellColumns
            $cellHeight = $innerHeight / $cellRows
            Add "<rect x=`"$cursorX`" y=`"$cursorY`" width=`"$columnWidth`" height=`"$tileHeight`" fill=`"#0b1018`" stroke=`"#64748b`"/>"
            Add "<text x=`"$($cursorX + 4)`" y=`"$($cursorY + 13)`" class=`"family`">$(Escape $group.Name)</text>"
            for ($index = 0; $index -lt $group.Count; ++$index) {
                $item = $group.Group[$index]
                $cellX = $innerX + ($index % $cellColumns) * $cellWidth
                $cellY = $innerY + [math]::Floor($index / $cellColumns) * $cellHeight
                $color = $colors[$item.Status]
                Add "<g><title>$(Escape $group.Name): $(Escape $item.Item) [$($item.Status)]</title><rect x=`"$([math]::Round($cellX, 2))`" y=`"$([math]::Round($cellY, 2))`" width=`"$([math]::Max([math]::Round($cellWidth - 1, 2), 1))`" height=`"$([math]::Max([math]::Round($cellHeight - 1, 2), 1))`" fill=`"$color`"/></g>"
            }
            $cursorY += $tileHeight
        }
        $cursorX += $columnWidth
    }
}

function Draw-Bar([int]$x, [int]$y, [string]$label, [int]$value, [int]$total,
                  [string]$color) {
    $barWidth = 300
    $filled = [math]::Round($barWidth * $value / $total)
    Add "<text x=`"$x`" y=`"$($y + 11)`" class=`"small`">$(Escape $label)</text>"
    Add "<rect x=`"$($x + 150)`" y=`"$y`" width=`"$barWidth`" height=`"14`" fill=`"#475569`"/><rect x=`"$($x + 150)`" y=`"$y`" width=`"$filled`" height=`"14`" fill=`"$color`"/>"
    Add "<text x=`"$($x + 462)`" y=`"$($y + 11)`" class=`"small`">$value/$total</text>"
}

$broad = ($items | Where-Object Status -eq 'Broad').Count
$partial = ($items | Where-Object Status -eq 'Partial').Count
$initial = ($items | Where-Object Status -eq 'Initial').Count
$planned = ($items | Where-Object Status -eq 'Planned').Count
$active = $broad + $partial + $initial

Add "<svg xmlns=`"http://www.w3.org/2000/svg`" width=`"$width`" height=`"$height`" viewBox=`"0 0 $width $height`" role=`"img`">"
Add '<rect width="1200" height="660" fill="#0b1018"/>'
Add '<style>.title{font:700 26px Segoe UI,Arial;fill:#f8fafc}.sub{font:13px Segoe UI,Arial;fill:#94a3b8}.panelTitle{font:15px Segoe UI,Arial;fill:#e2e8f0}.family{font:600 9px Segoe UI,Arial;fill:#f8fafc;paint-order:stroke;stroke:#0b1018;stroke-width:2px}.badge{font:700 12px Segoe UI,Arial;fill:#fff}.small{font:12px Segoe UI,Arial;fill:#e2e8f0}.section{font:15px Segoe UI,Arial;fill:#f8fafc}</style>'
Add '<text x="14" y="30" class="title">Status</text>'
Add '<text x="14" y="52" class="sub">CPUEmu instruction atlas — every cell maps to one catalog entry.</text>'
$badges = @(@('tracked', $items.Count, '#3b82f6'), @('broad', $broad, '#16a34a'), @('in progress', ($partial + $initial), '#65a30d'), @('planned', $planned, '#d97706'))
$badgeX = 590
foreach ($badge in $badges) {
    Add "<rect x=`"$badgeX`" y=`"18`" width=`"140`" height=`"28`" fill=`"$($badge[2])`"/><text x=`"$($badgeX + 70)`" y=`"37`" text-anchor=`"middle`" class=`"badge`">$($badge[1]) $($badge[0])</text>"
    $badgeX += 146
}

Draw-Panel ($items | Where-Object Status -ne 'Planned') 14 90 755 340 'Implemented and in-progress forms' 4
Draw-Panel ($items | Where-Object Status -eq 'Planned') 785 90 401 340 'Known forms still needed' 3

Add '<text x="14" y="462" class="section">Coverage by maturity</text>'
Draw-Bar 14 478 'Broad behavior' $broad $items.Count '#22c55e'
Draw-Bar 14 500 'Partial behavior' $partial $items.Count '#65a30d'
Draw-Bar 14 522 'Initial behavior' $initial $items.Count '#d97706'
Draw-Bar 14 544 'Tracked active work' $active $items.Count '#3b82f6'

Add '<text x="620" y="462" class="section">High-value work still needed</text>'
Add '<text x="620" y="487" class="small">SSE4.2    PCMPxSTRx, CRC32</text>'
Add '<text x="620" y="509" class="small">AVX/AVX2  VEX decode, YMM state, 256-bit integer, gather</text>'
Add '<text x="620" y="531" class="small">BMI1/2    extraction, deposit, multiply, variable shifts</text>'
Add '<text x="620" y="553" class="small">Exceptions divide, access, illegal instruction, breakpoint, SEH</text>'
Add '<text x="14" y="594" class="section">Legend and measurement</text>'
Add '<rect x="14" y="608" width="12" height="12" fill="#22c55e"/><text x="32" y="619" class="small">Broad</text><rect x="100" y="608" width="12" height="12" fill="#65a30d"/><text x="118" y="619" class="small">Partial</text><rect x="190" y="608" width="12" height="12" fill="#d97706"/><text x="208" y="619" class="small">Initial</text><rect x="275" y="608" width="12" height="12" fill="#334155"/><text x="293" y="619" class="small">Planned</text>'
Add '<text x="14" y="642" class="sub">Source: docs/instruction-atlas.csv • Cells are catalog entries, not equal-sized encoding totals or a percentage of all historical x86.</text>'
Add '</svg>'

$outputDirectory = (Resolve-Path (Split-Path $Output -Parent)).Path
[IO.File]::WriteAllText((Join-Path $outputDirectory (Split-Path $Output -Leaf)), $builder.ToString(), [Text.UTF8Encoding]::new($false))
