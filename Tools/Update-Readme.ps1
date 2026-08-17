#Requires -Version 5.1
<#
.SYNOPSIS
Generate the script inventory tables in README.md, README.de.md, README.es.md and README.fr.md.

.DESCRIPTION
Builds the inventory tables of all four README files from two sources:

- Tools/readme-inventory.json  : curated data (category order, purpose text per language, GPO templates)
- the script headers themselves: Version, License and article links

The generated blocks are delimited by "<!-- BEGIN GENERATED: <name> -->" / "<!-- END GENERATED: <name> -->"
markers; everything outside the markers is left untouched.

Version is taken from, in this order: $ScriptVersion / $scriptversion assignment, $script:BuildVer
assignment, the "Version :" header line (first token only). License is taken from the "License :"
header block, falling back to an explicit license statement elsewhere in the comment based help.

Every script in the repository must have an entry in readme-inventory.json, and every entry must
point to an existing file - otherwise the script fails. That is what keeps the README from drifting.

.PARAMETER Check
Do not write anything; fail with exit code 1 if the README files are not up to date. Used by CI.

.EXAMPLE
C:\PS> .\Tools\Update-Readme.ps1

Regenerates the inventory tables in all four README files.

.EXAMPLE
C:\PS> .\Tools\Update-Readme.ps1 -Check

Verifies that the committed README files match the repository content.

.NOTES
Author     :    Fabian Niesen (www.infrastrukturhelden.de)
Filename   :    Update-Readme.ps1
Requires   :    PowerShell Version 5.1
License    :    The MIT License (MIT)
                Copyright (c) 2026 Fabian Niesen
Disclaimer :    This script is provided "as is" without warranty. Use at your own risk.
Version    :    1.0
History    :    1.0   FN  Initial version

.LINK
https://github.com/InfrastructureHeroes/Scipts
#>
[CmdletBinding()]
Param(
    [switch]$Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$InventoryFile = Join-Path $PSScriptRoot 'readme-inventory.json'
$ScriptExtensions = @('.ps1', '.cmd', '.squid')
$ExcludedFolders = @('Tools', '.github', '.git')

function Get-RelativePath
{
    Param([Parameter(Mandatory = $true)][string]$Path)
    $relative = $Path.Substring($RepoRoot.Length).TrimStart([char]'\', [char]'/')
    return ($relative -replace '\\', '/')
}

function Get-RepositoryFile
{
    <#
        .SYNOPSIS
        All inventoried files of the repository, as repo-relative paths with forward slashes.
    #>
    $files = Get-ChildItem -Path $RepoRoot -Recurse -File | Where-Object {
        $ScriptExtensions -contains $_.Extension.ToLowerInvariant()
    }
    $result = New-Object System.Collections.Generic.List[string]
    foreach ($file in $files)
    {
        $relative = Get-RelativePath -Path $file.FullName
        $topLevel = ($relative -split '/')[0]
        if ($relative -ne $topLevel -and $ExcludedFolders -contains $topLevel) { continue }
        $result.Add($relative)
    }
    return $result
}

function Get-HelpBlock
{
    <#
        .SYNOPSIS
        The comment based help / header block of a script, or the leading comment lines of a
        .cmd / .squid file.
    #>
    Param([Parameter(Mandatory = $true)][string]$Content)

    $match = [regex]::Match($Content, '(?s)<#(.*?)#>')
    if ($match.Success) { return $match.Groups[1].Value }

    $lines = $Content -split "`r?`n"
    $header = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines)
    {
        if ($line -match '^\s*(#|::|REM\b|@?rem\b)') { $header.Add($line) } elseif ($header.Count -gt 0) { break }
    }
    return ($header -join "`n")
}

function Get-HeaderField
{
    <#
        .SYNOPSIS
        Value of a "Name : value" header field including its continuation lines.
    #>
    Param(
        [AllowEmptyString()][string]$HelpBlock = '',
        [Parameter(Mandatory = $true)][string]$Name
    )

    $lines = $HelpBlock -split "`r?`n"
    $collected = New-Object System.Collections.Generic.List[string]
    $inField = $false
    foreach ($line in $lines)
    {
        if (-not $inField)
        {
            $start = [regex]::Match($line, "^\s*$Name\s*:\s*(.*)$")
            if ($start.Success)
            {
                $inField = $true
                $collected.Add($start.Groups[1].Value.Trim())
            }
            continue
        }

        # A new field ("Name    : ...") or a new help section (".NOTES") ends the current field.
        if ($line -match '^\s*[A-Za-z][A-Za-z0-9 ]*\s+:\s' -or $line -match '^\s*\.[A-Z]+') { break }
        $collected.Add($line.Trim())
    }

    if (-not $inField) { return $null }
    return (($collected | Where-Object { $_ -ne '' }) -join ' ')
}

function Get-ScriptVersion
{
    Param(
        [AllowEmptyString()][string]$Content = '',
        [AllowEmptyString()][string]$HelpBlock = ''
    )

    foreach ($pattern in @('\$(?:script:)?[Ss]cript[Vv]ersion\s*=\s*[''"]([^''"]+)[''"]',
            '\$(?:script:)?BuildVer\s*=\s*[''"]([^''"]+)[''"]'))
    {
        $match = [regex]::Match($Content, $pattern)
        if ($match.Success) { return $match.Groups[1].Value.Trim() }
    }

    $header = Get-HeaderField -HelpBlock $HelpBlock -Name 'Version'
    if (-not [string]::IsNullOrWhiteSpace($header))
    {
        # Header versions often carry the change note of the release ("1.3 FN 03.12.2025 ...").
        return (($header -split '\s+')[0]).Trim()
    }

    return $null
}

function Get-ScriptLicense
{
    Param(
        [AllowEmptyString()][string]$HelpBlock = ''
    )

    $license = Get-HeaderField -HelpBlock $HelpBlock -Name 'License'
    $haystack = if ([string]::IsNullOrWhiteSpace($license)) { $HelpBlock } else { $license }

    if ($haystack -match 'Evotec') { return 'MIT-EVOTEC' }
    if ($haystack -match 'GNU General Public License v3|GPLv3') { return 'GPLv3' }
    if ($haystack -match 'MIT License|MIT license|\(MIT\)') { return 'MIT' }
    return $null
}

function Get-ArticleLink
{
    <#
        .SYNOPSIS
        Article links from the .LINK section, keyed by language ("de" for infrastrukturhelden.de,
        "en" for infrastructureheroes.org). Links to the repository itself are ignored.
    #>
    Param([AllowEmptyString()][string]$Content = '')

    $result = [ordered]@{}
    $match = [regex]::Match($Content, '(?s)\.LINK(.*?)(?:\n\s*\.[A-Z]+|#>)')
    if (-not $match.Success) { return $result }

    foreach ($url in [regex]::Matches($match.Groups[1].Value, 'https?://[^\s\)\]"'']+'))
    {
        $value = $url.Value.TrimEnd([char]'.', [char]',')
        if ($value -match 'github\.com') { continue }
        # Blog start pages are no article reference.
        if ($value -match '^https?://[^/]+/?$') { continue }
        if ($value -match 'infrastrukturhelden\.de' -and -not $result.Contains('de')) { $result['de'] = $value }
        elseif ($value -match 'infrastructureheroes\.org' -and -not $result.Contains('en')) { $result['en'] = $value }
    }
    return $result
}

function Get-ScriptMetadata
{
    Param([Parameter(Mandatory = $true)][string]$RelativePath)

    $fullPath = Join-Path $RepoRoot $RelativePath
    # -Raw honours the byte order mark, which matters for the UTF-16 encoded scripts in this repo.
    $content = Get-Content -LiteralPath $fullPath -Raw
    if ($null -eq $content) { $content = '' }
    $helpBlock = Get-HelpBlock -Content $content

    return [pscustomobject]@{
        Path     = $RelativePath
        Version  = Get-ScriptVersion -Content $content -HelpBlock $helpBlock
        License  = Get-ScriptLicense -HelpBlock $helpBlock
        Articles = Get-ArticleLink -Content $content
    }
}

function Get-CategoryId
{
    Param([Parameter(Mandatory = $true)][string]$RelativePath)

    if ($RelativePath -notmatch '/') { return 'root' }
    return ($RelativePath -split '/')[0]
}

function Format-Cell
{
    Param([AllowEmptyString()][string]$Value = '')
    return ($Value -replace '\|', '\|')
}

function New-InventoryTable
{
    Param(
        [Parameter(Mandatory = $true)]$Inventory,
        [Parameter(Mandatory = $true)]$Language,
        [Parameter(Mandatory = $true)][hashtable]$Metadata
    )

    $labels = $Language.labels
    $code = $Language.code
    $lines = New-Object System.Collections.Generic.List[string]

    foreach ($category in $Inventory.categories)
    {
        $entries = @($Inventory.scripts | Where-Object { (Get-CategoryId -RelativePath $_.path) -eq $category.id })
        if ($entries.Count -eq 0) { continue }

        $lines.Add("### $($category.titles.$code)")
        $lines.Add('')
        $lines.Add("| $($labels.file) | $($labels.purpose) | $($labels.version) | $($labels.license) | $($labels.article) |")
        $lines.Add('|---|---|---|---|---|')

        foreach ($entry in $entries)
        {
            $meta = $Metadata[$entry.path]
            $version = if ([string]::IsNullOrWhiteSpace($meta.Version)) { $labels.notAvailable } else { $meta.Version }
            $license = if ($null -eq $meta.License) { $labels.notSpecified } else { $Inventory.licenses.($meta.License).$code }

            $articles = New-Object System.Collections.Generic.List[string]
            foreach ($key in @('en', 'de'))
            {
                if ($meta.Articles.Contains($key)) { $articles.Add("[$($key.ToUpperInvariant())]($($meta.Articles[$key]))") }
            }
            $article = if ($articles.Count -eq 0) { $labels.none } else { $articles -join ' / ' }

            $lines.Add("| ``$($entry.path)`` | $(Format-Cell -Value $entry.purpose.$code) | $version | $license | $article |")
        }
        $lines.Add('')
    }

    return (($lines -join "`n").TrimEnd())
}

function New-TemplateTable
{
    Param(
        [Parameter(Mandatory = $true)]$Inventory,
        [Parameter(Mandatory = $true)]$Language
    )

    $labels = $Language.labels
    $code = $Language.code
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("| $($labels.template) | $($labels.purpose) | $($labels.backup) |")
    $lines.Add('|---|---|---|')

    foreach ($template in $Inventory.templates)
    {
        $zip = [System.IO.Path]::ChangeExtension($template.path, '.zip')
        $backup = if (Test-Path -LiteralPath (Join-Path $RepoRoot $zip)) { "[ZIP](./$zip)" } else { $labels.none }
        $lines.Add("| [``$($template.path)``](./$($template.path)) | $(Format-Cell -Value $template.purpose.$code) | $backup |")
    }

    return ($lines -join "`n")
}

function Update-Block
{
    Param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Body,
        [Parameter(Mandatory = $true)][string]$File
    )

    $begin = "<!-- BEGIN GENERATED: $Name -->"
    $end = "<!-- END GENERATED: $Name -->"
    $pattern = "(?s)" + [regex]::Escape($begin) + ".*?" + [regex]::Escape($end)
    if (-not [regex]::IsMatch($Content, $pattern))
    {
        throw "Marker '$begin' ... '$end' not found in $File. Add the markers before running this script."
    }

    $replacement = "$begin`n$Body`n$end"
    return [regex]::Replace($Content, $pattern, { $replacement })
}

# --- main -------------------------------------------------------------------------------------

$inventory = Get-Content -LiteralPath $InventoryFile -Raw | ConvertFrom-Json

$onDisk = Get-RepositoryFile
$inJson = @($inventory.scripts | ForEach-Object { $_.path })

$missing = @($onDisk | Where-Object { $inJson -notcontains $_ })
$stale = @($inJson | Where-Object { $onDisk -notcontains $_ })
$missingTemplates = @($inventory.templates | Where-Object { -not (Test-Path -LiteralPath (Join-Path $RepoRoot $_.path)) })

if ($missing.Count -gt 0)
{
    throw ("These files are not documented in Tools/readme-inventory.json: {0}. Add an entry (with all language variants) for each of them." -f ($missing -join ', '))
}
if ($stale.Count -gt 0)
{
    throw ("Tools/readme-inventory.json references files that do not exist: {0}." -f ($stale -join ', '))
}
if ($missingTemplates.Count -gt 0)
{
    throw ("Tools/readme-inventory.json references GPO templates that do not exist: {0}." -f (($missingTemplates | ForEach-Object { $_.path }) -join ', '))
}

$metadata = @{}
foreach ($path in $inJson) { $metadata[$path] = Get-ScriptMetadata -RelativePath $path }

$unknownLicense = @($metadata.Values | Where-Object { $_.License } | Where-Object { -not $inventory.licenses.PSObject.Properties.Name.Contains($_.License) })
if ($unknownLicense.Count -gt 0)
{
    throw ("Unknown license identifier(s) detected: {0}." -f (($unknownLicense | ForEach-Object { "$($_.Path) -> $($_.License)" }) -join ', '))
}

$outdated = New-Object System.Collections.Generic.List[string]

foreach ($language in $inventory.languages)
{
    $file = Join-Path $RepoRoot $language.file
    if (-not (Test-Path -LiteralPath $file)) { throw "README file not found: $($language.file)" }

    $original = Get-Content -LiteralPath $file -Raw
    $updated = Update-Block -Content $original -Name 'inventory' -File $language.file `
        -Body (New-InventoryTable -Inventory $inventory -Language $language -Metadata $metadata)
    $updated = Update-Block -Content $updated -Name 'gpo-templates' -File $language.file `
        -Body (New-TemplateTable -Inventory $inventory -Language $language)

    if ($updated -eq $original)
    {
        Write-Output "unchanged: $($language.file)"
        continue
    }

    if ($Check)
    {
        $outdated.Add($language.file)
        continue
    }

    # UTF8 without BOM, LF line endings - matching the committed README files.
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($updated -replace "`r`n", "`n"))
    [System.IO.File]::WriteAllBytes($file, $bytes)
    Write-Output "updated:   $($language.file)"
}

if ($Check -and $outdated.Count -gt 0)
{
    Write-Error ("These README files are out of date: {0}. Run 'pwsh ./Tools/Update-Readme.ps1' and commit the result." -f ($outdated -join ', '))
    exit 1
}

Write-Output "$($inJson.Count) scripts and $(@($inventory.templates).Count) GPO templates documented."
