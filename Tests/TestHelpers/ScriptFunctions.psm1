<#
.SYNOPSIS
    Test helper to unit test functions that live inside stand-alone PowerShell scripts.

.DESCRIPTION
    The scripts in this repository are stand-alone .ps1 files, not modules. Dot-sourcing
    them would execute their body (which requires domain controllers, WSUS servers,
    Exchange, ...). This helper parses a script with the PowerShell parser and returns
    only the source of the requested function, so it can be defined in a test scope
    and exercised in isolation.

.NOTES
    Author     :    Fabian Niesen
    Filename   :    ScriptFunctions.psm1
    Requires   :    PowerShell Version 5.1
    License    :    MIT License, Copyright (c) 2026 Fabian Niesen
    GitHub     :    https://github.com/InfrastructureHeroes/Scipts
#>

Set-StrictMode -Version Latest

function Get-RepositoryRoot {
    <#
    .SYNOPSIS
        Returns the root folder of the repository.
    #>
    [CmdletBinding()]
    param()
    Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}

function Get-RepositoryScript {
    <#
    .SYNOPSIS
        Returns all PowerShell scripts of the repository, excluding the test suite.
    #>
    [CmdletBinding()]
    param(
        [string]$Root = (Get-RepositoryRoot)
    )
    Get-ChildItem -Path $Root -Filter '*.ps1' -Recurse -File |
        Where-Object { $_.FullName -notlike "*$([IO.Path]::DirectorySeparatorChar)Tests$([IO.Path]::DirectorySeparatorChar)*" } |
        Sort-Object FullName
}

function Get-ScriptAst {
    <#
    .SYNOPSIS
        Parses a script file and returns its AST together with the parser errors.
    .PARAMETER Path
        Path of the script to parse.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path -LiteralPath $Path).ProviderPath, [ref]$tokens, [ref]$errors)
    [PSCustomObject]@{
        Ast    = $ast
        Tokens = $tokens
        Errors = $errors
    }
}

function Get-ScriptFunctionSource {
    <#
    .SYNOPSIS
        Returns the source code of a single function defined in a script file.
    .PARAMETER Path
        Path of the script containing the function.
    .PARAMETER Name
        Name of the function to extract.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    $parsed = Get-ScriptAst -Path $Path
    if ($parsed.Errors.Count -gt 0) {
        throw "Cannot parse '$Path': $($parsed.Errors[0].Message)"
    }
    $function = $parsed.Ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $Name
        }, $true) | Select-Object -First 1

    if (-not $function) {
        throw "Function '$Name' was not found in '$Path'."
    }
    $function.Extent.Text
}

function Get-ScriptFunctionScriptBlock {
    <#
    .SYNOPSIS
        Returns a script block that defines the requested function when dot-sourced.
    .DESCRIPTION
        Dot-source the returned script block in a Pester BeforeAll/BeforeEach block to
        make the function available to the tests:

            . (Get-ScriptFunctionScriptBlock -Path $script -Name 'New-CheckResult')

    .PARAMETER Path
        Path of the script containing the function.
    .PARAMETER Name
        Name of the function to extract. Multiple names can be passed to load helper
        functions the tested function depends on.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$Name
    )
    $sources = foreach ($functionName in $Name) {
        Get-ScriptFunctionSource -Path $Path -Name $functionName
    }
    [scriptblock]::Create($sources -join [Environment]::NewLine)
}

Export-ModuleMember -Function Get-RepositoryRoot, Get-RepositoryScript, Get-ScriptAst,
    Get-ScriptFunctionSource, Get-ScriptFunctionScriptBlock
