param(
    [switch]$Uninstall,
    [switch]$Help
)

function Show-Help {
    Write-Host "GitHub Package Cache Manager (Simplified)" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "  Install packages:"
    Write-Host "    .\im-install-simplified.ps1 <package1> <package2@version> ..."
    Write-Host "    .\im-install-simplified.ps1                                   # Process all dependencies in package.json"
    Write-Host ""
    Write-Host "  Uninstall packages:"
    Write-Host "    .\im-install-simplified.ps1 -Uninstall <package1> <package2> ..."
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  .\im-install-simplified.ps1 axios lodash"
    Write-Host "  .\im-install-simplified.ps1 express@4.18.0"
    Write-Host "  .\im-install-simplified.ps1 -Uninstall axios lodash"
    Write-Host ""
    Write-Host "NOTE:" -ForegroundColor Cyan
    Write-Host "  This version triggers ONE workflow per package, which handles all dependencies automatically."
    Write-Host ""
}

function Import-DotEnv {
    param([string]$Path = ".env")
    
    if (Test-Path $Path) {
        Get-Content $Path | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object {
            $key, $value = $_ -split '=', 2
            if ($key -and $value) {
                $value = $value.Trim('"').Trim("'")
                [Environment]::SetEnvironmentVariable($key.Trim(), $value, "Process")
            }
        }
    } else {
        Write-Warning "Environment file not found: $Path"
    }
}

# Load environment variables
Import-DotEnv -Path "./.env"

# --- CONFIGURATION ---
$GithubUsername = [Environment]::GetEnvironmentVariable("GITHUB_USER_NAME")
$GithubRepo = [Environment]::GetEnvironmentVariable("GITHUB_REPOSITORY_NAME")
$GithubApiUrl = "https://api.github.com/repos/$($GithubUsername)/$($GithubRepo)/actions/workflows/publish-to-ghp.yml/dispatches"
$GithubToken = [Environment]::GetEnvironmentVariable("GITHUB_PERSONAL_ACCESS_TOKEN")

if ([string]::IsNullOrEmpty($GithubToken)) {
    Write-Host "Error: GITHUB_TOKEN environment variable not set." -ForegroundColor Red
    exit 1
}

$Global:delimiter = "-p.g-"

$headers = @{
    "Authorization" = "token $GithubToken"
    "Accept" = "application/vnd.github.v3+json"
}

$allowedLicenses = @(
    'AFL-2.1',
    'Apache-2.0',
    'BSD',
    'BSD-2-Clause',
    'BSD-3-Clause',
    'CC0-1.0',
    'CC-BY-3.0',
    'ISC',
    'LGPL-3.0',
    'MIT',
    'Unicode-DFS-2016',
    'Unlicensed'
)

# Global caches
$Global:VersionCache = @{}

#region Utility Functions

function Get-PublishedName {
    param([string]$origName, [string]$owner)
    
    if ($origName.StartsWith("@")) {
        $parts = $origName.Split("/")
        $scope = $parts[0].Substring(1)
        $pkg = $parts[1]
        return "@$owner/$scope$Global:delimiter$pkg".ToLower()
    }
    return "@$owner/$origName".ToLower()
}

function Format-Json {
    [CmdletBinding(DefaultParameterSetName = 'Prettify')]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$Json,
        [Parameter(ParameterSetName = 'Minify')]
        [switch]$Minify,
        [Parameter(ParameterSetName = 'Prettify')]
        [ValidateRange(1, 1024)]
        [int]$Indentation = 2
    )
    
    if ($Minify) {
        return ($Json | ConvertFrom-Json) | ConvertTo-Json -Depth 100 -Compress
    }
    
    if ($Json -notmatch '\r?\n') {
        $Json = ($Json | ConvertFrom-Json) | ConvertTo-Json -Depth 100
    }
    
    $indent = 0
    $regexUnlessQuoted = '(?=([^"]*"[^"]*")*[^"]*$)'
    $result = ($Json -split '\r?\n' | ForEach-Object {
        if (($_ -match "[}\]]$regexUnlessQuoted") -and ($_ -notmatch "[\{\[]$regexUnlessQuoted")) {
            $indent = [Math]::Max($indent - $Indentation, 0)
        }
        $line = (' ' * $indent) + ($_.TrimStart() -replace ":\s+$regexUnlessQuoted", ': ')
        if (($_ -match "[\{\[]$regexUnlessQuoted") -and ($_ -notmatch "[}\]]$regexUnlessQuoted")) {
            $indent += $Indentation
        }
        $line -replace '\\u0027', "'"
    }) -join [Environment]::NewLine -replace '(\[)\s+(\])', '$1$2' -replace '(\{)\s+(\})', '$1$2'
    
    return $result
}

function Get-AlternativeVersions {
    param(
        [string]$PackageName,
        [string]$ProblemVersion,
        [int]$Max = 5
    )
    try {
        $raw = npm view "$PackageName" versions --json --registry=https://registry.npmjs.org/ 2>$null
        if (-not $raw) { return @() }
        $versions = $raw | ConvertFrom-Json
        if (-not $versions) { return @() }

        # Keep only versions different from the problem one; take last ( newest ) slice
        $candidates = ($versions | Where-Object { $_ -ne $ProblemVersion }) | Select-Object -Last 30
        # Reverse to have newest first
        $ordered = [System.Collections.Generic.List[string]]::new()
        ($candidates | Sort-Object -Descending) | ForEach-Object { $ordered.Add($_) }

        return $ordered | Select-Object -First $Max
    } catch {
        return @()
    }
}

function Write-VersionSuggestions {
    param(
        [string]$PackageName,
        [string]$ProblemVersion
    )
    $alts = Get-AlternativeVersions -PackageName $PackageName -ProblemVersion $ProblemVersion -Max 3
    if ($alts.Count -gt 0) {
        Write-Host "Suggested alternative versions for $PackageName (problem with $ProblemVersion):" -ForegroundColor Yellow
        Write-Host ("  " + ($alts -join ", ")) -ForegroundColor Yellow
    } else {
        Write-Host "No alternative version suggestions available for $PackageName right now." -ForegroundColor Yellow
    }
}

#endregion

#region License Validation

function Test-LicenseExpression {
    param([string]$Expression)
    
    $cleanExpression = $Expression -replace '[()]', '' -replace '\s+', ' '
    
    if ($cleanExpression -match ' OR ') {
        $licenses = $cleanExpression -split ' OR ' | ForEach-Object { $_.Trim() }
        foreach ($license in $licenses) {
            if (Test-LicenseExpression -Expression $license) {
                return $true
            }
        }
        return $false
    }
    
    if ($cleanExpression -match ' AND ') {
        $licenses = $cleanExpression -split ' AND ' | ForEach-Object { $_.Trim() }
        foreach ($license in $licenses) {
            if (-not (Test-LicenseExpression -Expression $license)) {
                return $false
            }
        }
        return $true
    }
    
    return $allowedLicenses -contains $cleanExpression.Trim()
}

function Get-PackageLicense {
    param(
        [string]$PackageName,
        [string]$Version
    )
    
    $cacheKey = "$PackageName@$Version"
    if ($Global:LicenseCache.ContainsKey($cacheKey)) {
        return $Global:LicenseCache[$cacheKey]
    }
    
    try {
        $license = npm view "$PackageName@$Version" license --registry=https://registry.npmjs.org/ 2>$null
        if ($license) {
            $Global:LicenseCache[$cacheKey] = $license
            return $license
        }
    } catch {}
    
    return "UNKNOWN"
}

#endregion

#region Node Compatibility

function Test-NodeCompatibility {
    param (
        [string]$PackageName,
        [string]$PackageVersion = "latest",
        [string]$NodeEngine = $null
    )

    # Check if Node.js is available
    try {
        $null = Get-Command node -ErrorAction Stop
    }
    catch {
        Write-Warning "Node.js not found. Skipping compatibility check for $PackageName"
        return $true
    }

    # Get current Node version
    try {
        $currentNodeVersionRaw = node -v 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrEmpty($currentNodeVersionRaw)) {
            Write-Warning "Could not determine Node.js version. Skipping compatibility check."
            return $true
        }
        
        $currentNodeVersion = $currentNodeVersionRaw -replace '^v', ''
        $currentVer = [System.Version]::Parse($currentNodeVersion)
    }
    catch {
        Write-Warning "Could not parse Node.js version: $currentNodeVersionRaw"
        return $true
    }

    try {
        # Get the engines.node field - handle both string and object responses
        $enginesNodeRaw = if ($NodeEngine) { $NodeEngine } else { npm view "$PackageName@$PackageVersion" engines.node --json --registry=https://registry.npmjs.org/ 2>$null }
        
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrEmpty($enginesNodeRaw) -or $enginesNodeRaw -eq "undefined") {
            Write-Host "No Node.js engine constraints found for $PackageName@$PackageVersion" -ForegroundColor Gray
            return $true
        }

        # Clean up the JSON response
        $enginesNode = $enginesNodeRaw.Trim('"') -replace '\\', ''
        
        if ([string]::IsNullOrEmpty($enginesNode) -or $enginesNode -eq "null") {
            Write-Host "No Node.js engine constraints specified for $PackageName@$PackageVersion" -ForegroundColor Gray
            return $true
        }

        Write-Host "Checking Node.js compatibility for $PackageName@$PackageVersion (requires: $enginesNode)" -ForegroundColor Yellow
        
        # Handle different constraint formats
        $compatible = Test-NodeVersionConstraint -CurrentVersion $currentVer -Constraint $enginesNode
        
        if (-not $compatible) {
            Write-Warning "COMPATIBILITY WARNING: $PackageName@$PackageVersion requires Node.js $enginesNode, but you have $currentNodeVersion"
            Write-Host "Consider upgrading Node.js or using a different package version." -ForegroundColor Yellow
            return $false
        }
        else {
            Write-Host "Node.js version compatibility: OK" -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Warning "Could not check Node.js compatibility for $PackageName@$PackageVersion : $($_.Exception.Message)"
        return $true  # Don't block installation on compatibility check failures
    }
}

function Test-NodeVersionConstraint {
    param (
        [Parameter(Mandatory)]
        [System.Version]$CurrentVersion,

        [Parameter(Mandatory)]
        [string]$Constraint
    )

    # Helper: safely convert version string to System.Version
    function ConvertTo-Version($v) {
        # Remove invalid characters (^, ~, x, etc.)
        $v = $v -replace '[^\d\.]', ''
        if ([string]::IsNullOrWhiteSpace($v)) { return $null }

        # Split and normalize: cap to 4 parts
        $parts = $v.Split('.')
        $normalized = @()

        foreach ($p in $parts) {
            if ($p -match '^\d+$') { $normalized += [int]$p }
            else { $normalized += 0 }
        }

        while ($normalized.Count -lt 3) { $normalized += 0 }
        if ($normalized.Count -gt 4) { $normalized = $normalized[0..3] }

        # Join safely into a string and parse
        $verString = ($normalized -join '.')
        try { return [System.Version]::Parse($verString) }
        catch { return $null }
    }


    # Split OR groups: e.g. ">=14 <16 || >=18"
    $orGroups = $Constraint -split '\|\|'

    foreach ($group in $orGroups) {
        $andConditions = [regex]::Matches($group, '([><=~^]*\s*[\d\.x]+)') | ForEach-Object { $_.Value.Trim() }
        $allMatch = $true

        foreach ($cond in $andConditions) {
            if ([string]::IsNullOrWhiteSpace($cond)) { continue }

            # Extract operator and version part
            if ($cond -match '^([><=~^]*)([\d\.x]+)$') {
                $op = $matches[1]
                $verPart = $matches[2]
            } else {
                continue
            }

            $ver = ConvertTo-Version $verPart
            if (-not $ver) { continue }
            switch -Regex ($op) {

                '^>=$' {  if ($CurrentVersion.CompareTo($ver) -lt 0) { $allMatch = $false; } }
                '^<=$' {  if ($CurrentVersion.CompareTo($ver) -gt 0) { $allMatch = $false; } }
                '^>$'  { if ($CurrentVersion.CompareTo($ver) -le 0) { $allMatch = $false;  } }
                '^<$'  { if ($CurrentVersion.CompareTo($ver) -ge 0) { $allMatch = $false;  } }
                '^\^'  { if ($CurrentVersion.Major -ne $ver.Major -or $CurrentVersion.CompareTo($ver) -lt 0) { $allMatch = $false; } }
                '^~'   { if ($CurrentVersion.Major -ne $ver.Major -or $CurrentVersion.Minor -ne $ver.Minor -or $CurrentVersion.CompareTo($ver) -lt 0) { $allMatch = $false; } }
                'x'    { if ($CurrentVersion.Major -ne $ver.Major) { $allMatch = $false } }
                default {
                    # Exact match
                    if ($CurrentVersion.Major -ne $ver.Major -or
                        $CurrentVersion.Minor -ne $ver.Minor -or
                        $CurrentVersion.Build -ne $ver.Build) {
                        $allMatch = $false
                        write-Host "Exact version mismatch: $CurrentVersion vs $ver" -ForegroundColor Gray
                    }
                }
            }
        }

        if ($allMatch) { return $true }  # one OR-group passes
    }

    return $false
}

#endregion

#region Package.json Management

function Remove-PackageJsonDependency {
    param([string]$PackageName)
    
    $pkgPath = Join-Path (Get-Location) 'package.json'
    if (-not (Test-Path $pkgPath)) { 
        Write-Warning "package.json not found"
        return 
    }
    
    try {
        $pkgObj = Get-Content $pkgPath -Raw | ConvertFrom-Json
        $removed = $false
        
        $sections = @('dependencies', 'devDependencies')
        foreach ($section in $sections) {
            if ($pkgObj.$section -and $pkgObj.$section.PSObject.Properties[$PackageName]) {
                $pkgObj.$section.PSObject.Properties.Remove($PackageName)
                $removed = $true
            }
        }
        
        if ($pkgObj.frontendDependencies -and $pkgObj.frontendDependencies.packages) {
            if ($pkgObj.frontendDependencies.packages.PSObject.Properties[$PackageName]) {
                $pkgObj.frontendDependencies.packages.PSObject.Properties.Remove($PackageName)
                $removed = $true
            }
        }
        
        if (-not $PackageName.StartsWith("@")) {
            $scopedName = "@$GithubUsername/$PackageName"
            foreach ($section in $sections) {
                if ($pkgObj.$section -and $pkgObj.$section.PSObject.Properties[$scopedName]) {
                    $pkgObj.$section.PSObject.Properties.Remove($scopedName)
                    $removed = $true
                }
            }
            if ($pkgObj.frontendDependencies -and $pkgObj.frontendDependencies.packages) {
                if ($pkgObj.frontendDependencies.packages.PSObject.Properties[$scopedName]) {
                    $pkgObj.frontendDependencies.packages.PSObject.Properties.Remove($scopedName)
                    $removed = $true
                }
            }
        }
        
        if ($removed) {
            ConvertTo-Json $pkgObj -Depth 10 | Format-Json | Set-Content $pkgPath -Encoding UTF8
            Write-Host "Removed $PackageName from package.json" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to update package.json: $($_.Exception.Message)"
    }
}

function Update-PackageJsonDependencyInCorrectSection {
    param(
        [string]$PackageName,
        [string]$Version
    )

    $pkgPath = Join-Path (Get-Location) 'package.json'
    if (-not (Test-Path $pkgPath)) { return }

    try {
        $pkgObj = Get-Content $pkgPath -Raw | ConvertFrom-Json
        $lowerUser = $GithubUsername.ToLower()
        $aliasValue = "@$lowerUser/$PackageName@$Version"
        $scopedName = "@$lowerUser/$PackageName"

        $isInFrontendDeps = $false
        if ($pkgObj.frontendDependencies -and
            $pkgObj.frontendDependencies.packages -and
            $pkgObj.frontendDependencies.packages.PSObject.Properties[$PackageName]) {
            $isInFrontendDeps = $true
        }

        if ($isInFrontendDeps) {
            # Update frontendDependencies
            $pkgObj.frontendDependencies.packages.$PackageName.version = $aliasValue
            # Remove scoped name from dependencies if npm added it
            if ($pkgObj.dependencies) {
                $pkgObj.dependencies.PSObject.Properties.Remove($scopedName) | Out-Null
            }
        } else {
            # Ensure dependencies section exists
            if (-not $pkgObj.dependencies) {
                $pkgObj | Add-Member -NotePropertyName dependencies -NotePropertyValue ([PSCustomObject]@{})
            }
            
            # Check if package already exists in alias format
            $alreadyHasAlias = $null -ne $pkgObj.dependencies.PSObject.Properties[$PackageName]
            
            # Check if npm added it in scoped format
            $npmAddedScoped = $null -ne $pkgObj.dependencies.PSObject.Properties[$scopedName]
            
            if ($npmAddedScoped) {
                # Remove that and add in alias format
                $pkgObj.dependencies.PSObject.Properties.Remove($scopedName) | Out-Null
                $pkgObj.dependencies | Add-Member -NotePropertyName $PackageName -NotePropertyValue $aliasValue -Force
            } elseif (-not $alreadyHasAlias) {
                # Package doesn't exist at all, add it in alias format
                $pkgObj.dependencies | Add-Member -NotePropertyName $PackageName -NotePropertyValue $aliasValue -Force
            } else {
                # Already exists in alias format, just update the version
                $pkgObj.dependencies.$PackageName = $aliasValue
            }
        }
        
        ConvertTo-Json $pkgObj -Depth 10 | Format-Json | Set-Content $pkgPath -Encoding UTF8
    } catch {
        Write-Warning "Failed to update package.json: $($_.Exception.Message)"
    }
}

function Convert-ToScopedFormat {
    <#
    .SYNOPSIS
    Converts package.json to scoped format: "@username/packagename": "version"
    This is done BEFORE installation to ensure npm can find packages in GitHub registry
    #>
    param([string]$Owner = $GithubUsername.ToLower())
    
    $pkgPath = Join-Path (Get-Location) "package.json"
    if (-not (Test-Path $pkgPath)) {
        Write-Warning "package.json not found"
        return $false
    }

    try {
        $json = Get-Content $pkgPath -Raw | ConvertFrom-Json
        $modified = $false

        # Process dependencies
        if ($json.dependencies) {
            $newDeps = [ordered]@{}
            foreach ($prop in $json.dependencies.PSObject.Properties) {
                $pkgName = $prop.Name
                $ver = $prop.Value

                # Skip if already in scoped format
                if ($pkgName.StartsWith("@$Owner/")) {
                    $newDeps[$pkgName] = $ver
                    continue
                }

                # Extract version from alias format if present
                if ($ver -match "npm:@$Owner/[^@]+@(.+)$") {
                    $ver = $matches[1]
                    $modified = $true
                } elseif ($ver -match "@$Owner/[^@]+@(.+)$") {
                    $ver = $matches[1]
                    $modified = $true
                }

                # Convert to scoped format
                $scopedName = "@$Owner/$pkgName"
                $newDeps[$scopedName] = $ver
                $modified = $true
            }
            
            # Replace dependencies object
            $json.dependencies = [PSCustomObject]$newDeps
        }

        # Process devDependencies
        if ($json.devDependencies) {
            $newDevDeps = [ordered]@{}
            foreach ($prop in $json.devDependencies.PSObject.Properties) {
                $pkgName = $prop.Name
                $ver = $prop.Value

                if ($pkgName.StartsWith("@$Owner/")) {
                    $newDevDeps[$pkgName] = $ver
                    continue
                }

                if ($ver -match "npm:@$Owner/[^@]+@(.+)$") {
                    $ver = $matches[1]
                    $modified = $true
                } elseif ($ver -match "@$Owner/[^@]+@(.+)$") {
                    $ver = $matches[1]
                    $modified = $true
                }

                $scopedName = "@$Owner/$pkgName"
                $newDevDeps[$scopedName] = $ver
                $modified = $true
            }
            
            $json.devDependencies = [PSCustomObject]$newDevDeps
        }

        # Process frontendDependencies
        if ($json.frontendDependencies -and $json.frontendDependencies.packages) {
            foreach ($prop in $json.frontendDependencies.packages.PSObject.Properties) {
                $pkgName = $prop.Name
                $verObj = $json.frontendDependencies.packages.$pkgName

                if (-not $verObj.version) { continue }
                
                # Skip if already in scoped format
                if ($pkgName.StartsWith("@$Owner/")) { continue }

                $currentVer = $verObj.version
                
                # Extract version from alias format if present
                if ($currentVer -match "npm:@$Owner/[^@]+@(.+)$") {
                    $currentVer = $matches[1]
                    $modified = $true
                } elseif ($currentVer -match "@$Owner/[^@]+@(.+)$") {
                    $currentVer = $matches[1]
                    $modified = $true
                }

                # Update to scoped format
                $verObj.version = $currentVer
                
                # Rename the property
                $scopedName = "@$Owner/$pkgName"
                $json.frontendDependencies.packages | Add-Member -NotePropertyName $scopedName -NotePropertyValue $verObj -Force
                $json.frontendDependencies.packages.PSObject.Properties.Remove($pkgName)
                $modified = $true
            }
        }

        if ($modified) {
            ConvertTo-Json $json -Depth 10 | Format-Json | Set-Content $pkgPath -Encoding UTF8
            Write-Host "Converted package.json to scoped format (@$Owner/...)" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Package.json already in scoped format" -ForegroundColor Gray
            return $false
        }
    } catch {
        Write-Warning "Failed to convert to scoped format: $($_.Exception.Message)"
        return $false
    }
}

$Global:packageJsonBackup = $null    
function Backup-PackageJson {
    $packageJsonPath = Join-Path (Get-Location) "package.json"
    if (Test-Path $packageJsonPath) {
        $Global:packageJsonBackup = Get-Content $packageJsonPath -Raw
        Write-Host "Package.json backed up successfully" -ForegroundColor Green
    }
}

function Restore-PackageJsonBackup {
    $packageJsonPath = Join-Path (Get-Location) "package.json"
    if ($null -ne $Global:packageJsonBackup) {
        try {
            Set-Content -Path $packageJsonPath -Value $Global:packageJsonBackup -Encoding UTF8
            Write-Host "Package.json restored to original format" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to restore package.json: $($_.Exception.Message)"
        }
    } else {
        Write-Warning "No backup available to restore package.json"
    }
}

function Convert-ToAliasFormat {
    <#
    .SYNOPSIS
    Converts package.json to alias format: "packageName": "npm:@username/packageName@version"
    This is done AFTER installation for better readability and compatibility
    #>
    param([string]$Owner = $GithubUsername.ToLower())
    
    $pkgPath = Join-Path (Get-Location) "package.json"
    if (-not (Test-Path $pkgPath)) {
        Write-Warning "package.json not found"
        return $false
    }

    try {
        $json = Get-Content $pkgPath -Raw | ConvertFrom-Json
        $modified = $false

        # Process dependencies
        if ($json.dependencies) {
            $newDeps = [ordered]@{}
            foreach ($prop in $json.dependencies.PSObject.Properties) {
                $pkgName = $prop.Name
                $ver = $prop.Value

                # Check if it's a scoped package from our registry
                if ($pkgName -match "^@$Owner/(.+)$") {
                    $unscopedName = $matches[1]
                    $aliasValue = "npm:@$Owner/$unscopedName@$ver"
                    $newDeps[$unscopedName] = $aliasValue
                    $modified = $true
                } else {
                    # Keep as-is if not our scoped package
                    $newDeps[$pkgName] = $ver
                }
            }
            
            $json.dependencies = [PSCustomObject]$newDeps
        }

        # Process devDependencies
        if ($json.devDependencies) {
            $newDevDeps = [ordered]@{}
            foreach ($prop in $json.devDependencies.PSObject.Properties) {
                $pkgName = $prop.Name
                $ver = $prop.Value

                if ($pkgName -match "^@$Owner/(.+)$") {
                    $unscopedName = $matches[1]
                    $aliasValue = "npm:@$Owner/$unscopedName@$ver"
                    $newDevDeps[$unscopedName] = $aliasValue
                    $modified = $true
                } else {
                    $newDevDeps[$pkgName] = $ver
                }
            }
            
            $json.devDependencies = [PSCustomObject]$newDevDeps
        }

        # Process frontendDependencies
        if ($json.frontendDependencies -and $json.frontendDependencies.packages) {
            $newFrontendPkgs = [ordered]@{}
            foreach ($prop in $json.frontendDependencies.packages.PSObject.Properties) {
                $pkgName = $prop.Name
                $verObj = $json.frontendDependencies.packages.$pkgName

                if ($pkgName -match "^@$Owner/(.+)$") {
                    $unscopedName = $matches[1]
                    $currentVer = $verObj.version
                    $aliasValue = "npm:@$Owner/$unscopedName@$currentVer"
                    
                    # Create new version object
                    $newVerObj = [PSCustomObject]@{}
                    foreach ($verProp in $verObj.PSObject.Properties) {
                        if ($verProp.Name -eq 'version') {
                            $newVerObj | Add-Member -NotePropertyName 'version' -NotePropertyValue $aliasValue
                        } else {
                            $newVerObj | Add-Member -NotePropertyName $verProp.Name -NotePropertyValue $verProp.Value
                        }
                    }
                    
                    $newFrontendPkgs[$unscopedName] = $newVerObj
                    $modified = $true
                } else {
                    $newFrontendPkgs[$pkgName] = $verObj
                }
            }
            
            $json.frontendDependencies.packages = [PSCustomObject]$newFrontendPkgs
        }

        if ($modified) {
            ConvertTo-Json $json -Depth 10 | Format-Json | Set-Content $pkgPath -Encoding UTF8
            Write-Host "Converted package.json to alias format (packageName: npm:@$Owner/...)" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Package.json already in alias format or no conversion needed" -ForegroundColor Gray
            return $false
        }
    } catch {
        Write-Warning "Failed to convert to alias format: $($_.Exception.Message)"
        return $false
    }
}

function Convert-PackageSymlinks {
    <#
    .SYNOPSIS
    Creates junction points for all installed scoped packages to their unscoped names.
    Handles both regular packages and scoped packages with delimiter.
    Examples:
    - @ve00ym329/axios -> axios
    - @ve00ym329/colors-p.g-colors -> @colors/colors
    #>
    param([string]$Owner = $GithubUsername.ToLower())
    
    $nodeModulesPath = Join-Path (Get-Location) "node_modules"
    if (-not (Test-Path $nodeModulesPath)) {
        Write-Warning "node_modules folder not found"
        return $false
    }

    $scopedPath = Join-Path $nodeModulesPath "@$Owner"
    if (-not (Test-Path $scopedPath)) {
        Write-Host "No @$Owner scoped packages found in node_modules" -ForegroundColor Gray
        return $false
    }

    try {
        $junctionCount = 0
        $skippedCount = 0
        $failedCount = 0

        # Get all packages in the scoped folder
        Get-ChildItem -Path $scopedPath -Directory | ForEach-Object {
            $scopedPackageName = $_.Name
            $scopedPackagePath = $_.FullName
            
            # Check if this is a package with the delimiter (originally a scoped package)
            if ($scopedPackageName -match "^(.+)$Global:delimiter(.+)$") {
                $originalScope = $matches[1]
                $originalPackageName = $matches[2]
                
                Write-Host "Processing scoped package: $originalScope/$originalPackageName" -ForegroundColor Cyan
                
                # Create the scope directory if it doesn't exist
                $targetScopePath = Join-Path $nodeModulesPath "@$originalScope"
                if (-not (Test-Path $targetScopePath)) {
                    try {
                        New-Item -ItemType Directory -Path $targetScopePath -Force -ErrorAction Stop | Out-Null
                        Write-Host "  Created scope directory: @$originalScope" -ForegroundColor Green
                    } catch {
                        Write-Warning "  Failed to create scope directory @$originalScope : $($_.Exception.Message)"
                        $failedCount++
                        return
                    }
                }
                
                # Create junction: @originalScope/originalPackageName -> @owner/scope-p.g-package
                $targetJunctionPath = Join-Path $targetScopePath $originalPackageName
                
                # Check if target already exists
                if (Test-Path $targetJunctionPath) {
                    $item = Get-Item $targetJunctionPath -Force
                    if ($item.LinkType -eq "Junction" -and $item.Target -eq $scopedPackagePath) {
                        Write-Host "  Junction already exists and is correct: @$originalScope/$originalPackageName" -ForegroundColor Gray
                        $skippedCount++
                        return
                    } elseif ($item.LinkType -eq "Junction") {
                        # Remove old junction and create new one
                        try {
                            Remove-Item $targetJunctionPath -Force -ErrorAction Stop
                            New-Item -ItemType Junction -Path $targetJunctionPath -Target $scopedPackagePath -Force -ErrorAction Stop | Out-Null
                            Write-Host "  Updated junction: @$originalScope/$originalPackageName -> @$Owner/$scopedPackageName" -ForegroundColor Green
                            $junctionCount++
                        } catch {
                            Write-Warning "  Failed to update junction: @$originalScope/$originalPackageName - $($_.Exception.Message)"
                            $failedCount++
                        }
                    } else {
                        Write-Warning "  Path exists but is not a junction: @$originalScope/$originalPackageName"
                        $skippedCount++
                    }
                } else {
                    # Create new junction
                    try {
                        New-Item -ItemType Junction -Path $targetJunctionPath -Target $scopedPackagePath -Force -ErrorAction Stop | Out-Null
                        Write-Host "  Created junction: @$originalScope/$originalPackageName -> @$Owner/$scopedPackageName" -ForegroundColor Green
                        $junctionCount++
                    } catch {
                        Write-Warning "  Failed to create junction: @$originalScope/$originalPackageName - $($_.Exception.Message)"
                        $failedCount++
                    }
                }
            } else {
                # Regular unscoped package
                $unscopedJunctionPath = Join-Path $nodeModulesPath $scopedPackageName

                # Check if unscoped name already exists
                if (Test-Path $unscopedJunctionPath) {
                    $item = Get-Item $unscopedJunctionPath -Force
                    if ($item.LinkType -eq "Junction" -and $item.Target -eq $scopedPackagePath) {
                        $skippedCount++
                    } elseif ($item.LinkType -eq "Junction") {
                        # Remove old junction and create new one
                        try {
                            Remove-Item $unscopedJunctionPath -Force -ErrorAction Stop
                            New-Item -ItemType Junction -Path $unscopedJunctionPath -Target $scopedPackagePath -Force -ErrorAction Stop | Out-Null
                            $junctionCount++
                        } catch {
                            Write-Warning "  Failed to update junction: $scopedPackageName - $($_.Exception.Message)"
                            $failedCount++
                        }
                    } else {
                        $skippedCount++
                    }
                } else {
                    # Create the junction point
                    try {
                        New-Item -ItemType Junction -Path $unscopedJunctionPath -Target $scopedPackagePath -Force -ErrorAction Stop | Out-Null
                        $junctionCount++
                    } catch {
                        Write-Warning "  Failed to create junction: $scopedPackageName - $($_.Exception.Message)"
                        $failedCount++
                    }
                }
            }
        }

        Write-Host "`n=== SYMLINK CREATION SUMMARY ===" -ForegroundColor Magenta
        if ($junctionCount -gt 0) {
            Write-Host "Created/Updated: $junctionCount junction(s)" -ForegroundColor Green
        }
        if ($skippedCount -gt 0) {
            Write-Host "Skipped: $skippedCount package(s) (already correct)" -ForegroundColor Gray
        }
        if ($failedCount -gt 0) {
            Write-Host "Failed: $failedCount package(s)" -ForegroundColor Red
        }
        
        Copy-FrontendDependencies | Out-Null
        return $junctionCount -gt 0
    } catch {
        Write-Warning "Failed to create junctions: $($_.Exception.Message)"
        return $false
    }
}

function Copy-FrontendDependencies {
    <#
    .SYNOPSIS
    Copies frontend dependency files from node_modules to target directories
    Mimics the functionality of the frontend-dependencies npm package
    #>
    
    $packageJsonPath = Join-Path (Get-Location) "package.json"
    if (-not (Test-Path $packageJsonPath)) {
        Write-Warning "package.json not found"
        return $false
    }

    try {
        $packageJson = Get-Content $packageJsonPath -Raw | ConvertFrom-Json
        
        if (-not $packageJson.frontendDependencies) {
            Write-Host "No frontendDependencies in package.json" -ForegroundColor Gray
            return $false
        }

        if (-not $packageJson.frontendDependencies.packages) {
            Write-Warning "No frontendDependencies.packages in package.json"
            return $false
        }

        $defaultTarget = $packageJson.frontendDependencies.target
        if (-not $defaultTarget) {
            Write-Warning "No default 'frontendDependencies.target' in package.json"
            return $false
        }

        $nodeModulesPath = Join-Path (Get-Location) "node_modules"
        $copiedCount = 0
        $failedCount = 0

        Write-Host "`n=== COPYING FRONTEND DEPENDENCIES TO TARGET PATHS ===" -ForegroundColor Magenta

        foreach ($prop in $packageJson.frontendDependencies.packages.PSObject.Properties) {
            $pkgName = $prop.Name
            $pkgConfig = $prop.Value

            # Determine source path in node_modules
            $scopedPath = Join-Path $nodeModulesPath "@$($GithubUsername.ToLower())/$pkgName" 
            $unscopedPath = Join-Path $nodeModulesPath $pkgName
            
            $modulePath = $null
            if (Test-Path $scopedPath) {
                $modulePath = $scopedPath
            } elseif (Test-Path $unscopedPath) {
                $modulePath = $unscopedPath
            } else {
                Write-Warning "  Module not found in node_modules: $pkgName"
                $failedCount++
                continue
            }

            # Determine source files/folder within the module
            $srcPattern = $pkgConfig.src
            if ($srcPattern) {
                $sourceFilesPath = Join-Path $modulePath $srcPattern
            } else {
                # Copy entire package (all files)
                $sourceFilesPath = Join-Path $modulePath "*"
            }

            # Determine target path
            $targetPath = $pkgConfig.target
            if (-not $targetPath) {
                $targetPath = $defaultTarget
            }
            $targetPath = Join-Path (Get-Location) $targetPath

            # Check namespaced option
            $namespaced = $pkgConfig.namespaced
            if ($null -eq $namespaced -and -not $srcPattern) {
                # Default to namespaced if src not defined (to prevent namespace errors)
                $namespaced = $true
            }

            if ($namespaced) {
                $unscopedPackageName = $pkgName -replace "@$($GithubUsername.ToLower())/", ""
                $targetPath = Join-Path $targetPath $unscopedPackageName
            }

            # Create target directory
            if (-not (Test-Path $targetPath)) {
                New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
            }

            # Copy files
            try {
                # Check if source path has wildcards or is a specific file/folder
                if ($srcPattern -and ($srcPattern -match '\*' -or $srcPattern -match '\{.*\}')) {
                    # Handle glob patterns like "dist/*" or "dist/{file1,file2}"
                    # PowerShell doesn't support brace expansion like bash, so we'll use wildcards
                    $sourceFiles = Get-ChildItem -Path $sourceFilesPath -Recurse -ErrorAction SilentlyContinue
                    
                    if ($sourceFiles) {
                        Copy-Item -Path $sourceFilesPath -Destination $targetPath -Recurse -Force -ErrorAction Stop
                        $copiedCount++
                    } else {
                        Write-Warning "  No files found matching pattern: $srcPattern"
                        $failedCount++
                    }
                } else {
                    # Copy entire directory or specific files
                    if (Test-Path $sourceFilesPath) {
                        Copy-Item -Path $sourceFilesPath -Destination $targetPath -Recurse -Force -ErrorAction Stop
                        $copiedCount++
                    } else {
                        Write-Warning "  Source path not found: $sourceFilesPath"
                        $failedCount++
                    }
                }
            } catch {
                Write-Warning "  Failed to copy files: $($_.Exception.Message)"
                $failedCount++
            }
        }

        if ($copiedCount -gt 0) {
            Write-Host "Successfully copied: $copiedCount package(s)" -ForegroundColor Green
        }
        if ($failedCount -gt 0) {
            Write-Host "Failed: $failedCount package(s)" -ForegroundColor Red
        }

        return $copiedCount -gt 0
    } catch {
        Write-Warning "Failed to process frontend dependencies: $($_.Exception.Message)"
        return $false
    }
}
   

#endregion

#region Version Resolution

function Get-PackageVersion {
    param(
        [string]$PackageName,
        [string]$VersionSpec = "latest"
    )

    $cacheKey = "$PackageName@$VersionSpec"
    if ($Global:VersionCache.ContainsKey($cacheKey)) {
        return $Global:VersionCache[$cacheKey]
    }

    try {
        $versionOutput = npm view "$PackageName@$VersionSpec" version `
            --registry=https://registry.npmjs.org/ 2>$null |
            Select-Object -Last 1 |
            ForEach-Object { if ($_ -match '\d+\.\d+\.\d+(?:-[0-9A-Za-z\.-]+)?') { $matches[0] } }

        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($versionOutput)) {
            $resolved = $versionOutput.Trim().Trim("'").Trim('"')
            $Global:VersionCache[$cacheKey] = $resolved
            return $resolved
        }

        if ($VersionSpec -match '^[><=]+') {
            $allVersionsRaw = npm view $PackageName versions --json --registry=https://registry.npmjs.org/ 2>$null
            if ($allVersionsRaw) {
                $allVersions = $allVersionsRaw | ConvertFrom-Json
                if ($allVersions -is [Array] -and $allVersions.Count -gt 0) {
                    $resolved = $allVersions[-1]
                    $Global:VersionCache[$cacheKey] = $resolved
                    return $resolved
                }
            }
        }

        Write-Host "Could not resolve '$VersionSpec' for '$PackageName'" -ForegroundColor Yellow
        return $VersionSpec
    } catch {
        Write-Host "Error resolving $PackageName : $($_.Exception.Message)" -ForegroundColor Red
        return $VersionSpec
    }
}

#endregion

#region Workflow Management

function Wait-For-Workflow {
    param(
        [string]$PackageName,
        [string]$Version
    )

    Write-Host "  Waiting for workflow to complete..." -ForegroundColor Gray
    
    Start-Sleep -Seconds 5
    
    try {
        $runsUrl = "https://api.github.com/repos/$GithubUsername/$GithubRepo/actions/workflows/publish-to-ghp.yml/runs?per_page=5"
        $workflowRuns = Invoke-RestMethod -Uri $runsUrl -Headers $headers
        $latestRun = $workflowRuns.workflow_runs | 
            Where-Object { $_.created_at -gt (Get-Date).AddMinutes(-5).ToUniversalTime().ToString("o") } |
            Sort-Object -Property created_at -Descending | 
            Select-Object -First 1

        if (-not $latestRun) {
            Write-Warning "Could not find workflow run"
            return $false
        }
        
        $runId = $latestRun.id
        $status = $latestRun.status
        $timeout = (Get-Date).AddMinutes(10)  # Longer timeout since processing all deps

        Write-Host "  Monitoring workflow run #$runId" -ForegroundColor Gray

        while ($status -ne "completed" -and (Get-Date) -lt $timeout) {
            Start-Sleep -Seconds 10
            
            $runUrl = "https://api.github.com/repos/$GithubUsername/$GithubRepo/actions/runs/$runId"
            $runDetails = Invoke-RestMethod -Uri $runUrl -Headers $headers
            $status = $runDetails.status
            
            Write-Host "  Status: $status" -ForegroundColor Gray
        }

        if ($status -ne "completed") {
            Write-Warning "Workflow timed out after 10 minutes"
            return $false
        }

        $conclusion = $runDetails.conclusion
        if ($conclusion -eq 'success') {
            Write-Host "Workflow completed successfully" -ForegroundColor Green
            return $true
        } else {
            Write-Warning "Workflow completed with status: $conclusion"
            return $false
        }
    } catch {
        Write-Warning "Error monitoring workflow: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-PackagePublishWorkflow {
    param(
        [string]$PackageName,
        [string]$Version
    )

    Write-Host "Processing Package: [$PackageName@$Version]" -ForegroundColor Cyan

    $cacheCheckOutput = npm view "$PackageName@$Version" version --registry=https://npm.pkg.github.com 2>&1
    $unscopedPackageName = $PackageName -replace "^@?$GithubUsername[/\-]", ""
    # If not found in GitHub registry, perform checks
    if ($LASTEXITCODE -ne 0 -or $cacheCheckOutput -notmatch '\d+\.\d+') { 
        # Fetch metadata (single call)
        $metaPackageData = npm view "$unscopedPackageName@$Version" --json | ConvertFrom-Json
        # Check for errors
        if ($LASTEXITCODE -ne 0 -or $metaPackageData -match "ERR!") {
            Write-Warning "Failed to fetch metadata for $unscopedPackageName@$Version, Output: $metaPackageData"
            continue
        }

        # Extract individual fields
        $extractedLicense = $metaPackageData.license
        $extractedNodeEngine = $metaPackageData.engines.node
        $deprecationStatus = $metaPackageData.deprecated   
        # Check deprecation status
        if (-not [string]::IsNullOrEmpty($deprecationStatus)) {
            Write-Warning "This package version is deprecated: $deprecationStatus"
            Write-Host "Consider using a different version." -ForegroundColor Yellow
            Write-VersionSuggestions -PackageName $unscopedPackageName -ProblemVersion $Version
        }

        # Dependency license check function
        function Test-DependencyLicenses {
            param(
                [string]$RootPackage,
                [string]$RootVersion
            )
            $checked = @{}
            
            function CheckRecursively {
                param (
                    [string]$Pkg,
                    [string]$Ver
                )
                $key = "$Pkg@$Ver"
                if ($checked.ContainsKey($key)) { return $true }
                $checked[$key] = $true
                
                # Skip if version has unresolved specifiers
                if ($Ver -match '[<>=~^]') {
                    Write-Host "  Skipping license check for $Pkg@$Ver (unresolved version)" -ForegroundColor DarkGray
                    return $true
                }
                
                Write-Host "  Checking license for $Pkg@$Ver" -ForegroundColor DarkCyan
                
                $depLicense = npm view "$Pkg@$Ver" license --registry=https://registry.npmjs.org/ 2>$null
                if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrEmpty($depLicense)) {
                    Write-Host "    Could not retrieve license, skipping" -ForegroundColor DarkGray
                    return $true
                }
                
                Write-Host "    License: $depLicense" -ForegroundColor DarkCyan
                if (-not (Test-LicenseExpression -Expression $depLicense)) {
                    Write-Error "LICENSE VIOLATION: Dependency $Pkg@$Ver has unapproved license '$depLicense'"
                    return $false
                }
                
                # Check dependencies of this package
                $depsJson = npm view "$Pkg@$Ver" dependencies --json --registry=https://registry.npmjs.org/ 2>$null
                if (-not [string]::IsNullOrEmpty($depsJson) -and $depsJson -ne 'undefined') {
                    try {
                        $depObj = $depsJson | ConvertFrom-Json
                        if ($depObj.PSObject.Properties.Count -gt 0) {
                            foreach ($depName in $depObj.PSObject.Properties.Name) {
                                $depVerSpec = $depObj.$depName
                                
                                # Try to resolve the dependency version
                                $resolvedDepVer = Get-PackageVersion -PackageName $depName -VersionSpec $depVerSpec
                                
                                # Skip if we couldn't resolve it properly
                                if ($resolvedDepVer -eq $depVerSpec -and $depVerSpec -match '[<>=~^]') {
                                    Write-Host "    Skipping $depName@$depVerSpec (complex range)" -ForegroundColor DarkGray
                                    continue
                                }
                                
                                if (-not (CheckRecursively -Pkg $depName -Ver $resolvedDepVer)) {
                                    return $false
                                }
                            }
                        }
                    } catch {
                        Write-Host "    Failed to parse dependencies: $($_.Exception.Message)" -ForegroundColor DarkGray
                    }
                }
                return $true
            }
            
            $result = CheckRecursively -Pkg $RootPackage -Ver $RootVersion
            Write-Host "Finished license check for $RootPackage@$RootVersion" -ForegroundColor Gray
            return $result
        }

        # LICENSE CHECK - only if not cached
        Write-Host "[LICENSE] Top-level license for $unscopedPackageName@$Version : $extractedLicense" -ForegroundColor Cyan

        if (-not (Test-LicenseExpression -Expression $extractedLicense)) {
            Write-Error "LICENSE VIOLATION: The license '$extractedLicense' for $unscopedPackageName@$Version is not approved. Halting."
            return $result
        }
    
        Write-Host "[LICENSE] Checking all dependencies for $unscopedPackageName@$Version..." -ForegroundColor Magenta
        if (-not (Test-DependencyLicenses -RootPackage $unscopedPackageName -RootVersion $Version)) {
            Write-Error "LICENSE VIOLATION: One or more dependencies of $unscopedPackageName@$Version have unapproved licenses."
            return $result
        }
        Write-Host "[LICENSE] All licenses approved!" -ForegroundColor Green
        
        NODE COMPATIBILITY CHECK
        $isCompatible = Test-NodeCompatibility -unscopedPackageName $unscopedPackageName -PackageVersion $Version -NodeEngine $extractedNodeEngine
        if (-not $isCompatible) {
            Write-Host "Proceeding despite compatibility warning..." -ForegroundColor Yellow
        }    
    } else {
        Write-Host "Package $unscopedPackageName@$Version already published in GitHub registry cache. Skipping license and compatibility checks." -ForegroundColor Green
    }
    # Trigger GitHub Workflow
    Write-Host "Triggering workflow for $unscopedPackageName@$Version (with all dependencies)" -ForegroundColor Cyan
    Write-Host "This will automatically process all transitive dependencies." -ForegroundColor Yellow
    
    try {
        $body = @{
            ref = "main"
            inputs = @{
                package_name = $unscopedPackageName
                package_version = $Version
            }
        } | ConvertTo-Json

        Invoke-RestMethod -Uri $GithubApiUrl -Method POST -Headers $headers -Body $body -ContentType "application/json" | Out-Null
        $workflowSucceeded = Wait-For-Workflow -PackageName $PackageName -Version $Version
        return $workflowSucceeded
    } catch {
        Write-Host "  Error triggering workflow: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

#endregion

#region Package Installation

function Install-FromGitHubRegistry {
    param(
        [string]$PackageName,
        [string]$Version,
        [boolean] $IsPackageJsonUpdateRequired = $true
    )
    $PublishedName = Get-PublishedName -origName $PackageName -owner $GithubUsername.ToLower()    
    try {
        $installCmd = "npm install `"$PublishedName@$Version`" --registry=https://npm.pkg.github.com --prefer-offline --no-audit --silent"
        Write-Host "Installing $PublishedName@$Version from GitHub registry..." -ForegroundColor Cyan        
        try {
            $output = & cmd /c $installCmd 2>&1
            $exitCode = $LASTEXITCODE

            if ($exitCode -eq 0) {
                Write-Host " Installed successfully" -ForegroundColor Green
                if ($IsPackageJsonUpdateRequired) {
                    Update-PackageJsonDependencyInCorrectSection -PackageName $PackageName -Version $Version
                }
                return $true
            }
            elseif ($output -match 'up to date' -or $output -match 'already satisfied' -or $output -match 'Nothing to install' -or $output -match 'added 0 packages') {
                Write-Host " Package already installed and up to date" -ForegroundColor Yellow
                return $true
            }
            else {
                Write-Warning " Installation failed with code $exitCode"
                Write-Host " Installation Failure Output: $output"
                return $false
            }
        }
        catch {
            Write-Warning " Installation failed with exception: $($_.Exception.Message)"
            return $false
        }

    } catch {
        Write-Host "  Exception: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

#endregion

#region Uninstall Functions

function Uninstall-Package {
    param([string]$PackageName)

    Write-Host "Uninstalling: $PackageName" -ForegroundColor Cyan

    $uninstalled = $false
    $nodeModulesPath = Join-Path (Get-Location) 'node_modules'
    
    if ($PackageName.StartsWith("@")) {
        $packagePath = Join-Path $nodeModulesPath $PackageName
        
        if (Test-Path $packagePath) {
            try {
                npm uninstall $PackageName --no-save 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "  Removed successfully" -ForegroundColor Green
                } else {
                    Remove-Item $packagePath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "  Manually removed" -ForegroundColor Green
                }
                $uninstalled = $true
            } catch {
                Write-Warning "Failed to remove: $($_.Exception.Message)"
            }
        }
    } else {
        $scopedName = "@$GithubUsername/$PackageName"
        $scopedPath = Join-Path $nodeModulesPath "@$GithubUsername"
        $scopedPackagePath = Join-Path $scopedPath $PackageName
        
        if (Test-Path $scopedPackagePath) {
            try {
                npm uninstall $scopedName --no-save 2>$null
                if ($LASTEXITCODE -ne 0) {
                    Remove-Item $scopedPackagePath -Recurse -Force -ErrorAction SilentlyContinue
                }
                Write-Host "  Removed scoped package" -ForegroundColor Green
                $uninstalled = $true
            } catch {}
        }
        
        $unscopedPath = Join-Path $nodeModulesPath $PackageName
        if (Test-Path $unscopedPath) {
            try {
                npm uninstall $PackageName --no-save 2>$null
                if ($LASTEXITCODE -ne 0) {
                    Remove-Item $unscopedPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                Write-Host "  Removed unscoped package" -ForegroundColor Green
                $uninstalled = $true
            } catch {}
        }
    }
    
    Remove-PackageJsonDependency -PackageName $PackageName
    
    if (-not $uninstalled) {
        Write-Host "  Package not found" -ForegroundColor Yellow
    }
    
    return $uninstalled
}

#endregion

#region Main Script Logic

if ($Help) {
    Show-Help
    exit 0
}

# Mode 1: Uninstall
if ($Uninstall -and $args.Count -gt 0) {
    Write-Host "=== UNINSTALL MODE ===" -ForegroundColor Magenta
    
    $uninstalledPackages = @()
    
    foreach ($arg in $args) {
        $packageName = $arg
        
        if ($packageName.StartsWith("@")) {
            $firstAt = $packageName.IndexOf('@')
            $lastAtIndex = $packageName.LastIndexOf('@')
            if ($lastAtIndex -gt $firstAt) {
                $packageName = $packageName.Substring(0, $lastAtIndex)
            }
        } else {
            $lastAtIndex = $packageName.LastIndexOf('@')
            if ($lastAtIndex -gt 0) {
                $packageName = $packageName.Substring(0, $lastAtIndex)
            }
        }
        
        if (Uninstall-Package -PackageName $packageName) {
            $uninstalledPackages += $packageName
        }
    }
    
    if ($uninstalledPackages.Count -gt 0) {
        Write-Host "Uninstalled: $($uninstalledPackages -join ', ')" -ForegroundColor Green
    } else {
        Write-Host "No packages were uninstalled" -ForegroundColor Yellow
    }
    
    exit 0
}

# Mode 2 & 3: Install specific packages or from package.json
Write-Host "=== CONVERTING PACKAGE.JSON TO SCOPED FORMAT ===" -ForegroundColor Magenta
Backup-PackageJson | Out-Null
Convert-ToScopedFormat | Out-Null

$packagesToInstall = @()
$frontendPackagesToInstall = @()
$packagesToPublish = @()

if ($args.Count -gt 0) {
    # Mode 2: Install specific packages
    Write-Host "=== INSTALL MODE ===" -ForegroundColor Magenta
    
    foreach ($arg in $args) {
        $packageName = $arg
        $versionSpec = "latest"

        if ($packageName.StartsWith("@")) {
            $firstAt = $packageName.IndexOf('@')
            $lastAtIndex = $packageName.LastIndexOf('@')
            if ($lastAtIndex -gt $firstAt) {
                $versionSpec = $packageName.Substring($lastAtIndex + 1)
                $packageName = $packageName.Substring(0, $lastAtIndex)
            }
        } else {
            $lastAtIndex = $packageName.LastIndexOf('@')
            if ($lastAtIndex -gt 0) {
                $versionSpec = $packageName.Substring($lastAtIndex + 1)
                $packageName = $packageName.Substring(0, $lastAtIndex)
            }
        }

        $resolvedVersion = Get-PackageVersion -PackageName $packageName -VersionSpec $versionSpec
        $packagesToInstall += @{
            Name = $packageName
            Version = $resolvedVersion
        }
        # Parse the backup
        $pkgObj = $Global:packageJsonBackup | ConvertFrom-Json
        # Add the package in dependencies for installation
        $pkgObj.dependencies | Add-Member -NotePropertyName $packageName -NotePropertyValue $resolvedVersion -Force
        # Update the backup
        $Global:packageJsonBackup = ConvertTo-Json $pkgObj -Depth 10 | Format-Json
    }
} else {
    # Mode 3: Process package.json
    Write-Host "=== PACKAGE.JSON MODE ===" -ForegroundColor Magenta
    
    $packageJsonPath = Join-Path (Get-Location) "package.json"
    if (-not (Test-Path $packageJsonPath)) {
        Write-Host "Error: package.json not found" -ForegroundColor Red
        exit 1
    }
    
    $packageJson = Get-Content $packageJsonPath -Raw | ConvertFrom-Json
    
    if ($packageJson.dependencies) { 
        $packageJson.dependencies.PSObject.Properties | ForEach-Object { 
            $version = ($_.Value -split '@')[-1]
            $packagesToInstall += @{ Name = $_.Name; Version = $version }
        } 
    }
    
    if ($packageJson.devDependencies) { 
        $packageJson.devDependencies.PSObject.Properties | ForEach-Object { 
            $version = ($_.Value -split '@')[-1]
            $packagesToInstall += @{ Name = $_.Name; Version = $version }
        } 
    }
    
    if ($packageJson.frontendDependencies -and $packageJson.frontendDependencies.packages) { 
        $packageJson.frontendDependencies.packages.PSObject.Properties | ForEach-Object { 
            $version = ($_.Value.version -split '@')[-1]
            $packagesToInstall += @{ Name = $_.Name; Version = $version }
            $frontendPackagesToInstall += @{ Name = $_.Name; Version = $version }
        } 
    }
    
    if ($packagesToInstall.Count -eq 0) {
        Write-Host "No dependencies found in package.json" -ForegroundColor Green
        exit 0
    }
}

Write-Host "Packages to process: $($packagesToInstall.Count)" -ForegroundColor Cyan

Write-Host "=== FAST INSTALL PACKAGES ===" -ForegroundColor Magenta
Write-Host "Attempting to install all packages from GitHub registry..." -ForegroundColor Cyan

try {
    # Single npm install command for all packages
    $installCmd = "npm install --registry=https://npm.pkg.github.com --no-audit 2>&1"
    $output = & cmd /c $installCmd
    $exitCode = $LASTEXITCODE

    Write-Host "Output from npm install: $output" -ForegroundColor Gray

    if ($frontendPackagesToInstall.Count -gt 0) {
        Write-Host "Installing frontend dependencies separately..." -ForegroundColor Cyan
        $packages = ($frontendPackagesToInstall |
            ForEach-Object { "$($_.Name)@$($_.Version)" }) -join " "

        # Build final npm command
        $npmCommand = "npm install $packages --registry=https://npm.pkg.github.com --no-save --no-audit 2>&1"
        # Run the command
        Invoke-Expression $npmCommand | Out-Null
    }
    else {
        Write-Host "No frontend dependencies to install"
    }


    if ($exitCode -eq 0) {
        Write-Host "All packages installed successfully from cache!" -ForegroundColor Green
        Write-Host "=== CONVERTING PACKAGE.JSON TO ALIAS FORMAT ===" -ForegroundColor Magenta
        Restore-PackageJsonBackup | Out-Null
        Convert-PackageSymlinks | Out-Null
        exit 0
    } else {
        Write-Host "Some packages not available in cache, parsing output... $output" -ForegroundColor Yellow
        
        # Parse npm error output to identify missing packages
        # npm typically outputs: "404 Not Found - GET https://npm.pkg.github.com/@owner/package"
        # or "ERR! 404 '@owner/package@version' is not in this registry"
        
        $outputText = $output -join "`n"
        
        # Extract package names from 404 errors
        $notFoundPackages = @()
        $pattern404 = "404.*?@$($GithubUsername.ToLower())/([^\s@']+)"
        $matches404 = [regex]::Matches($outputText, $pattern404, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        
        foreach ($match in $matches404) {
            $pkgName = $match.Groups[1].Value
            $notFoundPackages += $pkgName
        }
        
        # Remove duplicates
        $notFoundPackages = $notFoundPackages | Select-Object -Unique
        
        if ($notFoundPackages.Count -gt 0) {
            Write-Host "Packages not found in cache:" -ForegroundColor Yellow
            foreach ($pkgName in $notFoundPackages) {
                # Find the package in our list
                $pkg = $packagesToInstall | Where-Object { $_.Name -eq $pkgName }
                if ($pkg) {
                    $packagesToPublish += $pkg
                    Write-Host "  $($pkg.Name)@$($pkg.Version) - needs publishing" -ForegroundColor Yellow
                }
            }
        }
        
        # If we couldn't parse any failures but npm failed, fallback to checking all
        if ($packagesToPublish.Count -eq 0) {
            Write-Warning "Could not parse npm output, assuming all packages need publishing"
            $packagesToPublish = $packagesToInstall
        }
    }
} catch {
    Write-Warning "Fast install failed: $($_.Exception.Message)"
    # Fallback: assume all packages need publishing
    $packagesToPublish = $packagesToInstall
}

if ($packagesToPublish.Count -eq 0) {
    Write-Host "All packages are already available!" -ForegroundColor Green
    Restore-PackageJsonBackup | Out-Null
    exit 0
} else {
    Write-Host "$($packagesToPublish.Count) packages need to be published first." -ForegroundColor Yellow
}

Write-Host "=== PUBLISHING PACKAGES ===" -ForegroundColor Magenta
Write-Host "Note: Each workflow will automatically handle ALL transitive dependencies"
$stats = @{
    Total = $packagesToPublish.Count
    Success = 0
    Failed = 0
}

$failedPackages = @()

# Process each top-level package (workflow handles dependencies)
foreach ($pkg in $packagesToPublish) {
    $success = Invoke-PackagePublishWorkflow -PackageName $pkg.Name -Version $pkg.Version
    if ($success) {
        $stats.Success++
        Write-Host "Successfully published $($pkg.Name)@$($pkg.Version) and all dependencies" -ForegroundColor Green
    } else {
        $stats.Failed++
        $failedPackages += "$($pkg.Name)@$($pkg.Version)"
        Write-Warning "Failed to publish $($pkg.Name)@$($pkg.Version)"
    }
}

Write-Host "=== PUBLISHING COMPLETE ===" -ForegroundColor Magenta
Write-Host "Total packages: $($stats.Total)" -ForegroundColor Cyan
Write-Host "Successful: $($stats.Success)" -ForegroundColor Green
Write-Host "Failed: $($stats.Failed)" -ForegroundColor Red

if ($failedPackages.Count -gt 0) {
    Write-Host "Failed packages:" -ForegroundColor Red
    $failedPackages | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
}

# Install all packages
Write-Host "=== INSTALLING PACKAGES ===" -ForegroundColor Magenta
Write-Host "Waiting 10 seconds for package availability..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

$installStats = @{
    Success = 0
    Failed = 0
}

foreach ($pkg in $packagesToPublish) {
    if ($failedPackages -contains "$($pkg.Name)@$($pkg.Version)") {
        $installStats.Failed++
        continue
    }
    $res = Install-FromGitHubRegistry -PackageName $pkg.Name -Version $pkg.Version
    if ($res) {
        $installStats.Success++
    } else {
        $installStats.Failed++
    }
}

Write-Host "=== INSTALLATION SUMMARY ===" -ForegroundColor Magenta
Write-Host "Packages installed: $($installStats.Success)/$($packagesToInstall.Count)" -ForegroundColor Green

if ($stats.Failed -gt 0 -or $installStats.Failed -gt 0) {
    Write-Host "Some packages failed. Check the workflow logs at:" -ForegroundColor Yellow
    Write-Host "  https://github.com/$GithubUsername/$GithubRepo/actions" -ForegroundColor Cyan
} else {
    Write-Host "All packages processed and installed successfully!" -ForegroundColor Green
    Write-Host "=== CONVERTING PACKAGE.JSON TO ALIAS FORMAT ===" -ForegroundColor Magenta
    Restore-PackageJsonBackup | Out-Null
    Convert-PackageSymlinks | Out-Null 
}

#endregion
