

param(
    [switch]$Uninstall,
    [switch]$Help
)

function Show-Help {
    Write-Host "GitHub Package Cache Manager" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "  Install packages:"
    Write-Host "    .\im-install.ps1 <package1> <package2@version> ..."
    Write-Host "    .\im-install.ps1                                   # Process all dependencies in package.json"
    Write-Host ""
    Write-Host "  Uninstall packages:"
    Write-Host "    .\im-install.ps1 -Uninstall <package1> <package2> ..."
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  .\im-install.ps1 axios lodash"
    Write-Host "  .\im-install.ps1 express@4.18.0"
    Write-Host "  .\im-install.ps1 -Uninstall axios lodash"
    Write-Host ""
    Write-Host "OPTIONS:" -ForegroundColor Yellow
    Write-Host "  -Uninstall    Uninstall the specified packages"
    Write-Host "  -Help         Show this help message"
    Write-Host ""
}

function Load-DotEnv {
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

# Load environment variables from .env file if it exists
Load-DotEnv -Path "./.env"

# --- CONFIGURATION ---
$GithubUsername = [Environment]::GetEnvironmentVariable("GITHUB_USER_NAME")
$GithubRepo = [Environment]::GetEnvironmentVariable("GITHUB_REPOSITORY_NAME")

# --- SCRIPT SETUP ---
$GithubApiUrl = "https://api.github.com/repos/$($GithubUsername)/$($GithubRepo)/actions/workflows/publish-to-ghp.yml/dispatches"
$GithubToken = [Environment]::GetEnvironmentVariable("GITHUB_PERSONAL_ACCESS_TOKEN")

# At the top of your script or in the function, define allowed licenses
$allowedLicenses = @(
    'MIT',
    'ISC',
    'Apache-2.0',
    'BSD-2-Clause',
    'BSD-3-Clause',
    'CC-BY-3.0',
    'CC0-1.0'
    # Add other licenses you approve
)

if ([string]::IsNullOrEmpty($GithubToken)) {
    Write-Host "Error: GITHUB_TOKEN environment variable not set." -ForegroundColor Red
    Write-Host "Please create a Personal Access Token and set it as an environment variable."
    exit 1
}

$headers = @{
    "Authorization" = "token $GithubToken"
    "Accept" = "application/vnd.github.v3+json"
}

# Helper: Update package.json to ensure unscoped dependency is present with exact version
function Update-PackageJsonDependency {
    param(
        [string]$PackageName,
        [string]$Version
    )
    $pkgPath = Join-Path (Get-Location) 'package.json'
    if (-not (Test-Path $pkgPath)) { return }
    try {
        $jsonRaw = Get-Content $pkgPath -Raw
        $pkgObj = $jsonRaw | ConvertFrom-Json
        if (-not $pkgObj.dependencies) { $pkgObj | Add-Member -NotePropertyName dependencies -NotePropertyValue (@{}) }
        # Remove any scoped variant referencing this base name for our user scope
        $scopePrefix = "@$GithubUsername/"
        $toRemove = @()
        foreach ($prop in $pkgObj.dependencies.PSObject.Properties) {
            if ($prop.Name -eq "$scopePrefix$PackageName") { $toRemove += $prop.Name }
        }
        foreach ($r in $toRemove) { $pkgObj.dependencies.PSObject.Properties.Remove($r) }
        $pkgObj.dependencies.PSObject.Properties.Remove($PackageName) | Out-Null 2>$null
        $pkgObj.dependencies | Add-Member -NotePropertyName $PackageName -NotePropertyValue $Version
        ConvertTo-Json $pkgObj -Depth 10 | Format-Json | Set-Content $pkgPath -Encoding UTF8

        Write-Host "package.json updated: $PackageName@$Version (unscoped)" -ForegroundColor DarkGreen
    } catch {
        Write-Warning "Failed to update package.json: $($_.Exception.Message)"
    }
}

# Helper: Remove dependency from package.json
function Remove-PackageJsonDependency {
    param(
        [string]$PackageName
    )
    $pkgPath = Join-Path (Get-Location) 'package.json'
    if (-not (Test-Path $pkgPath)) { 
        Write-Warning "package.json not found, skipping package.json cleanup"
        return 
    }
    try {
        $jsonRaw = Get-Content $pkgPath -Raw
        $pkgObj = $jsonRaw | ConvertFrom-Json
        
        $removed = $false
        
        # Remove from dependencies
        if ($pkgObj.dependencies -and $pkgObj.dependencies.PSObject.Properties[$PackageName]) {
            $pkgObj.dependencies.PSObject.Properties.Remove($PackageName)
            $removed = $true
        }
        
        # Remove from devDependencies
        if ($pkgObj.devDependencies -and $pkgObj.devDependencies.PSObject.Properties[$PackageName]) {
            $pkgObj.devDependencies.PSObject.Properties.Remove($PackageName)
            $removed = $true
        }
        
        # Remove scoped variant
        $scopePrefix = "@$GithubUsername/"
        $scopedName = "$scopePrefix$PackageName"
        if ($pkgObj.dependencies -and $pkgObj.dependencies.PSObject.Properties[$scopedName]) {
            $pkgObj.dependencies.PSObject.Properties.Remove($scopedName)
            $removed = $true
        }
        if ($pkgObj.devDependencies -and $pkgObj.devDependencies.PSObject.Properties[$scopedName]) {
            $pkgObj.devDependencies.PSObject.Properties.Remove($scopedName)
            $removed = $true
        }
        
        if ($removed) {
            ConvertTo-Json $pkgObj -Depth 10 | Format-Json | Set-Content $pkgPath -Encoding UTF8
            Write-Host "Removed $PackageName from package.json" -ForegroundColor DarkGreen
        } else {
            Write-Host "$PackageName was not found in package.json" -ForegroundColor Gray
        }
    } catch {
        Write-Warning "Failed to update package.json: $($_.Exception.Message)"
    }
}

# Helper: Create an unscoped alias (symlink or copy) so require('pkg') works when only @user/pkg is installed
function Ensure-UnscopedAlias {
    param(
        [string]$PackageName
    )
    $scopedDir = Join-Path (Join-Path (Get-Location) 'node_modules') "@$GithubUsername"
    $scopedPath = Join-Path $scopedDir $PackageName
    $unscopedPath = Join-Path (Join-Path (Get-Location) 'node_modules') $PackageName
    if (-not (Test-Path $scopedPath)) { return }
    if (Test-Path $unscopedPath) { return }
    try {
        New-Item -ItemType SymbolicLink -Path $unscopedPath -Target $scopedPath -ErrorAction Stop | Out-Null
        Write-Host "Created symlink alias: $unscopedPath -> $scopedPath" -ForegroundColor Gray
    } catch {
        try {
            Copy-Item $scopedPath $unscopedPath -Recurse -Force
            Write-Host "Copied directory as alias: $unscopedPath" -ForegroundColor Gray
        } catch {
            Write-Warning "Could not create alias: $($_.Exception.Message)"
        }
    }
}

# Helper: Remove unscoped alias when uninstalling
function Remove-UnscopedAlias {
    param(
        [string]$PackageName
    )
    $unscopedPath = Join-Path (Join-Path (Get-Location) 'node_modules') $PackageName
    if (Test-Path $unscopedPath) {
        try {
            # Check if it's a symlink or junction
            $item = Get-Item $unscopedPath -Force
            if ($item.LinkType -eq "SymbolicLink" -or $item.LinkType -eq "Junction") {
                Remove-Item $unscopedPath -Force
                Write-Host "Removed symlink alias: $unscopedPath" -ForegroundColor Gray
            } else {
                # It's a copied directory, remove it
                Remove-Item $unscopedPath -Recurse -Force
                Write-Host "Removed copied alias directory: $unscopedPath" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "Could not remove alias: $($_.Exception.Message)"
        }
    }
}

function Get-PackageVersion {
    param(
        [string]$PackageName,
        [string]$VersionSpec = "latest"
    )
    
    try {
        # Always query the public registry to resolve the specifier to a concrete version.
        # This handles 'latest', '1.8.0', '^1.8.0', etc., consistently.
        $packageWithSpec = "$($PackageName)@$($VersionSpec)"
        Write-Host "Resolving version for '$($packageWithSpec)' from public npm registry..." -ForegroundColor Gray

        $registryUrl = $PackageName | Select-String -Pattern $GithubUsername -Quiet
        if ($registryUrl) {
            $registryUrl = "https://npm.pkg.github.com/$($GithubUsername)"
        } else {
            $registryUrl = "https://registry.npmjs.org/"
        }
        $versionOutput = npm view $packageWithSpec version --registry=$registryUrl 2>$null | Select-Object -Last 1

        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrEmpty($versionOutput)) {
            # The command can sometimes return the version in quotes, so we trim everything.
            $resolved = $versionOutput.Trim().Trim("'").Trim('"')
            Write-Host "Resolved '$($packageWithSpec)' to concrete version: $($resolved)" -ForegroundColor DarkGray
            return $resolved
        } else {
            # If resolution fails on the public registry, the package/version likely doesn't exist at all.
            Write-Host "Error: Could not resolve version specifier '$($VersionSpec)' for package '$($PackageName)' from npmjs.org." -ForegroundColor Red
            return $VersionSpec # Fallback to the original spec, though it's likely to fail later.
        }
    }
    catch {
        Write-Host "Error during version resolution for $PackageName : $($_.Exception.Message)" -ForegroundColor Red
        return $VersionSpec
    }
}

# Suggest alternative non-deprecated versions when a requested version is deprecated or unavailable
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
        Write-Host "Try: npm run im-install -- $PackageName@$($alts[0])" -ForegroundColor DarkYellow
    } else {
        Write-Host "No alternative version suggestions available for $PackageName right now." -ForegroundColor Yellow
    }
}

function Check-WorkflowStatus {
    param(
        [string]$PackageName
    )
    
    $workflowRunsUrl = "https://api.github.com/repos/$($GithubUsername)/$($GithubRepo)/actions/runs"
    
    try {
        $runs = Invoke-RestMethod -Uri $workflowRunsUrl -Headers $headers
        $recentRuns = $runs.workflow_runs | Where-Object { 
            $_.name -eq "Publish to GitHub Packages with Caching" -and 
            $_.created_at -gt (Get-Date).AddMinutes(-10) 
        } | Select-Object -First 3
        
        if ($recentRuns.Count -gt 0) {
            $latestRun = $recentRuns[0]
            Write-Host "Latest workflow status: $($latestRun.status) - $($latestRun.conclusion)" -ForegroundColor Cyan
            if ($latestRun.status -eq "in_progress") {
                Write-Host "Workflow is still running. You can monitor it at: $($latestRun.html_url)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "Could not check workflow status (this is not critical)" -ForegroundColor Yellow
    }
}

function Wait-For-Workflow {
    param(
        [string]$WorkflowFileName,
        [string]$PackageName
    )

    Write-Host "Waiting for caching workflow for '$($PackageName)' to complete..." -ForegroundColor Yellow
    
    # Give GitHub a moment to create the workflow run
    Start-Sleep -Seconds 3

    try {
        # Find the specific workflow run that was just triggered for our package
        $runsUrl = "https://api.github.com/repos/$($GithubUsername)/$($GithubRepo)/actions/workflows/$($WorkflowFileName)/runs?event=workflow_dispatch"
        $workflowRuns = Invoke-RestMethod -Uri $runsUrl -Headers $headers
        $latestRun = $workflowRuns.workflow_runs | Sort-Object -Property created_at -Descending | Select-Object -First 1

        if (-not $latestRun) {
            Write-Host "Error: Could not find the triggered workflow run." -ForegroundColor Red
            return $false
        }

        Write-Host "Monitoring workflow run: $($latestRun.html_url)" -ForegroundColor Cyan
        
        $runId = $latestRun.id
        $status = $latestRun.status
        $conclusion = $latestRun.conclusion
        $timeout = (Get-Date).AddMinutes(1) # 1-minute timeout

        # Poll the API until the workflow is 'completed' or we time out
        while ($status -ne "completed" -and (Get-Date) -lt $timeout) {
            Write-Host "Current status: $($status)... waiting..." -ForegroundColor Gray
            Start-Sleep -Seconds 3
            
            $runUrl = "https://api.github.com/repos/$($GithubUsername)/$($GithubRepo)/actions/runs/$($runId)"
            $runDetails = Invoke-RestMethod -Uri $runUrl -Headers $headers
            $status = $runDetails.status
            $conclusion = $runDetails.conclusion
        }

        if ($status -ne "completed") {
            Write-Host "Timed out waiting for workflow to complete." -ForegroundColor Red
            return $false
        }

        if ($conclusion -eq 'success') {
            Write-Host "Workflow finished with conclusion: '$($conclusion)'" -ForegroundColor Green
        } else {
            Write-Host "Workflow finished with conclusion: '$($conclusion)'" -ForegroundColor Red
        }
        Start-Sleep -Seconds 3
        return ($conclusion -eq "success")
    }
    catch {
        Write-Host "An error occurred while monitoring the workflow: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Parse-VersionFromPackageJson {
    param(
        [string]$VersionSpec
    )
    
    # Remove common version prefixes like ^, ~, >=, etc.
    $cleanVersion = $VersionSpec -replace '^[\^~>=<]+', ''
    
    # If it's a complex version range, default to latest
    if ($cleanVersion -match '[*x]' -or $cleanVersion -match '\|\|' -or $cleanVersion -match ' - ') {
        return "latest"
    }
    
    return $cleanVersion
}

function Check-NodeCompatibility {
    param (
        [string]$PackageName,
        [string]$PackageVersion = "latest"
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
        Write-Host "Current Node.js version: $currentNodeVersion" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Could not parse Node.js version: $currentNodeVersionRaw"
        return $true
    }

    try {
        # Get the engines.node field - handle both string and object responses
        $enginesNodeRaw = npm view "$PackageName@$PackageVersion" engines.node --json --registry=https://registry.npmjs.org/ 2>$null
        
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
    param(
        [System.Version]$CurrentVersion,
        [string]$Constraint
    )
    
    # Handle range constraints like ">=14.0.0 <17.0.0" or ">=16"
    if ($Constraint -match '\s+') {
        $constraints = $Constraint -split '\s+'
        foreach ($c in $constraints) {
            $c = $c.Trim()
            if (-not [string]::IsNullOrEmpty($c) -and -not (Test-SingleVersionConstraint -CurrentVersion $CurrentVersion -Constraint $c)) {
                return $false
            }
        }
        return $true
    }
    else {
        return Test-SingleVersionConstraint -CurrentVersion $CurrentVersion -Constraint $Constraint
    }
}

function Test-SingleVersionConstraint {
    param(
        [System.Version]$CurrentVersion,
        [string]$Constraint
    )
    
    # Parse version constraint patterns
    if ($Constraint -match '^(>=|<=|>|<|=|~|\^)?\s*([0-9]+(?:\.[0-9]+)?(?:\.[0-9]+)?)?(.*)$') {
        $operator = if ($matches[1]) { $matches[1] } else { "=" }
        $versionStr = $matches[2]
        # If versionStr is empty, skip parsing and return true
        if (-not $versionStr) {
            # No version specified after operator, treat as unconstrained
            return $true
        }
        # Handle incomplete version numbers (e.g., "14" -> "14.0.0")
        $versionParts = $versionStr -split '\.'
        while ($versionParts.Length -lt 3) {
            $versionParts += "0"
        }
        $normalizedVersion = $versionParts[0..2] -join '.'
        try {
            $targetVer = [System.Version]::Parse($normalizedVersion)
        }
        catch {
            Write-Warning "Could not parse version constraint: $Constraint"
            return $true
        }
        switch ($operator) {
            ">=" { 
                return $CurrentVersion -ge $targetVer
            }
            "<=" { 
                return $CurrentVersion -le $targetVer
            }
            ">" { 
                return $CurrentVersion -gt $targetVer
            }
            "<" { 
                return $CurrentVersion -lt $targetVer
            }
            "=" { 
                return $CurrentVersion -eq $targetVer
            }
            "~" {
                if ($versionParts.Length -ge 2) {
                    $nextMinor = [System.Version]::new($targetVer.Major, $targetVer.Minor + 1, 0)
                    return ($CurrentVersion -ge $targetVer) -and ($CurrentVersion -lt $nextMinor)
                }
                else {
                    $nextMajor = [System.Version]::new($targetVer.Major + 1, 0, 0)
                    return ($CurrentVersion -ge $targetVer) -and ($CurrentVersion -lt $nextMajor)
                }
            }
            "^" {
                if ($targetVer.Major -gt 0) {
                    $nextMajor = [System.Version]::new($targetVer.Major + 1, 0, 0)
                    return ($CurrentVersion -ge $targetVer) -and ($CurrentVersion -lt $nextMajor)
                }
                elseif ($targetVer.Minor -gt 0) {
                    $nextMinor = [System.Version]::new($targetVer.Major, $targetVer.Minor + 1, 0)
                    return ($CurrentVersion -ge $targetVer) -and ($CurrentVersion -lt $nextMinor)
                }
                else {
                    $nextPatch = [System.Version]::new($targetVer.Major, $targetVer.Minor, $targetVer.Build + 1)
                    return ($CurrentVersion -ge $targetVer) -and ($CurrentVersion -lt $nextPatch)
                }
            }
            default {
                Write-Warning "Unrecognized version operator: $operator"
                return $true
            }
        }
    }
    else {
        Write-Warning "Could not parse version constraint: $Constraint"
        return $true
    }
}

function Process-Package {
    param(
        [string]$PackageName,
    [string]$VersionSpec = "latest",
    [switch]$Recurse,
    [switch]$NoLicenseRecursion
    )

    if (-not $Global:ProcessedPackages) { $Global:ProcessedPackages = @{} }

    Write-Host "`n--- Processing package: $($PackageName)@$($VersionSpec) ---" -ForegroundColor Cyan

    # Short-circuit if we've already processed this exact spec (pre-version resolution) to avoid redundant network calls
    $preKey = "PRE::$PackageName@$VersionSpec"
    if ($Global:ProcessedPackages.ContainsKey($preKey)) {
        Write-Host "Already handled (spec): $PackageName@$VersionSpec" -ForegroundColor DarkGray
        return $true
    }
    
    # Resolve concrete version FIRST so later checks reference the right version
    $ConcreteVersion = Get-PackageVersion -PackageName $PackageName -VersionSpec $VersionSpec
    if (-not $ConcreteVersion) {
        Write-Host "Could not resolve package version, cannot proceed." -ForegroundColor Red
        return $false
    }

    # Short-circuit if we've already processed this resolved version
    $resolvedKey = "RES::$PackageName@$ConcreteVersion"
    if ($Global:ProcessedPackages.ContainsKey($resolvedKey)) {
        Write-Host "Already handled (resolved): $PackageName@$ConcreteVersion" -ForegroundColor DarkGray
        return $true
    }

    $Global:ProcessedPackages[$preKey] = $true
    $Global:ProcessedPackages[$resolvedKey] = $true

    $deprecationMessage = npm view "${PackageName}@${ConcreteVersion}" deprecated --registry=https://registry.npmjs.org/
    if (-not [string]::IsNullOrEmpty($deprecationMessage)) {
        Write-Warning "This package version is deprecated. Message: $deprecationMessage"
        Write-Host "Consider using a different version or package." -ForegroundColor Yellow
        Write-VersionSuggestions -PackageName $PackageName -ProblemVersion $ConcreteVersion
    }

    # Step 1: Check if the package is already in the GitHub Packages cache
    $ScopedPackageNameWithVersion = "@$GithubUsername/$PackageName@$ConcreteVersion"
    $versionExists = (npm view $ScopedPackageNameWithVersion versions --silent) | Select-String -Pattern $ConcreteVersion -Quiet

    if ($versionExists) {
        Write-Host "Package found in GitHub Packages cache." -ForegroundColor Green
        # Optionally: install or return true here, skipping license check
        return $true
    }

    # Only perform license check if not already cached
    $packageLicense = npm view "${PackageName}@${ConcreteVersion}" license --registry=https://registry.npmjs.org/
    Write-Host "[LICENSE] Top-level license for $PackageName@$ConcreteVersion : $packageLicense" -ForegroundColor Cyan
    if (-not ($allowedLicenses -contains $packageLicense)) {
        Write-Error "LICENSE VIOLATION: The license '$($packageLicense)' for $($PackageName)@$($ConcreteVersion) is not on the approved list. Halting installation."
        return $false
    }

    function Check-DependencyLicenses {
        param(
            [string]$RootPackage,
            [string]$RootVersion
        )
        $checked = @{}
        function CheckRecursively {
            param(
                [string]$Pkg,
                [string]$Ver
            )
            $key = "$Pkg@$Ver"
            if ($checked.ContainsKey($key)) { return $true }
            $checked[$key] = $true
            Write-Host "Checking license for $Pkg @ $Ver ..." -ForegroundColor Cyan
            $depLicense = npm view "$Pkg@$Ver" license --registry=https://registry.npmjs.org/
            Write-Host "  License for $Pkg @ $Ver : $depLicense" -ForegroundColor Cyan
            if (-not ($allowedLicenses -contains $depLicense)) {
                Write-Error "LICENSE VIOLATION: The license '$($depLicense)' for dependency $Pkg@$Ver is not on the approved list. Halting installation."
                return $false
            }
            $deps = npm view "$Pkg@$Ver" dependencies --json --registry=https://registry.npmjs.org/
            if (-not [string]::IsNullOrEmpty($deps) -and $deps -ne 'undefined') {
                try {
                    $depObj = $deps | ConvertFrom-Json
                    # Handle both hashtable/object and array cases robustly
                    if ($depObj -eq $null) {
                        Write-Host "  No subdependencies for $Pkg@$Ver (null)" -ForegroundColor Gray
                    } elseif ($depObj.PSObject.Properties.Count -gt 0) {
                        $depKeys = $depObj.PSObject.Properties.Name
                        Write-Host "  Found $($depKeys.Count) subdependencies for $Pkg@$Ver : $($depKeys -join ', ')" -ForegroundColor Yellow
                        foreach ($depName in $depKeys) {
                            $depVerSpec = $depObj.$depName
                            Write-Host "    Recursing into $depName@$depVerSpec (dependency of $Pkg@$Ver)" -ForegroundColor DarkYellow
                            $depVer = Get-PackageVersion -PackageName $depName -VersionSpec $depVerSpec
                            if (-not (CheckRecursively -Pkg $depName -Ver $depVer)) {
                                return $false
                            }
                        }
                    } elseif ($depObj -is [System.Collections.IEnumerable]) {
                        $depArr = @($depObj)
                        if ($depArr.Count -eq 0) {
                            Write-Host "  No subdependencies for $Pkg@$Ver (empty array)" -ForegroundColor Gray
                        } else {
                            Write-Host "  Found $($depArr.Count) subdependencies for $Pkg@$Ver (array)" -ForegroundColor Yellow
                            foreach ($dep in $depArr) {
                                if ($dep.PSObject.Properties["name"] -and $dep.PSObject.Properties["version"]) {
                                    $depName = $dep.name
                                    $depVerSpec = $dep.version
                                    Write-Host "    Recursing into $depName@$depVerSpec (dependency of $Pkg@$Ver)" -ForegroundColor DarkYellow
                                    $depVer = Get-PackageVersion -PackageName $depName -VersionSpec $depVerSpec
                                    if (-not (CheckRecursively -Pkg $depName -Ver $depVer)) {
                                        return $false
                                    }
                                }
                            }
                        }
                    } else {
                        Write-Host "  Unrecognized dependency object type for $Pkg@$Ver" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "  Failed to parse dependencies for $Pkg@$Ver : $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Write-Host "  No subdependencies for $Pkg@$Ver (empty or undefined)" -ForegroundColor Gray
            }
            return $true
        }
        Write-Host "Starting license check for $RootPackage@$RootVersion ..." -ForegroundColor Yellow
        $result = CheckRecursively -Pkg $RootPackage -Ver $RootVersion
        Write-Host "Finished license check for $RootPackage@$RootVersion" -ForegroundColor Yellow
        return $result
    }

    Write-Host "[LICENSE] Checking all dependencies for $PackageName@$ConcreteVersion ..." -ForegroundColor Magenta
    if (-not (Check-DependencyLicenses -RootPackage $PackageName -RootVersion $ConcreteVersion)) {
        Write-Error "LICENSE VIOLATION: One or more dependencies of $PackageName@$ConcreteVersion have unapproved licenses. Halting installation."
        return $false
    }

    # Check Node.js compatibility before proceeding
    $isCompatible = Check-NodeCompatibility -PackageName $PackageName -PackageVersion $ConcreteVersion
    if (-not $isCompatible) {
        Write-Host "Proceeding despite compatibility warning..." -ForegroundColor Yellow
    }

    if ($PackageName.StartsWith("@")) {
        Write-Host "Skipping caching of third-party scoped package (rule: skip scoped): $($PackageName)" -ForegroundColor DarkGray
        return $true
    }

    $ScopedPackageNameWithVersion = "@$($GithubUsername)/$($PackageName)"
    Write-Host "Checking for exact package '$($ScopedPackageNameWithVersion)/$($ConcreteVersion)' in your GitHub Packages cache..."
    
    # Step 2: Perform a reliable check for that *exact* concrete version in your private cache.
    # This command will only succeed if the specific version exists.
    # npm view $ScopedPackageNameWithVersion versions --silent > $null 2>&1

    # Run the command and check the result
    $versionExists = (npm view $ScopedPackageNameWithVersion versions --silent) | Select-String -Pattern $ConcreteVersion -Quiet

    if ($versionExists) {
        # The package and exact version exist in the cache. We can install it.
        Write-Host "Package found in GitHub Packages cache." -ForegroundColor Green

        # Check if the package still exists publicly
        npm view "$($PackageName)@$($ConcreteVersion)" version --registry=https://registry.npmjs.org/ > $null 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "The original package '$($PackageName)@$($ConcreteVersion)' no longer exists on the public NPM registry. You are installing from your private cache." -ForegroundColor Red
        }
        $result = $true
        return $result
    }

    # Step 3: If the check failed, the package is not in the cache. Trigger the workflow.
    Write-Host "Package not found. Triggering caching workflow for '$($PackageName)@$($VersionSpec)'..." -ForegroundColor Yellow
    try {
        $body = @{
            ref = "main" # Or your default branch
            inputs = @{
                package_name = $PackageName
                # Trigger the workflow with the original version specifier
                package_version = $VersionSpec
            }
        } | ConvertTo-Json

        Invoke-RestMethod -Uri $GithubApiUrl -Method POST -Headers $headers -Body $body -ContentType "application/json"
        
        # Instead of a simple sleep, we now wait for the workflow to finish
        $workflowSucceeded = Wait-For-Workflow -WorkflowFileName "publish-to-ghp.yml" -PackageName $PackageName
        
        if ($workflowSucceeded) {
            Write-Host "Package should now be cached. The script will attempt to use it." -ForegroundColor Green
            $result = $true
        } else {
            Write-Host "Workflow failed or timed out. Please check the Actions tab in your GitHub repository." -ForegroundColor Red
            $result = $false
        }
    }
    catch {
        Write-Host "Error starting GitHub workflow for $($PackageName)" -ForegroundColor Red
        Write-Host "Check your PAT permissions and repository configuration." -ForegroundColor Red
        Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
        $result = $false
    }
    
    # Optionally recurse into transitive dependencies for caching
    if ($Recurse -and $result) {
        try {
            $depsJson = npm view "$PackageName@$ConcreteVersion" dependencies --json --registry=https://registry.npmjs.org/ 2>$null
            if (-not [string]::IsNullOrEmpty($depsJson) -and $depsJson -ne 'undefined') {
                $depObj = $null
                try { $depObj = $depsJson | ConvertFrom-Json } catch { $depObj = $null }
                if ($depObj -ne $null) {
                    Write-Host " Recursing into transitive dependencies of $PackageName@$ConcreteVersion (count: $($depObj.Keys.Count))" -ForegroundColor DarkCyan
                    foreach ($depName in $depObj.Keys) {
                        $depSpec = $depObj[$depName]
                        # Avoid runaway recursion for large graphs; still leverage hash guard
                        Process-Package -PackageName $depName -VersionSpec $depSpec -Recurse -NoLicenseRecursion | Out-Null
                    }
                }
            }
        } catch {
            Write-Host "Warning: Failed to enumerate transitive dependencies for $PackageName@$ConcreteVersion : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    return $result
}

function Uninstall-Package {
    param(
        [string]$PackageName
    )

    Write-Host "`n--- Uninstalling package: $PackageName ---" -ForegroundColor Cyan

    $uninstalled = $false
    $nodeModulesPath = Join-Path (Get-Location) 'node_modules'
    
    # Try to uninstall scoped version first
    $scopedName = "@$GithubUsername/$PackageName"
    $scopedPath = Join-Path $nodeModulesPath "@$GithubUsername"
    $scopedPackagePath = Join-Path $scopedPath $PackageName
    
    if (Test-Path $scopedPackagePath) {
        try {
            Write-Host "Removing scoped package: $scopedName" -ForegroundColor Yellow
            npm uninstall $scopedName --no-save 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Successfully removed scoped package: $scopedName" -ForegroundColor Green
            } else {
                # Manual removal if npm uninstall fails
                Remove-Item $scopedPackagePath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Manually removed scoped package directory: $scopedPackagePath" -ForegroundColor Green
            }
            $uninstalled = $true
        } catch {
            Write-Warning "Failed to remove scoped package: $($_.Exception.Message)"
        }
    }
    
    # Try to uninstall unscoped version
    $unscopedPath = Join-Path $nodeModulesPath $PackageName
    if (Test-Path $unscopedPath) {
        try {
            Write-Host "Removing unscoped package: $PackageName" -ForegroundColor Yellow
            npm uninstall $PackageName --no-save 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Successfully removed unscoped package: $PackageName" -ForegroundColor Green
            } else {
                # Manual removal if npm uninstall fails
                Remove-Item $unscopedPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Manually removed unscoped package directory: $unscopedPath" -ForegroundColor Green
            }
            $uninstalled = $true
        } catch {
            Write-Warning "Failed to remove unscoped package: $($_.Exception.Message)"
        }
    }
    
    # Remove unscoped alias if it exists
    Remove-UnscopedAlias -PackageName $PackageName
    
    # Remove from package.json
    Remove-PackageJsonDependency -PackageName $PackageName
    
    if (-not $uninstalled) {
        Write-Host "Package $PackageName was not found in node_modules" -ForegroundColor Yellow
    }
    
    return $uninstalled
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
        [int]$Indentation = 2,

        [Parameter(ParameterSetName = 'Prettify')]
        [switch]$AsArray
    )
    if ($PSCmdlet.ParameterSetName -eq 'Minify') {
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
        # Replace all colon-space combinations by ": " unless it is inside quotes.
        $line = (' ' * $indent) + ($_.TrimStart() -replace ":\s+$regexUnlessQuoted", ': ')
        if (($_ -match "[\{\[]$regexUnlessQuoted") -and ($_ -notmatch "[}\]]$regexUnlessQuoted")) {
            $indent += $Indentation
        }
        $line -replace '\\u0027', "'"
    # join the array with newlines and convert multiline empty [] or {} into inline arrays or objects
    }) -join [Environment]::NewLine -replace '(\[)\s+(\])', '$1$2' -replace '(\{)\s+(\})', '$1$2'

    if ($AsArray) { return ,[string[]]($result -split '\r?\n') }
    $result
}


# --- SCRIPT LOGIC ---

# Check for help flag first
if ($Help) {
    Show-Help
    exit 0
}

Write-Host "GitHub Package Cache Manager" -ForegroundColor Magenta
Write-Host "Repository: $GithubUsername/$GithubRepo" -ForegroundColor Gray

# Mode 1: Uninstall specific packages
if ($Uninstall -and $args.Count -gt 0) {
    Write-Host "`nRunning in UNINSTALL mode..." -ForegroundColor Magenta
    
    $uninstalledPackages = @()
    $failedPackages = @()
    
    foreach ($arg in $args) {
        $packageName = $arg
        
        # Remove version specifier if present (for uninstall we only need package name)
        $lastAtIndex = $packageName.LastIndexOf('@')
        if ($lastAtIndex -gt 0) {
            $packageName = $packageName.Substring(0, $lastAtIndex)
        }
        
        $success = Uninstall-Package -PackageName $packageName
        if ($success) {
            $uninstalledPackages += $packageName
        } else {
            $failedPackages += $packageName
        }
    }
    
    # Summary
    if ($uninstalledPackages.Count -gt 0) {
        Write-Host "`nSuccessfully uninstalled: $($uninstalledPackages -join ', ')" -ForegroundColor Green
    }
    if ($failedPackages.Count -gt 0) {
        Write-Host "`nFailed to uninstall: $($failedPackages -join ', ')" -ForegroundColor Red
    }
    if ($uninstalledPackages.Count -eq 0 -and $failedPackages.Count -eq 0) {
        Write-Host "`nNo packages were found to uninstall." -ForegroundColor Yellow
    }
}
# Mode 2: Install specific packages
elseif ($args.Count -gt 0) {
    Write-Host "`nRunning in INSTALL mode..." -ForegroundColor Magenta
    
    $successfulPackages = @()
    $pendingPackages = @()
    
    # CORRECTED: Loop through arguments and parse them
    foreach ($arg in $args) {
        $packageNameFromArg = $arg
        $versionSpecFromArg = "latest"

        # Check for a version specifier, like 'axios@1.8.0'.
        $lastAtIndex = $packageNameFromArg.LastIndexOf('@')
        if ($lastAtIndex -gt 0) {
            $versionSpecFromArg = $packageNameFromArg.Substring($lastAtIndex + 1)
            $packageNameFromArg = $packageNameFromArg.Substring(0, $lastAtIndex)
        }

        # Now, process the package with the correctly parsed name and version
        $canInstall = Process-Package -PackageName $packageNameFromArg -VersionSpec $versionSpecFromArg -Recurse
        if ($canInstall) {
            # Resolve concrete version
            $installVersion = Get-PackageVersion -PackageName $packageNameFromArg -VersionSpec $versionSpecFromArg
            $scopedInstall = "@$GithubUsername/$packageNameFromArg@$installVersion"
            Write-Host "Installing (scoped from GitHub cache) $scopedInstall ..." -ForegroundColor Cyan
            try {
                # Install scoped package (registry for this scope is set via .npmrc; don't override global to allow unscoped deps from public registry)
                npm install $scopedInstall --no-save 2>&1 | Tee-Object -Variable rawOut | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Downloaded scoped package: $scopedInstall" -ForegroundColor Green
                    Update-PackageJsonDependency -PackageName $packageNameFromArg -Version $installVersion
                    Ensure-UnscopedAlias -PackageName $packageNameFromArg
                    $successfulPackages += "$packageNameFromArg@$installVersion"
                } else {
                    if ($rawOut -match 'E404' -or $rawOut -match '404 Not Found') {
                        Write-Warning "Scoped package not found. Falling back to public unscoped install: $packageNameFromArg@$installVersion"
                        npm install "$packageNameFromArg@$installVersion" --save-exact
                        if ($LASTEXITCODE -eq 0) {
                            Write-Host "Installed unscoped from public registry: $packageNameFromArg@$installVersion" -ForegroundColor Yellow
                            Update-PackageJsonDependency -PackageName $packageNameFromArg -Version $installVersion
                            $successfulPackages += "$packageNameFromArg@$installVersion"
                        } else {
                            Write-Host "Error installing fallback unscoped package $packageNameFromArg@$installVersion" -ForegroundColor Red
                            Write-VersionSuggestions -PackageName $packageNameFromArg -ProblemVersion $installVersion
                        }
                    } else {
                        Write-Host "Error installing $scopedInstall" -ForegroundColor Red
                        Write-VersionSuggestions -PackageName $packageNameFromArg -ProblemVersion $installVersion
                    }
                }
            } catch {
                Write-Host "Error installing $scopedInstall" -ForegroundColor Red
                Write-Host $_.Exception.Message
                Write-VersionSuggestions -PackageName $packageNameFromArg -ProblemVersion $installVersion
            }
        } else {
            $pendingPackages += "$($packageNameFromArg)@$($versionSpecFromArg)"
        }
    }
    
    # Summary
    if ($successfulPackages.Count -gt 0) {
        Write-Host "`nSuccessfully installed: $($successfulPackages -join ', ')" -ForegroundColor Green
    }
    if ($pendingPackages.Count -gt 0) {
        Write-Host "`nPackages being cached: $($pendingPackages -join ', ')" -ForegroundColor Yellow
        Write-Host "Run the script again in a few minutes to install these packages." -ForegroundColor Yellow
    }
}
# Mode 3: Process package.json
else {
    Write-Host "`nRunning in CACHE-ALL mode for package.json..." -ForegroundColor Magenta
    $packageJsonPath = Resolve-Path "./package.json"
    if (-not (Test-Path $packageJsonPath)) {
        Write-Host "Error: package.json not found in the current directory." -ForegroundColor Red
        exit 1
    }
    
    $packageJson = Get-Content $packageJsonPath -Raw | ConvertFrom-Json

    $allDependencies = @{}
    if ($null -ne $packageJson.dependencies) { 
        $packageJson.dependencies.psobject.Properties | ForEach-Object { 
            $allDependencies[$_.Name] = Parse-VersionFromPackageJson $_.Value 
        } 
    }
    if ($null -ne $packageJson.devDependencies) { 
        $packageJson.devDependencies.psobject.Properties | ForEach-Object { 
            $allDependencies[$_.Name] = Parse-VersionFromPackageJson $_.Value 
        } 
    }

    if ($allDependencies.Count -eq 0) {
        Write-Host "No dependencies found in package.json." -ForegroundColor Green
        exit 0
    }
    
    Write-Host "Found $($allDependencies.Count) total dependencies. Checking cache status..."
    
    $cachedCount = 0
    $pendingCount = 0
    $finalResolvedDeps = @{}
    foreach ($entry in $allDependencies.GetEnumerator()) {
        $isAvailable = Process-Package -PackageName $entry.Name -VersionSpec $entry.Value -Recurse
        $resolvedVersion = Get-PackageVersion -PackageName $entry.Name -VersionSpec $entry.Value
        if ($isAvailable) {
            $scopedInstall = "@$GithubUsername/$($entry.Name)@$resolvedVersion"
            try {
                # Scoped install; .npmrc handles registry routing
                npm install $scopedInstall --no-save 2>&1 | Tee-Object -Variable rawCacheOut | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Cached / verified $scopedInstall" -ForegroundColor Green
                    $finalResolvedDeps[$entry.Name] = $resolvedVersion
                    Ensure-UnscopedAlias -PackageName $entry.Name
                    $cachedCount++
                } else {
                    if ($rawCacheOut -match 'E404' -or $rawCacheOut -match '404 Not Found') {
                        Write-Warning "Scoped package not found for $($entry.Name). Falling back to unscoped public install."
                        npm install "$($entry.Name)@$resolvedVersion" --save-exact --no-save
                        if ($LASTEXITCODE -eq 0) {
                            Write-Host "Installed unscoped $($entry.Name)@$resolvedVersion from public registry" -ForegroundColor Yellow
                            $finalResolvedDeps[$entry.Name] = $resolvedVersion
                            $cachedCount++
                        } else {
                            Write-Host "Error installing fallback unscoped $($entry.Name)@$resolvedVersion" -ForegroundColor Red
                            Write-VersionSuggestions -PackageName $entry.Name -ProblemVersion $resolvedVersion
                        }
                    } else {
                        Write-Host "Error installing $scopedInstall" -ForegroundColor Red
                        Write-VersionSuggestions -PackageName $entry.Name -ProblemVersion $resolvedVersion
                    }
                }
            } catch {
                Write-Host "Error installing $scopedInstall" -ForegroundColor Red
                Write-VersionSuggestions -PackageName $entry.Name -ProblemVersion $resolvedVersion
            }
        } else {
            $pendingCount++
        }
    }

    # Update package.json only once at the end with all resolved versions
    if ($finalResolvedDeps.Count -gt 0) {
        $pkgPath = Join-Path (Get-Location) 'package.json'
        if (Test-Path $pkgPath) {
            try {
                $jsonRaw = Get-Content $pkgPath -Raw
                $pkgObj = $jsonRaw | ConvertFrom-Json
                if (-not $pkgObj.dependencies) { $pkgObj | Add-Member -NotePropertyName dependencies -NotePropertyValue (@{}) }
                foreach ($depName in $finalResolvedDeps.Keys) {
                    $pkgObj.dependencies.PSObject.Properties.Remove($depName) | Out-Null 2>$null
                    $pkgObj.dependencies | Add-Member -NotePropertyName $depName -NotePropertyValue $finalResolvedDeps[$depName] -Force
                }
                ConvertTo-Json $pkgObj -Depth 10 | Format-Json | Set-Content $pkgPath -Encoding UTF8
                Write-Host "package.json updated with all resolved dependency versions." -ForegroundColor DarkGreen
            } catch {
                Write-Warning "Failed to update package.json at end: $($_.Exception.Message)"
            }
        }
    }
    
    Write-Host "`nSummary:" -ForegroundColor Magenta
    Write-Host "Already cached: $cachedCount packages" -ForegroundColor Green
    Write-Host "Being cached: $pendingCount packages" -ForegroundColor Yellow
    
    if ($pendingCount -gt 0) {
        Write-Host "`nWorkflows have been triggered for missing packages." -ForegroundColor Yellow
        Write-Host "Monitor progress at: https://github.com/$GithubUsername/$GithubRepo/actions" -ForegroundColor Cyan
        Write-Host "Run this script again once workflows complete to verify all packages are cached." -ForegroundColor Yellow
    } else {
        Write-Host "`nAll dependencies are cached and ready to use!" -ForegroundColor Green
        try {
            npm install 2>&1 | Tee-Object -Variable rawInstallOut | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "All dependencies installed successfully from cache." -ForegroundColor Green
            } else {
                Write-Host "Error during 'npm install':" -ForegroundColor Red
                Write-Host $rawInstallOut -ForegroundColor Red
            }
        } catch {
            Write-Host "Exception during 'npm install': $_" -ForegroundColor Red
        }
    }
}

