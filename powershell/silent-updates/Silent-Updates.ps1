<#
/////////////////////////////////////////////////////////////////////////////////
//  ██████╗ ██╗      ██████╗██╗  ██╗███████╗███╗   ██╗ █████╗ ██╗  ██╗███████╗  //
//  ██╔══██╗██║     ██╔════╝██║ ██╔╝██╔════╝████╗  ██║██╔══██╗██║ ██╔╝██╔════╝  //
//  ██████╔╝██║     ██║     █████╔╝ ███████╗██╔██╗ ██║███████║█████╔╝ █████╗    //
//  ██╔══██╗██║     ██║     ██╔═██╗ ╚════██║██║╚██╗██║██╔══██║██╔═██╗ ██╔══╝    //
//  ██████╔╝███████╗╚██████╗██║  ██╗███████║██║ ╚████║██║  ██║██║  ██╗███████╗  //
//  ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝  //
//===============================================================================//
// SCRIPT:    Silent-Updates.ps1
// AUTHOR:    BLCKSNAKE
// DATE:      2026-09-18
// VERSION:   1.0.0
// PURPOSE:   Automated Windows Update + third-party (winget) patch management,
//            run silently via Scheduled Task during a maintenance window.
// USAGE:     Run as Administrator: .\Silent-Updates.ps1
//            (or register as a SYSTEM Scheduled Task for hands-off operation)
//
// RESOURCES:
//   - BLCKSNAKE: https://blcksnake.com
//   - PSWindowsUpdate module (PowerShell Gallery)
//   - Windows Package Manager (winget)
//
// DETAILS:
//   1. Confirms it's running elevated (admin); exits if not.
//   2. Ensures the PSWindowsUpdate module is available (installs if missing).
//   3. Installs all available Windows Updates silently.
//   4. Upgrades all winget-managed third-party apps silently.
//   5. Writes a timestamped log to C:\ProgramData\AutoUpdates for review.
//
// CHANGELOG:
// v1.0.0
//   Windows Update installation (via PSWindowsUpdate) plus per-package
//   third-party updates via winget, each with an attributed outcome
//   (ok / failed / blocked). Summary names packages blocked by
//   install-technology changes and prints the exact uninstall+install
//   commands. Optional $AutoReinstallBlocked switch (default $false) can
//   perform those uninstall+reinstall steps automatically, reinstalling
//   only after a confirmed uninstall. Bootstraps winget (App Installer)
//   if missing, with SYSTEM-aware machine-wide provisioning. Live output
//   streaming and --disable-interactivity so runs never hang on prompts.
//   Timestamped logs written to C:\ProgramData\AutoUpdates.
//   NOTE: the upgrade-list parser relies on winget's table column layout;
//         re-verify parsing if a future winget changes its output format.
//
// LEGAL:
//   BLCKSNAKE Tools - Licensed under the MIT License.
//   Copyright (c) 2026 Jeysson Rostran. See LICENSE for full text.
//===============================================================================//
#>

# ---------- Settings you might want to change ----------
$LogFolder   = "C:\ProgramData\AutoUpdates"       # Where logs are stored
$RebootMode  = "Ignore"                            # "Ignore" = never reboot now,
                                                   # "Auto"   = reboot immediately if needed

# When a package can't upgrade in place (new version uses a different install
# technology), the ONLY way to update it is uninstall + reinstall.
#   $false = SAFE default. Just report these and print the commands.
#   $true  = script will AUTOMATICALLY uninstall then reinstall each one.
# WARNING: uninstalling can wipe an app's settings/data, and if the reinstall
# fails the app is left uninstalled until the next run. Only enable this if
# you're comfortable with unattended removal + replacement of software.
$AutoReinstallBlocked = $false

# Apps that refuse to upgrade silently (they pop their own UI) can be skipped
# here by winget package ID. Find the exact ID with:  winget list
# Leave empty to upgrade everything. (--exclude needs a recent winget, 1.6+)
$ExcludeApps = @(
    # "Publisher.AppName"
)
# ------------------------------------------------------

# Make sure the log folder exists
if (-not (Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path $LogFolder ("Update-{0}.log" -f (Get-Date -Format "yyyy-MM-dd_HHmmss"))

# Simple logging helper: writes to file and console at once
function Write-Log {
    param([string]$Message)
    $line = "{0}  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $LogFile -Value $line
    Write-Output $line
}

Write-Log "=== Update run started ==="

# --- Step 1: Confirm we're running as Administrator ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Log "ERROR: Script must be run as Administrator. Exiting."
    exit 1
}

# --- Step 2: Make sure PSWindowsUpdate is installed ---
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Log "PSWindowsUpdate module not found. Installing..."
    try {
        # NuGet provider is required to install modules from the gallery
        Install-PackageProvider -Name NuGet -Force -Scope AllUsers -ErrorAction Stop | Out-Null
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -ErrorAction Stop
        Write-Log "PSWindowsUpdate installed successfully."
    }
    catch {
        Write-Log ("ERROR installing PSWindowsUpdate: {0}" -f $_.Exception.Message)
        exit 1
    }
}

Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue

# --- Step 3: Install Windows Updates silently ---
Write-Log "Checking for Windows Updates..."
try {
    if ($RebootMode -eq "Auto") {
        $result = Install-WindowsUpdate -AcceptAll -AutoReboot -Verbose 4>&1
    }
    else {
        # Install everything but never reboot on its own
        $result = Install-WindowsUpdate -AcceptAll -IgnoreReboot -Verbose 4>&1
    }
    Write-Log "Windows Update results:"
    $result | ForEach-Object { Write-Log ("   " + $_) }
}
catch {
    Write-Log ("ERROR during Windows Update: {0}" -f $_.Exception.Message)
}

# --- Helper: bootstrap winget (App Installer) if it's missing ---
function Install-Winget {
    Write-Log "winget not found. Attempting to install App Installer (winget)..."

    # Are we running as the SYSTEM account (e.g. a Scheduled Task)?
    # winget is a per-user app, so under SYSTEM we must PROVISION it
    # machine-wide rather than do a normal per-user install.
    $runningAsSystem = [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem

    # Make sure we can talk to GitHub over TLS 1.2 on older PowerShell
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $temp = Join-Path $env:TEMP ("winget-bootstrap-" + [guid]::NewGuid().ToString())
    New-Item -Path $temp -ItemType Directory -Force | Out-Null

    try {
        # Ask GitHub for the latest winget-cli release and grab its assets
        $api     = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
        $release = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "winget-bootstrap" } -ErrorAction Stop

        $bundle  = $release.assets | Where-Object { $_.name -like "*.msixbundle" }      | Select-Object -First 1
        $license = $release.assets | Where-Object { $_.name -like "*License1.xml" }     | Select-Object -First 1
        $depzip  = $release.assets | Where-Object { $_.name -like "*Dependencies.zip" } | Select-Object -First 1

        if (-not $bundle) { throw "Could not find the winget .msixbundle in the latest release." }

        # Download the main bundle
        $bundlePath = Join-Path $temp $bundle.name
        Write-Log ("Downloading " + $bundle.name + " ...")
        Invoke-WebRequest -Uri $bundle.browser_download_url -OutFile $bundlePath -UseBasicParsing -ErrorAction Stop

        # Download + extract dependencies (VCLibs / UI.Xaml), matching CPU arch
        $depPaths = @()
        if ($depzip) {
            $depZipPath = Join-Path $temp $depzip.name
            Write-Log ("Downloading dependencies " + $depzip.name + " ...")
            Invoke-WebRequest -Uri $depzip.browser_download_url -OutFile $depZipPath -UseBasicParsing -ErrorAction Stop

            $depExtract = Join-Path $temp "deps"
            Expand-Archive -Path $depZipPath -DestinationPath $depExtract -Force

            $archFolder = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
            $depPaths = Get-ChildItem -Path (Join-Path $depExtract $archFolder) -Filter *.appx -Recurse -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty FullName
        }

        if ($runningAsSystem) {
            # Machine-wide provisioning (the correct path under SYSTEM)
            Write-Log "Running as SYSTEM - provisioning winget for all users..."
            $licensePath = $null
            if ($license) {
                $licensePath = Join-Path $temp $license.name
                Invoke-WebRequest -Uri $license.browser_download_url -OutFile $licensePath -UseBasicParsing -ErrorAction Stop
            }

            $provArgs = @{ Online = $true; PackagePath = $bundlePath }
            if ($depPaths.Count) { $provArgs.DependencyPackagePath = $depPaths }
            if ($licensePath)    { $provArgs.LicensePath = $licensePath }
            else                 { $provArgs.SkipLicense = $true }

            Add-AppxProvisionedPackage @provArgs -ErrorAction Stop | Out-Null
        }
        else {
            # Normal per-user install: dependencies first, then winget
            Write-Log "Installing dependencies and winget for the current user..."
            foreach ($dep in $depPaths) {
                try { Add-AppxPackage -Path $dep -ErrorAction Stop }
                catch { Write-Log ("   dependency note: " + $_.Exception.Message) }
            }
            Add-AppxPackage -Path $bundlePath -ErrorAction Stop
        }

        Write-Log "winget bootstrap finished."
    }
    catch {
        Write-Log ("ERROR bootstrapping winget: {0}" -f $_.Exception.Message)
    }
    finally {
        Remove-Item -Path $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- Step 4: Upgrade third-party apps via winget ---
$winget = Get-Command winget -ErrorAction SilentlyContinue

# If winget isn't present, try to install it, then re-check.
if (-not $winget) {
    Install-Winget
    $winget = Get-Command winget -ErrorAction SilentlyContinue

    # The app-execution alias may not be on PATH yet this session, so also
    # look for winget.exe directly under WindowsApps as a fallback.
    if (-not $winget) {
        $found = Get-ChildItem "$env:ProgramFiles\WindowsApps" -Recurse -Filter winget.exe -ErrorAction SilentlyContinue |
                 Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) { $winget = $found }
    }
}

# Resolve a usable path/command for winget, whether it came from
# Get-Command or a direct file lookup.
$wingetPath = if ($winget -is [System.IO.FileInfo]) { $winget.FullName }
              elseif ($winget)                      { $winget.Source }
              else                                  { $null }

if ($wingetPath) {
    Write-Log "Building list of available upgrades..."
    try {
        # ---- 1. Get the upgradable packages and parse their IDs ----
        # We read winget's table and slice the "Id" column by its header
        # position -- the reliable way to parse winget's text output.
        $listLines = & $wingetPath upgrade --include-unknown `
                        --accept-source-agreements 2>&1 |
                     ForEach-Object { ($_.ToString() -replace "[`r`b]", "") }

        $ids = @()
        $idCol = -1; $verCol = -1
        foreach ($ln in $listLines) {
            if ($idCol -lt 0) {
                # Locate the header row and remember where columns start
                if ($ln -match '^\s*Name\s+Id\s+Version') {
                    $idCol  = $ln.IndexOf("Id")
                    $verCol = $ln.IndexOf("Version")
                }
                continue
            }
            if ($ln -match '^\s*-{5,}') { continue }                # dashes line
            if ($ln -match 'upgrades available' -or
                $ln -match 'package\(s\)'       -or
                $ln.Trim() -eq "") { break }                        # end of table
            if ($ln.Length -gt $idCol) {
                $len = [Math]::Min($verCol - $idCol, $ln.Length - $idCol)
                $id  = $ln.Substring($idCol, $len).Trim()
                if ($id -and ($ExcludeApps -notcontains $id)) { $ids += $id }
            }
        }

        Write-Log ("Found {0} package(s) to try: {1}" -f $ids.Count, ($ids -join ", "))

        # ---- 2. Upgrade each package individually so we can attribute ----
        # ----    the exact outcome (ok / failed / blocked) to each ID  ----
        $upgraded = @(); $failed = @(); $blocked = @()

        foreach ($id in $ids) {
            Write-Log ("Upgrading {0} ..." -f $id)
            $out = & $wingetPath upgrade --id $id --exact --silent `
                     --disable-interactivity `
                     --accept-package-agreements `
                     --accept-source-agreements `
                     --include-unknown 2>&1 |
                   ForEach-Object { ($_.ToString() -replace "[`r`b]", "").Trim() }

            $out | Where-Object { $_ } | ForEach-Object { Write-Log ("   " + $_) }
            $joined = ($out -join " ")

            # winget's wording varies: the per-package message says
            # "the install technology is different..." while the --all
            # summary says "different install technology". Match the stable
            # part of the phrase ("install technology") to catch both.
            if ($joined -match 'install technology') {
                $blocked += $id
            }
            elseif ($joined -match 'Successfully installed') {
                $upgraded += $id
            }
            else {
                $failed += $id
            }
        }

        # ---- 3. Clear summary with ready-to-paste manual commands ----
        Write-Log "--------------- UPGRADE SUMMARY ---------------"
        if ($upgraded.Count) { Write-Log ("Upgraded OK : " + ($upgraded -join ", ")) }
        if ($failed.Count)   { Write-Log ("Failed      : " + ($failed   -join ", ")) }
        if ($blocked.Count) {
            Write-Log "BLOCKED - these need a manual uninstall + reinstall:"
            foreach ($b in $blocked) {
                Write-Log ("   * {0}" -f $b)
                Write-Log ("       winget uninstall --id {0} --exact" -f $b)
                Write-Log ("       winget install   --id {0} --exact" -f $b)
            }

            # If enabled, actually perform the uninstall + reinstall for each
            # blocked package. Off by default (see $AutoReinstallBlocked).
            if ($AutoReinstallBlocked) {
                Write-Log "AutoReinstallBlocked is ON - processing blocked packages..."
                foreach ($b in $blocked) {
                    Write-Log ("Uninstalling {0} ..." -f $b)
                    $uOut = & $wingetPath uninstall --id $b --exact --silent `
                              --disable-interactivity `
                              --accept-source-agreements 2>&1 |
                            ForEach-Object { ($_.ToString() -replace "[`r`b]", "").Trim() }
                    $uOut | Where-Object { $_ } | ForEach-Object { Write-Log ("   " + $_) }

                    # Only reinstall if the uninstall actually succeeded, so we
                    # don't leave the machine in a worse state on failure.
                    if (($uOut -join " ") -match 'Successfully uninstalled') {
                        Write-Log ("Reinstalling {0} ..." -f $b)
                        $iOut = & $wingetPath install --id $b --exact --silent `
                                  --disable-interactivity `
                                  --accept-package-agreements `
                                  --accept-source-agreements 2>&1 |
                                ForEach-Object { ($_.ToString() -replace "[`r`b]", "").Trim() }
                        $iOut | Where-Object { $_ } | ForEach-Object { Write-Log ("   " + $_) }

                        if (($iOut -join " ") -match 'Successfully installed') {
                            Write-Log ("OK: {0} reinstalled on the new version." -f $b)
                        }
                        else {
                            Write-Log ("WARNING: {0} was uninstalled but the reinstall did NOT confirm success. Check this app manually." -f $b)
                        }
                    }
                    else {
                        Write-Log ("Skipped reinstall of {0}: uninstall did not confirm success (app left as-is)." -f $b)
                    }
                }
            }
        }
        else {
            Write-Log "No packages blocked by install-technology changes."
        }
        Write-Log "----------------------------------------------"
        Write-Log "winget upgrade pass complete."
    }
    catch {
        Write-Log ("ERROR during winget upgrade: {0}" -f $_.Exception.Message)
    }
}
else {
    Write-Log "winget could not be found or installed. Skipping third-party updates."
}

Write-Log "=== Update run finished ==="