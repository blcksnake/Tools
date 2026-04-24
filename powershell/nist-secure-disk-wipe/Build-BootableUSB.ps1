#Requires -RunAsAdministrator
<#
///////////////////////////////////////////////////////////////////////////////
//  BLCKSNAKE SECURITY TOOLS
//  -----------------------------------------------------------------------
//  SCRIPT  : Build-BootableUSB.ps1
//  AUTHOR  : Jeysson Rostran  (@BLCKSNAKE)
//  VERSION : 2.0.0
//  PURPOSE : Builds the NIST SP 800-88r2 SecureWipe bootable WinPE USB
//
//  USAGE   : Run as Administrator
//              .\Build-BootableUSB.ps1 -UsbDriveLetter E
//
//  PREREQS : Windows ADK + WinPE add-on (auto-installed via Chocolatey
//            if not already present)
//            USB drive >= 1 GB (ALL DATA ERASED)
//
//  LEGAL   : BLCKSNAKE Security Tools - MIT License
//            https://blcksnake.com/security
///////////////////////////////////////////////////////////////////////////////

.PARAMETER UsbDriveLetter
    Drive letter of the target USB (e.g. "E"). Do NOT include the colon.

.PARAMETER Architecture
    Target CPU architecture: AMD64 (default) or ARM64.

.PARAMETER Force
    Skip all interactive confirmation prompts (for automation).

.EXAMPLE
    .\Build-BootableUSB.ps1 -UsbDriveLetter E
    .\Build-BootableUSB.ps1 -UsbDriveLetter F -Architecture ARM64 -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z]$')]
    [string]$UsbDriveLetter,

    [ValidateSet("AMD64","ARM64","x86")]
    [string]$Architecture = "AMD64",

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Constants --------------------------------------------------------------
$ADK_ROOT   = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit"
$COPYPE     = Join-Path $ADK_ROOT "Windows Preinstallation Environment\copype.cmd"
$MAKEPE     = Join-Path $ADK_ROOT "Windows Preinstallation Environment\MakeWinPEMedia.cmd"
$WORK_DIR   = "$env:TEMP\WinPE_SecureWipe_$Architecture"
$MOUNT_DIR  = "$env:TEMP\WinPE_Mount_$Architecture"
$SCRIPT_SRC = Join-Path $PSScriptRoot "src"
$USB_DRIVE  = "${UsbDriveLetter}:"

# ---- Helper functions -------------------------------------------------------
function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) { Write-Host "[X] $msg" -ForegroundColor Red; exit 1 }

# ---- Banner -----------------------------------------------------------------
Write-Host ""
Write-Host "  +================================================================+" -ForegroundColor Yellow
Write-Host "  |   BLCKSNAKE SecureWipe  |  Bootable USB Builder  |  v2.0      |" -ForegroundColor Yellow
Write-Host "  |   NIST SP 800-88r2  |  by Jeysson Rostran  |  blcksnake.com  |" -ForegroundColor Yellow
Write-Host "  +================================================================+" -ForegroundColor Yellow
Write-Host ""

# ---- Prerequisite check: install ADK via Chocolatey if missing --------------
if (-not (Test-Path $COPYPE)) {
    Write-Warn "Windows ADK / WinPE add-on not found."
    Write-Step "Installing via Chocolatey (windows-adk-deploy + windows-adk-winpe)..."
    Write-Warn "This downloads ~1 GB and may take 15-20 minutes."

    if (-not $Force) {
        Write-Host "  Press ENTER to install or Ctrl+C to abort." -NoNewline
        Read-Host | Out-Null
    }

    $adkVer = "10.1.26100.2454"
    choco install windows-adk-deploy --version $adkVer -y --no-progress 2>&1
    if ($LASTEXITCODE -notin @(0, 3010)) { Write-Fail "windows-adk-deploy install failed ($LASTEXITCODE)" }

    choco install windows-adk-winpe --version $adkVer -y --no-progress 2>&1
    if ($LASTEXITCODE -notin @(0, 3010)) { Write-Fail "windows-adk-winpe install failed ($LASTEXITCODE)" }

    if (-not (Test-Path $COPYPE)) {
        Write-Fail "copype.cmd still not found after install. Check Chocolatey log."
    }
    Write-Ok "ADK installed."
} else {
    Write-Ok "ADK found at: $ADK_ROOT"
}

if (-not (Test-Path $SCRIPT_SRC)) {
    Write-Fail "src\ not found at $SCRIPT_SRC - run from the project root directory."
}

# ---- Verify USB drive -------------------------------------------------------
$usbDisk = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $USB_DRIVE }
if (-not $usbDisk) {
    Write-Fail "USB drive $USB_DRIVE not found. Check the drive letter and retry."
}
$usbSizeGB = [Math]::Round($usbDisk.Size / 1GB, 1)
Write-Warn "USB drive $USB_DRIVE ($($usbSizeGB) GB) will be COMPLETELY ERASED."
if (-not $Force) {
    Write-Host "  Press ENTER to continue or Ctrl+C to abort." -NoNewline
    Read-Host | Out-Null
} else {
    Write-Host "  -Force: continuing automatically." -ForegroundColor Yellow
}

# ---- Set ADK environment variables (required by copype.cmd) -----------------
$DISM    = Join-Path $ADK_ROOT "Deployment Tools\$Architecture\DISM\dism.exe"
$env:WinPERoot   = Join-Path $ADK_ROOT "Windows Preinstallation Environment"
$env:DISMRoot    = Join-Path $ADK_ROOT "Deployment Tools\$Architecture\DISM"
$env:OSCDImgRoot = Join-Path $ADK_ROOT "Deployment Tools\$Architecture\Oscdimg"
$env:DandIRoot   = Join-Path $ADK_ROOT "Deployment Tools"
$env:PATH        = "$env:OSCDImgRoot;$env:DISMRoot;$env:DandIRoot\$Architecture\BCDBoot;" + $env:PATH
Write-Step "ADK env vars set."

# ---- Step 1: copype - create WinPE working directory ------------------------
# Discard any stale mounts from prior interrupted runs
Write-Step "Checking for stale DISM mounts..."
& $DISM /Get-MountedImageInfo 2>$null | Select-String "Mount Dir" | ForEach-Object {
    $p = $_.Line.Substring($_.Line.IndexOf(' : ') + 3).Trim()
    Write-Warn "Discarding stale mount: $p"
    & $DISM /Unmount-Image /MountDir:"$p" /Discard | Out-Null
}
if (Test-Path $MOUNT_DIR) { & $DISM /Unmount-Image /MountDir:"$MOUNT_DIR" /Discard 2>$null | Out-Null }

Write-Step "Creating WinPE working directory..."
if (Test-Path $WORK_DIR) { Remove-Item $WORK_DIR -Recurse -Force -ErrorAction SilentlyContinue }
& cmd.exe /c "`"$COPYPE`" $Architecture `"$WORK_DIR`""
if ($LASTEXITCODE -ne 0) { Write-Fail "copype failed." }
Write-Ok "WinPE staged at $WORK_DIR"

# ---- Step 2: Mount boot.wim -------------------------------------------------
if (Test-Path $MOUNT_DIR) { Remove-Item $MOUNT_DIR -Recurse -Force }
New-Item -ItemType Directory $MOUNT_DIR | Out-Null

$WIM = Join-Path $WORK_DIR "media\sources\boot.wim"
Write-Step "Mounting boot.wim..."
& $DISM /Mount-Image /ImageFile:"$WIM" /Index:1 /MountDir:"$MOUNT_DIR"
if ($LASTEXITCODE -ne 0) { Write-Fail "DISM mount failed." }
Write-Ok "WIM mounted."

# ---- Step 3: Add optional components ----------------------------------------
$OC_BASE = Join-Path $ADK_ROOT "Windows Preinstallation Environment\$Architecture\WinPE_OCs"

$components = @(
    "WinPE-WMI.cab",            "en-us\WinPE-WMI_en-us.cab",
    "WinPE-NetFX.cab",          "en-us\WinPE-NetFX_en-us.cab",
    "WinPE-Scripting.cab",      "en-us\WinPE-Scripting_en-us.cab",
    "WinPE-PowerShell.cab",     "en-us\WinPE-PowerShell_en-us.cab",
    "WinPE-StorageWMI.cab",     "en-us\WinPE-StorageWMI_en-us.cab",
    "WinPE-DismCmdlets.cab",    "en-us\WinPE-DismCmdlets_en-us.cab",
    "WinPE-HTA.cab",            "en-us\WinPE-HTA_en-us.cab"
)

foreach ($cab in $components) {
    $p = Join-Path $OC_BASE $cab
    if (Test-Path $p) {
        Write-Step "Adding $cab..."
        & $DISM /Image:"$MOUNT_DIR" /Add-Package /PackagePath:"$p" /LogLevel:1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Warn "Failed to add $cab (non-fatal)" }
    } else {
        Write-Warn "Component not found (skipping): $cab"
    }
}

# ---- Step 4: Inject SecureWipe scripts --------------------------------------
$destTool = Join-Path $MOUNT_DIR "WipeTool"
New-Item -ItemType Directory $destTool -Force | Out-Null

Copy-Item (Join-Path $SCRIPT_SRC "WipeTool.ps1") $destTool -Force
Write-Ok "WipeTool.ps1 injected."

(Get-Content (Join-Path $SCRIPT_SRC "startnet.cmd")) `
    -replace '%~dp0WipeTool.ps1','%SYSTEMDRIVE%\WipeTool\WipeTool.ps1' |
    Out-File (Join-Path $MOUNT_DIR "Windows\System32\startnet.cmd") -Encoding ASCII
Copy-Item (Join-Path $SCRIPT_SRC "winpeshl.ini") `
          (Join-Path $MOUNT_DIR "Windows\System32\winpeshl.ini") -Force
Write-Ok "startnet.cmd + winpeshl.ini installed."

# ---- Step 5: Commit WIM -----------------------------------------------------
Write-Step "Committing WIM..."
& $DISM /Unmount-Image /MountDir:"$MOUNT_DIR" /Commit
if ($LASTEXITCODE -ne 0) { Write-Fail "DISM commit failed." }
Write-Ok "WIM committed."

# ---- Step 6: Write to USB ---------------------------------------------------
Write-Step "Writing WinPE to $USB_DRIVE ..."
& cmd.exe /c "`"$MAKEPE`" /UFD `"$WORK_DIR`" $USB_DRIVE"
if ($LASTEXITCODE -ne 0) { Write-Fail "MakeWinPEMedia failed." }

# ---- Step 6b: Install newer Secure Boot EFI (2023 Microsoft UEFI CA) -------
$bootbins = Join-Path $WORK_DIR "bootbins"
$efiDest  = "${USB_DRIVE}\EFI\Boot"
if ((Test-Path $efiDest) -and (Test-Path (Join-Path $bootbins "bootmgfw_EX.efi"))) {
    Copy-Item (Join-Path $bootbins "bootmgfw_EX.efi") (Join-Path $efiDest "bootx64.efi") -Force
    Write-Ok "2023 UEFI CA boot file installed (Secure Boot compatible)."
}

# ---- Step 7: Cleanup --------------------------------------------------------
Write-Step "Cleaning up temp files..."
try { Remove-Item $WORK_DIR  -Recurse -Force -ErrorAction SilentlyContinue } catch {}
try { Remove-Item $MOUNT_DIR -Recurse -Force -ErrorAction SilentlyContinue } catch {}

Write-Host ""
Write-Host "  +================================================================+" -ForegroundColor Green
Write-Host "  |  SUCCESS - Bootable USB ready on drive $USB_DRIVE                   |" -ForegroundColor Green
Write-Host "  +================================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  Boot any PC from $USB_DRIVE - SecureWipe launches automatically." -ForegroundColor White
Write-Host "  Secure Boot: supported (Microsoft-signed WinPE bootloader)." -ForegroundColor White
Write-Host ""
Write-Host "  If ATA Purge shows FROZEN on a laptop: suspend/resume to unfreeze." -ForegroundColor Yellow
Write-Host ""
