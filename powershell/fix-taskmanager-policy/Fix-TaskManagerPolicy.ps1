<#
/////////////////////////////////////////////////////////////////////////////////
//  ██████╗ ██╗      ██████╗██╗  ██╗███████╗███╗   ██╗ █████╗ ██╗  ██╗███████╗  //
//  ██╔══██╗██║     ██╔════╝██║ ██╔╝██╔════╝████╗  ██║██╔══██╗██║ ██╔╝██╔════╝  //
//  ██████╔╝██║     ██║     █████╔╝ ███████╗██╔██╗ ██║███████║█████╔╝ █████╗    //
//  ██╔══██╗██║     ██║     ██╔═██╗ ╚════██║██║╚██╗██║██╔══██║██╔═██╗ ██╔══╝    //
//  ██████╔╝███████╗╚██████╗██║  ██╗███████║██║ ╚████║██║  ██║██║  ██╗███████╗  //
//  ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝  //
//===============================================================================//
// SCRIPT:    Fix-TaskManagerPolicy.ps1
// AUTHOR:    BLCKSNAKE
// DATE:      2026-03-27
// VERSION:   1.3.0
// PURPOSE:   Task Manager policy repair/reset with local + domain audit and user-hive remediation
// SUPPORTED: Windows 10/11 and Windows Server 2016+ (PowerShell 5.1+)
// REQUIRES:  Administrator privileges and local profile access
// USAGE:     Run as Administrator: .\Fix-TaskManagerPolicy.ps1 [-SkipGpUpdate] [-NoRestartPrompt]
// SAFE-RUN:  Validate in a test environment first and review backup/log output after execution
// OUTPUT:    Creates timestamped log and backup folder in script directory
// ROLLBACK:  Import saved .reg backups and restore policy files from backup-* folder
// 
// RESOURCES:
//   - BLCKSNAKE IT Support: https://blcksnake.com
//   - Microsoft Group Policy and Windows Security Baselines
// 
// CHANGELOG:
// v1.3.0 [2026-03-27] - Fixed hive handling/path reliability and gpupdate output logging robustness
// v1.2.0 [2026-03-27] - Added domain/local GPO audit with gpresult output capture
// v1.1.0 [2026-03-27] - Added domain/local user policy reset context in header
// v1.0.0 [2026-03-27] - Initial Task Manager remediation script
// 
// LEGAL:
//   BLCKSNAKE Tools - Licensed under the MIT License
//===============================================================================//
#>

#requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$SkipGpUpdate,
    [switch]$NoRestartPrompt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$timeStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Join-Path $PSScriptRoot "Fix-TaskManagerPolicy-$timeStamp.log"

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    Add-Content -Path $logPath -Value $line
}

function Confirm-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Host 'This script must run as Administrator. Relaunching elevated...'
        $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
        if ($SkipGpUpdate) { $argList += '-SkipGpUpdate' }
        if ($NoRestartPrompt) { $argList += '-NoRestartPrompt' }

        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList | Out-Null
        exit 0
    }
}

function New-BackupDirectory {
    $backupDir = Join-Path $PSScriptRoot "backup-$timeStamp"
    New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    return $backupDir
}

function Backup-RegistryPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationFile
    )

    try {
        $null = Get-Item -Path $RegistryPath -ErrorAction Stop
        $nativePath = $RegistryPath -replace '^Registry::', '' -replace '^HKLM:', 'HKEY_LOCAL_MACHINE' -replace '^HKCU:', 'HKEY_CURRENT_USER' -replace '^HKU:', 'HKEY_USERS'
        $cmd = "reg.exe export `"$nativePath`" `"$DestinationFile`" /y"
        cmd /c $cmd | Out-Null
        Write-Log "Backed up $RegistryPath to $DestinationFile"
    }
    catch {
        Write-Log "Registry path not found (no backup needed): $RegistryPath" 'WARN'
    }
}

function Remove-DisableTaskMgrValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyPath
    )

    if (-not (Test-Path -Path $PolicyPath)) {
        Write-Log "Policy path not found (skip): $PolicyPath" 'WARN'
        return
    }

    $value = Get-ItemProperty -Path $PolicyPath -Name DisableTaskMgr -ErrorAction SilentlyContinue
    if ($null -ne $value) {
        Remove-ItemProperty -Path $PolicyPath -Name DisableTaskMgr -ErrorAction Stop
        Write-Log "Removed DisableTaskMgr from $PolicyPath"
    }
    else {
        Write-Log "DisableTaskMgr not present at $PolicyPath"
    }
}

function Initialize-RegistryPath {
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Invoke-UserHivePolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sid,
        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,
        [Parameter(Mandatory = $true)]
        [string]$BackupDir
    )

    $ntUserDat = Join-Path $ProfilePath 'NTUSER.DAT'
    if (-not (Test-Path -Path $ntUserDat)) {
        Write-Log "NTUSER.DAT not found for SID $Sid at $ntUserDat" 'WARN'
        return
    }

    $hiveLoadedByScript = $false
    if (-not (Test-Path -Path "Registry::HKEY_USERS\$Sid")) {
        $loadResult = & reg.exe load "HKU\$Sid" "$ntUserDat" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to load hive for SID ${Sid}: $loadResult" 'WARN'
            return
        }
        $hiveLoadedByScript = $true
        Write-Log "Loaded user hive for SID $Sid"
    }

    try {
        $policyPath = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $tmPath = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Windows\CurrentVersion\TaskManager"

        Backup-RegistryPath -RegistryPath $policyPath -DestinationFile (Join-Path $BackupDir "$Sid-Policies-System.reg")
        Backup-RegistryPath -RegistryPath $tmPath -DestinationFile (Join-Path $BackupDir "$Sid-TaskManager.reg")

        Initialize-RegistryPath -Path $policyPath
        Remove-DisableTaskMgrValue -PolicyPath $policyPath

        if (Test-Path -Path $tmPath) {
            Remove-Item -Path $tmPath -Recurse -Force -ErrorAction Stop
            Write-Log "Reset Task Manager settings for SID $Sid"
        }
        else {
            Write-Log "Task Manager settings key missing for SID $Sid (nothing to reset)"
        }
    }
    finally {
        if ($hiveLoadedByScript) {
            $unloaded = $false
            $maxUnloadAttempts = 5

            for ($attempt = 1; $attempt -le $maxUnloadAttempts; $attempt++) {
                # Give registry provider handles time to close before unloading offline hive.
                [GC]::Collect()
                [GC]::WaitForPendingFinalizers()

                try {
                    $proc = Start-Process -FilePath "$env:SystemRoot\System32\reg.exe" -ArgumentList @('unload', "HKU\$Sid") -NoNewWindow -Wait -PassThru -ErrorAction Stop
                    if ($proc.ExitCode -eq 0) {
                        Write-Log "Unloaded user hive for SID $Sid"
                        $unloaded = $true
                        break
                    }

                    Write-Log "Hive unload attempt $attempt/$maxUnloadAttempts failed for SID ${Sid} (exit code: $($proc.ExitCode))" 'WARN'
                }
                catch {
                    Write-Log "Hive unload attempt $attempt/$maxUnloadAttempts threw an error for SID ${Sid}: $($_.Exception.Message)" 'WARN'
                }

                Start-Sleep -Milliseconds 400
            }

            if (-not $unloaded) {
                Write-Log "Could not unload hive for SID ${Sid}; continuing. A reboot will release the hive." 'WARN'
            }
        }
    }
}

function Backup-And-RenameLocalGpoFiles {
    param([string]$BackupDir)

    $gpFiles = @(
        "$env:SystemRoot\System32\GroupPolicy\Machine\Registry.pol",
        "$env:SystemRoot\System32\GroupPolicy\User\Registry.pol"
    )

    foreach ($file in $gpFiles) {
        if (Test-Path -Path $file) {
            $dest = Join-Path $BackupDir ([IO.Path]::GetFileName($file) + '.bak')
            Copy-Item -Path $file -Destination $dest -Force
            Rename-Item -Path $file -NewName (([IO.Path]::GetFileName($file)) + ".old-$timeStamp") -ErrorAction Stop
            Write-Log "Backed up and renamed local GPO file: $file"
        }
        else {
            Write-Log "Local GPO file not found (skip): $file" 'WARN'
        }
    }
}

function Invoke-TaskManagerPolicyAudit {
    param([string]$OutputDir)

    Write-Log 'Starting Task Manager policy audit (domain/local GPO check)'

    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($computerSystem.PartOfDomain) {
            Write-Log "Computer is domain joined to: $($computerSystem.Domain)"
        }
        else {
            Write-Log 'Computer is not domain joined. Only local policy applies.' 'WARN'
        }
    }
    catch {
        Write-Log "Unable to determine domain join status: $($_.Exception.Message)" 'WARN'
    }

    $auditPatterns = @(
        'Task Manager',
        'Remove Task Manager',
        'DisableTaskMgr',
        'Policies\System'
    )

    $computerReportPath = Join-Path $OutputDir 'gpresult-computer.txt'
    $userReportPath = Join-Path $OutputDir 'gpresult-user.txt'

    try {
        $gpComputerOut = & gpresult /SCOPE COMPUTER /Z 2>&1
        $gpComputerOut | Set-Content -Path $computerReportPath -Encoding UTF8
        Write-Log "Saved COMPUTER gpresult report: $computerReportPath"

        $computerHits = $gpComputerOut | Select-String -Pattern $auditPatterns -SimpleMatch
        if ($computerHits) {
            Write-Log 'Potential Task Manager-related entries found in COMPUTER gpresult:'
            $computerHits | Select-Object -First 20 | ForEach-Object {
                Write-Log ("COMPUTER HIT: {0}" -f $_.Line.Trim())
            }
        }
        else {
            Write-Log 'No obvious Task Manager-related entries found in COMPUTER gpresult.'
        }
    }
    catch {
        Write-Log "Failed to collect COMPUTER gpresult data: $($_.Exception.Message)" 'WARN'
    }

    try {
        $gpUserOut = & gpresult /SCOPE USER /Z 2>&1
        $gpUserOut | Set-Content -Path $userReportPath -Encoding UTF8
        Write-Log "Saved USER gpresult report: $userReportPath"

        $userHits = $gpUserOut | Select-String -Pattern $auditPatterns -SimpleMatch
        if ($userHits) {
            Write-Log 'Potential Task Manager-related entries found in USER gpresult:'
            $userHits | Select-Object -First 20 | ForEach-Object {
                Write-Log ("USER HIT: {0}" -f $_.Line.Trim())
            }
        }
        else {
            Write-Log 'No obvious Task Manager-related entries found in USER gpresult.'
        }
    }
    catch {
        Write-Log "Failed to collect USER gpresult data: $($_.Exception.Message)" 'WARN'
    }

    $effectivePolicyPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    )

    foreach ($path in $effectivePolicyPaths) {
        try {
            $value = Get-ItemProperty -Path $path -Name DisableTaskMgr -ErrorAction Stop
            Write-Log "Effective policy still sets DisableTaskMgr=$($value.DisableTaskMgr) at $path" 'WARN'
        }
        catch {
            Write-Log "Effective policy check: DisableTaskMgr not set at $path"
        }
    }

    Write-Log 'Task Manager policy audit completed.'
}

Confirm-Admin
$backupDir = New-BackupDirectory
Write-Log "Started repair. Log: $logPath"
Write-Log "Backup directory: $backupDir"

# Machine-level policy keys that can disable Task Manager.
$machinePolicy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$machinePolicyWow = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\System'
$currentUserPolicy = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
$currentUserTaskManager = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager'

Initialize-RegistryPath -Path $machinePolicy
Initialize-RegistryPath -Path $machinePolicyWow
Initialize-RegistryPath -Path $currentUserPolicy

Backup-RegistryPath -RegistryPath $machinePolicy -DestinationFile (Join-Path $backupDir 'HKLM-Policies-System.reg')
Backup-RegistryPath -RegistryPath $machinePolicyWow -DestinationFile (Join-Path $backupDir 'HKLM-WOW6432Node-Policies-System.reg')
Backup-RegistryPath -RegistryPath $currentUserPolicy -DestinationFile (Join-Path $backupDir 'HKCU-Policies-System.reg')
Backup-RegistryPath -RegistryPath $currentUserTaskManager -DestinationFile (Join-Path $backupDir 'HKCU-TaskManager.reg')

Remove-DisableTaskMgrValue -PolicyPath $machinePolicy
Remove-DisableTaskMgrValue -PolicyPath $machinePolicyWow
Remove-DisableTaskMgrValue -PolicyPath $currentUserPolicy

if (Test-Path -Path $currentUserTaskManager) {
    Remove-Item -Path $currentUserTaskManager -Recurse -Force -ErrorAction Stop
    Write-Log 'Reset current user Task Manager settings key'
}
else {
    Write-Log 'Current user Task Manager settings key not present (already default)'
}

# Process all local user profiles so non-admin accounts are corrected too.
$profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$profileEntries = @(Get-ChildItem -Path $profileListPath | ForEach-Object {
    $rawProfilePath = (Get-ItemProperty -Path $_.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
    $expandedProfilePath = if ($rawProfilePath) {
        [Environment]::ExpandEnvironmentVariables($rawProfilePath)
    }
    else {
        $null
    }

    [PSCustomObject]@{
        Sid = $_.PSChildName
        RawProfilePath = $rawProfilePath
        ProfilePath = $expandedProfilePath
    }
})

$profileSids = @($profileEntries | Where-Object {
    $_.Sid -match '^S-1-5-21-' -and
    $_.ProfilePath -and
    (Test-Path -Path $_.ProfilePath)
})

$skippedProfiles = @($profileEntries | Where-Object {
    $_.Sid -match '^S-1-5-21-' -and
    (-not $_.ProfilePath -or -not (Test-Path -Path $_.ProfilePath))
})

foreach ($skipped in $skippedProfiles) {
    Write-Log "Skipped SID $($skipped.Sid) because profile path was not accessible: $($skipped.RawProfilePath)" 'WARN'
}

Write-Log "Discovered $($profileSids.Count) local user profiles to process"

foreach ($entry in $profileSids) {
    Invoke-UserHivePolicy -Sid $entry.Sid -ProfilePath $entry.ProfilePath -BackupDir $backupDir
}

Backup-And-RenameLocalGpoFiles -BackupDir $backupDir

if (-not $SkipGpUpdate) {
    Write-Log 'Running gpupdate /force'
    $gpOut = & gpupdate /force 2>&1
    $gpOut | ForEach-Object {
        $line = [string]$_
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Log $line
        }
    }
}
else {
    Write-Log 'Skipped gpupdate as requested' 'WARN'
}

Invoke-TaskManagerPolicyAudit -OutputDir $backupDir

Write-Log 'Attempting to launch Task Manager for validation'
try {
    Start-Process -FilePath "$env:SystemRoot\System32\Taskmgr.exe"
    Write-Log 'Task Manager launch command sent.'
}
catch {
    Write-Log "Failed to launch Task Manager: $($_.Exception.Message)" 'WARN'
}

Write-Log 'Repair completed.'

if (-not $NoRestartPrompt) {
    $response = Read-Host 'A restart is strongly recommended. Restart now? (Y/N)'
    if ($response -match '^[Yy]') {
        Restart-Computer -Force
    }
}
