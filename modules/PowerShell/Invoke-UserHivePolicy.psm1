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
