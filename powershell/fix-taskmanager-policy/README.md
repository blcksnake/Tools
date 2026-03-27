# Fix Task Manager Policy

PowerShell remediation script to fix the error:

"Task Manager has been disabled by your administrator"

This script is designed for enterprise and managed environments where Task Manager may be blocked by local policy, stale user registry values, or management tooling.

## What This Script Does

- Backs up relevant registry policy keys before making changes
- Removes `DisableTaskMgr` from:
  - Machine policy locations
  - Current user policy location
  - Other local user profile hives on the computer
- Resets Task Manager user settings key when present
- Backs up and rotates local Group Policy cache files (`Registry.pol`)
- Runs `gpupdate /force` (optional)
- Performs policy audit and saves:
  - `gpresult-computer.txt`
  - `gpresult-user.txt`
- Logs all actions to a timestamped log file
- Attempts to launch Task Manager for validation

## Files Generated

When you run the script, it creates:

- `Fix-TaskManagerPolicy-<timestamp>.log`
- `backup-<timestamp>/`
  - Registry backups (`.reg`)
  - `gpresult-computer.txt`
  - `gpresult-user.txt`

## Requirements

- Windows PowerShell 5.1+
- Administrator rights
- Local access to user profiles to remediate offline hives

## Supported Environments

- Windows 10/11
- Windows Server 2016+
- Local and domain-joined machines

## Script

- [Fix-TaskManagerPolicy.ps1](Fix-TaskManagerPolicy.ps1)

## Usage

Run from elevated PowerShell:

```powershell
.\Fix-TaskManagerPolicy.ps1
```

Optional parameters:

```powershell
.\Fix-TaskManagerPolicy.ps1 -SkipGpUpdate -NoRestartPrompt
```

## Example Output

```text
[2026-03-27 12:05:11] [INFO] Started repair. Log: ...\Fix-TaskManagerPolicy-20260327-120511.log
[2026-03-27 12:05:11] [INFO] Backup directory: ...\backup-20260327-120511
[2026-03-27 12:05:12] [INFO] Removed DisableTaskMgr from HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System
[2026-03-27 12:05:21] [INFO] Task Manager policy audit completed.
[2026-03-27 12:05:22] [INFO] Repair completed.
```

## Recommended Validation

After script completion:

1. Log in as affected standard/domain user.
2. Verify registry value is not set:

```cmd
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr
```

3. Launch Task Manager:

```cmd
taskmgr.exe
```

## Enterprise Note (Important)

If the issue returns later, it is often being re-applied by endpoint tooling (for example BigFix, SCCM/MECM baselines, login scripts, or security hardening jobs), not by an active local machine setting.

Use these artifacts from the backup folder to investigate reapplication source:

- `gpresult-computer.txt`
- `gpresult-user.txt`
- Script log file

Look for tools or policies writing this value:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr`

## Safety and Rollback

- Registry and policy artifacts are backed up before changes.
- If needed, rollback can be done by importing saved `.reg` files and restoring policy files from backup.

## License

This project is licensed under the MIT License. See [repository LICENSE](../../LICENSE) for full terms.

Copyright (c) 2026 BLCKSNAKE Tools

## Disclaimer

Use at your own risk. Validate in a test environment before broad deployment in production domains.
