# Silent-Updates.ps1

Automated patch management for Windows. Installs pending **Windows Updates** and updates **third-party apps** (via `winget`) in one run, logging every result to a timestamped file. Designed to run unattended — typically as a Scheduled Task during a maintenance window.

---

## ⚠️ Intended use — please read before deploying

This script updates software **silently and without prompting the user**, and can optionally **uninstall and reinstall** applications. That is powerful and, on the wrong machine, disruptive.

- Only run it on **machines you own or administer**, or where you have explicit authorization to install, update, and remove software.
- If **other people use the machine**, tell them it auto-patches on a schedule. A silent update — and especially an unexpected reboot or a changed/removed app — should never come as a surprise to whoever is sitting at that PC. In a workplace setting this disclosure is usually expected (and sometimes required).
- This is a **first public test release**. Try it on a non-critical machine first. Review the log after the first few runs before trusting it unattended.

This tool is provided as-is for testing. You are responsible for what it does on the machines you point it at.

---

## Requirements

- Windows 10 / 11 (or Windows Server with `winget` available)
- **Administrator** privileges (the script exits if not elevated)
- Internet access (to reach Microsoft Update, the PowerShell Gallery, and `winget` sources)
- `winget` — if missing, the script attempts to install it automatically

---

## Usage

Interactive (run as Administrator):

```powershell
powershell -ExecutionPolicy Bypass -File "C:\path\to\Silent-Updates.ps1"
```

Unattended, as a Scheduled Task running under `SYSTEM`:

```powershell
$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Silent-Updates.ps1"'
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "AutoUpdates" -Action $action -Trigger $trigger -Principal $principal
```

> **Note:** `winget` under the `SYSTEM` account behaves differently than in an interactive admin shell and is the least-exercised code path. If you deploy via Scheduled Task, verify one run manually first. Running the task as an **admin user** with "Run whether user is logged on or not" is often more reliable than `SYSTEM`.

Logs are written to: `C:\ProgramData\AutoUpdates\Update-<timestamp>.log`

---

## Settings (top of the script)

| Setting | Default | What it does |
|---|---|---|
| `$LogFolder` | `C:\ProgramData\AutoUpdates` | Where logs are stored |
| `$RebootMode` | `"Ignore"` | `"Ignore"` never reboots; `"Auto"` reboots immediately if an update requires it |
| `$ExcludeApps` | *(empty)* | winget package IDs to skip (find IDs with `winget list`) |
| `$AutoReinstallBlocked` | `$false` | See the warning below |

---

## ⚠️ `$AutoReinstallBlocked` — read before enabling

Some apps can't be upgraded in place because the newer version uses a **different install technology**. The only way to update them is to **uninstall the old version, then install the new one**.

- **`$false` (default):** the script only *reports* these packages and prints the exact `uninstall` / `install` commands. Nothing is removed. You run them yourself when ready.
- **`$true`:** the script **automatically uninstalls and then reinstalls** each blocked package.

**Risks of enabling it:**

- Uninstalling an app can **erase its settings, data, or license activation**. This varies by app and is outside the script's control.
- Between the two steps the app is **temporarily not installed**. The script only reinstalls after a *confirmed* uninstall, and logs a clear **WARNING** if the reinstall doesn't succeed — but a failed reinstall still leaves the app missing until the next run.

Leave this `$false` unless you're comfortable with unattended removal and replacement of software, and have verified it against apps whose settings/data you don't mind losing. **Back up anything important first.**

---

## Troubleshooting — expected "failures"

Some packages will show up as **Failed** or **Blocked** on almost every run. These are usually **external conditions, not script bugs.** Before reporting an issue, check whether it's one of these:

**"Installer hash does not match; this cannot be overridden when running as admin"**
The file the vendor is serving doesn't match what winget's manifest expects, usually a stale manifest on the vendor's side. winget refuses it as a safety measure and you can't override it as admin. Fix: wait for the vendor to update their manifest, or update that app through its own built-in updater.

**"Installer failed with exit code: 1603"**
A generic Windows Installer failure. Common causes: the app was **running** during the update, or a **reboot is pending**. Often resolves on the next run or after a restart. The log points to the app's own installer log for details.

**"No applicable upgrade found" (often `msstore` source apps)**
A newer version exists but doesn't apply to this system, or the app is managed by the **Microsoft Store**, which updates it independently. Add its ID to `$ExcludeApps` to stop it showing as a failure, or switch to the winget-source package for that app.

**"the install technology is different from the current version"**
Not a bug — this is the **BLOCKED** category. The app needs a manual uninstall + reinstall (see `$AutoReinstallBlocked` above). The script prints the exact commands.

**winget not found / third-party updates skipped**
The script tries to install winget automatically. If that fails, check internet access and that the machine can reach GitHub and the Microsoft Store. On Windows Server, `winget` may need manual setup.

---

## Reporting issues

When reporting a problem, please include:

- The **full log file** from `C:\ProgramData\AutoUpdates`
- Whether you ran it **interactively** or as a **Scheduled Task** (and under which account)
- Your Windows version and `winget --version`

> **Heads-up for testers:** the winget upgrade-list parser depends on winget's current table output format. If a future winget release changes that layout, package detection may break — flag it if you see the "Found N package(s)" line reporting the wrong packages or none at all.