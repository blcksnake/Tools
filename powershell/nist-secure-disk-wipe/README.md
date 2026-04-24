# NIST SP 800-88r2 Secure Disk Wipe


Bootable WinPE USB tool that permanently sanitizes HDDs, SSDs, and NVMe
drives to **NIST SP 800-88 Revision 2** standard. Boots from USB on any
Windows PC with no operating system required.

---

## What Issue It Addresses

When decommissioning computers, retiring storage media, or preparing drives
for donation/resale, a simple format or delete is insufficient -- data can
be recovered with readily available tools. This script builds a bootable USB
that implements forensically-sound sanitization methods (Clear and Purge) as
defined by NIST SP 800-88r2, and produces a signed Certificate of Sanitization
for compliance records.

---

## Supported Environments

| Component | Requirement |
|---|---|
| Build machine | Windows 10/11 (64-bit), run as Administrator |
| Target machine | Any x64 PC -- no OS required, boots from USB |
| PowerShell | 5.1+ (on build machine only) |
| Chocolatey | Required on build machine (auto-detects and installs ADK) |
| USB drive | >= 1 GB -- all data will be erased during build |

---

## Prerequisites

- **Chocolatey** installed on the build machine
  (https://chocolatey.org/install)
- **Run as Administrator**

The script will automatically install Windows ADK and WinPE add-on via
Chocolatey if they are not already present (~1 GB download, ~20 min).

---

## Execution Instructions

**Step 1 -- Build the bootable USB** (run as Administrator):

```powershell
.\Build-BootableUSB.ps1 -UsbDriveLetter E
```

Replace `E` with your USB drive letter. The script will:
- Install Windows ADK + WinPE add-on if missing (via Chocolatey)
- Build a minimal WinPE image with PowerShell, StorageWMI, and HTA
- Inject the SecureWipe tool into the image
- Write the bootable image to the USB

**Step 2 -- Boot the target computer from the USB:**
- Enter BIOS/UEFI (F12 / F9 / Esc / Del at POST) and select the USB
- SecureWipe launches automatically -- no manual commands needed

**Step 3 -- Select a drive and method:**

```
-- Detected Physical Drives -------------------------------------------
Idx  Model               Serial         Size(GB)  Bus       Type
----------------------------------------------------------------------
0    Samsung SSD 870     S4EWNX0T123      465.8   ATA/SATA  SSD
1    WD Blue HDD         WD-WXE1A80K      931.5   ATA/SATA  HDD

Enter drive index (e.g. 1) or 'q' to quit: 0

-- Select Sanitization Method -----------------------------------------
[1] PURGE  - ATA Sanitize Crypto Scramble EXT  [NIST Sec.3.1.2]
[2] CLEAR  - Overwrite with zeros (1 pass)      [NIST Sec.3.1.1]
[3] CLEAR+ - Overwrite with zeros (3 passes)    [NIST Sec.3.1.1]
```

---

## Sample Output

```
-- CLEAR - Overwrite with zeros (1-pass overwrite) ---------------
[!] This will PERMANENTLY destroy all data on PhysicalDrive0!
Drive : Samsung SSD 870  [465.8 GB]
Method: Overwrite all addressable sectors with 0x00 (1 pass)
NIST  : SP 800-88r2 Section 3.1.1 - Clear

Confirm DESTROY ALL DATA on this drive? [y/N] y

[######################################################] 100.0%  512.3 MB/s  ETA 0s
[+] Overwrite complete.
[*] Verifying wipe by sampling 256 random sectors...
Verifying... 100.0%
[+] Verification PASSED - all 256 sampled sectors contain zeros.

-- Wipe Complete --------------------------------------------------
Result  : SUCCESS
Method  : Overwrite 0x00 x 1 pass
Duration: 00:15:12

-- Generating Compliance Report ----------------------------------
[+] TXT  report: X:\WipeReports\WipeReport_20260424_120000.txt
[+] HTML report: X:\WipeReports\WipeReport_20260424_120000.html
```

---

## Sanitization Methods (NIST SP 800-88r2)

| Media | Clear (Sec.3.1.1) | Purge (Sec.3.1.2) |
|---|---|---|
| HDD | Overwrite 0x00 x 1 pass | ATA Security Erase Unit (Enhanced) |
| SSD | Overwrite (fallback only) | ATA SANITIZE Crypto Scramble / Block Erase |
| NVMe | Overwrite (fallback only) | NVMe Sanitize - Crypto Erase (SANACT=1) |

> r2 explicitly states multi-pass overwriting is **not required**. Gutmann
> 35-pass and DoD 5220.22-M are not referenced in the current standard.

---

## Compliance Reports

After each session, two files are saved to `X:\WipeReports\` on the WinPE
RAM disk:

- `WipeReport_YYYYMMDD_HHmmss.txt` -- plain-text Certificate of Sanitization
- `WipeReport_YYYYMMDD_HHmmss.html` -- branded HTML version (auto-opens)

**Copy reports off before rebooting** (they are on a RAM disk):

```cmd
xcopy X:\WipeReports D:\WipeReports /E /I /Y
```

---

## Rollback / Recovery Notes

- The **USB build process** is reversible -- re-running the script rebuilds
  the USB from scratch. The ADK installation is permanent on the build machine
  but can be uninstalled via `choco uninstall windows-adk-deploy windows-adk-winpe`
- The **disk wipe itself is irreversible** -- there is no undo
- If a wipe is interrupted, re-run the tool and select the same drive. The
  verification step will indicate if the wipe was incomplete

---

## Security Notes

- No data is transmitted over the network during wipe operations
- Compliance reports contain drive serial numbers -- handle as sensitive
  asset disposition records
- The NULL ATA security password set during Purge is destroyed by the
  erase operation itself

---

## Reference

- NIST SP 800-88r2: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf
- IEEE 2883 (Sanitizing Storage): https://standards.ieee.org/ieee/2883/
- DOI: https://doi.org/10.6028/NIST.SP.800-88r2

---

*Part of the BLCKSNAKE Tools repository -- blcksnake.com*
