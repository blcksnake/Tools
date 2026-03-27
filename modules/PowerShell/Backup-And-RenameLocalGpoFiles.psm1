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
