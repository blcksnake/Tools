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
