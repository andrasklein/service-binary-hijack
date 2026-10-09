<#
    Find-WritableService-WinRM.ps1
    ------------------------------
    For NETWORK logons (WinRM / bind shell / reverse shell), where Get-CimInstance
    and Get-Service often fail with "access denied" for non-admin users.

    This version does NOT use Get-CimInstance. It reads service binary paths
    straight from the registry (HKLM\SYSTEM\CurrentControlSet\Services), which a
    normal user CAN read over a network logon. That makes it reliable in the exact
    situation where the RDP script would break.

    What it does (same goal as Listings 40-43):
      1. Reads every service's ImagePath from the registry.
      2. Flags binaries NOT under C:\Windows (user-installed, like XAMPP).
      3. Tests whether YOUR account can WRITE/MODIFY the binary or its folder.
      4. Prints the service account and start type.

    Read-only. Does not touch, start, or stop anything.
    Run:  powershell -ep bypass -File .\Find-WritableService-WinRM.ps1
#>

$me   = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$mySids = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })
$writeMask = 'Write|Modify|FullControl|WriteData|CreateFiles|AppendData|TakeOwnership|ChangePermissions'

function Test-IWrite($path) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) { return $false }
    try { $acl = Get-Acl -LiteralPath $path -ErrorAction Stop } catch { return $false }
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $sid = $ace.IdentityReference.Value }
        if ($mySids -contains $sid -and $ace.FileSystemRights.ToString() -match $writeMask) { return $true }
    }
    return $false
}

function Get-Exe($imagePath) {
    if (-not $imagePath) { return $null }
    # registry ImagePath may use environment strings like \SystemRoot\...
    $p = [System.Environment]::ExpandEnvironmentVariables($imagePath).Trim()
    if ($p.StartsWith('"')) { $e = $p.IndexOf('"',1); if ($e -gt 1) { return $p.Substring(1,$e-1) } }
    $i = $p.IndexOf('.exe',[StringComparison]::OrdinalIgnoreCase)
    if ($i -ge 0) { return $p.Substring(0,$i+4) }
    return ($p -split '\s+')[0]
}

# start-type number -> text
$startMap = @{ 2 = 'Auto'; 3 = 'Manual'; 4 = 'Disabled'; 0 = 'Boot'; 1 = 'System' }

Write-Host "`n[*] Running as: $($me.Name)" -ForegroundColor Cyan
Write-Host "[*] Scanning services via registry (WinRM / network-logon safe)...`n" -ForegroundColor Cyan

$svcKeys = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue

if (-not $svcKeys) {
    Write-Host "[!] Could not read the services registry key.`n" -ForegroundColor Red
    return
}

$hits = foreach ($k in $svcKeys) {
    $props = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
    if (-not $props.ImagePath) { continue }
    $exe = Get-Exe $props.ImagePath
    if (-not $exe -or ($exe -notlike '*.exe')) { continue }     # skip driver .sys etc.
    if ($exe -like 'C:\Windows\*') { continue }                  # skip standard Windows binaries
    $dir = Split-Path -Parent $exe -ErrorAction SilentlyContinue
    $fileW = Test-IWrite $exe
    $dirW  = Test-IWrite $dir
    if ($fileW -or $dirW) {
        [PSCustomObject]@{
            Service        = $k.PSChildName
            RunsAs         = $props.ObjectName
            StartMode      = $(if ($startMap.ContainsKey([int]$props.Start)) { $startMap[[int]$props.Start] } else { $props.Start })
            Binary         = $exe
            BinaryWritable = $fileW
            FolderWritable = $dirW
        }
    }
}

if (-not $hits) {
    Write-Host "[-] No non-Windows service binary is writable by you.`n" -ForegroundColor Yellow
} else {
    Write-Host "[+] WRITABLE service binaries found — hijack candidates:`n" -ForegroundColor Green
    $hits | Format-List
    Write-Host "[*] For each hit:" -ForegroundColor Cyan
    Write-Host "      RunsAs = LocalSystem  -> payload runs as SYSTEM"
    Write-Host "      StartMode = Auto      -> reboot triggers it (need SeShutdownPrivilege: whoami /priv)"
    Write-Host "      else try: net stop [svc]  /  Restart-Service [svc]"
    Write-Host ""
}