<#
    Find-WritableService-RDP.ps1
    -----------------------------
    For INTERACTIVE logons (RDP / console), where Get-CimInstance works fine.

    What it does (mirrors Listings 40-43 of the material):
      1. Lists every service and its binary path.
      2. Flags the "interesting" ones - binaries NOT under C:\Windows (user-installed, like XAMPP).
      3. Tests whether YOUR account can WRITE/MODIFY the binary or its folder.
      4. Prints the service account (LocalSystem = SYSTEM payoff) and start mode (Auto = reboot triggers it).

    Read-only. Does not touch, start, or stop anything.
    Run:  powershell -ep bypass -File .\Find-WritableService-RDP.ps1
#>

# --- who am I (my SID + every group SID I belong to) ---
$me   = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$mySids = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })

# --- rights that let me replace a file ---
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

function Get-Exe($pathName) {
    if (-not $pathName) { return $null }
    $p = $pathName.Trim()
    if ($p.StartsWith('"')) { $e = $p.IndexOf('"',1); if ($e -gt 1) { return $p.Substring(1,$e-1) } }
    $i = $p.IndexOf('.exe',[StringComparison]::OrdinalIgnoreCase)
    if ($i -ge 0) { return $p.Substring(0,$i+4) }
    return ($p -split '\s+')[0]
}

Write-Host "`n[*] Running as: $($me.Name)" -ForegroundColor Cyan
Write-Host "[*] Scanning services (RDP / interactive mode)...`n" -ForegroundColor Cyan

$svcs = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Select-Object Name, State, StartMode, StartName, PathName

if (-not $svcs) {
    Write-Host "[!] Get-CimInstance returned nothing. If you're on WinRM/bind shell, use the -WinRM script instead.`n" -ForegroundColor Red
    return
}

$hits = foreach ($s in $svcs) {
    $exe = Get-Exe $s.PathName
    if (-not $exe) { continue }
    # skip standard Windows binaries - not realistic targets
    if ($exe -like 'C:\Windows\*') { continue }
    $dir = Split-Path -Parent $exe -ErrorAction SilentlyContinue
    $fileW = Test-IWrite $exe
    $dirW  = Test-IWrite $dir
    if ($fileW -or $dirW) {
        [PSCustomObject]@{
            Service        = $s.Name
            RunsAs         = $s.StartName
            StartMode      = $s.StartMode
            State          = $s.State
            Binary         = $exe
            BinaryWritable = $fileW
            FolderWritable = $dirW
        }
    }
}

if (-not $hits) {
    Write-Host "[-] No non-Windows service binary is writable by you.`n" -ForegroundColor Yellow
} else {
    Write-Host "[+] WRITABLE service binaries found - hijack candidates:`n" -ForegroundColor Green
    $hits | Format-List
    Write-Host "[*] For each hit:" -ForegroundColor Cyan
    Write-Host "      RunsAs = LocalSystem  -> payload runs as SYSTEM"
    Write-Host "      StartMode = Auto      -> reboot triggers it (need SeShutdownPrivilege: whoami /priv)"
    Write-Host "      else try: net stop [svc]  /  Restart-Service [svc]"
    Write-Host ""
}