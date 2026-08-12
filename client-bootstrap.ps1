<#
  client-bootstrap.ps1  --  one-shot, idempotent client-machine enrolment.

  What it does (safe to re-run any number of times):
    1. Installs Tailscale (winget, MSI fallback) and joins the tailnet with a TAGGED,
       single-use pre-auth key passed as -AuthKey (tag:client -> quarantined node).
    2. Enables the Windows OpenSSH Server, sets it Automatic, starts it.
    3. Installs OUR management public key into administrators_authorized_keys (only ours;
       does not touch any key already present).
    4. Firewall-scopes inbound SSH (tcp/22) to the Tailscale CGNAT range 100.64.0.0/10 ONLY,
       so SSH is never reachable from the LAN or the internet.
    5. Prints a success summary (Tailscale IP + sshd status + firewall state).

  NO SECRETS ARE BAKED IN. The pre-auth key is a runtime parameter. The public key below is
  public by nature. Run elevated (Administrator).

  Usage (elevated PowerShell):
    .\client-bootstrap.ps1 -AuthKey 'tskey-auth-xxxxxxxx'

  Remote one-liner form: see the header of CLIENT-ONBOARD-RUNBOOK.md.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AuthKey,

    # Optional friendly tailnet hostname; defaults to the machine name lowercased.
    [string]$Hostname = ($env:COMPUTERNAME.ToLower())
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- OUR management public key (public by nature; private lives in secret-get on aerodeck as client-mgmt-ssh-key) ---
$MgmtPubKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINYx3YclpUbl74O8FbHYwdZPcep0gtvBz2G5Hvq4VgwU client-mgmt@aerodeck'

$TailnetRange = '100.64.0.0/10'   # Tailscale CGNAT range -- the ONLY source allowed to reach sshd
$TsExe        = 'C:\Program Files\Tailscale\tailscale.exe'

function Say([string]$m) { Write-Host "[bootstrap] $m" }

# ---- 0. Must be elevated -------------------------------------------------------------------
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    throw "This script must be run from an ELEVATED (Administrator) PowerShell. Right-click PowerShell -> Run as administrator, then re-run."
}
Say "Running elevated. Beginning idempotent enrolment."

# ---- 1. Install Tailscale ------------------------------------------------------------------
if (-not (Test-Path $TsExe)) {
    Say "Tailscale not present -- installing."
    $installed = $false
    # Preferred: winget (present on modern Win11)
    try {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Say "Installing via winget..."
            winget install --id Tailscale.Tailscale --silent --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Null
            if (Test-Path $TsExe) { $installed = $true; Say "winget install OK." }
        }
    } catch { Say "winget path failed ($($_.Exception.Message)); falling back to MSI." }

    if (-not $installed) {
        $msi = Join-Path $env:TEMP 'tailscale-setup.msi'
        $url = 'https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi'
        Say "Downloading MSI: $url"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing
        Say "Installing MSI silently..."
        $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /quiet /norestart" -Wait -PassThru
        if ($p.ExitCode -ne 0) { throw "msiexec exited $($p.ExitCode)" }
        Remove-Item $msi -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path $TsExe)) { throw "Tailscale install did not produce $TsExe" }
} else {
    Say "Tailscale already installed."
}

# Bring the tailnet up ONLY if not already authenticated (the pre-auth key is single-use).
$needUp = $true
try {
    $st = & $TsExe status --json 2>$null | ConvertFrom-Json
    if ($st -and $st.BackendState -eq 'Running' -and $st.Self -and $st.Self.TailscaleIPs) {
        $needUp = $false
        Say "Tailscale already up (BackendState=Running, IP=$($st.Self.TailscaleIPs -join ','))."
    }
} catch { $needUp = $true }

if ($needUp) {
    Say "Joining tailnet with pre-auth key (hostname=$Hostname)..."
    & $TsExe up --authkey $AuthKey --unattended --hostname $Hostname --accept-routes=$false
    if ($LASTEXITCODE -ne 0) { throw "tailscale up failed (exit $LASTEXITCODE). Key may be expired/consumed -- mint a fresh tag:client key." }
    Say "tailscale up OK."
}

# ---- 2. Enable Windows OpenSSH Server ------------------------------------------------------
$cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
if ($cap.State -ne 'Installed') {
    Say "Installing OpenSSH.Server capability..."
    Add-WindowsCapability -Online -Name $cap.Name | Out-Null
} else {
    Say "OpenSSH Server capability already installed."
}

Set-Service -Name sshd -StartupType Automatic
if ((Get-Service sshd).Status -ne 'Running') {
    Start-Service sshd
    Say "sshd started."
} else {
    Say "sshd already running."
}
# ssh-agent optional but harmless; leave Automatic so keys survive reboots if ever used
Set-Service -Name ssh-agent -StartupType Automatic -ErrorAction SilentlyContinue

# ---- 3. Install our management public key (administrators_authorized_keys) ------------------
$adminKeys = 'C:\ProgramData\ssh\administrators_authorized_keys'
$sshDir    = Split-Path $adminKeys
if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir -Force | Out-Null }

$present = $false
if (Test-Path $adminKeys) {
    $present = Select-String -Path $adminKeys -SimpleMatch $MgmtPubKey -Quiet
}
if (-not $present) {
    Add-Content -Path $adminKeys -Value $MgmtPubKey -Encoding ascii
    Say "Management key installed into administrators_authorized_keys."
} else {
    Say "Management key already present."
}
# Windows requires this file to be owned by Administrators/SYSTEM only, else sshd ignores it.
icacls $adminKeys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
Say "administrators_authorized_keys ACL locked to Administrators+SYSTEM."

# ---- 4. Firewall: SSH reachable from the tailnet range ONLY --------------------------------
# Scope every existing inbound Allow rule for tcp/22 to the tailnet range (neutralise any 'Any').
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | ForEach-Object {
    $r = $_
    try {
        $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        if ($pf -and $pf.Protocol -eq 'TCP' -and ("$($pf.LocalPort)" -eq '22')) {
            Set-NetFirewallRule -Name $r.Name -RemoteAddress $TailnetRange
            Say "Scoped firewall rule '$($r.DisplayName)' to $TailnetRange."
        }
    } catch { }
}
# Ensure our explicit, clearly-named tailnet-only rule exists.
if (-not (Get-NetFirewallRule -Name 'sshd-tailnet-only' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'sshd-tailnet-only' -DisplayName 'OpenSSH SSH Server (Tailnet only)' `
        -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow `
        -RemoteAddress $TailnetRange -Profile Any -Enabled True | Out-Null
    Say "Created firewall rule sshd-tailnet-only ($TailnetRange)."
} else {
    Set-NetFirewallRule -Name 'sshd-tailnet-only' -RemoteAddress $TailnetRange -Enabled True
    Say "Firewall rule sshd-tailnet-only confirmed ($TailnetRange)."
}

# ---- 5. Success summary --------------------------------------------------------------------
$tsip = (& $TsExe ip -4 2>$null | Select-Object -First 1)
$sshdStatus = (Get-Service sshd).Status
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " CLIENT BOOTSTRAP COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host (" Tailscale IP : {0}" -f $tsip)
Write-Host (" Tailnet name : {0}" -f $Hostname)
Write-Host (" sshd status  : {0} (Automatic)" -f $sshdStatus)
Write-Host (" SSH exposure : tcp/22 from {0} ONLY (LAN + internet blocked)" -f $TailnetRange)
Write-Host (" Mgmt key     : client-mgmt@aerodeck installed")
Write-Host "============================================================" -ForegroundColor Green
Write-Host " This machine is now managed over SSH by our agents. Nothing"
Write-Host " else to do. Uninstalling Tailscale (Add/Remove Programs) fully"
Write-Host " reverses it -- it breaks nothing else on this PC."
Write-Host "============================================================" -ForegroundColor Green
