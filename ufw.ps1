<#
    UFW for Windows Server (2019, 2022, 2025)
    Emulates Linux UFW (Uncomplicated Firewall) using Windows Defender Firewall cmdlets.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Command,

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

# -------------------------------------------------------------
# 1. Administrator Check
# -------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] Administrator privileges are required. Please run your shell as Administrator." -ForegroundColor Red
    exit 1
}

# -------------------------------------------------------------
# 2. Service Aliases Dictionary
# -------------------------------------------------------------
$Services = @{
    "ssh"        = @{ Port = "22"; Proto = "TCP" }
    "http"       = @{ Port = "80"; Proto = "TCP" }
    "https"      = @{ Port = "443"; Proto = "TCP" }
    "ftp"        = @{ Port = "21"; Proto = "TCP" }
    "dns"        = @{ Port = "53"; Proto = "BOTH" }
    "rdp"        = @{ Port = "3389"; Proto = "TCP" }
    "smb"        = @{ Port = "445"; Proto = "TCP" }
    "telnet"     = @{ Port = "23"; Proto = "TCP" }
    "smtp"       = @{ Port = "25"; Proto = "TCP" }
    "submission" = @{ Port = "587"; Proto = "TCP" }
    "smtps"      = @{ Port = "465"; Proto = "TCP" }
    "pop3"       = @{ Port = "110"; Proto = "TCP" }
    "pop3s"      = @{ Port = "995"; Proto = "TCP" }
    "imap"       = @{ Port = "143"; Proto = "TCP" }
    "imaps"      = @{ Port = "993"; Proto = "TCP" }
    "mysql"      = @{ Port = "3306"; Proto = "TCP" }
    "mssql"      = @{ Port = "1433"; Proto = "TCP" }
    "postgres"   = @{ Port = "5432"; Proto = "TCP" }
    "mongodb"    = @{ Port = "27017"; Proto = "TCP" }
    "redis"      = @{ Port = "6379"; Proto = "TCP" }
    "ntp"        = @{ Port = "123"; Proto = "UDP" }
    "openvpn"    = @{ Port = "1194"; Proto = "UDP" }
    "wireguard"  = @{ Port = "51820"; Proto = "UDP" }
}

# -------------------------------------------------------------
# 3. Parser Helpers
# -------------------------------------------------------------
function Normalize-PortRange([string]$p) {
    if (-not $p) { return "" }
    return $p.Replace(':', '-')
}

function Test-ValidPort([string]$portStr) {
    if (-not $portStr) { return $true }
    if ($portStr -match '^(\d+)-(\d+)$') {
        $p1 = [long]$matches[1]
        $p2 = [long]$matches[2]
        return ($p1 -ge 1 -and $p1 -le 65535 -and $p2 -ge 1 -and $p2 -le 65535 -and $p1 -le $p2)
    }
    if ($portStr -match '^\d+$') {
        $p = [long]$portStr
        return ($p -ge 1 -and $p -le 65535)
    }
    return $false
}

function Parse-UfwRuleArgs([string[]]$argsList) {
    if (-not $argsList -or $argsList.Count -eq 0) {
        return $null
    }

    $direction = "Inbound"
    $protocol = "BOTH"
    $localPort = ""
    $remoteAddress = "Any"
    $localAddress = "Any"
    $comment = ""

    $i = 0
    $tokens = @()
    while ($i -lt $argsList.Count) {
        $arg = $argsList[$i]
        if ($arg.ToLower() -eq "comment" -and ($i + 1) -lt $argsList.Count) {
            $comment = $argsList[$i + 1]
            $i += 2
            continue
        }
        $tokens += $arg
        $i++
    }

    if ($tokens.Count -eq 0) { return $null }

    # Optionale Richtung im ersten Token: "in" oder "out"
    $idx = 0
    if ($tokens[$idx].ToLower() -in @("in", "inbound")) {
        $direction = "Inbound"
        $idx++
    } elseif ($tokens[$idx].ToLower() -in @("out", "outbound")) {
        $direction = "Outbound"
        $idx++
    }

    # Restliche Tokens parsen
    while ($idx -lt $tokens.Count) {
        $token = $tokens[$idx].ToLower()

        if ($token -eq "proto") {
            if ($idx + 1 -lt $tokens.Count) {
                $protocol = $tokens[$idx + 1].ToUpper()
                $idx += 2
                continue
            }
        }
        elseif ($token -eq "from") {
            if ($idx + 1 -lt $tokens.Count) {
                $remoteAddress = $tokens[$idx + 1]
                $idx += 2
                continue
            }
        }
        elseif ($token -eq "to") {
            if ($idx + 1 -lt $tokens.Count) {
                $localAddress = $tokens[$idx + 1]
                $idx += 2
                continue
            }
        }
        elseif ($token -eq "port") {
            if ($idx + 1 -lt $tokens.Count) {
                $localPort = Normalize-PortRange $tokens[$idx + 1]
                $idx += 2
                continue
            }
        }
        elseif ($token -in @("any", "anywhere")) {
            $idx++
            continue
        }
        # Fallback 1: Service Alias (z.B. ssh, http, rdp)
        elseif ($Services.ContainsKey($token)) {
            $svc = $Services[$token]
            $localPort = $svc.Port
            if ($protocol -eq "BOTH") {
                $protocol = $svc.Proto
            }
            $idx++
            continue
        }
        # Fallback 2: Port/Proto Kurzform (z.B. 80/tcp, 7000:7010/udp)
        elseif ($token -match '^([\d\:\-]+)\/(tcp|udp)$') {
            $localPort = Normalize-PortRange $matches[1]
            $protocol = $matches[2].ToUpper()
            $idx++
            continue
        }
        # Fallback 3: Nur Port (z.B. 80 oder 7000:7010)
        elseif ($token -match '^([\d\:\-]+)$') {
            $localPort = Normalize-PortRange $token
            if ($idx + 1 -lt $tokens.Count -and $tokens[$idx + 1].ToLower() -match '^(tcp|udp)$') {
                $protocol = $tokens[$idx + 1].ToUpper()
                $idx++
            }
            $idx++
            continue
        }
        else {
            $idx++
        }
    }

    # Validate port range (1-65535)
    if ($localPort -and -not (Test-ValidPort $localPort)) {
        Write-Host "[ERROR] Invalid port or port range: '$localPort'. Valid ports are 1 to 65535." -ForegroundColor Red
        return $null
    }

    # Wenn kein Port spezifiziert wurde und RemoteAddress Any ist -> unvollständig
    if (-not $localPort -and $remoteAddress -eq "Any") {
        return $null
    }

    return [PSCustomObject]@{
        Direction     = $direction
        Protocol      = $protocol
        LocalPort     = $localPort
        RemoteAddress = $remoteAddress
        LocalAddress  = $localAddress
        Comment       = $comment
    }
}

# -------------------------------------------------------------
# 4. Rule Execution
# -------------------------------------------------------------
function Add-UfwFirewallRule($parsed, [string]$action) {
    $protocols = if ($parsed.Protocol -eq "BOTH") {
        if (-not $parsed.LocalPort) { @("Any") } else { @("TCP", "UDP") }
    } else {
        @($parsed.Protocol)
    }

    $actionCmd = if ($action -match '^(deny|block)$') { "Block" } else { "Allow" }
    $dirShort = if ($parsed.Direction -eq "Inbound") { "IN" } else { "OUT" }

    foreach ($p in $protocols) {
        $portId = if ($parsed.LocalPort) { $parsed.LocalPort.Replace('-', '_') } else { "ANY" }
        $fromId = if ($parsed.RemoteAddress -ne "Any") { $parsed.RemoteAddress.Replace('/', '_').Replace('.', '_').Replace(':', '_') } else { "ANY" }
        $ruleName = "UFW-$dirShort-$actionCmd-$p-P$portId-F$fromId"
        
        $portDisplay = if ($parsed.LocalPort) { "$($parsed.LocalPort)/$p" } else { "$p" }
        $displayName = "UFW: $actionCmd $dirShort $portDisplay (From: $($parsed.RemoteAddress))"

        # Vorhandene Regel mit demselben Namen entfernen
        Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule

        $splat = @{
            Name        = $ruleName
            DisplayName = $displayName
            Description = if ($parsed.Comment) { "UFW: $($parsed.Comment)" } else { "Managed by UFW Windows CLI" }
            Direction   = $parsed.Direction
            Action      = $actionCmd
            Enabled     = "True"
        }

        if ($p -ne "Any") {
            $splat["Protocol"] = $p
        }
        if ($parsed.LocalPort) {
            $splat["LocalPort"] = $parsed.LocalPort
        }
        if ($parsed.RemoteAddress -ne "Any") {
            $splat["RemoteAddress"] = $parsed.RemoteAddress
        }

        try {
            New-NetFirewallRule @splat -ErrorAction Stop | Out-Null
            $color = if ($actionCmd -eq "Allow") { "Green" } else { "Magenta" }
            $fromInfo = if ($parsed.RemoteAddress -ne "Any") { " from $($parsed.RemoteAddress)" } else { "" }
            Write-Host "Rule added ($($parsed.Direction)): $portDisplay$fromInfo [$actionCmd]" -ForegroundColor $color
        } catch {
            Write-Host "[ERROR] Failed to add firewall rule: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Remove-UfwFirewallRule($parsed, [string]$action = "") {
    $protocols = if ($parsed.Protocol -eq "BOTH") {
        if (-not $parsed.LocalPort) { @("Any") } else { @("TCP", "UDP") }
    } else {
        @($parsed.Protocol)
    }

    $deletedCount = 0
    $allRules = Get-NetFirewallRule -Name "UFW-*" -ErrorAction SilentlyContinue

    foreach ($r in $allRules) {
        $portFilter = $r | Get-NetFirewallPortFilter
        $addrFilter = $r | Get-NetFirewallAddressFilter

        $matchProto = ($protocols -contains "Any") -or ($protocols -contains $portFilter.Protocol)
        $matchPort = (-not $parsed.LocalPort) -or ($portFilter.LocalPort -eq $parsed.LocalPort)
        $matchFrom = ($parsed.RemoteAddress -eq "Any") -or ($addrFilter.RemoteAddress -contains $parsed.RemoteAddress)
        $matchDir  = ($r.Direction.ToString().ToLower() -eq $parsed.Direction.ToLower())

        if ($matchProto -and $matchPort -and $matchFrom -and $matchDir) {
            $r | Remove-NetFirewallRule
            Write-Host "Rule deleted: $($r.DisplayName)" -ForegroundColor Yellow
            $deletedCount++
        }
    }

    if ($deletedCount -eq 0) {
        Write-Host "Could not find any matching UFW rule to delete." -ForegroundColor DarkYellow
    }
}

function Remove-UfwByIndex([int]$index) {
    $rules = @(Get-NetFirewallRule -Name "UFW-*" -ErrorAction SilentlyContinue | Sort-Object -Property CreationTime, Name)
    if ($rules.Count -eq 0) {
        Write-Host "No active UFW rules found." -ForegroundColor DarkGray
        return
    }

    if ($index -lt 1 -or $index -gt $rules.Count) {
        Write-Host "[ERROR] Invalid rule index: $index. Valid range is 1 to $($rules.Count)." -ForegroundColor Red
        return
    }

    $targetRule = $rules[$index - 1]
    $confirm = Read-Host "Deleting [$index] '$($targetRule.DisplayName)'. Proceed with operation (y|n)?"
    if ($confirm -match '^(y|yes)$') {
        $targetRule | Remove-NetFirewallRule
        Write-Host "Rule [$index] deleted." -ForegroundColor Yellow
    } else {
        Write-Host "Aborted." -ForegroundColor DarkGray
    }
}

function Show-UfwStatus([bool]$Numbered = $false) {
    $profile = Get-NetFirewallProfile -Profile Public,Domain,Private
    $fwEnabled = ($profile | Where-Object { $_.Enabled -eq "True" }).Count -gt 0
    $statusText = if ($fwEnabled) { "active" } else { "inactive" }
    $statusColor = if ($fwEnabled) { "Green" } else { "Red" }

    Write-Host "Status: " -NoNewline
    Write-Host "$statusText" -ForegroundColor $statusColor
    Write-Host ""

    $rules = @(Get-NetFirewallRule -Name "UFW-*" -ErrorAction SilentlyContinue | Sort-Object -Property CreationTime, Name)
    if ($rules.Count -eq 0) {
        Write-Host "No rules configured." -ForegroundColor DarkGray
        return
    }

    $idx = 1
    $rows = foreach ($r in $rules) {
        $portFilter = $r | Get-NetFirewallPortFilter
        $addrFilter = $r | Get-NetFirewallAddressFilter

        $to = if ($portFilter.LocalPort) {
            "$($portFilter.LocalPort)/$($portFilter.Protocol.ToLower())"
        } else {
            if ($portFilter.Protocol -and $portFilter.Protocol -ne "Any") { "$($portFilter.Protocol.ToLower())" } else { "Anywhere" }
        }

        $action = $r.Action.ToString().ToUpper()
        $dir = if ($r.Direction -eq "Inbound") { "IN" } else { "OUT" }
        $actionDisplay = "$action $dir"

        $from = if ($addrFilter.RemoteAddress -and $addrFilter.RemoteAddress -notcontains "Any") {
            $addrFilter.RemoteAddress -join ", "
        } else {
            "Anywhere"
        }

        if ($Numbered) {
            [PSCustomObject]@{
                "["   = "[$idx]"
                "To"     = $to
                "Action" = $actionDisplay
                "From"   = $from
            }
        } else {
            [PSCustomObject]@{
                "To"     = $to
                "Action" = $actionDisplay
                "From"   = $from
            }
        }
        $idx++
    }

    $rows | Format-Table -AutoSize
}

# -------------------------------------------------------------
# 5. Command Dispatcher
# -------------------------------------------------------------
$cmdLower = if ($Command) { $Command.ToLower() } else { "help" }

switch ($cmdLower) {
    "allow" {
        $parsed = Parse-UfwRuleArgs $Arguments
        if (-not $parsed) {
            Write-Host "Usage: ufw allow [in|out] [proto <tcp|udp>] [from <ip>] [to any] [port <port>]" -ForegroundColor Yellow
            Write-Host "       ufw allow <port>[/protocol] | ufw allow <service>" -ForegroundColor DarkGray
            Write-Host "Examples: ufw allow 80/tcp | ufw allow ssh | ufw allow from 192.168.1.100 to any port 22 proto tcp" -ForegroundColor DarkGray
            exit 1
        }
        Add-UfwFirewallRule $parsed "Allow"
    }

    "deny" {
        $parsed = Parse-UfwRuleArgs $Arguments
        if (-not $parsed) {
            Write-Host "Usage: ufw deny [in|out] [proto <tcp|udp>] [from <ip>] [port <port>]" -ForegroundColor Yellow
            Write-Host "       ufw deny <port>[/protocol] | ufw deny <service>" -ForegroundColor DarkGray
            exit 1
        }
        Add-UfwFirewallRule $parsed "Block"
    }

    "reject" {
        $parsed = Parse-UfwRuleArgs $Arguments
        if (-not $parsed) {
            Write-Host "Usage: ufw reject <port>[/protocol]" -ForegroundColor Yellow
            exit 1
        }
        Add-UfwFirewallRule $parsed "Block"
    }

    "delete" {
        if (-not $Arguments -or $Arguments.Count -eq 0) {
            Write-Host "Usage: ufw delete <number> | ufw delete [allow|deny] <rule...>" -ForegroundColor Yellow
            exit 1
        }

        # Check if first arg is an integer index: ufw delete 3
        if ($Arguments[0] -match '^\d+$') {
            Remove-UfwByIndex ([int]$Arguments[0])
            break
        }

        # Check if first arg is allow/deny: ufw delete allow 80/tcp
        $actionArg = ""
        $remainingArgs = $Arguments
        if ($Arguments[0].ToLower() -in @("allow", "deny", "reject")) {
            $actionArg = $Arguments[0]
            $remainingArgs = $Arguments[1..($Arguments.Count - 1)]
        }

        $parsed = Parse-UfwRuleArgs $remainingArgs
        if (-not $parsed) {
            Write-Host "Could not parse rule arguments for deletion." -ForegroundColor Red
            exit 1
        }
        Remove-UfwFirewallRule $parsed $actionArg
    }

    "status" {
        $isNumbered = ($Arguments -and $Arguments.Count -ge 1 -and $Arguments[0].ToLower() -eq "numbered")
        Show-UfwStatus -Numbered $isNumbered
    }

    "enable" {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Write-Host "Firewall is active and enabled on system startup." -ForegroundColor Green
    }

    "disable" {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
        Write-Host "Firewall stopped and disabled on system startup." -ForegroundColor Red
    }

    "reload" {
        Write-Host "Firewall reloaded." -ForegroundColor Green
    }

    "reset" {
        $confirm = Read-Host "Resetting all UFW rules to default. Proceed with operation (y|n)?"
        if ($confirm -match '^(y|yes)$') {
            $rules = Get-NetFirewallRule -Name "UFW-*" -ErrorAction SilentlyContinue
            if ($rules) {
                $rules | Remove-NetFirewallRule
                Write-Host "All UFW rules deleted." -ForegroundColor Yellow
            } else {
                Write-Host "No UFW rules to delete." -ForegroundColor DarkGray
            }
        } else {
            Write-Host "Aborted." -ForegroundColor DarkGray
        }
    }

    "version" {
        Write-Host "ufw (Windows Server Edition) 1.0.1" -ForegroundColor Cyan
        Write-Host "Emulating Linux UFW for Windows Server 2019 / 2022 / 2025" -ForegroundColor DarkGray
    }

    "default" {
        if ($Arguments -and $Arguments.Count -ge 2) {
            $direction = $Arguments[1].ToLower()
            $action = $Arguments[0].ToLower()
            $winDir = if ($direction -in @("incoming", "inbound", "in")) { "Inbound" } else { "Outbound" }
            $winAction = if ($action -in @("allow")) { "Allow" } else { "Block" }
            
            if ($winDir -eq "Inbound") {
                Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction $winAction
            } else {
                Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction $winAction
            }
            Write-Host "Default $direction policy changed to '$action'" -ForegroundColor Green
        } else {
            Write-Host "Usage: ufw default [allow|deny] [incoming|outgoing]" -ForegroundColor Yellow
        }
    }

    default {
        Write-Host "UFW for Windows Server (Version 1.0.1)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Usage: ufw [--version] <command> [arguments]" -ForegroundColor White
        Write-Host ""
        Write-Host "Commands:" -ForegroundColor Yellow
        Write-Host "  enable                          enables the firewall"
        Write-Host "  disable                         disables the firewall"
        Write-Host "  default ARG                     set default policy (e.g. ufw default deny incoming)"
        Write-Host "  reload                          reloads firewall"
        Write-Host "  reset                           removes all UFW firewall rules"
        Write-Host "  status                          shows firewall status and rules"
        Write-Host "  status numbered                 shows rules with order index"
        Write-Host "  allow <rule>                    adds an allow rule"
        Write-Host "  deny <rule>                     adds a deny rule"
        Write-Host "  delete <number>                 deletes rule by index number"
        Write-Host "  delete [allow|deny] <rule>      deletes specific rule by definition"
        Write-Host "  version                         displays version info"
        Write-Host ""
        Write-Host "Examples:" -ForegroundColor Yellow
        Write-Host "  ufw allow 80/tcp"
        Write-Host "  ufw allow 25565"
        Write-Host "  ufw allow 7000:7010/udp"
        Write-Host "  ufw allow ssh"
        Write-Host "  ufw allow rdp"
        Write-Host "  ufw allow from 192.168.1.0/24 to any port 22 proto tcp"
        Write-Host "  ufw deny from 10.0.0.5"
        Write-Host "  ufw status numbered"
        Write-Host "  ufw delete 2"
    }
}