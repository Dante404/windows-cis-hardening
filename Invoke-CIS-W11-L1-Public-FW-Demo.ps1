[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Assess', 'Plan', 'TestLGPO', 'Apply', 'Verify', 'Rollback')]
    [string] $Mode = 'Assess',
    [switch] $Approved,
    [string] $LgpoPath = (Join-Path $PSScriptRoot 'LGPO.exe'),
    [string] $OutputRoot = (Join-Path $env:ProgramData 'CIS-Section9.3-Demo'),
    [string] $RunDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:DemoId = 'CIS-W11-Standalone-v5-L1-9.3'
$script:LogPath = '%SystemRoot%\System32\LogFiles\Firewall\publicfw.log'
$root = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
$logging = $root + '\Logging'
$script:Controls = @(
    [pscustomobject]@{ Id = '9.3.1'; Name = 'Firewall state'; Key = $root; Value = 'EnableFirewall'; Type = 'DWORD'; Target = 1; Criterion = 'EQ1' },
    [pscustomobject]@{ Id = '9.3.2'; Name = 'Inbound connections'; Key = $root; Value = 'DefaultInboundAction'; Type = 'DWORD'; Target = 1; Criterion = 'EQ1' },
    [pscustomobject]@{ Id = '9.3.3'; Name = 'Display a notification'; Key = $root; Value = 'DisableNotifications'; Type = 'DWORD'; Target = 1; Criterion = 'EQ1' },
    [pscustomobject]@{ Id = '9.3.4'; Name = 'Log file name'; Key = $logging; Value = 'LogFilePath'; Type = 'SZ'; Target = $script:LogPath; Criterion = 'LOG' },
    [pscustomobject]@{ Id = '9.3.5'; Name = 'Log size KB'; Key = $logging; Value = 'LogFileSize'; Type = 'DWORD'; Target = 16384; Criterion = 'MIN16384' },
    [pscustomobject]@{ Id = '9.3.6'; Name = 'Log dropped packets'; Key = $logging; Value = 'LogDroppedPackets'; Type = 'DWORD'; Target = 1; Criterion = 'EQ1' },
    [pscustomobject]@{ Id = '9.3.7'; Name = 'Log successful connections'; Key = $logging; Value = 'LogSuccessfulConnections'; Type = 'DWORD'; Target = 1; Criterion = 'EQ1' }
)

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This operation requires elevated 64-bit Windows PowerShell 5.1.'
    }
    if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }
}

function Assert-LabMachine([switch]$SkipServiceCheck) {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    if ([int]$os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000) {
        throw 'Apply/Rollback is intentionally restricted to Windows 11 client systems.'
    }
    if ($computer.PartOfDomain) { throw 'Domain-joined machine: use the owning GPO, not this local-policy demo.' }
    $dsregcmd = Join-Path $env:WINDIR 'System32\dsregcmd.exe'
    if (Test-Path -LiteralPath $dsregcmd) {
        $dsregStatus = (& $dsregcmd /status 2>$null | Out-String)
        if ($dsregStatus -match '(?im)^\s*AzureAdJoined\s*:\s*YES\s*$' -or
            $dsregStatus -match '(?im)^\s*DomainJoined\s*:\s*YES\s*$') {
            throw 'Entra/domain-joined machine: use central management instead of this demo.'
        }
    }
    if (-not $SkipServiceCheck) {
        $service = Get-Service -Name MpsSvc -ErrorAction Stop
        if ($service.Status -ne 'Running') { throw 'Windows Defender Firewall service is not running; investigate first.' }
    }
}

function Get-PolicyValue($control) {
    $regPath = 'Registry::HKEY_LOCAL_MACHINE\' + $control.Key
    $regKey = Get-Item -LiteralPath $regPath -ErrorAction SilentlyContinue
    if ($null -eq $regKey -or $regKey.GetValueNames() -notcontains $control.Value) {
        return [pscustomobject]@{ Present = $false; Kind = ''; Data = $null }
    }
    $kind = [string]$regKey.GetValueKind($control.Value)
    $data = $regKey.GetValue($control.Value, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    return [pscustomobject]@{ Present = $true; Kind = $kind; Data = $data }
}

function Test-PolicyCriterion($control, $state) {
    if (-not $state.Present) { return $false }
    switch ($control.Criterion) {
        'EQ1' { return ($state.Kind -eq 'DWord' -and [int]$state.Data -eq 1) }
        'MIN16384' { return ($state.Kind -eq 'DWord' -and [int]$state.Data -ge 16384) }
        'LOG' { return ($state.Kind -in @('String', 'ExpandString') -and [string]$state.Data -match '(?i)[\\/][^\\/]+\.log$') }
    }
    return $false
}

function ConvertTo-Bool($value) { return ([string]$value -in @('True', '1', 'Yes')) }

function Get-EffectiveValue($control, $firewall) {
    switch ($control.Id) {
        '9.3.1' { return $firewall.Enabled }
        '9.3.2' { return $firewall.DefaultInboundAction }
        '9.3.3' { return $firewall.NotifyOnListen }
        '9.3.4' { return $firewall.LogFileName }
        '9.3.5' { return $firewall.LogMaxSizeKilobytes }
        '9.3.6' { return $firewall.LogBlocked }
        '9.3.7' { return $firewall.LogAllowed }
    }
}

function Test-EffectiveCriterion($control, $value) {
    switch ($control.Id) {
        '9.3.1' { return (ConvertTo-Bool $value) }
        '9.3.2' { return ([string]$value -eq 'Block') }
        '9.3.3' { return ([string]$value -in @('False', '0', 'No')) }
        '9.3.4' { return ([string]$value -match '(?i)[\\/][^\\/]+\.log$') }
        '9.3.5' { $size = 0; return ([int]::TryParse([string]$value, [ref]$size) -and $size -ge 16384) }
        '9.3.6' { return (ConvertTo-Bool $value) }
        '9.3.7' { return (ConvertTo-Bool $value) }
    }
    return $false
}

function ConvertTo-ReadableEffective($control, $value) {
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
        return '(not reported)'
    }
    switch ($control.Id) {
        '9.3.1' {
            if (ConvertTo-Bool $value) { return 'On' }
            if ([string]$value -in @('False', '0', 'No')) { return 'Off' }
        }
        '9.3.2' { return [string]$value }
        '9.3.3' {
            if (ConvertTo-Bool $value) { return 'Yes (notifications enabled)' }
            if ([string]$value -in @('False', '0', 'No')) { return 'No (notifications disabled)' }
        }
        '9.3.4' { return [string]$value }
        '9.3.5' { return ('{0} KB' -f $value) }
        '9.3.6' {
            if (ConvertTo-Bool $value) { return 'Yes' }
            if ([string]$value -in @('False', '0', 'No')) { return 'No' }
        }
        '9.3.7' {
            if (ConvertTo-Bool $value) { return 'Yes' }
            if ([string]$value -in @('False', '0', 'No')) { return 'No' }
        }
    }
    return [string]$value
}

function Get-ReadableTarget($control) {
    switch ($control.Id) {
        '9.3.1' { return 'On' }
        '9.3.2' { return 'Block (default)' }
        '9.3.3' { return 'No (notifications disabled)' }
        '9.3.4' { return 'Configured path ending in .log' }
        '9.3.5' { return '16384 KB or greater' }
        '9.3.6' { return 'Yes' }
        '9.3.7' { return 'Yes' }
    }
    return [string]$control.Target
}

function Get-PlannedChange($control, $policyPass, $effectivePass) {
    if ($policyPass -and $effectivePass) {
        return 'No change required.'
    }
    if ($policyPass -and -not $effectivePass) {
        return 'STOP: local policy already meets the target but is not effective. Investigate policy precedence.'
    }
    $action = ('Set local policy {0} ({1}) to {2} via LGPO' -f $control.Value, $control.Type, $control.Target)
    if ($effectivePass) {
        return ($action + '. Current effective behavior already meets the target; this enforces it explicitly.')
    }
    return ($action + '. Verify the resulting effective setting after application.')
}

function Get-Assessment {
    $firewall = Get-NetFirewallProfile -Name Public -PolicyStore ActiveStore -ErrorAction Stop
    foreach ($control in $script:Controls) {
        $current = Get-PolicyValue $control
        $effective = Get-EffectiveValue $control $firewall
        $policyPass = Test-PolicyCriterion $control $current
        $effectivePass = Test-EffectiveCriterion $control $effective
        $localPolicy = if ($current.Present) {
            ('{0}: {1}' -f $current.Kind, $current.Data)
        } else {
            '(not explicitly configured)'
        }
        $planType = if ($policyPass -and $effectivePass) {
            'NONE'
        } elseif ($policyPass -and -not $effectivePass) {
            'INVESTIGATE'
        } elseif ($effectivePass) {
            'ENFORCE'
        } else {
            'CHANGE'
        }
        [pscustomobject]@{
            CIS = $control.Id
            Setting = $control.Name
            CurrentEffective = ConvertTo-ReadableEffective $control $effective
            CisTarget = Get-ReadableTarget $control
            Result = if ($effectivePass) { 'MEETS CIS TARGET' } else { 'DOES NOT MEET CIS TARGET' }
            ExistingLocalPolicy = $localPolicy
            PlanType = $planType
            PlannedChange = Get-PlannedChange $control $policyPass $effectivePass
            ExpectedAfterApply = if ($planType -eq 'NONE') {
                'No change needed.'
            } elseif ($planType -eq 'INVESTIGATE') {
                'No automatic change. Investigate effective policy first.'
            } else {
                'Target should be enforced locally; re-assess and functionally test.'
            }
            PolicyPass = [bool]$policyPass
            EffectivePass = [bool]$effectivePass
            Status = if ($policyPass -and $effectivePass) { 'PASS' } else { 'REVIEW' }
        }
    }
}

function Show-Assessment($assessment, [ValidateSet('Assess', 'Plan', 'Verify')][string]$View = 'Assess') {
    $rows = @($assessment)
    Write-Host ''
    Write-Host 'CIS WINDOWS 11 STAND-ALONE v5.0.0 | LEVEL 1 | SECTION 9.3'
    $heading = switch ($View) {
        'Assess' { 'ASSESS | Current effective values and local policy state' }
        'Plan'   { 'PLAN | Proposed changes to local policy (no changes made)' }
        'Verify' { 'VERIFY | Effective settings and explicit local policy' }
    }
    Write-Host ('Public firewall profile - ' + $heading)
    Write-Host ('-' * 76)

    foreach ($item in $rows) {
        $effectiveLabel = if ($item.EffectivePass) { 'MEETS CIS TARGET' } else { 'NOT COMPLIANT' }
        $policyLabel = if ($item.PolicyPass) {
            'Explicit and meets target (' + $item.ExistingLocalPolicy + ')'
        } elseif ($item.ExistingLocalPolicy -eq '(not explicitly configured)') {
            'Not explicitly configured'
        } else {
            'Explicit but does not meet target (' + $item.ExistingLocalPolicy + ')'
        }
        Write-Host ''
        if ($View -eq 'Verify') {
            $verificationLabel = if ($item.Status -eq 'PASS') { 'VERIFIED' } else { 'REVIEW' }
            Write-Host ('[{0}] {1} | {2}' -f $item.CIS, $item.Setting, $verificationLabel)
        } else {
            Write-Host ('[{0}] {1} | {2}' -f $item.CIS, $item.Setting, $effectiveLabel)
        }
        Write-Host ('  Current      : {0}' -f $item.CurrentEffective)
        Write-Host ('  CIS target   : {0}' -f $item.CisTarget)

        if ($View -eq 'Plan') {
            $action = switch ($item.PlanType) {
                'NONE'        { 'NO CHANGE (already enforced)' }
                'INVESTIGATE' { 'STOP - INVESTIGATE POLICY PRECEDENCE' }
                'ENFORCE'     {
                    if ($item.CIS -eq '9.3.4') { 'STANDARDIZE LOG PATH (OPTIONAL DESIGN CHOICE)' }
                    else { 'ENFORCE COMPLIANT VALUE' }
                }
                default { 'CORRECT NONCOMPLIANT VALUE' }
            }
            Write-Host ('  Local policy : {0}' -f $policyLabel)
            Write-Host ('  Action       : {0}' -f $action)
            if ($item.PlanType -eq 'INVESTIGATE') {
                Write-Host '  Reason       : Explicit policy meets target but effective Windows settings do not.'
            } elseif ($item.PlanType -ne 'NONE') {
                $control = $script:Controls | Where-Object { $_.Id -eq $item.CIS } | Select-Object -First 1
                Write-Host ('  Would set    : {0} ({1}) = {2}' -f $control.Value, $control.Type, $control.Target)
                if ($item.CIS -eq '9.3.4' -and $item.EffectivePass) {
                    Write-Host '  Note         : Existing log path already meets CIS. This demo chooses a'
                    Write-Host '                 dedicated publicfw.log path for easier per-profile review.'
                    Write-Host '                 CIS does not require this filename. Review before Apply.'
                } elseif ($item.EffectivePass) {
                    Write-Host '  Note         : Effective value already meets CIS; local policy would enforce it.'
                }
            }
        } else {
            Write-Host ('  Effective    : {0}' -f $effectiveLabel)
            Write-Host ('  Local policy : {0}' -f $policyLabel)
        }
    }

    $matching = @($rows | Where-Object { $_.EffectivePass }).Count
    $explicit = @($rows | Where-Object { $_.PolicyPass }).Count
    Write-Host ''
    if ($View -eq 'Plan') {
        $corrections = @($rows | Where-Object { $_.PlanType -eq 'CHANGE' }).Count
        $standardize = @($rows | Where-Object { $_.PlanType -eq 'ENFORCE' -and $_.CIS -eq '9.3.4' }).Count
        $enforceOnly = @($rows | Where-Object { $_.PlanType -eq 'ENFORCE' -and $_.CIS -ne '9.3.4' }).Count
        $skip = @($rows | Where-Object { $_.PlanType -eq 'NONE' }).Count
        $investigate = @($rows | Where-Object { $_.PlanType -eq 'INVESTIGATE' }).Count
        Write-Host ('Summary: {0}/{1} meet CIS | {2} corrections | {3} enforcement | {4} log-path standardization | {5} skip | {6} investigate' -f $matching, $rows.Count, $corrections, $enforceOnly, $standardize, $skip, $investigate)
        Write-Host 'A compliant effective value can exist without an explicit local policy.'
    } elseif ($View -eq 'Verify') {
        $verified = @($rows | Where-Object { $_.Status -eq 'PASS' }).Count
        Write-Host ('Summary: {0}/{1} meet effective CIS target | {2}/{1} explicit policies meet target | {3}/{1} fully verified' -f $matching, $rows.Count, $explicit, $verified)
        Write-Host 'Verification checks Windows settings and local policy, not application compatibility.'
    } else {
        Write-Host ('Summary: {0}/{1} meet effective CIS target | {2}/{1} explicit policies meet target' -f $matching, $rows.Count, $explicit)
        Write-Host 'Assess reports current state only. Use -Mode Plan to see proposed changes.'
    }
}

function Invoke-Preview {
    # Scope this preference to the read-only preview. This avoids -WhatIf
    # affecting auto-imported PowerShell modules and ForEach-Object -MemberName.
    # This function contains no file writes or policy modifications, and Apply
    # -WhatIf returns from the script before its mutating branch is reached.
    $WhatIfPreference = $false
    if ($Mode -eq 'Apply') {
        Assert-Administrator
        Assert-LabMachine
        if (-not (Test-Path -LiteralPath $LgpoPath -PathType Leaf)) {
            throw ('Microsoft LGPO.exe not found: ' + $LgpoPath)
        }
    }
    $assessment = @(Get-Assessment)
    Show-Assessment $assessment -View Plan
    Write-Host ''
    Write-Host 'PREVIEW ONLY: No policy backup, LGPO import, gpupdate or file writes were performed.'
    if (@($assessment | Where-Object { $_.PlanType -eq 'INVESTIGATE' }).Count -gt 0) {
        Write-Host 'Apply would be blocked because one or more explicit policies are ineffective.'
    }
    Write-Host ''
}

function Save-Assessment($assessment, $directory, $fileName) {
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $assessment | Export-Csv -Path (Join-Path $directory $fileName) -NoTypeInformation -Encoding UTF8
}

function Write-LgpoText([string]$path, [object[]]$entries) {
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $entries) {
        $lines.Add('Computer')
        $lines.Add($entry.Key)
        $lines.Add($entry.Value)
        $lines.Add([string]$entry.Action)
        $lines.Add('')
    }
    $text = ($lines -join "`r`n") + "`r`n"
    if ($text -match '[^\x00-\x7F]') { throw 'LGPO example requires ASCII-only policy data for safe round-trip.' }
    [System.IO.File]::WriteAllText($path, $text, [System.Text.Encoding]::ASCII)
}

function Get-TargetEntry($control) {
    return [pscustomobject]@{
        Key = $control.Key
        Value = $control.Value
        Action = ('{0}:{1}' -f $control.Type, $control.Target)
    }
}

function Get-RestoreEntry($control, $state) {
    $action = 'CLEAR'
    if ($state.Present) {
        switch ($state.Kind) {
            'DWord' { $action = 'DWORD:' + [string]$state.Data; break }
            'String' { $action = 'SZ:' + [string]$state.Data; break }
            'ExpandString' { $action = 'EXSZ:' + [string]$state.Data; break }
            default { throw ('Cannot safely preserve original type {0} for {1}.' -f $state.Kind, $control.Id) }
        }
    }
    return [pscustomobject]@{ Key = $control.Key; Value = $control.Value; Action = $action }
}

function Invoke-Checked($exe, [string[]]$arguments, [string]$outputFile = '') {
    # Some versions of Windows PowerShell ISE report native stderr as errors
    # even when LGPO.exe returns exit code 0. Use the process exit code.
    $ErrorActionPreference = 'Continue'
    $output = @(& $exe @arguments 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw ('Command failed with exit {0}: {1} {2}. Output: {3}' -f $exitCode, $exe, ($arguments -join ' '), ($output -join ' | '))
    }
    if (-not [string]::IsNullOrWhiteSpace($outputFile)) {
        [System.IO.File]::WriteAllLines($outputFile, [string[]]$output, [System.Text.Encoding]::ASCII)
    }
    Write-Host ('Completed: {0} {1}' -f (Split-Path -Path $exe -Leaf), $arguments[0])
}

# A real -Mode Plan is a read-only preview. Apply -WhatIf is handled here,
# before any modification, so internal PowerShell cmdlets do not emit noisy
# inherited WhatIf messages or suppress planned control IDs.
$explicitWhatIf = ($PSBoundParameters.ContainsKey('WhatIf') -and [bool]$PSBoundParameters['WhatIf'])
if ($Mode -eq 'Plan' -or ($Mode -eq 'Apply' -and $explicitWhatIf)) {
    Invoke-Preview
    return
}

if ($Mode -eq 'Assess' -or $Mode -eq 'Verify') {
    $results = @(Get-Assessment)
    Show-Assessment $results -View $Mode
    if ($Mode -eq 'Verify' -and @($results | Where-Object { $_.Status -ne 'PASS' }).Count -gt 0) {
        throw 'One or more controls require review. Do not report this section as fully verified.'
    }
    if ($Mode -eq 'Assess') {
        Write-Host 'Read-only assessment complete. No settings were changed.'
    }
    return
}

# A syntax-only LGPO test. The same embedded control catalogue and text
# serializer used by Apply generate the input for LGPO.exe /r. Unlike /t,
# /r and /parse only create/read files and do not import local policy.
if ($Mode -eq 'TestLGPO') {
    if (-not (Test-Path -LiteralPath $LgpoPath -PathType Leaf)) {
        throw ('Microsoft LGPO.exe not found: ' + $LgpoPath)
    }
    $assessment = @(Get-Assessment)
    $mismatch = @($assessment | Where-Object { $_.PlanType -eq 'INVESTIGATE' })
    if ($mismatch.Count -gt 0) {
        throw 'Local policy is configured but ineffective for at least one control. Investigate before generating an apply plan.'
    }
    $planned = @($assessment | Where-Object { $_.PlanType -in @('CHANGE', 'ENFORCE') })
    $testDirectory = Join-Path $OutputRoot ('LGPO-Validation-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    New-Item -ItemType Directory -Path $testDirectory -Force | Out-Null

    $allEntries = @($script:Controls | ForEach-Object { Get-TargetEntry $_ })
    $fullText = Join-Path $testDirectory 'Full-Section-9.3.lgpo.txt'
    $fullPol = Join-Path $testDirectory 'Full-Section-9.3.pol'
    $fullParsed = Join-Path $testDirectory 'Full-Section-9.3-Parsed.txt'
    Write-LgpoText $fullText $allEntries
    Invoke-Checked $LgpoPath @('/r', $fullText, '/w', $fullPol)
    Invoke-Checked $LgpoPath @('/parse', '/m', $fullPol) $fullParsed
    if (-not (Test-Path -LiteralPath $fullPol -PathType Leaf) -or (Get-Item -LiteralPath $fullPol).Length -le 8) {
        throw 'LGPO did not generate a nonempty registry.pol for the full section.'
    }
    $parsedContent = Get-Content -LiteralPath $fullParsed -Raw
    foreach ($entry in $allEntries) {
        if ($parsedContent -notmatch [regex]::Escape($entry.Value)) {
            throw ('LGPO round-trip did not include expected policy value: ' + $entry.Value)
        }
    }

    if ($planned.Count -gt 0) {
        $deltaEntries = @(
            foreach ($item in $planned) {
                $control = $script:Controls | Where-Object { $_.Id -eq $item.CIS } | Select-Object -First 1
                Get-TargetEntry $control
            }
        )
        $deltaText = Join-Path $testDirectory 'Planned-Delta.lgpo.txt'
        $deltaPol = Join-Path $testDirectory 'Planned-Delta.pol'
        $deltaParsed = Join-Path $testDirectory 'Planned-Delta-Parsed.txt'
        Write-LgpoText $deltaText $deltaEntries
        Invoke-Checked $LgpoPath @('/r', $deltaText, '/w', $deltaPol)
        Invoke-Checked $LgpoPath @('/parse', '/m', $deltaPol) $deltaParsed
        if (-not (Test-Path -LiteralPath $deltaPol -PathType Leaf) -or (Get-Item -LiteralPath $deltaPol).Length -le 8) {
            throw 'LGPO did not generate a nonempty registry.pol for the planned delta.'
        }
        $deltaParsedContent = Get-Content -LiteralPath $deltaParsed -Raw
        foreach ($entry in $deltaEntries) {
            if ($deltaParsedContent -notmatch [regex]::Escape($entry.Value)) {
                throw ('LGPO delta round-trip did not include expected policy value: ' + $entry.Value)
            }
        }
    }
    Write-Host ''
    Write-Host ('Full section: {0} controls built and parsed by LGPO.exe.' -f $allEntries.Count)
    Write-Host ('Current planned delta: {0} controls.' -f $planned.Count)
    Write-Host ('Validation files: ' + $testDirectory)
    Write-Host 'NO POLICY CHANGES: LGPO /t, /m (import), gpupdate and policy backup were not executed.'
    Write-Host 'This checks LGPO text conversion only; it does not validate Apply or Rollback behavior.'
    return
}

if (-not $Approved) { throw 'Explicit -Approved is required for Apply and Rollback.' }
Assert-Administrator
Assert-LabMachine -SkipServiceCheck:($Mode -eq 'Rollback')
if (-not (Test-Path -LiteralPath $LgpoPath -PathType Leaf)) {
    throw ('Microsoft LGPO.exe not found: ' + $LgpoPath)
}

if ($Mode -eq 'Apply') {
    $before = @(Get-Assessment)
    Show-Assessment $before -View Plan
    $toChange = @($before | Where-Object { $_.Status -ne 'PASS' })
    if ($toChange.Count -eq 0) { Write-Host 'No change needed. All seven controls meet the effective target and explicit local-policy checks.'; return }
    $mismatch = @($before | Where-Object { $_.PolicyPass -and -not $_.EffectivePass })
    if ($mismatch.Count -gt 0) {
        throw 'Some settings are already configured but not effective. Resolve policy precedence before applying a local delta.'
    }
    Write-Host ('Proposed local policy changes: ' + (($toChange | ForEach-Object { $_.CIS }) -join ', '))
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Back up policy and apply section 9.3 L1 delta')) { return }

    $runPath = Join-Path $OutputRoot (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
    New-Item -ItemType Directory -Path $runPath -Force | Out-Null
    $backupPath = Join-Path $runPath 'LGPO-Backup'
    New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
    Save-Assessment $before $runPath 'Before.csv'
    $deltaEntries = @()
    $restoreEntries = @()
    $originalStates = @()
    foreach ($item in $toChange) {
        $control = $script:Controls | Where-Object { $_.Id -eq $item.CIS } | Select-Object -First 1
        $state = Get-PolicyValue $control
        $deltaEntries += (Get-TargetEntry $control)
        $restoreEntries += (Get-RestoreEntry $control $state)
        $originalStates += [pscustomobject]@{ CIS = $control.Id; Present = $state.Present; Kind = $state.Kind; Data = $state.Data }
    }
    $deltaFile = Join-Path $runPath 'Delta.lgpo.txt'
    $restoreFile = Join-Path $runPath 'Rollback.lgpo.txt'
    Write-LgpoText $deltaFile $deltaEntries
    Write-LgpoText $restoreFile $restoreEntries
    [pscustomobject]@{
        DemoId = $script:DemoId
        ComputerName = $env:COMPUTERNAME
        Created = (Get-Date).ToString('o')
        OriginalStates = $originalStates
        Changes = @($toChange | ForEach-Object { $_.CIS })
    } | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $runPath 'Run.json') -Encoding UTF8
    Write-Host ('Run directory (keep for rollback): ' + $runPath)
    Invoke-Checked $LgpoPath @('/b', $backupPath, '/n', 'Before CIS Section 9.3 demo')
    Invoke-Checked $LgpoPath @('/t', $deltaFile)
    Invoke-Checked 'gpupdate.exe' @('/target:computer', '/force')
    $after = @(Get-Assessment)
    Save-Assessment $after $runPath 'After.csv'
    Show-Assessment $after -View Verify
    if (@($after | Where-Object { $_.Status -ne 'PASS' }).Count -gt 0) {
        throw ('Verification is not fully passing. Inspect results and use targeted rollback: ' + $runPath)
    }
    Write-Host 'All seven checks pass in policy and effective-state assessment. Functional testing is still required.'
    return
}

if ($Mode -eq 'Rollback') {
    if ([string]::IsNullOrWhiteSpace($RunDirectory)) { throw 'Specify -RunDirectory from a previous Apply run.' }
    $metadataFile = Join-Path $RunDirectory 'Run.json'
    $restoreFile = Join-Path $RunDirectory 'Rollback.lgpo.txt'
    if (-not (Test-Path -LiteralPath $metadataFile) -or -not (Test-Path -LiteralPath $restoreFile)) {
        throw 'Run.json or Rollback.lgpo.txt is missing. Do not guess a rollback.'
    }
    $metadata = Get-Content -LiteralPath $metadataFile -Raw | ConvertFrom-Json
    if ($metadata.DemoId -ne $script:DemoId -or $metadata.ComputerName -ne $env:COMPUTERNAME) {
        throw 'Rollback metadata is not from this script on this computer.'
    }
    Write-Host ('Targeted rollback of: ' + ((@($metadata.Changes)) -join ', '))
    if ((Get-Content -LiteralPath $restoreFile -Raw) -match '(?m)^DELETE\s*$') {
        throw 'This rollback file contains legacy DELETE actions. Verify and regenerate with CLEAR before rollback.'
    }
    foreach ($saved in @($metadata.OriginalStates)) {
        $control = $script:Controls | Where-Object { $_.Id -eq $saved.CIS } | Select-Object -First 1
        $current = Get-PolicyValue $control
        $matchesApplied = ($current.Present -and [string]$current.Data -ceq [string]$control.Target)
        $matchesOriginal = if (-not [bool]$saved.Present) {
            (-not $current.Present)
        } else {
            ($current.Present -and $current.Kind -eq [string]$saved.Kind -and [string]$current.Data -ceq [string]$saved.Data)
        }
        if (-not $matchesApplied -and -not $matchesOriginal) {
            throw ('Current policy for {0} differs from both the original and this run''s target. Manual review is required.' -f $saved.CIS)
        }
    }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restore previous section 9.3 local policy entries')) { return }
    Invoke-Checked $LgpoPath @('/t', $restoreFile)
    Invoke-Checked 'gpupdate.exe' @('/target:computer', '/force')
    $verification = @()
    foreach ($saved in @($metadata.OriginalStates)) {
        $control = $script:Controls | Where-Object { $_.Id -eq $saved.CIS } | Select-Object -First 1
        $current = Get-PolicyValue $control
        $matched = if (-not [bool]$saved.Present) {
            (-not $current.Present)
        } else {
            ($current.Present -and $current.Kind -eq [string]$saved.Kind -and [string]$current.Data -ceq [string]$saved.Data)
        }
        $verification += [pscustomobject]@{ CIS = $saved.CIS; OriginalPolicyRestored = [bool]$matched }
    }
    $verification | Export-Csv -Path (Join-Path $RunDirectory 'Rollback-Verification.csv') -NoTypeInformation -Encoding UTF8
    Save-Assessment @(Get-Assessment) $RunDirectory 'After-Rollback.csv'
    $verification | Format-Table -AutoSize | Out-String | Write-Host
    if (@($verification | Where-Object { -not $_.OriginalPolicyRestored }).Count -gt 0) {
        throw 'One or more original local policy registry values were not restored. Investigate before continuing.'
    }
    Write-Host 'Previous scoped local policy values restored; validate networking and application behavior.'
}