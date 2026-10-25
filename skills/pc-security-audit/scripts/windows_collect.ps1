# Read-only native Windows metadata. PowerShell 5.1+/7+, trusted interpreter.
# No process arguments, credentials, scans, repairs, elevation or installation.
[CmdletBinding()]
param([ValidateRange(1,1000)][int]$Limit = 200,
      [ValidateRange(1,30)][int]$CheckTimeoutSeconds = 8,
      [ValidateRange(10,600)][int]$TimeBudgetSeconds = 110)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    @{status='NOT RUN';reason='Requires native Windows';verdict='NOT ASSESSED'} | ConvertTo-Json
    exit 2
}
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
# Limit module discovery to trusted system installation paths. Admin compromise
# or a replaced interpreter/system module can still falsify every result.
$systemModules = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\Modules'
$env:PSModulePath = (Join-Path $PSHOME 'Modules') + ';' + $systemModules
$checks = New-Object System.Collections.Generic.List[object]
$collector = {
    param([string]$Name,[int]$RowLimit)
    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $systemModules = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\Modules'
    $env:PSModulePath = (Join-Path $PSHOME 'Modules') + ';' + $systemModules
    function Rows {
        param([object[]]$Values)
        @{rows=@($Values | Select-Object -First $RowLimit)
          partial=(@($Values).Count -gt $RowLimit);limit=$RowLimit
          coverage='Current bounded sample, not historical coverage'}
    }
    switch ($Name) {
        'os_and_memory' { Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 5 |
            Select-Object Version,BuildNumber,OSArchitecture,
            @{n='LastBootUpTime';e={if ($_.LastBootUpTime -is [DateTime]) {$_.LastBootUpTime.ToUniversalTime().ToString('o')}}},
            TotalVisibleMemorySize,FreePhysicalMemory }
        'storage' { Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -OperationTimeoutSec 5 |
            Select-Object DeviceID,FileSystem,Size,FreeSpace }
        'defender' { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,
            RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,IsTamperProtected,
            @{n='AntivirusSignatureLastUpdated';e={if ($_.AntivirusSignatureLastUpdated -is [DateTime] -and $_.AntivirusSignatureLastUpdated.Year -gt 1970) {$_.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')}}},
            @{n='QuickScanEndTime';e={if ($_.QuickScanEndTime -is [DateTime] -and $_.QuickScanEndTime.Year -gt 1970) {$_.QuickScanEndTime.ToUniversalTime().ToString('o')}}},
            @{n='FullScanEndTime';e={if ($_.FullScanEndTime -is [DateTime] -and $_.FullScanEndTime.Year -gt 1970) {$_.FullScanEndTime.ToUniversalTime().ToString('o')}}},
            @{n='AMRunningMode';e={$_.AMRunningMode.ToString()}} }
        'defender_exclusion_counts' {
            $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
            $principal=New-Object Security.Principal.WindowsPrincipal($identity)
            if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Not elevated' }
            $pref=Get-MpPreference
            foreach ($v in @($pref.ExclusionPath)+@($pref.ExclusionProcess)+@($pref.ExclusionExtension)) {
                if ($null -ne $v -and $v -match '^(N/A|Access denied|Must be an administrator)') { throw 'Unavailable' }
            }
            @{path_count=@($pref.ExclusionPath | Where-Object {$null -ne $_}).Count
              process_count=@($pref.ExclusionProcess | Where-Object {$null -ne $_}).Count
              extension_count=@($pref.ExclusionExtension | Where-Object {$null -ne $_}).Count
              meaning='Counts only; no exclusion values emitted'}
        }
        'firewall' { Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,
            @{n='Enabled';e={$_.Enabled.ToString()}},
            @{n='DefaultInboundAction';e={$_.DefaultInboundAction.ToString()}},
            @{n='DefaultOutboundAction';e={$_.DefaultOutboundAction.ToString()}} }
        'secure_boot' { @{enabled=(Confirm-SecureBootUEFI)} }
        'bitlocker_status' { Get-BitLockerVolume | Select-Object MountPoint,
            @{n='VolumeType';e={$_.VolumeType.ToString()}},@{n='VolumeStatus';e={$_.VolumeStatus.ToString()}},
            @{n='ProtectionStatus';e={$_.ProtectionStatus.ToString()}},
            @{n='EncryptionMethod';e={$_.EncryptionMethod.ToString()}},EncryptionPercentage }
        'process_metadata' { Rows @(Get-Process | Sort-Object WorkingSet64 -Descending |
            Select-Object -First ($RowLimit+1) Id,ProcessName,WorkingSet64,CPU) }
        'scheduled_task_metadata' { Rows @(Get-ScheduledTask | Select-Object -First ($RowLimit+1) TaskName,
            TaskPath,@{n='State';e={$_.State.ToString()}}) }
        'service_metadata' { Rows @(Get-Service | Select-Object -First ($RowLimit+1) Name,
            @{n='Status';e={$_.Status.ToString()}},@{n='StartType';e={$_.StartType.ToString()}}) }
        'network_tcp' { Rows @(Get-NetTCPConnection | Select-Object -First ($RowLimit+1) LocalAddress,
            @{n='State';e={$_.State.ToString()}},LocalPort,OwningProcess) }
        'network_udp' { Rows @(Get-NetUDPEndpoint | Select-Object -First ($RowLimit+1) LocalAddress,LocalPort,OwningProcess) }
        'wmi_persistence_counts' {
            # Request keys only: do not retrieve command templates or script bodies.
            @{filters=(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -KeyOnly -OperationTimeoutSec 5 | Measure-Object).Count
              command_consumers=(Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -KeyOnly -OperationTimeoutSec 5 | Measure-Object).Count
              script_consumers=(Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -KeyOnly -OperationTimeoutSec 5 | Measure-Object).Count
              bindings=(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -KeyOnly -OperationTimeoutSec 5 | Measure-Object).Count}
        }
    }
}
$timer = [Diagnostics.Stopwatch]::StartNew()
foreach ($name in @('os_and_memory','storage','defender','defender_exclusion_counts',
    'firewall','secure_boot','bitlocker_status','process_metadata','scheduled_task_metadata',
    'service_metadata','network_tcp','network_udp','wmi_persistence_counts')) {
    $job=$null
    try {
        if ($timer.Elapsed.TotalSeconds -ge $TimeBudgetSeconds) { throw 'Overall collection budget exhausted' }
        # Timeouts stop only this collector's child jobs, never user processes.
        $job=Start-Job -ScriptBlock $collector -ArgumentList $name,$Limit
        $remaining = [Math]::Min($CheckTimeoutSeconds, $TimeBudgetSeconds - $timer.Elapsed.TotalSeconds)
        if ($remaining -lt 1) { throw 'Overall collection budget exhausted' }
        $done=Wait-Job -Job $job -Timeout ([int][Math]::Floor($remaining))
        if ($null -eq $done -or $job.State -ne 'Completed') { throw 'Unavailable or timed out' }
        $data=@(Receive-Job -Job $job -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null)
        $collection='PASS'; $protection='NOT ASSESSED'
        if ($data.Count -eq 0) { $collection='PARTIAL' }
        if ($data.Count -eq 1 -and $data[0] -is [System.Collections.IDictionary] -and $data[0].Contains('partial') -and $data[0]['partial']) { $collection='PARTIAL' }
        $flags=@()
        switch ($name) {
            'defender' {
                if ($data.Count -gt 0) {
                    foreach ($f in @('AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled',
                        'BehaviorMonitorEnabled','IoavProtectionEnabled','IsTamperProtected')) {
                        if ($null -eq $data[0].PSObject.Properties[$f]) { $flags+= $null } else { $flags+= $data[0].$f }
                    }
                }
            }
            'firewall' { foreach ($r in $data) {
                if ($r.Enabled -ceq 'True') {$flags+= $true} elseif ($r.Enabled -ceq 'False') {$flags+= $false} else {$flags+= $null}
                if ($r.DefaultInboundAction -ceq 'Block') {$flags+= $true} elseif ($r.DefaultInboundAction -ceq 'Allow') {$flags+= $false} else {$flags+= $null}
            } }
            'secure_boot' { if ($data.Count -gt 0) {$flags+= $data[0].enabled} }
            'bitlocker_status' { foreach ($r in $data) {
                if ($r.ProtectionStatus -ceq 'On') {$flags+= $true} elseif ($r.ProtectionStatus -ceq 'Off') {$flags+= $false} else {$flags+= $null}
            } }
        }
        if ($name -in @('defender','firewall','secure_boot','bitlocker_status')) {
            if ($flags.Count -eq 0 -or @($flags | Where-Object {$_ -isnot [bool]}).Count -gt 0) {$collection='PARTIAL'}
            else { $protection='PASS' }
            if ($flags -contains $false) {$protection='FAIL'}
        }
        if ($name -eq 'defender' -and ($data.Count -ne 1 -or $data[0].AMRunningMode -cne 'Normal')) {
            $collection='PARTIAL'; $protection='NOT ASSESSED'
        }
        $status=$collection; if ($protection -eq 'FAIL') {$status='FAIL'}
        $value=$data
        if ($name -notin @('firewall','bitlocker_status') -and $data.Count -eq 1) {$value=$data[0]}
        $checks.Add([ordered]@{check=$name;status=$status;observed_at=[DateTime]::UtcNow.ToString('o')
            collection_status=$collection;protection_status=$protection;data=$value
            meaning='Observed flags; passive AV/provider role requires interpretation; no host safety verdict'})
    } catch {
        $checks.Add([ordered]@{check=$name;status='NOT RUN';observed_at=[DateTime]::UtcNow.ToString('o')
            collection_status='NOT RUN';protection_status='NOT RUN';reason='Unavailable, timed out or access denied'})
    } finally {
        if ($null -ne $job) {
            if ($job.State -notin @('Completed','Failed','Stopped')) {Stop-Job -Job $job -ErrorAction SilentlyContinue}
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}
foreach ($name in @('patch_freshness','memory_integrity','browser_extensions','account_security',
    'backup_restore','autorun_targets','effective_harness_permissions','agent_extensions',
    'package_advisories','cleanup_eligibility','uac','smartscreen','asr_configuration',
    'rdp_smb','credential_guard','application_control')) {
    $checks.Add([ordered]@{check=$name;status='NOT RUN';observed_at=[DateTime]::UtcNow.ToString('o')
        reason='Requires separate scoped native or manual verification'})
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
$architecture='unknown'
try {$architecture=[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()} catch {}
$counts=@{}
foreach ($s in @('PASS','FAIL','PARTIAL','NOT RUN')) {$counts[$s]=@($checks | Where-Object {$_.status -eq $s}).Count}
$status='PASS'
if ($counts['FAIL'] -gt 0) {$status='FAIL'} elseif ($counts['PARTIAL']+$counts['NOT RUN'] -gt 0) {$status='PARTIAL'}
[ordered]@{schema_version=1;collector_version='0.2.0';platform='windows';architecture=$architecture
    observed_at=[DateTime]::UtcNow.ToString('o');status=$status;summary=$counts
    identity=@{elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
               host_attestation='NOT ATTESTED';interpreter=$PSVersionTable.PSVersion.ToString()}
    scope='Bounded local metadata';verdict='NOT ASSESSED';checks=$checks.ToArray()
} | ConvertTo-Json -Depth 10
if ($status -eq 'FAIL') {exit 1}
if ($status -eq 'PARTIAL') {exit 2}
