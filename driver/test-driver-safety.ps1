$ErrorActionPreference = 'Stop'

$project = Split-Path -Parent $PSScriptRoot
$driver = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'EchoVaultFilter.c') -Raw
$inf = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'EchoVaultFilter.inf') -Raw
$control = Get-Content -LiteralPath (Join-Path $project 'filterctl\filterctl.c') -Raw
$filterIo = Get-Content -LiteralPath (Join-Path $project 'filterio.cpp') -Raw
$devicePath = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'evdevpath.c') -Raw

$portSecurityBuilder = [regex]::Match(
    $driver,
    'static NTSTATUS EvBuildPortSecurityDescriptor[\s\S]*?(?=static VOID EvFreePortSecurityDescriptor)'
).Value
$allocationTags = [regex]::Matches(
    $driver,
    "(?m)^#define\s+EV_(?:POOL|NOTIFY|SD)_TAG\s+'([^']+)'"
) | ForEach-Object { $_.Groups[1].Value }

$failed = 0
function Test-SafetyRule([bool]$Condition, [string]$Name) {
    if ($Condition) {
        Write-Output "PASS $Name"
    } else {
        Write-Output "FAIL $Name"
        $script:failed++
    }
}

Test-SafetyRule ($inf -match '(?m)^StartType\s*=\s*3\b') 'INF is demand-start'
Test-SafetyRule ($inf -match '(?m)^HKR,\s*"Parameters\\Instances\\EchoVaultFilter Instance",\s*"Flags",\s*0x00010001,\s*1\s*$') 'INF suppresses automatic volume attachment'
Test-SafetyRule ($control -match 'SERVICE_DEMAND_START') 'control tool enforces demand-start'
Test-SafetyRule ($control -notmatch 'start\s*=\s*boot') 'control tool contains no boot-start command'
Test-SafetyRule ($control -match 'Parameters\\\\Instances' -and $control -match 'DWORD flags = 1') 'control tool suppresses automatic volume attachment'
Test-SafetyRule ($driver -match 'EvInstanceSetup' -and $driver -match 'FLTFL_INSTANCE_SETUP_MANUAL_ATTACHMENT' -and $driver -match 'STATUS_FLT_DO_NOT_ATTACH') 'driver accepts only explicit manual volume attachment'
Test-SafetyRule ($driver -match 'ExWaitForRundownProtectionRelease') 'unload drains notification workers'
Test-SafetyRule ($driver -match 'FltSendMessage[\s\S]{0,250}&timeout') 'kernel-to-user send has a timeout'
Test-SafetyRule ($driver -match 'EVFILTER_ROLE_GUARD') 'notifications use a guard-only connection'
Test-SafetyRule ($driver -match 'FltCloseClientPort') 'disconnect closes client ports'
Test-SafetyRule ($driver -match 'RequestorMode\s*==\s*KernelMode') 'kernel-originated opens fail open'
Test-SafetyRule (
    $portSecurityBuilder -match '\*OutSd\s*=\s*sd;[\s\S]{0,200}sd\s*=\s*NULL;[\s\S]{0,200}acl\s*=\s*NULL;'
) 'port descriptor transfers both descriptor and DACL ownership'
Test-SafetyRule (
    $allocationTags.Count -eq 3 -and
    @($allocationTags | Sort-Object -Unique).Count -eq 3
) 'entry, notification, and security-descriptor pool tags are distinct'
Test-SafetyRule ($filterIo -match 'ULONGLONG\s+MessageId') 'message header uses the 64-bit Windows ABI'
Test-SafetyRule ($filterIo -match 'FnGetMessage\)\(HANDLE, LPVOID, DWORD, LPOVERLAPPED\)') 'FilterGetMessage uses OVERLAPPED ABI'
Test-SafetyRule ($filterIo -match 'EVFILTER_ROLE_GUARD') 'guard declares its connection role'
Test-SafetyRule (($filterIo -notmatch 'FilterClose') -and ($control -notmatch 'FilterClose')) 'connection handles use CloseHandle'
Test-SafetyRule ($control -match 'RunPersistentSelfTest' -and $control -match 'PORT_ALIVE_AT_END') 'persistent policy diagnostic keeps one port through all transitions'
Test-SafetyRule ($driver -match 'EvFreeDevicePath\(&path, &devPath\)' -and $driver -notmatch 'ExFreePool\(devPath\.Buffer\)') 'message callback uses the tested path ownership cleanup'
Test-SafetyRule ($devicePath -match 'if \(translated->Buffer &&') 'path cleanup refuses NULL pool frees'
$messageHandler = [regex]::Match($driver, 'static NTSTATUS EvMessageNotify[\s\S]*?(?=// ---- Pre-op callback)').Value
$translationIndex = $messageHandler.IndexOf('EvToDevicePath(&path, &devPath)')
$pathlessClearIndex = $messageHandler.IndexOf('if (m->OpCode == EVFILTER_MSG_CLEAR)')
$pathlessStatusIndex = $messageHandler.IndexOf('if (m->OpCode == EVFILTER_MSG_STATUS)')
$emptyPathIndex = $messageHandler.IndexOf('if (path.Length == 0)')
Test-SafetyRule ($pathlessClearIndex -ge 0 -and $pathlessClearIndex -lt $translationIndex -and $pathlessStatusIndex -ge 0 -and $pathlessStatusIndex -lt $translationIndex -and $emptyPathIndex -ge 0 -and $emptyPathIndex -lt $translationIndex) 'pathless commands and empty paths are handled before translation'

if ($failed -ne 0) {
    Write-Output "`n$failed safety rule(s) failed."
    exit 1
}

Write-Output "`nAll driver safety rules passed."
exit 0
