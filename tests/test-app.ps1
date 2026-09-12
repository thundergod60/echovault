param(
    [string]$Executable = (Join-Path $PSScriptRoot '..\EchoVault.exe'),
    [string]$ReportDirectory = (Join-Path $env:TEMP 'EchoVault-tests')
)
$ErrorActionPreference = 'Stop'
$appPath = (Resolve-Path -LiteralPath $Executable).Path
$reportPath = [IO.Path]::GetFullPath($ReportDirectory)
New-Item -ItemType Directory -Path $reportPath -Force | Out-Null
$process = Start-Process -FilePath $appPath -ArgumentList @('--selftest', ('"' + $reportPath + '"')) -WindowStyle Hidden -PassThru
if (-not $process.WaitForExit(120000)) {
    Stop-Process -Id $process.Id
    throw "The test process timed out. Test files are retained under $reportPath."
}
$process.Refresh()
$log = Join-Path $reportPath 'selftest.log'
if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log }
if ($process.ExitCode -ne 0) { throw "App tests failed (exit $($process.ExitCode)). Report: $log" }
if (-not (Test-Path -LiteralPath $log)) { throw 'Tests exited without producing a report.' }
$sourceRoot = Split-Path -Parent $PSScriptRoot
$uiSource = Get-Content -LiteralPath (Join-Path $sourceRoot 'ui.cpp') -Raw
if ($uiSource -match 'lpVerb\s*=\s*L"openas"') {
    throw 'Unsafe asynchronous Open With fallback was reintroduced.'
}
if ($uiSource -notmatch 'OAIF_EXEC\s*\|\s*OAIF_HIDE_REGISTRATION') {
    throw 'Open With must execute the selected editor without allowing it to replace EchoVault as the default.'
}
$commonBlock = [regex]::Match(
    $uiSource,
    'static const wchar_t\* kCommonExtensions\[\] = \{(?<body>.*?)\};',
    [Text.RegularExpressions.RegexOptions]::Singleline
).Groups['body'].Value
$commonCount = ([regex]::Matches($commonBlock, 'L"\.[a-z0-9]+"')).Count
if ($commonCount -lt 50) {
    throw "Common file type registration is incomplete ($commonCount entries found)."
}
Write-Output "PASS modal non-registering Open With source guard"
Write-Output "PASS common file type registration source guard ($commonCount entries found)"
foreach ($scriptType in @('.bat','.cmd','.ps1','.vbs','.js','.mjs','.cjs','.py','.pyw','.rb','.php','.lua','.sh','.ahk')) {
    if ($commonBlock -match [regex]::Escape('L"' + $scriptType + '"')) {
        throw "Executable script type $scriptType must not be registered as a common document."
    }
}
if ($uiSource -notmatch 'bool RepairScriptAssociations\(\)') {
    throw 'The legacy executable-script association repair is missing.'
}
Write-Output "PASS executable script types excluded and legacy repair present"
Write-Output "Completed. Copyable report: $log"
