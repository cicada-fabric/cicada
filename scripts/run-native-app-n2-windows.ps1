[CmdletBinding()]
param(
    [ValidateSet('A', 'B', 'SelfTest')][string]$Phase = 'A',
    [string]$TransferFile = '',
    [string]$FixtureSHA256 = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$prefix = 'TestN2NativeWindows'
$requiredTests = @('Context', 'ProtectorRoundTrip', 'VaultAndACL', 'ACLRejectsTampering', 'CrossUserProduce', 'CrossUserVerifyA', 'CrossUserRejectB') | ForEach-Object { $prefix + $_ }
$tamperCases = @('directory-extra-ace', 'vault-extra-ace', 'lock-extra-ace', 'directory-inheritance')
$utf8 = [System.Text.UTF8Encoding]::new($false)

function Assert-NativeOutput([string[]]$Lines, [int]$ExitCode, [string]$Name, [string]$RunID) {
    if ($ExitCode -ne 0) { throw "Native phase exit was $ExitCode for $Name" }
    $expected = @($Name)
    if ($Name -eq ($prefix + 'ACLRejectsTampering')) { $expected += @($tamperCases | ForEach-Object { "$Name/$_" }) }
    $runs = @(); $passes = @(); $receipts = @(); $complete = 0
    foreach ($line in $Lines) {
        $trimmed = $line.TrimStart()
        if ($trimmed -match '^--- (FAIL|SKIP):' -or $trimmed -match '^FAIL(?:\s|$)' -or $trimmed -match 'no tests to run') { throw "Failed, skipped or empty native phase: $Name" }
        if ($trimmed -match '^=== RUN\s+(\S+)$') { $runs += $Matches[1] }
        if ($trimmed -match '^--- PASS: (\S+) \(') { $passes += $Matches[1] }
        if ($trimmed -eq 'PASS') { $complete++ }
        if ($line -match '^N2_NATIVE_RESULT (\{.*\})$') {
            $receipt = $Matches[1] | ConvertFrom-Json
            if ($receipt.schema -ne 'cicada.n2.windows.native-result.v1' -or $receipt.run_id -ne $RunID -or
                $receipt.sid -notmatch '^S-' -or $receipt.machine_sha256 -notmatch '^[0-9a-f]{64}$' -or
                $receipt.windows_build -notmatch '^\d+\.\d+\.\d+$' -or @($receipt.assertions).Count -eq 0) { throw 'Invalid native receipt metadata' }
            $receipts += $receipt
        }
    }
    foreach ($nameInSet in @('runs', 'passes')) {
        $actual = @(Get-Variable -Name $nameInSet -ValueOnly)
        if ($actual.Count -ne $expected.Count -or @(Compare-Object ($actual | Sort-Object) ($expected | Sort-Object)).Count -ne 0) { throw "Missing, duplicate or extra native cases in $nameInSet" }
    }
    if ($complete -ne 1 -or $receipts.Count -ne $expected.Count -or
        @(Compare-Object @($receipts | ForEach-Object { $_.test } | Sort-Object) @($expected | Sort-Object)).Count -ne 0) { throw 'Missing or duplicate native receipts/completion' }
    return $receipts
}

function Invoke-RunnerSelfTest {
    $id = 'a' * 32
    $name = $prefix + 'Context'
    $receipt = @{ schema = 'cicada.n2.windows.native-result.v1'; test = $name; run_id = $id; sid = 'S-1-5-21-1-2-3-1001'; machine_sha256 = ('b' * 64); windows_build = '10.0.26200'; ordinary_user = $true; assertions = @('synthetic-parser-fixture') } | ConvertTo-Json -Compress
    $good = @("=== RUN   $name", "N2_NATIVE_RESULT $receipt", "--- PASS: $name (0.01s)", 'PASS')
    $null = Assert-NativeOutput $good 0 $name $id
    $cases = @(
        @{ lines = @('PASS'); code = 0 },
        @{ lines = $good; code = 1 },
        @{ lines = @("=== RUN   $name", "--- SKIP: $name (0.00s)", 'PASS'); code = 0 },
        @{ lines = ($good + "--- FAIL: $name (0.00s)"); code = 0 },
        @{ lines = ($good + "--- PASS: $name (0.00s)"); code = 0 },
        @{ lines = @($good | Where-Object { $_ -notmatch '^N2_NATIVE_RESULT ' }); code = 0 }
    )
    foreach ($case in $cases) {
        $rejected = $false
        try { $null = Assert-NativeOutput $case.lines $case.code $name $id } catch { $rejected = $true }
        if (-not $rejected) { throw 'A false-success parser fixture was accepted' }
    }
    Write-Output 'PASS: native runner parser, six false-success cases rejected; no Windows API executed.'
}

if ($Phase -eq 'SelfTest') {
    try { Invoke-RunnerSelfTest; exit 0 } catch { Write-Error $_; exit 1 }
}

function Get-SHA256([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-JSON([string]$Path, $Value) { [IO.File]::WriteAllText($Path, (($Value | ConvertTo-Json -Depth 14) + "`n"), $utf8) }

$runID = ''; $outputDirectory = ''; $result = $null; $finalExit = 1
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Actual Windows is required; cross-builds are NOT_RUN.' }
    $exePath = Join-Path $PSScriptRoot 'cicada-appvault-tests.exe'
    $buildPath = Join-Path $PSScriptRoot 'n2-native-windows-build.json'
    $build = Get-Content -LiteralPath $buildPath -Raw | ConvertFrom-Json
    $exeHash = Get-SHA256 $exePath
    if ($build.schema -ne 'cicada.n2.windows.native-build.v1' -or
        $exeHash -ne $build.files.'cicada-appvault-tests.exe' -or
        (Get-SHA256 $PSCommandPath) -ne $build.files.'run-native-app-n2-windows.ps1') { throw 'Package build manifest or executable/runner hash mismatch' }
    if ($Phase -eq 'A') {
        $runID = [Guid]::NewGuid().ToString('N')
        $publicDocuments = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonDocuments)
        $transferDirectory = Join-Path $publicDocuments ("cicada-n2-native-synthetic-$runID")
        $TransferFile = Join-Path $transferDirectory ("n2-native-synthetic-$runID.json")
        if (Test-Path -LiteralPath $transferDirectory) { throw 'Synthetic transfer directory already exists' }
    } else {
        $transferMatch = [regex]::Match([IO.Path]::GetFileName($TransferFile), '^n2-native-synthetic-([0-9a-f]{32})\.json$')
        if (-not $transferMatch.Success -or $FixtureSHA256 -notmatch '^[0-9a-f]{64}$') { throw 'Phase B requires the exact producer transfer file and its SHA256.' }
        $runID = $transferMatch.Groups[1].Value
    }
    if ($TransferFile -notmatch '^[A-Za-z]:\\' -or [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($TransferFile)) -ne "cicada-n2-native-synthetic-$runID") { throw 'Only the named local synthetic transfer directory is allowed.' }
    $outputDirectory = Join-Path ([IO.Path]::GetTempPath()) ("cicada-n2-native-evidence-$Phase-$runID-" + [Guid]::NewGuid().ToString('N'))
    if ($outputDirectory -notmatch '^[A-Za-z]:\\' -or (Test-Path -LiteralPath $outputDirectory)) { throw 'A fresh local evidence directory is required.' }
    $null = New-Item -ItemType Directory -Path $outputDirectory
    Copy-Item -LiteralPath $buildPath -Destination (Join-Path $outputDirectory 'build-manifest.json')
    $result = [ordered]@{
        schema = 'cicada.n2.windows.native-phase.v1'; phase = $Phase; run_id = $runID;
        status = 'FAIL'; exit_code = 1; cross_user = 'NOT_RUN';
        started_utc = [DateTime]::UtcNow.ToString('o');
        finished_utc = '';
        exe_sha256 = $exeHash; runner_sha256 = (Get-SHA256 $PSCommandPath);
        build_manifest_sha256 = (Get-SHA256 $buildPath); transfer_file = $TransferFile;
        tests = @(); fixture_sha256 = ''; entropy_sha256 = ''; producer_sid = '';
        context = $null; failure = ''; native_runtime = 'ACTUAL_WINDOWS_TEST_BINARY'
    }

    function Invoke-NativeProcess([string]$Arguments) {
        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $exePath; $info.Arguments = $Arguments
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        foreach ($key in @($info.EnvironmentVariables.Keys)) { if ($key -like 'CICADA_N2_NATIVE_*') { $info.EnvironmentVariables.Remove($key) } }
        $info.EnvironmentVariables['CICADA_N2_NATIVE_RUN_ID'] = $runID
        $info.EnvironmentVariables['CICADA_N2_NATIVE_PHASE'] = $Phase
        $info.EnvironmentVariables['CICADA_N2_NATIVE_TRANSFER'] = $TransferFile
        $info.EnvironmentVariables['CICADA_N2_NATIVE_FIXTURE_SHA256'] = $FixtureSHA256
        $process = [Diagnostics.Process]::new(); $process.StartInfo = $info
        if (-not $process.Start()) { throw 'Native test process did not start' }
        $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(180000)) { $process.Kill(); $process.WaitForExit(); throw 'Native process deadline exceeded' }
        $text = $stdout.Result + $stderr.Result; $code = $process.ExitCode; $process.Dispose()
        if ($text.Length -gt 1048576) { throw 'Native test output limit exceeded' }
        return @{ text = $text; code = $code }
    }

    function Invoke-NativeTest([string]$Name) {
        $processResult = Invoke-NativeProcess ("-test.v -test.count=1 -test.timeout=120s -test.run=^" + $Name + '$')
        $logName = "$Name.log"
        [IO.File]::WriteAllText((Join-Path $outputDirectory $logName), $processResult.text, $utf8)
        $entry = [ordered]@{ name = $Name; exit_code = $processResult.code; log = $logName; log_sha256 = (Get-SHA256 (Join-Path $outputDirectory $logName)); receipts = @() }
        $result.tests += $entry
        $entry.receipts = @(Assert-NativeOutput @($processResult.text -split '\r?\n') $processResult.code $Name $runID)
        return @($entry.receipts | Where-Object { $_.test -eq $Name })[0]
    }

    $listing = Invoke-NativeProcess '-test.list=^TestN2NativeWindows'
    [IO.File]::WriteAllText((Join-Path $outputDirectory 'test-list.log'), $listing.text, $utf8)
    $listed = @($listing.text -split '\r?\n' | Where-Object { $_ -ne '' })
    if ($listing.code -ne 0 -or $listed.Count -ne $requiredTests.Count -or @(Compare-Object @($listed | Sort-Object) @($requiredTests | Sort-Object)).Count -ne 0) { throw 'Required native tests are missing, duplicated or unexpected.' }
    $context = Invoke-NativeTest ($prefix + 'Context')
    $result.context = $context
    if ($Phase -eq 'B' -and $context.ordinary_user -ne $true) {
        $result.status = 'NOT_RUN'; $result.exit_code = 2
        $result.failure = 'No ordinary consumer account: administrator/service/SYSTEM is not phase B.'
        $finalExit = 2
    } elseif ($Phase -eq 'A') {
        foreach ($suffix in @('ProtectorRoundTrip', 'VaultAndACL', 'ACLRejectsTampering')) { $null = Invoke-NativeTest ($prefix + $suffix) }
        $producer = Invoke-NativeTest ($prefix + 'CrossUserProduce')
        $FixtureSHA256 = $producer.fixture_sha256
        if ((Get-SHA256 $TransferFile) -ne $FixtureSHA256) { throw 'Published transfer digest differs from native producer.' }
        $verified = Invoke-NativeTest ($prefix + 'CrossUserVerifyA')
        if ($verified.fixture_sha256 -ne $FixtureSHA256 -or $verified.entropy_sha256 -ne $producer.entropy_sha256 -or $verified.producer_sid -ne $context.sid -or -not $verified.unwrap_attempted) { throw 'Separate-process producer verification mismatch.' }
        $result.fixture_sha256 = $FixtureSHA256; $result.entropy_sha256 = $verified.entropy_sha256; $result.producer_sid = $context.sid
        $result.status = 'SCOPED_PASS_PHASE_A'; $result.exit_code = 0; $finalExit = 0
    } else {
        $consumer = Invoke-NativeTest ($prefix + 'CrossUserRejectB')
        if ($consumer.fixture_sha256 -ne $FixtureSHA256 -or $consumer.producer_sid -eq $context.sid -or -not $consumer.unwrap_attempted) { throw 'Consumer phase did not verify an independent DPAPI rejection.' }
        $result.fixture_sha256 = $FixtureSHA256; $result.entropy_sha256 = $consumer.entropy_sha256; $result.producer_sid = $consumer.producer_sid
        $result.cross_user = 'CONSUMER_REJECTION_OBSERVED_REQUIRES_MATCHING_PHASE_A'
        $result.status = 'SCOPED_PASS_PHASE_B'; $result.exit_code = 0; $finalExit = 0
    }
    if ((Get-SHA256 $exePath) -ne $exeHash -or (Get-SHA256 $PSCommandPath) -ne $result.runner_sha256) { throw 'Executable or runner changed during native execution.' }
} catch {
    $finalExit = 1
    if ($null -ne $result) { $result.status = 'FAIL'; $result.exit_code = 1; $result.failure = $_.Exception.Message }
    Write-Host ("Native acceptance failed: " + $_.Exception.Message)
} finally {
    if ($null -ne $result) {
        $result.finished_utc = [DateTime]::UtcNow.ToString('o')
        Write-JSON (Join-Path $outputDirectory 'result.json') $result
        $index = [ordered]@{}
        foreach ($file in @(Get-ChildItem -LiteralPath $outputDirectory -File | Sort-Object Name)) { $index[$file.Name] = Get-SHA256 $file.FullName }
        Write-JSON (Join-Path $outputDirectory 'artifacts.sha256.json') $index
        Write-Host "Native evidence: $outputDirectory"
        Write-Host ("status=" + $result.status + " cross_user=" + $result.cross_user + " exit=" + $finalExit)
        if ($Phase -eq 'A' -and $finalExit -eq 0) {
            Write-Host 'On the SAME machine, sign in to a DIFFERENT existing ordinary Windows account and run this bundle:'
            Write-Host ('.\run-native-app-n2-windows.ps1 -Phase B -TransferFile "' + $TransferFile + '" -FixtureSHA256 ' + $FixtureSHA256)
        }
    }
}
exit $finalExit
