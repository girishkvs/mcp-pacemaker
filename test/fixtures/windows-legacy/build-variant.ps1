# TEST-SETUP only. Compile a marked, unshipped regression mutant with the recorded toolchain.
param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [ValidateSet('ignore-expected', 'deny-observed-stop', 'fragmented-utf8', 'older-nonmember', 'path-forms',
        'deny-query-open', 'deny-terminate-open', 'deny-token-owner', 'deny-image')][string]$Variant = 'ignore-expected',
    [string]$SourceRoot
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
if ($SourceRoot) { $root = [IO.Path]::GetFullPath($SourceRoot) }
$metadata = [IO.File]::ReadAllText((Join-Path $root 'bin\windows-legacy\LegacyProcessBroker.build.json')) | ConvertFrom-Json
$compiler = $env:MCP_NATIVE_COMPILER
if (-not $compiler) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $installation = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -property installationPath
    if ($LASTEXITCODE -ne 0 -or
        -not $installation) { throw 'Installed recorded compiler required' }
    $compiler = Join-Path $installation 'MSBuild\Current\Bin\Roslyn\csc.exe'
}
if ((Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash.ToLowerInvariant() -ne $metadata.inputs.compilerSha256) {
    throw 'Test compiler differs from recorded compiler'
}
$references = $env:MCP_NATIVE_REFERENCES
if (-not $references) {
    $references = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.6.2'
}
$args = @($metadata.inputs.compilerArguments)
foreach ($entry in $metadata.inputs.referenceSha256.PSObject.Properties) {
    $reference = Join-Path $references $entry.Name
    if ((Get-FileHash -LiteralPath $reference -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) {
        throw 'Test reference assembly differs from recorded reference'
    }
    $args += "/reference:$reference"
}
$directory = Join-Path $OutputDirectory 'windows-legacy'
$null = New-Item -ItemType Directory -Path $directory -ErrorAction Stop
$sources = foreach ($name in @('AssemblyInfo.cs', 'LegacyNative.cs', 'LegacyProcessBroker.cs')) {
    $source = [IO.File]::ReadAllText((Join-Path $root "bin\windows-legacy\src\$name")).Replace("`r`n", "`n")
    $diagnosticVariant = $Variant -in @('deny-query-open', 'deny-terminate-open', 'deny-token-owner', 'deny-image')
    if ($diagnosticVariant) {
        $needle = $null
        $replacement = $null
        if ($name -eq 'LegacyProcessBroker.cs' -and
            $Variant -eq 'deny-query-open') {
            $needle = 'var handle = Api.OpenProcess(0x00100000 | 0x1000, false, id);'
            $replacement = 'var handle = new OwnedApiDenial().Open();'
        } elseif ($name -eq 'LegacyProcessBroker.cs' -and
            $Variant -eq 'deny-terminate-open') {
            $needle = 'var terminable = Api.OpenProcess(0x00100000 | 0x1000 | 1, false, id);'
            $replacement = 'var terminable = new OwnedApiDenial().Open();'
        } elseif ($name -eq 'LegacyNative.cs' -and
            $Variant -eq 'deny-token-owner') {
            $needle = 'Api.OpenProcessToken(process, 8, out token)'
            $replacement = 'new OwnedApiDenial().Token(out token)'
        } elseif ($name -eq 'LegacyNative.cs' -and
            $Variant -eq 'deny-image') {
            $needle = 'Api.QueryFullProcessImageNameW(process, 0, value, ref size)'
            $replacement = 'new OwnedApiDenial().Image()'
        }
        if ($needle) {
            if ($source.Split(@($needle), [StringSplitOptions]::None).Length -ne 2) { throw 'API-denial injection point changed' }
            $source = $source.Replace($needle, $replacement)
        }
        if ($name -eq 'LegacyNative.cs') {
            $source += @'

internal sealed class OwnedApiDenial
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll", EntryPoint = "SetLastError", SetLastError = true)]
    private static extern void SetError(uint code);
    internal SafeProcess Open() { var handle = new SafeProcess(); SetError(5); return handle; }
    internal bool Token(out SafeProcess token) { token = new SafeProcess(); SetError(5); return false; }
    internal bool Image() { SetError(5); return false; }
}
'@
        }
    }
    if ($name -eq 'LegacyProcessBroker.cs' -and
        -not $diagnosticVariant) {
        $needle = if ($Variant -eq 'ignore-expected') {
            'if (request.expected != null &&'
        } elseif ($Variant -eq 'deny-observed-stop') {
            'if (!native.Alive(process.Handle)) return;'
        } elseif ($Variant -eq 'fragmented-utf8') {
            'Console.Out.WriteLine(json.Serialize(value));'
        } elseif ($Variant -eq 'older-nonmember') {
            'ids.Sort();'
        } else {
            'return new LegacyProcessBroker().Run(args);'
        }
        if ($source.Split(@($needle), [StringSplitOptions]::None).Length -ne 2) { throw 'Regression injection point changed' }
        $replacement = if ($Variant -eq 'ignore-expected') {
            'request.expected = null; if (request.expected != null &&'
        } elseif ($Variant -eq 'deny-observed-stop') {
            'if (!native.Alive(process.Handle)) return; if (process.Info.scriptSha256 == null) throw new Win32Exception(5);'
        } elseif ($Variant -eq 'fragmented-utf8') {
            'var data = Encoding.UTF8.GetBytes(json.Serialize(value) + "\n"); var output = Console.OpenStandardOutput(); foreach (byte item in data) { output.WriteByte(item); output.Flush(); if (item >= 0xc0) Thread.Sleep(20); }'
        } elseif ($Variant -eq 'older-nonmember') {
            'if (parentId.ToString(CultureInfo.InvariantCulture) == Environment.GetEnvironmentVariable("MCP_TEST_PARENT")) ids.Add(int.Parse(Environment.GetEnvironmentVariable("MCP_TEST_OLDER_PID"), CultureInfo.InvariantCulture)); ids.Sort();'
        } else {
            'Console.Out.WriteLine(new LegacyProcessBroker().FullyQualifiedScriptPath(args[0]) ? "full" : "ambiguous"); return 0;'
        }
        $source = $source.Replace($needle, $replacement)
    }
    if ($name -eq 'LegacyNative.cs' -and
        $Variant -eq 'older-nonmember') {
        $needle = "internal int Parent(SafeProcess process)`n    {"
        if (-not $source.Contains($needle)) { throw 'Native parent regression boundary changed' }
        $source = $source.Replace($needle, $needle + "`n" +
            '        if (Creation(process).ToString(CultureInfo.InvariantCulture) == Environment.GetEnvironmentVariable("MCP_TEST_OLDER_BIRTH")) return int.Parse(Environment.GetEnvironmentVariable("MCP_TEST_PARENT"), CultureInfo.InvariantCulture);')
    }
    $path = Join-Path $OutputDirectory $name
    [IO.File]::WriteAllText($path, $source)
    $path
}
$binary = Join-Path $directory 'LegacyProcessBroker.exe'
& $compiler @args "/out:$binary" @sources
if ($LASTEXITCODE -ne 0) { throw 'Regression mutant compile failed' }
$metadata.binarySha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $directory 'LegacyProcessBroker.build.json'),
    (ConvertTo-Json $metadata -Depth 10))
Copy-Item -LiteralPath (Join-Path $root 'bin\windows-legacy-process.mjs') -Destination $OutputDirectory
Write-Output (Join-Path $OutputDirectory 'windows-legacy-process.mjs')
