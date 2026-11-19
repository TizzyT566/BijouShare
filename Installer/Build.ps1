#requires -Version 7.4
[CmdletBinding()]
param([string]$OutputDirectory = (Join-Path $PSScriptRoot '..\artifacts\bijoushare\installers'))

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
Set-StrictMode -Version Latest
if (-not $IsWindows -or -not [Environment]::Is64BitProcess) { throw 'Build setup with 64-bit PowerShell on Windows.' }
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$version = [string]([xml](Get-Content -LiteralPath (Join-Path $root 'Directory.Build.props') -Raw)).Project.PropertyGroup.Version
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Use a three-part Windows Installer product version.' }
$output = [IO.Path]::GetFullPath($OutputDirectory)
$run = Join-Path $root 'artifacts\installer-build' ([Guid]::NewGuid().ToString('N'))
$payloads = Join-Path $run 'publish'
$setups = Join-Path $run 'setups'
$null = New-Item -ItemType Directory -Path $setups -Force
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) { throw 'Install the Windows .NET Framework 4.x compiler to build the setup launchers.' }

$wixVersion = '5.0.2'
$tools = Join-Path $root 'artifacts\installer-tools\wix'
$wix = Join-Path $tools 'wix.exe'
$util = Join-Path $tools ".wix\extensions\WixToolset.Util.wixext\$wixVersion\wixext5\WixToolset.Util.wixext.dll"
if (-not (Test-Path -LiteralPath $wix)) { & dotnet tool install wix --version $wixVersion --tool-path $tools }
if ((& $wix --version).Split('+')[0] -ne $wixVersion) { throw "Expected WiX $wixVersion at $wix." }
if (-not (Test-Path -LiteralPath $util)) {
    Push-Location -LiteralPath $tools
    try { & $wix extension add "WixToolset.Util.wixext/$wixVersion" } finally { Pop-Location }
}

foreach ($role in 'Server','Client') {
    $name = "BijouShare.$role"
    $payload = Join-Path $payloads $role
    $project = Join-Path $root $name "$name.csproj"
    & dotnet publish $project -c Release -r win-x64 --self-contained true --artifacts-path (Join-Path $run 'dotnet') -o $payload
    $assembly = Get-Item -LiteralPath (Join-Path $payload "$name.dll")
    if ($assembly.VersionInfo.ProductVersion.Split('+')[0] -cne $version) { throw "$name is out of sync with version $version." }
    if ($role -eq 'Server') {
        # Build from the same project against the staged service, using the runtime already in its payload.
        $trayOutput = Join-Path $run 'tray'
        & dotnet build $project -c Release -r win-x64 --self-contained true --artifacts-path (Join-Path $run 'tray-dotnet') `
            "-p:TrayServerAssembly=$($assembly.FullName)" -o $trayOutput
        foreach ($extension in 'exe','dll','deps.json','runtimeconfig.json') {
            Copy-Item -LiteralPath (Join-Path $trayOutput "$name.Tray.$extension") -Destination $payload
        }
    }

    $msi = Join-Path $run "$name.msi"
    & $wix build -arch x64 -ext $util -d "Role=$role" -d "ProductVersion=$version" -d "PublishDir=$payload" `
        -intermediatefolder (Join-Path $run "wix-$role") -pdbtype none -o $msi (Join-Path $PSScriptRoot 'Service.wxs')
    $info = Join-Path $run "$role.AssemblyInfo.cs"
    @"
using System.Reflection;
[assembly: AssemblyTitle("BijouShare $role Setup")]
[assembly: AssemblyProduct("BijouShare $role")]
[assembly: AssemblyCompany("BijouShare")]
[assembly: AssemblyVersion("$version.0")]
[assembly: AssemblyFileVersion("$version.0")]
[assembly: AssemblyInformationalVersion("$version")]
"@ | Set-Content -LiteralPath $info -Encoding utf8
    $exe = Join-Path $setups "$name-$version-win-x64-Setup.exe"
    $roleDefine = '/define:' + $role.ToUpperInvariant()
    $manifest = Join-Path $PSScriptRoot 'setup.manifest'
    $icon = Join-Path $root 'Shared\Icons' "$name.ico"
    $launcherSources = @($info, (Join-Path $PSScriptRoot 'Setup.cs'))
    $launcherReferences = @('/reference:System.Windows.Forms.dll')
    if ($role -eq 'Server') {
        $launcherSources += Join-Path $PSScriptRoot 'ExplorerDesktop.cs'
        $launcherSources += Join-Path $PSScriptRoot 'ServerTrayRegistration.cs'
        $launcherSources += Join-Path $PSScriptRoot 'ServerInstallAccount.cs'
        $launcherSources += Join-Path $PSScriptRoot 'ServiceLogon.cs'
        $launcherSources += Join-Path $PSScriptRoot 'ServerAccountMaintenance.cs'
        $launcherReferences += '/reference:System.ServiceProcess.dll','/reference:System.Drawing.dll','/reference:System.Management.dll'
    }
    & $csc /nologo /target:winexe /platform:x64 /optimize+ /warnaserror+ $roleDefine "/win32manifest:$manifest" `
        "/win32icon:$icon" @launcherReferences "/resource:$msi,BijouShare.Package.msi" "/out:$exe" `
        @launcherSources
}

& (Join-Path $PSScriptRoot 'Test-Packages.ps1') -PackageDirectory $setups -PublishDirectory $payloads
$null = New-Item -ItemType Directory -Path $output -Force
$checksums = foreach ($setup in Get-ChildItem -LiteralPath $setups -Filter '*.exe' -File | Sort-Object Name) {
    $stream = $setup.OpenRead()
    try { $hash = [Convert]::ToHexString([Security.Cryptography.SHA3_256]::HashData($stream)).ToLowerInvariant() } finally { $stream.Dispose() }
    Copy-Item -LiteralPath $setup.FullName -Destination (Join-Path $output $setup.Name) -Force
    "$hash  $($setup.Name)"
}
$checksums | Set-Content -LiteralPath (Join-Path $output "SHA3-256SUMS-$version.txt") -Encoding utf8
Write-Output "Validated Windows installers are in $output"
