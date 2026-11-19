#requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageDirectory,
    [Parameter(Mandatory)][string]$PublishDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows -or -not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell on Windows.' }
$PackageDirectory = (Resolve-Path -LiteralPath $PackageDirectory).Path
$PublishDirectory = (Resolve-Path -LiteralPath $PublishDirectory).Path

function Confirm-Check([bool]$Condition, [string]$Description) {
    if (-not $Condition) { throw "Failed: $Description" }
}

function Invoke-MsiMember($Object, [string]$Name, [object[]]$Values, [string]$Kind = 'InvokeMethod') {
    # IDispatch expects native VARIANTs, and PowerShell providers can wrap their string results.
    if ($null -ne $Values) {
        for ($i = 0; $i -lt $Values.Length; $i++) { $Values[$i] = $Values[$i].PSObject.BaseObject }
    }
    $Object.GetType().InvokeMember($Name, $Kind, $null, $Object, $Values)
}

function Read-MsiTable($Database, [string]$Table, [string[]]$Columns) {
    $fields = ($Columns | ForEach-Object { '`' + $_ + '`' }) -join ','
    $view = Invoke-MsiMember $Database OpenView @('SELECT ' + $fields + ' FROM `' + $Table + '`')
    try {
        $null = Invoke-MsiMember $view Execute $null
        while ($record = Invoke-MsiMember $view Fetch $null) {
            try {
                $values = [ordered]@{}
                for ($i = 0; $i -lt $Columns.Length; $i++) {
                    $values[$Columns[$i]] = Invoke-MsiMember $record StringData @($i + 1) GetProperty
                }
                [pscustomobject]$values
            } finally { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
        }
    } finally {
        $null = Invoke-MsiMember $view Close $null
        $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
}

function Expand-MsiCabinet($Database, [string]$Cabinet, [string]$Destination) {
    Confirm-Check ($Cabinet -match '^#[a-zA-Z0-9_.-]+$') "MSI contains its cabinet ($Cabinet)"
    $name = $Cabinet.Substring(1)
    $path = Join-Path $Destination 'payload.cab'
    $view = Invoke-MsiMember $Database OpenView @("SELECT ``Data`` FROM ``_Streams`` WHERE ``Name``='$name'")
    try {
        $null = Invoke-MsiMember $view Execute $null
        $record = Invoke-MsiMember $view Fetch $null
        if ($null -eq $record) { throw "No embedded cabinet $name" }
        try {
            $output = [IO.File]::Create($path)
            try {
                while ($chunk = Invoke-MsiMember $record ReadStream @(1, 524288, 1)) {
                    # msiReadStreamBytes returns one byte per character, including embedded nulls.
                    $bytes = [Text.Encoding]::Latin1.GetBytes($chunk)
                    $output.Write($bytes, 0, $bytes.Length)
                }
            } finally { $output.Dispose() }
        } finally { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
    } finally {
        $null = Invoke-MsiMember $view Close $null
        $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
    & "$env:SystemRoot\System32\expand.exe" '-F:*' $path $Destination | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not extract $name from the MSI" }
}

function Get-InstallDirectoryPath([hashtable]$Rows, [string]$Id) {
    $parts = [Collections.Generic.List[string]]::new()
    while ($Id -ne 'ProgramFiles64Folder') {
        if (-not $Rows.ContainsKey($Id) -or $parts.Count -gt 100) { throw "Unexpected installation directory $Id" }
        $row = $Rows[$Id]
        $name = ($row.DefaultDir.Split(':')[0].Split('|'))[-1]
        if ($name -ne '.') { $parts.Insert(0, $name) }
        $Id = $row.Directory_Parent
    }
    $parts -join '\'
}

function Test-Msi($Database, [string]$Role, [string]$Version, [string]$Scratch) {
    $properties = @{}
    foreach ($row in Read-MsiTable $Database Property @('Property','Value')) { $properties[$row.Property] = $row.Value }
    $summary = Invoke-MsiMember $Database SummaryInformation @(0) GetProperty
    try { $template = Invoke-MsiMember $summary Property @(7) GetProperty }
    finally { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary) }
    Confirm-Check ($template -like 'x64;*' -and $properties.ALLUSERS -eq '1') "$Role x64 per-machine installation"
    Confirm-Check ($properties.ProductVersion -eq $Version) "$Role version matches both published programs"
    $upgrade = @(Read-MsiTable $Database Upgrade @('UpgradeCode','Attributes','VersionMin','VersionMax'))
    Confirm-Check ($upgrade.Where({ $_.UpgradeCode -eq $properties.UpgradeCode -and $_.VersionMax -eq $Version }).Count -ge 1) "$Role upgrade detection"
    Confirm-Check ($upgrade.Where({ $_.UpgradeCode -eq $properties.UpgradeCode -and $_.VersionMin -eq $Version -and ([int]$_.Attributes -band 2) }).Count -ge 1) "$Role newer-version detection"

    $name = "BijouShare.$Role"
    $services = @(Read-MsiTable $Database ServiceInstall @('Name','ServiceType','StartType','StartName','Password','Component_'))
    Confirm-Check ($services.Count -eq 1 -and $services[0].Name -eq $name -and [int]$services[0].StartType -eq 2 -and [int]$services[0].ServiceType -eq 16) "$Role automatic own-process service"
    $service = $services[0]
    if ($Role -eq 'Client') {
        Confirm-Check ($service.StartName -in @('','LocalSystem','NT AUTHORITY\SYSTEM')) 'Client runs under LocalSystem'
        Confirm-Check ([string]::IsNullOrEmpty($service.Password)) 'Client has no service password binding'
    } else {
        Confirm-Check ($service.StartName -ceq '[BIJOUSERVICEACCOUNT]' -and $service.Password -ceq '[BIJOUSERVICEPASSWORD]') 'Server service starts under the selected identity'
        Confirm-Check ($properties.BIJOUSERVICEACCOUNT -ceq 'NT AUTHORITY\LocalService' -and !$properties.ContainsKey('BIJOUSERVICEPASSWORD')) 'Unattended setup defaults to LocalService with no embedded password'
        $secure = $properties.SecureCustomProperties -split ';'
        Confirm-Check ('BIJOUSERVICEACCOUNT' -cin $secure -and 'BIJOUSERVICEPASSWORD' -cin $secure) 'Server credentials reach the elevated MSI transaction'
        Confirm-Check ('BIJOUSERVICEPASSWORD' -cin ($properties.MsiHiddenProperties -split ';')) 'MSI logging hides the service password'
    }
    $control = @(Read-MsiTable $Database ServiceControl @('Name','Event','Component_','Wait'))
    $events = 0
    foreach ($entry in $control) {
        Confirm-Check ($entry.Name -eq $name -and $entry.Component_ -eq $service.Component_ -and $entry.Wait -ne '0') "$Role controls only its own service and waits for it"
        $events = $events -bor [int]$entry.Event
    }
    Confirm-Check ($events -eq 163) "$Role start, stop, and uninstall actions"
    $recovery = @(Read-MsiTable $Database Wix4ServiceConfig @('ServiceName','Component_','FirstFailureActionType','SecondFailureActionType','ThirdFailureActionType'))
    Confirm-Check ($recovery.Count -eq 1 -and $recovery[0].ServiceName -eq $name -and $recovery[0].Component_ -eq $service.Component_ -and
        $recovery[0].FirstFailureActionType -eq 'restart' -and $recovery[0].SecondFailureActionType -eq 'restart' -and $recovery[0].ThirdFailureActionType -eq 'restart') "$Role service recovery"
    $sequence = @{}
    $conditions = @{}
    foreach ($entry in Read-MsiTable $Database InstallExecuteSequence @('Action','Sequence','Condition')) {
        $sequence[$entry.Action] = [int]$entry.Sequence
        $conditions[$entry.Action] = $entry.Condition
    }
    Confirm-Check ($sequence.ContainsKey('RemoveExistingProducts') -and $sequence.StopServices -lt $sequence.RemoveFiles -and $sequence.InstallFiles -lt $sequence.InstallServices -and $sequence.InstallServices -lt $sequence.StartServices) "$Role service and upgrade sequencing"
    $registry = @(Read-MsiTable $Database Registry @('Root','Key','Name','Value'))
    $guards = @(Read-MsiTable $Database LaunchCondition @('Condition','Description'))
    Confirm-Check ($guards.Where({ $_.Condition -match 'Privileged' }).Count -gt 0) "$Role direct MSI elevation"
    Confirm-Check ($guards.Where({ $_.Condition -match 'NOT WIX_DOWNGRADE_DETECTED' }).Count -gt 0) "$Role blocks downgrades"
    Confirm-Check ($guards.Where({ $_.Condition -match 'NOT EXISTING_SERVICE' }).Count -gt 0) "$Role protects an existing service installed outside MSI"
    $shortcut = @(Read-MsiTable $Database Shortcut @('Name','Arguments','Component_'))
    Confirm-Check ($shortcut.Count -eq 1 -and $shortcut[0].Name.Split('|')[-1] -eq "BijouShare $Role") "$Role Start menu entry"
    $storageActions = @(Read-MsiTable $Database CustomAction @('Action','Type','Source','Target') | Where-Object Action -eq 'PrepareServiceStorage')
    if ($Role -eq 'Server') {
        Confirm-Check ($registry.Where({ $_.Root -eq 2 -and $_.Key -eq 'Software\Microsoft\Windows\CurrentVersion\Run' -and $_.Name -eq 'BijouShare.Server.Tray' -and $_.Value -ceq '"[#ServerTrayExe]" --tray-only' }).Count -eq 1) 'Server tray at sign-in'
        Confirm-Check ($shortcut[0].Arguments -eq '--tray-only' -and $shortcut[0].Component_ -eq 'ServerTrayHost') 'Server Start menu opens the dedicated tray executable'
        Confirm-Check ($storageActions.Count -eq 1 -and [int]$storageActions[0].Type -eq 3090 -and $storageActions[0].Source -eq 'ServiceExe' -and
            $storageActions[0].Target -eq '--prepare-service-storage' -and $sequence.PrepareServiceStorage -gt $sequence.InstallFiles -and
            $sequence.PrepareServiceStorage -lt $sequence.StartServices -and $conditions.PrepareServiceStorage -match '\$ServiceHost\s*=\s*3') 'Server prepares private storage as SYSTEM before first service start'
        Confirm-Check ($guards.Where({ $_.Description -match 'Dokan' }).Count -eq 0) 'Server package runs independently of the Dokan driver'
    } else {
        Confirm-Check ($storageActions.Count -eq 0 -and $shortcut[0].Arguments -eq '--open-management' -and $shortcut[0].Component_ -eq $service.Component_) 'Client Start menu opens the signed-in user console'
        Confirm-Check ($registry.Where({ $_.Root -eq 2 -and $_.Key -eq 'Software\Classes\wad' -and $_.Name -eq 'URL Protocol' }).Count -eq 1) 'Client wad URI protocol'
        Confirm-Check ($registry.Where({ $_.Key -eq 'Software\Classes\wad\shell\open\command' -and $_.Value -match '^".+" --open-uri "%1"$' }).Count -eq 1) 'Client quotes and isolates the URI argument'
        Confirm-Check ($guards.Where({ $_.Description -match 'Dokan' -and $_.Condition -match 'DOKAN_RUNTIME' -and $_.Condition -match 'DOKAN_DRIVER' -and $_.Condition -match 'REMOVE' }).Count -gt 0) 'MSI enforces Dokan for installation and permits removal'
    }
    $dirs = @{}
    foreach ($entry in Read-MsiTable $Database Directory @('Directory','Directory_Parent','DefaultDir')) { $dirs[$entry.Directory] = $entry }
    $components = @{}
    foreach ($entry in Read-MsiTable $Database Component @('Component','Directory_','KeyPath','Attributes')) { $components[$entry.Component] = $entry }
    $files = @(Read-MsiTable $Database File @('File','Component_','FileName','FileSize'))
    foreach ($media in Read-MsiTable $Database Media @('Cabinet')) { Expand-MsiCabinet $Database $media.Cabinet $Scratch }
    $published = Join-Path $PublishDirectory $Role
    $expected = @{}
    foreach ($file in Get-ChildItem -LiteralPath $published -File -Recurse) {
        if ($file.Extension -ne '.pdb' -and $file.Name -ne 'Install-Service.ps1') {
            $expected[[IO.Path]::GetRelativePath($published, $file.FullName)] = $file
        }
    }
    foreach ($file in $files) {
        $component = $components[$file.Component_]
        $directory = Get-InstallDirectoryPath $dirs $component.Directory_
        $leaf = $file.FileName.Split('|')[-1]
        $relative = [IO.Path]::GetRelativePath("C:\BijouShare\$Role", "C:\$directory\$leaf")
        Confirm-Check ($expected.ContainsKey($relative)) "$Role installs published file $relative inside Program Files"
        $from = $expected[$relative]
        $packed = Join-Path $Scratch $file.File
        Confirm-Check ($from.Length -eq [long]$file.FileSize -and (Get-FileHash -LiteralPath $from.FullName).Hash -eq (Get-FileHash -LiteralPath $packed).Hash) "$Role payload bytes match $relative"
        if ($leaf -eq "$name.exe") {
            Confirm-Check ($component.Component -eq $service.Component_ -and $component.KeyPath -eq $file.File -and ([int]$component.Attributes -band 256)) "$Role service uses its own x64 apphost"
        }
        if ($Role -eq 'Server' -and $file.File -eq 'ServerTrayExe') {
            Confirm-Check ($relative -eq 'BijouShare.Server.Tray.exe' -and $component.Component -eq 'ServerTrayHost' -and $component.KeyPath -eq $file.File) 'The server tray has its own executable'
        }
        if ($relative -eq 'BijouShare.Server.Tray.runtimeconfig.json') {
            $trayRuntime = Get-Content -LiteralPath $packed -Raw | ConvertFrom-Json
            Confirm-Check ($trayRuntime.runtimeOptions.configProperties.'System.GC.Server' -eq $false) 'The tray uses workstation garbage collection'
        }
        if ($Role -eq 'Server' -and $relative -eq 'appsettings.json') {
            Confirm-Check (([int]$component.Attributes -band 144) -eq 144) 'Server settings survive uninstall and upgrades'
            $acl = @(Read-MsiTable $Database MsiLockPermissionsEx @('LockObject','Table','SDDLText') | Where-Object { $_.Table -eq 'File' -and $_.LockObject -eq $file.File })
            Confirm-Check ($acl.Count -eq 1 -and $acl[0].SDDLText -eq 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;LS)') 'Server settings accessible only to SYSTEM, Administrators and LocalService'
        }
        $expected.Remove($relative)
    }
    Confirm-Check ($expected.Count -eq 0) "$Role includes all runtime and management files: $($expected.Keys -join ', ')"
    Write-Host "$Role MSI verified, including $($files.Count) installed files."
    $properties
}

# Inspect the UAC manifest and extract the embedded database. Never launch setup or
# schedule an MSI installation, registration, repair or removal on the test machine.
if (-not ('PackageInspection' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'Tests/PackageInspection.cs') }
$info = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $PublishDirectory 'Server/BijouShare.Server.dll'))
$version = $info.ProductVersion.Split('+')[0]
$clientInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $PublishDirectory 'Client/BijouShare.Client.dll'))
Confirm-Check ($version -eq $clientInfo.ProductVersion.Split('+')[0]) 'Published component versions match'
$scratch = [IO.Directory]::CreateTempSubdirectory('BijouShare-package-qa-').FullName
$installer = New-Object -ComObject WindowsInstaller.Installer
$metadata = @{}
try {
    foreach ($role in @('Server','Client')) {
        $file = (Get-Item -LiteralPath (Join-Path $PackageDirectory "BijouShare.$role-$version-win-x64-Setup.exe")).FullName
        $wrapper = [Diagnostics.FileVersionInfo]::GetVersionInfo($file)
        $wrapperVersion = [version]::new($wrapper.FileMajorPart, $wrapper.FileMinorPart, $wrapper.FileBuildPart)
        Confirm-Check ($wrapperVersion.ToString() -eq $version) "$role setup executable has the published file version"
        $manifest = [xml][PackageInspection]::ReadManifest($file)
        $level = $manifest.SelectSingleNode("//*[local-name()='requestedExecutionLevel']")
        Confirm-Check ($null -ne $level -and $level.level -eq 'requireAdministrator' -and $level.uiAccess -eq 'false') "$role requires elevation before executing user code"
        $assembly = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($file))
        $machine = [Reflection.PortableExecutableKinds]0
        $architecture = [Reflection.ImageFileMachine]::I386
        $assembly.ManifestModule.GetPEKind([ref]$machine, [ref]$architecture)
        Confirm-Check ($architecture -eq [Reflection.ImageFileMachine]::AMD64) "$role bootstrapper is x64"
        [PackageInspection]::CheckPostInstall($assembly, $role)
        [PackageInspection]::CheckStorageDiagnostics($assembly, $role)
        [PackageInspection]::CheckUnattendedArguments($assembly)
        foreach ($switch in '/quiet','/passive') {
            $accountArgs = [object[]]::new(1)
            $accountArgs[0] = [string[]]@('/serviceaccount',$switch,'/?')
            Confirm-Check ($assembly.EntryPoint.Invoke($null, $accountArgs) -eq 1639) "$role rejects unattended credential prompts"
        }
        if ($role -eq 'Client') { [PackageInspection]::CheckDokanFlow($assembly) }
        else { Confirm-Check ($null -eq $assembly.GetType('BijouShare.Installer.DokanPrerequisite')) 'Server bootstrapper has no client driver prerequisite' }

        $work = [IO.Directory]::CreateDirectory((Join-Path $scratch $role)).FullName
        $path = Join-Path $work 'package.msi'
        $resource = $assembly.GetManifestResourceStream('BijouShare.Package.msi')
        Confirm-Check ($null -ne $resource) "$role wrapper embeds a Windows Installer package"
        try {
            $output = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
            try { $resource.CopyTo($output) } finally { $output.Dispose() }
        } finally { $resource.Dispose() }
        $db = Invoke-MsiMember $installer OpenDatabase @($path, 0)
        try { $metadata[$role] = Test-Msi $db $role $version $work }
        finally { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) }
    }
    Confirm-Check ($metadata.Client.UpgradeCode -ne $metadata.Server.UpgradeCode -and $metadata.Client.ProductCode -ne $metadata.Server.ProductCode) 'Each role has an independent Windows Installer upgrade family'
    Write-Output "Verified client and server installers $version, tray startup, completion messages, and unattended options."
} finally {
    $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    $parent = [IO.Path]::GetDirectoryName($scratch)
    if (([IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath([IO.Path]::GetTempPath())) -eq $parent) -and
        [IO.Path]::GetFileName($scratch).StartsWith('BijouShare-package-qa-', [StringComparison]::Ordinal)) {
        # The automation marshaler can retain a transient COM wrapper after closing a
        # read-only view. Cleanup must also preserve the original validation exception.
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        for ($attempt = 0; $attempt -lt 3; $attempt++) {
            try { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction Stop; break }
            catch {
                if ($attempt -eq 2) { Write-Warning "Could not remove temporary package inspection files at $scratch. $($_.Exception.Message)" }
                else { Start-Sleep -Milliseconds 250 }
            }
        }
    }
}
