#Requires -RunAsAdministrator
#Requires -Version 5.1
param(
    [Parameter(Mandatory = $true)]
    [string]$DriverInf
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$install = Join-Path $env:ProgramFiles 'UsbGuard'
$DriverInf = (Resolve-Path -LiteralPath $DriverInf).Path

$windowsBuild = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -or $windowsBuild -lt 26100) {
    throw 'Use x64 Windows 11 24H2 or later for this lab package.'
}
if (Get-Service UsbGuard -ErrorAction SilentlyContinue) {
    throw 'The UsbGuard service already exists. See the README for lab removal before reinstalling.'
}
if ((Get-Service clamd).Status -ne 'Running') {
    throw 'Start the configured clamd service first. See the README.'
}
foreach ($app in @('Service', 'Tray')) {
    $exe = Join-Path $repo "artifacts\$app\UsbGuard.$app.exe"
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        throw 'Run Publish-Apps.ps1 first.'
    }
}

# Install the primitive INF using the supported driver-store API.
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class UsbGuardDriverPackage
{
    [DllImport("newdev.dll", EntryPoint = "DiInstallDriverW", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool Install(System.IntPtr window, string inf, uint flags, out bool reboot);
}
'@
$reboot = $false
if (-not [UsbGuardDriverPackage]::Install([IntPtr]::Zero, $DriverInf, 0, [ref]$reboot)) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw [ComponentModel.Win32Exception]::new($errorCode)
}
if ($reboot) {
    throw 'Windows requires a reboot to finish installing the driver. Reboot the lab machine and rerun this script.'
}

foreach ($app in @('Service', 'Tray')) {
    $source = Join-Path $repo "artifacts\$app"
    $destination = Join-Path $install $app
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    Copy-Item -Path (Join-Path $source '*') -Destination $destination -Recurse -Force
}

$filters = fltmc.exe filters
if ($LASTEXITCODE -ne 0) { throw 'Cannot query the loaded minifilters.' }
if (-not ($filters -match '^\s*UsbGuardFilter\s')) {
    fltmc.exe load UsbGuardFilter
    if ($LASTEXITCODE -ne 0) { throw 'UsbGuardFilter could not load. Check the driver signature and test-signing mode.' }
}

$serviceExe = Join-Path $install 'Service\UsbGuard.Service.exe'
New-Service -Name UsbGuard -DisplayName 'USB Guard' -BinaryPathName ('"' + $serviceExe + '"') `
    -StartupType Manual -DependsOn UsbGuardFilter | Out-Null
Start-Service UsbGuard
Write-Host "Launch $install\Tray\UsbGuard.Tray.exe from the standard test account before inserting a drive."
