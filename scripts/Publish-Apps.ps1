#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
foreach ($app in @('Service', 'Tray')) {
    $project = Join-Path $repo "src\UsbGuard.$app\UsbGuard.$app.csproj"
    $output = Join-Path $repo "artifacts\$app"
    dotnet publish $project -c Release -r win-x64 --self-contained false -o $output
    if ($LASTEXITCODE -ne 0) { throw "Publishing UsbGuard.$app failed." }
}
