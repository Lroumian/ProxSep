param(
    [string]$WdkRoot = 'C:\Program Files (x86)\Windows Kits\10',
    [string]$LibClang = 'E:\Program Files\IDA Professional 9.4',
    [switch]$DebugBuild
)
$ErrorActionPreference = 'Stop'
$driverRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\drivers\proxsep-wfp'))
$previousWdkRoot = $env:WDKContentRoot
$previousClang = $env:LIBCLANG_PATH
$previousLocation = Get-Location
try {
    if (!(Test-Path -LiteralPath $WdkRoot)) { throw "WDK not found: $WdkRoot" }
    if (!(Test-Path -LiteralPath (Join-Path $LibClang 'libclang.dll'))) { throw "Existing libclang not found: $LibClang" }
    $env:WDKContentRoot = $WdkRoot
    $env:LIBCLANG_PATH = $LibClang
    Set-Location -LiteralPath $driverRoot
    $driverCargoArguments = @('build', '-p', 'proxsep-wfp', '--target', 'x86_64-pc-windows-msvc')
    $driverProfile = 'debug'
    if (!$DebugBuild) { $driverCargoArguments += '--release'; $driverProfile = 'release' }
    & cargo @driverCargoArguments
    if ($LASTEXITCODE -ne 0) { throw 'Driver build failed.' }
    $driverDll = Join-Path $driverRoot "target\x86_64-pc-windows-msvc\$driverProfile\proxsep_wfp.dll"
    $driverSys = Join-Path $driverRoot "target\x86_64-pc-windows-msvc\$driverProfile\proxsep-wfp.sys"
    Copy-Item -LiteralPath $driverDll -Destination $driverSys -Force
    Get-FileHash -LiteralPath $driverSys -Algorithm SHA256
    Write-Output "Built unsigned driver: $driverSys"
} finally {
    Set-Location -LiteralPath $previousLocation.Path
    $env:WDKContentRoot = $previousWdkRoot
    $env:LIBCLANG_PATH = $previousClang
}
