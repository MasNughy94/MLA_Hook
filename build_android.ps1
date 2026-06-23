param(
    [string]$NDK = "D:\android-ndk-r27c",
    [string]$ABI = "arm64-v8a",
    [int]$API = 24,
    [string]$BuildType = "Release",
    [string]$CMake = "D:\cmake-portable\bin\cmake.exe"
)

$ProjectRoot = Split-Path -Parent $PSCommandPath
$ModuleDir = Join-Path $ProjectRoot "module"
$BuildDir = Join-Path $ProjectRoot "build\android"

# Clean and create build dir
if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
$null = New-Item -ItemType Directory -Path $BuildDir -Force

# Download prebuilt if not present
$PrebuiltDir = Join-Path $ModuleDir "prebuilt\$ABI"
if (-not (Test-Path (Join-Path $PrebuiltDir "libDobby.a"))) {
    Write-Host "Downloading prebuilt Dobby libraries..."
    & "$PSScriptRoot\module\download_prebuilt.ps1"
}

# Configure
Write-Host "Configuring CMake..."
& $CMake -G "Ninja" `
    -DCMAKE_TOOLCHAIN_FILE="$NDK\build\cmake\android.toolchain.cmake" `
    -DANDROID_ABI=$ABI `
    -DANDROID_PLATFORM=android-$API `
    -DANDROID_STL=c++_shared `
    -DCMAKE_BUILD_TYPE=$BuildType `
    -DCMAKE_SYSTEM_NAME=Android `
    -B $BuildDir `
    -S $ModuleDir

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Build
Write-Host "Building..."
& $CMake --build $BuildDir --config $BuildType --parallel

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build succeeded! Output:"
    Get-ChildItem -Recurse $BuildDir -Filter "*.so" | Select-Object FullName
}
