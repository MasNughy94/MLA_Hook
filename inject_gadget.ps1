# ====================================================
# Inject Frida Gadget + IL2CPP Hook ke MLA APK
# ====================================================
param(
    [string]$ApkInput = "C:\Users\ADMIN SERVICE\Videos\MLA\sources\MLADVENTURE.apk",
    [string]$ApktoolDir = "C:\Users\ADMIN SERVICE\Videos\MLA\sources\MLADVENTURE2",
    [string]$GadgetSo = "C:\Users\ADMIN SERVICE\Videos\MLA\sources\libfrida-gadget.so",
    [string]$HookScript = "C:\Users\ADMIN SERVICE\Videos\MLA\gadget_il2cpp_formation.js",
    [string]$OutputApk = "C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE_MODDED.apk",
    [string]$Apktool = "C:\Users\ADMIN SERVICE\Videos\MLA\sources\apktool.jar"
)

Write-Host "=== MLA Frida Gadget Injection ===" -ForegroundColor Cyan
Write-Host ""

# 1. Verify files
Write-Host "[1/5] Verifying files..." -ForegroundColor Yellow
$files = @{
    "APK input" = $ApkInput
    "Apktool dir" = $ApktoolDir
    "Gadget .so" = $GadgetSo
    "Hook script" = $HookScript
    "apktool.jar" = $Apktool
}
$allOk = $true
foreach ($f in $files.Keys) {
    if (Test-Path $files[$f]) {
        Write-Host "  OK: $f -> $($files[$f])" -ForegroundColor Green
    } else {
        Write-Host "  MISSING: $f -> $($files[$f])" -ForegroundColor Red
        $allOk = $false
    }
}
if (-not $allOk) { exit 1 }

# 2. Copy gadget .so to lib/arm64-v8a
Write-Host "[2/5] Copying frida-gadget.so to lib/arm64-v8a..." -ForegroundColor Yellow
$gadgetTarget = Join-Path $ApktoolDir "lib\arm64-v8a\libfrida-gadget.so"
Copy-Item $GadgetSo $gadgetTarget -Force
Write-Host "  Copied: $gadgetTarget" -ForegroundColor Green

# 3. Create gadget config (embedded in filename)
Write-Host "[3/5] Creating gadget config..." -ForegroundColor Yellow
$config = @{
    interaction = @{
        type = "script"
        path = "/data/local/tmp/gadget_il2cpp_formation.js"
        on_load = "resume"
    }
} | ConvertTo-Json -Compress

# Also create a config file alongside the .so
$configFile = Join-Path $ApktoolDir "lib\arm64-v8a\libfrida-gadget.config.so"
$config | Out-File -FilePath $configFile -Encoding ascii
Write-Host "  Config: $configFile" -ForegroundColor Green
Write-Host "  Config content: $config" -ForegroundColor Gray

# 4. Copy hook script
Write-Host "[4/5] Preparing hook script for device..." -ForegroundColor Yellow
$hookTarget = Join-Path $ApktoolDir "assets\gadget_il2cpp_formation.js"
Copy-Item $HookScript $hookTarget -Force
Write-Host "  Copied: $hookTarget" -ForegroundColor Green

# 5. Build & sign
Write-Host "[5/5] Building modified APK..." -ForegroundColor Yellow
$buildDir = Join-Path $ApktoolDir "..\MLADVENTURE_BUILD"
if (Test-Path $buildDir) { Remove-Item -Recurse -Force $buildDir }

# Build
java -jar $Apktool b $ApktoolDir -o $OutputApk 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  apktool build FAILED!" -ForegroundColor Red
    exit 1
}
Write-Host "  Built: $OutputApk" -ForegroundColor Green

# Sign with debug key
Write-Host "  Signing APK..." -ForegroundColor Yellow
$debugKeystore = "$env:USERPROFILE\.android\debug.keystore"
if (Test-Path $debugKeystore) {
    # Use apksigner from Android SDK if available
    $apksigner = Get-Command "apksigner" -ErrorAction SilentlyContinue
    if ($apksigner) {
        & $apksigner sign --ks $debugKeystore --ks-pass pass:android $OutputApk 2>&1
    } else {
        # Use jarsigner
        jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore $debugKeystore -storepass android $OutputApk androiddebugkey 2>&1
    }
    Write-Host "  Signed with debug key" -ForegroundColor Green
} else {
    Write-Host "  [!] No debug keystore found. Create one: 'keytool -genkey -v -keystore debug.keystore -alias debug -keyalg RSA -keysize 2048 -validity 10000'" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== DONE ===" -ForegroundColor Cyan
Write-Host "Modified APK: $OutputApk" -ForegroundColor Green
Write-Host ""
Write-Host "Install & run:"
Write-Host "  adb uninstall com.moonton.mobilehero"
Write-Host "  adb install $OutputApk"
Write-Host "  adb shell monkey -p com.moonton.mobilehero -c android.intent.category.LAUNCHER 1"
Write-Host ""
Write-Host "Then push hook script:"
Write-Host "  adb push gadget_il2cpp_formation.js /data/local/tmp/"
Write-Host ""
