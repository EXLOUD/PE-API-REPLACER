#!/usr/bin/env pwsh
# ============================================================================
# EXSENS.dll (SENSAPI Emulator) - Build Script (CMake + Ninja + LLVM)
# ============================================================================
$ErrorActionPreference = "Stop"

# ============================================================================
# Налаштування
# ============================================================================
$NETWORK_ONLINE = $true  # $true = IsNetworkAlive() повертає TRUE, $false = FALSE

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " EXSENS.dll Build Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NETWORK_ONLINE: $(if($NETWORK_ONLINE){'YES (online mode)'}else{'NO (offline mode)'})" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# Перевірка інструментів
# ============================================================================
foreach ($tool in @("cmake", "ninja", "clang")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: '$tool' not found on PATH!" -ForegroundColor Red
        Write-Host "Please install LLVM and add it to PATH" -ForegroundColor Yellow
        exit 1
    }
}

# Перевірка llvm-rc або windres
$rcTool = $null
foreach ($rc in @("llvm-rc", "llvm-windres", "windres")) {
    if (Get-Command $rc -ErrorAction SilentlyContinue) {
        $rcTool = $rc
        break
    }
}

if (-not $rcTool) {
    Write-Host "ERROR: Resource compiler (llvm-rc/windres) not found!" -ForegroundColor Red
    exit 1
}

Write-Host "Found tools: CMake, Ninja, Clang, $rcTool" -ForegroundColor Green
Write-Host ""

# ============================================================================
# Конфігурації збірки
# ============================================================================
$configurations = @(
    # UCRT builds only
    @{
        Runtime = "ucrt"
        Arch = "x64"
        Target = "x86_64-pc-windows-msvc"
        Processor = "AMD64"
        BuildDir = "build-ucrt-x64"
    },
    @{
        Runtime = "ucrt"
        Arch = "arm64"
        Target = "aarch64-pc-windows-msvc"
        Processor = "ARM64"
        BuildDir = "build-ucrt-arm64"
    },
    @{
        Runtime = "ucrt"
        Arch = "x32"
        Target = "i686-pc-windows-msvc"
        Processor = "X86"
        BuildDir = "build-ucrt-x32"
    }
)

# ============================================================================
# Функція збірки
# ============================================================================
function Build-Configuration {
    param($Config)
    
    $name = "$($Config.Runtime)\$($Config.Arch)"
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " Building: $name" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Очистка build директорії
    if (Test-Path $Config.BuildDir) {
        Write-Host "Cleaning build directory..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $Config.BuildDir
    }
    
    # Створення output директорії
    $outputDir = "$($Config.Runtime)/$($Config.Arch)"
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    
    # CMake Configure
    Write-Host "Configuring..." -ForegroundColor Yellow
    
    $cmakeArgs = @(
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_C_COMPILER=clang",
        "-DCMAKE_C_COMPILER_TARGET=$($Config.Target)",
        "-DCMAKE_SYSTEM_NAME=Windows",
        "-DCMAKE_SYSTEM_PROCESSOR=$($Config.Processor)",
        "-DARCH_SUFFIX=$($Config.Arch)",
        "-DNETWORK_ONLINE=$(if($NETWORK_ONLINE){'ON'}else{'OFF'})",
        "-B", $Config.BuildDir,
        "-S", "."
    )
    
    & cmake @cmakeArgs
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: CMake configuration failed for $name!" -ForegroundColor Red
        exit 1
    }
    
    # Build
    Write-Host "Building..." -ForegroundColor Yellow
    & ninja -C $Config.BuildDir
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Build failed for $name!" -ForegroundColor Red
        exit 1
    }
    
    # Перевірка результату
    $dllPath = "$outputDir/EXSENS.dll"
    $libPath = "$outputDir/EXSENS.lib"
    
    if ((Test-Path $dllPath) -and (Test-Path $libPath)) {
        $dllSize = (Get-Item $dllPath).Length
        $libSize = (Get-Item $libPath).Length
        Write-Host "SUCCESS: $name" -ForegroundColor Green
        Write-Host "  DLL: $dllPath ($dllSize bytes)" -ForegroundColor Gray
        Write-Host "  LIB: $libPath ($libSize bytes)" -ForegroundColor Gray
    } else {
        Write-Host "ERROR: Output files not found for $name!" -ForegroundColor Red
        exit 1
    }
}

# ============================================================================
# Основний цикл збірки
# ============================================================================
$startTime = Get-Date

foreach ($config in $configurations) {
    Build-Configuration -Config $config
}

# ============================================================================
# Підсумок
# ============================================================================
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ALL BUILDS COMPLETED SUCCESSFULLY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build time: $($duration.ToString('mm\:ss'))" -ForegroundColor White
Write-Host ""
Write-Host "Output structure:" -ForegroundColor White
Write-Host "  ucrt/x64/EXSENS.dll + EXSENS.lib" -ForegroundColor Gray
Write-Host "  ucrt/arm64/EXSENS.dll + EXSENS.lib" -ForegroundColor Gray
Write-Host "  ucrt/x32/EXSENS.dll + EXSENS.lib" -ForegroundColor Gray
Write-Host ""
Write-Host "Configuration:" -ForegroundColor White
Write-Host "  IsNetworkAlive() -> $(if($NETWORK_ONLINE){'TRUE'}else{'FALSE'})" -ForegroundColor Gray
Write-Host "  IsDestinationReachable() -> FALSE (always)" -ForegroundColor Gray
Write-Host ""