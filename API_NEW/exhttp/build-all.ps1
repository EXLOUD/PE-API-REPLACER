#!/usr/bin/env pwsh
# WinHTTP Emulator Build Script
# Builds EXHTTP.dll for multiple architectures and runtimes

param(
    [switch]$Clean,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Configuration
$PROJECT_NAME = "EXHTTP"
$RUNTIMES = @("ucrt")
$ARCHITECTURES = @("x64", "arm64", "x32")

# Colors
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Write-Header($message) {
    Write-Host ""
    Write-ColorOutput Cyan "========================================"
    Write-ColorOutput Cyan " $message"
    Write-ColorOutput Cyan "========================================"
    Write-Host ""
}

function Write-Error-Custom($message) {
    Write-ColorOutput Red "ERROR: $message"
}

function Write-Success($message) {
    Write-ColorOutput Green $message
}

function Write-Info($message) {
    Write-ColorOutput Yellow $message
}

function Write-Warning-Custom($message) {
    Write-ColorOutput Yellow "WARNING: $message"
}

# Check required tools
function Test-Tools {
    Write-Header "$PROJECT_NAME.dll Build Configuration"
    
    $tools = @{
        "CMake" = "cmake"
        "Ninja" = "ninja"
        "Clang" = "clang"
        "llvm-rc" = "llvm-rc"
    }
    
    $allFound = $true
    foreach ($tool in $tools.GetEnumerator()) {
        $cmd = Get-Command $tool.Value -ErrorAction SilentlyContinue
        if ($cmd) {
            Write-Host "$($tool.Key): Found" -ForegroundColor Green
        } else {
            Write-Error-Custom "$($tool.Key) ($($tool.Value)) not found in PATH"
            $allFound = $false
        }
    }
    
    if (-not $allFound) {
        Write-Host ""
        Write-Error-Custom "Missing required tools. Please install LLVM/Clang toolchain."
        exit 1
    }
    
    Write-Host ""
    return $true
}

# Check for exws2.lib dependencies
function Test-Dependencies($runtime, $arch) {
    $exws2Path = "include\$arch\exws2.lib"
    
    if (-not (Test-Path $exws2Path)) {
        Write-Warning-Custom "exws2.lib not found at: $exws2Path"
        Write-Host ""
        Write-Host "EXHTTP requires exws2.lib to build." -ForegroundColor Yellow
        Write-Host "Please build EXWS2 first or place exws2.lib in include\$arch\" -ForegroundColor Yellow
        Write-Host ""
        return $false
    }
    
    return $true
}

# Clean build directories
function Invoke-Clean {
    Write-Header "Cleaning build directories"
    
    Get-ChildItem -Path . -Filter "build-*" -Directory | ForEach-Object {
        Write-Host "Removing: $($_.FullName)"
        Remove-Item $_.FullName -Recurse -Force
    }
    
    foreach ($runtime in $RUNTIMES) {
        if (Test-Path $runtime) {
            Write-Host "Removing: $runtime"
            Remove-Item $runtime -Recurse -Force
        }
    }
    
    Write-Success "Clean complete!"
}

# Build for specific runtime and architecture
function Invoke-Build($runtime, $arch) {
    $buildDir = "build-$runtime-$arch"
    
    Write-Header "Building: $runtime\$arch"
    
    # Check dependencies first
    if (-not (Test-Dependencies $runtime $arch)) {
        Write-Error-Custom "Missing dependencies for $runtime\$arch"
        return $false
    }
    
    # Determine target triple
    $targetTriple = switch ($arch) {
        "x64"   { "x86_64-pc-windows-msvc" }
        "arm64" { "aarch64-pc-windows-msvc" }
        "x32"   { "i686-pc-windows-msvc" }
    }
    
    # Configure
    Write-Host "Configuring..." -ForegroundColor Cyan
    
    $cmakeArgs = @(
        "-G", "Ninja"
        "-S", "."
        "-B", $buildDir
        "-DCMAKE_BUILD_TYPE=Release"
        "-DCMAKE_C_COMPILER=clang"
        "-DCMAKE_C_COMPILER_TARGET=$targetTriple"
        "-DARCH_SUFFIX=$arch"
        "-DRUNTIME_DIR=$runtime"
    )
    
    if ($Verbose) {
        $cmakeArgs += "--log-level=VERBOSE"
    }
    
    Write-Host "CMake command: cmake $($cmakeArgs -join ' ')" -ForegroundColor DarkGray
    & cmake @cmakeArgs
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Custom "CMake configuration failed for $runtime\$arch"
        return $false
    }
    
    # Build
    Write-Host "Building..." -ForegroundColor Cyan
    Write-Host "Build command: cmake --build $buildDir --config Release" -ForegroundColor DarkGray
    & cmake --build $buildDir --config Release
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Custom "Build failed for $runtime\$arch!"
        return $false
    }
    
    # Перевірка створених файлів
    $dllPath = "$runtime\$arch\EXHTTP.dll"
    $libPath = "$runtime\$arch\EXHTTP.lib"
    
    if (Test-Path $dllPath) {
        $dllSize = (Get-Item $dllPath).Length
        Write-Host "  ✓ DLL created: $dllPath ($([math]::Round($dllSize/1KB, 2)) KB)" -ForegroundColor Green
    } else {
        Write-Error-Custom "DLL not found: $dllPath"
        return $false
    }
    
    if (Test-Path $libPath) {
        $libSize = (Get-Item $libPath).Length
        Write-Host "  ✓ LIB created: $libPath ($([math]::Round($libSize/1KB, 2)) KB)" -ForegroundColor Green
    } else {
        Write-Warning "LIB not found: $libPath"
    }
    
    Write-Success "$runtime\$arch - OK"
    return $true
}

# Main execution
if ($Clean) {
    Invoke-Clean
    exit 0
}

Test-Tools

# Show dependency information
Write-Header "Dependency Check"
Write-Host "EXHTTP requires exws2.lib for each architecture." -ForegroundColor Cyan
Write-Host "Checking for exws2.lib files..." -ForegroundColor Cyan
Write-Host ""

$allDepsFound = $true
foreach ($arch in $ARCHITECTURES) {
    $exws2Path = "include\$arch\exws2.lib"
    if (Test-Path $exws2Path) {
        Write-Host "  ✓ $exws2Path" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $exws2Path (MISSING)" -ForegroundColor Red
        $allDepsFound = $false
    }
}

if (-not $allDepsFound) {
    Write-Host ""
    Write-Error-Custom "Some exws2.lib files are missing!"
    Write-Host "Please build EXWS2 first or place exws2.lib files in the include\ directories." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

Write-Host ""

# Build all configurations
$totalBuilds = 0
$successBuilds = 0

foreach ($runtime in $RUNTIMES) {
    foreach ($arch in $ARCHITECTURES) {
        $totalBuilds++
        if (Invoke-Build $runtime $arch) {
            $successBuilds++
        }
    }
}

Write-Host ""
Write-Header "Build Summary"
Write-Host "Total builds: $totalBuilds"
Write-Host "Successful: $successBuilds" -ForegroundColor Green
Write-Host "Failed: $($totalBuilds - $successBuilds)" -ForegroundColor $(if ($totalBuilds -eq $successBuilds) { "Green" } else { "Red" })

if ($successBuilds -eq $totalBuilds) {
    Write-Host ""
    Write-Success "All builds completed successfully!"
    Write-Host ""
    exit 0
} else {
    Write-Host ""
    Write-Error-Custom "Some builds failed!"
    exit 1
}