#!/usr/bin/env pwsh
# ============================================================================
# EXMSW (mswsock.dll emulator) Build Script
# ============================================================================
# Requires: exws2.lib in output directories
# ============================================================================

param(
    [switch]$Clean,
    [switch]$Verbose,
    [switch]$ShowErrors = $true,
    [switch]$CleanupEXWS2 = $true  # Cleanup EXWS2.dll/lib after build
)

$ErrorActionPreference = "Continue"

# ============================================================================
# Configuration
# ============================================================================
$ProjectName = "EXMSW"
$OutputDLL = "EXMSW.dll"
$RuntimeDir = "ucrt"

$Architectures = @(
    @{ Name = "x64";   Target = "x86_64-pc-windows-msvc" }
    @{ Name = "arm64"; Target = "aarch64-pc-windows-msvc" }
    @{ Name = "x32";   Target = "i686-pc-windows-msvc" }
)

# ============================================================================
# Helper Functions
# ============================================================================
function Write-Status {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "[$ProjectName] $Message" -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-Status $Message -Color Green }
function Write-Error-Custom { param([string]$Message) Write-Status $Message -Color Red }
function Write-Warning-Custom { param([string]$Message) Write-Status $Message -Color Yellow }
function Test-Command { param([string]$Command) return (Get-Command $Command -ErrorAction SilentlyContinue) -ne $null }

# ============================================================================
# Prerequisites
# ============================================================================
Write-Status "Checking prerequisites..."
$required = @("cmake", "ninja", "clang-cl", "lld-link")
$missing = $required | Where-Object { -not (Test-Command $_) }

$hasRC = (Test-Command "llvm-rc") -or (Test-Command "windres")
if (-not $hasRC) {
    $missing += "llvm-rc/windres"
}

if ($missing) {
    Write-Error-Custom "Missing: $($missing -join ', ')"
    exit 1
}
Write-Success "All tools found"

# ============================================================================
# Check for exws2.lib
# ============================================================================
Write-Status "Checking for exws2.lib in include directories..."
$exws2Found = $false

foreach ($arch in $Architectures) {
    $libPath = "include\$($arch.Name)\exws2.lib"
    if (Test-Path $libPath) {
        Write-Status "  Found: $libPath" -Color Green
        $exws2Found = $true
    } else {
        Write-Warning-Custom "  Missing: $libPath"
    }
}

if (-not $exws2Found) {
    Write-Warning-Custom "No exws2.lib found!"
    Write-Warning-Custom "EXMSW requires exws2.lib to link properly."
    Write-Warning-Custom "Build will continue but may fail at link stage."
    Write-Host ""
    Write-Host "To fix:" -ForegroundColor Yellow
    Write-Host "  1. Build exws2 project first" -ForegroundColor Yellow
    Write-Host "  2. Copy exws2.lib to include\{arch}\ directories" -ForegroundColor Yellow
    Write-Host "     Example: include\x64\exws2.lib" -ForegroundColor Yellow
    Write-Host ""
    
    $continue = Read-Host "Continue anyway? (y/N)"
    if ($continue -ne "y" -and $continue -ne "Y") {
        exit 1
    }
}

# ============================================================================
# Clean
# ============================================================================
if ($Clean) {
    Write-Status "Cleaning..."
    Get-ChildItem -Directory -Filter "build-*" | Remove-Item -Recurse -Force
    Write-Success "Clean complete"
    if (-not $Verbose) { exit 0 }
}

# ============================================================================
# Build Function
# ============================================================================
function Build-Architecture {
    param([hashtable]$Arch)
    
    $archName = $Arch.Name
    $target = $Arch.Target
    
    Write-Status "========================================" -Color Yellow
    Write-Status "Building $archName ($target)" -Color Yellow
    Write-Status "========================================" -Color Yellow
    
    $buildDir = "build-$archName"
    $outputDir = "$RuntimeDir\$archName"
    
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    
    # Check for exws2.lib in include directory
    $exws2Lib = "include\$archName\exws2.lib"
    if (-not (Test-Path $exws2Lib)) {
        Write-Warning-Custom "exws2.lib not found at: $exws2Lib"
        Write-Warning-Custom "Build may fail at link stage!"
    }
    
    # ========================================================================
    # CMake Configure
    # ========================================================================
    Write-Status "Configuring CMake..."
    
    $cmakeArgs = @(
        "-G", "Ninja"
        "-DCMAKE_BUILD_TYPE=Release"
        "-DCMAKE_C_COMPILER=clang-cl"
        "-DCMAKE_RC_COMPILER=llvm-rc"
        "-DCMAKE_LINKER=lld-link"
        "-DCMAKE_SYSTEM_NAME=Windows"
        "-DCMAKE_C_COMPILER_TARGET=$target"
        "-DARCH_SUFFIX=$archName"
        "-DRUNTIME_DIR=$RuntimeDir"
        "-B", $buildDir
    )
    
    if ($Verbose) { $cmakeArgs += "--trace-expand" }
    
    $output = & cmake @cmakeArgs 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    
    if ($Verbose) {
        Write-Host "=== CMake Output ===" -ForegroundColor DarkCyan
        Write-Host $output
    }
    
    if ($exitCode -ne 0) {
        Write-Error-Custom "Configuration failed (exit: $exitCode)"
        
        if (-not $Verbose -and $ShowErrors) {
            Write-Host ""
            Write-Host "=== ERRORS ===" -ForegroundColor Red
            $output -split "`n" | Where-Object { $_ -match "error|fatal|CMake Error" } | ForEach-Object {
                Write-Host $_ -ForegroundColor Red
            }
            Write-Host ""
        }
        
        $output | Out-File "$buildDir-config.log"
        Write-Host "Full log: $buildDir-config.log" -ForegroundColor Yellow
        
        return $false
    }
    
    Write-Success "Configuration successful"
    
    # ========================================================================
    # Build
    # ========================================================================
    Write-Status "Building..."
    
    $buildArgs = @("--build", $buildDir)
    if ($Verbose) { $buildArgs += "--verbose" }
    
    $output = & cmake @buildArgs 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    
    if ($Verbose) {
        Write-Host "=== Build Output ===" -ForegroundColor DarkCyan
        Write-Host $output
    }
    
    if ($exitCode -ne 0) {
        Write-Error-Custom "Build failed (exit: $exitCode)"
        
        if (-not $Verbose -and $ShowErrors) {
            Write-Host ""
            Write-Host "=== ERRORS ===" -ForegroundColor Red
            $output -split "`n" | Where-Object { 
                $_ -match "error" -and $_ -notmatch "0 error"
            } | ForEach-Object {
                Write-Host $_ -ForegroundColor Red
            }
            Write-Host ""
        }
        
        $output | Out-File "$buildDir-build.log"
        Write-Host "Full log: $buildDir-build.log" -ForegroundColor Yellow
        
        return $false
    }
    
    Write-Success "Build complete: $outputDir\$OutputDLL"
    
    # Verify DLL
    $dllPath = "$outputDir\$OutputDLL"
    if (Test-Path $dllPath) {
        $size = [math]::Round((Get-Item $dllPath).Length/1KB, 2)
        Write-Status "  Size: $size KB" -Color Green
    } else {
        Write-Error-Custom "DLL not found: $dllPath"
        return $false
    }
    
    return $true
}

# ============================================================================
# Cleanup EXWS2 files
# ============================================================================
function Cleanup-EXWS2Files {
    Write-Status ""
    Write-Status "========================================" -Color Cyan
    Write-Status "Cleaning up EXWS2.dll files" -Color Cyan
    Write-Status "========================================" -Color Cyan
    
    $cleaned = 0
    
    foreach ($arch in $Architectures) {
        $dir = "$RuntimeDir\$($arch.Name)"
        
        $exws2Dll = "$dir\EXWS2.dll"
        
        if (Test-Path $exws2Dll) {
            Remove-Item $exws2Dll -Force
            Write-Status "  Deleted: $exws2Dll" -Color Yellow
            $cleaned++
        }
    }
    
    if ($cleaned -eq 0) {
        Write-Status "  No EXWS2.dll files to clean" -Color Gray
    } else {
        Write-Success "Cleaned $cleaned EXWS2.dll files"
    }
    
    Write-Status "Note: exws2.lib stays in include/{arch}/ (needed for builds)" -Color Gray
}

# ============================================================================
# Main Build
# ============================================================================
Write-Status ""
Write-Status "========================================" -Color Cyan
Write-Status "EXMSW Build (mswsock.dll Emulator)" -Color Cyan
Write-Status "========================================" -Color Cyan
Write-Status "Runtime: $RuntimeDir"
Write-Status "Toolchain: clang-cl + lld-link"
Write-Status "Dependencies: include/{arch}/exws2.lib (static link)"
Write-Status "Architectures: $($Architectures.Name -join ', ')"
Write-Status ""

$startTime = Get-Date
$results = @()

foreach ($arch in $Architectures) {
    $success = Build-Architecture -Arch $arch
    $results += @{ Arch = $arch.Name; Success = $success }
    Write-Host ""
}

# ============================================================================
# Cleanup (if requested)
# ============================================================================
if ($CleanupEXWS2) {
    Cleanup-EXWS2Files
    Write-Host ""
}

# ============================================================================
# Summary
# ============================================================================
$duration = (Get-Date) - $startTime
$durationFormatted = "{0:mm}:{0:ss}" -f $duration
$successCount = ($results | Where-Object { $_.Success }).Count
$failCount = ($results | Where-Object { -not $_.Success }).Count

Write-Status "========================================" -Color Cyan
Write-Status "Build Summary" -Color Cyan
Write-Status "========================================" -Color Cyan
Write-Status "Duration: $durationFormatted"
Write-Status "Success: $successCount" -Color $(if ($successCount -eq 3) { "Green" } else { "Yellow" })
Write-Status "Failed: $failCount" -Color $(if ($failCount -gt 0) { "Red" } else { "Green" })

foreach ($r in $results) {
    $status = if ($r.Success) { "✓" } else { "✗" }
    $color = if ($r.Success) { "Green" } else { "Red" }
    Write-Host "  $($r.Arch): $status" -ForegroundColor $color
}

Write-Status "========================================" -Color Cyan

if ($failCount -gt 0) {
    Write-Error-Custom "Build completed with errors!"
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Ensure exws2.lib exists in include\{arch}\" -ForegroundColor Yellow
    Write-Host "     Example: include\x64\exws2.lib" -ForegroundColor Yellow
    Write-Host "  2. Check logs: build-*-build.log" -ForegroundColor Yellow
    Write-Host "  3. Run: .\build-all.ps1 -Verbose" -ForegroundColor Yellow
    exit 1
} else {
    Write-Success "All builds completed successfully!"
    Write-Host ""
    Write-Status "Note: EXMSW.dll requires:" -Color Yellow
    Write-Status "  - exws2.dll (in same directory)" -Color Yellow
    Write-Status "  - ws2_32.dll (system)" -Color Yellow
    exit 0
}