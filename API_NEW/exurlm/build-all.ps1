#!/usr/bin/env pwsh
# ============================================================================
# EXURLM Build Script v2.0 - Enhanced Error Diagnostics
# ============================================================================

param(
    [switch]$Clean,
    [switch]$Verbose,
    [switch]$ShowErrors = $true
)

$ErrorActionPreference = "Continue"

# ============================================================================
# Configuration
# ============================================================================
$ProjectName = "EXURLM"
$OutputDLL = "EXURLM.dll"
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
function Test-Command { param([string]$Command) return (Get-Command $Command -ErrorAction SilentlyContinue) -ne $null }

# ============================================================================
# Prerequisites
# ============================================================================
Write-Status "Checking prerequisites..."
$required = @("cmake", "ninja", "clang-cl", "lld-link", "llvm-rc")
$missing = $required | Where-Object { -not (Test-Command $_) }

if ($missing) {
    Write-Error-Custom "Missing: $($missing -join ', ')"
    exit 1
}
Write-Success "All tools found"

# ============================================================================
# Clean
# ============================================================================
if ($Clean) {
    Write-Status "Cleaning..."
    Get-ChildItem -Directory -Filter "build-*" | Remove-Item -Recurse -Force
    if (Test-Path $RuntimeDir) { Remove-Item -Recurse -Force $RuntimeDir }
    Write-Success "Clean complete"
    if (-not $Verbose) { exit 0 }
}

# ============================================================================
# Build Function with FULL ERROR CAPTURE
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
    
    # ========================================================================
    # CMake Configure - CAPTURE ALL OUTPUT
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
    
    # CAPTURE OUTPUT
    $output = & cmake @cmakeArgs 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    
    # SHOW OUTPUT
    if ($Verbose) {
        Write-Host "=== CMake Output ===" -ForegroundColor DarkCyan
        Write-Host $output
    }
    
    if ($exitCode -ne 0) {
        Write-Error-Custom "Configuration failed (exit: $exitCode)"
        
        # SHOW ERRORS
        Write-Host ""
        Write-Host "=== ERRORS ===" -ForegroundColor Red
        $output -split "`n" | Where-Object { $_ -match "error|fatal|CMake Error" } | ForEach-Object {
            Write-Host $_ -ForegroundColor Red
        }
        Write-Host ""
        
        # Save log
        $output | Out-File "$buildDir-config.log"
        Write-Host "Full log: $buildDir-config.log" -ForegroundColor Yellow
        
        return $false
    }
    
    # ========================================================================
    # Build - CAPTURE ALL OUTPUT
    # ========================================================================
    Write-Status "Building..."
    
    $buildArgs = @("--build", $buildDir)
    if ($Verbose) { $buildArgs += "--verbose" }
    
    # CAPTURE OUTPUT
    $output = & cmake @buildArgs 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    
    # SHOW OUTPUT
    if ($Verbose) {
        Write-Host "=== Build Output ===" -ForegroundColor DarkCyan
        Write-Host $output
    }
    
    if ($exitCode -ne 0) {
        Write-Error-Custom "Build failed (exit: $exitCode)"
        
        # SHOW ERRORS
        Write-Host ""
        Write-Host "=== COMPILATION ERRORS ===" -ForegroundColor Red
        $output -split "`n" | Where-Object { 
            $_ -match "error" -and $_ -notmatch "0 error"
        } | ForEach-Object {
            Write-Host $_ -ForegroundColor Red
        }
        Write-Host ""
        
        # Save log
        $output | Out-File "$buildDir-build.log"
        Write-Host "Full log: $buildDir-build.log" -ForegroundColor Yellow
        Write-Host "Tip: Run with -Verbose for complete output" -ForegroundColor Yellow
        
        return $false
    }
    
    Write-Success "Build complete: $outputDir\$OutputDLL"
    
    # Verify
    $dllPath = "$outputDir\$OutputDLL"
    if (Test-Path $dllPath) {
        $size = [math]::Round((Get-Item $dllPath).Length/1KB, 2)
        Write-Status "  Size: $size KB" -Color Green
    } else {
        Write-Error-Custom "DLL not found: $dllPath"
    }
    
    return $true
}

# ============================================================================
# Main Build
# ============================================================================
Write-Status ""
Write-Status "========================================" -Color Cyan
Write-Status "EXURLM Build (Pure LLVM)" -Color Cyan
Write-Status "========================================" -Color Cyan
Write-Status "Runtime: $RuntimeDir"
Write-Status "Toolchain: clang-cl + lld-link + llvm-rc"
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
    Write-Host "  1. Check logs: build-*-build.log" -ForegroundColor Yellow
    Write-Host "  2. Run: .\build-all.ps1 -Verbose" -ForegroundColor Yellow
    Write-Host "  3. Verify files: dllmain.c, urlmon.def, version.rc" -ForegroundColor Yellow
    exit 1
} else {
    Write-Success "All builds completed successfully!"
    exit 0
}