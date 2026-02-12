#!/usr/bin/env pwsh
# ==============================================================================
# EXINET - WinINet Emulator Build Script
# Builds exinet.dll for multiple architectures and runtimes
# ==============================================================================

param(
    [switch]$Clean,
    [switch]$Verbose,
    [switch]$SkipDepCheck
)

$ErrorActionPreference = "Stop"

# ==============================================================================
# Configuration
# ==============================================================================
$PROJECT_NAME  = "EXINET"
$DLL_NAME      = "exinet.dll"
$LIB_NAME      = "exinet.lib"
$RUNTIMES      = @("ucrt")
$ARCHES        = @("x64", "arm64", "x32")
$SCRIPT_DIR    = $PSScriptRoot

# ==============================================================================
# Output helpers
# ==============================================================================
function Print-Header($msg) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $msg" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

function Print-Error($msg)    { Write-Host "ERROR: $msg" -ForegroundColor Red }
function Print-Warn($msg)     { Write-Host "WARNING: $msg" -ForegroundColor Yellow }
function Print-OK($msg)       { Write-Host "$msg" -ForegroundColor Green }
function Print-Info($msg)     { Write-Host "$msg" -ForegroundColor Yellow }
function Print-Detail($msg)   { Write-Host "  $msg" -ForegroundColor DarkGray }

# ==============================================================================
# Tool detection
# ==============================================================================
function Test-Tools {
    Print-Header "$PROJECT_NAME Build Configuration"

    $tools = @{
        "CMake"   = "cmake"
        "Ninja"   = "ninja"
        "Clang"   = "clang"
        "llvm-rc" = "llvm-rc"
    }

    $ok = $true
    foreach ($t in $tools.GetEnumerator()) {
        if (Get-Command $t.Value -ErrorAction SilentlyContinue) {
            Write-Host "  ✓ $($t.Key): Found" -ForegroundColor Green
        } else {
            Write-Host "  ✗ $($t.Key) not found" -ForegroundColor Red
            $ok = $false
        }
    }

    if (-not $ok) {
        Print-Error "Required tools missing. Install LLVM + Ninja + CMake."
        exit 1
    }
}

# ==============================================================================
# Source File Check
# ==============================================================================
function Test-Sources {
    Print-Header "Source File Check"

    $files = @(
        "main.c"
        "http.c"
        "ftp.c"
        "cache.c"
        "stubs.c"
        "wininet_internal.h"
        "wininet.def"
        "version.rc"
        "CMakeLists.txt"
    )

    $ok = $true
    foreach ($f in $files) {
        $path = Join-Path $SCRIPT_DIR $f
        if (-not (Test-Path $path)) {
            Write-Host "  ✗ $f (missing)" -ForegroundColor Red
            $ok = $false
        } elseif ($Verbose) {
            Write-Host "  ✓ $f" -ForegroundColor Green
        }
    }

    if (-not $ok) {
        Print-Error "Some required source files missing."
        exit 1
    }

    Print-OK "All source files found!"
}

# ==============================================================================
# Dependency Check
# ==============================================================================
function Test-Deps($arch) {
    $exws2Path = Join-Path $SCRIPT_DIR "include\$arch\exws2.lib"
    $exiphlPath = Join-Path $SCRIPT_DIR "include\$arch\exiphl.lib"

    $ok = $true

    if (-not (Test-Path $exws2Path)) {
        Print-Warn "exws2.lib missing for architecture: $arch"
        Print-Detail "Expected path: $($exws2Path)"
        $ok = $false
    }

    if (-not (Test-Path $exiphlPath)) {
        Print-Warn "exiphl.lib missing for architecture: $arch"
        Print-Detail "Expected path: $($exiphlPath)"
        $ok = $false
    }

    return $ok
}

# ==============================================================================
# Clean command
# ==============================================================================
function Run-Clean {
    Print-Header "Cleaning build directories"

    Get-ChildItem -Path $SCRIPT_DIR -Filter "build-*" -Directory |
        ForEach-Object {
            Print-Detail "Removing $($_.Name)"
            Remove-Item $_.FullName -Force -Recurse
        }

    foreach ($r in $RUNTIMES) {
        $rt = Join-Path $SCRIPT_DIR $r
        if (Test-Path $rt) {
            Print-Detail "Removing $r"
            Remove-Item $rt -Force -Recurse
        }
    }

    Print-OK "Cleanup complete!"
}

# ==============================================================================
# Build process for a single configuration
# ==============================================================================
function Run-Build($runtime, $arch) {

    Print-Header "Building: $runtime\$arch"

    if (-not $SkipDepCheck) {
        if (-not (Test-Deps $arch)) {
            Print-Error "Required libraries (exws2.lib or exiphl.lib) missing for $arch — skipping."
            return $false
        }
    }

    $triple = switch ($arch) {
        "x64"   { "x86_64-pc-windows-msvc" }
        "arm64" { "aarch64-pc-windows-msvc" }
        "x32"   { "i686-pc-windows-msvc" }
    }

    Write-Host "  Target triple: $triple" -ForegroundColor Yellow

    $buildDir = Join-Path $SCRIPT_DIR "build-$runtime-$arch"

    $configureCmd = @(
        "-G", "Ninja"
        "-S", $SCRIPT_DIR
        "-B", $buildDir
        "-DCMAKE_BUILD_TYPE=Release"
        "-DCMAKE_C_COMPILER=clang"
        "-DCMAKE_C_COMPILER_TARGET=$triple"
        "-DARCH_SUFFIX=$arch"
        "-DRUNTIME_DIR=$runtime"
    )

    if ($Verbose) { Print-Detail "cmake $($configureCmd -join ' ')" }

    $cfg = & cmake @configureCmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Print-Error "Configuration failed."
        $cfg | Select-Object -Last 20 | ForEach-Object { Print-Detail $_ }
        return $false
    }

    $buildCmd = @("--build", $buildDir, "--config", "Release")
    if ($Verbose) { $buildCmd += "--verbose" }

    $buildOut = & cmake @buildCmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Print-Error "Compilation failed."
        $buildOut | ForEach-Object { Print-Detail $_ }
        return $false
    }

    # --- verify ---
    $outDir = Join-Path $SCRIPT_DIR "$runtime\$arch"
    $dll = Join-Path $outDir $DLL_NAME
    $lib = Join-Path $outDir $LIB_NAME

    if (Test-Path $dll) {
        $sz = [math]::Round((Get-Item $dll).Length / 1KB, 2)
        Write-Host "  ✓ DLL: exinet.dll ($sz KB)" -ForegroundColor Green
    } else {
        Print-Error "DLL missing: $dll"
        return $false
    }

    if (Test-Path $lib) {
        $sz = [math]::Round((Get-Item $lib).Length / 1KB, 2)
        Write-Host "  ✓ LIB: exinet.lib ($sz KB)" -ForegroundColor Green
    } else {
        Print-Warn "Import library missing: $lib"
    }

    Print-OK "$runtime\$arch - OK"
    return $true
}

# ==============================================================================
# Main
# ==============================================================================
Write-Host ""
Write-Host "  +==========================================+" -ForegroundColor Magenta
Write-Host "  |       EXINET - WinINet Emulator          |" -ForegroundColor Magenta
Write-Host "  +==========================================+" -ForegroundColor Magenta
Write-Host ""

if ($Clean) {
    Run-Clean
    exit 0
}

Test-Tools
Test-Sources

Print-Header "Dependency Check"

$allDeps = $true
foreach ($a in $ARCHES) {
    $exws2Path = Join-Path $SCRIPT_DIR "include\$a\exws2.lib"
    $exiphlPath = Join-Path $SCRIPT_DIR "include\$a\exiphl.lib"
    
    $exws2Exists = Test-Path $exws2Path
    $exiphlExists = Test-Path $exiphlPath
    
    if ($exws2Exists) {
        Write-Host "  ✓ include\$a\exws2.lib" -ForegroundColor Green
    } else {
        Write-Host "  ✗ include\$a\exws2.lib" -ForegroundColor Red
        $allDeps = $false
    }
    
    if ($exiphlExists) {
        Write-Host "  ✓ include\$a\exiphl.lib" -ForegroundColor Green
    } else {
        Write-Host "  ✗ include\$a\exiphl.lib" -ForegroundColor Red
        $allDeps = $false
    }
}

if (-not $allDeps -and -not $SkipDepCheck) {
    Print-Error "Missing required libraries (exws2.lib or exiphl.lib) for some architectures."
    exit 1
}

# --- build all ---
$total = 0
$ok = 0
$failed = @{}
$times = @{}

$timer = [Diagnostics.Stopwatch]::StartNew()

foreach ($r in $RUNTIMES) {
    foreach ($a in $ARCHES) {

        $total++
        $sw = [Diagnostics.Stopwatch]::StartNew()

        if (Run-Build $r $a) {
            $ok++
        } else {
            $failed["$r\$a"] = 1
        }

        $sw.Stop()
        $times["$r\$a"] = $sw.Elapsed
    }
}

$timer.Stop()

# ==============================================================================
# Summary
# ==============================================================================
Print-Header "Build Summary"

$failedCount = $total - $ok
$failedColor = if ($ok -eq $total) { "Green" } else { "Red" }

Write-Host "  Project:       $PROJECT_NAME"
Write-Host "  Version:       1.0.5.0"
Write-Host "  Total builds:  $total"
Write-Host "  Successful:    $ok" -ForegroundColor Green
Write-Host "  Failed:        $failedCount" -ForegroundColor $failedColor

if ($failedCount -gt 0) {
    Write-Host ""
    foreach ($f in $failed.Keys | Sort-Object) {
        Write-Host "    ✗ $f" -ForegroundColor Red
    }
}

Write-Host "`n  Build times:"
foreach ($t in $times.Keys | Sort-Object) {
    $dur = "{0:mm\:ss\.fff}" -f $times[$t]
    $okFlag = if ($failed.ContainsKey($t)) { "✗" } else { "✓" }
    Write-Host ("    {0} {1}: {2}" -f $okFlag, $t, $dur)
}

Write-Host "`n  Total time: $("{0:mm\:ss\.fff}" -f $timer.Elapsed)" -ForegroundColor Cyan

if ($ok -eq $total) {
    Print-OK "All builds completed successfully!"
    exit 0
}

Print-Error "Some builds failed!"
exit 1