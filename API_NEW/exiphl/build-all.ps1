#!/usr/bin/env pwsh
# EXIPHL.dll Build Script
# Builds EXIPHL.dll for multiple architectures and runtimes

param(
    [switch]$Clean,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Configuration
$PROJECT_NAME = "EXIPHL"
$RUNTIMES = @("ucrt")  # Can add "msvcrt" if needed
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
    
    # Determine target triple
    $targetTriple = switch ($arch) {
        "x64"   { "x86_64-pc-windows-msvc" }
        "arm64" { "aarch64-pc-windows-msvc" }
        "x32"   { "i686-pc-windows-msvc" }
    }
    
    # Configure
    Write-Host "Configuring..." -ForegroundColor Cyan
    
    # Автоматична перевірка exws2.lib для цієї архітектури
    $exws2Path = "include\$arch\exws2.lib"
    $useExWS2 = Test-Path $exws2Path
    
    if ($useExWS2) {
        Write-Host "  → EXWS2 linking: ENABLED (found $exws2Path)" -ForegroundColor Green
    } else {
        Write-Host "  → EXWS2 linking: DISABLED (exws2.lib not found)" -ForegroundColor DarkGray
    }
    
    $cmakeArgs = @(
        "-G", "Ninja"
        "-S", "."
        "-B", $buildDir
        "-DCMAKE_BUILD_TYPE=Release"
        "-DCMAKE_C_COMPILER=clang"
        "-DCMAKE_CXX_COMPILER=clang++"
        "-DCMAKE_C_COMPILER_TARGET=$targetTriple"
        "-DCMAKE_CXX_COMPILER_TARGET=$targetTriple"
        "-DARCH_SUFFIX=$arch"
        "-DRUNTIME_DIR=$runtime"
    )
    
    # Додаємо USE_EXWS2 автоматично на основі наявності файлу
    if ($useExWS2) {
        $cmakeArgs += "-DUSE_EXWS2=ON"
    } else {
        $cmakeArgs += "-DUSE_EXWS2=OFF"
    }
    
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
        Write-Host ""
        Write-Host "To see detailed error output, run:" -ForegroundColor Yellow
        Write-Host "  cmake --build $buildDir --config Release --verbose" -ForegroundColor White
        return $false
    }
    
    # Перевірка створених файлів
    $dllPath = "$runtime\$arch\EXIPHL.dll"
    $libPath = "$runtime\$arch\EXIPHL.lib"
    
    # Якщо файли не в правильному місці, спробуємо знайти і скопіювати
    if (-not (Test-Path $dllPath)) {
        Write-Host "  Searching for output files..." -ForegroundColor Yellow
        
        $buildDll = Get-ChildItem -Path $buildDir -Recurse -Filter "EXIPHL.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
        $buildLib = Get-ChildItem -Path $buildDir -Recurse -Filter "EXIPHL.lib" -ErrorAction SilentlyContinue | Select-Object -First 1
        
        if ($buildDll) {
            New-Item -ItemType Directory -Force -Path "$runtime\$arch" | Out-Null
            Copy-Item $buildDll.FullName "$runtime\$arch\EXIPHL.dll" -Force
            Write-Host "  → Copied DLL from build directory" -ForegroundColor Gray
        }
        
        if ($buildLib) {
            Copy-Item $buildLib.FullName "$runtime\$arch\EXIPHL.lib" -Force
            Write-Host "  → Copied LIB from build directory" -ForegroundColor Gray
        }
    }
    
    # Тепер перевіряємо чи файли на місці
    if (Test-Path $dllPath) {
        $dllSize = (Get-Item $dllPath).Length
        Write-Host "  ✓ DLL created: $dllPath ($([math]::Round($dllSize/1KB, 2)) KB)" -ForegroundColor Green
    } else {
        Write-Error-Custom "DLL not found: $dllPath"
        Write-Host "  Build directory contents:" -ForegroundColor Yellow
        Get-ChildItem -Path $buildDir -Recurse -Include "*.dll","*.lib" -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "    $($_.FullName)" -ForegroundColor Gray
        }
        return $false
    }
    
    if (Test-Path $libPath) {
        $libSize = (Get-Item $libPath).Length
        Write-Host "  ✓ LIB created: $libPath ($([math]::Round($libSize/1KB, 2)) KB)" -ForegroundColor Green
    } else {
        Write-Warning "LIB not found: $libPath"
    }
    
    # Перевірка exws2.lib якщо було увімкнено
    if ($useExWS2) {
        Write-Host "  ✓ Using exws2.lib: $exws2Path" -ForegroundColor Green
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
    Write-Host "Output files:" -ForegroundColor Cyan
    Get-ChildItem -Path "ucrt" -Recurse -Include "*.dll","*.lib" -ErrorAction SilentlyContinue | ForEach-Object {
        $size = [math]::Round($_.Length / 1KB, 2)
        Write-Host "  $($_.FullName) ($size KB)" -ForegroundColor White
    }
    
    # Показати інформацію про використання exws2
    $hasExWS2 = $false
    foreach ($arch in $ARCHITECTURES) {
        if (Test-Path "include\$arch\exws2.lib") {
            $hasExWS2 = $true
            break
        }
    }
    
    if ($hasExWS2) {
        Write-Host ""
        Write-Info "Note: exws2.lib was found and linked. exws2.dll must be next to EXIPHL.dll at runtime!"
    }
    
    exit 0
} else {
    Write-Host ""
    Write-Error-Custom "Some builds failed!"
    exit 1
}