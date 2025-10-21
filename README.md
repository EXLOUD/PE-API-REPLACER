<div align="center">

### 👇

  <p>
    <a href="https://github.com/EXLOUD/PE-API-REPLACER/releases/download/v1.0.8/PE-API-REPLACER_v1.0.8.zip">
      <img src="https://img.shields.io/badge/Download_PE_API_Replacer-darkgreen?style=for-the-badge&logo=download&logoColor=white">
    </a>
  </p>

---

### 👀 Repository Stats

  <img alt="GitHub Views" src="https://count.getloli.com/get/@:EXLOUD-PE-API-REPLACER?theme=rule34" />

  **⭐ If this tool helped you, please consider giving it a star! ⭐**

---

  <h1>PE API Replacer</h1>
  
  <p>
    <a href="https://en.wikipedia.org/wiki/Portable_Executable">
      <img src="https://img.shields.io/badge/PE_Patching-Binary_Modification-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="PE Patching">
    </a>
    <a href="https://www.python.org/downloads/">
      <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+">
    </a>
    <a href="https://riverbankcomputing.com/software/pyqt/">
      <img src="https://img.shields.io/badge/PyQt6-GUI_Framework-5391FE?style=for-the-badge&logo=qt&logoColor=white" alt="PyQt6">
    </a>
    <a href="https://github.com/mstorsjo/llvm-mingw/releases">
      <img src="https://img.shields.io/badge/llvm--mingw_21.1.3-C_Native_Libraries-DD0031?style=for-the-badge&logo=gnu&logoColor=white" alt="llvm-mingw">
    </a>
  </p>
  
  <img src="assets/preview.png" width="700" alt="PE API Replacer demo preview">
  
  [![GitHub issues](https://img.shields.io/github/issues/EXLOUD/pe-api-replacer?style=flat-square)](https://github.com/EXLOUD/pe-api-replacer/issues)
  ![Windows](https://img.shields.io/badge/OS-Windows%2FmacOS%2FLinux-0078D4?style=for-the-badge&logo=windows&logoColor=white)
  ![License](https://img.shields.io/badge/License-GPL--3.0-blue?style=for-the-badge)
  [![GitHub stars](https://img.shields.io/github/stars/EXLOUD/pe-api-replacer?style=flat-square)](https://github.com/EXLOUD/pe-api-replacer/stargazers)

  Professional GUI tool for replacing API imports in PE files. Batch process EXE, DLL, VST, and SYS files with automatic backups and detailed logging.

</div>

---

## 🎯 Features Overview

| Feature | Description |
|---------|-------------|
| **Batch Processing** | Handle multiple files simultaneously with progress tracking |
| **IAT Patching** | Direct modification of Import Address Tables in PE structures |
| **Hex Patching** | Binary search and replace for deep file modifications |
| **Recursive Scanning** | Automatically find PE files in nested directories |
| **Auto Backup** | Preserve originals before any modifications |
| **Real-time Logs** | Complete operation history for debugging |
| **Modern GUI** | Dark theme with smooth animations and intuitive layout |
| **Flexible Config** | Define custom API replacements easily |
| **Custom API Emulators** | Native C libraries compiled with llvm-mingw for high performance |

---

## 📋 System Requirements

- **OS:** Windows, macOS, or Linux
- **Python:** 3.10 or higher
- **Permissions:** Standard user (auto-elevates on Windows)
- **Native Libraries:** MinGW x64 runtime (included in package)

---

## 🛠️ Technology Stack

### Frontend & Core
- **Python 3.10+** - Main application logic
- **PyQt6** - Modern cross-platform GUI framework

### Native API Emulators
- **C/C++** - High-performance network interceptor libraries
- **llvm-mingw 21.1.3** with LLVM 21.1.3 - Compiler toolchain
  - Download: [llvm-mingw releases](https://github.com/mstorsjo/llvm-mingw/releases)
  - Target: x86_64-w64-mingw32 (64-bit Windows)

### Compilation Details
```bash
# llvm-mingw 20251007 provides:
- Clang/LLVM 21.1.3
- MinGW-w64 runtime
- Full Windows API support
- Optimized for native PE binary generation
```

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/pe-api-replacer.git
cd pe-api-replacer

# Install dependencies
pip install PyQt6 pefile
```

### Usage

```bash
python api_patcher_qt6.py
```

Then:
1. Click "Add Files" or "Add Folder"
2. Select APIs to replace
3. Configure backup/overwrite options
4. Click "Start Patching"

---

## 📁 Project Structure

```
📂 pe-api-replacer/
├── 📄 api_patcher_qt6.py          # Main GUI application (Python/PyQt6)
├── 📄 config.py                   # API configuration
├── 📂 api/                        # Native API emulator libraries
│   ├── 📄 winhttp_replacement.dll # Compiled with llvm-mingw 21.1.3
│   ├── 📄 wininet_replacement.dll # Compiled with llvm-mingw 21.1.3
│   └── 📄 ...                     # Additional C/C++ emulators
├── 📂 src/                        # C/C++ source files
│   ├── 📄 winhttp_replacement.c
│   ├── 📄 wininet_replacement.c
│   └── 📄 Makefile                # Build with llvm-mingw
├── 📂 assets/
│   └── 📄 preview.gif             # Demo screenshot
├── 📄 README.md
├── 📄 README-UK.md
└── 📄 LICENSE
```

---

## ⚙️ Configuration

Edit `config.py` to define your API replacements:

```python
DLL_REPLACEMENTS = {
    1: {'name': 'WINHTTP', 'replacements': {
        b'WINHTTP.DLL': b'MYHTTP.DLL\x00',
        b'WINHTTP.dll': b'MYHTTP.dll\x00',
    }},
    2: {'name': 'WININET', 'replacements': {
        b'WININET.DLL': b'MYINET.DLL\x00',
        b'WININET.dll': b'MYINET.dll\x00',
    }},
}
```

**Important:** Replacement length must equal original length. Pad with `\x00` if needed.

---

## 🔧 How It Works

### 1. IAT Modification (Python/PyQt6)
Directly edits the Import Address Table in the PE file header to redirect DLL imports.

### 2. Hex Patching (Python/PyQt6)
Scans binary content for DLL name sequences and replaces them throughout the file.

### 3. Native API Emulation (C/llvm-mingw)
Replacement DLL emulators provide drop-in replacements for system APIs with custom behavior:
- Compiled with **llvm-mingw 21.1.3 (LLVM 21.1.3)**
- Native x64 Windows binaries
- Transparent API interception
- Full Windows API compatibility

### 4. Multi-threaded Processing (Python)
Operations run asynchronously, keeping the GUI responsive during heavy workloads.

### 5. Safety Features (Python)
- Automatic backups in `backup/` folder
- Windows permission elevation
- Detailed operation logging
- Checksum recalculation

---

## 📊 Supported APIs (Default)

- ✅ WINHTTP
- ✅ WININET
- ✅ WS2_32
- ✅ SENSAPI
- ✅ IPHLPAPI
- ✅ URLMON
- ✅ NETAPI32
- ✅ WSOCK32
- ✅ WINTRUST

*Easily extensible – add custom APIs to `config.py` and compile emulators with llvm-mingw*

---

## 💡 Use Cases

### Replace Standard Libraries with Custom Versions
```python
b'WINHTTP.DLL': b'CUSTOM.DLL\x00'
```

### Network Traffic Interception (C Emulator)
```python
b'WININET.DLL': b'PROXY.DLL\x00\x00\x00'
# Native proxy emulator compiled with llvm-mingw intercepts calls
```

### DirectX Version Swapping
Add to `config.py`:
```python
b'D3D9.DLL': b'D3D9_EX.DLL\x00'
```

---

## 🔨 Building Native Libraries (Developers)

### Prerequisites
1. Download **llvm-mingw 20251007** from [mstorsjo/llvm-mingw releases](https://github.com/mstorsjo/llvm-mingw/releases)
2. Extract and add to PATH
3. Ensure `clang`, `clang++`, and `x86_64-w64-mingw32-gcc` are available

### Build Commands

```bash
# Navigate to source directory
cd src/

# Build individual emulator
x86_64-w64-mingw32-gcc -shared -O3 -o winhttp_replacement.dll winhttp_replacement.c

# Or use provided Makefile
make all

# Place compiled DLLs in api/ directory
mv *.dll ../api/
```

### Makefile Example
```makefile
CC = x86_64-w64-mingw32-gcc
CFLAGS = -shared -fPIC -O3 -Wall
TARGET = api/

all: winhttp_replacement.dll wininet_replacement.dll

winhttp_replacement.dll: src/winhttp_replacement.c
	$(CC) $(CFLAGS) -o $(TARGET)$@ $<

wininet_replacement.dll: src/wininet_replacement.c
	$(CC) $(CFLAGS) -o $(TARGET)$@ $<

clean:
	rm -f $(TARGET)*.dll
```

---

## ⚠️ Important Notes

- **Backup First:** Always create system restore points before patching
- **Test Before Production:** Use virtual machines for initial testing
- **Update Awareness:** Some settings may reset after Windows updates
- **Signature Impact:** Patching may invalidate digital signatures
- **Native Library Compatibility:** Ensure emulator DLLs are compiled for target architecture

---

## 🔄 Restoring Original Files

If patching causes issues:

1. Restore from `backup/` folder
2. Use system restore point (if created)
3. Manually restore from clean installation

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| ModuleNotFoundError | Run `pip install PyQt6 pefile` |
| "No files found" | Ensure PE files exist with correct format |
| Permission denied | Run with admin privileges on Windows |
| UI frozen | Wait for patching to complete (progress bar shows status) |
| Native DLL not found | Verify emulator DLLs in `api/` folder and recompile with llvm-mingw if needed |
| "Entry point not found" | Ensure DLL was compiled with compatible architecture (x64) |

---

## 📜 License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0)

```
PE API Replacer - Professional GUI tool for replacing API imports in PE files
Copyright (c) 2025 PE API Replacer Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
```

### What this means:

- ✅ You can use, modify, and distribute this software
- ✅ You can use it commercially
- ⚠️ Any modified versions must also be GPL 3
- ⚠️ You must provide source code to users
- ⚠️ You must include the GPL 3 license text
- ⚠️ You must credit the original authors

See [LICENSE](LICENSE) for full text.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

For native library contributions, ensure compilation with **llvm-mingw 21.1.3**.

---

## 📞 Support & Feedback

- **Report Bugs:** [Create an Issue](https://github.com/yourusername/pe-api-replacer/issues)
- **Feature Requests:** Use Issues with `[FEATURE]` tag
- **Discussions:** Check existing discussions first

---

## 🔗 Related Resources

- [pefile Documentation](https://github.com/erocarrera/pefile)
- [PE File Format](https://en.wikipedia.org/wiki/Portable_Executable)
- [PyQt6 Documentation](https://www.riverbankcomputing.com/static/Docs/PyQt6/)
- [llvm-mingw Releases](https://github.com/mstorsjo/llvm-mingw/releases)
- [Reverse Engineering Resources](https://www.reverseengineering.com/)

---

## 👨‍💻 Author

**PE API Replacer Development Team**

- GitHub: [EXLOUD](https://github.com/EXLOUD)
- Issues & Support: [GitHub Issues](https://github.com/EXLOUD/pe-api-replacer/issues)

---

<div align="center">

**Version:** 1.0.8 
**Last Updated:** 2025  
**Status:** ✅ Stable  
**Built with:** Python 3.10+, PyQt6, C/llvm-mingw 21.1.3

**[⬆ Back to Top](#pe-api-replacer)**

</div>
