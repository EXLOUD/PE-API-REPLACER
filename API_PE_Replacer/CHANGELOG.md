# Changelog

---

## [1.0.13] — 2026-03-07

### Fixed
- **Context menu corners transparent on Linux** — replaced the default `QMenu` with a
  `DarkMenu(QMenu)` subclass that sets `WA_TranslucentBackground`,
  `FramelessWindowHint`, and `NoDropShadowWindowHint`, so rounded corners are truly
  transparent instead of showing opaque background pixels outside the border-radius.
- **Log selection lost on right-click** — `QTextEdit` lost focus on right-click,
  clearing the selection before the context menu appeared. Fixed by saving
  `selectionStart` / `selectionEnd` before showing the menu and restoring the cursor
  with `KeepAnchor` afterwards.
- **Log selection color changed to grey when unfocused** — when the context menu stole
  focus, Qt switched the `QTextEdit` to the `Inactive` palette group, rendering the
  highlight grey. Fixed by copying the `Active` `Highlight` and `HighlightedText`
  palette colors into the `Inactive` group via `QPalette`.
- **Message dialog text not centered** — all `QMessageBox` dialogs displayed
  left-aligned text. Introduced `CenteredMessageBox(QMessageBox)` which overrides
  `showEvent` to apply `AlignHCenter | AlignVCenter` to every text `QLabel`, and two
  helpers `_msg()` / `_msg_question()` that replace all eight former static calls to
  `QMessageBox.warning`, `QMessageBox.information`, and `QMessageBox.question`.
- **About dialog — no spacing between info card and donations section** — the
  `donations_panel` had `setContentsMargins(0, 0, 0, 0)`; changed top margin to `16px`
  so the "Support" section is visually separated from the title/author card.

### Improved
- **Dark-themed log context menu** — added `QMenu` styling to `REFINED_STYLESHEET`
  (`bg_elevated` background, rounded items, `bg_overlay` hover, muted separator) and
  wired it via `CustomContextMenu` policy so the system menu is never shown.
- **Font selection on all platforms** — at startup `QApplication` now iterates
  `Inter → Segoe UI → DejaVu Sans → Liberation Sans → Noto Sans` and sets the first
  font for which `QFont.exactMatch()` returns `True`. Eliminates the
  `OpenType support missing for "Adwaita Sans"` Qt warning on GNOME/Fedora and ensures
  a consistent sans-serif face on Windows and macOS as well.
- **Folder search dialog replaced with resizable `QDialog`** — the subfolder-search
  prompt was a `QMessageBox` whose buttons had a fixed size and could not adapt to the
  window dimensions. Replaced with `FolderSearchDialog(QDialog)`: the window is
  resizable (`setSizeGripEnabled`), the three buttons sit in a `QHBoxLayout` with equal
  stretch factor so they always fill the full width, the primary action uses
  `variant="primary"` styling, and the text label wraps and stays centred at any size.
- **About dialog now maximisable on Windows** — `setFixedSize` replaced with
  `setMinimumSize` and `WindowMaximizeButtonHint` added to window flags, so double-
  clicking the title bar or pressing the maximise button correctly expands the window on
  Windows (Linux already handled this natively).
- **"Show every time" checkbox styled consistently across platforms** — on Linux the
  checkbox in the Language Selection dialog used the system GTK appearance instead of
  the application dark theme. Applied a scoped `setStyleSheet` directly on
  `show_again_checkbox` with accent-coloured indicator (`bg_overlay` background,
  rounded corners, `accent` fill when checked). The API-list checkboxes in the main
  window are intentionally left with their default system style.

### Code Quality
- **W0246 — useless parent delegation** — removed the trivial `__init__` from
  `CenteredMessageBox` that only called `super().__init__(*args, **kwargs)` with no
  additional logic.

### Performance
- **File addition speed** — replaced `lief.PE.parse()` in `FileProcessorWorker` with a
  manual raw-header read (`_read_pe_info`): reads only ~88 bytes from two offsets
  (DOS header + COFF header) instead of parsing the full PE structure. On large DLLs
  this can be orders of magnitude faster. Additionally, `update_stats()` is now called
  once after the entire batch completes instead of after every single file, and
  duplicate detection switched from `O(n²)` `any()` to an `O(n)` set lookup.

### Added
- **ARM64 architecture detection** — `_read_pe_info` now recognises machine type
  `0xAA64` (`IMAGE_FILE_MACHINE_ARM64`) and tags the file as `arm64` in the file list.
  Previously only `x86` and `x64` were detected; ARM64 binaries were silently shown as
  `x86`.

---

## [1.0.12] — 2026-03-05

### Fixed
- **Stylesheet parse errors** — `RefinedDivider`, `QTextEdit`, `QScrollArea`, and
  hover-state widgets emitted Qt warnings `Could not parse stylesheet`.
  Root cause: closing `}}` in plain (non-`f`) string literals was passed literally to
  the CSS parser instead of being collapsed to `}`.
  Fixed 7 occurrences across `RefinedDivider.__init__`, `_create_log_panel`,
  `RefinedFolderDialog.__init__`, and `on_file_item_hover`.

### Security
- **B314 (Medium) — XML injection** — replaced `import xml.etree.ElementTree as ET`
  with `import defusedxml.ElementTree as ET` across all XML parsing calls
  (`TranslationManager.load_language`, `get_language_name_from_xml`).
  The standard library parser is vulnerable to Billion Laughs and XXE attacks
  (CWE-20); `defusedxml` mitigates both.
- **B110 (Low) × 3 — Silent exception suppression** — replaced bare `except: pass`
  blocks with explicit error handling:
  - `get_language_name_from_xml` — prints a warning with filename and exception message
  - `UniversalPEPatcher.patch_all` IAT fallthrough — emits `log_iat_parse_failed` via
    `log_emitter`
  - `FileProcessorWorker.run` PE metadata read — prints a warning with exception message

### Code Quality
- `too-many-lines` — added module-level disable (2 400-line single-file GUI is an
  accepted constraint)
- `attribute-defined-outside-init` × 27 — pre-declared all 27 `PEPatcherGUI` UI
  attributes as `None` in `__init__` before `setup_ui()` call
- `redefined-outer-name` × 8 — renamed shadowing parameters:
  `lang_code` → `language_code` / `file_lang_code` / `selected_code`,
  `show_dialog` → `show_again`, `translator` → `tr`
- `too-many-nested-blocks` — extracted IAT scanning logic from `patch_all` into two
  helpers: `_apply_iat_replacements()` and `_scan_iat_entries()`, reducing nesting from
  9 to ≤ 5 levels
- `invalid-name` × 4 — added method-level disables for Qt-mandated camelCase event
  overrides (`mousePressEvent`, `mouseMoveEvent`, `mouseReleaseEvent`, `closeEvent`)
- `too-few-public-methods` × 6 — added class-level disables for intentionally minimal
  Qt signal/widget subclasses (`PatcherLogEmitter`, `FileProcessorWorker`,
  `RefinedContainer`, `RefinedSplitter`, `RefinedDivider`, `AboutDialog`)
- `too-many-instance-attributes` × 3 — added class-level disables for
  `SwipeableFileItem`, `RefinedFolderDialog`, `PEPatcherGUI`
- `too-many-*` (statements/locals/branches) × 7 — added method-level disables for
  `patch_all`, `PatcherWorker.run`, `LanguageDialog.__init__`,
  `SwipeableFileItem.__init__`, `RefinedFolderDialog.__init__`, `setup_ui`,
  `_create_settings_panel`, `AboutDialog.setup_ui`, `patching_done`
- `too-many-public-methods` — added class-level disable for `PEPatcherGUI`
- `c-extension-no-member` — added inline disable for `lief.PE.MACHINE_TYPES.AMD64`
- `line-too-long` (CSS block) — wrapped `REFINED_STYLESHEET` with
  `pylint: disable/enable=line-too-long`; added inline disable for Monero address
  (hash is immutable)
- `wrong-import-order` — moved `glob` before third-party imports; moved `defusedxml`
  into the third-party block alongside `lief`
- `missing-final-newline` — added trailing newline at EOF

### Dependencies
- Added `defusedxml` to `requirements.txt`

### Tooling
- Added `run.sh` — Unix equivalent of `run.bat`: creates venv, installs dependencies,
  launches `main.py`

---

## [1.0.11] — 2026-03-04

> Static-analysis refactor pass. No functional behaviour changed.

### Code Quality

#### Imports
- **W0611 × 9 — unused imports removed:**
  `platform`, `subprocess`, `tempfile` (stdlib);
  `QGridLayout`, `QListWidget`, `QSizePolicy`, `QFont`, `QPalette`, `QTextCursor`
  (PySide6) — none were referenced anywhere in the codebase.

#### Documentation
- **C0114** — added module-level docstring describing the application purpose and
  technology stack.
- **C0115 × 16** — added class docstrings to all 16 classes:
  `TranslationManager`, `PatcherLogEmitter`, `PermissionsManager`,
  `UniversalPEPatcher`, `FileProcessorWorker`, `FolderScannerWorker`,
  `PatcherWorker`, `ThreadManager`, `LanguageDialog`, `RefinedContainer`,
  `SwipeableFileItem`, `RefinedFolderDialog`, `RefinedSplitter`, `RefinedDivider`,
  `AboutDialog`, `PEPatcherGUI`.
- **C0116 × 57** — added docstrings to all public functions and methods.

#### Naming
- **C0103** — renamed `PatcherLogEmitter.log_Signal` → `log_signal` (3 occurrences:
  declaration, `emit()` body, and connection in `PatcherWorker.__init__`).
- **W0621** — renamed local variable `time` → `timestamp` in `PEPatcherGUI.log()` to
  avoid shadowing the standard library `time` module.
- **W0612** — renamed `no_button` → `_no_button` in `add_folder()`.

#### Protected Access
- **W0212 / E1101** — replaced `sys._MEIPASS` bare attribute access with
  `getattr(sys, '_MEIPASS', os.path.abspath("."))`.

#### Formatting
- **C0321 × 169** — expanded all semicolon-separated compound statements onto
  individual lines throughout the entire file.
- **C0303 × 117** — stripped trailing spaces from every affected line.
- **W0301 × 1** — removed stray `;` after `api_checks = {}` in `_create_settings_panel`.
- **C0325 × 2** — removed redundant parens in `not (...)` and `include_subfolders = (...)`.
- **W1309 × 2** — converted two literal f-strings with no placeholders to plain strings.

#### Logic
- **R1705** — removed redundant `else` branch after explicit `return` in `get_base_path()`.
- **W0107** — annotated the bare `except Exception: pass` in `patch_all` with an
  explanatory comment.

#### Tooling
- Added module-level `# pylint: disable` directives for C-extension false positives
  (`PySide6`, `lief`) and intentional Qt GUI patterns.

---

## [1.0.10] — 2025-10-29

_Update main.py to v1.0.10._

---

## [1.0.9] — 2025-10-28

### Added
- Cancel button improvements: added early cancellation detection with multiple
  checkpoints during file processing.
- Smart file removal: processed files are now automatically removed from the list when
  cancellation is triggered.
- Enhanced logging: cancellation logs now show total files processed, original file
  count, and remaining files.
- Language files validation: added error message when language files are missing from
  the `languages` folder.

### Fixed
- Fixed file counter synchronization when cancelling batch operations.
- Corrected remaining file count calculation after cancellation.
- Resolved issue where file list wouldn't update properly after processing multiple batches.
- Fixed UI file removal to prevent duplicate entries.
- Fixed language selection dialog to show proper error message when language files are
  not found.

### Improved
- Faster cancellation response time — now stops at the earliest possible point.
- Better user feedback with detailed cancellation statistics in logs.
- Cleaner UI state management after batch operations.
- Added 500 ms delay before showing cancellation dialog to allow UI animations to complete.
- Improved error handling for missing application resources.

### Technical
- Refactored `PatcherWorker` to track total file count and remaining files accurately.
- Optimized file removal logic in `patching_done` to prevent duplicate removals.
- Improved permission restoration handling during cancellation.
- Enhanced `LanguageDialog` with resource validation and user-friendly error messages.

---

## [1.0.8] — 2025-10-21

### Added
- **Dynamic language support** — application now automatically detects and loads
  language files (`lang_*.xml`) from a dedicated `languages` folder. Adding a new
  language requires no code changes.
- Language selection dialog on first launch with a scrollable list of available languages.
- Installer for required emulators (Inno Setup), located in the `API` folder.

### Fixed
- Restored polished "Refined Dark Theme" across the entire application, including
  dialogs and all button types.
- Buttons in About and Language Selection dialogs now correctly use the standard solid
  gray style.
- Re-implemented custom-styled scrollbars for all scrollable areas.
- User language preference is now correctly saved in `settings.ini` next to the
  executable when compiled with PyInstaller.

### Improved
- **Cancellable patching** — Start Patching button dynamically changes to Cancel
  during operation.
- **Thread management** — implemented `ThreadManager` to handle all background tasks
  cleanly, preventing UI freezes.
- Reinstated swipe-to-delete and hover-highlight on file list items.
- Sticky headers in Settings and Logs panels; Donation title in About window.
- Fixed `build.bat` and path handling to correctly bundle language files and
  `config.py` for compiled `.exe`.

---

## [1.0.0] — 2025-10-19

_Initial release._

- IAT and hex patching support.
- Batch file processing with real-time logging.
- Backup and overwrite options.
- Ukrainian interface.
- Supported APIs: WINHTTP, WININET, WS2_32, SENSAPI, IPHLPAPI, URLMON, NETAPI32,
  WSOCK32, WINTRUST.