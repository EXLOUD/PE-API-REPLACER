# -*- coding: utf-8 -*-
"""
PE Patcher GUI — graphical tool for binary-patching DLL import names in PE files.

Patches Windows PE executables to redirect DLL imports (WINHTTP, WININET, etc.)
using both IAT-level and raw-hex strategies.  Supports backup, overwrite, folder
scanning, and a localised PySide6 dark-theme UI.
"""
# pylint: disable=line-too-long
# pylint: disable=too-many-lines
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-few-public-methods
# pylint: disable=too-many-public-methods
# pylint: disable=too-many-statements
# pylint: disable=too-many-locals
# pylint: disable=too-many-branches
# pylint: disable=too-many-nested-blocks
# pylint: disable=too-many-arguments
# pylint: disable=too-many-positional-arguments
# pylint: disable=attribute-defined-outside-init
# pylint: disable=redefined-outer-name
# pylint: disable=invalid-name
# pylint: disable=c-extension-no-member

import sys
import os
import stat
import shutil
import re
from datetime import datetime
from pathlib import Path
from typing import List, Tuple
from configparser import ConfigParser
import glob

import defusedxml.ElementTree as ET  # pylint: disable=import-error
import lief  # pylint: disable=import-error
from PySide6.QtWidgets import (  # pylint: disable=no-name-in-module
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTextEdit, QFrame, QFileDialog, QMessageBox, QCheckBox, QDialog,
    QProgressBar, QScrollArea, QGraphicsDropShadowEffect,
    QGroupBox, QSplitter, QTextBrowser,
)
from PySide6.QtCore import (  # pylint: disable=no-name-in-module
    QThread, QObject, Signal, Qt, QTranslator, QLibraryInfo, QTimer,
    QPropertyAnimation, QPoint, QEasingCurve, QParallelAnimationGroup,
)
from PySide6.QtGui import QColor  # pylint: disable=no-name-in-module

try:
    from config import DLL_REPLACEMENTS
except ImportError:
    print("❌ Error: config.py file not found or is corrupted")
    sys.exit(1)
except Exception as exc:  # pylint: disable=broad-exception-caught
    print(f"❌ Error loading configuration: {exc}")
    sys.exit(1)

DONATION_ADDRESSES = {
    'bitcoin': 'bc1pfnf3ukjn6sdpdujwxav8wlv0p6k5sp5fzwnz8wmdndd57z9yym7slu5dgr',
    'ethereum': '0x671c0f7d78d777da2b576ca9b6cc559f7e048d5f',
    'monero': '43myvYnEM8q2g1AULm7dp1XzLRrjZ73VaSnCmvyhSEHHGG1e3weAUFG8RWZhSasbSz9H8jZpGv8LQ8wc9aQHjvfSKW4rt4z',
    'ton': 'UQCb_q_NLHfYC4Sj0MURw57mYlK6IQXSpOkzBZIyyXnscp7m',
    'usdt_trc20': 'TFqV65zvK6NfPbtmx1pqVxSYBCjW8Vz23K',
    'usdt_erc20': '0x671c0f7d78d777da2b576ca9b6cc559f7e048d5f',
    'usdc_erc20': '0x671c0f7d78d777da2b576ca9b6cc559f7e048d5f',
    'tron': 'TTFqV65zvK6NfPbtmx1pqVxSYBCjW8Vz23K',
    'bnb': '0x671c0f7d78d777da2b576ca9b6cc559f7e048d5f',
    'github': 'https://github.com/EXLOUD',
}

APP_VERSION = "1.0.12"
LANG_FOLDER = "languages"


def sanitize_filename(filename: str) -> str:
    """Replace characters forbidden in Windows filenames with underscores."""
    return re.sub(r'[\\/*?:"<>|]', '_', filename)


def resource_path(relative_path):
    """Return the absolute path to a resource, handling PyInstaller bundles."""
    base_path = getattr(sys, '_MEIPASS', os.path.abspath("."))
    return os.path.join(base_path, relative_path)


def get_base_path():
    """Return the directory that contains the running executable or script."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


# =============================================================================
# THEME
# =============================================================================
REFINED_PALETTE = {
    'bg_primary': '#0E0E10', 'bg_secondary': '#141417', 'bg_tertiary': '#1A1A1E',
    'bg_elevated': '#202024', 'bg_overlay': '#26262B',
    'accent': '#8B7FB8', 'accent_hover': '#9D91C7',
    'accent_muted': 'rgba(139, 127, 184, 0.15)', 'accent_subtle': 'rgba(139, 127, 184, 0.08)',
    'text': '#E8E6F0', 'text_secondary': '#A8A5B8', 'text_muted': '#6B6878',
    'text_disabled': '#48465A',
    'success': '#6BCF7F', 'warning': '#E4A853', 'error': '#CF6679', 'info': '#64B5F6',
    'border': 'rgba(255, 255, 255, 0.04)', 'border_hover': 'rgba(139, 127, 184, 0.2)',
    'shadow': 'rgba(0, 0, 0, 0.4)',
}

STANDARD_BUTTON_STYLE = f"""
    QPushButton {{
        font-size: 13px; font-weight: 500; letter-spacing: 0.5px; padding: 11px 20px;
        border-radius: 8px; background-color: {REFINED_PALETTE['bg_tertiary']};
        color: {REFINED_PALETTE['text_secondary']}; border: none;
    }}
    QPushButton:hover {{
        background-color: {REFINED_PALETTE['bg_overlay']}; color: {REFINED_PALETTE['text']};
    }}
    QPushButton:disabled {{
        background-color: {REFINED_PALETTE['bg_overlay']}; color: {REFINED_PALETTE['text_muted']};
    }}
"""

REFINED_STYLESHEET = f"""
    * {{ margin: 0; padding: 0; border: none; outline: none; }}
    QWidget {{ color: {REFINED_PALETTE['text']}; font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', system-ui, sans-serif; font-size: 13px; font-weight: 400; letter-spacing: 0.3px; }}
    QMainWindow {{ background-color: {REFINED_PALETTE['bg_primary']}; }}
    #RefinedCard {{ background-color: {REFINED_PALETTE['bg_secondary']}; border-radius: 12px; }}
    #ElevatedCard {{ background-color: {REFINED_PALETTE['bg_elevated']}; border-radius: 16px; border: 1px solid {REFINED_PALETTE['border']}; }}
    #AppHeader {{ background-color: {REFINED_PALETTE['bg_secondary']}; border-bottom: 1px solid {REFINED_PALETTE['border']}; padding: 28px 32px; }}
    {STANDARD_BUTTON_STYLE}
    QPushButton[variant="primary"] {{ background-color: {REFINED_PALETTE['accent']}; color: white; font-weight: 600; }}
    QPushButton[variant="primary"]:hover {{ background-color: {REFINED_PALETTE['accent_hover']}; }}
    QPushButton[variant="primary"]:disabled {{ background-color: {REFINED_PALETTE['accent_muted']}; color: rgba(255, 255, 255, 0.5); }}
    QPushButton[variant="secondary"] {{ background-color: {REFINED_PALETTE['accent_subtle']}; color: {REFINED_PALETTE['accent']}; border: 1px solid {REFINED_PALETTE['accent_muted']}; }}
    QPushButton[variant="secondary"]:hover {{ background-color: {REFINED_PALETTE['accent_muted']}; border-color: {REFINED_PALETTE['accent']}; }}
    QPushButton[variant="ghost"] {{ background-color: transparent; color: {REFINED_PALETTE['text_muted']}; padding: 8px 12px; }}
    QPushButton[variant="ghost"]:hover {{ background-color: {REFINED_PALETTE['bg_overlay']}; color: {REFINED_PALETTE['text_secondary']}; }}
    QLabel {{ background-color: transparent; }}
    QLabel[class="h1"] {{ font-size: 32px; font-weight: 300; letter-spacing: -0.5px; color: {REFINED_PALETTE['text']}; }}
    QLabel[class="h3"] {{ font-size: 18px; font-weight: 500; color: {REFINED_PALETTE['text']}; }}
    #FileItem {{ background-color: {REFINED_PALETTE['bg_tertiary']}; border-radius: 0; padding: 14px 16px; border: 1px solid transparent; }}
    #FileItem:hover {{ background-color: {REFINED_PALETTE['bg_overlay']}; border-color: {REFINED_PALETTE['border_hover']}; }}
    #Divider {{ background-color: {REFINED_PALETTE['border']}; height: 1px; margin: 10px 0; }}
    QGroupBox {{ background-color: transparent; border: 1px solid {REFINED_PALETTE['border']}; border-radius: 8px; padding-top: 16px; font-size: 11px; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; }}
    QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 8px; color: {REFINED_PALETTE['text_muted']}; background-color: {REFINED_PALETTE['bg_secondary']}; text-align: center; }}
    QTextEdit {{ background-color: {REFINED_PALETTE['bg_tertiary']}; border: 1px solid {REFINED_PALETTE['border']}; border-radius: 8px; padding: 12px; font-family: 'SF Mono', 'Monaco', 'Consolas', monospace; font-size: 12px; line-height: 1.6; color: {REFINED_PALETTE['text_secondary']}; }}
    QProgressBar {{ background-color: {REFINED_PALETTE['bg_overlay']}; height: 5px; border-radius: 5px; border: none; text-align: center; margin: 0px; padding: 0px; }}
    QProgressBar::chunk {{ background-color: {REFINED_PALETTE['accent']}; border-radius: 5px; margin: 0px; padding: 0px; }}
    QScrollArea QScrollBar:vertical {{ background-color: transparent; width: 16px; margin: 20px 4px 20px 4px; }}
    QScrollBar:vertical {{ background-color: {REFINED_PALETTE['bg_overlay']}; width: 12px; border-radius: 6px; margin: 4px 2px; }}
    QScrollBar::handle:vertical {{ background-color: {REFINED_PALETTE['text_muted']}; border-radius: 6px; min-height: 50px; margin: 2px; width: 12px; }}
    QScrollBar::handle:vertical:hover {{ background-color: {REFINED_PALETTE['accent']}; width: 12px; }}
    QScrollBar::handle:vertical:pressed {{ background-color: {REFINED_PALETTE['accent_hover']}; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical, QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ height: 0; background: transparent; }}
    QScrollArea QScrollBar:horizontal {{ background-color: transparent; height: 16px; margin: 4px 20px 4px 20px; }}
    QScrollBar:horizontal {{ background-color: {REFINED_PALETTE['bg_overlay']}; height: 12px; border-radius: 6px; margin: 2px 4px; }}
    QScrollBar::handle:horizontal {{ background-color: {REFINED_PALETTE['text_muted']}; border-radius: 6px; min-width: 50px; margin: 2px; height: 12px; }}
    QScrollBar::handle:horizontal:hover {{ background-color: {REFINED_PALETTE['accent']}; height: 12px; }}
    QScrollBar::handle:horizontal:pressed {{ background-color: {REFINED_PALETTE['accent_hover']}; }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal, QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ width: 0; background: transparent; }}
    QAbstractScrollArea::corner {{ background-color: transparent; }}
    QDialog, QMessageBox {{ background-color: {REFINED_PALETTE['bg_secondary']}; }}
    QMessageBox QLabel {{ color: {REFINED_PALETTE['text']}; }}
"""


def create_subtle_shadow():
    """Create and return a soft drop-shadow graphics effect for elevated cards."""
    shadow = QGraphicsDropShadowEffect()
    shadow.setBlurRadius(16)
    shadow.setXOffset(0)
    shadow.setYOffset(2)
    shadow.setColor(QColor(0, 0, 0, 80))
    return shadow


# =============================================================================
# TRANSLATIONS & SETTINGS
# =============================================================================
class TranslationManager:
    """Loads XML translation files and provides key-based string lookup."""

    def __init__(self, lang_code='en'):
        """Initialise and immediately load the requested language."""
        self.translations = {}
        self.load_language(lang_code)

    def load_language(self, lang_code):
        """Parse *lang_<lang_code>.xml* and populate the translation map."""
        lang_path = resource_path(LANG_FOLDER)
        if not os.path.exists(lang_path):
            print(f"⚠️ Warning: Languages folder not found: {lang_path}")
            self.translations = {}
            return
        filepath = os.path.join(lang_path, f"lang_{lang_code}.xml")
        if not os.path.exists(filepath):
            print(f"⚠️ Warning: Translation file not found: {filepath}")
            self.translations = {}
            return
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            for string_tag in root.findall('string'):
                key = string_tag.get('name')
                value = string_tag.text
                if key and value:
                    self.translations[key] = value
        except Exception as exc:  # pylint: disable=broad-exception-caught
            print(f"❌ Error loading translation file {filepath}: {exc}")
            self.translations = {}

    def get(self, key, *args):
        """Return the translated string for *key*, formatted with *args*."""
        template = self.translations.get(key, key)
        try:
            return template.format(*args)
        except (IndexError, TypeError):
            return template


def get_settings_path():
    """Return the absolute path to settings.ini next to the executable."""
    return os.path.join(get_base_path(), "settings.ini")


def load_settings():
    """Load language code and show-dialog flag; return defaults when missing."""
    path = get_settings_path()
    config = ConfigParser()
    if os.path.exists(path):
        config.read(path, encoding='utf-8')
        return (
            config.get("Settings", "language", fallback="en"),
            config.getboolean("Settings", "show_dialog", fallback=True),
        )
    return "en", True


def save_settings(lang, show_dialog):
    """Persist language code and show-dialog flag to settings.ini."""
    path = get_settings_path()
    config = ConfigParser()
    config.add_section("Settings")
    config.set("Settings", "language", lang)
    config.set("Settings", "show_dialog", str(show_dialog))
    with open(path, 'w', encoding='utf-8') as f:
        config.write(f)


def get_language_name_from_xml(filepath: str) -> str:
    """Extract the human-readable language name from a translation XML file."""
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        lang_name_tag = root.find(".//string[@name='language_name']")
        if lang_name_tag is not None and lang_name_tag.text:
            return lang_name_tag.text
    except Exception as exc:  # pylint: disable=broad-exception-caught
        print(f"\u26a0\ufe0f Warning: could not read language name from {filepath}: {exc}")
    basename = os.path.basename(filepath)
    try:
        return basename.split('_')[1].split('.')[0]
    except IndexError:
        return basename


# =============================================================================
# BACKEND LOGIC
# =============================================================================
class PatcherLogEmitter(QObject):
    """Emits translated log messages as Qt signals for cross-thread logging."""

    log_signal = Signal(str, str, list)

    def emit(self, key: str, level: str, args: list = None):
        """Emit a log signal with translation key, severity level and format args."""
        self.log_signal.emit(key, level, args or [])


class PermissionsManager:
    """Context manager that temporarily grants write permission to a read-only file."""

    def __init__(self, file_path: str, log_emitter: PatcherLogEmitter):
        """Store path and emitter; initialise state flags."""
        self.file_path = file_path
        self.log_emitter = log_emitter
        self.original_permissions = None
        self.permissions_were_changed = False

    def __enter__(self):
        """Ensure the file is writable, changing permissions if necessary."""
        try:
            self.original_permissions = os.stat(self.file_path).st_mode
            if not self.original_permissions & stat.S_IWUSR:
                self.log_emitter.emit("log_readonly_file", "warning",
                                      [os.path.basename(self.file_path)])
                self.log_emitter.emit("log_changing_perms", "info")
                os.chmod(self.file_path, self.original_permissions | stat.S_IWUSR)
                self.log_emitter.emit("log_perms_changed", "success")
                self.permissions_were_changed = True
            return self
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.log_emitter.emit("log_perms_error", "error", [str(exc)])
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Restore the original file permissions when leaving the context."""
        if self.permissions_were_changed and self.original_permissions is not None:
            try:
                self.log_emitter.emit("log_restoring_perms", "info")
                os.chmod(self.file_path, self.original_permissions)
                self.log_emitter.emit("log_perms_restored", "success")
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self.log_emitter.emit("log_restore_perms_error", "error", [str(exc)])


class UniversalPEPatcher:
    """Patches DLL names inside a PE file using both IAT and raw-hex strategies."""

    def __init__(self, file_path: str, selected_apis: List[int],
                 log_emitter: PatcherLogEmitter):
        """Build the replacement map from the selected API numbers."""
        self.file_path = file_path
        self.log_emitter = log_emitter
        self.binary = None
        self.data = None
        self.active_replacements = {
            k: v
            for api_num in selected_apis
            for k, v in DLL_REPLACEMENTS[api_num]['replacements'].items()
        }

    def _rva_to_offset(self, rva: int):
        """Convert a relative virtual address to a raw file offset."""
        for section in self.binary.sections:
            vstart = section.virtual_address
            vsize = max(section.virtual_size, section.size)
            if vstart <= rva < vstart + vsize:
                return section.offset + (rva - vstart)
        return None

    def load_file(self) -> bool:
        """Read the file into a mutable bytearray and parse it with LIEF."""
        try:
            with open(self.file_path, 'rb') as f:
                self.data = bytearray(f.read())
            self.binary = lief.PE.parse(self.file_path)
            if self.binary is None:
                raise ValueError("LIEF: could not parse file as PE")
            return True
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.log_emitter.emit("log_load_error", "error", [str(exc)])
            return False

    def check_if_patchable(self) -> int:
        """Return the number of replaceable occurrences found in this PE."""
        if not self.data and not self.load_file():
            return 0
        count = 0
        iat_details = []
        hex_details = []

        if self.binary and self.binary.has_imports:
            for imp in self.binary.imports:
                dll_upper = imp.name.upper()
                for orig_bytes in self.active_replacements:
                    if dll_upper == orig_bytes.decode('utf-8', 'ignore').rstrip('\x00').upper():
                        count += 1
                        iat_details.append(dll_upper)
                        break

        for old_bytes in self.active_replacements:
            hex_count = self.data.count(old_bytes)
            if hex_count > 0:
                count += hex_count
                hex_details.append(
                    f"{old_bytes.decode('utf-8', 'ignore')} x{hex_count}"
                )

        if iat_details or hex_details:
            self.log_emitter.emit("log_patch_details_header", "info")
            if iat_details:
                self.log_emitter.emit("log_patch_details_iat", "info",
                                      [', '.join(iat_details)])
            if hex_details:
                self.log_emitter.emit("log_patch_details_hex", "info",
                                      [', '.join(hex_details)])
        return count

    def patch_all(self) -> int:
        """Apply IAT and hex patches; return the total number of replacements made."""
        count = 0
        iat_count = 0
        hex_patched_details = {}

        try:
            import_dir = self.binary.data_directories[1]
            dir_rva = import_dir.rva
            dir_file_offset = self._rva_to_offset(dir_rva) if dir_rva else None

            if dir_file_offset is not None:
                idx = 0
                while True:
                    base = dir_file_offset + idx * 20
                    if base + 20 > len(self.data):
                        break
                    oft = int.from_bytes(self.data[base:base + 4], 'little')
                    name_rva = int.from_bytes(self.data[base + 12:base + 16], 'little')
                    ft = int.from_bytes(self.data[base + 16:base + 20], 'little')
                    if oft == 0 and ft == 0:
                        break
                    if name_rva:
                        name_off = self._rva_to_offset(name_rva)
                        if name_off is not None and name_off < len(self.data):
                            end = name_off
                            while end < len(self.data) and self.data[end] != 0:
                                end += 1
                            dll_name = self.data[name_off:end].decode('utf-8', 'ignore')
                            for orig, repl in self.active_replacements.items():
                                orig_str = orig.decode('utf-8', 'ignore').rstrip('\x00').upper()
                                if dll_name.upper() == orig_str:
                                    avail = end - name_off + 1
                                    if len(repl) <= avail:
                                        self.data[name_off:name_off + len(repl)] = repl
                                        if len(repl) < avail:
                                            pad = avail - len(repl)
                                            self.data[
                                                name_off + len(repl):
                                                name_off + len(repl) + pad
                                            ] = b'\x00' * pad
                                        count += 1
                                        iat_count += 1
                                    else:
                                        self.log_emitter.emit(
                                            "log_iat_skipped_long", "warning", [dll_name]
                                        )
                                    break
                    idx += 1
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.log_emitter.emit("log_iat_parse_failed", "warning", [str(exc)])

        for old, new in self.active_replacements.items():
            if len(old) != len(new):
                self.log_emitter.emit(
                    "log_hex_skipped_len", "warning", [old.decode('utf-8', 'ignore')]
                )
                continue
            start_index = 0
            local_count = 0
            while (index := self.data.find(old, start_index)) != -1:
                self.data[index:index + len(old)] = new
                start_index = index + len(old)
                count += 1
                local_count += 1
            if local_count > 0:
                hex_patched_details[old.decode('utf-8', 'ignore')] = (
                    new.decode('utf-8', 'ignore'), local_count
                )

        if count > 0:
            for dll, (new_dll, cnt) in hex_patched_details.items():
                self.log_emitter.emit("log_hex_patched", "info", [dll, new_dll, cnt])
            self.log_emitter.emit("log_total_changes", "success", [count])
        return count

    def save(self, output_path: str) -> bool:
        """Write the patched byte buffer to *output_path*."""
        try:
            with open(output_path, 'wb') as f:
                f.write(bytes(self.data))
            self.log_emitter.emit(
                "log_file_saved", "success", [os.path.basename(output_path)]
            )
            return True
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.log_emitter.emit("log_save_error", "error", [str(exc)])
            return False

    def close(self):
        """Release LIEF binary and byte buffer."""
        self.binary = None
        self.data = None


class FileProcessorWorker(QObject):
    """Background worker that validates and collects metadata for a list of PE files."""

    file_processed = Signal(dict)
    finished = Signal(int, int)

    def __init__(self, file_paths):
        """Store the list of paths to process."""
        super().__init__()
        self.file_paths = file_paths

    def run(self):
        """Validate each file as a PE and emit metadata; emit totals when done."""
        added = 0
        error = 0
        for path in self.file_paths:
            try:
                with open(path, 'rb') as f:
                    if f.read(2) != b'MZ':
                        error += 1
                        continue
                info = {'path': path, 'size': os.path.getsize(path), 'type': 'PE', 'arch': 'x86'}
                try:
                    binary = lief.PE.parse(path)
                    if binary is not None:
                        chars = binary.header.characteristics
                        if chars & 0x2000:
                            info['type'] = 'DLL'
                        elif chars & 0x0002:
                            info['type'] = 'EXE'
                        else:
                            info['type'] = 'PE'
                        try:
                            info['arch'] = (
                                'x64'
                                if binary.header.machine == lief.PE.MACHINE_TYPES.AMD64
                                else 'x86'
                            )
                        except Exception:  # pylint: disable=broad-exception-caught
                            info['arch'] = 'x64' if int(binary.header.machine) == 0x8664 else 'x86'
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    print(f"⚠️ Warning: could not read PE metadata: {exc}")
                self.file_processed.emit(info)
                added += 1
            except Exception:  # pylint: disable=broad-exception-caught
                error += 1
        self.finished.emit(added, error)


class FolderScannerWorker(QObject):
    """Background worker that recursively scans a folder for PE files."""

    finished = Signal()
    file_found = Signal(str)
    scan_complete = Signal(list, list)

    def __init__(self, folder_path, include_subfolders):
        """Store scan parameters."""
        super().__init__()
        self.folder_path = Path(folder_path)
        self.include_subfolders = include_subfolders
        self.is_cancelled = False

    def run(self):
        """Scan the folder and emit each discovered PE file name."""
        try:
            found = []
            skipped = set()
            exts = {'.exe', '.dll', '.vst3', '.vst', '.sys', '.ocx', '.ax'}
            pattern = '**/*' if self.include_subfolders else '*'
            for p in self.folder_path.glob(pattern):
                if self.is_cancelled:
                    break
                if p.is_dir() or p.suffix.lower() not in exts:
                    continue
                parts_lower = {part.lower() for part in p.parts}
                if not {'patched', 'backup'}.isdisjoint(parts_lower):
                    skipped.add("Patched/Backup")
                    continue
                try:
                    with p.open('rb') as f:
                        if f.read(2) == b'MZ':
                            found.append(str(p))
                            self.file_found.emit(p.name)
                except (IOError, PermissionError):
                    continue
            if not self.is_cancelled:
                self.scan_complete.emit(sorted(list(set(found))), sorted(list(skipped)))
        except Exception as exc:  # pylint: disable=broad-exception-caught
            print(f"Error in FolderScannerWorker: {exc}")
        finally:
            self.finished.emit()

    def cancel(self):
        """Request cancellation of the ongoing scan."""
        self.is_cancelled = True


class PatcherWorker(QObject):
    """Background worker that applies DLL-name patches to a batch of PE files."""

    log_message = Signal(str, str, list)
    file_status_updated = Signal(str, str, str)
    progress_updated = Signal(int)
    finished = Signal(tuple, bool, int, int, int)  # cancelled_file_index uses -1 instead of None

    def __init__(self, files, selected_apis, backup, overwrite):
        """Store all patching parameters."""
        super().__init__()
        self.files = files
        self.selected_apis = selected_apis
        self.backup_var = backup
        self.overwrite_var = overwrite
        self.is_cancelled = False
        self.total_files = len(files)
        self.log_emitter = PatcherLogEmitter()
        self.log_emitter.log_signal.connect(self.log_message)

    def cancel(self):
        """Request cancellation after the current file finishes."""
        self.log_message.emit("log_cancel_request", "warning", [])
        self.is_cancelled = True

    def run(self):
        """Iterate over files, patch each one, and emit progress/status signals."""
        s = 0
        e = 0
        k = 0
        total = len(self.files)
        was_cancelled = False
        cancelled_file_index = None

        try:
            for i, info in enumerate(self.files):
                if self.is_cancelled:
                    was_cancelled = True
                    cancelled_file_index = i
                    self.log_message.emit("log_patching_cancelled", "warning", [])
                    for remaining_info in self.files[i:]:
                        self.file_status_updated.emit(
                            remaining_info['path'], 'warning', 'status_cancelled'
                        )
                    break

                path = info['path']
                name = sanitize_filename(os.path.basename(path))
                self.log_message.emit("", "info", [])
                self.log_message.emit(
                    "log_processing_file", "info",
                    [f"[{i + 1}/{total}]", os.path.basename(path)]
                )
                original_file_data = None

                try:
                    with open(path, 'rb') as fh:
                        original_file_data = fh.read()
                except Exception as read_err:  # pylint: disable=broad-exception-caught
                    self.log_message.emit("log_read_error", "error", [str(read_err)])
                    e += 1
                    self.file_status_updated.emit(path, 'error', 'status_error')
                    self.progress_updated.emit(int((i + 1) / total * 100))
                    continue

                patcher = None
                try:
                    with PermissionsManager(path, self.log_emitter):
                        if self.is_cancelled:
                            was_cancelled = True
                            cancelled_file_index = i
                            self.log_message.emit("log_patching_cancelled", "warning", [])
                            for remaining_info in self.files[i:]:
                                self.file_status_updated.emit(
                                    remaining_info['path'], 'warning', 'status_cancelled'
                                )
                            break

                        patcher = UniversalPEPatcher(path, self.selected_apis, self.log_emitter)
                        if not patcher.load_file() or patcher.check_if_patchable() == 0:
                            self.log_message.emit("log_nothing_to_patch", "warning", [])
                            k += 1
                            self.file_status_updated.emit(path, 'warning', 'status_skipped')
                            self.progress_updated.emit(int((i + 1) / total * 100))
                            continue

                        if self.is_cancelled:
                            was_cancelled = True
                            cancelled_file_index = i
                            self.log_message.emit("log_patching_cancelled", "warning", [])
                            for remaining_info in self.files[i:]:
                                self.file_status_updated.emit(
                                    remaining_info['path'], 'warning', 'status_cancelled'
                                )
                            break

                        p_count = patcher.patch_all()

                        if p_count > 0:
                            if self.is_cancelled:
                                was_cancelled = True
                                cancelled_file_index = i
                                self.log_message.emit("log_patching_cancelled", "warning", [])
                                for remaining_info in self.files[i:]:
                                    self.file_status_updated.emit(
                                        remaining_info['path'], 'warning', 'status_cancelled'
                                    )
                                break

                            if self.backup_var:
                                b_dir = os.path.join(os.path.dirname(path), 'backup')
                                os.makedirs(b_dir, exist_ok=True)
                                b_path = os.path.join(b_dir, name)
                                cnt = 1
                                base, ext = os.path.splitext(name)
                                while os.path.exists(b_path):
                                    b_path = os.path.join(b_dir, f"{base}.backup{cnt}{ext}")
                                    cnt += 1
                                with open(b_path, 'wb') as bf:
                                    bf.write(original_file_data)
                                self.log_message.emit(
                                    "log_backup_saved", "info", [os.path.basename(b_path)]
                                )

                            if self.is_cancelled:
                                was_cancelled = True
                                cancelled_file_index = i
                                self.log_message.emit("log_patching_cancelled", "warning", [])
                                for remaining_info in self.files[i:]:
                                    self.file_status_updated.emit(
                                        remaining_info['path'], 'warning', 'status_cancelled'
                                    )
                                break

                            p_dir = os.path.join(os.path.dirname(path), 'patched')
                            os.makedirs(p_dir, exist_ok=True)
                            i_path = os.path.join(p_dir, name)

                            if not patcher.save(i_path):
                                e += 1
                                self.file_status_updated.emit(path, 'error', 'status_error')
                                self.progress_updated.emit(int((i + 1) / total * 100))
                                continue

                            if self.overwrite_var:
                                try:
                                    shutil.move(i_path, path)
                                    self.log_message.emit("log_original_replaced", "info", [])
                                    if not os.listdir(p_dir):
                                        os.rmdir(p_dir)
                                except Exception as move_err:  # pylint: disable=broad-exception-caught
                                    self.log_message.emit(
                                        "log_move_error", "error", [str(move_err)]
                                    )
                                    e += 1
                                    self.file_status_updated.emit(path, 'error', 'status_error')

                            s += 1
                            self.file_status_updated.emit(path, 'success', 'status_done')
                        else:
                            k += 1
                            self.file_status_updated.emit(path, 'warning', 'status_no_changes')

                except Exception as err:  # pylint: disable=broad-exception-caught
                    self.log_message.emit("log_general_error", "error", [str(err)])
                    e += 1
                    self.file_status_updated.emit(path, 'error', 'status_error')
                finally:
                    if patcher:
                        patcher.close()

                self.progress_updated.emit(int((i + 1) / total * 100))

        finally:
            remaining_files = (
                total - cancelled_file_index
                if cancelled_file_index is not None else 0
            )
            self.finished.emit(
                (s, k, e),
                was_cancelled,
                cancelled_file_index if cancelled_file_index is not None else -1,
                self.total_files,
                remaining_files,
            )


class ThreadManager(QObject):
    """Manages a single background QThread, ensuring only one task runs at a time."""

    task_started = Signal(str)
    task_finished = Signal(str)
    error = Signal(str, str)

    def __init__(self, parent=None):
        """Initialise with empty thread/worker references."""
        super().__init__(parent)
        self.current_thread = None
        self.current_worker = None
        self.current_task_name = None

    def is_running(self) -> bool:
        """Return True if a background thread is currently active."""
        return self.current_thread is not None and self.current_thread.isRunning()

    def start_task(self, worker_class, task_name: str, *args, **kwargs) -> QObject:
        """Create and start a worker of *worker_class*; return the worker instance."""
        if self.is_running():
            self.error.emit("dialog_op_in_progress", "")
            return None
        self.current_task_name = task_name
        self.current_thread = QThread()
        self.current_worker = worker_class(*args, **kwargs)
        worker = self.current_worker
        worker.moveToThread(self.current_thread)
        self.current_thread.started.connect(worker.run)
        worker.finished.connect(self.current_thread.quit)
        self.current_thread.finished.connect(self._cleanup_after_thread_finish)
        self.current_thread.finished.connect(worker.deleteLater)
        self.current_thread.finished.connect(self.current_thread.deleteLater)
        self.current_thread.start()
        self.task_started.emit(task_name)
        return worker

    def _cleanup_after_thread_finish(self):
        """Reset internal references after a thread completes."""
        task_name = self.current_task_name
        self.current_thread = None
        self.current_worker = None
        self.current_task_name = None
        self.task_finished.emit(task_name)

    def stop_current_task(self):
        """Request cancellation of the running worker if it supports cancel()."""
        if self.is_running() and hasattr(self.current_worker, 'cancel'):
            self.current_worker.cancel()


# =============================================================================
# WIDGETS & DIALOGS
# =============================================================================
class LanguageDialog(QDialog):
    """Startup dialog that lets the user pick the UI language from available XML files."""

    def __init__(self, parent=None):
        """Build the language-selection UI."""
        super().__init__(parent)
        self.setWindowTitle("Language Selection")
        self.setMinimumWidth(400)
        self.setMinimumHeight(300)
        self.language = "en"

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(20)

        title_label = QLabel("Select Language")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setProperty("class", "h3")
        main_layout.addWidget(title_label)

        lang_path = resource_path(LANG_FOLDER)
        lang_files = (
            glob.glob(os.path.join(lang_path, "lang_*.xml"))
            if os.path.exists(lang_path) else []
        )

        if not lang_files:
            error_label = QLabel(
                "⚠️ Language files not found!\n\n"
                "Please ensure the 'languages' folder exists with translation files:\n"
                "- languages/lang_en.xml\n\n"
                "Copy the language files from the application directory and try again."
            )
            error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            error_label.setWordWrap(True)
            error_label.setStyleSheet(
                f"color: {REFINED_PALETTE['warning']}; font-size: 12px;"
            )
            main_layout.addWidget(error_label, 1)

            close_btn = QPushButton("Exit")
            close_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
            close_btn.clicked.connect(self.reject)
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()
            btn_layout.addWidget(close_btn)
            btn_layout.addStretch()
            main_layout.addLayout(btn_layout)
        else:
            scroll_area = QScrollArea()
            scroll_area.setWidgetResizable(True)
            scroll_area.setFrameShape(QFrame.Shape.NoFrame)
            scroll_area.setStyleSheet("background: transparent;")

            button_container = QWidget()
            buttons_layout = QVBoxLayout(button_container)
            buttons_layout.setContentsMargins(0, 0, 0, 0)
            buttons_layout.setSpacing(8)

            available_languages = {}
            for lang_file in lang_files:
                lang_code = os.path.basename(lang_file).split('_')[1].split('.')[0]
                lang_name = get_language_name_from_xml(lang_file)
                available_languages[lang_code] = lang_name

            for code, name in sorted(available_languages.items()):
                btn = QPushButton(name)
                btn.setStyleSheet(STANDARD_BUTTON_STYLE)
                btn.clicked.connect(lambda _, c=code: self.set_language(c))
                buttons_layout.addWidget(btn)

            buttons_layout.addStretch()
            button_container.setLayout(buttons_layout)
            scroll_area.setWidget(button_container)
            main_layout.addWidget(scroll_area)

            self.show_again_checkbox = QCheckBox("Show every time")
            self.show_again_checkbox.setChecked(True)
            main_layout.addWidget(self.show_again_checkbox)

    def set_language(self, lang_code):
        """Store the selected language code and close the dialog."""
        self.language = lang_code
        self.accept()

    def get_selection(self):
        """Return (language_code, show_again_flag) from the dialog."""
        if hasattr(self, 'show_again_checkbox'):
            return self.language, self.show_again_checkbox.isChecked()
        return self.language, False


class RefinedContainer(QWidget):
    """Styled QWidget used as a card or elevated-card container in the UI."""

    def __init__(self, container_type="card", parent=None):
        """Create the container with the correct object name and optional shadow."""
        super().__init__(parent)
        name_map = {"card": "RefinedCard", "elevated": "ElevatedCard"}
        self.setObjectName(name_map.get(container_type, "RefinedCard"))
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        if container_type == "elevated":
            self.setGraphicsEffect(create_subtle_shadow())


class SwipeableFileItem(QWidget):
    """File list row widget that supports a left-swipe gesture to trigger removal."""

    removed = Signal(str)

    def __init__(self, file_info, translator):
        """Build the file row UI with name, details, status and remove button."""
        super().__init__()
        self.file_info = file_info
        self.translator = translator
        self.start_pos = None
        self.current_pos = 0
        self.swipe_threshold = 60
        self.is_swiped = False

        wrapper_layout = QVBoxLayout(self)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(0)

        file_widget = QWidget()
        file_widget.setObjectName("FileItem")
        file_widget.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        file_widget.setFixedHeight(56)

        main_layout = QHBoxLayout(file_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.content_widget = QWidget()
        self.content_widget.setStyleSheet("background: transparent;")

        content_layout = QHBoxLayout(self.content_widget)
        content_layout.setContentsMargins(16, 0, 16, 0)
        content_layout.setSpacing(12)

        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)
        info_layout.setContentsMargins(0, 0, 0, 0)

        name_label = QLabel(os.path.basename(file_info['path']))
        name_label.setProperty("class", "subtitle")
        name_label.setStyleSheet(f"color: {REFINED_PALETTE['text']};")
        info_layout.addWidget(name_label)

        details = QLabel(
            f"{file_info['type']} · {self._format_size(file_info['size'])} · {file_info['arch']}"
        )
        details.setProperty("class", "caption")
        info_layout.addWidget(details)
        content_layout.addLayout(info_layout, 1)

        self.status_label = QLabel(
            self.translator.get(file_info.get('status_text_key', 'status_ready'))
        )
        self.status_label.setProperty("class", "caption")
        content_layout.addWidget(self.status_label)

        remove_btn = QPushButton("×")
        remove_btn.setProperty("variant", "ghost")
        remove_btn.setFixedSize(24, 24)
        remove_btn.setStyleSheet(
            "QPushButton { font-size: 18px; padding: 0; border-radius: 4px; color: #6B6878; }"
            " QPushButton:hover { color: #CF6679; background-color: rgba(207,102,121,0.1); }"
        )
        remove_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        remove_btn.clicked.connect(lambda: self.removed.emit(self.file_info['path']))
        content_layout.addWidget(remove_btn)

        self.delete_icon = QLabel("🗑️")
        self.delete_icon.setProperty("class", "caption")
        self.delete_icon.setStyleSheet(
            f"color: {REFINED_PALETTE['error']}; padding: 0 16px;"
        )
        self.delete_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.delete_icon.hide()

        main_layout.addWidget(self.content_widget)
        main_layout.addWidget(self.delete_icon)

        self.animation = QPropertyAnimation(self.content_widget, b"pos")
        self.animation.setDuration(200)
        self.animation.finished.connect(self.on_animation_finished)

        wrapper_layout.addWidget(file_widget)

        divider = QFrame()
        divider.setFixedHeight(1)
        divider.setStyleSheet(
            f"background-color: {REFINED_PALETTE['border']}; margin: 0;"
        )
        wrapper_layout.addWidget(divider)

    def _format_size(self, size):
        """Convert *size* bytes to a human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f}{unit}"
            size /= 1024.0
        return f"{size:.1f}TB"

    def mousePressEvent(self, event):
        """Record the press position to track horizontal swipe distance."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.start_pos = event.pos()

    def mouseMoveEvent(self, event):
        """Slide the content widget left as the user drags to show the delete icon."""
        if self.start_pos is not None and event.buttons() & Qt.MouseButton.LeftButton:
            delta = event.pos().x() - self.start_pos.x()
            if delta < 0:
                self.current_pos = max(delta, -self.swipe_threshold)
                self.content_widget.move(self.current_pos, 0)
                if abs(self.current_pos) > self.swipe_threshold * 0.7:
                    self.delete_icon.show()
                else:
                    self.delete_icon.hide()

    def mouseReleaseEvent(self, _event):
        """Commit the swipe-removal or spring back, depending on distance."""
        if self.start_pos is not None:
            if abs(self.current_pos) > self.swipe_threshold * 0.8:
                self.is_swiped = True
                self.animation.setStartValue(self.content_widget.pos())
                self.animation.setEndValue(QPoint(-self.width(), 0))
                self.animation.start()
            else:
                self.animation.setStartValue(self.content_widget.pos())
                self.animation.setEndValue(QPoint(0, 0))
                self.animation.start()
                self.delete_icon.hide()
        self.start_pos = None

    def on_animation_finished(self):
        """Emit *removed* signal when the swipe-out animation completes."""
        if self.is_swiped:
            self.removed.emit(self.file_info['path'])

    def update_status(self, status: str, text: str):
        """Update the status label text and colour."""
        self.status_label.setText(text)
        colors = {
            'success': REFINED_PALETTE['success'],
            'warning': REFINED_PALETTE['warning'],
            'error': REFINED_PALETTE['error'],
            'ready': REFINED_PALETTE['text_muted'],
        }
        self.status_label.setStyleSheet(f"color: {colors.get(status, colors['ready'])};")


class RefinedFolderDialog(QDialog):
    """Dialog that scans a folder for PE files and lets the user review them."""

    files_changed = Signal()

    def update_display(self):
        """Refresh the file count label and button state after a removal."""
        file_count = len(self.found_files)
        if file_count == 0:
            self.scroll_area.hide()
            self.empty_state_internal.show()
            self.status_label.setText(self.translator.get("files_not_added"))
        else:
            self.empty_state_internal.hide()
            self.scroll_area.show()
            self.status_label.setText(self.translator.get("found_n_files", file_count))
        self.update_buttons(is_scanning=False, found_count=file_count)

    def __init__(self, parent, folder_path, include_subfolders):
        """Build the scan dialog and launch the background scanner thread."""
        super().__init__(parent)
        self.found_files = []
        self.is_closing = False
        self.translator = parent.translator
        self.setWindowTitle(self.translator.get("scan_folder_title"))
        self.setFixedSize(600, 640)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header_widget = QWidget()
        header_widget.setStyleSheet(
            f"background-color: {REFINED_PALETTE['bg_secondary']};"
            " border-radius: 12px; padding: 16px;"
        )
        header_layout = QVBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(12)

        title_label = QLabel(self.translator.get("scan_folder_title"))
        title_label.setProperty("class", "h3")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(title_label)

        path_scroll = QScrollArea()
        path_scroll.setWidgetResizable(True)
        path_scroll.setFixedHeight(80)
        path_scroll.setFrameShape(QFrame.Shape.NoFrame)
        path_scroll.setStyleSheet(
            f"QScrollArea {{ background-color: {REFINED_PALETTE['bg_tertiary']};"
            f" border: none; border-radius: 8px; }}"
            f" QScrollBar:horizontal {{ background-color: {REFINED_PALETTE['bg_overlay']};"
            f" height: 8px; border-radius: 4px; margin: 2px; }}"
            f" QScrollBar::handle:horizontal {{ background-color: {REFINED_PALETTE['text_muted']};"
            f" border-radius: 4px; min-width: 50px; margin: 1px; }}"
            f" QScrollBar::handle:horizontal:hover {{ background-color: {REFINED_PALETTE['accent']}; }}"
            " QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal"
            " { width: 0; background: transparent; }"
        )

        path_label = QLabel(folder_path)
        path_label.setProperty("class", "mono")
        path_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        path_label.setStyleSheet(
            f"color: {REFINED_PALETTE['text_secondary']}; padding: 12px;"
        )
        path_scroll.setWidget(path_label)
        header_layout.addWidget(path_scroll)
        layout.addWidget(header_widget)

        self.status_label = QLabel(self.translator.get("scanning_status_searching"))
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)

        self.central_container = QWidget()
        self.central_layout = QVBoxLayout(self.central_container)
        self.central_layout.setContentsMargins(0, 0, 0, 0)
        self.central_layout.setSpacing(0)

        empty_scroll = QScrollArea()
        empty_scroll.setWidgetResizable(True)
        empty_scroll.setFrameShape(QFrame.Shape.NoFrame)
        empty_scroll.setStyleSheet("background: transparent;")

        self.empty_state = RefinedContainer("elevated")
        self.empty_state.setStyleSheet(
            f"background-color: {REFINED_PALETTE['bg_secondary']}; border-radius: 12px;"
        )
        empty_layout = QVBoxLayout(self.empty_state)
        empty_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.setSpacing(12)
        empty_layout.setContentsMargins(24, 24, 24, 24)

        self.empty_text = QLabel(self.translator.get("files_not_added"))
        self.empty_text.setProperty("class", "h3")
        self.empty_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(self.empty_text)

        empty_scroll.setWidget(self.empty_state)
        self.central_layout.addWidget(empty_scroll, 1)

        self.files_container = RefinedContainer("elevated")
        self.files_container.setStyleSheet(
            f"background-color: {REFINED_PALETTE['bg_tertiary']};"
            " border: none; border-radius: 8px;"
        )
        self.files_layout = QVBoxLayout(self.files_container)
        self.files_layout.setContentsMargins(12, 12, 12, 12)
        self.files_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent; border: none;")
        scroll.hide()

        self.files_content = QWidget()
        self.files_content.setStyleSheet("background: transparent;")
        self.files_main_layout = QVBoxLayout(self.files_content)
        self.files_main_layout.setContentsMargins(0, 0, 0, 0)
        self.files_main_layout.setSpacing(0)
        self.files_main_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        scroll.setWidget(self.files_content)
        self.files_layout.addWidget(scroll)
        self.scroll_area = scroll

        self.empty_state_internal = QWidget()
        self.empty_state_internal.setStyleSheet("background: transparent;")
        empty_internal_layout = QVBoxLayout(self.empty_state_internal)
        empty_internal_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_internal_layout.setSpacing(12)

        empty_internal_text = QLabel(self.translator.get("files_not_added"))
        empty_internal_text.setProperty("class", "h3")
        empty_internal_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_internal_text.setStyleSheet(f"color: {REFINED_PALETTE['text_muted']};")
        empty_internal_layout.addWidget(empty_internal_text)

        self.files_layout.addWidget(self.empty_state_internal)
        self.empty_state_internal.hide()
        self.central_layout.addWidget(self.files_container, 1)
        layout.addWidget(self.central_container, 1)

        self.info_container = QWidget()
        self.info_container.setStyleSheet(
            f"background-color: {REFINED_PALETTE['bg_tertiary']};"
            " border-radius: 8px; padding: 12px;"
        )
        info_layout = QVBoxLayout(self.info_container)
        info_layout.setContentsMargins(12, 12, 12, 12)
        info_layout.setSpacing(6)

        self.skipped_label = QLabel()
        self.skipped_label.setProperty("class", "caption")
        self.skipped_label.setStyleSheet(f"color: {REFINED_PALETTE['text_muted']};")
        self.skipped_label.setWordWrap(True)
        info_layout.addWidget(self.skipped_label)
        self.info_container.hide()
        layout.addWidget(self.info_container)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(3)
        layout.addWidget(self.progress_bar)

        self.btn_layout = QHBoxLayout()
        self.btn_layout.setSpacing(12)
        layout.addLayout(self.btn_layout)
        self.update_buttons(is_scanning=True)

        self.thread = QThread(self)
        self.worker = FolderScannerWorker(folder_path, include_subfolders)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.thread.finished.connect(self.on_thread_finished)
        self.worker.scan_complete.connect(self.on_scan_complete)
        self.worker.file_found.connect(self.on_file_found)

        self.thread.start()
        self.files_changed.connect(self.update_display)

    def update_buttons(self, is_scanning=False, found_count=0):
        """Rebuild the button row for scanning vs. finished states."""
        while self.btn_layout.count():
            item = self.btn_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self.btn_layout.addStretch()
        if is_scanning:
            cancel_btn = QPushButton(self.translator.get("cancel"))
            cancel_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
            cancel_btn.clicked.connect(self.reject)
            self.btn_layout.addWidget(cancel_btn)
        else:
            if found_count > 0:
                add_btn = QPushButton(self.translator.get("add_n_files", found_count))
                add_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
                add_btn.setProperty("variant", "primary")
                add_btn.clicked.connect(self.accept)
                self.btn_layout.addWidget(add_btn)
            close_btn = QPushButton(self.translator.get("close"))
            close_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
            close_btn.clicked.connect(self.reject)
            self.btn_layout.addWidget(close_btn)
        self.btn_layout.addStretch()

    def on_file_found(self, filename):
        """Add a newly discovered file to the list while scanning."""
        file_widget = QWidget()
        file_layout = QHBoxLayout(file_widget)
        file_layout.setContentsMargins(12, 8, 12, 8)
        file_layout.setSpacing(12)

        file_item = QLabel(filename)
        file_item.setProperty("class", "caption")
        file_item.setStyleSheet(f"color: {REFINED_PALETTE['text_secondary']};")
        file_item.setWordWrap(True)
        file_layout.addWidget(file_item, 1)

        remove_btn = QPushButton("×")
        remove_btn.setProperty("variant", "ghost")
        remove_btn.setFixedSize(24, 24)
        remove_btn.setStyleSheet(
            "QPushButton { font-size: 18px; padding: 0; border-radius: 4px; color: #6B6878; }"
            " QPushButton:hover { color: #CF6679; background-color: rgba(207,102,121,0.1); }"
        )
        remove_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        remove_btn.clicked.connect(lambda: self.remove_file_item(file_widget))
        file_layout.addWidget(remove_btn)

        file_widget.setStyleSheet(
            "QWidget { background-color: transparent; border-radius: 6px; padding: 0px; }"
        )
        file_widget.enterEvent = lambda ev: self.on_file_item_hover(file_widget, True)
        file_widget.leaveEvent = lambda ev: self.on_file_item_hover(file_widget, False)

        self.files_main_layout.addWidget(file_widget)

        if self.files_main_layout.count() > 1:
            divider = QFrame()
            divider.setFrameShape(QFrame.Shape.HLine)
            divider.setFrameShadow(QFrame.Shadow.Plain)
            divider.setLineWidth(1)
            divider.setFixedHeight(1)
            divider.setStyleSheet(
                f"QFrame {{ background-color: {REFINED_PALETTE['border']};"
                f" margin: 0; border: none; }}"
            )
            self.files_main_layout.insertWidget(self.files_main_layout.count() - 1, divider)

        if self.files_main_layout.count() <= 2:
            for idx in range(self.central_layout.count()):
                widget = self.central_layout.itemAt(idx).widget()
                if isinstance(widget, QScrollArea) and widget.widget() == self.empty_state:
                    widget.hide()
            self.scroll_area.show()

    def on_file_item_hover(self, widget, is_hovering):
        """Highlight or reset a file row on mouse enter/leave."""
        if is_hovering:
            widget.setStyleSheet(
                f"QWidget {{ background-color: {REFINED_PALETTE['bg_overlay']};"
                f" border-radius: 6px; padding: 0px; }}"
            )
        else:
            widget.setStyleSheet(
                "QWidget { background-color: transparent; border-radius: 6px; padding: 0px; }"
            )

    def remove_file_item(self, widget):
        """Remove a file row from the list and update the found-files state."""
        index = self.files_main_layout.indexOf(widget)
        if index >= 0:
            self.files_main_layout.removeWidget(widget)
            widget.deleteLater()

            if index < self.files_main_layout.count():
                next_widget = self.files_main_layout.itemAt(index).widget()
                if isinstance(next_widget, QFrame):
                    self.files_main_layout.removeWidget(next_widget)
                    next_widget.deleteLater()
            elif index > 0:
                prev_widget = self.files_main_layout.itemAt(index - 1).widget()
                if isinstance(prev_widget, QFrame):
                    self.files_main_layout.removeWidget(prev_widget)
                    prev_widget.deleteLater()

            self.found_files = []
            for idx in range(self.files_main_layout.count()):
                widget_item = self.files_main_layout.itemAt(idx).widget()
                if not isinstance(widget_item, QFrame):
                    for j in range(widget_item.layout().count()):
                        child = widget_item.layout().itemAt(j).widget()
                        next_item = (
                            widget_item.layout().itemAt(j + 1).widget()
                            if j + 1 < widget_item.layout().count() else None
                        )
                        if isinstance(child, QLabel) and child != next_item:
                            self.found_files.append(child.text())
                            break

            self.files_changed.emit()

    def on_scan_complete(self, found, skipped):
        """Handle scanner completion: show results and update buttons."""
        self.found_files = found
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)

        if skipped:
            self.skipped_label.setText(
                self.translator.get("skipped_folders_info") + ", ".join(skipped)
            )
            self.info_container.show()

        if found:
            self.status_label.setText(self.translator.get("found_n_files", len(found)))
        else:
            self.scroll_area.hide()
            for idx in range(self.central_layout.count()):
                widget = self.central_layout.itemAt(idx).widget()
                if isinstance(widget, QScrollArea) and widget.widget() == self.empty_state:
                    widget.show()
            self.status_label.setText(self.translator.get("files_not_added"))

        self.update_buttons(is_scanning=False, found_count=len(found))

    def on_thread_finished(self):
        """Clean up thread and worker references after the scan ends."""
        if self.thread:
            self.thread.deleteLater()
        if self.worker:
            self.worker.deleteLater()
        self.thread = None
        self.worker = None
        if self.is_closing:
            super().reject()

    def get_found_files(self):
        """Return the list of discovered PE file paths."""
        return self.found_files

    def reject(self):
        """Cancel the scan gracefully before closing if it is still running."""
        if self.thread and self.thread.isRunning():
            if not self.is_closing:
                self.is_closing = True
                self.status_label.setText(self.translator.get("cancelling"))
                for idx in range(self.btn_layout.count()):
                    item = self.btn_layout.itemAt(idx)
                    if item:
                        btn_widget = item.widget()
                        if btn_widget:
                            btn_widget.setEnabled(False)
                self.worker.cancel()
        else:
            super().reject()

    def closeEvent(self, event):
        """Intercept the window close to ensure the scan is cancelled first."""
        event.ignore()
        self.reject()


class RefinedSplitter(QSplitter):
    """QSplitter with a wider, transparent handle styled for the dark theme."""

    def __init__(self, orientation, parent=None):
        """Create the splitter with a wide transparent handle."""
        super().__init__(orientation, parent)
        self.setHandleWidth(20)
        self.setStyleSheet("QSplitter { background-color: transparent; }")


class RefinedDivider(QFrame):
    """Thin horizontal rule used as a visual separator inside panels."""

    def __init__(self, parent=None):
        """Create a 1-pixel styled horizontal line."""
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.HLine)
        self.setFrameShadow(QFrame.Shadow.Plain)
        self.setLineWidth(1)
        self.setFixedHeight(1)
        self.setStyleSheet(
            f"QFrame {{ background-color: {REFINED_PALETTE['border']};"
            f" margin: 6px 0; border: none; }}"
        )


class AboutDialog(QDialog):
    """Dialog showing application version, author link and donation addresses."""

    def __init__(self, parent, translator):
        """Initialise and build the About dialog."""
        super().__init__(parent)
        self.translator = translator
        self.setWindowTitle(self.translator.get("about"))
        self.setFixedSize(600, 690)
        self.setup_ui()

    def setup_ui(self):
        """Construct all UI widgets for the About dialog."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(16)

        about_text = (
            f"<h2>{self.translator.get('app_title')} {APP_VERSION}</h2>"
            f"<hr style=\"margin: 12px 0; border: none; border-top: 1px solid"
            f" {REFINED_PALETTE['border']};\">"
            f"<p style=\"font-size: 13px; margin-top: 12px;\">"
            f"<b>{self.translator.get('author')}:</b>"
            f" <a href=\"{DONATION_ADDRESSES['github']}\" style=\"color:"
            f" {REFINED_PALETTE['accent']}; text-decoration: none;\">"
            f"github.com/EXLOUD</a></p>"
        )

        text_browser = QTextBrowser()
        text_browser.setHtml(about_text)
        text_browser.setReadOnly(True)
        text_browser.setOpenExternalLinks(True)
        text_browser.setFixedHeight(120)

        donations_panel = QWidget()
        donations_panel_layout = QVBoxLayout(donations_panel)
        donations_panel_layout.setContentsMargins(0, 0, 0, 0)
        donations_panel_layout.setSpacing(8)

        title_label = QLabel(self.translator.get("donation_title"))
        title_label.setProperty("class", "caption")
        donations_panel_layout.addWidget(title_label)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        scroll_area.setStyleSheet("background: transparent;")

        button_container = QWidget()
        buttons_layout = QVBoxLayout(button_container)
        buttons_layout.setContentsMargins(0, 8, 0, 0)
        buttons_layout.setSpacing(8)

        address_buttons = [
            ("Bitcoin", "bitcoin"), ("Ethereum", "ethereum"), ("Monero", "monero"),
            ("TON", "ton"), ("USDT (TRC20)", "usdt_trc20"), ("USDT (ERC20)", "usdt_erc20"),
            ("USDC (ERC20)", "usdc_erc20"), ("Tron", "tron"), ("BNB", "bnb"),
        ]
        for btn_name, key in address_buttons:
            btn = QPushButton(f"📋 {btn_name}")
            btn.setStyleSheet(STANDARD_BUTTON_STYLE)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(
                lambda checked, addr_key=key: (
                    QApplication.clipboard().setText(DONATION_ADDRESSES[addr_key]),
                    self.parent().log(
                        "log_copied", "success",
                        [addr_key.upper(), DONATION_ADDRESSES[addr_key][:15]]
                    ),
                )
            )
            buttons_layout.addWidget(btn)

        buttons_layout.addStretch()
        button_container.setLayout(buttons_layout)
        scroll_area.setWidget(button_container)
        donations_panel_layout.addWidget(scroll_area)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(text_browser)
        splitter.addWidget(donations_panel)
        splitter.setSizes([120, 520])
        splitter.setStyleSheet(
            "QSplitter::handle { height: 1px; background-color: transparent; }"
        )
        main_layout.addWidget(splitter)

        close_btn = QPushButton(self.translator.get("close"))
        close_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
        close_btn.setFixedWidth(120)
        close_btn.clicked.connect(self.accept)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        btn_layout.addStretch()
        main_layout.addLayout(btn_layout)


# =============================================================================
# MAIN WINDOW
# =============================================================================
class PEPatcherGUI(QMainWindow):
    """Main application window for the PE Patcher tool."""

    def __init__(self, translator: TranslationManager):
        """Initialise the main window, build the UI, and log the startup message."""
        super().__init__()
        self.translator = translator
        self.files = []
        self.file_items = {}
        self.thread_manager = ThreadManager(self)
        self.thread_manager.error.connect(self.show_task_error)
        self.setMinimumSize(960, 780)
        self.center_window()
        self.setup_ui()
        self.retranslate_ui()
        self.log("log_app_started", "info",
                 [self.translator.get('app_title'), APP_VERSION])

    def center_window(self):
        """Move the window to the centre of the available screen area."""
        screen = self.screen()
        if screen:
            geo = screen.availableGeometry()
            self.move(
                (geo.width() - self.width()) // 2,
                (geo.height() - self.height()) // 2,
            )

    def setup_ui(self):
        """Build the full main-window layout with header, panels, and footer."""
        main = QWidget()
        self.setCentralWidget(main)
        layout = QVBoxLayout(main)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._create_header(layout)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(24, 24, 24, 24)
        content_layout.setSpacing(0)

        self.horizontal_splitter = RefinedSplitter(Qt.Orientation.Horizontal)
        left_panel = self._create_left_panel()
        self.horizontal_splitter.addWidget(left_panel)

        self.vertical_splitter = RefinedSplitter(Qt.Orientation.Vertical)
        settings_panel = self._create_settings_panel()
        log_panel = self._create_log_panel()
        self.vertical_splitter.addWidget(settings_panel)
        self.vertical_splitter.addWidget(log_panel)
        self.vertical_splitter.setSizes([300, 300])

        self.horizontal_splitter.addWidget(self.vertical_splitter)
        self.horizontal_splitter.setSizes([600, 400])
        content_layout.addWidget(self.horizontal_splitter)
        layout.addWidget(content, 1)
        self._create_bottom(layout)

    def _create_header(self, layout):
        """Build and add the top header widget with title and file counter."""
        header = QWidget()
        header.setObjectName("AppHeader")
        header_layout = QHBoxLayout(header)

        title_section = QWidget()
        title_layout = QVBoxLayout(title_section)
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(2)

        self.title_label = QLabel()
        self.title_label.setProperty("class", "h1")
        title_layout.addWidget(self.title_label)

        self.subtitle_label = QLabel()
        self.subtitle_label.setProperty("class", "caption")
        title_layout.addWidget(self.subtitle_label)

        header_layout.addWidget(title_section)
        header_layout.addStretch()

        stats_section = QWidget()
        stats_layout = QHBoxLayout(stats_section)
        stats_layout.setSpacing(24)

        self.files_count = QLabel("0")
        self.files_count.setProperty("class", "h1")
        self.files_count.setStyleSheet(f"color: {REFINED_PALETTE['accent']};")
        stats_layout.addWidget(self.files_count)

        self.files_label = QLabel()
        self.files_label.setProperty("class", "caption")
        stats_layout.addWidget(self.files_label)

        header_layout.addWidget(stats_section)
        layout.addWidget(header)

    def _create_left_panel(self):
        """Build the left panel with file-add buttons, file list, and action buttons."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        file_actions_container = RefinedContainer("card")
        file_actions_layout = QVBoxLayout(file_actions_container)
        file_actions_layout.setContentsMargins(20, 16, 20, 16)
        file_actions_layout.setSpacing(12)

        header_layout_top = QHBoxLayout()
        header_layout_top.setSpacing(12)

        self.add_files_btn = QPushButton()
        self.add_files_btn.clicked.connect(self.add_files)
        header_layout_top.addWidget(self.add_files_btn, 1)

        self.add_folder_btn = QPushButton()
        self.add_folder_btn.clicked.connect(self.add_folder)
        header_layout_top.addWidget(self.add_folder_btn, 1)

        file_actions_layout.addLayout(header_layout_top)
        layout.addWidget(file_actions_container)

        files_panel = self._create_files_panel()
        layout.addWidget(files_panel, 1)

        buttons_container = RefinedContainer("card")
        buttons_layout = QHBoxLayout(buttons_container)
        buttons_layout.setContentsMargins(20, 16, 20, 16)
        buttons_layout.setSpacing(12)

        self.main_action_btn = QPushButton()
        self.main_action_btn.clicked.connect(self.on_main_action_click)
        buttons_layout.addWidget(self.main_action_btn, 1)

        self.clear_btn = QPushButton()
        self.clear_btn.clicked.connect(self.clear_all)
        buttons_layout.addWidget(self.clear_btn, 1)

        layout.addWidget(buttons_container)
        return container

    def _create_files_panel(self):
        """Build the scrollable file list panel with empty state."""
        container = RefinedContainer("elevated")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        self.files_content = QWidget()
        self.files_content.setStyleSheet("background: transparent;")
        self.files_main_layout = QVBoxLayout(self.files_content)
        self.files_main_layout.setContentsMargins(0, 0, 0, 0)
        self.files_main_layout.setSpacing(0)

        self.empty_state = QWidget()
        self.empty_state.setObjectName("EmptyState")
        self.empty_state.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.empty_state.setMinimumHeight(250)

        empty_layout = QVBoxLayout(self.empty_state)
        empty_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.setSpacing(12)

        self.empty_text = QLabel()
        self.empty_text.setProperty("class", "h3")
        self.empty_text.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.empty_hint = QLabel()
        self.empty_hint.setProperty("class", "caption")
        self.empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)

        empty_layout.addWidget(self.empty_text)
        empty_layout.addWidget(self.empty_hint)

        self.files_container = QWidget()
        self.files_container.setStyleSheet("background: transparent;")
        self.files_layout = QVBoxLayout(self.files_container)
        self.files_layout.setContentsMargins(12, 12, 12, 12)
        self.files_layout.setSpacing(0)
        self.files_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.files_main_layout.addWidget(self.empty_state)
        self.files_main_layout.addWidget(self.files_container)
        self.files_container.hide()

        scroll.setWidget(self.files_content)
        layout.addWidget(scroll, 1)
        return container

    def _create_settings_panel(self):
        """Build the right-top settings panel with API checkboxes and options."""
        settings = RefinedContainer("card")
        settings_layout = QVBoxLayout(settings)
        settings_layout.setContentsMargins(0, 0, 0, 0)
        settings_layout.setSpacing(0)

        header_widget = QWidget()
        header_widget.setStyleSheet(
            f"background-color: {REFINED_PALETTE['bg_secondary']};"
            " border-top-left-radius: 12px; border-top-right-radius: 12px;"
            " padding-bottom: 10px;"
        )
        header_layout = QVBoxLayout(header_widget)
        header_layout.setContentsMargins(20, 12, 20, 0)
        header_layout.setSpacing(0)

        self.settings_title = QLabel()
        self.settings_title.setProperty("class", "h3")
        self.settings_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(self.settings_title)
        settings_layout.addWidget(header_widget)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        settings_content = QWidget()
        content_layout = QVBoxLayout(settings_content)
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(16)

        self.api_group = QGroupBox()
        api_layout = QVBoxLayout(self.api_group)
        api_layout.setContentsMargins(12, 12, 12, 12)
        api_layout.setSpacing(12)

        self.all_apis = QCheckBox()
        self.all_apis.setChecked(True)
        self.all_apis.stateChanged.connect(self.toggle_apis)
        api_layout.addWidget(self.all_apis)
        api_layout.addWidget(RefinedDivider())

        self.api_checks = {}
        for num, data in DLL_REPLACEMENTS.items():
            check = QCheckBox(data['name'])
            check.setChecked(True)
            check.stateChanged.connect(self.on_api_change)
            self.api_checks[num] = check
            api_layout.addWidget(check)

        api_layout.addStretch()
        content_layout.addWidget(self.api_group)

        self.options_group = QGroupBox()
        options_layout = QVBoxLayout(self.options_group)
        options_layout.setContentsMargins(12, 12, 12, 12)
        options_layout.setSpacing(8)

        self.backup = QCheckBox()
        self.backup.setChecked(True)
        options_layout.addWidget(self.backup)

        self.overwrite = QCheckBox()
        self.overwrite.setChecked(True)
        options_layout.addWidget(self.overwrite)

        content_layout.addWidget(self.options_group)
        content_layout.addStretch()

        scroll.setWidget(settings_content)
        settings_layout.addWidget(scroll, 1)
        return settings

    def _create_log_panel(self):
        """Build the right-bottom log panel with a scrollable text area."""
        log_panel = RefinedContainer("card")
        log_layout = QVBoxLayout(log_panel)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_layout.setSpacing(0)

        header_widget = QWidget()
        header_widget.setStyleSheet(
            f"background-color: {REFINED_PALETTE['bg_secondary']};"
            " border-top-left-radius: 12px; border-top-right-radius: 12px;"
            " padding-bottom: 10px;"
        )
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(20, 12, 20, 0)
        header_layout.setSpacing(12)

        self.log_title = QLabel()
        self.log_title.setProperty("class", "h3")
        header_layout.addWidget(self.log_title)
        header_layout.addStretch()

        self.clear_log_btn = QPushButton()
        self.clear_log_btn.setProperty("variant", "ghost")
        self.clear_log_btn.clicked.connect(self.clear_log)
        header_layout.addWidget(self.clear_log_btn)
        log_layout.addWidget(header_widget)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet(
            f"QTextEdit {{ padding: 20px; border: none; border-radius: 0;"
            f" border-bottom-left-radius: 12px; border-bottom-right-radius: 12px;"
            f" background-color: {REFINED_PALETTE['bg_tertiary']};"
            " font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;"
            " font-size: 12px; }"
        )
        log_layout.addWidget(self.log_text, 1)
        return log_panel

    def _create_bottom(self, layout):
        """Build and add the bottom bar with progress indicator and About button."""
        bottom = QWidget()
        bottom.setStyleSheet(
            f"background: {REFINED_PALETTE['bg_secondary']};"
            f" border-top: 1px solid {REFINED_PALETTE['border']};"
        )
        bottom_layout = QVBoxLayout(bottom)
        bottom_layout.setContentsMargins(24, 16, 24, 16)
        bottom_layout.setSpacing(12)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(5)
        bottom_layout.addWidget(self.progress)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.about_btn = QPushButton()
        self.about_btn.setProperty("variant", "ghost")
        self.about_btn.clicked.connect(self.show_about)
        btn_layout.addWidget(self.about_btn)

        btn_layout.addStretch()
        bottom_layout.addLayout(btn_layout)
        layout.addWidget(bottom)

    def retranslate_ui(self):
        """Apply translated strings to every labelled widget."""
        self.setWindowTitle(f"{self.translator.get('app_title')} v{APP_VERSION}")
        self.title_label.setText(self.translator.get('app_title'))
        self.subtitle_label.setText(self.translator.get("version") + f" {APP_VERSION}")
        self.files_label.setText(self.translator.get("files"))
        self.add_files_btn.setText(self.translator.get("add_files"))
        self.add_folder_btn.setText(self.translator.get("add_folder"))
        self.main_action_btn.setText(self.translator.get("start_patching"))
        self.clear_btn.setText(self.translator.get("clear_all"))
        self.empty_text.setText(self.translator.get("files_not_added"))
        self.empty_hint.setText(self.translator.get("add_pe_files_hint"))
        self.settings_title.setText(self.translator.get("settings"))
        self.log_title.setText(self.translator.get("logs"))
        self.clear_log_btn.setText(self.translator.get("clear"))
        self.about_btn.setText(self.translator.get("about"))
        self.api_group.setTitle(self.translator.get("api_group_title"))
        self.all_apis.setText(self.translator.get("all_apis"))
        self.options_group.setTitle(self.translator.get("options_group_title"))
        self.backup.setText(self.translator.get("create_backups"))
        self.overwrite.setText(self.translator.get("overwrite_originals"))

    def log(self, msg_key: str, level="info", args: list = None):
        """Append a timestamped, colour-coded message to the log widget."""
        if args is None:
            args = []
        formatted_msg = self.translator.get(msg_key, *args)
        if not formatted_msg:
            self.log_text.append("")
            return
        colors = {
            'info': REFINED_PALETTE['text_secondary'],
            'success': REFINED_PALETTE['success'],
            'warning': REFINED_PALETTE['warning'],
            'error': REFINED_PALETTE['error'],
        }
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = colors.get(level, colors['info'])
        self.log_text.append(
            f'<span style="color: {REFINED_PALETTE["text_muted"]};">{timestamp}</span>'
            f' <span style="color: {color};">{formatted_msg}</span>'
        )

    def show_task_error(self, title_key, message):
        """Show a warning dialog for a task-manager error."""
        QMessageBox.warning(self, self.translator.get(title_key), message)

    def add_files(self):
        """Open a file picker and queue the selected PE files."""
        files, _ = QFileDialog.getOpenFileNames(
            self,
            self.translator.get("dialog_select_pe_files"),
            "",
            self.translator.get("dialog_pe_files_filter"),
        )
        if files:
            self.process_files(files)

    def add_folder(self):
        """Prompt for sub-folder option, pick a folder, and launch the scan dialog."""
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(self.translator.get("dialog_search_option"))
        msg_box.setText(self.translator.get("dialog_search_subfolders"))
        yes_button = msg_box.addButton(
            self.translator.get("dialog_yes_recursive"), QMessageBox.ButtonRole.YesRole
        )
        _no_button = msg_box.addButton(
            self.translator.get("dialog_no_folder_only"), QMessageBox.ButtonRole.NoRole
        )
        cancel_button = msg_box.addButton(
            self.translator.get("dialog_cancel"), QMessageBox.ButtonRole.RejectRole
        )
        msg_box.exec()
        if msg_box.clickedButton() == cancel_button:
            return
        include_subfolders = msg_box.clickedButton() == yes_button
        folder = QFileDialog.getExistingDirectory(
            self, self.translator.get("dialog_select_folder")
        )
        if folder:
            subfolder_hint = (
                self.translator.get('log_with_subfolders') if include_subfolders else ''
            )
            self.log('log_scanning_folder', 'info', [folder, subfolder_hint])
            scan_dialog = RefinedFolderDialog(self, folder, include_subfolders)
            accepted = scan_dialog.exec() == QDialog.DialogCode.Accepted
            found_files = scan_dialog.get_found_files()
            if accepted and found_files:
                self.process_files(found_files)

    def process_files(self, paths):
        """Start background validation of *paths* and add valid files to the list."""
        new = [p for p in paths if not any(f['path'] == p for f in self.files)]
        if not new:
            self.log("log_all_files_added", "warning")
            return
        self.progress.setRange(0, 0)
        worker = self.thread_manager.start_task(
            FileProcessorWorker,
            self.translator.get("task_analyzing_files"),
            new,
        )
        if not worker:
            self.progress.setRange(0, 100)
            return
        worker.file_processed.connect(self.add_file_item)
        worker.finished.connect(self.files_added)

    def add_file_item(self, info):
        """Add a validated file entry to the list widget."""
        if self.empty_state.isVisible():
            self.empty_state.hide()
            self.files_container.show()
        item = SwipeableFileItem(info, self.translator)
        item.removed.connect(self.remove_file_with_animation)
        self.files.append(info)
        self.file_items[info['path']] = item
        self.files_layout.addWidget(item)
        self.update_stats()

    def files_added(self, added, errors):
        """Reset the progress bar and log the outcome of file processing."""
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        if added:
            self.log("log_files_added", "success", [added])
        if errors:
            self.log("log_files_skipped", "warning", [errors])

    def remove_file_with_animation(self, path):
        """Trigger the removal animation for the file at *path*."""
        if path in self.file_items:
            self.animate_card_removal(path)

    def animate_card_removal(self, path: str):
        """Run a slide-out + shrink animation then finalise removal."""
        widget = self.file_items.get(path)
        if not widget:
            return
        anim_group = QParallelAnimationGroup(widget)
        slide_anim = QPropertyAnimation(widget, b"pos")
        slide_anim.setDuration(300)
        slide_anim.setStartValue(widget.pos())
        slide_anim.setEndValue(QPoint(widget.width() * -1, widget.pos().y()))
        slide_anim.setEasingCurve(QEasingCurve.Type.InCubic)
        shrink_anim = QPropertyAnimation(widget, b"maximumHeight")
        shrink_anim.setDuration(250)
        shrink_anim.setStartValue(widget.height())
        shrink_anim.setEndValue(0)
        anim_group.addAnimation(slide_anim)
        anim_group.addAnimation(shrink_anim)
        anim_group.finished.connect(lambda: self.finalize_removal(path, widget))
        anim_group.start()

    def finalize_removal(self, path, item):
        """Remove the file record and widget after the animation finishes."""
        self.files = [f for f in self.files if f['path'] != path]
        self.file_items.pop(path, None)
        item.deleteLater()
        if not self.files:
            self.empty_state.show()
            self.files_container.hide()
        self.update_stats()

    def clear_all(self):
        """Remove all files from the list after confirmation."""
        if self.thread_manager.is_running():
            QMessageBox.warning(
                self,
                self.translator.get("dialog_op_in_progress"),
                self.translator.get("dialog_cannot_clear"),
            )
            return
        if not self.files:
            QMessageBox.information(
                self,
                self.translator.get("dialog_list_empty"),
                self.translator.get("dialog_no_files_to_clear"),
            )
            return
        question = QMessageBox.question(
            self,
            self.translator.get("dialog_confirmation"),
            self.translator.get("dialog_clear_all_q"),
        )
        if question == QMessageBox.StandardButton.Yes:
            for item in self.file_items.values():
                item.deleteLater()
            self.files.clear()
            self.file_items.clear()
            self.empty_state.show()
            self.files_container.hide()
            self.update_stats()
            self.log("log_list_cleared", "info")

    def clear_log(self):
        """Clear the log widget and log the clear action itself."""
        self.log_text.clear()
        self.log("log_cleared", "info")

    def update_stats(self):
        """Refresh the file-count badge in the header."""
        self.files_count.setText(str(len(self.files)))

    def toggle_apis(self, state):
        """Check or uncheck all individual API checkboxes at once."""
        for check in self.api_checks.values():
            check.setChecked(bool(state))

    def on_api_change(self):
        """Keep the 'All APIs' master checkbox in sync with individual ones."""
        all_checked = all(c.isChecked() for c in self.api_checks.values())
        self.all_apis.blockSignals(True)
        self.all_apis.setChecked(all_checked)
        self.all_apis.blockSignals(False)

    def on_main_action_click(self):
        """Toggle between starting a patch run and requesting cancellation."""
        if self.thread_manager.is_running():
            self.thread_manager.stop_current_task()
            self.main_action_btn.setText(self.translator.get("cancelling"))
            self.main_action_btn.setEnabled(False)
        else:
            self.start_patching()

    def set_ui_for_patching(self, is_patching: bool):
        """Enable or disable interactive controls during a patch operation."""
        if is_patching:
            self.main_action_btn.setText(self.translator.get("cancel"))
            self.main_action_btn.setEnabled(True)
            self.clear_btn.setEnabled(False)
            self.add_files_btn.setEnabled(False)
            self.add_folder_btn.setEnabled(False)
            for item in self.file_items.values():
                item.setEnabled(False)
        else:
            self.main_action_btn.setText(self.translator.get("start_patching"))
            self.main_action_btn.setEnabled(True)
            self.clear_btn.setEnabled(True)
            self.add_files_btn.setEnabled(True)
            self.add_folder_btn.setEnabled(True)
            for item in self.file_items.values():
                item.setEnabled(True)

    def start_patching(self):
        """Validate the selection and launch the PatcherWorker thread."""
        if not self.files:
            QMessageBox.warning(
                self,
                self.translator.get("warning_title"),
                self.translator.get("warning_no_files"),
            )
            return

        apis = [key for key, checkbox in self.api_checks.items() if checkbox.isChecked()]
        if self.all_apis.isChecked():
            apis = list(DLL_REPLACEMENTS.keys())
        if not apis:
            QMessageBox.warning(
                self,
                self.translator.get("warning_title"),
                self.translator.get("warning_no_api"),
            )
            return

        self.set_ui_for_patching(True)
        self.progress.setValue(0)

        worker = self.thread_manager.start_task(
            PatcherWorker,
            self.translator.get("task_patching_files"),
            list(self.files),
            apis,
            self.backup.isChecked(),
            self.overwrite.isChecked(),
        )

        if not worker:
            self.set_ui_for_patching(False)
            return

        worker.log_message.connect(self.log)
        worker.progress_updated.connect(self.progress.setValue)
        worker.file_status_updated.connect(self.on_file_status_updated)
        worker.finished.connect(self.patching_done)

    def on_file_status_updated(self, path: str, status: str, text_key: str):
        """Update the visual status of a file row without removing it yet."""
        widget = self.file_items.get(path)
        if widget:
            widget.update_status(status, self.translator.get(text_key))

    def patching_done(
        self,
        stats: Tuple[int, int, int],
        was_cancelled: bool,
        cancelled_file_index: int = -1,
        total_files: int = 0,
        remaining_files: int = 0,
    ):
        """Handle patching completion: clean up the file list and show a summary."""
        s, k, e = stats

        # -1 is used instead of None because Qt Signal cannot carry NoneType int
        if cancelled_file_index == -1:
            cancelled_file_index = None

        if total_files is None or total_files == 0:
            total_files = (
                cancelled_file_index + len(self.files)
                if cancelled_file_index else len(self.files)
            )
        if remaining_files is None:
            remaining_files = (
                total_files - cancelled_file_index
                if cancelled_file_index is not None else 0
            )

        self.progress.setValue(0)
        self.set_ui_for_patching(False)

        if was_cancelled and cancelled_file_index is not None:
            paths_to_remove = [self.files[i]['path'] for i in range(cancelled_file_index)]
            for path in paths_to_remove:
                if path in self.file_items:
                    widget = self.file_items[path]
                    self.files_layout.removeWidget(widget)
                    widget.deleteLater()
                    self.file_items.pop(path, None)
            self.files = self.files[cancelled_file_index:]
            if not self.files:
                self.files_container.hide()
                self.empty_state.show()
            self.update_stats()
            self.log(
                "log_patched_files_removed", "info",
                [cancelled_file_index, total_files, remaining_files]
            )
        else:
            if not was_cancelled:
                for path in list(self.file_items.keys()):
                    widget = self.file_items[path]
                    self.files_layout.removeWidget(widget)
                    widget.deleteLater()
                    self.file_items.pop(path, None)
                self.files.clear()
                self.files_container.hide()
                self.empty_state.show()
                self.update_stats()

        summary_parts = []
        if s > 0:
            summary_parts.append(self.translator.get("summary_patched", s))
        if k > 0:
            summary_parts.append(self.translator.get("summary_skipped", k))
        if e > 0:
            summary_parts.append(self.translator.get("summary_errors", e))

        if was_cancelled:
            summary_text = (
                self.translator.get("summary_cancelled_prefix") + ", ".join(summary_parts)
            )
        else:
            summary_text = (
                self.translator.get("summary_finished_prefix") + ", ".join(summary_parts)
                if summary_parts else self.translator.get("summary_no_ops")
            )

        level = "success" if e == 0 and s > 0 and not was_cancelled else "warning"
        self.log(summary_text, level, [])

        if not was_cancelled:
            QMessageBox.information(
                self,
                self.translator.get("dialog_completed_title"),
                summary_text,
            )
        else:
            self.log("log_operation_stopped", "info")

            def show_cancel_dialog():
                """Show a dialog reporting how many files were not processed."""
                if remaining_files > 0:
                    cancel_message = self.translator.get(
                        "dialog_cancel_remaining", remaining_files
                    )
                    QMessageBox.information(
                        self,
                        self.translator.get("dialog_cancelled_title"),
                        cancel_message,
                    )

            QTimer.singleShot(500, show_cancel_dialog)

    def show_about(self):
        """Open the About dialog."""
        about_dialog = AboutDialog(self, self.translator)
        about_dialog.exec()


# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setStyleSheet(REFINED_STYLESHEET)

    lang_code, show_dialog = load_settings()

    if show_dialog:
        dialog = LanguageDialog()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            lang_code, show_dialog_next_time = dialog.get_selection()
            save_settings(lang_code, show_dialog_next_time)
        else:
            sys.exit(0)

    translator = TranslationManager(lang_code)

    qt_translator = QTranslator()
    if lang_code != "en":
        translations_path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
        if qt_translator.load(f"qt_{lang_code}.qm", translations_path):
            app.installTranslator(qt_translator)

    window = PEPatcherGUI(translator)
    window.show()
    sys.exit(app.exec())
