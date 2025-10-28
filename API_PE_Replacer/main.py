# -*- coding: utf-8 -*-

import sys
import os
import stat
import shutil
import platform
import subprocess
import tempfile
import re
from datetime import datetime
from pathlib import Path
from typing import List, Tuple
from configparser import ConfigParser
import xml.etree.ElementTree as ET
import glob

import pefile
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTextEdit, QFrame, QFileDialog, QMessageBox, QCheckBox, QDialog,
    QProgressBar, QScrollArea, QListWidget, QGraphicsDropShadowEffect,
    QGridLayout, QGroupBox, QSizePolicy, QSplitter, QTextBrowser
)
from PyQt6.QtCore import (
    QThread, QObject, pyqtSignal, Qt, QTranslator, QLibraryInfo, QTimer,
    QPropertyAnimation, QPoint, QEasingCurve, QParallelAnimationGroup
)
from PyQt6.QtGui import QTextCursor, QFont, QColor, QPalette

# Імпортуємо конфігурацію із зовнішнього файлу
try:
    from config import DLL_REPLACEMENTS
except ImportError:
    print("❌ Помилка: Файл config.py не знайдено або він пошкоджений")
    sys.exit(1)
except Exception as e:
    print(f"❌ Помилка при завантаженні конфігурації: {e}")
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
    'github': 'https://github.com/EXLOUD'
}

# =============================================================================
# 0. ГЛОБАЛЬНІ КОНФІГУРАЦІЇ
# =============================================================================

APP_VERSION = "1.0.9b"
LANG_FOLDER = "languages"

def sanitize_filename(filename: str) -> str:
    return re.sub(r'[\\/*?:"<>|]', '_', filename)

# ### ЗМІНА: Функції для правильного визначення шляхів ###
def resource_path(relative_path):
    """ Отримує абсолютний шлях до ресурсу, вбудованого в .exe """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def get_base_path():
    """ Повертає шлях до папки з .exe або .py файлом """
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

# =============================================================================
# 1. REFINED DARK THEME
# =============================================================================
REFINED_PALETTE = {
    'bg_primary': '#0E0E10', 'bg_secondary': '#141417', 'bg_tertiary': '#1A1A1E', 'bg_elevated': '#202024',
    'bg_overlay': '#26262B', 'accent': '#8B7FB8', 'accent_hover': '#9D91C7', 'accent_muted': 'rgba(139, 127, 184, 0.15)',
    'accent_subtle': 'rgba(139, 127, 184, 0.08)', 'text': '#E8E6F0', 'text_secondary': '#A8A5B8', 'text_muted': '#6B6878',
    'text_disabled': '#48465A', 'success': '#6BCF7F', 'warning': '#E4A853', 'error': '#CF6679', 'info': '#64B5F6',
    'border': 'rgba(255, 255, 255, 0.04)', 'border_hover': 'rgba(139, 127, 184, 0.2)', 'shadow': 'rgba(0, 0, 0, 0.4)'
}

STANDARD_BUTTON_STYLE = f"""
    QPushButton {{
        font-size: 13px; font-weight: 500; letter-spacing: 0.5px; padding: 11px 20px;
        border-radius: 8px; background-color: {REFINED_PALETTE['bg_tertiary']}; color: {REFINED_PALETTE['text_secondary']};
        border: none;
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
    shadow = QGraphicsDropShadowEffect(); shadow.setBlurRadius(16); shadow.setXOffset(0); shadow.setYOffset(2); shadow.setColor(QColor(0, 0, 0, 80)); return shadow

# =============================================================================
# 2. МЕНЕДЖЕР ПЕРЕКЛАДІВ ТА НАЛАШТУВАНЬ
# =============================================================================
class TranslationManager:
    def __init__(self, lang_code='en'):
        self.translations = {}
        self.load_language(lang_code)
    
    def load_language(self, lang_code):
        lang_path = resource_path(LANG_FOLDER)
        
        # ← НОВЕ: Перевіряємо чи папка існує
        if not os.path.exists(lang_path):
            print(f"⚠️ Warning: Languages folder not found: {lang_path}")
            self.translations = {}
            return
        
        filepath = os.path.join(lang_path, f"lang_{lang_code}.xml")
        
        # ← НОВЕ: Перевіряємо чи файл існує
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
        except Exception as e:
            print(f"❌ Error loading translation file {filepath}: {e}")
            self.translations = {}
    
    def get(self, key, *args):
        template = self.translations.get(key, key)
        try:
            return template.format(*args)
        except (IndexError, TypeError):
            return template

def get_settings_path():
    return os.path.join(get_base_path(), "settings.ini")

def load_settings():
    path = get_settings_path()
    config = ConfigParser()
    if os.path.exists(path):
        config.read(path, encoding='utf-8')
        return (
            config.get("Settings", "language", fallback="en"),
            config.getboolean("Settings", "show_dialog", fallback=True)
        )
    return "en", True

def save_settings(lang, show_dialog):
    path = get_settings_path()
    config = ConfigParser()
    config.add_section("Settings")
    config.set("Settings", "language", lang)
    config.set("Settings", "show_dialog", str(show_dialog))
    with open(path, 'w', encoding='utf-8') as f:
        config.write(f)

def get_language_name_from_xml(filepath: str) -> str:
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        lang_name_tag = root.find(".//string[@name='language_name']")
        if lang_name_tag is not None and lang_name_tag.text:
            return lang_name_tag.text
    except Exception:
        pass
    basename = os.path.basename(filepath)
    try:
        return basename.split('_')[1].split('.')[0]
    except IndexError:
        return basename

# =============================================================================
# 3. БЕКЕНД ЛОГІКА (без змін)
# =============================================================================
class PatcherLogEmitter(QObject):
    log_signal = pyqtSignal(str, str, list)
    def emit(self, key: str, level: str, args: list = None): self.log_signal.emit(key, level, args or [])

class PermissionsManager:
    def __init__(self, file_path: str, log_emitter: PatcherLogEmitter):
        self.file_path, self.log_emitter = file_path, log_emitter
        self.original_permissions, self.permissions_were_changed = None, False
    def __enter__(self):
        try:
            self.original_permissions = os.stat(self.file_path).st_mode
            if not (self.original_permissions & stat.S_IWUSR):
                self.log_emitter.emit("log_readonly_file", "warning", [os.path.basename(self.file_path)])
                self.log_emitter.emit("log_changing_perms", "info")
                os.chmod(self.file_path, self.original_permissions | stat.S_IWUSR)
                self.log_emitter.emit("log_perms_changed", "success")
                self.permissions_were_changed = True
            return self
        except Exception as e:
            self.log_emitter.emit("log_perms_error", "error", [str(e)]); raise
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.permissions_were_changed and self.original_permissions is not None:
            try:
                self.log_emitter.emit("log_restoring_perms", "info")
                os.chmod(self.file_path, self.original_permissions)
                self.log_emitter.emit("log_perms_restored", "success")
            except Exception as e:
                self.log_emitter.emit("log_restore_perms_error", "error", [str(e)])

class UniversalPEPatcher:
    def __init__(self, file_path: str, selected_apis: List[int], log_emitter: PatcherLogEmitter):
        self.file_path, self.log_emitter, self.pe, self.data = file_path, log_emitter, None, None
        self.active_replacements = {k: v for api_num in selected_apis for k, v in DLL_REPLACEMENTS[api_num]['replacements'].items()}
    def load_file(self) -> bool:
        try:
            with open(self.file_path, 'rb') as f: self.data = bytearray(f.read())
            self.pe = pefile.PE(data=self.data); return True
        except Exception as e:
            self.log_emitter.emit("log_load_error", "error", [str(e)]); return False
    def check_if_patchable(self) -> int:
        if not self.data and not self.load_file(): return 0
        count, iat_details, hex_details = 0, [], []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', 'ignore').upper() if entry.dll else ""
                for orig_dll_bytes in self.active_replacements:
                    if dll_name == orig_dll_bytes.decode('utf-8').upper():
                        count += 1; iat_details.append(dll_name); break
        for old_bytes in self.active_replacements:
            hex_count = self.data.count(old_bytes)
            if hex_count > 0: count += hex_count; hex_details.append(f"{old_bytes.decode('utf-8', 'ignore')} ({hex_count}x)")
        if iat_details or hex_details:
            self.log_emitter.emit("log_patch_details_header", "info")
            if iat_details: self.log_emitter.emit("log_patch_details_iat", "info", [', '.join(iat_details)])
            if hex_details: self.log_emitter.emit("log_patch_details_hex", "info", [', '.join(hex_details)])
        return count
    def patch_all(self) -> int:
        count, iat_count, hex_patched_details = 0, 0, {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                if not entry.dll: continue
                dll_name = entry.dll.decode('utf-8', 'ignore')
                for orig, repl in self.active_replacements.items():
                    if dll_name.upper() == orig.decode('utf-8').upper():
                        offset = self.pe.get_offset_from_rva(entry.struct.Name)
                        if offset and len(repl) <= len(entry.dll):
                            self.data[offset:offset + len(repl)] = repl
                            if len(repl) < len(entry.dll): self.data[offset + len(repl):offset + len(entry.dll)] = b'\x00' * (len(entry.dll) - len(repl))
                            count += 1; iat_count += 1
                        else: self.log_emitter.emit("log_iat_skipped_long", "warning", [dll_name])
                        break
        for old, new in self.active_replacements.items():
            if len(old) != len(new):
                self.log_emitter.emit("log_hex_skipped_len", "warning", [old.decode('utf-8', 'ignore')]); continue
            start_index, local_count = 0, 0
            while (index := self.data.find(old, start_index)) != -1:
                self.data[index:index + len(old)] = new; start_index = index + len(old)
                count += 1; local_count += 1
            if local_count > 0: hex_patched_details[old.decode('utf-8', 'ignore')] = (new.decode('utf-8', 'ignore'), local_count)
        if count > 0:
            for dll, (new_dll, cnt) in hex_patched_details.items(): self.log_emitter.emit("log_hex_patched", "info", [dll, new_dll, cnt])
            self.log_emitter.emit("log_total_changes", "success", [count])
        return count
    def save(self, output_path: str) -> bool:
        try:
            pe_patched = pefile.PE(data=self.data); pe_patched.write(output_path); pe_patched.close()
            self.log_emitter.emit("log_file_saved", "success", [os.path.basename(output_path)]); return True
        except Exception as e:
            self.log_emitter.emit("log_save_error", "error", [str(e)]); return False
    def close(self): self.pe = None; self.data = None

class FileProcessorWorker(QObject):
    file_processed = pyqtSignal(dict); finished = pyqtSignal(int, int)
    def __init__(self, file_paths): super().__init__(); self.file_paths = file_paths
    def run(self):
        added, error = 0, 0
        for path in self.file_paths:
            try:
                with open(path, 'rb') as f:
                    if f.read(2) != b'MZ': error += 1; continue
                info = {'path': path, 'size': os.path.getsize(path), 'type': 'PE', 'arch': 'x86', 'status': 'ready', 'status_text_key': 'status_ready'}
                try:
                    pe = pefile.PE(path, fast_load=True)
                    info['type'] = 'DLL' if pe.is_dll() else 'EXE' if pe.is_exe() else 'PE'
                    info['arch'] = 'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'
                    pe.close()
                except Exception: pass
                self.file_processed.emit(info); added += 1
            except Exception: error += 1
        self.finished.emit(added, error)

class FolderScannerWorker(QObject):
    finished = pyqtSignal(); file_found = pyqtSignal(str); scan_complete = pyqtSignal(list, list)
    def __init__(self, folder_path, include_subfolders):
        super().__init__(); self.folder_path = Path(folder_path)
        self.include_subfolders = include_subfolders; self.is_cancelled = False
    def run(self):
        try:
            found, skipped, exts = [], set(), {'.exe', '.dll', '.vst3', '.vst', '.sys', '.ocx', '.ax'}
            pattern = '**/*' if self.include_subfolders else '*'
            for p in self.folder_path.glob(pattern):
                if self.is_cancelled: break
                if p.is_dir() or p.suffix.lower() not in exts: continue
                if not {'patched', 'backup'}.isdisjoint({part.lower() for part in p.parts}): skipped.add("Patched/Backup"); continue
                try:
                    with p.open('rb') as f:
                        if f.read(2) == b'MZ': found.append(str(p)); self.file_found.emit(p.name)
                except (IOError, PermissionError): continue
            if not self.is_cancelled: self.scan_complete.emit(sorted(list(set(found))), sorted(list(skipped)))
        except Exception as e: print(f"Error in FolderScannerWorker: {e}")
        finally: self.finished.emit()
    def cancel(self): self.is_cancelled = True

class PatcherWorker(QObject):
    log_message = pyqtSignal(str, str, list)
    file_status_updated = pyqtSignal(str, str, str)
    progress_updated = pyqtSignal(int)
    finished = pyqtSignal(tuple, bool, int, int, int)  # ← НОВЕ: +int для remaining_files
    
    def __init__(self, files, selected_apis, backup, overwrite):
        super().__init__()
        self.files, self.selected_apis = files, selected_apis
        self.backup_var, self.overwrite_var = backup, overwrite
        self.is_cancelled = False
        self.total_files = len(files)
        self.log_emitter = PatcherLogEmitter()
        self.log_emitter.log_signal.connect(self.log_message)
    
    def cancel(self):
        self.log_message.emit("log_cancel_request", "warning", [])
        self.is_cancelled = True
    
    def run(self):
        s, e, k, total = 0, 0, 0, len(self.files)
        was_cancelled = False
        cancelled_file_index = None
        
        try:
            for i, info in enumerate(self.files):
                if self.is_cancelled:
                    was_cancelled = True
                    cancelled_file_index = i
                    self.log_message.emit("log_patching_cancelled", "warning", [])
                    
                    for remaining_info in self.files[i:]:
                        self.file_status_updated.emit(remaining_info['path'], 'warning', 'status_cancelled')
                    break

                path, name = info['path'], sanitize_filename(os.path.basename(info['path']))
                self.log_message.emit("", "info", [])
                self.log_message.emit("log_processing_file", "info", [f"[{i+1}/{total}]", os.path.basename(path)])
                original_file_data = None

                try:
                    with open(path, 'rb') as f:
                        original_file_data = f.read()
                except Exception as read_err:
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
                                self.file_status_updated.emit(remaining_info['path'], 'warning', 'status_cancelled')
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
                                self.file_status_updated.emit(remaining_info['path'], 'warning', 'status_cancelled')
                            break

                        p_count = patcher.patch_all()

                        if p_count > 0:
                            if self.is_cancelled:
                                was_cancelled = True
                                cancelled_file_index = i
                                self.log_message.emit("log_patching_cancelled", "warning", [])
                                for remaining_info in self.files[i:]:
                                    self.file_status_updated.emit(remaining_info['path'], 'warning', 'status_cancelled')
                                break

                            if self.backup_var:
                                b_dir = os.path.join(os.path.dirname(path), 'backup')
                                os.makedirs(b_dir, exist_ok=True)
                                b_path, cnt = os.path.join(b_dir, name), 1
                                base, ext = os.path.splitext(name)
                                while os.path.exists(b_path):
                                    b_path = os.path.join(b_dir, f"{base}.backup{cnt}{ext}")
                                    cnt += 1
                                with open(b_path, 'wb') as bf:
                                    bf.write(original_file_data)
                                self.log_message.emit("log_backup_saved", "info", [os.path.basename(b_path)])

                            if self.is_cancelled:
                                was_cancelled = True
                                cancelled_file_index = i
                                self.log_message.emit("log_patching_cancelled", "warning", [])
                                for remaining_info in self.files[i:]:
                                    self.file_status_updated.emit(remaining_info['path'], 'warning', 'status_cancelled')
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
                                except Exception as move_err:
                                    self.log_message.emit("log_move_error", "error", [str(move_err)])
                                    e += 1
                                    self.file_status_updated.emit(path, 'error', 'status_error')
                            
                            s += 1
                            self.file_status_updated.emit(path, 'success', 'status_done')
                        else:
                            k += 1
                            self.file_status_updated.emit(path, 'warning', 'status_no_changes')

                except Exception as err:
                    self.log_message.emit("log_general_error", "error", [str(err)])
                    e += 1
                    self.file_status_updated.emit(path, 'error', 'status_error')
                finally:
                    if patcher:
                        patcher.close()

                self.progress_updated.emit(int((i + 1) / total * 100))

        finally:
            # ← НОВЕ: Обраховуємо залишені файли
            remaining_files = total - cancelled_file_index if cancelled_file_index is not None else 0
            # ← НОВЕ: Передаємо remaining_files у сигнал
            self.finished.emit((s, k, e), was_cancelled, cancelled_file_index, self.total_files, remaining_files)
        
class ThreadManager(QObject):
    task_started = pyqtSignal(str); task_finished = pyqtSignal(str); error = pyqtSignal(str, str)
    def __init__(self, parent=None):
        super().__init__(parent); self.current_thread, self.current_worker, self.current_task_name = None, None, None
    def is_running(self) -> bool: return self.current_thread is not None and self.current_thread.isRunning()
    def start_task(self, worker_class, task_name: str, *args, **kwargs) -> QObject:
        if self.is_running():
            self.error.emit("dialog_op_in_progress", f"Зачекайте, доки завершиться: '{self.current_task_name}'."); return None
        self.current_task_name, self.current_thread = task_name, QThread()
        self.current_worker = worker_class(*args, **kwargs); worker = self.current_worker
        worker.moveToThread(self.current_thread)
        self.current_thread.started.connect(worker.run); worker.finished.connect(self.current_thread.quit)
        self.current_thread.finished.connect(self._cleanup_after_thread_finish)
        self.current_thread.finished.connect(worker.deleteLater); self.current_thread.finished.connect(self.current_thread.deleteLater)
        self.current_thread.start(); self.task_started.emit(task_name); return worker
    def _cleanup_after_thread_finish(self):
        task_name = self.current_task_name; self.current_thread, self.current_worker, self.current_task_name = None, None, None; self.task_finished.emit(task_name)
    def stop_current_task(self):
        if self.is_running() and hasattr(self.current_worker, 'cancel'): self.current_worker.cancel()

# =============================================================================
# 4. ВІДЖЕТИ ТА ДІАЛОГИ
# =============================================================================
class LanguageDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Language Selection")
        self.setMinimumWidth(400)
        self.setMinimumHeight(300)
        self.language = "en"  # Default
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(20)

        title_label = QLabel("Select Language")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setProperty("class", "h3")
        main_layout.addWidget(title_label)
        
        # ← НОВЕ: Перевіряємо чи існує папка languages
        lang_path = resource_path(LANG_FOLDER)
        lang_files = glob.glob(os.path.join(lang_path, "lang_*.xml")) if os.path.exists(lang_path) else []
        
        if not lang_files:
            # ← НОВЕ: Папки нема або в ній немає мовних файлів
            error_label = QLabel(
                "⚠️ Language files not found!\n\n"
                "Please ensure the 'languages' folder exists with translation files:\n"
                "- languages/lang_en.xml\n\n"
                "Copy the language files from the application directory and try again."
            )
            error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            error_label.setWordWrap(True)
            error_label.setStyleSheet(f"color: {REFINED_PALETTE['warning']}; font-size: 12px;")
            main_layout.addWidget(error_label, 1)
            
            # Кнопка для закриття
            close_btn = QPushButton("Exit")
            close_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
            close_btn.clicked.connect(self.reject)
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()
            btn_layout.addWidget(close_btn)
            btn_layout.addStretch()
            main_layout.addLayout(btn_layout)
        else:
            # ← НОВЕ: Мови знайдені - показуємо їх як раніше
            scroll_area = QScrollArea()
            scroll_area.setWidgetResizable(True)
            scroll_area.setFrameShape(QFrame.Shape.NoFrame)
            scroll_area.setStyleSheet("background: transparent;")
            
            button_container = QWidget()
            buttons_layout = QVBoxLayout(button_container)
            buttons_layout.setContentsMargins(0, 0, 0, 0)
            buttons_layout.setSpacing(8)

            available_languages = {}
            for f in lang_files:
                lang_code = os.path.basename(f).split('_')[1].split('.')[0]
                lang_name = get_language_name_from_xml(f)
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
        self.language = lang_code
        self.accept()

    def get_selection(self):
        if hasattr(self, 'show_again_checkbox'):
            return self.language, self.show_again_checkbox.isChecked()
        return self.language, False


class RefinedContainer(QWidget):
    def __init__(self, container_type="card", parent=None):
        super().__init__(parent); self.setObjectName({"card": "RefinedCard", "elevated": "ElevatedCard"}.get(container_type, "RefinedCard"))
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        if container_type == "elevated": self.setGraphicsEffect(create_subtle_shadow())

class SwipeableFileItem(QWidget):
    removed = pyqtSignal(str)
    def __init__(self, file_info, translator):
        super().__init__()
        self.file_info = file_info; self.translator = translator
        self.start_pos = None; self.current_pos = 0; self.swipe_threshold = 60; self.is_swiped = False
        wrapper_layout = QVBoxLayout(self); wrapper_layout.setContentsMargins(0, 0, 0, 0); wrapper_layout.setSpacing(0)
        file_widget = QWidget(); file_widget.setObjectName("FileItem"); file_widget.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True); file_widget.setFixedHeight(56)
        main_layout = QHBoxLayout(file_widget); main_layout.setContentsMargins(0, 0, 0, 0); main_layout.setSpacing(0)
        self.content_widget = QWidget(); self.content_widget.setStyleSheet("background: transparent;")
        content_layout = QHBoxLayout(self.content_widget); content_layout.setContentsMargins(16, 0, 16, 0); content_layout.setSpacing(12)
        info_layout = QVBoxLayout(); info_layout.setSpacing(2); info_layout.setContentsMargins(0, 0, 0, 0)
        name = QLabel(os.path.basename(file_info['path'])); name.setProperty("class", "subtitle"); name.setStyleSheet(f"color: {REFINED_PALETTE['text']};"); info_layout.addWidget(name)
        details = QLabel(f"{file_info['type']} · {self._format_size(file_info['size'])} · {file_info['arch']}"); details.setProperty("class", "caption"); info_layout.addWidget(details)
        content_layout.addLayout(info_layout, 1)
        self.status_label = QLabel(self.translator.get(file_info.get('status_text_key', 'status_ready'))); self.status_label.setProperty("class", "caption"); content_layout.addWidget(self.status_label)
        remove_btn = QPushButton("×"); remove_btn.setProperty("variant", "ghost"); remove_btn.setFixedSize(24, 24)
        remove_btn.setStyleSheet("""QPushButton { font-size: 18px; padding: 0; border-radius: 4px; color: #6B6878; } QPushButton:hover { color: #CF6679; background-color: rgba(207, 102, 121, 0.1); }""")
        remove_btn.setCursor(Qt.CursorShape.PointingHandCursor); remove_btn.clicked.connect(lambda: self.removed.emit(self.file_info['path'])); content_layout.addWidget(remove_btn)
        self.delete_icon = QLabel("🗑️"); self.delete_icon.setProperty("class", "caption"); self.delete_icon.setStyleSheet(f"color: {REFINED_PALETTE['error']}; padding: 0 16px;"); self.delete_icon.setAlignment(Qt.AlignmentFlag.AlignCenter); self.delete_icon.hide()
        main_layout.addWidget(self.content_widget); main_layout.addWidget(self.delete_icon)
        self.animation = QPropertyAnimation(self.content_widget, b"pos"); self.animation.setDuration(200); self.animation.finished.connect(self.on_animation_finished)
        wrapper_layout.addWidget(file_widget)
        divider = QFrame(); divider.setFixedHeight(1); divider.setStyleSheet(f"background-color: {REFINED_PALETTE['border']}; margin: 0;"); wrapper_layout.addWidget(divider)
    def _format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0: return f"{size:.1f}{unit}"
            size /= 1024.0
        return f"{size:.1f}TB"
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton: self.start_pos = event.pos()
    def mouseMoveEvent(self, event):
        if self.start_pos is not None and event.buttons() & Qt.MouseButton.LeftButton:
            delta = event.pos().x() - self.start_pos.x()
            if delta < 0:
                self.current_pos = max(delta, -self.swipe_threshold); self.content_widget.move(self.current_pos, 0)
                if abs(self.current_pos) > self.swipe_threshold * 0.7: self.delete_icon.show()
                else: self.delete_icon.hide()
    def mouseReleaseEvent(self, event):
        if self.start_pos is not None:
            if abs(self.current_pos) > self.swipe_threshold * 0.8:
                self.is_swiped = True; self.animation.setStartValue(self.content_widget.pos()); self.animation.setEndValue(QPoint(-self.width(), 0)); self.animation.start()
            else:
                self.animation.setStartValue(self.content_widget.pos()); self.animation.setEndValue(QPoint(0, 0)); self.animation.start(); self.delete_icon.hide()
        self.start_pos = None
    def on_animation_finished(self):
        if self.is_swiped: self.removed.emit(self.file_info['path'])
    def update_status(self, status: str, text: str):
        self.status_label.setText(text); colors = {'success': REFINED_PALETTE['success'], 'warning': REFINED_PALETTE['warning'], 'error': REFINED_PALETTE['error'], 'ready': REFINED_PALETTE['text_muted']}
        self.status_label.setStyleSheet(f"color: {colors.get(status, colors['ready'])};")

class RefinedFolderDialog(QDialog):
    def __init__(self, parent, folder_path, include_subfolders):
        super().__init__(parent); self.found_files, self.is_closing = [], False; self.translator = parent.translator
        self.setWindowTitle(self.translator.get("scan_folder_title")); self.setFixedSize(600, 500); self.setModal(True)
        layout = QVBoxLayout(self); layout.setContentsMargins(24, 24, 24, 24); layout.setSpacing(20)
        header = QLabel(self.translator.get("scan_folder_title")); header.setProperty("class", "h3"); layout.addWidget(header)
        path_label = QLabel(folder_path if len(folder_path) <= 60 else "..." + folder_path[-57:]); path_label.setProperty("class", "mono"); layout.addWidget(path_label)
        self.status_label = QLabel(self.translator.get("scanning_status_searching")); layout.addWidget(self.status_label)
        self.progress_bar = QProgressBar(); self.progress_bar.setRange(0, 0); self.progress_bar.setTextVisible(False); layout.addWidget(self.progress_bar)
        self.files_list = QListWidget(); layout.addWidget(self.files_list, 1)
        self.info_container = QWidget(); self.info_container.setStyleSheet(f"background-color: {REFINED_PALETTE['bg_tertiary']}; border-radius: 8px; padding: 12px;"); info_layout = QVBoxLayout(self.info_container); info_layout.setContentsMargins(12, 12, 12, 12); info_layout.setSpacing(6); self.skipped_label = QLabel(); self.skipped_label.setProperty("class", "caption"); self.skipped_label.setStyleSheet(f"color: {REFINED_PALETTE['text_muted']};"); self.skipped_label.setWordWrap(True); info_layout.addWidget(self.skipped_label); self.info_container.hide(); layout.addWidget(self.info_container)
        self.btn_layout = QHBoxLayout(); self.btn_layout.setSpacing(12); layout.addLayout(self.btn_layout); self.update_buttons(is_scanning=True)
        self.thread = QThread(self); self.worker = FolderScannerWorker(folder_path, include_subfolders); self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run); self.worker.finished.connect(self.thread.quit); self.thread.finished.connect(self.on_thread_finished)
        self.worker.scan_complete.connect(self.on_scan_complete); self.worker.file_found.connect(self.files_list.addItem)
        self.thread.start()
    def update_buttons(self, is_scanning=False, found_count=0):
        while self.btn_layout.count():
            item = self.btn_layout.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        self.btn_layout.addStretch()
        if is_scanning:
            cancel_btn = QPushButton(self.translator.get("cancel")); cancel_btn.clicked.connect(self.reject); self.btn_layout.addWidget(cancel_btn)
        else:
            if found_count > 0:
                add_btn = QPushButton(self.translator.get("add_n_files", found_count)); add_btn.clicked.connect(self.accept); self.btn_layout.addWidget(add_btn)
            close_btn = QPushButton(self.translator.get("close")); close_btn.clicked.connect(self.reject); self.btn_layout.addWidget(close_btn)
        self.btn_layout.addStretch()
    def on_scan_complete(self, found, skipped):
        self.found_files = found; self.progress_bar.setRange(0, 100); self.progress_bar.setValue(100)
        if skipped: self.skipped_label.setText(self.translator.get("skipped_folders_info") + ", ".join(skipped)); self.info_container.show()
        if found: self.status_label.setText(self.translator.get("found_n_files", len(found)))
        else: self.status_label.setText(self.translator.get("no_pe_files_found"))
        self.update_buttons(is_scanning=False, found_count=len(found))
    def on_thread_finished(self):
        if self.thread: self.thread.deleteLater()
        if self.worker: self.worker.deleteLater()
        self.thread, self.worker = None, None
        if self.is_closing: super().reject()
    def get_found_files(self): return self.found_files
    def reject(self):
        if self.thread and self.thread.isRunning():
            if not self.is_closing:
                self.is_closing = True; self.status_label.setText(self.translator.get("cancelling"))
                for i in range(self.btn_layout.count()):
                    if item := self.btn_layout.itemAt(i):
                        if widget := item.widget(): widget.setEnabled(False)
                self.worker.cancel()
        else: super().reject()
    def closeEvent(self, event): event.ignore(); self.reject()

class RefinedSplitter(QSplitter):
    def __init__(self, o, p=None): super().__init__(o, p); self.setHandleWidth(20); self.setStyleSheet("QSplitter { background-color: transparent; }")
class RefinedDivider(QFrame):
    def __init__(self, p=None): super().__init__(p); self.setFrameShape(QFrame.Shape.HLine); self.setFrameShadow(QFrame.Shadow.Plain); self.setLineWidth(1); self.setFixedHeight(1); self.setStyleSheet(f"QFrame {{ background-color: {REFINED_PALETTE['border']}; margin: 6px 0; border: none; }}")

class AboutDialog(QDialog):
    def __init__(self, parent, translator):
        super().__init__(parent)
        self.translator = translator
        self.setWindowTitle(self.translator.get("about"))
        self.setFixedSize(600, 690)
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self); main_layout.setContentsMargins(24, 24, 24, 24); main_layout.setSpacing(16)
        about_text = f"""<h2>{self.translator.get("app_title")} {APP_VERSION}</h2><hr style="margin: 12px 0; border: none; border-top: 1px solid {REFINED_PALETTE['border']};"><p style="font-size: 13px; margin-top: 12px;"><b>{self.translator.get("author")}:</b> <a href="{DONATION_ADDRESSES['github']}" style="color: {REFINED_PALETTE['accent']}; text-decoration: none;">github.com/EXLOUD</a></p>"""
        text_browser = QTextBrowser(); text_browser.setHtml(about_text); text_browser.setReadOnly(True); text_browser.setOpenExternalLinks(True)
        text_browser.setFixedHeight(120)
        
        donations_panel = QWidget()
        donations_panel_layout = QVBoxLayout(donations_panel)
        donations_panel_layout.setContentsMargins(0, 0, 0, 0)
        donations_panel_layout.setSpacing(8)

        title_label = QLabel(self.translator.get("donation_title"))
        title_label.setProperty("class", "caption")
        donations_panel_layout.addWidget(title_label)

        scroll_area = QScrollArea(); scroll_area.setWidgetResizable(True); scroll_area.setFrameShape(QFrame.Shape.NoFrame); scroll_area.setStyleSheet("background: transparent;")
        
        button_container = QWidget()
        buttons_layout = QVBoxLayout(button_container)
        buttons_layout.setContentsMargins(0, 8, 0, 0)
        buttons_layout.setSpacing(8)

        address_buttons = [("Bitcoin", "bitcoin"), ("Ethereum", "ethereum"), ("Monero", "monero"), ("TON", "ton"), ("USDT (TRC20)", "usdt_trc20"), ("USDT (ERC20)", "usdt_erc20"), ("USDC (ERC20)", "usdc_erc20"), ("Tron", "tron"), ("BNB", "bnb")]
        for name, key in address_buttons:
            btn = QPushButton(f"📋 {name}")
            btn.setStyleSheet(STANDARD_BUTTON_STYLE)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, addr_key=key: (QApplication.clipboard().setText(DONATION_ADDRESSES[addr_key]), self.parent().log("log_copied", "success", [addr_key.upper(), DONATION_ADDRESSES[addr_key][:15]])))
            buttons_layout.addWidget(btn)
        
        buttons_layout.addStretch()
        button_container.setLayout(buttons_layout)
        scroll_area.setWidget(button_container)
        
        donations_panel_layout.addWidget(scroll_area)
        
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(text_browser)
        splitter.addWidget(donations_panel)
        splitter.setSizes([120, 520])
        splitter.setStyleSheet("QSplitter::handle { height: 1px; background-color: transparent; }")

        main_layout.addWidget(splitter)

        close_btn = QPushButton(self.translator.get("close")); close_btn.setStyleSheet(STANDARD_BUTTON_STYLE); close_btn.setFixedWidth(120); close_btn.clicked.connect(self.accept)
        btn_layout = QHBoxLayout(); btn_layout.addStretch(); btn_layout.addWidget(close_btn); btn_layout.addStretch(); main_layout.addLayout(btn_layout)

# =============================================================================
# 5. ГОЛОВНЕ ВІКНО
# =============================================================================
class PEPatcherGUI(QMainWindow):
    def __init__(self, translator: TranslationManager):
        super().__init__()
        self.translator = translator
        self.files, self.file_items = [], {}
        self.thread_manager = ThreadManager(self); self.thread_manager.error.connect(self.show_task_error)
        self.setMinimumSize(960, 780); self.center_window(); self.setup_ui()
        self.retranslate_ui()
        self.log("log_app_started", "info", [self.translator.get('app_title'), APP_VERSION])

    def center_window(self):
        if screen := self.screen(): g = screen.availableGeometry(); self.move((g.width() - self.width()) // 2, (g.height() - self.height()) // 2)

    def setup_ui(self):
        main = QWidget(); self.setCentralWidget(main); layout = QVBoxLayout(main); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(0)
        self._create_header(layout)
        content = QWidget(); content_layout = QVBoxLayout(content); content_layout.setContentsMargins(24, 24, 24, 24); content_layout.setSpacing(0)
        self.horizontal_splitter = RefinedSplitter(Qt.Orientation.Horizontal); left_panel = self._create_left_panel(); self.horizontal_splitter.addWidget(left_panel)
        self.vertical_splitter = RefinedSplitter(Qt.Orientation.Vertical)
        settings_panel = self._create_settings_panel()
        log_panel = self._create_log_panel()
        self.vertical_splitter.addWidget(settings_panel)
        self.vertical_splitter.addWidget(log_panel)
        self.vertical_splitter.setSizes([300, 300]); self.horizontal_splitter.addWidget(self.vertical_splitter)
        self.horizontal_splitter.setSizes([600, 400]); content_layout.addWidget(self.horizontal_splitter); layout.addWidget(content, 1)
        self._create_bottom(layout)
    
    def _create_header(self, layout):
        header = QWidget(); header.setObjectName("AppHeader"); header_layout = QHBoxLayout(header)
        title_section = QWidget(); title_layout = QVBoxLayout(title_section); title_layout.setContentsMargins(0,0,0,0); title_layout.setSpacing(2)
        self.title_label = QLabel(); self.title_label.setProperty("class", "h1"); title_layout.addWidget(self.title_label)
        self.subtitle_label = QLabel(); self.subtitle_label.setProperty("class", "caption"); title_layout.addWidget(self.subtitle_label)
        header_layout.addWidget(title_section); header_layout.addStretch()
        stats_section = QWidget(); stats_layout = QHBoxLayout(stats_section); stats_layout.setSpacing(24)
        self.files_count = QLabel("0"); self.files_count.setProperty("class", "h1"); self.files_count.setStyleSheet(f"color: {REFINED_PALETTE['accent']};"); stats_layout.addWidget(self.files_count)
        self.files_label = QLabel(); self.files_label.setProperty("class", "caption"); stats_layout.addWidget(self.files_label)
        header_layout.addWidget(stats_section); layout.addWidget(header)

    def _create_left_panel(self):
        container = QWidget(); layout = QVBoxLayout(container); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(12)
        file_actions_container = RefinedContainer("card"); file_actions_layout = QVBoxLayout(file_actions_container)
        file_actions_layout.setContentsMargins(20, 16, 20, 16); file_actions_layout.setSpacing(12); header_layout_top = QHBoxLayout(); header_layout_top.setSpacing(12)
        self.add_files_btn = QPushButton(); self.add_files_btn.clicked.connect(self.add_files); header_layout_top.addWidget(self.add_files_btn, 1)
        self.add_folder_btn = QPushButton(); self.add_folder_btn.clicked.connect(self.add_folder); header_layout_top.addWidget(self.add_folder_btn, 1)
        file_actions_layout.addLayout(header_layout_top); layout.addWidget(file_actions_container)
        files_panel = self._create_files_panel(); layout.addWidget(files_panel, 1)
        buttons_container = RefinedContainer("card"); buttons_layout = QHBoxLayout(buttons_container)
        buttons_layout.setContentsMargins(20, 16, 20, 16); buttons_layout.setSpacing(12)
        self.main_action_btn = QPushButton(); self.main_action_btn.clicked.connect(self.on_main_action_click); buttons_layout.addWidget(self.main_action_btn, 1)
        self.clear_btn = QPushButton(); self.clear_btn.clicked.connect(self.clear_all); buttons_layout.addWidget(self.clear_btn, 1)
        layout.addWidget(buttons_container); return container

    def _create_files_panel(self):
        container = RefinedContainer("elevated"); layout = QVBoxLayout(container); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(0)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.Shape.NoFrame); scroll.setStyleSheet("background: transparent;")
        self.files_content = QWidget(); self.files_content.setStyleSheet("background: transparent;"); self.files_main_layout = QVBoxLayout(self.files_content); self.files_main_layout.setContentsMargins(0, 0, 0, 0); self.files_main_layout.setSpacing(0)
        self.empty_state = QWidget(); self.empty_state.setObjectName("EmptyState"); self.empty_state.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True); self.empty_state.setMinimumHeight(250)
        empty_layout = QVBoxLayout(self.empty_state); empty_layout.setAlignment(Qt.AlignmentFlag.AlignCenter); empty_layout.setSpacing(12)
        self.empty_text = QLabel(); self.empty_text.setProperty("class", "h3"); self.empty_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_hint = QLabel(); self.empty_hint.setProperty("class", "caption"); self.empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(self.empty_text); empty_layout.addWidget(self.empty_hint)
        self.files_container = QWidget(); self.files_container.setStyleSheet("background: transparent;"); self.files_layout = QVBoxLayout(self.files_container); self.files_layout.setContentsMargins(12, 12, 12, 12); self.files_layout.setSpacing(0); self.files_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.files_main_layout.addWidget(self.empty_state); self.files_main_layout.addWidget(self.files_container); self.files_container.hide()
        scroll.setWidget(self.files_content); layout.addWidget(scroll, 1); return container

    def _create_settings_panel(self):
        settings = RefinedContainer("card"); settings_layout = QVBoxLayout(settings); settings_layout.setContentsMargins(0, 0, 0, 0); settings_layout.setSpacing(0)
        header_widget = QWidget()
        header_widget.setStyleSheet(f""" background-color: {REFINED_PALETTE['bg_secondary']}; border-top-left-radius: 12px; border-top-right-radius: 12px; padding-bottom: 10px; """)
        header_layout = QVBoxLayout(header_widget); header_layout.setContentsMargins(20, 12, 20, 0); header_layout.setSpacing(0)
        self.settings_title = QLabel(); self.settings_title.setProperty("class", "h3"); self.settings_title.setAlignment(Qt.AlignmentFlag.AlignCenter); header_layout.addWidget(self.settings_title)
        settings_layout.addWidget(header_widget)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.Shape.NoFrame); scroll.setStyleSheet("background: transparent;")
        settings_content = QWidget(); content_layout = QVBoxLayout(settings_content); content_layout.setContentsMargins(20, 20, 20, 20); content_layout.setSpacing(16)
        self.api_group = QGroupBox(); api_layout = QVBoxLayout(self.api_group); api_layout.setContentsMargins(12, 12, 12, 12); api_layout.setSpacing(12)
        self.all_apis = QCheckBox(); self.all_apis.setChecked(True); self.all_apis.stateChanged.connect(self.toggle_apis); api_layout.addWidget(self.all_apis)
        api_layout.addWidget(RefinedDivider())
        self.api_checks = {};
        for num, data in DLL_REPLACEMENTS.items():
            check = QCheckBox(data['name']); check.setChecked(True); check.stateChanged.connect(self.on_api_change)
            self.api_checks[num] = check; api_layout.addWidget(check)
        api_layout.addStretch(); content_layout.addWidget(self.api_group)
        self.options_group = QGroupBox(); options_layout = QVBoxLayout(self.options_group); options_layout.setContentsMargins(12, 12, 12, 12); options_layout.setSpacing(8)
        self.backup = QCheckBox(); self.backup.setChecked(True); options_layout.addWidget(self.backup)
        self.overwrite = QCheckBox(); self.overwrite.setChecked(True); options_layout.addWidget(self.overwrite)
        content_layout.addWidget(self.options_group); content_layout.addStretch()
        scroll.setWidget(settings_content); settings_layout.addWidget(scroll, 1); return settings
    
    def _create_log_panel(self):
        log_panel = RefinedContainer("card"); log_layout = QVBoxLayout(log_panel); log_layout.setContentsMargins(0, 0, 0, 0); log_layout.setSpacing(0)
        header_widget = QWidget(); header_widget.setStyleSheet(f" background-color: {REFINED_PALETTE['bg_secondary']}; border-top-left-radius: 12px; border-top-right-radius: 12px; padding-bottom: 10px; ")
        header_layout = QHBoxLayout(header_widget); header_layout.setContentsMargins(20, 12, 20, 0); header_layout.setSpacing(12)
        self.log_title = QLabel(); self.log_title.setProperty("class", "h3"); header_layout.addWidget(self.log_title); header_layout.addStretch()
        self.clear_log_btn = QPushButton(); self.clear_log_btn.setProperty("variant", "ghost"); self.clear_log_btn.clicked.connect(self.clear_log); header_layout.addWidget(self.clear_log_btn)
        log_layout.addWidget(header_widget)
        self.log_text = QTextEdit(); self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet(f""" QTextEdit {{ padding: 20px; border: none; border-radius: 0; border-bottom-left-radius: 12px; border-bottom-right-radius: 12px; background-color: {REFINED_PALETTE['bg_tertiary']}; font-family: 'SF Mono', 'Monaco', 'Consolas', monospace; font-size: 12px; }} """)
        log_layout.addWidget(self.log_text, 1); return log_panel
        
    def _create_bottom(self, layout):
        bottom = QWidget(); bottom.setStyleSheet(f"background: {REFINED_PALETTE['bg_secondary']}; border-top: 1px solid {REFINED_PALETTE['border']};")
        bottom_layout = QVBoxLayout(bottom); bottom_layout.setContentsMargins(24, 16, 24, 16); bottom_layout.setSpacing(12)
        self.progress = QProgressBar(); self.progress.setTextVisible(False); self.progress.setFixedHeight(5); bottom_layout.addWidget(self.progress)
        btn_layout = QHBoxLayout(); btn_layout.addStretch()
        self.about_btn = QPushButton(); self.about_btn.setProperty("variant", "ghost"); self.about_btn.clicked.connect(self.show_about); btn_layout.addWidget(self.about_btn)
        btn_layout.addStretch(); bottom_layout.addLayout(btn_layout); layout.addWidget(bottom)
        
    def retranslate_ui(self):
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
        if args is None: args = []
        formatted_msg = self.translator.get(msg_key, *args)
        if not formatted_msg: self.log_text.append(""); return
        colors = {'info': REFINED_PALETTE['text_secondary'], 'success': REFINED_PALETTE['success'], 'warning': REFINED_PALETTE['warning'], 'error': REFINED_PALETTE['error']}
        time = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f'<span style="color: {REFINED_PALETTE["text_muted"]};">{time}</span> <span style="color: {colors.get(level, colors["info"])};">{formatted_msg}</span>')

    def show_task_error(self, title_key, message): QMessageBox.warning(self, self.translator.get(title_key), message)
        
    def add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, self.translator.get("dialog_select_pe_files"), "", self.translator.get("dialog_pe_files_filter"))
        if files: self.process_files(files)

    def add_folder(self):
        msg_box = QMessageBox(self); msg_box.setWindowTitle(self.translator.get("dialog_search_option")); msg_box.setText(self.translator.get("dialog_search_subfolders"))
        yes_button = msg_box.addButton(self.translator.get("dialog_yes_recursive"), QMessageBox.ButtonRole.YesRole)
        no_button = msg_box.addButton(self.translator.get("dialog_no_folder_only"), QMessageBox.ButtonRole.NoRole)
        cancel_button = msg_box.addButton(self.translator.get("dialog_cancel"), QMessageBox.ButtonRole.RejectRole); msg_box.exec()
        if msg_box.clickedButton() == cancel_button: return
        include_subfolders = (msg_box.clickedButton() == yes_button)
        folder = QFileDialog.getExistingDirectory(self, self.translator.get("dialog_select_folder"))
        if folder:
            self.log('log_scanning_folder', 'info', [folder, self.translator.get('log_with_subfolders') if include_subfolders else ''])
            dialog = RefinedFolderDialog(self, folder, include_subfolders)
            if dialog.exec() == QDialog.DialogCode.Accepted and (files := dialog.get_found_files()): self.process_files(files)

    def process_files(self, paths):
        new = [p for p in paths if not any(f['path'] == p for f in self.files)]
        if not new: self.log("log_all_files_added", "warning"); return
        self.progress.setRange(0, 0)
        worker = self.thread_manager.start_task(FileProcessorWorker, self.translator.get("task_analyzing_files"), new)
        if not worker: self.progress.setRange(0, 100); return
        worker.file_processed.connect(self.add_file_item); worker.finished.connect(self.files_added)

    def add_file_item(self, info):
        if self.empty_state.isVisible(): self.empty_state.hide(); self.files_container.show()
        item = SwipeableFileItem(info, self.translator); item.removed.connect(self.remove_file_with_animation)
        self.files.append(info); self.file_items[info['path']] = item
        self.files_layout.addWidget(item); self.update_stats()

    def files_added(self, added, errors):
        self.progress.setRange(0, 100); self.progress.setValue(0)
        if added: self.log("log_files_added", "success", [added])
        if errors: self.log("log_files_skipped", "warning", [errors])

    def remove_file_with_animation(self, path):
        if path in self.file_items: self.animate_card_removal(path)

    def animate_card_removal(self, path: str):
        if not (widget := self.file_items.get(path)): return
        anim_group = QParallelAnimationGroup(widget)
        slide_anim = QPropertyAnimation(widget, b"pos"); slide_anim.setDuration(300); slide_anim.setStartValue(widget.pos()); slide_anim.setEndValue(QPoint(widget.width() * -1, widget.pos().y())); slide_anim.setEasingCurve(QEasingCurve.Type.InCubic)
        shrink_anim = QPropertyAnimation(widget, b"maximumHeight"); shrink_anim.setDuration(250); shrink_anim.setStartValue(widget.height()); shrink_anim.setEndValue(0)
        anim_group.addAnimation(slide_anim); anim_group.addAnimation(shrink_anim)
        anim_group.finished.connect(lambda: self.finalize_removal(path, widget)); anim_group.start()

    def finalize_removal(self, path, item):
        self.files = [f for f in self.files if f['path'] != path]
        self.file_items.pop(path, None); item.deleteLater()
        if not self.files: self.empty_state.show(); self.files_container.hide()
        self.update_stats()

    def clear_all(self):
        if self.thread_manager.is_running():
            QMessageBox.warning(self, self.translator.get("dialog_op_in_progress"), self.translator.get("dialog_cannot_clear"))
            return
        if not self.files:
            QMessageBox.information(self, self.translator.get("dialog_list_empty"), self.translator.get("dialog_no_files_to_clear")); return
        if QMessageBox.question(self, self.translator.get("dialog_confirmation"), self.translator.get("dialog_clear_all_q")) == QMessageBox.StandardButton.Yes:
            for item in self.file_items.values(): item.deleteLater()
            self.files.clear(); self.file_items.clear()
            self.empty_state.show(); self.files_container.hide()
            self.update_stats(); self.log("log_list_cleared", "info")

    def clear_log(self): self.log_text.clear(); self.log("log_cleared", "info")
    def update_stats(self): self.files_count.setText(str(len(self.files)))
    def toggle_apis(self, state):
        for check in self.api_checks.values(): check.setChecked(bool(state))
    def on_api_change(self):
        all_checked = all(c.isChecked() for c in self.api_checks.values())
        self.all_apis.blockSignals(True); self.all_apis.setChecked(all_checked); self.all_apis.blockSignals(False)

    def on_main_action_click(self):
        if self.thread_manager.is_running():
            self.thread_manager.stop_current_task()
            self.main_action_btn.setText(self.translator.get("cancelling"))
            self.main_action_btn.setEnabled(False)
        else: self.start_patching()

    def set_ui_for_patching(self, is_patching: bool):
        if is_patching:
            self.main_action_btn.setText(self.translator.get("cancel"))
            self.main_action_btn.setEnabled(True)
            self.clear_btn.setEnabled(False)
            for item in self.file_items.values(): item.setEnabled(False)
        else:
            self.main_action_btn.setText(self.translator.get("start_patching"))
            self.main_action_btn.setEnabled(True)
            self.clear_btn.setEnabled(True)
            for item in self.file_items.values(): item.setEnabled(True)

    def start_patching(self):
        if not self.files: 
            QMessageBox.warning(self, self.translator.get("warning_title"), self.translator.get("warning_no_files"))
            return
        
        apis = [key for key, checkbox in self.api_checks.items() if checkbox.isChecked()]
        if self.all_apis.isChecked(): 
            apis = list(DLL_REPLACEMENTS.keys())
        if not apis: 
            QMessageBox.warning(self, self.translator.get("warning_title"), self.translator.get("warning_no_api"))
            return
        
        self.set_ui_for_patching(True)
        self.progress.setValue(0)
        
        worker = self.thread_manager.start_task(
            PatcherWorker,
            self.translator.get("task_patching_files"),
            list(self.files),
            apis,
            self.backup.isChecked(),
            self.overwrite.isChecked()
        )
        
        if not worker:
            self.set_ui_for_patching(False)
            return
        
        worker.log_message.connect(self.log)
        worker.progress_updated.connect(self.progress.setValue)
        worker.file_status_updated.connect(self.on_file_status_updated)
        worker.finished.connect(self.patching_done)


    def on_file_status_updated(self, path: str, status: str, text_key: str):
        """
        Оновлює статус файлу в UI.
        
        text_key може бути:
        - 'status_done' → Success → НЕ анімуємо (видаляється в patching_done)
        - 'status_skipped' → Skipped (оброблена) → НЕ анімуємо (видаляється в patching_done)
        - 'status_cancelled' → Cancelled (скасована) → НЕ анімуємо (залишається в списку)
        - 'status_no_changes' → No changes → НЕ анімуємо (видаляється в patching_done)
        - 'status_error' → Error → НЕ анімуємо (залишається в списку)
        """
        if widget := self.file_items.get(path):
            widget.update_status(status, self.translator.get(text_key))
            
            # ← НОВЕ: НЕ видаляємо файли під час обробки
            # Вони будуть видалені в patching_done
            # Це запобігає подвійному видаленню

    def patching_done(self, stats: Tuple[int, int, int], was_cancelled: bool, cancelled_file_index: int = None, total_files: int = None, remaining_files: int = None):
        """
        Обробляє завершення патчингу.
        """
        s, k, e = stats
        
        if total_files is None:
            total_files = cancelled_file_index + len(self.files) if cancelled_file_index else len(self.files)
        
        if remaining_files is None:
            remaining_files = total_files - cancelled_file_index if cancelled_file_index is not None else 0
        
        # ================================================================
        # PARTE 0: Скидаємо UI стан
        # ================================================================
        self.progress.setValue(0)
        self.set_ui_for_patching(False)
        
        # ================================================================
        # PARTE 1: Якщо було скасування - видаляємо обробленні файли
        # ================================================================
        if was_cancelled and cancelled_file_index is not None:
            # ← ВАЖЛИВО: Видаляємо ВСІХ файлів від 0 до cancelled_file_index
            # включаючи ті що мають статус 'cancelled'
            paths_to_remove = [self.files[i]['path'] for i in range(cancelled_file_index)]
            
            for path in paths_to_remove:
                if path in self.file_items:
                    widget = self.file_items[path]
                    # Видаляємо з layout
                    self.files_layout.removeWidget(widget)
                    widget.deleteLater()
                    self.file_items.pop(path, None)
            
            # Оновлюємо список файлів (залишаємо тільки необроблені)
            self.files = self.files[cancelled_file_index:]
            
            # Перевіряємо чи список пустий
            if not self.files:
                self.files_container.hide()
                self.empty_state.show()
            
            # Оновлюємо статистику
            self.update_stats()
            
            # Логуємо з правильною кількістю залишених файлів
            self.log("log_patched_files_removed", "info", [cancelled_file_index, total_files, remaining_files])
        else:
            # Якщо не було скасування, але всі файли обробленні
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
        
        # ================================================================
        # PARTE 2: Формуємо повідомлення про результати
        # ================================================================
        summary_parts = []
        
        if s > 0:
            summary_parts.append(self.translator.get("summary_patched", s))
        if k > 0:
            summary_parts.append(self.translator.get("summary_skipped", k))
        if e > 0:
            summary_parts.append(self.translator.get("summary_errors", e))
        
        if was_cancelled:
            summary_text = self.translator.get("summary_cancelled_prefix") + ", ".join(summary_parts)
        else:
            summary_text = (self.translator.get("summary_finished_prefix") + ", ".join(summary_parts)) if summary_parts else self.translator.get("summary_no_ops")
        
        level = "success" if e == 0 and s > 0 and not was_cancelled else "warning"
        self.log(summary_text, level, [])
        
        # ================================================================
        # PARTE 3: Показуємо діалог з затримкою
        # ================================================================
        if not was_cancelled:
            QMessageBox.information(
                self,
                self.translator.get("dialog_completed_title"),
                summary_text
            )
        else:
            self.log("log_operation_stopped", "info")
            
            def show_cancel_dialog():
                if remaining_files > 0:
                    cancel_message = self.translator.get("dialog_cancel_remaining", remaining_files)
                    QMessageBox.information(
                        self,
                        self.translator.get("dialog_cancelled_title"),
                        cancel_message
                    )
                else:
                    QMessageBox.information(
                        self,
                        self.translator.get("dialog_cancelled_title"),
                        "Патчинг скасовано. Список файлів очищено."
                    )
            
            QTimer.singleShot(500, show_cancel_dialog)
        
    def show_about(self):
        dialog = AboutDialog(self, self.translator)
        dialog.exec()

# =============================================================================
# 6. ENTRY POINT
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
        else: sys.exit(0)
    
    translator = TranslationManager(lang_code)

    qt_translator = QTranslator()
    if lang_code != "en":
        translations_path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
        if qt_translator.load(f"qt_{lang_code}.qm", translations_path):
            app.installTranslator(qt_translator)

    window = PEPatcherGUI(translator)
    window.show()
    sys.exit(app.exec())
