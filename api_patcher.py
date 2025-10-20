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
from typing import List

import pefile
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTextEdit, QFrame, QFileDialog, QMessageBox, QCheckBox, QDialog,
    QProgressBar, QScrollArea, QListWidget, QGraphicsDropShadowEffect,
    QGridLayout, QGroupBox, QSizePolicy, QSplitter
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
    print("Створіть файл config.py з коректними налаштуваннями DLL_REPLACEMENTS")
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

APP_TITLE = "PE API Replacer"
APP_VERSION = "1.0.2"

def sanitize_filename(filename: str) -> str:
    """Видаляє або замінює невалідні для Windows символи з імені файлу."""
    return re.sub(r'[\\/*?:"<>|]', '_', filename)

# =============================================================================
# 1. REFINED DARK THEME
# =============================================================================

REFINED_PALETTE = {
    'bg_primary': '#0E0E10', 'bg_secondary': '#141417', 'bg_tertiary': '#1A1A1E',
    'bg_elevated': '#202024', 'bg_overlay': '#26262B', 'accent': '#8B7FB8',
    'accent_hover': '#9D91C7', 'accent_muted': 'rgba(139, 127, 184, 0.15)',
    'accent_subtle': 'rgba(139, 127, 184, 0.08)', 'text': '#E8E6F0',
    'text_secondary': '#A8A5B8', 'text_muted': '#6B6878', 'text_disabled': '#48465A',
    'success': '#6BCF7F', 'warning': '#E4A853', 'error': '#CF6679', 'info': '#64B5F6',
    'border': 'rgba(255, 255, 255, 0.04)', 'border_hover': 'rgba(139, 127, 184, 0.2)',
    'shadow': 'rgba(0, 0, 0, 0.4)', 'glow': 'rgba(139, 127, 184, 0.05)',
}

# Стиль для стандартних кнопок
STANDARD_BUTTON_STYLE = f"""
    QPushButton {{
        font-size: 13px; 
        font-weight: 500; 
        letter-spacing: 0.5px; 
        padding: 11px 20px;
        border-radius: 8px; 
        background-color: {REFINED_PALETTE['bg_tertiary']}; 
        color: {REFINED_PALETTE['text_secondary']};
        border: none;
    }}
    QPushButton:hover {{
        background-color: {REFINED_PALETTE['bg_overlay']}; 
        color: {REFINED_PALETTE['text']};
    }}
    QPushButton:disabled {{
        background-color: {REFINED_PALETTE['bg_overlay']}; 
        color: {REFINED_PALETTE['text_muted']};
    }}
"""

REFINED_STYLESHEET = f"""
    * {{ margin: 0; padding: 0; border: none; outline: none; }}
    QWidget {{
        color: {REFINED_PALETTE['text']}; font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', system-ui, sans-serif;
        font-size: 13px; font-weight: 400; letter-spacing: 0.3px;
    }}
    QMainWindow {{ background-color: {REFINED_PALETTE['bg_primary']}; }}
    #RefinedCard {{ background-color: {REFINED_PALETTE['bg_secondary']}; border-radius: 12px; }}
    #ElevatedCard {{ background-color: {REFINED_PALETTE['bg_elevated']}; border-radius: 16px; border: 1px solid {REFINED_PALETTE['border']}; }}
    #AppHeader {{ background-color: {REFINED_PALETTE['bg_secondary']}; border-bottom: 1px solid {REFINED_PALETTE['border']}; padding: 28px 32px; }}
    QPushButton {{
        font-size: 13px; font-weight: 500; letter-spacing: 0.5px; padding: 11px 20px;
        border-radius: 8px; background-color: {REFINED_PALETTE['bg_tertiary']}; color: {REFINED_PALETTE['text_secondary']};
    }}
    QPushButton:hover {{ background-color: {REFINED_PALETTE['bg_overlay']}; color: {REFINED_PALETTE['text']}; }}
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
    QLabel[class="subtitle"] {{ font-size: 14px; font-weight: 500; color: {REFINED_PALETTE['text_secondary']}; }}
    QLabel[class="caption"] {{ font-size: 11px; font-weight: 500; letter-spacing: 0.5px; color: {REFINED_PALETTE['text_muted']}; text-transform: uppercase; }}
    QLabel[class="mono"] {{ font-family: 'SF Mono', 'Monaco', 'Consolas', monospace; font-size: 12px; color: {REFINED_PALETTE['text_secondary']}; }}
    #FileItem {{ background-color: {REFINED_PALETTE['bg_tertiary']}; border-radius: 0; padding: 14px 16px; border: 1px solid transparent; }}
    #FileItem:hover {{ background-color: {REFINED_PALETTE['bg_overlay']}; border-color: {REFINED_PALETTE['border_hover']}; }}
    QGroupBox {{
        background-color: transparent; border: 1px solid {REFINED_PALETTE['border']}; border-radius: 8px;
        padding-top: 16px; font-size: 11px; font-weight: 600;
        letter-spacing: 0.5px; text-transform: uppercase;
    }}
    QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 8px; color: {REFINED_PALETTE['text_muted']}; background-color: {REFINED_PALETTE['bg_secondary']}; text-align: center; }}
    QTextEdit {{
        background-color: {REFINED_PALETTE['bg_tertiary']}; border: 1px solid {REFINED_PALETTE['border']}; border-radius: 8px;
        padding: 12px; font-family: 'SF Mono', 'Monaco', 'Consolas', monospace; font-size: 12px;
        line-height: 1.6; color: {REFINED_PALETTE['text_secondary']};
    }}
    QProgressBar {{ 
        background-color: {REFINED_PALETTE['bg_overlay']}; 
        height: 5px;
        border-radius: 5px; 
        border: none;
        text-align: center;
        margin: 0px;
        padding: 0px;
    }}
    QProgressBar::chunk {{ 
        background-color: {REFINED_PALETTE['accent']}; 
        border-radius: 5px;
        margin: 0px;
        padding: 0px;
    }}

 /* Вертикальний скролбар з відступами */
    QScrollArea QScrollBar:vertical {{ 
        background-color: transparent; 
        width: 16px;
        margin: 20px 4px 20px 4px;
    }}
    QScrollBar:vertical {{ 
        background-color: {REFINED_PALETTE['bg_overlay']}; 
        width: 12px;
        border-radius: 6px;
        margin: 4px 2px;
    }}
    QScrollBar::handle:vertical {{ 
        background-color: {REFINED_PALETTE['text_muted']}; 
        border-radius: 6px;
        min-height: 50px;
        margin: 2px;
        width: 12px;
    }}
    QScrollBar::handle:vertical:hover {{ 
        background-color: {REFINED_PALETTE['accent']}; 
        width: 12px;  /* І ТУТ */
    }}
    QScrollBar::handle:vertical:pressed {{ 
        background-color: {REFINED_PALETTE['accent_hover']}; 
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical, 
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ 
        height: 0; 
        background: transparent;
    }}

    /* Горизонтальний скролбар з відступами */
    QScrollArea QScrollBar:horizontal {{ 
        background-color: transparent; 
        height: 16px;
        margin: 4px 20px 4px 20px;
    }}
    QScrollBar:horizontal {{ 
        background-color: {REFINED_PALETTE['bg_overlay']}; 
        height: 12px;
        border-radius: 6px;
        margin: 2px 4px;
    }}
    QScrollBar::handle:horizontal {{ 
        background-color: {REFINED_PALETTE['text_muted']}; 
        border-radius: 6px;
        min-width: 50px;
        margin: 2px;
        height: 12px;
    }}
    QScrollBar::handle:horizontal:hover {{ 
        background-color: {REFINED_PALETTE['accent']}; 
        height: 12px;
    }}
    QScrollBar::handle:horizontal:pressed {{ 
        background-color: {REFINED_PALETTE['accent_hover']}; 
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal, 
    QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ 
        width: 0; 
        background: transparent;
    }}
    
    QAbstractScrollArea::corner {{
        background-color: transparent;
    }}
    
    #Divider {{ background-color: {REFINED_PALETTE['border']}; height: 1px; margin: 10px 0; }}
    #EmptyState {{ 
        background-color: {REFINED_PALETTE['bg_tertiary']}; 
        border: 1px dashed {REFINED_PALETTE['border']}; 
        border-radius: 12px; 
        min-height: 200px;
    }}
    #EmptyStateContainer {{
        background-color: transparent;
        border: none;
    }}
    QDialog, QMessageBox {{ background-color: {REFINED_PALETTE['bg_secondary']}; }}
    QMessageBox QLabel {{ color: {REFINED_PALETTE['text']}; }}
"""

def create_subtle_shadow():
    shadow = QGraphicsDropShadowEffect()
    shadow.setBlurRadius(16); shadow.setXOffset(0); shadow.setYOffset(2)
    shadow.setColor(QColor(0, 0, 0, 80))
    return shadow

# =============================================================================
# 2. БЕКЕНД ЛОГІКА
# =============================================================================
class PermissionsManager:
    def __init__(self, file_path: str, log_callback=None):
        self.file_path = file_path
        self.log_callback = log_callback
        self.original_permissions = None
        self.permissions_were_changed = False
    
    def log(self, message, level="info"):
        if self.log_callback:
            self.log_callback(message, level)
    
    def __enter__(self):
        try:
            # Отримуємо поточні права доступу
            self.original_permissions = os.stat(self.file_path).st_mode
            
            # Перевіряємо, чи файл read-only
            is_readonly = not (self.original_permissions & stat.S_IWUSR)
            
            if is_readonly:
                self.log(f"⚠️ Файл '{os.path.basename(self.file_path)}' доступний тільки для читання", "warning")
                self.log(f"   Спроба змінити права доступу...", "info")
                
                # Додаємо право на запис для власника
                new_permissions = self.original_permissions | stat.S_IWUSR
                os.chmod(self.file_path, new_permissions)
                
                self.log(f"✅ Права змінено на read/write", "success")
                self.permissions_were_changed = True
            else:
                self.log(f"✅ Файл доступний для запису", "success")
            
            return self
        
        except Exception as e:
            self.log(f"❌ Помилка при зміні прав доступу: {e}", "error")
            raise PermissionError(f"Не вдалося змінити права доступу: {e}")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Відновлюємо оригінальні права, якщо вони були змінені
        if self.permissions_were_changed and self.original_permissions:
            try:
                self.log("🔄 Відновлення оригінальних прав доступу...", "info")
                os.chmod(self.file_path, self.original_permissions)
                self.log("✅ Права відновлено (read-only)", "success")
            except Exception as e:
                self.log(f"❌ Помилка при відновленні прав: {e}", "error")

class UniversalPEPatcher:
    def __init__(self, file_path: str, selected_apis: List[int] = None, log_callback=None):
        self.file_path, self.log_callback, self.pe, self.data = file_path, log_callback, None, None
        apis_keys = list(DLL_REPLACEMENTS.keys())
        self.apis_to_patch = apis_keys if selected_apis is None or 0 in selected_apis else [api for api in selected_apis if api in apis_keys]
        self.active_replacements = {k: v for api_num in self.apis_to_patch for k, v in DLL_REPLACEMENTS[api_num]['replacements'].items()}
    
    def log(self, message, level="info"):
        if self.log_callback: self.log_callback(message, level)
    
    def load_file(self) -> bool:
        try:
            with open(self.file_path, 'rb') as f: self.data = bytearray(f.read())
            self.pe = pefile.PE(data=self.data)
            return True
        except Exception as e:
            self.log(f"❌ Помилка завантаження: {e}", "error"); return False
    
    def check_if_patchable(self) -> int:
        """Перевіряє кількість патчабельних імпортів"""
        if not self.data and not self.load_file(): return 0
        count = 0
        found_details = []
        
        # Перевіряємо IAT
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', 'ignore').upper() if entry.dll else ""
                for orig_dll in self.active_replacements.keys():
                    if dll_name == orig_dll.decode('utf-8').upper():
                        count += 1
                        found_details.append(('IAT', dll_name))
                        break
        
        # Перевіряємо Hex
        for old_bytes in self.active_replacements.keys():
            hex_count = self.data.count(old_bytes)
            if hex_count > 0:
                count += hex_count
                dll_str = old_bytes.decode('utf-8', 'ignore')
                found_details.append(('HEX', f"{dll_str} ({hex_count}x)"))
        
        # Логуємо знайдені деталі при первій перевірці
        if found_details:
            self.log("📊 Деталі перед патчингом:", "info")
            for src, detail in found_details:
                self.log(f"   [{src}] {detail}", "info")
        
        return count
    
    def patch_all(self) -> int:
        if not self.data and not self.load_file(): return 0
        self.log(f"🔄 Патчинг {os.path.basename(self.file_path)}...", "info")
        count = 0
        
        # Словник для статистики
        iat_count = 0
        hex_details = {}
        
        # ============================================================
        # 1. IAT ПАТЧИНГ
        # ============================================================
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                if not entry.dll: continue
                dll_name = entry.dll.decode('utf-8', 'ignore')
                for orig, repl in self.active_replacements.items():
                    if dll_name.upper() == orig.decode('utf-8').upper():
                        offset = self.pe.get_offset_from_rva(entry.struct.Name)
                        if offset and len(repl) <= len(entry.dll):
                            self.data[offset:offset + len(repl)] = repl
                            if len(repl) < len(entry.dll): 
                                self.data[offset + len(repl):offset + len(entry.dll)] = b'\x00' * (len(entry.dll) - len(repl))
                            self.log(f"   ✅ [IAT] {dll_name} → {repl.decode('utf-8')}", "success")
                            count += 1
                            iat_count += 1
                        else: 
                            self.log(f"   ⚠️  [IAT] Пропущено {dll_name}, заміна занадто довга.", "warning")
                        break
        
        # ============================================================
        # 2. HEX ПАТЧИНГ
        # ============================================================
        for old, new in self.active_replacements.items():
            if len(old) != len(new):
                self.log(f"   ⚠️  [HEX] Пропуск {old.decode('utf-8', 'ignore')}, довжина не збігається.", "warning")
                continue
            
            start_index, local_count = 0, 0
            dll_str = old.decode('utf-8', 'ignore')
            
            while (index := self.data.find(old, start_index)) != -1:
                self.data[index:index + len(old)] = new
                start_index = index + len(old)
                count += 1
                local_count += 1
            
            if local_count > 0:
                new_str = new.decode('utf-8', 'ignore')
                self.log(f"   ✅ [HEX] {dll_str} → {new_str} ({local_count}x)", "success")
                hex_details[dll_str] = local_count
        
        # Виводимо финальну статистику
        self.log("", "info")  # Пустий рядок
        self.log(f"📈 Фінальна статистика патчингу:", "info")
        self.log(f"   [IAT] Змін: {iat_count}", "info")
        for dll, cnt in hex_details.items():
            self.log(f"   [HEX] {dll}: {cnt} змін", "info")
        self.log(f"   ─────────────────────", "info")
        self.log(f"   ВСЬОГО: {count} змін", "success")
        
        return count
    
    def save(self, output_path: str) -> bool:
        try:
            with open(output_path, 'wb') as f: f.write(self.data)
            try:
                pe_new = pefile.PE(output_path)
                pe_new.OPTIONAL_HEADER.CheckSum = pe_new.generate_checksum()
                pe_new.write(output_path); pe_new.close()
            except Exception as checksum_err:
                self.log(f"⚠️ Не вдалося оновити контрольну суму: {checksum_err}", "warning")
            self.log(f"💾 Збережено: {os.path.basename(output_path)}", "success"); return True
        except Exception as e:
            self.log(f"❌ Помилка збереження: {e}", "error"); return False
    
    def close(self):
        if self.pe: self.pe.close(); self.pe = None
        self.data = None

class FileProcessorWorker(QObject):
    file_processed = pyqtSignal(dict); finished = pyqtSignal(int, int)
    def __init__(self, file_paths): super().__init__(); self.file_paths = file_paths
    def run(self):
        added, error = 0, 0
        for path in self.file_paths:
            try:
                with open(path, 'rb') as f:
                    if f.read(2) != b'MZ': error += 1; continue
                info = {'path': path, 'size': os.path.getsize(path), 'type': 'PE', 'arch': 'x86', 'status': 'ready', 'status_text': 'Готово'}
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
    file_found = pyqtSignal(str); scan_complete = pyqtSignal(list, list)
    def __init__(self, folder_path, include_subfolders):
        super().__init__(); self.folder_path, self.include_subfolders, self.is_cancelled = Path(folder_path), include_subfolders, False
    def run(self):
        try:
            found, skipped, exts = [], set(), {'.exe', '.dll', '.vst3', '.vst', '.sys', '.ocx', '.ax'}
            skip_folders = {'patched', 'backup'}
            pattern = '**/*' if self.include_subfolders else '*'
            for p in self.folder_path.glob(pattern):
                if self.is_cancelled: break
                if p.is_dir() or p.suffix.lower() not in exts: continue
                if not skip_folders.isdisjoint({part.lower() for part in p.parts}): skipped.add("Patched/Backup"); continue
                try:
                    with p.open('rb') as f:
                        if f.read(2) == b'MZ': found.append(str(p)); self.file_found.emit(p.name)
                except (IOError, PermissionError): continue
            if not self.is_cancelled: self.scan_complete.emit(sorted(list(set(found))), sorted(list(skipped)))
        except Exception: pass
    def cancel(self): self.is_cancelled = True

class PatcherWorker(QObject):
    log_message = pyqtSignal(str, str)
    file_status_updated = pyqtSignal(str, str, str)
    progress_updated = pyqtSignal(int)
    finished = pyqtSignal(str, str, list, list)  # Додаємо списки директорій для видалення
    
    def __init__(self, files, selected_apis, backup, overwrite):
        super().__init__()
        self.files = files
        self.selected_apis = selected_apis
        self.backup_var = backup
        self.overwrite_var = overwrite
    
    def run(self):
        s, e, k, total = 0, 0, 0, len(self.files)
        patched_dirs = set()
        backup_dirs = set()
        
        for i, info in enumerate(self.files):
            path, name = info['path'], sanitize_filename(os.path.basename(info['path']))
            self.log_message.emit("", "")
            self.log_message.emit(f"[{i+1}/{total}] Обробка: {os.path.basename(path)}", "info")
            original_file_data = None
            
            try:
                with open(path, 'rb') as f:
                    original_file_data = f.read()
            except Exception as read_err:
                self.log_message.emit(f"❌ Помилка читання: {read_err}", "error")
                e += 1
                self.file_status_updated.emit(path, 'error', 'Помилка')
                self.progress_updated.emit(int((i + 1) / total * 100))
                continue
            
            patcher = None
            try:
                with PermissionsManager(path, log_callback=lambda m, l: self.log_message.emit(f"   {m}", l)):
                    patcher = UniversalPEPatcher(path, self.selected_apis, log_callback=lambda m, l: self.log_message.emit(f"   {m}", l))
                    
                    if not patcher.load_file() or patcher.check_if_patchable() == 0:
                        self.log_message.emit("⚠️ Немає що патчити", "warning")
                        k += 1
                        self.file_status_updated.emit(path, 'warning', 'Пропущено')
                        self.progress_updated.emit(int((i + 1) / total * 100))
                        continue
                    
                    p_count = patcher.patch_all()
                    
                    if p_count > 0:
                        # Обробка бекапів
                        if self.backup_var:
                            b_dir = os.path.join(os.path.dirname(path), 'backup')
                            b_name = name
                            os.makedirs(b_dir, exist_ok=True)
                            b_path, cnt = os.path.join(b_dir, b_name), 1
                            base, ext = os.path.splitext(b_name)
                            while os.path.exists(b_path):
                                b_path = os.path.join(b_dir, f"{base}.backup{cnt}{ext}")
                                cnt += 1
                            with open(b_path, 'wb') as bf:
                                bf.write(original_file_data)
                            self.log_message.emit(f"📁 Бекап збережено", "success")
                        else:
                            b_dir = os.path.join(os.path.dirname(path), 'backup')
                            if os.path.exists(b_dir):
                                backup_dirs.add(b_dir)
                        
                        p_dir = os.path.join(os.path.dirname(path), 'patched')
                        i_path = os.path.join(p_dir, name)
                        os.makedirs(p_dir, exist_ok=True)
                        
                        if self.overwrite_var:
                            patched_dirs.add(p_dir)
                        
                        if not patcher.save(i_path):
                            self.log_message.emit("❌ Помилка збереження", "error")
                            e += 1
                            self.file_status_updated.emit(path, 'error', 'Помилка')
                            self.progress_updated.emit(int((i + 1) / total * 100))
                            continue
                        
                        if self.overwrite_var:
                            shutil.move(i_path, path)
                            self.log_message.emit(f"🔄 Оригінал замінено", "info")
                        
                        self.log_message.emit(f"✅ Пропатчено: {p_count} змін", "success")
                        s += 1
                        self.file_status_updated.emit(path, 'success', 'Готово')
                        self.progress_updated.emit(int((i + 1) / total * 100))
                    else:
                        self.log_message.emit("⚠️ Змін не внесено", "warning")
                        k += 1
                        self.file_status_updated.emit(path, 'warning', 'Без змін')
                        self.progress_updated.emit(int((i + 1) / total * 100))
            
            except Exception as err:
                self.log_message.emit(f"❌ Помилка: {err}", "error")
                e += 1
                self.file_status_updated.emit(path, 'error', 'Помилка')
                self.progress_updated.emit(int((i + 1) / total * 100))
            
            finally:
                if patcher:
                    patcher.close()
            
            self.progress_updated.emit(int((i + 1) / total * 100))
        
        # Видаляємо непотрібні папки після завершення всіх патчингів
        self.log_message.emit("", "info")
        
        # Видалення папок patched (якщо перезаписуються оригінали)
        if self.overwrite_var and patched_dirs:
            self.log_message.emit("🗑️ Видалення папок patched...", "info")
            for patched_dir in patched_dirs:
                try:
                    if os.path.exists(patched_dir) and not os.listdir(patched_dir):
                        shutil.rmtree(patched_dir)
                        # self.log_message.emit(f"   ✅ Видалено: {patched_dir}", "success")
                    elif os.path.exists(patched_dir):
                        self.log_message.emit(f"   ⚠️ Папка не порожня: {patched_dir}", "warning")
                except Exception as err:
                    self.log_message.emit(f"   ❌ Помилка видалення: {err}", "error")
        
        # Видалення папок backup (якщо бекапи вимкнені)
        if not self.backup_var and backup_dirs:
            self.log_message.emit("🗑️ Видалення папок backup...", "info")
            for backup_dir in backup_dirs:
                try:
                    if os.path.exists(backup_dir) and not os.listdir(backup_dir):
                        shutil.rmtree(backup_dir)
                        # self.log_message.emit(f"   ✅ Видалено: {backup_dir}", "success")
                    elif os.path.exists(backup_dir):
                        self.log_message.emit(f"   ⚠️ Папка не порожня: {backup_dir}", "warning")
                except Exception as err:
                    self.log_message.emit(f"   ❌ Помилка видалення: {err}", "error")
        
        summary = []
        if s > 0:
            summary.append(f"{s} пропатчено")
        if k > 0:
            summary.append(f"{k} пропущено")
        if e > 0:
            summary.append(f"{e} помилок")
        
        result = "Завершено: " + ", ".join(summary) if summary else "Операцій не виконано"
        level = "success" if e == 0 and s > 0 else "error" if e > 0 else "warning"
        
        self.finished.emit(result, level, list(patched_dirs), list(backup_dirs))

# =============================================================================
# 3. REFINED WIDGETS
# =============================================================================

class RefinedContainer(QWidget):
    def __init__(self, container_type="card", parent=None):
        super().__init__(parent)
        types = {"card": "RefinedCard", "elevated": "ElevatedCard"}
        self.setObjectName(types.get(container_type, "RefinedCard"))
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        if container_type == "elevated":
            self.setGraphicsEffect(create_subtle_shadow())

class SwipeableFileItem(QWidget):
    removed = pyqtSignal(str)
    swiped = pyqtSignal(str)
    
    def __init__(self, file_info):
        super().__init__()
        self.file_info = file_info
        self.start_pos = None
        self.current_pos = 0
        self.swipe_threshold = 60
        self.is_swiped = False
        
        # Головний контейнер з роздільником
        wrapper_layout = QVBoxLayout(self)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(0)
        
        # Контейнер для файлу
        file_widget = QWidget()
        file_widget.setObjectName("FileItem")
        file_widget.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        file_widget.setFixedHeight(56)
        self.file_widget = file_widget
        
        # Головний контейнер для вмісту файлу
        main_layout = QHBoxLayout(file_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Контейнер для вмісту
        self.content_widget = QWidget()
        self.content_widget.setStyleSheet("background: transparent;")
        content_layout = QHBoxLayout(self.content_widget)
        content_layout.setContentsMargins(16, 0, 16, 0)
        content_layout.setSpacing(12)
        
        # Інформація про файл
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)
        info_layout.setContentsMargins(0, 0, 0, 0)
        
        name = QLabel(os.path.basename(file_info['path']))
        name.setProperty("class", "subtitle")
        name.setStyleSheet(f"color: {REFINED_PALETTE['text']};")
        info_layout.addWidget(name)
        
        details = QLabel(f"{file_info['type']} · {self._format_size(file_info['size'])} · {file_info['arch']}")
        details.setProperty("class", "caption")
        info_layout.addWidget(details)
        
        content_layout.addLayout(info_layout, 1)
        
        # Статус
        self.status_label = QLabel(file_info.get('status_text', 'Готово'))
        self.status_label.setProperty("class", "caption")
        content_layout.addWidget(self.status_label)
        
        # Кнопка видалення (хрестик)
        remove_btn = QPushButton("×")
        remove_btn.setProperty("variant", "ghost")
        remove_btn.setFixedSize(24, 24)
        remove_btn.setStyleSheet("""
            QPushButton {
                font-size: 18px; 
                padding: 0; 
                border-radius: 4px; 
                color: #6B6878;
            } 
            QPushButton:hover {
                color: #CF6679; 
                background-color: rgba(207, 102, 121, 0.1);
            }
        """)
        remove_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        remove_btn.clicked.connect(lambda: self.removed.emit(self.file_info['path']))
        content_layout.addWidget(remove_btn)
        
        # Іконка видалення (з'являється при свайпі)
        self.delete_icon = QLabel("🗑️")
        self.delete_icon.setProperty("class", "caption")
        self.delete_icon.setStyleSheet(f"color: {REFINED_PALETTE['error']}; padding: 0 16px;")
        self.delete_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.delete_icon.hide()
        
        main_layout.addWidget(self.content_widget)
        main_layout.addWidget(self.delete_icon)
        
        # Анімація
        self.animation = QPropertyAnimation(self.content_widget, b"pos")
        self.animation.setDuration(200)
        self.animation.finished.connect(self.on_animation_finished)
        
        # Додаємо файл до wrapper
        wrapper_layout.addWidget(file_widget)
        
        # Роздільник
        divider = QFrame()
        divider.setObjectName("Divider")
        divider.setFixedHeight(1)
        divider.setStyleSheet(f"background-color: {REFINED_PALETTE['border']}; margin: 0;")
        wrapper_layout.addWidget(divider)
    
    def _format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f}{unit}"
            size /= 1024.0
        return f"{size:.1f}TB"
    
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.start_pos = event.pos()
    
    def mouseMoveEvent(self, event):
        if self.start_pos is not None and event.buttons() & Qt.MouseButton.LeftButton:
            delta = event.pos().x() - self.start_pos.x()
            
            # Обмежуємо свайп тільки вліво (від'ємні значення)
            if delta < 0:
                self.current_pos = max(delta, -self.swipe_threshold)
                self.content_widget.move(self.current_pos, 0)
                
                # Показуємо іконку видалення при достатньому свайпі
                if abs(self.current_pos) > self.swipe_threshold * 0.7:
                    self.delete_icon.show()
                else:
                    self.delete_icon.hide()
    
    def mouseReleaseEvent(self, event):
        if self.start_pos is not None:
            # Якщо свайпнули достатньо далеко - запускаємо анімацію видалення
            if abs(self.current_pos) > self.swipe_threshold * 0.8:
                self.is_swiped = True
                self.animation.setStartValue(self.content_widget.pos())
                self.animation.setEndValue(QPoint(-self.width(), 0))
                self.animation.start()
            else:
                # Повертаємо на місце
                self.animation.setStartValue(self.content_widget.pos())
                self.animation.setEndValue(QPoint(0, 0))
                self.animation.start()
                self.delete_icon.hide()
        
        self.start_pos = None
    
    def on_animation_finished(self):
        if self.is_swiped:
            self.removed.emit(self.file_info['path'])
    
    def update_status(self, status: str, text: str):
        self.status_label.setText(text)
        
        # Змінюємо колір статусу
        colors = {
            'success': REFINED_PALETTE['success'],
            'warning': REFINED_PALETTE['warning'], 
            'error': REFINED_PALETTE['error'],
            'ready': REFINED_PALETTE['text_muted']
        }
        color = colors.get(status, REFINED_PALETTE['text_muted'])
        self.status_label.setStyleSheet(f"color: {color};")

class RefinedFolderDialog(QDialog):
    def __init__(self, parent, folder_path, include_subfolders):
        super().__init__(parent)
        self.found_files = []
        self.setWindowTitle("Сканування папки"); self.setFixedSize(600, 500); self.setModal(True); self.setStyleSheet(REFINED_STYLESHEET)
        layout = QVBoxLayout(self); layout.setContentsMargins(24, 24, 24, 24); layout.setSpacing(20)
        header = QLabel("Сканування папки"); header.setProperty("class", "h3"); layout.addWidget(header)
        path_label = QLabel(folder_path if len(folder_path) <= 60 else "..." + folder_path[-57:]); path_label.setProperty("class", "mono"); layout.addWidget(path_label)
        self.status_label = QLabel("Пошук..."); layout.addWidget(self.status_label)
        self.progress_bar = QProgressBar(); self.progress_bar.setRange(0, 0); self.progress_bar.setTextVisible(False); layout.addWidget(self.progress_bar)
        self.files_list = QListWidget(); layout.addWidget(self.files_list, 1)
        
        # Інформаційна панель для пропущених папок
        self.info_container = QWidget()
        self.info_container.setStyleSheet(f"background-color: {REFINED_PALETTE['bg_tertiary']}; border-radius: 8px; padding: 12px;")
        info_layout = QVBoxLayout(self.info_container)
        info_layout.setContentsMargins(12, 12, 12, 12)
        info_layout.setSpacing(6)
        
        self.skipped_label = QLabel()
        self.skipped_label.setProperty("class", "caption")
        self.skipped_label.setStyleSheet(f"color: {REFINED_PALETTE['text_muted']};")
        self.skipped_label.setWordWrap(True)
        info_layout.addWidget(self.skipped_label)
        
        self.info_container.hide()  # Ховаємо спочатку
        layout.addWidget(self.info_container)
        
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)
        
        # Кнопка скасування (спочатку центрована)
        self.cancel_btn = QPushButton("Скасувати")
        self.cancel_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
        self.cancel_btn.clicked.connect(self.reject)
        
        # Додаємо кнопку по центру
        btn_layout.addStretch()
        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        self.thread = QThread(); self.worker = FolderScannerWorker(folder_path, include_subfolders); self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run); self.worker.scan_complete.connect(self.on_complete); self.worker.file_found.connect(self.files_list.addItem)
        self.finished.connect(self.thread.quit); self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()
    
    def on_complete(self, found, skipped):
        self.found_files = found; self.progress_bar.setRange(0, 100); self.progress_bar.setValue(100)
        
        # Показуємо інформацію про пропущені папки
        if skipped:
            skipped_text = "ℹ️ Пропущено папки: " + ", ".join(skipped)
            self.skipped_label.setText(skipped_text)
            self.info_container.show()
        
        if found:
            self.status_label.setText(f"Знайдено {len(found)} файлів")
            
            # Отримуємо layout кнопок
            btn_layout = self.layout().itemAt(self.layout().count() - 1)
            
            # Очищаємо старі кнопки
            while btn_layout.count():
                item = btn_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            
            # Створюємо нові кнопки з правильним вирівнюванням
            btn_layout.addStretch()
            
            add_btn = QPushButton(f"Додати {len(found)} файлів")
            add_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
            add_btn.clicked.connect(self.accept)
            btn_layout.addWidget(add_btn)
            
            close_btn = QPushButton("Закрити")
            close_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
            close_btn.clicked.connect(self.reject)
            btn_layout.addWidget(close_btn)
            
            btn_layout.addStretch()
        else:
            self.status_label.setText("PE файлів не знайдено")
            self.cancel_btn.setText("Закрити")
    
    def get_found_files(self): return self.found_files

# Custom Splitter Widget for better spacing
class RefinedSplitter(QSplitter):
    def __init__(self, orientation, parent=None):
        super().__init__(orientation, parent)
        self.setHandleWidth(20)  # Збільшуємо область для захоплення
        self.setStyleSheet("""
            QSplitter {
                background-color: transparent;
            }
        """)
        
class RefinedDivider(QFrame):
    """Роздільник для групування елементів у GroupBox - ненав'язливий і тонкий"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.HLine)
        self.setFrameShadow(QFrame.Shadow.Plain)
        self.setLineWidth(1)
        self.setFixedHeight(1)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: rgba(139, 127, 184, 0.15);
                margin-left: 0px;
                margin-right: 0px;
                margin-top: 6px;
                margin-bottom: 6px;
                border: none;
            }}
        """)

# =============================================================================
# 4. MAIN WINDOW
# =============================================================================

class PEPatcherGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.files, self.file_items = [], {}
        self.file_processor_thread = None; self.patcher_thread = None
        self.setWindowTitle(f"{APP_TITLE} {APP_VERSION}")
        self.setMinimumSize(960, 780)
        self.setStyleSheet(REFINED_STYLESHEET)
        self.center_window(); self.setup_ui()
        self.log(f"Запущено API PE Replacer v{APP_VERSION}", "info")

    def center_window(self):
        if screen := self.screen(): g = screen.availableGeometry(); self.move((g.width() - self.width()) // 2, (g.height() - self.height()) // 2)

    def setup_ui(self):
        main = QWidget(); self.setCentralWidget(main)
        layout = QVBoxLayout(main); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(0)
        self._create_header(layout)
        
        # Основний вміст з горизонтальним splitter
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(24, 24, 24, 24)
        content_layout.setSpacing(0)
        
        # Горизонтальний splitter між файлами і правою панеллю
        self.horizontal_splitter = RefinedSplitter(Qt.Orientation.Horizontal)
        
        # Ліва панель - файли та кнопки
        left_panel = self._create_left_panel()
        self.horizontal_splitter.addWidget(left_panel)
        
        # Права панель з вертикальним splitter
        self.vertical_splitter = RefinedSplitter(Qt.Orientation.Vertical)
        
        # Налаштування (верхня частина правої панелі)
        settings_panel = self._create_settings_panel()
        self.vertical_splitter.addWidget(settings_panel)
        
        # Логи (нижня частина правої панелі)  
        log_panel = self._create_log_panel()
        self.vertical_splitter.addWidget(log_panel)
        
        # Встановлюємо пропорції для вертикального splitter (50/50)
        self.vertical_splitter.setSizes([300, 300])
        
        self.horizontal_splitter.addWidget(self.vertical_splitter)
        
        # Встановлюємо пропорції для горизонтального splitter (60/40)
        self.horizontal_splitter.setSizes([600, 400])
        
        content_layout.addWidget(self.horizontal_splitter)
        
        layout.addWidget(content, 1)
        self._create_bottom(layout)

    def _create_header(self, layout):
        header = QWidget(); header.setObjectName("AppHeader"); header_layout = QHBoxLayout(header)
        title_section = QWidget(); title_layout = QVBoxLayout(title_section); title_layout.setContentsMargins(0,0,0,0); title_layout.setSpacing(2)
        title = QLabel(APP_TITLE); title.setProperty("class", "h1"); title_layout.addWidget(title)
        subtitle = QLabel(f"Version {APP_VERSION}"); subtitle.setProperty("class", "caption"); title_layout.addWidget(subtitle)
        header_layout.addWidget(title_section); header_layout.addStretch()
        stats_section = QWidget(); stats_layout = QHBoxLayout(stats_section); stats_layout.setSpacing(24)
        self.files_count = QLabel("0"); self.files_count.setProperty("class", "h1"); self.files_count.setStyleSheet(f"color: {REFINED_PALETTE['accent']};"); stats_layout.addWidget(self.files_count)
        files_label = QLabel("файлів"); files_label.setProperty("class", "caption"); stats_layout.addWidget(files_label)
        header_layout.addWidget(stats_section); layout.addWidget(header)

    def _create_left_panel(self):
        """Створює ліву панель з файлами та кнопками"""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        
        # Кнопки управління файлами вгорі (новий контейнер з заголовком)
        file_actions_container = RefinedContainer("card")
        file_actions_layout = QVBoxLayout(file_actions_container)
        file_actions_layout.setContentsMargins(20, 16, 20, 16)
        file_actions_layout.setSpacing(12)
        
        # Горизонтальний layout для кнопок
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        # Кнопка "Додати файли" - розтягується
        add_files_btn = QPushButton("Додати файли")
        add_files_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
        add_files_btn.clicked.connect(self.add_files)
        header_layout.addWidget(add_files_btn, 1)  # 1 = розтягується

        # Кнопка "Додати папку" - розтягується
        add_folder_btn = QPushButton("Додати папку")
        add_folder_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
        add_folder_btn.clicked.connect(self.add_folder)
        header_layout.addWidget(add_folder_btn, 1)  # 1 = розтягується

        file_actions_layout.addLayout(header_layout)
        
        layout.addWidget(file_actions_container)
        
        # Панель файлів
        files_panel = self._create_files_panel()
        layout.addWidget(files_panel, 1)
        
        # Кнопки патчингу внизу
        buttons_container = RefinedContainer("card")
        buttons_layout_bottom = QHBoxLayout(buttons_container)
        buttons_layout_bottom.setContentsMargins(20, 16, 20, 16)
        buttons_layout_bottom.setSpacing(12)
        
        # Кнопка "Почати патчинг" - розтягується
        self.patch_btn = QPushButton("Почати патчинг")
        self.patch_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
        self.patch_btn.clicked.connect(self.start_patching)
        buttons_layout_bottom.addWidget(self.patch_btn, 1)  # 1 = розтягується
        
        # Кнопка "Очистити все" - розтягується
        clear_btn = QPushButton("Очистити все")
        clear_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
        clear_btn.clicked.connect(self.clear_all)
        buttons_layout_bottom.addWidget(clear_btn, 1)  # 1 = розтягується
        
        layout.addWidget(buttons_container)
        
        return container

    def _create_files_panel(self):
        container = RefinedContainer("elevated")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Scroll area для файлів
        scroll = QScrollArea()
        scroll.setObjectName("FilesScrollArea")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent;")
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        # Головний контейнер для всього вмісту
        self.files_content = QWidget()
        self.files_content.setStyleSheet("background: transparent;")
        self.files_main_layout = QVBoxLayout(self.files_content)
        self.files_main_layout.setContentsMargins(0, 0, 0, 0)
        self.files_main_layout.setSpacing(0)
        
        # Empty state
        self.empty_state = QWidget()
        self.empty_state.setObjectName("EmptyState")
        self.empty_state.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.empty_state.setMinimumHeight(250)
        
        empty_layout = QVBoxLayout(self.empty_state)
        empty_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.setSpacing(12)
        
        empty_text = QLabel("Файли не додано")
        empty_text.setProperty("class", "h3")
        empty_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        empty_hint = QLabel("Додайте PE файли для початку")
        empty_hint.setProperty("class", "caption")
        empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        empty_layout.addWidget(empty_text)
        empty_layout.addWidget(empty_hint)
        
        # Контейнер для файлів (з'являється коли є файли)
        self.files_container = QWidget()
        self.files_container.setStyleSheet("background: transparent;")
        self.files_layout = QVBoxLayout(self.files_container)
        self.files_layout.setContentsMargins(12, 12, 12, 12)
        self.files_layout.setSpacing(0)
        self.files_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        # Додаємо обидва контейнери до головного лейаута
        self.files_main_layout.addWidget(self.empty_state)
        self.files_main_layout.addWidget(self.files_container)
        self.files_container.hide()  # Ховаємо контейнер з файлами спочатку
        
        scroll.setWidget(self.files_content)
        layout.addWidget(scroll, 1)
        
        return container

    def _create_settings_panel(self):
        """Створює панель налаштувань"""
        settings = RefinedContainer("card")
        settings_layout = QVBoxLayout(settings)
        settings_layout.setContentsMargins(0, 0, 0, 0)
        settings_layout.setSpacing(0)
        
        # ЛИПКИЙ заголовок
        header_widget = QWidget()
        header_widget.setStyleSheet(f"""
            background-color: {REFINED_PALETTE['bg_secondary']};
            border-top-left-radius: 16px;
            border-top-right-radius: 16px;
            padding-bottom: 10px;
        """)
        header_layout = QVBoxLayout(header_widget)
        header_layout.setContentsMargins(20, 12, 20, 0)
        header_layout.setSpacing(0)
        
        settings_title = QLabel("Налаштування")
        settings_title.setProperty("class", "h3")
        settings_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(settings_title)
        
        settings_layout.addWidget(header_widget)
        
        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent;")
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        settings_content = QWidget()
        settings_content.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(settings_content)
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(12)
        
        # ===== API НАЛАШТУВАННЯ =====
        api_group = QGroupBox("API для заміни")
        api_layout = QVBoxLayout(api_group)
        api_layout.setContentsMargins(12, 6, 12, 12)
        api_layout.setSpacing(12)
        
        self.all_apis = QCheckBox("Всі API")
        self.all_apis.setChecked(True)
        self.all_apis.stateChanged.connect(self.toggle_apis)
        api_layout.addWidget(self.all_apis)
        
        # РОЗДІЛЬНИК
        api_layout.addWidget(RefinedDivider())
        
        api_list_widget = QWidget()
        api_list_layout = QVBoxLayout(api_list_widget)
        api_list_layout.setContentsMargins(0, 0, 0, 0)
        api_list_layout.setSpacing(8)

        self.api_checks = {}
        for num, data in DLL_REPLACEMENTS.items():
            check = QCheckBox(data['name'])
            check.setChecked(True)
            check.stateChanged.connect(self.on_api_change)
            self.api_checks[num] = check
            api_list_layout.addWidget(check)
        
        api_list_layout.addStretch()
        api_list_widget.setLayout(api_list_layout)
        api_layout.addWidget(api_list_widget, 1)
        content_layout.addWidget(api_group)
        
        # ===== ОПЦІЇ ЗБЕРЕЖЕННЯ =====
        options_group = QGroupBox("Опції збереження")
        options_group_layout = QVBoxLayout(options_group)
        options_group_layout.setContentsMargins(12, 6, 12, 12)
        options_group_layout.setSpacing(8)
        
        self.backup = QCheckBox("Створювати бекапи")
        self.backup.setChecked(True)
        options_group_layout.addWidget(self.backup)
        
        self.overwrite = QCheckBox("Перезаписувати оригінали")
        self.overwrite.setChecked(True)
        options_group_layout.addWidget(self.overwrite)
        
        content_layout.addWidget(options_group)
        content_layout.addStretch()
        
        scroll.setWidget(settings_content)
        settings_layout.addWidget(scroll, 1)
        
        return settings
    
    def _create_log_panel(self):
        """Створює панель логів"""
        log = RefinedContainer("card")
        log_layout = QVBoxLayout(log)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_layout.setSpacing(0)
        
        # ЛИПКИЙ заголовок (залишається на місці при перемотці)
        header_widget = QWidget()
        header_widget.setStyleSheet(f"""
            background-color: {REFINED_PALETTE['bg_secondary']};
            border-top-left-radius: 16px;
            border-top-right-radius: 16px;
            padding-bottom: 10px;
        """)
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(20, 12, 20, 0)
        header_layout.setSpacing(0)
        
        log_title = QLabel("Логи")
        log_title.setProperty("class", "h3")
        header_layout.addWidget(log_title)
        header_layout.addStretch()
        
        clear_log = QPushButton("Очистити")
        clear_log.setProperty("variant", "ghost")
        clear_log.clicked.connect(self.clear_log)
        header_layout.addWidget(clear_log)
        
        log_layout.addWidget(header_widget)
        
        # Scroll area для всього вмісту (БЕЗ заголовка)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent;")
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        # Контейнер для вмісту (без заголовка)
        log_content = QWidget()
        log_content.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(log_content)
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(12)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        content_layout.addWidget(self.log_text, 1)
        
        scroll.setWidget(log_content)
        log_layout.addWidget(scroll, 1)
        
        return log
    
    def _create_bottom(self, layout):
        bottom = QWidget()
        bottom.setStyleSheet(f"background: {REFINED_PALETTE['bg_secondary']}; border-top: 1px solid {REFINED_PALETTE['border']};")
        bottom_layout = QVBoxLayout(bottom)
        bottom_layout.setContentsMargins(24, 16, 24, 16)
        bottom_layout.setSpacing(12)
        
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(5)
        self.progress.setMinimumHeight(5)
        self.progress.setMaximumHeight(5)
        bottom_layout.addWidget(self.progress)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        # Кнопка "Про програму" залишається внизу
        about_btn = QPushButton("Про програму")
        about_btn.setProperty("variant", "ghost")
        about_btn.clicked.connect(self.show_about)
        btn_layout.addWidget(about_btn)
        
        btn_layout.addStretch()
        bottom_layout.addLayout(btn_layout)
        layout.addWidget(bottom)

    def log(self, msg, level="info"):
        if not msg: self.log_text.append(""); return
        colors = {'info': REFINED_PALETTE['text_secondary'], 'success': REFINED_PALETTE['success'], 'warning': REFINED_PALETTE['warning'], 'error': REFINED_PALETTE['error']}
        time = datetime.now().strftime("%H:%M:%S"); color = colors.get(level, REFINED_PALETTE['text_secondary'])
        self.log_text.append(f'<span style="color: {REFINED_PALETTE["text_muted"]};">{time}</span> <span style="color: {color};">{msg}</span>')

    def add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Виберіть PE Файли", "", "PE Files (*.exe *.dll *.vst3 *.vst *.sys);;All Files (*)")
        if files: self.process_files(files)

    def add_folder(self):
        msg_box = QMessageBox(self); msg_box.setWindowTitle("Опція пошуку"); msg_box.setText("Шукати файли у підпапках?")
        yes_button = msg_box.addButton("Так (рекурсивно)", QMessageBox.ButtonRole.YesRole)
        no_button = msg_box.addButton("Ні (лише ця папка)", QMessageBox.ButtonRole.NoRole)
        cancel_button = msg_box.addButton("Скасувати", QMessageBox.ButtonRole.RejectRole)
        msg_box.exec()
        clicked = msg_box.clickedButton()
        if clicked == cancel_button: return
        include_subfolders = (clicked == yes_button)
        folder = QFileDialog.getExistingDirectory(self, "Виберіть папку")
        if folder:
            self.log(f"Сканування: {folder} {'(з підпапками)' if include_subfolders else ''}", "info")
            dialog = RefinedFolderDialog(self, folder, include_subfolders)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                if files := dialog.get_found_files(): self.process_files(files)

    def process_files(self, paths):
        new = [p for p in paths if not any(f['path'] == p for f in self.files)]
        if not new: self.log("Всі обрані файли вже додано", "warning"); return
        self.progress.setRange(0, 0)
        self.file_processor_thread = QThread(); self.file_processor_worker = FileProcessorWorker(new); self.file_processor_worker.moveToThread(self.file_processor_thread)
        self.file_processor_thread.started.connect(self.file_processor_worker.run); self.file_processor_worker.finished.connect(self.file_processor_thread.quit);
        self.file_processor_worker.file_processed.connect(self.add_file_item); self.file_processor_worker.finished.connect(self.files_added)
        self.file_processor_thread.start()

    def add_file_item(self, info):
        # Ховаємо empty state і показуємо контейнер з файлами
        if self.empty_state.isVisible():
            self.empty_state.hide()
            self.files_container.show()
        
        # Використовуємо SwipeableFileItem замість RefinedFileItem
        item = SwipeableFileItem(info)
        item.removed.connect(self.remove_file_with_animation)
        self.files.append(info)
        self.file_items[info['path']] = item
        self.files_layout.addWidget(item)
        self.update_stats()

    def files_added(self, added, errors):
        self.progress.setRange(0, 100); self.progress.setValue(0)
        if added: self.log(f"Додано {added} файлів", "success")
        if errors: self.log(f"Пропущено {errors} файлів (не PE)", "warning")

    def remove_file_with_animation(self, path):
        """Видалення файлу з анімацією (для ручного видалення)"""
        if path in self.file_items:
            self.animate_card_removal(path)

    def animate_card_removal(self, path: str):
        """Анімація видалення картки файлу (свайп вліво та зникнення)"""
        if not (widget := self.file_items.get(path)):
            return
        
        # Створюємо анімаційну групу
        anim_group = QParallelAnimationGroup(widget)
        
        # Анімація зсуву вліво
        slide_anim = QPropertyAnimation(widget, b"pos")
        slide_anim.setDuration(300)
        slide_anim.setStartValue(widget.pos())
        slide_anim.setEndValue(QPoint(widget.width() * -1, widget.pos().y()))
        slide_anim.setEasingCurve(QEasingCurve.Type.InCubic)
        
        # Анімація зменшення висоти
        shrink_anim = QPropertyAnimation(widget, b"maximumHeight")
        shrink_anim.setDuration(250)
        shrink_anim.setStartValue(widget.height())
        shrink_anim.setEndValue(0)
        
        # Додаємо анімації до групи
        anim_group.addAnimation(slide_anim)
        anim_group.addAnimation(shrink_anim)
        
        # Видаляємо файл після завершення анімації
        anim_group.finished.connect(lambda: self.finalize_removal(path, widget))
        anim_group.start()

    def finalize_removal(self, path, item):
        """Фінальне видалення файлу після анімації"""
        self.files = [f for f in self.files if f['path'] != path]
        self.file_items.pop(path, None)
        item.deleteLater()
        
        # Якщо файлів не залишилось, показуємо empty state
        if not self.files:
            self.empty_state.show()
            self.files_container.hide()
        
        self.update_stats()
        # self.log(f"Файл був видалений з списку для пропатчування: {os.path.basename(path)}", "info")

    def clear_all(self):
        """Очищення списку файлів з перевіркою активного патчинга"""
        
        # Перевіряємо, чи іде патчинг
        if self.patcher_thread and self.patcher_thread.isRunning():
            QMessageBox.warning(
                self, 
                "Патчинг у дії", 
                "Не можна очистити список файлів під час активного патчинга.\n\n"
                "Дочекайтесь завершення операції."
            )
            return
        
        if not self.files:
            QMessageBox.information(self, "Список пустий", "Немає файлів для очищення")
            return
            
        if QMessageBox.question(
            self, 
            "Підтвердження", 
            "Видалити всі файли зі списку?"
        ) == QMessageBox.StandardButton.Yes:
            for item in self.file_items.values():
                item.deleteLater()
            self.files.clear()
            self.file_items.clear()
            self.empty_state.show()
            self.files_container.hide()
            self.update_stats()
            self.log("Список файлів очищено", "info")

    def clear_log(self): self.log_text.clear(); self.log("Логи очищено", "info")
    def update_stats(self): self.files_count.setText(str(len(self.files)))
    def toggle_apis(self, state):
        for check in self.api_checks.values(): check.setChecked(bool(state))
    def on_api_change(self):
        all_checked = all(c.isChecked() for c in self.api_checks.values())
        self.all_apis.blockSignals(True); self.all_apis.setChecked(all_checked); self.all_apis.blockSignals(False)

    def start_patching(self):
        if not self.files: 
            QMessageBox.warning(self, "Увага", "Немає файлів для патчингу")
            return
        
        # Отримуємо вибрані API
        apis = [0] if self.all_apis.isChecked() else [n for n, c in self.api_checks.items() if c.isChecked()]
        if not apis: 
            QMessageBox.warning(self, "Увага", "Виберіть хоча б один API")
            return
        
        self.patch_btn.setEnabled(False)
        self.patch_btn.setText("Патчинг...")
        self.progress.setValue(0)
        
        # Блокуємо свайп для всіх файлів під час патчингу
        for item in self.file_items.values():
            item.setEnabled(False)
        
        self.patcher_thread = QThread()
        self.patcher_worker = PatcherWorker(
            list(self.files), 
            apis,
            self.backup.isChecked(), 
            self.overwrite.isChecked()
        )
        self.patcher_worker.moveToThread(self.patcher_thread)
        
        self.patcher_thread.started.connect(self.patcher_worker.run)
        self.patcher_worker.finished.connect(self.patcher_thread.quit)
        self.patcher_worker.log_message.connect(self.log)
        self.patcher_worker.progress_updated.connect(self.progress.setValue)
        self.patcher_worker.file_status_updated.connect(self.on_file_status_updated)
        self.patcher_worker.finished.connect(self.patching_done)
        
        self.patcher_thread.start()

    def on_file_status_updated(self, path: str, status: str, text: str):
        """Оновлює статус файлу та запускає анімацію для успішних/пропущених файлів"""
        if widget := self.file_items.get(path):
            widget.update_status(status, text)
            # Для успішних та пропущених файлів запускаємо анімацію видалення
            if status in ['success', 'warning']:  # 'warning' - це пропущені файли
                QTimer.singleShot(1200, lambda: self.animate_card_removal(path))

    def patching_done(self, summary, level, patched_dirs=None, backup_dirs=None):
        self.log(summary, level)
        self.patch_btn.setEnabled(True)
        self.patch_btn.setText("Почати патчинг")
        self.progress.setValue(0)
        
        # Розблоковуємо свайп для всіх файлів після патчингу
        for item in self.file_items.values():
            item.setEnabled(True)
        
        QMessageBox.information(self, "Завершено", summary)

    def show_about(self):
        from PyQt6.QtWidgets import QTextBrowser
        from PyQt6.QtGui import QDesktopServices
        from PyQt6.QtCore import QUrl
        
        # Створюємо кастомний діалог
        dialog = QDialog(self)
        dialog.setWindowTitle("Про програму")
        dialog.setFixedSize(600, 640)
        dialog.setStyleSheet(REFINED_STYLESHEET)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        about_text = f"""
        <h2>{APP_TITLE} {APP_VERSION}</h2>
        
        <hr style="margin: 12px 0; border: none; border-top: 1px solid rgba(139, 127, 184, 0.3);">
        
        <p style="font-size: 13px; margin-top: 12px;">
            <b>Автор:</b> <a href="https://github.com/EXLOUD" style="color: #8B7FB8; text-decoration: none;">github.com/EXLOUD</a>
        </p>
        """
        
        # TextBrowser для відображення HTML
        text_browser = QTextBrowser()
        text_browser.setHtml(about_text)
        text_browser.setReadOnly(True)
        text_browser.setOpenExternalLinks(True)
        
        # Scroll area для всього вмісту
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll_layout.setSpacing(12)
        
        # ============================================================
        # КРИПТО АДРЕСИ
        # ============================================================
        addresses_panel = QWidget()
        addresses_layout = QVBoxLayout(addresses_panel)
        addresses_layout.setContentsMargins(0, 0, 0, 0)
        addresses_layout.setSpacing(8)
        
        title_label = QLabel("💰 Донат (натисніть щоб скопіювати):")
        title_label.setProperty("class", "caption")
        addresses_layout.addWidget(title_label)
        
        address_buttons = [
            ("Bitcoin", "bitcoin"),
            ("Ethereum", "ethereum"),
            ("Monero", "monero"),
            ("TON", "ton"),
            ("USDT (TRC20)", "usdt_trc20"),
            ("USDT (ERC20)", "usdt_erc20"),
            ("USDC (ERC20)", "usdc_erc20"),
            ("Tron", "tron"),
            ("BNB", "bnb"),
        ]
        
        for name, key in address_buttons:
            btn = QPushButton(f"📋 {name}")
            btn.setStyleSheet(STANDARD_BUTTON_STYLE)
            btn.setMinimumHeight(36)
            btn.setProperty("variant", "secondary")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            
            def copy_address(checked, addr_key=key):
                address = DONATION_ADDRESSES[addr_key]
                clipboard = QApplication.clipboard()
                clipboard.setText(address)
                self.log(f"✅ Скопійовано {addr_key.upper()}: {address[:15]}...", "success")
            
            btn.clicked.connect(copy_address)
            addresses_layout.addWidget(btn)
        
        scroll_layout.addWidget(addresses_panel)
        scroll_layout.addStretch()
        
        layout.addWidget(text_browser, 1)
        layout.addWidget(scroll_widget, 1)
        
        # ============================================================
        # КНОПКА ЗАКРИТТЯ
        # ============================================================
        close_btn = QPushButton("Закрити")
        close_btn.setStyleSheet(STANDARD_BUTTON_STYLE)
        close_btn.setFixedWidth(120)
        close_btn.clicked.connect(dialog.accept)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        dialog.exec()

# =============================================================================
# 5. ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Локалізація Qt
    translator = QTranslator()
    if translator.load(QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath) + "/qt_uk.qm"):
        app.installTranslator(translator)
    
    window = PEPatcherGUI()
    window.show()
    sys.exit(app.exec())
