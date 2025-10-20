#include <windows.h>
#include <wintrust.h>
#include <mscat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <mssip.h>

// === НАЛАГОДЖУВАЛЬНІ КОНСТАНТИ ===
#define ENABLE_DEBUG_CONSOLE 0
#define ENABLE_FILE_LOGGING  0
#define ENABLE_MEMORY_TRACKING 1

// === ФАЛЛБЕКИ ДЛЯ КОНСТАНТ ТА ТИПІВ ===
#ifndef TRUST_E_NOSIGNATURE
#define TRUST_E_NOSIGNATURE ((HRESULT)0x800B0100L)
#endif
#ifndef E_MOREDATA
#define E_MOREDATA HRESULT_FROM_WIN32(ERROR_MORE_DATA)
#endif

// Повертаємо визначення, щоб код був самодостатнім
#ifndef _MSSIP_H_
typedef struct _SIP_CAPS { DWORD cbSize; DWORD dwVersion; BOOL isMultiSign; DWORD dwReserved; } SIP_CAPS, *PSIP_CAPS;
typedef struct _SIP_INFO { DWORD cbSize; GUID gSubject; DWORD dwUnionChoice; union { LPCWSTR pwszFileName; LPCWSTR pwszFileData; }; DWORD dwReserved; } SIP_INFO, *PSIP_INFO;
#endif
typedef struct CRYPTCATSTORE_ CRYPTCATSTORE;
#if !defined(CRYPT_PROVIDER_DEFINITION_DECLARED)
#define CRYPT_PROVIDER_DEFINITION_DECLARED
typedef struct _CRYPT_PROVIDER_DEFINITION { DWORD cbStruct; GUID *pgTrustProvider; void *pfnGetCertSigner; void *pfnGetCertTrust; void *pfnGetCrlSigner; void *pfnGetCrlTrust; void *pfnGetSpcSigner; void *pfnGetSpcTrust; void *pfnGetStsSigner; void *pfnGetStsTrust; void *pfnGetStlSigner; void *pfnGetStlTrust; } CRYPT_PROVIDER_DEFINITION, *PCRYPT_PROVIDER_DEFINITION;
#endif

// === ВИЗНАЧЕННЯ GUID'ІВ ДЛЯ СУМІСНОСТІ ===
static const GUID MY_WINTRUST_ACTION_GENERIC_VERIFY_V2      = {0x00aac56b, 0xcd44, 0x11d0, {0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}};
static const GUID MY_DRIVER_ACTION_VERIFY                   = {0xf750e6c3, 0x38ee, 0x11d1, {0x85, 0xe5, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}};
static const GUID MY_HTTPSPROV_ACTION                       = {0x573e31f8, 0xaaba, 0x11d0, {0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}};
static const GUID MY_WIN_SPUB_ACTION_TRUSTED_PUBLISHER      = {0x66426730, 0x8da1, 0x11cf, {0x87, 0x36, 0x00, 0xaa, 0x00, 0xa4, 0x85, 0xeb}};
static const GUID MY_WIN_SPUB_ACTION_PUBLISHED_SOFTWARE     = {0x64b9d180, 0x8da2, 0x11cf, {0x87, 0x36, 0x00, 0xaa, 0x00, 0xa4, 0x85, 0xeb}};
static const GUID MY_OFFICESIGN_ACTION_VERIFY               = {0x5555c201, 0x1296, 0x11d1, {0x85, 0x52, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}};
static const GUID MY_WINTRUST_ACTION_GENERIC_CHAIN_VERIFY   = {0xa4533171, 0x4879, 0x4376, {0x89, 0xae, 0x56, 0x04, 0xb7, 0x12, 0xd4, 0x48}};
static const GUID MY_WINTRUST_ACTION_TRUSTPROVIDER_TEST     = {0x573e31f8, 0xaaba, 0x11d0, {0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}};


// === РІВНІ ЛОГУВАННЯ ===
typedef enum { LOG_LEVEL_ERROR = 0, LOG_LEVEL_WARNING, LOG_LEVEL_INFO, LOG_LEVEL_DEBUG } LogLevel;

// === СТРУКТУРИ ДЛЯ ВІДСТЕЖЕННЯ ===
typedef struct _MEMORY_BLOCK { void* ptr; size_t size; char function[64]; DWORD thread_id; struct _MEMORY_BLOCK* next; } MEMORY_BLOCK;
typedef struct _FAKE_CATALOG { DWORD magic; CATALOG_INFO info; BOOL in_use; } FAKE_CATALOG;
typedef struct _OBJECT_NODE { void* object; DWORD thread_id; struct _OBJECT_NODE* next; } OBJECT_NODE;
#define FAKE_CATALOG_MAGIC 0xCAFEBABE
#define FAKE_HASH_SIZE 32
// === ГЛОБАЛЬНІ ЗМІННІ ===
#if ENABLE_FILE_LOGGING
static FILE* g_log_file = NULL; static CRITICAL_SECTION g_log_lock;
#endif
#if ENABLE_MEMORY_TRACKING
static MEMORY_BLOCK* g_memory_list = NULL; static CRITICAL_SECTION g_memory_lock; static size_t g_total_allocated = 0; static size_t g_total_freed = 0; static size_t g_allocation_count = 0;
#endif
static CRYPT_PROVIDER_DATA g_fake_prov_data = { sizeof(CRYPT_PROVIDER_DATA) };
static BOOL g_locks_initialized = FALSE; static LogLevel g_current_log_level = LOG_LEVEL_INFO;
static OBJECT_NODE* g_wvt_state_list = NULL; static OBJECT_NODE* g_cat_admin_list = NULL; static OBJECT_NODE* g_cat_info_list = NULL; static OBJECT_NODE* g_cat_handle_list = NULL;
static CRITICAL_SECTION g_wvt_list_lock; static CRITICAL_SECTION g_cat_admin_list_lock; static CRITICAL_SECTION g_cat_info_list_lock; static CRITICAL_SECTION g_cat_handle_list_lock;

// === ФУНКЦІЇ ЛОГУВАННЯ ===
void GetTimestamp(char* buffer, size_t bufferSize) { if (!buffer || bufferSize < 20) return; SYSTEMTIME st; GetLocalTime(&st); snprintf(buffer, bufferSize, "[%02d:%02d:%02d.%03d]", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds); }
const char* GetLogLevelString(LogLevel level) { switch (level) { case LOG_LEVEL_ERROR: return "ERROR"; case LOG_LEVEL_WARNING: return "WARN "; case LOG_LEVEL_INFO: return "INFO "; case LOG_LEVEL_DEBUG: return "DEBUG"; default: return "?????"; } }
void LogMessageEx(LogLevel level, const char* function, const char* format, ...) { if (level > g_current_log_level) return; char timestamp[20] = { 0 }; GetTimestamp(timestamp, sizeof(timestamp)); va_list args; va_start(args, format);
#if ENABLE_FILE_LOGGING
if (g_log_file && g_locks_initialized) { EnterCriticalSection(&g_log_lock); fprintf(g_log_file, "%s [%s] [%s] ", timestamp, GetLogLevelString(level), function); vfprintf(g_log_file, format, args); fprintf(g_log_file, "\n"); fflush(g_log_file); LeaveCriticalSection(&g_log_lock); }
#endif
#if ENABLE_DEBUG_CONSOLE
printf("[WINTRUST] %s [%s] [%s] ", timestamp, GetLogLevelString(level), function); vprintf(format, args); printf("\n");
#endif
va_end(args); }
#define LogError(fmt, ...)   LogMessageEx(LOG_LEVEL_ERROR, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogWarning(fmt, ...) LogMessageEx(LOG_LEVEL_WARNING, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogInfo(fmt, ...)    LogMessageEx(LOG_LEVEL_INFO, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogDebug(fmt, ...)   LogMessageEx(LOG_LEVEL_DEBUG, __FUNCTION__, fmt, ##__VA_ARGS__)
void LogHexBuffer(LogLevel level, const char* function, const char* prefix, const BYTE* buffer, DWORD size) { if (level > g_current_log_level) return; if (!buffer || size == 0) { LogMessageEx(level, function, "%s: <NULL or empty>", prefix); return; } char hex_str[257] = { 0 }; DWORD len = 0; DWORD bytes_to_log = (size > 128) ? 128 : size; for (DWORD i = 0; i < bytes_to_log; i++) { len += snprintf(hex_str + len, sizeof(hex_str) - len, "%02X", buffer[i]); } if (size > 128) { snprintf(hex_str + len, sizeof(hex_str) - len, "..."); } LogMessageEx(level, function, "%s (%lu bytes): %s", prefix, size, hex_str); }
// === ФУНКЦІЇ УПРАВЛІННЯ ПАМ'ЯТТЮ ===
#if ENABLE_MEMORY_TRACKING
void* TrackedAlloc(size_t size, const char* function) { if (size == 0) { LogWarning("Attempted to allocate 0 bytes"); return NULL; } void* ptr = malloc(size); if (!ptr) { LogError("Failed to allocate %zu bytes", size); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; } memset(ptr, 0, size); if (g_locks_initialized) { EnterCriticalSection(&g_memory_lock); MEMORY_BLOCK* block = (MEMORY_BLOCK*)malloc(sizeof(MEMORY_BLOCK)); if (block) { block->ptr = ptr; block->size = size; strncpy(block->function, function, sizeof(block->function) - 1); block->function[sizeof(block->function) - 1] = '\0'; block->thread_id = GetCurrentThreadId(); block->next = g_memory_list; g_memory_list = block; g_total_allocated += size; g_allocation_count++; LogDebug("Allocated %zu bytes (total: %zu, count: %zu): %p", size, g_total_allocated - g_total_freed, g_allocation_count, ptr); } LeaveCriticalSection(&g_memory_lock); } return ptr; }
BOOL TrackedFree(void* ptr, const char* function) { if (!ptr) return TRUE; BOOL found = FALSE; if (g_locks_initialized) { EnterCriticalSection(&g_memory_lock); MEMORY_BLOCK** current = &g_memory_list; while (*current) { if ((*current)->ptr == ptr) { MEMORY_BLOCK* block = *current; *current = block->next; g_total_freed += block->size; g_allocation_count--; LogDebug("Freed %zu bytes from %s (remaining: %zu, count: %zu): %p", block->size, block->function, g_total_allocated - g_total_freed, g_allocation_count, ptr); free(block); found = TRUE; break; } current = &(*current)->next; } LeaveCriticalSection(&g_memory_lock); } if (!found && g_locks_initialized) { LogWarning("Attempting to free untracked memory: %p", ptr); } free(ptr); return TRUE; }
void ReportMemoryLeaks() { if (!g_locks_initialized) return; EnterCriticalSection(&g_memory_lock); if (g_memory_list) { LogError("=== MEMORY LEAKS DETECTED ==="); LogError("Total leaked: %zu bytes in %zu allocations", g_total_allocated - g_total_freed, g_allocation_count); MEMORY_BLOCK* current = g_memory_list; int leak_count = 0; while (current && leak_count < 100) { LogError("  Leak #%d: %zu bytes from %s (thread %lu): %p", ++leak_count, current->size, current->function, current->thread_id, current->ptr); current = current->next; } if (current) { LogError("  ... and more leaks (showing first 100)"); } } else { LogInfo("No memory leaks detected!"); LogInfo("Total allocated: %zu bytes, Total freed: %zu bytes", g_total_allocated, g_total_freed); } LeaveCriticalSection(&g_memory_lock); }
void CleanupAllMemory() { if (!g_locks_initialized) return; EnterCriticalSection(&g_memory_lock); MEMORY_BLOCK* current = g_memory_list; int cleaned = 0; while (current) { MEMORY_BLOCK* next = current->next; free(current->ptr); free(current); current = next; cleaned++; } if (cleaned > 0) { LogWarning("Force-cleaned %d memory blocks on shutdown", cleaned); } g_memory_list = NULL; g_total_allocated = 0; g_total_freed = 0; g_allocation_count = 0; LeaveCriticalSection(&g_memory_lock); }
#define SAFE_ALLOC(size) TrackedAlloc(size, __FUNCTION__)
#define SAFE_FREE(ptr) TrackedFree(ptr, __FUNCTION__)
#else
#define SAFE_ALLOC(size) calloc(1, size)
#define SAFE_FREE(ptr) free(ptr)
#define ReportMemoryLeaks()
#define CleanupAllMemory()
#endif
// === ДОПОМІЖНІ ФУНКЦІЇ ДЛЯ КЕРУВАННЯ ОБ'ЄКТАМИ ===
void* AddObjectToList(OBJECT_NODE** list_head, CRITICAL_SECTION* lock, void* object_data) { if (!object_data) return NULL; OBJECT_NODE* new_node = (OBJECT_NODE*)SAFE_ALLOC(sizeof(OBJECT_NODE)); if (!new_node) { LogError("Failed to allocate object node"); return NULL; } new_node->object = object_data; new_node->thread_id = GetCurrentThreadId(); EnterCriticalSection(lock); new_node->next = *list_head; *list_head = new_node; LeaveCriticalSection(lock); LogDebug("Added object %p to list (Thread: %lu)", object_data, new_node->thread_id); return object_data; }
BOOL FindObjectInList(OBJECT_NODE* list_head, CRITICAL_SECTION* lock, void* object_to_find) { if (!object_to_find) return FALSE; BOOL found = FALSE; EnterCriticalSection(lock); OBJECT_NODE* current = list_head; while (current) { if (current->object == object_to_find) { found = TRUE; break; } current = current->next; } LeaveCriticalSection(lock); if (!found) { LogWarning("Attempt to use invalid or freed handle: %p", object_to_find); } return found; }
BOOL RemoveObjectFromList(OBJECT_NODE** list_head, CRITICAL_SECTION* lock, void* object_to_remove) { if (!object_to_remove) return FALSE; BOOL found = FALSE; EnterCriticalSection(lock); OBJECT_NODE** current_ptr = list_head; while (*current_ptr) { if ((*current_ptr)->object == object_to_remove) { OBJECT_NODE* node_to_delete = *current_ptr; *current_ptr = node_to_delete->next; LogDebug("Removing object %p from list (created by thread: %lu)", node_to_delete->object, node_to_delete->thread_id); SAFE_FREE(node_to_delete->object); SAFE_FREE(node_to_delete); found = TRUE; break; } current_ptr = &(*current_ptr)->next; } LeaveCriticalSection(lock); if (!found) { LogWarning("Attempt to remove non-existent handle: %p", object_to_remove); } return found; }
void CleanupObjectList(OBJECT_NODE** list_head, CRITICAL_SECTION* lock, const char* list_name) { EnterCriticalSection(lock); OBJECT_NODE* current = *list_head; int count = 0; while (current) { OBJECT_NODE* next = current->next; LogWarning("Force-cleaning leaked object from '%s': %p (Thread: %lu)", list_name, current->object, current->thread_id); SAFE_FREE(current->object); SAFE_FREE(current); current = next; count++; } *list_head = NULL; if (count > 0) { LogWarning("Cleaned up %d leaked objects from '%s' list.", count, list_name); } LeaveCriticalSection(lock); }
// === ДОПОМІЖНІ ФУНКЦІЇ ===
DWORD HashString(LPCWSTR str) { if (!str) return 5381; unsigned long hash = 5381; int c; while ((c = *str++)) { hash = ((hash << 5) + hash) + c; } return hash; }
BOOL handle_hash_buffer(LPCWSTR pwszFilePath, HANDLE hFile, DWORD* pcbHash, BYTE* pbHash) { if (!pcbHash) { LogError("pcbHash is NULL"); SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } if (pbHash == NULL) { *pcbHash = FAKE_HASH_SIZE; LogDebug("Returning required hash size: %d bytes", FAKE_HASH_SIZE); SetLastError(ERROR_MORE_DATA); return FALSE; } if (*pcbHash < FAKE_HASH_SIZE) { LogWarning("Buffer too small. Need %d bytes, got %d", FAKE_HASH_SIZE, *pcbHash); *pcbHash = FAKE_HASH_SIZE; SetLastError(ERROR_MORE_DATA); return FALSE; } DWORD seed; if (pwszFilePath && wcslen(pwszFilePath) > 0) { seed = HashString(pwszFilePath); LogDebug("Generating hash based on file path: %S", pwszFilePath); } else { seed = (DWORD)(ULONG_PTR)hFile; LogDebug("Generating hash based on file handle: 0x%p", hFile); } for (DWORD i = 0; i < FAKE_HASH_SIZE; i++) { seed = seed * 1103515245 + 12345; pbHash[i] = (BYTE)(seed >> 16); } *pcbHash = FAKE_HASH_SIZE; return TRUE; }

// === ДОПОМІЖНІ ФУНКЦІЇ ДЛЯ ДЕТАЛЬНОГО ЛОГУВАННЯ ===
const char* GetActionIDName(const GUID* pgActionID) {
    if (!pgActionID) return "NULL";
    if (IsEqualGUID(pgActionID, &MY_WINTRUST_ACTION_GENERIC_VERIFY_V2)) return "WINTRUST_ACTION_GENERIC_VERIFY_V2";
    if (IsEqualGUID(pgActionID, &MY_DRIVER_ACTION_VERIFY)) return "DRIVER_ACTION_VERIFY";
    if (IsEqualGUID(pgActionID, &MY_HTTPSPROV_ACTION)) return "HTTPSPROV_ACTION / WINTRUST_ACTION_TRUSTPROVIDER_TEST";
    if (IsEqualGUID(pgActionID, &MY_WIN_SPUB_ACTION_TRUSTED_PUBLISHER)) return "WIN_SPUB_ACTION_TRUSTED_PUBLISHER";
    if (IsEqualGUID(pgActionID, &MY_WIN_SPUB_ACTION_PUBLISHED_SOFTWARE)) return "WIN_SPUB_ACTION_PUBLISHED_SOFTWARE";
    if (IsEqualGUID(pgActionID, &MY_OFFICESIGN_ACTION_VERIFY)) return "OFFICESIGN_ACTION_VERIFY";
    if (IsEqualGUID(pgActionID, &MY_WINTRUST_ACTION_GENERIC_CHAIN_VERIFY)) return "WINTRUST_ACTION_GENERIC_CHAIN_VERIFY";
    return "Unknown Action";
}

void LogProvFlags(DWORD flags) { if (flags == 0) { LogInfo("      (none)"); return; } if (flags & WTD_USE_IE4_TRUST_FLAG) LogInfo("      WTD_USE_IE4_TRUST_FLAG"); if (flags & WTD_NO_IE4_CHAIN_FLAG) LogInfo("      WTD_NO_IE4_CHAIN_FLAG"); if (flags & WTD_NO_POLICY_USAGE_FLAG) LogInfo("      WTD_NO_POLICY_USAGE_FLAG"); if (flags & WTD_USE_LOCAL_MACHINE_CERTS) LogInfo("      WTD_USE_LOCAL_MACHINE_CERTS"); if (flags & WTD_SAFER_FLAG) LogInfo("      WTD_SAFER_FLAG"); if (flags & WTD_HASH_ONLY_FLAG) LogInfo("      WTD_HASH_ONLY_FLAG"); if (flags & WTD_USE_DEFAULT_OSVER_CHECK) LogInfo("      WTD_USE_DEFAULT_OSVER_CHECK"); if (flags & WTD_LIFETIME_SIGNING_FLAG) LogInfo("      WTD_LIFETIME_SIGNING_FLAG"); if (flags & WTD_CACHE_ONLY_URL_RETRIEVAL) LogInfo("      WTD_CACHE_ONLY_URL_RETRIEVAL"); if (flags & WTD_DISABLE_MD2_MD4) LogInfo("      WTD_DISABLE_MD2_MD4"); if (flags & WTD_MOTW) LogInfo("      WTD_MOTW"); }
void LogRevocationChecks(DWORD flags) { if (flags == WTD_REVOKE_NONE) { LogInfo("      WTD_REVOKE_NONE"); return; } if (flags & WTD_REVOCATION_CHECK_END_CERT) LogInfo("      WTD_REVOCATION_CHECK_END_CERT"); if (flags & WTD_REVOCATION_CHECK_CHAIN) LogInfo("      WTD_REVOCATION_CHECK_CHAIN"); if (flags & WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT) LogInfo("      WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT"); if (flags & WTD_REVOKE_WHOLECHAIN) LogInfo("      WTD_REVOKE_WHOLECHAIN"); }

// === ОСНОВНІ ФУНКЦІЇ ===
LONG WINAPI EXLOUD_WinVerifyTrust(HWND hwnd, GUID* pgActionID, LPVOID pWinTrustData) {
    LogInfo("-------------------- WinVerifyTrust Called --------------------");
    WINTRUST_DATA* pData = (WINTRUST_DATA*)pWinTrustData;
    if (!pData) { LogError("  pWinTrustData is NULL!"); return E_INVALIDARG; }
    LogInfo("  Called with hwnd: 0x%p", hwnd);
    if (pgActionID) { char guid_str[40]; snprintf(guid_str, sizeof(guid_str), "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", pgActionID->Data1, pgActionID->Data2, pgActionID->Data3, pgActionID->Data4[0], pgActionID->Data4[1], pgActionID->Data4[2], pgActionID->Data4[3], pgActionID->Data4[4], pgActionID->Data4[5], pgActionID->Data4[6], pgActionID->Data4[7]); LogInfo("  ActionID: %s (%s)", guid_str, GetActionIDName(pgActionID)); }
    else { LogInfo("  ActionID: NULL"); }
    LogInfo("  WINTRUST_DATA at 0x%p:", pWinTrustData);
    LogInfo("    cbStruct: %lu", pData->cbStruct);
    LogInfo("    dwStateAction: 0x%08lX (%s)", pData->dwStateAction, pData->dwStateAction == WTD_STATEACTION_VERIFY ? "WTD_STATEACTION_VERIFY" : pData->dwStateAction == WTD_STATEACTION_CLOSE ? "WTD_STATEACTION_CLOSE" : pData->dwStateAction == WTD_STATEACTION_IGNORE ? "WTD_STATEACTION_IGNORE" : "other");
    LogInfo("    hWVTStateData: 0x%p", pData->hWVTStateData);
    LogInfo("    dwUnionChoice: %lu (%s)", pData->dwUnionChoice, pData->dwUnionChoice == WTD_CHOICE_FILE ? "WTD_CHOICE_FILE" : pData->dwUnionChoice == WTD_CHOICE_CATALOG ? "WTD_CHOICE_CATALOG" : pData->dwUnionChoice == WTD_CHOICE_BLOB ? "WTD_CHOICE_BLOB" : "other");
    LogInfo("    dwUIChoice: %lu (%s)", pData->dwUIChoice, pData->dwUIChoice == WTD_UI_ALL ? "WTD_UI_ALL" : pData->dwUIChoice == WTD_UI_NONE ? "WTD_UI_NONE" : pData->dwUIChoice == WTD_UI_NOBAD ? "WTD_UI_NOBAD" : "other");
    LogInfo("    fdwRevocationChecks: 0x%08lX", pData->fdwRevocationChecks);
    LogRevocationChecks(pData->fdwRevocationChecks);
    LogInfo("    dwProvFlags: 0x%08lX", pData->dwProvFlags);
    LogProvFlags(pData->dwProvFlags);
    LogInfo("    dwUIContext: %lu (%s)", pData->dwUIContext, pData->dwUIContext == WTD_UICONTEXT_EXECUTE ? "WTD_UICONTEXT_EXECUTE" : pData->dwUIContext == WTD_UICONTEXT_INSTALL ? "WTD_UICONTEXT_INSTALL" : "other");
    switch(pData->dwUnionChoice) { case WTD_CHOICE_FILE: if (pData->pFile) { LogInfo("      File Path: %S", pData->pFile->pcwszFilePath ? pData->pFile->pcwszFilePath : L"<NULL>"); LogInfo("      File Handle: 0x%p", pData->pFile->hFile); } break; }
    if (pData->dwStateAction == WTD_STATEACTION_VERIFY) { LogInfo("  Processing WTD_STATEACTION_VERIFY..."); CRYPT_PROVIDER_DATA* new_state_data = (CRYPT_PROVIDER_DATA*)SAFE_ALLOC(sizeof(CRYPT_PROVIDER_DATA)); if (new_state_data) { memcpy(new_state_data, &g_fake_prov_data, sizeof(CRYPT_PROVIDER_DATA)); pData->hWVTStateData = AddObjectToList(&g_wvt_state_list, &g_wvt_list_lock, new_state_data); if (pData->hWVTStateData) { LogInfo("  Created state data at 0x%p", pData->hWVTStateData); } else { LogError("  Failed to add new state data to list!"); SAFE_FREE(new_state_data); } }
    } else if (pData->dwStateAction == WTD_STATEACTION_CLOSE) { LogInfo("  Processing WTD_STATEACTION_CLOSE..."); if (RemoveObjectFromList(&g_wvt_state_list, &g_wvt_list_lock, pData->hWVTStateData)) { LogInfo("  Freed state data: 0x%p", pData->hWVTStateData); pData->hWVTStateData = NULL; } }
    LogInfo("  Returning: ERROR_SUCCESS (0)"); LogInfo("------------------------------------------------------------\n"); return 0;
}
LONG WINAPI EXLOUD_WinVerifyTrustEx(HWND hwnd, GUID* pgActionID, WINTRUST_DATA* pWinTrustData) { LogInfo("WinVerifyTrustEx called"); return EXLOUD_WinVerifyTrust(hwnd, pgActionID, pWinTrustData); }

BOOL WINAPI EXLOUD_CryptCATAdminAcquireContext2(HCATADMIN* phCatAdmin, const GUID* pgSubsystem, PCWSTR pwszHashAlgorithm, LPVOID pStrongHashPolicy, DWORD dwFlags) { LogInfo("CryptCATAdminAcquireContext2 called"); if (!phCatAdmin) { LogError("phCatAdmin is NULL"); SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } FAKE_CATALOG* context = (FAKE_CATALOG*)SAFE_ALLOC(sizeof(FAKE_CATALOG)); if (!context) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; } context->magic = FAKE_CATALOG_MAGIC; context->in_use = TRUE; context->info.cbStruct = sizeof(CATALOG_INFO); wcscpy_s(context->info.wszCatalogFile, MAX_PATH, L"fake_catalog.cat"); *phCatAdmin = AddObjectToList(&g_cat_admin_list, &g_cat_admin_list_lock, context); if (*phCatAdmin) { LogDebug("  Created new catalog admin context: %p", *phCatAdmin); return TRUE; } else { LogError("  Failed to create/add catalog admin context!"); SAFE_FREE(context); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; } }
BOOL WINAPI EXLOUD_CryptCATAdminAcquireContext(HCATADMIN* phCatAdmin, const GUID* pgSubsystem, DWORD dwFlags) { return EXLOUD_CryptCATAdminAcquireContext2(phCatAdmin, pgSubsystem, NULL, NULL, dwFlags); }
BOOL WINAPI EXLOUD_CryptCATAdminReleaseContext(HCATADMIN hCatAdmin, DWORD dwFlags) { LogInfo("CryptCATAdminReleaseContext for: %p", hCatAdmin); if (RemoveObjectFromList(&g_cat_admin_list, &g_cat_admin_list_lock, hCatAdmin)) { LogInfo("CryptCATAdminReleaseContext succeeded"); return TRUE; } SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
HCATINFO WINAPI EXLOUD_CryptCATAdminAddCatalog(HCATADMIN hCatAdmin, PWSTR pwszCatalogFile, PWSTR pwszSelectBaseName, DWORD dwFlags) { LogInfo("CryptCATAdminAddCatalog for admin: %p", hCatAdmin); if (!FindObjectInList(g_cat_admin_list, &g_cat_admin_list_lock, hCatAdmin)) { SetLastError(ERROR_INVALID_HANDLE); return NULL; } FAKE_CATALOG* catalog = (FAKE_CATALOG*)SAFE_ALLOC(sizeof(FAKE_CATALOG)); if (!catalog) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; } catalog->magic = FAKE_CATALOG_MAGIC; catalog->in_use = TRUE; catalog->info.cbStruct = sizeof(CATALOG_INFO); if (pwszCatalogFile) { wcsncpy(catalog->info.wszCatalogFile, pwszCatalogFile, MAX_PATH - 1); } HCATINFO new_cat_info = AddObjectToList(&g_cat_info_list, &g_cat_info_list_lock, catalog); if (new_cat_info) { LogDebug("Created HCATINFO: %p", new_cat_info); } else { SAFE_FREE(catalog); } return new_cat_info; }
BOOL WINAPI EXLOUD_CryptCATAdminReleaseCatalogContext(HCATADMIN hCatAdmin, HCATINFO hCatInfo, DWORD dwFlags) { LogInfo("CryptCATAdminReleaseCatalogContext for info: %p", hCatInfo); if (RemoveObjectFromList(&g_cat_info_list, &g_cat_info_list_lock, hCatInfo)) { LogDebug("Released HCATINFO: %p", hCatInfo); return TRUE; } SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
BOOL WINAPI EXLOUD_CryptCATAdminCalcHashFromFileHandle(HANDLE hFile, DWORD* pcbHash, BYTE* pbHash, DWORD dwFlags) { LogInfo("CryptCATAdminCalcHashFromFileHandle called"); return handle_hash_buffer(NULL, hFile, pcbHash, pbHash); }
BOOL WINAPI EXLOUD_CryptCATAdminCalcHashFromFileHandle2(HCATADMIN hCatAdmin, HANDLE hFile, DWORD* pcbHash, BYTE* pbHash, DWORD dwFlags) { LogInfo("CryptCATAdminCalcHashFromFileHandle2 called"); return handle_hash_buffer(NULL, hFile, pcbHash, pbHash); }
BOOL WINAPI EXLOUD_CryptCATAdminCalcHashFromFileHandle3(HCATADMIN hCatAdmin, HANDLE hFile, DWORD* pcbHash, BYTE* pbHash, DWORD dwFlags) { LogInfo("CryptCATAdminCalcHashFromFileHandle3 called"); return handle_hash_buffer(NULL, hFile, pcbHash, pbHash); }
HCATINFO WINAPI EXLOUD_CryptCATAdminEnumCatalogFromHash(HCATADMIN hCatAdmin, BYTE* pbHash, DWORD cbHash, DWORD dwFlags, HCATINFO* phPrevCatInfo) { LogInfo("CryptCATAdminEnumCatalogFromHash called"); LogHexBuffer(LOG_LEVEL_INFO, __FUNCTION__, "  Searching for Hash", pbHash, cbHash); if (phPrevCatInfo && *phPrevCatInfo) { if (FindObjectInList(g_cat_info_list, &g_cat_info_list_lock, *phPrevCatInfo)) { LogDebug("  Previous catalog info handle %p was valid. No more catalogs found.", *phPrevCatInfo); } } SetLastError(ERROR_NOT_FOUND); LogInfo("  No catalogs found for this hash. Returning NULL."); return NULL; }
BOOL WINAPI EXLOUD_CryptCATCatalogInfoFromContext(HCATINFO hCatInfo, CATALOG_INFO* psCatInfo, DWORD dwFlags) { LogInfo("CryptCATCatalogInfoFromContext for info: %p", hCatInfo); if (!psCatInfo) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } if (FindObjectInList(g_cat_info_list, &g_cat_info_list_lock, hCatInfo)) { FAKE_CATALOG* catalog = (FAKE_CATALOG*)hCatInfo; if (catalog->magic == FAKE_CATALOG_MAGIC) { memcpy(psCatInfo, &catalog->info, sizeof(CATALOG_INFO)); return TRUE; } } SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
HANDLE WINAPI EXLOUD_CryptCATOpen(LPWSTR pwszFileName, DWORD fdwOpenFlags, HCRYPTPROV hProv, DWORD dwPublicVersion, DWORD dwEncodingType) { LogInfo("CryptCATOpen with file: %S", pwszFileName ? pwszFileName : L"<NULL>"); FAKE_CATALOG* catalog = (FAKE_CATALOG*)SAFE_ALLOC(sizeof(FAKE_CATALOG)); if (!catalog) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return INVALID_HANDLE_VALUE; } catalog->magic = FAKE_CATALOG_MAGIC; catalog->in_use = TRUE; catalog->info.cbStruct = sizeof(CATALOG_INFO); if (pwszFileName) { wcsncpy(catalog->info.wszCatalogFile, pwszFileName, MAX_PATH - 1); } HANDLE hCatalog = AddObjectToList(&g_cat_handle_list, &g_cat_handle_list_lock, catalog); if (hCatalog) { LogDebug("Opened catalog, handle: %p", hCatalog); return hCatalog; } SAFE_FREE(catalog); return INVALID_HANDLE_VALUE; }
BOOL WINAPI EXLOUD_CryptCATClose(HANDLE hCatalog) { LogInfo("CryptCATClose for handle: %p", hCatalog); if (RemoveObjectFromList(&g_cat_handle_list, &g_cat_handle_list_lock, hCatalog)) { LogDebug("Closed catalog handle successfully"); return TRUE; } SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
CRYPT_PROVIDER_DATA* WINAPI EXLOUD_WTHelperProvDataFromStateData(HANDLE hStateData) { LogInfo("WTHelperProvDataFromStateData for handle: %p", hStateData); if (FindObjectInList(g_wvt_state_list, &g_wvt_list_lock, hStateData)) { LogDebug("Found valid state data handle."); return (CRYPT_PROVIDER_DATA*)hStateData; } LogWarning("Unknown or invalid state data handle."); return NULL; }
HRESULT WINAPI EXLOUD_WintrustGetHash(HANDLE hFile, LPCWSTR pwszFilePath, GUID *pgActionID, LPVOID pvReserved, DWORD *pcbHash, BYTE *pbHash) { LogDebug("WintrustGetHash called"); LogDebug("  File: %S, Handle: 0x%p", pwszFilePath ? pwszFilePath : L"<NULL>", hFile); if (handle_hash_buffer(pwszFilePath, hFile, pcbHash, pbHash)) { return S_OK; } return HRESULT_FROM_WIN32(GetLastError()); }
BOOL WINAPI EXLOUD_AddPersonalTrustDBPages(HWND hwndParent, DWORD dwFlags) { LogDebug("STUB: AddPersonalTrustDBPages called"); return TRUE; }
HRESULT WINAPI EXLOUD_CatalogCompactHashDatabase(LPCWSTR pwszDbFileName, DWORD dwFlags) { LogDebug("STUB: CatalogCompactHashDatabase called"); return S_OK; }
HRESULT WINAPI EXLOUD_ComputeFirstPageHash(LPCWSTR lpwszFilePath, CATALOG_INFO* pCatInfo, LARGE_INTEGER* pliFileSize, BYTE* pbCalculatedHash, DWORD* pcbCalculatedHash) { LogDebug("STUB: ComputeFirstPageHash called"); if (pcbCalculatedHash) { if (!pbCalculatedHash || *pcbCalculatedHash < FAKE_HASH_SIZE) { *pcbCalculatedHash = FAKE_HASH_SIZE; return E_MOREDATA; } memset(pbCalculatedHash, 0, FAKE_HASH_SIZE); *pcbCalculatedHash = FAKE_HASH_SIZE; } return S_OK; }
HRESULT WINAPI EXLOUD_ConfigCiFinalPolicy(LPVOID p) { LogDebug("STUB: ConfigCiFinalPolicy called"); return S_OK; }
HRESULT WINAPI EXLOUD_ConfigCiPackageFamilyNameCheck(PCWSTR packageFamilyName, LPVOID reserved) { LogDebug("STUB: ConfigCiPackageFamilyNameCheck called"); return S_OK; }
LPVOID WINAPI EXLOUD_CryptCATAllocSortedMemberInfo(HANDLE h, WCHAR* p) { return SAFE_ALLOC(sizeof(CRYPTCATMEMBER)); }
BOOL WINAPI EXLOUD_CryptCATAdminRemoveCatalog(HCATADMIN hCatAdmin, LPCWSTR pwszCatalogFile, DWORD dwFlags) { LogDebug("STUB: CryptCATAdminRemoveCatalog called"); return TRUE; }
BOOL WINAPI EXLOUD_CryptCATAdminPauseServiceForBackup(BOOL fPause, DWORD dwFlags) { LogDebug("STUB: CryptCATAdminPauseServiceForBackup called"); return TRUE; }
BOOL WINAPI EXLOUD_CryptCATAdminResolveCatalogPath(HCATADMIN hCatAdmin, WCHAR* pwszCatalogFile, CATALOG_INFO* psCatInfo, DWORD dwFlags) { LogDebug("STUB: CryptCATAdminResolveCatalogPath called"); SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }
CRYPTCATATTRIBUTE* WINAPI EXLOUD_CryptCATCDFEnumCatAttributes(CRYPTCATCDF* pCDF, CRYPTCATATTRIBUTE* pPrevAttr, PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError) { LogDebug("STUB: CryptCATCDFEnumCatAttributes called"); SetLastError(ERROR_NOT_FOUND); return NULL; }
CRYPTCATMEMBER* WINAPI EXLOUD_CryptCATCDFEnumMembers(CRYPTCATCDF* pCDF, CRYPTCATMEMBER* pPrevMember, PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError) { LogDebug("STUB: CryptCATCDFEnumMembers called"); SetLastError(ERROR_NOT_FOUND); return NULL; }
CRYPTCATMEMBER* WINAPI EXLOUD_CryptCATCDFEnumMembersByCDFTag(CRYPTCATCDF* pCDF, LPWSTR pwszMemberTag, PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError, CRYPTCATMEMBER* pPrevMember) { LogDebug("STUB: CryptCATCDFEnumMembersByCDFTag called"); SetLastError(ERROR_NOT_FOUND); return NULL; }
CRYPTCATMEMBER* WINAPI EXLOUD_CryptCATCDFEnumMembersByCDFTagEx(CRYPTCATCDF* pCDF, LPWSTR pwszMemberTag, PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError, CRYPTCATMEMBER* pPrevMember, DWORD dwFlags, LPVOID pvReserved) { LogDebug("STUB: CryptCATCDFEnumMembersByCDFTagEx called"); SetLastError(ERROR_NOT_FOUND); return NULL; }
CRYPTCATATTRIBUTE* WINAPI EXLOUD_CryptCATCDFEnumAttributes(CRYPTCATCDF* pCDF, CRYPTCATMEMBER* pMember, CRYPTCATATTRIBUTE* pPrevAttr, PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError) { LogDebug("STUB: CryptCATCDFEnumAttributes called"); SetLastError(ERROR_NOT_FOUND); return NULL; }
CRYPTCATATTRIBUTE* WINAPI EXLOUD_CryptCATCDFEnumAttributesWithCDFTag(CRYPTCATCDF* pCDF, LPWSTR pwszMemberTag, CRYPTCATMEMBER* pMember, CRYPTCATATTRIBUTE* pPrevAttr, PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError) { LogDebug("STUB: CryptCATCDFEnumAttributesWithCDFTag called"); SetLastError(ERROR_NOT_FOUND); return NULL; }
BOOL WINAPI EXLOUD_CryptCATCDFClose(LPVOID pCDF) { if(pCDF) SAFE_FREE(pCDF); return TRUE; }
LPVOID WINAPI EXLOUD_CryptCATCDFOpen(LPWSTR pwszFilePath, LPVOID pfnParseError) { return SAFE_ALLOC(sizeof(CRYPTCATCDF)); }
CRYPTCATATTRIBUTE* WINAPI EXLOUD_CryptCATEnumerateAttr(HANDLE hCatalog, CRYPTCATMEMBER* pCatMember, CRYPTCATATTRIBUTE* pPrevAttr) { LogDebug("STUB: CryptCATEnumerateAttr called"); SetLastError(ERROR_NOT_FOUND); return NULL; }
CRYPTCATATTRIBUTE* WINAPI EXLOUD_CryptCATEnumerateCatAttr(HANDLE hCatalog, CRYPTCATATTRIBUTE* pPrevAttr) { LogDebug("STUB: CryptCATEnumerateCatAttr called"); SetLastError(ERROR_NOT_FOUND); return NULL; }
CRYPTCATMEMBER* WINAPI EXLOUD_CryptCATEnumerateMember(HANDLE hCatalog, CRYPTCATMEMBER* pPrevMember) { LogDebug("STUB: CryptCATEnumerateMember called"); SetLastError(ERROR_NOT_FOUND); return NULL; }
void WINAPI EXLOUD_CryptCATFreeSortedMemberInfo(HANDLE h, LPVOID m) { if(m) SAFE_FREE(m); }
CRYPTCATATTRIBUTE* WINAPI EXLOUD_CryptCATGetAttrInfo(HANDLE hCatalog, CRYPTCATMEMBER* pCatMember, LPWSTR pwszReferenceTag) { LogDebug("STUB: CryptCATGetAttrInfo called"); SetLastError(ERROR_NOT_FOUND); return NULL; }
CRYPTCATATTRIBUTE* WINAPI EXLOUD_CryptCATGetCatAttrInfo(HANDLE hCatalog, LPWSTR pwszReferenceTag) { LogDebug("STUB: CryptCATGetCatAttrInfo called"); SetLastError(ERROR_NOT_FOUND); return NULL; }
CRYPTCATMEMBER* WINAPI EXLOUD_CryptCATGetMemberInfo(HANDLE hCatalog, LPWSTR pwszReferenceTag) { LogDebug("STUB: CryptCATGetMemberInfo called"); SetLastError(ERROR_NOT_FOUND); return NULL; }
BOOL WINAPI EXLOUD_CryptCATHandleFromStore(CRYPTCATSTORE* pCatStore, HCATADMIN* phCatAdmin) { LogDebug("STUB: CryptCATHandleFromStore called"); SetLastError(ERROR_NOT_FOUND); return FALSE; }
BOOL WINAPI EXLOUD_CryptCATPersistStore(HANDLE hCatalog) { LogDebug("STUB: CryptCATPersistStore called"); return TRUE; }
CRYPTCATATTRIBUTE* WINAPI EXLOUD_CryptCATPutAttrInfo(HANDLE h, CRYPTCATMEMBER* p, LPWSTR t, DWORD d, DWORD c, BYTE* b) { LogDebug("STUB: CryptCATPutAttrInfo called"); return (CRYPTCATATTRIBUTE*)SAFE_ALLOC(sizeof(CRYPTCATATTRIBUTE)); }
CRYPTCATATTRIBUTE* WINAPI EXLOUD_CryptCATPutCatAttrInfo(HANDLE h, LPWSTR t, DWORD d, DWORD c, BYTE *b) { LogDebug("STUB: CryptCATPutCatAttrInfo called"); return (CRYPTCATATTRIBUTE*)SAFE_ALLOC(sizeof(CRYPTCATATTRIBUTE)); }
CRYPTCATMEMBER* WINAPI EXLOUD_CryptCATPutMemberInfo(HANDLE h, LPWSTR f, LPWSTR t, GUID* g, DWORD v, DWORD c, BYTE* b) { LogDebug("STUB: CryptCATPutMemberInfo called"); return (CRYPTCATMEMBER*)SAFE_ALLOC(sizeof(CRYPTCATMEMBER)); }
CRYPTCATSTORE* WINAPI EXLOUD_CryptCATStoreFromHandle(HANDLE hCatalog) { LogDebug("STUB: CryptCATStoreFromHandle called"); return NULL; }
BOOL WINAPI EXLOUD_CryptCATVerifyMember(HANDLE hCatalog, CRYPTCATMEMBER *pCatMember) { LogDebug("STUB: CryptCATVerifyMember called - always TRUE"); return TRUE; }
BOOL WINAPI EXLOUD_CryptSIPCreateIndirectData(SIP_SUBJECTINFO *pSubjectInfo, DWORD *pcbIndirectData, SIP_INDIRECT_DATA *pIndirectData) { LogDebug("STUB: CryptSIPCreateIndirectData called"); SetLastError(TRUST_E_NOSIGNATURE); return FALSE; }
BOOL WINAPI EXLOUD_CryptSIPGetCaps(SIP_SUBJECTINFO *pSubjectInfo, SIP_CAPS *pCaps) { LogDebug("STUB: CryptSIPGetCaps called"); if (pCaps) { pCaps->dwVersion = 2; } return TRUE; }
BOOL WINAPI EXLOUD_CryptSIPGetInfo(SIP_SUBJECTINFO *pSubjectInfo, SIP_INFO *pInfo) { LogDebug("STUB: CryptSIPGetInfo called"); SetLastError(ERROR_NOT_FOUND); return FALSE; }
BOOL WINAPI EXLOUD_CryptSIPGetRegWorkingFlags(DWORD *pdwFlags) { LogDebug("STUB: CryptSIPGetRegWorkingFlags called"); if (pdwFlags) *pdwFlags = 0; return TRUE; }
BOOL WINAPI EXLOUD_CryptSIPGetSealedDigest(SIP_SUBJECTINFO* p, const BYTE* s, DWORD d, BYTE* b, DWORD* c) { LogDebug("STUB: CryptSIPGetSealedDigest called"); return FALSE; }
BOOL WINAPI EXLOUD_CryptSIPGetSignedDataMsg(LPVOID p, DWORD* e, DWORD i, DWORD* cb, BYTE* b) { LogDebug("STUB: CryptSIPGetSignedDataMsg called"); SetLastError(TRUST_E_NOSIGNATURE); return FALSE; }
BOOL WINAPI EXLOUD_CryptSIPPutSignedDataMsg(SIP_SUBJECTINFO* p, DWORD e, DWORD* i, DWORD c, BYTE* b) { LogDebug("STUB: CryptSIPPutSignedDataMsg called"); if(i) *i = 0; return TRUE; }
BOOL WINAPI EXLOUD_CryptSIPRemoveSignedDataMsg(SIP_SUBJECTINFO *pSubjectInfo, DWORD dwIndex) { LogDebug("STUB: CryptSIPRemoveSignedDataMsg called"); return TRUE; }
BOOL WINAPI EXLOUD_CryptSIPVerifyIndirectData(SIP_SUBJECTINFO *p, SIP_INDIRECT_DATA *d) { LogDebug("STUB: CryptSIPVerifyIndirectData called - always TRUE"); return TRUE; }
HRESULT WINAPI EXLOUD_DllRegisterServer(void) { LogDebug("STUB: DllRegisterServer called"); return S_OK; }
HRESULT WINAPI EXLOUD_DllUnregisterServer(void) { LogDebug("STUB: DllUnregisterServer called"); return S_OK; }
PCCERT_CONTEXT WINAPI EXLOUD_FindCertsByIssuer(HCERTSTORE s, PCCTL_CONTEXT c, const WCHAR* i, PCCERT_CONTEXT p) { LogDebug("STUB: FindCertsByIssuer called"); return NULL; }
HRESULT WINAPI EXLOUD_GetAuthenticodeSha256Hash(HANDLE h, LPCWSTR p, BYTE* b, DWORD* c) { LogDebug("STUB: GetAuthenticodeSha256Hash called"); return E_NOTIMPL; }
BOOL WINAPI EXLOUD_IsCatalogFile(HANDLE hFile, WCHAR *pwszFileName) { LogDebug("STUB: IsCatalogFile called"); return FALSE; }
LPVOID WINAPI EXLOUD_MsCatConstructHashTag(DWORD cbHash, BYTE *pbHash) { LogDebug("STUB: MsCatConstructHashTag called"); return NULL; }
void WINAPI EXLOUD_MsCatFreeHashTag(LPVOID pbHashTag) { LogDebug("STUB: MsCatFreeHashTag called"); }
BOOL WINAPI EXLOUD_OpenPersonalTrustDBDialog(HWND hwndParent) { LogDebug("STUB: OpenPersonalTrustDBDialog called"); return TRUE; }
BOOL WINAPI EXLOUD_OpenPersonalTrustDBDialogEx(HWND h, DWORD f, PVOID* r) { LogDebug("STUB: OpenPersonalTrustDBDialogEx called"); return TRUE; }
void WINAPI EXLOUD_SetMessageDigestInfo(PCRYPT_ATTRIBUTES a, PCMSG_SIGNER_INFO i, DWORD d) { LogDebug("STUB: SetMessageDigestInfo called"); }
HRESULT WINAPI EXLOUD_SoftpubAuthenticode(LPVOID p) { LogDebug("STUB: SoftpubAuthenticode called"); return S_OK; }
HRESULT WINAPI EXLOUD_SoftpubCheckCert(LPVOID p) { LogDebug("STUB: SoftpubCheckCert called"); return S_OK; }
HRESULT WINAPI EXLOUD_SoftpubCleanup(LPVOID p) { LogDebug("STUB: SoftpubCleanup called"); return S_OK; }
HRESULT WINAPI EXLOUD_SoftpubDefCertInit(LPVOID p) { LogDebug("STUB: SoftpubDefCertInit called"); return S_OK; }
HRESULT WINAPI EXLOUD_SoftpubDllRegisterServer(void) { LogDebug("STUB: SoftpubDllRegisterServer called"); return S_OK; }
HRESULT WINAPI EXLOUD_SoftpubDllUnregisterServer(void) { LogDebug("STUB: SoftpubDllUnregisterServer called"); return S_OK; }
void WINAPI EXLOUD_SoftpubDumpStructure(WINTRUST_DATA *p) { LogDebug("STUB: SoftpubDumpStructure called"); }
void WINAPI EXLOUD_SoftpubFreeDefUsageCallData(const char *u, LPVOID d) { LogDebug("STUB: SoftpubFreeDefUsageCallData called"); }
HRESULT WINAPI EXLOUD_SoftpubInitialize(LPVOID p) { LogDebug("STUB: SoftpubInitialize called"); return S_OK; }
HRESULT WINAPI EXLOUD_SoftpubLoadDefUsageCallData(const char *u, LPVOID d) { LogDebug("STUB: SoftpubLoadDefUsageCallData called"); return E_NOTIMPL; }
BOOL WINAPI EXLOUD_SoftpubLoadMessage(SIP_SUBJECTINFO *p, HCRYPTMSG *h) { LogDebug("STUB: SoftpubLoadMessage called"); return FALSE; }
BOOL WINAPI EXLOUD_SoftpubLoadSignature(SIP_SUBJECTINFO *p, DWORD g, PCRYPT_ATTRIBUTE_TYPE_VALUE *a, DWORD *c, BYTE *b) { LogDebug("STUB: SoftpubLoadSignature called"); return FALSE; }
HRESULT WINAPI EXLOUD_SrpCheckSmartlockerEAandProcessToken(LPCWSTR p, HANDLE h) { LogDebug("STUB: SrpCheckSmartlockerEAandProcessToken called"); return S_OK; }
BOOL WINAPI EXLOUD_TrustDecode(HWND h, LPWSTR d, LPWSTR f, CRYPT_DATA_BLOB *b) { LogDebug("STUB: TrustDecode called"); return FALSE; }
PCCERT_CONTEXT WINAPI EXLOUD_TrustFindIssuerCertificate(PCCERT_CONTEXT p, HCERTSTORE h, DWORD f, LPVOID v) { LogDebug("STUB: TrustFindIssuerCertificate called"); return NULL; }
void WINAPI EXLOUD_TrustFreeDecode(CRYPT_DATA_BLOB *p) { LogDebug("STUB: TrustFreeDecode called"); }
BOOL WINAPI EXLOUD_TrustIsCertificateSelfSigned(PCCERT_CONTEXT p, DWORD e, DWORD f) { LogDebug("STUB: TrustIsCertificateSelfSigned called"); return FALSE; }
BOOL WINAPI EXLOUD_TrustOpenStores(CRYPT_PROVIDER_DATA *p, const WCHAR *u, DWORD f) { LogDebug("STUB: TrustOpenStores called"); return FALSE; }
void WINAPI EXLOUD_WTConfigCiFreePrivateData(LPVOID p) { LogDebug("STUB: WTConfigCiFreePrivateData called"); }
HRESULT WINAPI EXLOUD_WTConvertCertCtxToChainInfo(PCCERT_CONTEXT p, LPVOID i) { LogDebug("STUB: WTConvertCertCtxToChainInfo called"); return E_NOTIMPL; }
HRESULT WINAPI EXLOUD_WTGetBioSignatureInfo(LPVOID d, LPVOID i) { LogDebug("STUB: WTGetBioSignatureInfo called"); return E_NOTIMPL; }
HRESULT WINAPI EXLOUD_WTGetPluginSignatureInfo(HANDLE h, LPVOID s, LPVOID i, LPVOID d) { LogDebug("STUB: WTGetPluginSignatureInfo called"); return E_NOTIMPL; }
HRESULT WINAPI EXLOUD_WTGetSignatureInfo(LPCWSTR f, HANDLE h, DWORD d, LPVOID i, LPVOID s, LPVOID c) { LogDebug("STUB: WTGetSignatureInfo called - returning TRUST_E_NOSIGNATURE"); return TRUST_E_NOSIGNATURE; }
HRESULT WINAPI EXLOUD_WTHelperCertCheckValidSignature(CRYPT_PROVIDER_DATA *p) { LogDebug("STUB: WTHelperCertCheckValidSignature called - returning S_OK"); return S_OK; }
PCCERT_CONTEXT WINAPI EXLOUD_WTHelperCertFindIssuerCertificate(HCERTSTORE s, PCCERT_CONTEXT c, DWORD f, LPVOID v, PCCERT_CONTEXT p) { LogDebug("STUB: WTHelperCertFindIssuerCertificate called"); return NULL; }
BOOL WINAPI EXLOUD_WTHelperCertIsSelfSigned(DWORD e, PCERT_INFO p) { LogDebug("STUB: WTHelperCertIsSelfSigned called"); return FALSE; }
BOOL WINAPI EXLOUD_WTHelperCheckCertUsage(CRYPT_PROVIDER_CERT *p) { LogDebug("STUB: WTHelperCheckCertUsage called - returning TRUE"); return TRUE; }
BOOL WINAPI EXLOUD_WTHelperGetAgencyInfo(PCCERT_CONTEXT p, PCERT_AUTHORITY_INFO_ACCESS i) { LogDebug("STUB: WTHelperGetAgencyInfo called"); return FALSE; }
HANDLE WINAPI EXLOUD_WTHelperGetFileHandle(LPCWSTR p, DWORD a, DWORD s, DWORD c, LPVOID v) { LogDebug("STUB: WTHelperGetFileHandle called"); return INVALID_HANDLE_VALUE; }
HRESULT WINAPI EXLOUD_WTHelperGetFileHash(LPCWSTR p, DWORD f, LPVOID v, BYTE *b, DWORD *c, BYTE *a) { LogDebug("STUB: WTHelperGetFileHash called"); return E_NOTIMPL; }
WCHAR* WINAPI EXLOUD_WTHelperGetFileName(WINTRUST_DATA *p) { LogDebug("STUB: WTHelperGetFileName called"); return NULL; }
BOOL WINAPI EXLOUD_WTHelperGetKnownUsages(BOOL f, PCTL_USAGE *r) { LogDebug("STUB: WTHelperGetKnownUsages called"); return FALSE; }
PCCERT_CONTEXT WINAPI EXLOUD_WTHelperGetProvCertFromChain(CRYPT_PROVIDER_SGNR *p, DWORD i) { LogDebug("STUB: WTHelperGetProvCertFromChain called"); return NULL; }
CRYPT_PROVIDER_PRIVDATA* WINAPI EXLOUD_WTHelperGetProvPrivateDataFromChain(CRYPT_PROVIDER_DATA *p, GUID *g) { LogDebug("STUB: WTHelperGetProvPrivateDataFromChain called"); return NULL; }
LPVOID WINAPI EXLOUD_WTHelperGetProvSignerFromChain(LPVOID d, DWORD s, BOOL c, DWORD cs) { LogDebug("STUB: WTHelperGetProvSignerFromChain called"); return NULL; }
BOOL WINAPI EXLOUD_WTHelperIsChainedToMicrosoft(CRYPT_PROVIDER_DATA *p) { LogDebug("STUB: WTHelperIsChainedToMicrosoft called"); return FALSE; }
BOOL WINAPI EXLOUD_WTHelperIsChainedToMicrosoftFromStateData(HANDLE h) { LogDebug("STUB: WTHelperIsChainedToMicrosoftFromStateData called"); return FALSE; }
BOOL WINAPI EXLOUD_WTHelperIsInRootStore(CRYPT_PROVIDER_CERT *p) { LogDebug("STUB: WTHelperIsInRootStore called"); return FALSE; }
BOOL WINAPI EXLOUD_WTHelperOpenKnownStores(CRYPT_PROVIDER_DATA *p) { LogDebug("STUB: WTHelperOpenKnownStores called - returning TRUE"); return TRUE; }
BOOL WINAPI EXLOUD_WTIsFirstConfigCiResultPreferred(LPVOID r, LPVOID p) { LogDebug("STUB: WTIsFirstConfigCiResultPreferred called"); return FALSE; }
HRESULT WINAPI EXLOUD_WTLogConfigCiScriptEvent(LPVOID p, LPVOID e) { LogDebug("STUB: WTLogConfigCiScriptEvent called"); return S_OK; }
HRESULT WINAPI EXLOUD_WTLogConfigCiScriptEvent2(LPVOID p, LPVOID e) { LogDebug("STUB: WTLogConfigCiScriptEvent2 called"); return S_OK; }
HRESULT WINAPI EXLOUD_WTLogConfigCiSignerEvent(LPVOID s, LPVOID i, BOOL a) { LogDebug("STUB: WTLogConfigCiSignerEvent called"); return S_OK; }
HRESULT WINAPI EXLOUD_WTValidateBioSignaturePolicy(LPVOID s, LPVOID p) { LogDebug("STUB: WTValidateBioSignaturePolicy called"); return E_NOTIMPL; }
BOOL WINAPI EXLOUD_WVTAsn1CatMemberInfo2Decode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1CatMemberInfo2Decode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1CatMemberInfo2Encode(LPCSTR l, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1CatMemberInfo2Encode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1CatMemberInfoDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1CatMemberInfoDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1CatMemberInfoEncode(LPCSTR l, DWORD f, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1CatMemberInfoEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1CatNameValueDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1CatNameValueDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1CatNameValueEncode(LPCSTR l, DWORD f, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1CatNameValueEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1IntentToSealAttributeDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1IntentToSealAttributeDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1IntentToSealAttributeEncode(LPCSTR l, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1IntentToSealAttributeEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SealingSignatureAttributeDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1SealingSignatureAttributeDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SealingSignatureAttributeEncode(LPCSTR l, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1SealingSignatureAttributeEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SealingTimestampAttributeDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1SealingTimestampAttributeDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SealingTimestampAttributeEncode(LPCSTR l, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1SealingTimestampAttributeEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcFinancialCriteriaInfoDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1SpcFinancialCriteriaInfoDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcFinancialCriteriaInfoEncode(LPCSTR l, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1SpcFinancialCriteriaInfoEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcIndirectDataContentDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1SpcIndirectDataContentDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcIndirectDataContentEncode(LPCSTR l, DWORD f, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1SpcIndirectDataContentEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcLinkDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1SpcLinkDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcLinkEncode(LPCSTR l, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1SpcLinkEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcMinimalCriteriaInfoDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1SpcMinimalCriteriaInfoDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcMinimalCriteriaInfoEncode(LPCSTR l, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1SpcMinimalCriteriaInfoEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcPeImageDataDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1SpcPeImageDataDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcPeImageDataEncode(LPCSTR l, DWORD f, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1SpcPeImageDataEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcSigInfoDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1SpcSigInfoDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcSigInfoEncode(LPCSTR l, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1SpcSigInfoEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcSpAgencyInfoDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1SpcSpAgencyInfoDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcSpAgencyInfoEncode(LPCSTR l, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1SpcSpAgencyInfoEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcSpOpusInfoDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1SpcSpOpusInfoDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcSpOpusInfoEncode(LPCSTR l, DWORD f, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1SpcSpOpusInfoEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcStatementTypeDecode(LPCSTR l, const BYTE *e, DWORD c, DWORD f, PFN_CRYPT_ALLOC a, PFN_CRYPT_FREE fr, void *i, DWORD *cb) { LogDebug("STUB: WVTAsn1SpcStatementTypeDecode called"); SetLastError(ERROR_INVALID_DATA); return FALSE; }
BOOL WINAPI EXLOUD_WVTAsn1SpcStatementTypeEncode(LPCSTR l, DWORD f, void *i, DWORD *pcb) { LogDebug("STUB: WVTAsn1SpcStatementTypeEncode called"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI EXLOUD_WintrustAddActionID(GUID *g, DWORD f, CRYPT_REGISTER_ACTIONID *p) { LogDebug("STUB: WintrustAddActionID called"); return TRUE; }
BOOL WINAPI EXLOUD_WintrustAddDefaultForUsage(const char *u, CRYPT_PROVIDER_REGDEFUSAGE *p) { LogDebug("STUB: WintrustAddDefaultForUsage called"); return TRUE; }
HRESULT WINAPI EXLOUD_WintrustAddProviderToProcess(GUID *p, GUID *a, WCHAR *d, DWORD m, CRYPT_PROVIDER_DEFINITION *s) { LogDebug("STUB: WintrustAddProviderToProcess called"); return S_OK; }
HRESULT WINAPI EXLOUD_WintrustCertificateTrust(WINTRUST_DATA *p) { LogDebug("STUB: WintrustCertificateTrust called"); return S_OK; }
BOOL WINAPI EXLOUD_WintrustGetDefaultForUsage(DWORD a, const char *u, CRYPT_PROVIDER_DEFUSAGE *s) { LogDebug("STUB: WintrustGetDefaultForUsage called"); return FALSE; }
void WINAPI EXLOUD_WintrustGetRegPolicyFlags(DWORD *p) { LogDebug("STUB: WintrustGetRegPolicyFlags called"); if (p) *p = 0; }
BOOL WINAPI EXLOUD_WintrustLoadFunctionPointers(GUID *g, CRYPT_PROVIDER_FUNCTIONS *f) { LogDebug("STUB: WintrustLoadFunctionPointers called"); return TRUE; }
BOOL WINAPI EXLOUD_WintrustRemoveActionID(GUID *g) { LogDebug("STUB: WintrustRemoveActionID called"); return TRUE; }
void WINAPI EXLOUD_WintrustSetDefaultIncludePEPageHashes(BOOL f) { LogDebug("STUB: WintrustSetDefaultIncludePEPageHashes called"); }
BOOL WINAPI EXLOUD_WintrustSetRegPolicyFlags(DWORD d) { LogDebug("STUB: WintrustSetRegPolicyFlags called"); return TRUE; }
BOOL WINAPI EXLOUD_WintrustUserWriteabilityCheck(HWND h, GUID *g) { LogDebug("STUB: WintrustUserWriteabilityCheck called"); return TRUE; }
HRESULT WINAPI EXLOUD_mscat32DllRegisterServer(void) { LogDebug("STUB: mscat32DllRegisterServer called"); return S_OK; }
HRESULT WINAPI EXLOUD_mscat32DllUnregisterServer(void) { LogDebug("STUB: mscat32DllUnregisterServer called"); return S_OK; }
HRESULT WINAPI EXLOUD_mssip32DllRegisterServer(void) { LogDebug("STUB: mssip32DllRegisterServer called"); return S_OK; }
HRESULT WINAPI EXLOUD_mssip32DllUnregisterServer(void) { LogDebug("STUB: mssip32DllUnregisterServer called"); return S_OK; }
HRESULT WINAPI EXLOUD_GenericChainCertificateTrust(LPVOID p) { return S_OK; }
HRESULT WINAPI EXLOUD_GenericChainFinalProv(LPVOID p) { return S_OK; }
HRESULT WINAPI EXLOUD_HTTPSCertificateTrust(LPVOID p) { return S_OK; }
HRESULT WINAPI EXLOUD_HTTPSFinalProv(LPVOID p) { return S_OK; }
HRESULT WINAPI EXLOUD_OfficeInitializePolicy(LPVOID p) { return S_OK; }
void WINAPI EXLOUD_OfficeCleanupPolicy(LPVOID p) { }
HRESULT WINAPI EXLOUD_DriverInitializePolicy(LPVOID p) { return S_OK; }
HRESULT WINAPI EXLOUD_DriverCleanupPolicy(LPVOID p) { return S_OK; }
HRESULT WINAPI EXLOUD_DriverFinalPolicy(LPVOID p) { return S_OK; }

// === DLL MAIN ===
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
#if ENABLE_FILE_LOGGING
        InitializeCriticalSection(&g_log_lock);
#endif
#if ENABLE_MEMORY_TRACKING
        InitializeCriticalSection(&g_memory_lock);
#endif
        InitializeCriticalSection(&g_wvt_list_lock);
        InitializeCriticalSection(&g_cat_admin_list_lock);
        InitializeCriticalSection(&g_cat_info_list_lock);
        InitializeCriticalSection(&g_cat_handle_list_lock);
        g_locks_initialized = TRUE;
#if ENABLE_DEBUG_CONSOLE
        if (AllocConsole()) {
            FILE* fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
            freopen_s(&fDummy, "CONOUT$", "w", stderr);
            freopen_s(&fDummy, "CONIN$", "r", stdin);
            SetConsoleTitleA("Wintrust Stub Debug Console v1.0 (Final)");
            printf("=========================================================\n");
            printf("    Wintrust Stub Debug Console v1.0\n");
            printf("    Build: %s %s\n", __DATE__, __TIME__);
            printf("=========================================================\n\n");
        }
#endif
        LogInfo("=== WINTRUST STUB v1.0 LOADED ===");
        break;
    }
    case DLL_PROCESS_DETACH: {
        LogInfo("=== WINTRUST STUB v1.0 UNLOADING ===");
        if (g_locks_initialized) {
#if ENABLE_MEMORY_TRACKING
            ReportMemoryLeaks();
#endif
            LogInfo("Force-cleaning all object lists...");
            CleanupObjectList(&g_wvt_state_list, &g_wvt_list_lock, "WVT State");
            CleanupObjectList(&g_cat_admin_list, &g_cat_admin_list_lock, "CAT Admin");
            CleanupObjectList(&g_cat_info_list, &g_cat_info_list_lock, "CAT Info");
            CleanupObjectList(&g_cat_handle_list, &g_cat_handle_list_lock, "CAT Handle");
            LogInfo("Object list cleanup complete.");
#if ENABLE_MEMORY_TRACKING
            CleanupAllMemory();
#endif
            DeleteCriticalSection(&g_wvt_list_lock);
            DeleteCriticalSection(&g_cat_admin_list_lock);
            DeleteCriticalSection(&g_cat_info_list_lock);
            DeleteCriticalSection(&g_cat_handle_list_lock);
#if ENABLE_FILE_LOGGING
            if (g_log_file) { fclose(g_log_file); g_log_file = NULL; }
            DeleteCriticalSection(&g_log_lock);
#endif
#if ENABLE_MEMORY_TRACKING
            DeleteCriticalSection(&g_memory_lock);
#endif
            g_locks_initialized = FALSE;
        }
#if ENABLE_DEBUG_CONSOLE
        printf("\nStub Unloading Complete...\n"); Sleep(500); FreeConsole();
#endif
        break;
    }
    }
    return TRUE;
}