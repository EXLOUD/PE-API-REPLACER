#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// === ФАЛЛБЕКИ ДЛЯ СУМІСНОСТІ ===
// ============================================================================
#ifndef LPINTERNET_CACHE_CONFIG_INFOA
typedef void* LPINTERNET_CACHE_CONFIG_INFOA; typedef void* LPINTERNET_CACHE_CONFIG_INFOW;
#endif
#ifndef WEB_SOCKET_BUFFER_TYPE
typedef DWORD WEB_SOCKET_BUFFER_TYPE; typedef DWORD* PWEB_SOCKET_BUFFER_TYPE;
#endif
#ifndef INTERNET_COOKIE_SENT_OK
#define INTERNET_COOKIE_SENT_OK 0
#endif
#ifndef HSR_INITIATE
#define HSR_INITIATE 0x00000008
#endif
#ifndef ERROR_INTERNET_AUTODETECTION_FAILED
#define ERROR_INTERNET_AUTODETECTION_FAILED 12180
#endif
#if !defined(_tagINTERNET_COOKIE2_DEFINED) && !defined(__MINGW32__)
#define _tagINTERNET_COOKIE2_DEFINED
typedef struct { PWSTR pwszName; PWSTR pwszValue; PWSTR pwszDomain; PWSTR pwszPath; DWORD dwFlags; FILETIME ftExpires; BOOL fExpiresSet; } INTERNET_COOKIE2;
#endif

// ============================================================================
// === НАЛАГОДЖУВАЛЬНІ КОНСТАНТИ ===
// ============================================================================
#define ENABLE_DEBUG_CONSOLE    0
#define ENABLE_FILE_LOGGING     0
#define ENABLE_MEMORY_TRACKING  0 

// ============================================================================
// === СТРУКТУРИ ТА КОНСТАНТИ ДЛЯ ВІДСТЕЖЕННЯ ===
// ============================================================================
#define MAGIC_SESSION       0xDEADBEEF
#define MAGIC_CONNECT       0xCAFEBABE
#define MAGIC_REQUEST       0xFEEDFACE
#define MAGIC_FIND_HANDLE   0xDEADF11E

#define HTTP_QUERY_STATUS_CODE        19
#define HTTP_QUERY_STATUS_TEXT        20
#define HTTP_QUERY_MODIFIER_MASK      0x0000FFFF

typedef struct _FAKE_HANDLE { DWORD magic; char type_name[24]; struct _FAKE_HANDLE* parent; DWORD read_attempts; } FAKE_HANDLE;
typedef struct _MEMORY_BLOCK { void* ptr; size_t size; char function[64]; DWORD thread_id; struct _MEMORY_BLOCK* next; } MEMORY_BLOCK;
typedef struct _OBJECT_NODE { void* object; DWORD thread_id; struct _OBJECT_NODE* next; } OBJECT_NODE;
typedef enum { LOG_LEVEL_ERROR = 0, LOG_LEVEL_WARNING, LOG_LEVEL_INFO, LOG_LEVEL_DEBUG } LogLevel;

// ============================================================================
// === ГЛОБАЛЬНІ ЗМІННІ ===
// ============================================================================
#if ENABLE_FILE_LOGGING
static FILE* g_log_file = NULL; static CRITICAL_SECTION g_log_lock;
#endif
#if ENABLE_MEMORY_TRACKING
static MEMORY_BLOCK* g_memory_list = NULL; static CRITICAL_SECTION g_memory_lock; static size_t g_total_allocated = 0; static size_t g_total_freed = 0; static size_t g_allocation_count = 0;
#endif
static BOOL g_locks_initialized = FALSE; static LogLevel g_current_log_level = LOG_LEVEL_DEBUG;
static OBJECT_NODE* g_hinternet_list = NULL; static CRITICAL_SECTION g_hinternet_list_lock;

// ============================================================================
// === ФУНКЦІЇ ЛОГУВАННЯ, УПРАВЛІННЯ ПАМ'ЯТТЮ ТА ОБ'ЄКТАМИ ===
// ============================================================================
void GetTimestamp(char* buffer, size_t bufferSize) { if (!buffer || bufferSize < 20) return; SYSTEMTIME st; GetLocalTime(&st); snprintf(buffer, bufferSize, "[%02d:%02d:%02d.%03d]", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds); }
const char* GetLogLevelString(LogLevel level) { switch (level) { case LOG_LEVEL_ERROR: return "ERROR"; case LOG_LEVEL_WARNING: return "WARN "; case LOG_LEVEL_INFO: return "INFO "; case LOG_LEVEL_DEBUG: return "DEBUG"; default: return "?????"; } }
void LogMessageEx(LogLevel level, const char* function, const char* format, ...) { if (level > g_current_log_level) return; char timestamp[20] = { 0 }; GetTimestamp(timestamp, sizeof(timestamp)); va_list args; va_start(args, format);
#if ENABLE_DEBUG_CONSOLE
printf("[WININET] %s [%s] [%s] ", timestamp, GetLogLevelString(level), function); vprintf(format, args); printf("\n");
#endif
#if ENABLE_FILE_LOGGING
if (g_log_file && g_locks_initialized) { EnterCriticalSection(&g_log_lock); fprintf(g_log_file, "%s [%s] [%s] ", timestamp, GetLogLevelString(level), function); vfprintf(g_log_file, format, args); fprintf(g_log_file, "\n"); fflush(g_log_file); LeaveCriticalSection(&g_log_lock); }
#endif
va_end(args); }
#define LogError(fmt, ...)   LogMessageEx(LOG_LEVEL_ERROR, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogWarning(fmt, ...) LogMessageEx(LOG_LEVEL_WARNING, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogInfo(fmt, ...)    LogMessageEx(LOG_LEVEL_INFO, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogDebug(fmt, ...)   LogMessageEx(LOG_LEVEL_DEBUG, __FUNCTION__, fmt, ##__VA_ARGS__)
#if ENABLE_MEMORY_TRACKING
void* TrackedAlloc(size_t size, const char* function) { if (size == 0) { return NULL; } void* ptr = malloc(size); if (!ptr) { LogError("Failed to allocate %zu bytes", size); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; } memset(ptr, 0, size); if (g_locks_initialized) { EnterCriticalSection(&g_memory_lock); MEMORY_BLOCK* block = (MEMORY_BLOCK*)malloc(sizeof(MEMORY_BLOCK)); if (block) { block->ptr = ptr; block->size = size; strncpy_s(block->function, sizeof(block->function), function, _TRUNCATE); block->thread_id = GetCurrentThreadId(); block->next = g_memory_list; g_memory_list = block; g_total_allocated += size; g_allocation_count++; } LeaveCriticalSection(&g_memory_lock); } LogDebug("Allocated %zu bytes at %p", size, ptr); return ptr; }
BOOL TrackedFree(void* ptr, const char* function) { if (!ptr) return TRUE; BOOL found = FALSE; if (g_locks_initialized) { EnterCriticalSection(&g_memory_lock); MEMORY_BLOCK** current = &g_memory_list; while (*current) { if ((*current)->ptr == ptr) { MEMORY_BLOCK* block = *current; *current = block->next; g_total_freed += block->size; g_allocation_count--; LogDebug("Freed %zu bytes from %p (allocated in %s)", block->size, ptr, block->function); free(block->ptr); free(block); found = TRUE; break; } current = &(*current)->next; } LeaveCriticalSection(&g_memory_lock); } if (!found) { LogWarning("Attempt to free untracked/already freed memory: %p", ptr); free(ptr); } return found; }
void ReportMemoryLeaks() { if (!g_locks_initialized) return; EnterCriticalSection(&g_memory_lock); if (g_memory_list) { LogError("=== MEMORY LEAKS DETECTED ==="); LogError("Total leaked: %zu bytes in %zu allocations", g_total_allocated - g_total_freed, g_allocation_count); MEMORY_BLOCK* current = g_memory_list; while (current) { LogError("  Leak: %zu bytes from %s (thread %lu): %p", current->size, current->function, current->thread_id, current->ptr); current = current->next; } } else { LogInfo("No memory leaks detected."); } LeaveCriticalSection(&g_memory_lock); }
#define SAFE_ALLOC(size) TrackedAlloc(size, __FUNCTION__)
#define SAFE_FREE(ptr) TrackedFree(ptr, __FUNCTION__)
#else
#define SAFE_ALLOC(size) calloc(1, size)
#define SAFE_FREE(ptr) free(ptr)
#define ReportMemoryLeaks()
#endif
void* AddObjectToList(OBJECT_NODE** list_head, CRITICAL_SECTION* lock, void* object_data) { if (!object_data) return NULL; OBJECT_NODE* new_node = (OBJECT_NODE*)SAFE_ALLOC(sizeof(OBJECT_NODE)); if (!new_node) { LogError("Failed to allocate object node"); return NULL; } new_node->object = object_data; new_node->thread_id = GetCurrentThreadId(); EnterCriticalSection(lock); new_node->next = *list_head; *list_head = new_node; LeaveCriticalSection(lock); return object_data; }
BOOL FindObjectInList(OBJECT_NODE* list_head, CRITICAL_SECTION* lock, void* object_to_find) { if (!object_to_find) return FALSE; BOOL found = FALSE; EnterCriticalSection(lock); OBJECT_NODE* current = list_head; while (current) { if (current->object == object_to_find) { found = TRUE; break; } current = current->next; } LeaveCriticalSection(lock); if (!found) { LogWarning("Attempt to use invalid or freed handle: %p", object_to_find); } return found; }
BOOL RemoveObjectFromList(OBJECT_NODE** list_head, CRITICAL_SECTION* lock, void* object_to_remove) { if (!object_to_remove) return FALSE; BOOL found = FALSE; EnterCriticalSection(lock); OBJECT_NODE** current_ptr = list_head; while (*current_ptr) { if ((*current_ptr)->object == object_to_remove) { OBJECT_NODE* node_to_delete = *current_ptr; *current_ptr = node_to_delete->next; SAFE_FREE(node_to_delete->object); SAFE_FREE(node_to_delete); found = TRUE; break; } current_ptr = &(*current_ptr)->next; } LeaveCriticalSection(lock); if (!found) { LogWarning("Attempt to remove non-existent handle: %p", object_to_remove); } return found; }
void CleanupObjectList(OBJECT_NODE** list_head, CRITICAL_SECTION* lock, const char* list_name) { EnterCriticalSection(lock); OBJECT_NODE* current = *list_head; while (current) { OBJECT_NODE* next = current->next; LogWarning("Force-cleaning leaked object from '%s': %p (Thread: %lu)", list_name, current->object, current->thread_id); SAFE_FREE(current->object); SAFE_FREE(current); current = next; } *list_head = NULL; LeaveCriticalSection(lock); }
static HINTERNET CreateFakeHandle(DWORD magic, const char* type_name, HINTERNET hParent) { FAKE_HANDLE* handle = (FAKE_HANDLE*)SAFE_ALLOC(sizeof(FAKE_HANDLE)); if (handle) { handle->magic = magic; strncpy_s(handle->type_name, sizeof(handle->type_name), type_name, _TRUNCATE); handle->parent = (FAKE_HANDLE*)hParent; if (AddObjectToList(&g_hinternet_list, &g_hinternet_list_lock, handle)) return (HINTERNET)handle; SAFE_FREE(handle); } LogError("Failed to create fake handle of type '%s'", type_name); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
static BOOL IsValidHandle(HINTERNET hInternet) { if (!hInternet) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; } if (!FindObjectInList(g_hinternet_list, &g_hinternet_list_lock, hInternet)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; } return TRUE; }

#define STUB_LOG LogDebug("STUB: %s called", __FUNCTION__)
#define STUB_SUCCESS_BOOL() do { STUB_LOG; return TRUE; } while (0)
#define STUB_FAIL_BOOL(err) do { STUB_LOG; SetLastError(err); return FALSE; } while (0)
#define STUB_FAIL_PTR(err) do { STUB_LOG; SetLastError(err); return NULL; } while (0)
#define STUB_FAIL_DWORD(val, err) do { STUB_LOG; SetLastError(err); return (val); } while (0)

// === НОВА, ПОКРАЩЕНА РЕАЛІЗАЦІЯ INTERNET_CRACK_URL ===
static void CopyUrlComponent(LPWSTR pDest, DWORD* dwDestLen, LPCWSTR pSrc, DWORD dwSrcLen) {
    if (!pSrc || dwSrcLen == 0) { if (pDest) pDest[0] = L'\0'; *dwDestLen = 0; return; }
    if (pDest && *dwDestLen > 0) {
        DWORD lenToCopy = (dwSrcLen < *dwDestLen) ? dwSrcLen : (*dwDestLen - 1);
        wcsncpy_s(pDest, *dwDestLen, pSrc, lenToCopy);
        pDest[lenToCopy] = L'\0';
    }
    *dwDestLen = dwSrcLen;
}

BOOL WINAPI ex_InternetCrackUrlW(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpComponents) {
    LogInfo("InternetCrackUrlW(URL: %S)", lpszUrl ? lpszUrl : L"<null>");
    if (!lpszUrl || !lpComponents || lpComponents->dwStructSize != sizeof(URL_COMPONENTSW)) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    LPCWSTR pEnd = lpszUrl + (dwUrlLength == 0 ? wcslen(lpszUrl) : dwUrlLength);
    LPCWSTR pCurrent = lpszUrl;
    LPCWSTR pSchemeEnd = wcsstr(pCurrent, L"://");
    if (pSchemeEnd && pSchemeEnd < pEnd) {
        CopyUrlComponent(lpComponents->lpszScheme, &lpComponents->dwSchemeLength, pCurrent, (DWORD)(pSchemeEnd - pCurrent));
        if (_wcsnicmp(pCurrent, L"https", 5) == 0) lpComponents->nScheme = INTERNET_SCHEME_HTTPS;
        else if (_wcsnicmp(pCurrent, L"http", 4) == 0) lpComponents->nScheme = INTERNET_SCHEME_HTTP;
        else if (_wcsnicmp(pCurrent, L"ftp", 3) == 0) lpComponents->nScheme = INTERNET_SCHEME_FTP;
        else lpComponents->nScheme = INTERNET_SCHEME_UNKNOWN;
        pCurrent = pSchemeEnd + 3;
    } else { lpComponents->dwSchemeLength = 0; lpComponents->nScheme = INTERNET_SCHEME_UNKNOWN; }
    
    LPCWSTR pPathStart = wcschr(pCurrent, L'/');
    if (!pPathStart || pPathStart > pEnd) pPathStart = pEnd;
    LPCWSTR pAuthEnd = wcschr(pCurrent, L'@');
    if (pAuthEnd && pAuthEnd < pPathStart) {
        LPCWSTR pPassEnd = wcschr(pCurrent, L':');
        if (pPassEnd && pPassEnd < pAuthEnd) {
            CopyUrlComponent(lpComponents->lpszUserName, &lpComponents->dwUserNameLength, pCurrent, (DWORD)(pPassEnd - pCurrent));
            CopyUrlComponent(lpComponents->lpszPassword, &lpComponents->dwPasswordLength, pPassEnd + 1, (DWORD)(pAuthEnd - (pPassEnd + 1)));
        } else { CopyUrlComponent(lpComponents->lpszUserName, &lpComponents->dwUserNameLength, pCurrent, (DWORD)(pAuthEnd - pCurrent)); }
        pCurrent = pAuthEnd + 1;
    }

    LPCWSTR pHostEnd = pPathStart;
    LPCWSTR pPortStart = wcschr(pCurrent, L':');
    if (pPortStart && pPortStart < pHostEnd) {
        CopyUrlComponent(lpComponents->lpszHostName, &lpComponents->dwHostNameLength, pCurrent, (DWORD)(pPortStart - pCurrent));
        WCHAR portBuf[10] = {0}; wcsncpy_s(portBuf, 10, pPortStart + 1, (size_t)(pHostEnd - (pPortStart + 1)));
        lpComponents->nPort = (INTERNET_PORT)_wtoi(portBuf);
    } else {
        CopyUrlComponent(lpComponents->lpszHostName, &lpComponents->dwHostNameLength, pCurrent, (DWORD)(pHostEnd - pCurrent));
        if (lpComponents->nScheme == INTERNET_SCHEME_HTTPS) lpComponents->nPort = 443;
        else if (lpComponents->nScheme == INTERNET_SCHEME_HTTP) lpComponents->nPort = 80;
        else if (lpComponents->nScheme == INTERNET_SCHEME_FTP) lpComponents->nPort = 21;
        else lpComponents->nPort = 0;
    }
    pCurrent = pHostEnd;

    if (pCurrent < pEnd) {
        LPCWSTR pQueryStart = wcschr(pCurrent, L'?');
        if (!pQueryStart || pQueryStart > pEnd) pQueryStart = pEnd;
        CopyUrlComponent(lpComponents->lpszUrlPath, &lpComponents->dwUrlPathLength, pCurrent, (DWORD)(pQueryStart - pCurrent));
        CopyUrlComponent(lpComponents->lpszExtraInfo, &lpComponents->dwExtraInfoLength, pQueryStart, (DWORD)(pEnd - pQueryStart));
    } else { lpComponents->dwUrlPathLength = 0; lpComponents->dwExtraInfoLength = 0; }

    LogDebug("  -> Parsed successfully");
    return TRUE;
}

BOOL WINAPI ex_InternetCrackUrlA(LPCSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSA lpUrlComponents) {
    LogInfo("InternetCrackUrlA(URL: %s)", lpszUrl ? lpszUrl : "<null>");
    if (!lpszUrl || !lpUrlComponents) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    
    int url_len_w = MultiByteToWideChar(CP_ACP, 0, lpszUrl, dwUrlLength == 0 ? -1 : (int)dwUrlLength, NULL, 0);
    WCHAR* url_w = (WCHAR*)SAFE_ALLOC(url_len_w * sizeof(WCHAR));
    if (!url_w) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    MultiByteToWideChar(CP_ACP, 0, lpszUrl, dwUrlLength == 0 ? -1 : (int)dwUrlLength, url_w, url_len_w);
    
    URL_COMPONENTSW comp_w = { sizeof(URL_COMPONENTSW) };
    WCHAR scheme_w[128], host_w[1024], user_w[256], pass_w[256], path_w[2048], extra_w[2048];
    comp_w.lpszScheme = scheme_w; comp_w.dwSchemeLength = 128;
    comp_w.lpszHostName = host_w; comp_w.dwHostNameLength = 1024;
    comp_w.lpszUserName = user_w; comp_w.dwUserNameLength = 256;
    comp_w.lpszPassword = pass_w; comp_w.dwPasswordLength = 256;
    comp_w.lpszUrlPath = path_w; comp_w.dwUrlPathLength = 2048;
    comp_w.lpszExtraInfo = extra_w; comp_w.dwExtraInfoLength = 2048;

    BOOL result = ex_InternetCrackUrlW(url_w, 0, dwFlags, &comp_w);
    if (result) {
        lpUrlComponents->nScheme = comp_w.nScheme; lpUrlComponents->nPort = comp_w.nPort;
        if (lpUrlComponents->lpszScheme && lpUrlComponents->dwSchemeLength > 0) WideCharToMultiByte(CP_ACP,0,comp_w.lpszScheme,comp_w.dwSchemeLength+1,lpUrlComponents->lpszScheme,lpUrlComponents->dwSchemeLength,0,0);
        if (lpUrlComponents->lpszHostName && lpUrlComponents->dwHostNameLength > 0) WideCharToMultiByte(CP_ACP,0,comp_w.lpszHostName,comp_w.dwHostNameLength+1,lpUrlComponents->lpszHostName,lpUrlComponents->dwHostNameLength,0,0);
        if (lpUrlComponents->lpszUserName && lpUrlComponents->dwUserNameLength > 0) WideCharToMultiByte(CP_ACP,0,comp_w.lpszUserName,comp_w.dwUserNameLength+1,lpUrlComponents->lpszUserName,lpUrlComponents->dwUserNameLength,0,0);
        if (lpUrlComponents->lpszPassword && lpUrlComponents->dwPasswordLength > 0) WideCharToMultiByte(CP_ACP,0,comp_w.lpszPassword,comp_w.dwPasswordLength+1,lpUrlComponents->lpszPassword,lpUrlComponents->dwPasswordLength,0,0);
        if (lpUrlComponents->lpszUrlPath && lpUrlComponents->dwUrlPathLength > 0) WideCharToMultiByte(CP_ACP,0,comp_w.lpszUrlPath,comp_w.dwUrlPathLength+1,lpUrlComponents->lpszUrlPath,lpUrlComponents->dwUrlPathLength,0,0);
        if (lpUrlComponents->lpszExtraInfo && lpUrlComponents->dwExtraInfoLength > 0) WideCharToMultiByte(CP_ACP,0,comp_w.lpszExtraInfo,comp_w.dwExtraInfoLength+1,lpUrlComponents->lpszExtraInfo,lpUrlComponents->dwExtraInfoLength,0,0);
        lpUrlComponents->dwSchemeLength = comp_w.dwSchemeLength; lpUrlComponents->dwHostNameLength = comp_w.dwHostNameLength; lpUrlComponents->dwUserNameLength = comp_w.dwUserNameLength;
        lpUrlComponents->dwPasswordLength = comp_w.dwPasswordLength; lpUrlComponents->dwUrlPathLength = comp_w.dwUrlPathLength; lpUrlComponents->dwExtraInfoLength = comp_w.dwExtraInfoLength;
    }
    SAFE_FREE(url_w);
    return result;
}

// === ІНШІ КЛЮЧОВІ API ===
BOOL WINAPI ex_InternetGetConnectedState(LPDWORD lpdwFlags, DWORD dwReserved) { LogInfo("InternetGetConnectedState called."); if (lpdwFlags) { *lpdwFlags = INTERNET_CONNECTION_OFFLINE; } SetLastError(ERROR_INTERNET_DISCONNECTED); LogWarning("  -> Returning FALSE (emulating OFFLINE state)."); return FALSE; }
BOOL WINAPI ex_InternetCheckConnectionA(LPCSTR u, DWORD f, DWORD r) { LogInfo("InternetCheckConnectionA(URL: %s)", u ? u : "<null>"); SetLastError(ERROR_INTERNET_CANNOT_CONNECT); return FALSE; }
BOOL WINAPI ex_InternetCheckConnectionW(LPCWSTR u, DWORD f, DWORD r) { LogInfo("InternetCheckConnectionW(URL: %S)", u ? u : L"<null>"); SetLastError(ERROR_INTERNET_CANNOT_CONNECT); return FALSE; }
HINTERNET WINAPI ex_InternetOpenA(LPCSTR a, DWORD t, LPCSTR p, LPCSTR b, DWORD f) { LogInfo("InternetOpenA(Agent: '%s')", a ? a : "<null>"); return CreateFakeHandle(MAGIC_SESSION, "SESSION", NULL); }
HINTERNET WINAPI ex_InternetOpenW(LPCWSTR a, DWORD t, LPCWSTR p, LPCWSTR b, DWORD f) { LogInfo("InternetOpenW(Agent: '%S')", a ? a : L"<null>"); return CreateFakeHandle(MAGIC_SESSION, "SESSION", NULL); }
HINTERNET WINAPI ex_InternetConnectA(HINTERNET h, LPCSTR s, INTERNET_PORT n, LPCSTR u, LPCSTR p, DWORD d, DWORD f, DWORD_PTR c) { LogInfo("InternetConnectA(Server: '%s')", s); if (!IsValidHandle(h)) return NULL; return CreateFakeHandle(MAGIC_CONNECT, "CONNECT", h); }
HINTERNET WINAPI ex_InternetConnectW(HINTERNET h, LPCWSTR s, INTERNET_PORT n, LPCWSTR u, LPCWSTR p, DWORD d, DWORD f, DWORD_PTR c) { LogInfo("InternetConnectW(Server: '%S')", s); if (!IsValidHandle(h)) return NULL; return CreateFakeHandle(MAGIC_CONNECT, "CONNECT", h); }
HINTERNET WINAPI ex_InternetOpenUrlA(HINTERNET h, LPCSTR u, LPCSTR d, DWORD l, DWORD f, DWORD_PTR c) { LogInfo("InternetOpenUrlA(URL: '%s')", u); if (!IsValidHandle(h)) return NULL; return CreateFakeHandle(MAGIC_REQUEST, "URL_REQUEST", h); }
HINTERNET WINAPI ex_InternetOpenUrlW(HINTERNET h, LPCWSTR u, LPCWSTR d, DWORD l, DWORD f, DWORD_PTR c) { LogInfo("InternetOpenUrlW(URL: '%S')", u); if (!IsValidHandle(h)) return NULL; return CreateFakeHandle(MAGIC_REQUEST, "URL_REQUEST", h); }
HINTERNET WINAPI ex_HttpOpenRequestA(HINTERNET h, LPCSTR v, LPCSTR o, LPCSTR z, LPCSTR r, LPCSTR* t, DWORD f, DWORD_PTR c) { LogInfo("HttpOpenRequestA(Object: '%s')", o); if (!IsValidHandle(h)) return NULL; return CreateFakeHandle(MAGIC_REQUEST, "HTTP_REQUEST", h); }
HINTERNET WINAPI ex_HttpOpenRequestW(HINTERNET h, LPCWSTR v, LPCWSTR o, LPCWSTR z, LPCWSTR r, LPCWSTR* t, DWORD f, DWORD_PTR c) { LogInfo("HttpOpenRequestW(Object: '%S')", o); if (!IsValidHandle(h)) return NULL; return CreateFakeHandle(MAGIC_REQUEST, "HTTP_REQUEST", h); }

BOOL WINAPI ex_HttpSendRequestA(HINTERNET h, LPCSTR d, DWORD l, LPVOID o, DWORD ol) { LogInfo("HttpSendRequestA(hRequest: %p)", h); if (!IsValidHandle(h)) return FALSE; LogWarning("  -> Simulating SUCCESS to proceed to reading stage."); return TRUE; }
BOOL WINAPI ex_HttpSendRequestW(HINTERNET h, LPCWSTR d, DWORD l, LPVOID o, DWORD ol) { LogInfo("HttpSendRequestW(hRequest: %p)", h); if (!IsValidHandle(h)) return FALSE; LogWarning("  -> Simulating SUCCESS to proceed to reading stage."); return TRUE; }

BOOL WINAPI ex_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    LogInfo("InternetReadFile(hFile: %p, bufferSize: %lu)", hFile, dwNumberOfBytesToRead);
    if (!IsValidHandle(hFile)) return FALSE;
    FAKE_HANDLE* handle = (FAKE_HANDLE*)hFile;
    if (handle->magic != MAGIC_REQUEST && handle->magic != MAGIC_FIND_HANDLE) {
        LogWarning("  -> Called on a non-request handle type (%s), emulating EOF.", handle->type_name);
        if (lpdwNumberOfBytesRead) *lpdwNumberOfBytesRead = 0;
        return TRUE;
    }
    handle->read_attempts++;
    if (handle->read_attempts == 1) {
        LogWarning("  -> Simulating IO_PENDING (attempt %lu)", handle->read_attempts);
        if (lpdwNumberOfBytesRead) *lpdwNumberOfBytesRead = 0; SetLastError(ERROR_IO_PENDING); return FALSE;
    }
    if (handle->read_attempts == 2) {
        LogWarning("  -> Simulating TIMEOUT (attempt %lu)", handle->read_attempts);
        if (lpdwNumberOfBytesRead) *lpdwNumberOfBytesRead = 0; SetLastError(ERROR_INTERNET_TIMEOUT); return FALSE;
    }
    LogWarning("  -> Forcing End-Of-Stream to break loop (attempt %lu)", handle->read_attempts);
    if (lpdwNumberOfBytesRead) *lpdwNumberOfBytesRead = 0;
    return TRUE;
}

BOOL WINAPI ex_HttpQueryInfoA(HINTERNET h, DWORD l, LPVOID b, LPDWORD s, LPDWORD x) {
    LogInfo("HttpQueryInfoA(hRequest: %p, InfoLevel: 0x%lX)", h, l); if (!IsValidHandle(h)) return FALSE;
    DWORD queryType = l & HTTP_QUERY_MODIFIER_MASK;
    if (queryType == HTTP_QUERY_STATUS_CODE || queryType == HTTP_QUERY_STATUS_TEXT) {
        SetLastError(ERROR_INTERNET_CANNOT_CONNECT); return FALSE;
    }
    SetLastError(ERROR_HTTP_HEADER_NOT_FOUND); return FALSE;
}
BOOL WINAPI ex_HttpQueryInfoW(HINTERNET h, DWORD l, LPVOID b, LPDWORD s, LPDWORD x) {
    LogInfo("HttpQueryInfoW(hRequest: %p, InfoLevel: 0x%lX)", h, l); if (!IsValidHandle(h)) return FALSE;
    SetLastError(ERROR_INTERNET_CANNOT_CONNECT); return FALSE;
}
BOOL WINAPI ex_InternetCloseHandle(HINTERNET h) { LogInfo("InternetCloseHandle(hInternet: %p)", h); if (!IsValidHandle(h)) return FALSE; if (RemoveObjectFromList(&g_hinternet_list, &g_hinternet_list_lock, h)) { LogInfo("  -> Handle %p closed successfully.", h); return TRUE; } return FALSE; }

// === ІНШІ ЗАГЛУШКИ ===
// ... (всі інші STUB_xxx функції залишаються тут, я їх приховав для стислості)
BOOL WINAPI ex_AppCacheCheckManifest() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheCloseHandle() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheCreateAndCommitFile() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheDeleteGroup() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheDeleteIEGroup() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheDuplicateHandle() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheFinalize() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheFreeDownloadList() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheFreeGroupList() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheFreeIESpace() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheFreeSpace() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheGetDownloadList() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheGetFallbackUrl() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheGetGroupList() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheGetIEGroupList() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheGetInfo() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheGetManifestUrl() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_AppCacheLookup() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_CommitUrlCacheEntryBinaryBlob() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_CreateMD5SSOHash(PWSTR ci, PWSTR r, PWSTR t, PBYTE h) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_CreateUrlCacheContainerA() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_CreateUrlCacheContainerW() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_CreateUrlCacheEntryExW() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_DeleteIE3Cache() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_DeleteUrlCacheContainerA() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_DeleteUrlCacheContainerW() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_DeleteWpadCacheForNetworks() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
HANDLE WINAPI ex_FindFirstUrlCacheContainerA(LPDWORD m, LPVOID b, LPDWORD bs, DWORD o) { STUB_FAIL_PTR(ERROR_FILE_NOT_FOUND); }
HANDLE WINAPI ex_FindFirstUrlCacheContainerW(LPDWORD m, LPVOID b, LPDWORD bs, DWORD o) { STUB_FAIL_PTR(ERROR_FILE_NOT_FOUND); }
BOOL WINAPI ex_FindNextUrlCacheContainerA(HANDLE h, LPVOID b, LPDWORD bs) { STUB_FAIL_BOOL(ERROR_NO_MORE_FILES); }
BOOL WINAPI ex_FindNextUrlCacheContainerW(HANDLE h, LPVOID b, LPDWORD bs) { STUB_FAIL_BOOL(ERROR_NO_MORE_FILES); }
BOOL WINAPI ex_FreeUrlCacheSpaceA(LPCSTR p, DWORD s, DWORD f) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_FreeUrlCacheSpaceW(LPCWSTR p, DWORD s, DWORD f) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_GetUrlCacheConfigInfoA(LPINTERNET_CACHE_CONFIG_INFOA i, LPDWORD s, DWORD fc) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_GetUrlCacheConfigInfoW(LPINTERNET_CACHE_CONFIG_INFOW i, LPDWORD s, DWORD fc) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_GetUrlCacheEntryBinaryBlob() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_GetUrlCacheHeaderData() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_IncrementUrlCacheHeaderData() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_IsUrlCacheEntryExpiredA(LPCSTR u, DWORD f, LPFILETIME l) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_IsUrlCacheEntryExpiredW(LPCWSTR u, DWORD f, LPFILETIME l) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_LoadUrlCacheContent() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_ReadUrlCacheEntryStreamEx() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_RegisterUrlCacheNotification() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_RunOnceUrlCache() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_SetUrlCacheConfigInfoA(LPINTERNET_CACHE_CONFIG_INFOA i, DWORD fc) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_SetUrlCacheConfigInfoW(LPINTERNET_CACHE_CONFIG_INFOW i, DWORD fc) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_SetUrlCacheHeaderData() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UpdateUrlCacheContentPath() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheCheckEntriesExist() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheCloseEntryHandle() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheContainerSetEntryMaximumAge() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheCreateContainer() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheFindFirstEntry() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheFindNextEntry() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheFreeEntryInfo() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheFreeGlobalSpace() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheGetContentPaths() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheGetEntryInfo() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheGetGlobalCacheSize() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheGetGlobalLimit() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheReadEntryStream() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheReloadSettings() { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_UrlCacheRetrieveEntryFile() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheRetrieveEntryStream() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheServer() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlCacheSetGlobalLimit() { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_UrlCacheUpdateEntryExtraData() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_UrlZonesDetach() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex__GetFileExtensionFromUrl() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_DispatchAPICall() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_ForceNexusLookup() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_ForceNexusLookupExW() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_GetProxyDllInfo() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_ParseX509EncodedCertificateForListBoxEntry() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_ResumeSuspendedDownload(HINTERNET h, DWORD r) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_ShowCertificate() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_ShowClientAuthCerts() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_ShowSecurityInfo() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_ShowX509EncodedCertificate() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_InternetAttemptConnect(DWORD r) { STUB_LOG; return ERROR_INTERNET_DISCONNECTED; }
BOOL WINAPI ex_HttpSendRequestExA(HINTERNET h, LPINTERNET_BUFFERSA bi, LPINTERNET_BUFFERSA bo, DWORD fl, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_INTERNET_CONNECTION_RESET); }
BOOL WINAPI ex_HttpSendRequestExW(HINTERNET h, LPINTERNET_BUFFERSW bi, LPINTERNET_BUFFERSW bo, DWORD fl, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_INTERNET_CONNECTION_RESET); }
BOOL WINAPI ex_HttpEndRequestA(HINTERNET h, LPINTERNET_BUFFERSA bo, DWORD fl, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_HttpEndRequestW(HINTERNET h, LPINTERNET_BUFFERSW bo, DWORD fl, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_HttpAddRequestHeadersA(HINTERNET h, LPCSTR hdr, DWORD len, DWORD mod) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_HttpAddRequestHeadersW(HINTERNET h, LPCWSTR hdr, DWORD len, DWORD mod) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetReadFileExA(HINTERNET h, LPINTERNET_BUFFERSA bo, DWORD fl, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_InternetReadFileExW(HINTERNET h, LPINTERNET_BUFFERSW bo, DWORD fl, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_InternetQueryDataAvailable(HINTERNET h, LPDWORD ba, DWORD fl, DWORD_PTR ctx) { if(ba) *ba = 0; STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_InternetWriteFile(HINTERNET h, LPCVOID b, DWORD bw, LPDWORD bwritten) { if(bwritten) *bwritten=0; STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
INTERNET_STATUS_CALLBACK WINAPI ex_InternetSetStatusCallback(HINTERNET h, INTERNET_STATUS_CALLBACK cb) { STUB_LOG; return NULL; }
INTERNET_STATUS_CALLBACK WINAPI ex_InternetSetStatusCallbackA(HINTERNET h, INTERNET_STATUS_CALLBACK cb) { return ex_InternetSetStatusCallback(h, cb); }
INTERNET_STATUS_CALLBACK WINAPI ex_InternetSetStatusCallbackW(HINTERNET h, INTERNET_STATUS_CALLBACK cb) { return ex_InternetSetStatusCallback(h, cb); }
BOOL WINAPI ex_InternetSetOptionA(HINTERNET h, DWORD o, LPVOID b, DWORD bl) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetSetOptionW(HINTERNET h, DWORD o, LPVOID b, DWORD bl) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetSetOptionExA(HINTERNET h, DWORD o, LPVOID b, DWORD bl, DWORD fl) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetSetOptionExW(HINTERNET h, DWORD o, LPVOID b, DWORD bl, DWORD fl) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetQueryOptionA(HINTERNET h, DWORD o, LPVOID b, LPDWORD bl) { if(bl) *bl=0; STUB_FAIL_BOOL(ERROR_INSUFFICIENT_BUFFER); }
BOOL WINAPI ex_InternetQueryOptionW(HINTERNET h, DWORD o, LPVOID b, LPDWORD bl) { if(bl) *bl=0; STUB_FAIL_BOOL(ERROR_INSUFFICIENT_BUFFER); }
BOOL WINAPI ex_DeleteUrlCacheEntryA(LPCSTR u) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_DeleteUrlCacheEntryW(LPCWSTR u) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_DeleteUrlCacheGroup(GROUPID g, DWORD f, LPVOID r) { STUB_FAIL_BOOL(ERROR_INVALID_PARAMETER); }
BOOL WINAPI ex_CreateUrlCacheEntryA(LPCSTR u, DWORD s, LPCSTR e, LPSTR f, DWORD r) { if (f) f[0]='\0'; STUB_FAIL_BOOL(ERROR_ACCESS_DENIED); }
BOOL WINAPI ex_CreateUrlCacheEntryW(LPCWSTR u, DWORD s, LPCWSTR e, LPWSTR f, DWORD r) { if (f) f[0]=L'\0'; STUB_FAIL_BOOL(ERROR_ACCESS_DENIED); }
BOOL WINAPI ex_CommitUrlCacheEntryA(LPCSTR u, LPCSTR l, FILETIME et, FILETIME lmt, DWORD cet, LPBYTE h, DWORD hs, LPCSTR fe, LPCSTR ou) { STUB_FAIL_BOOL(ERROR_ACCESS_DENIED); }
BOOL WINAPI ex_CommitUrlCacheEntryW(LPCWSTR u, LPCWSTR l, FILETIME et, FILETIME lmt, DWORD cet, LPWSTR h, DWORD hs, LPCWSTR fe, LPCWSTR ou) { STUB_FAIL_BOOL(ERROR_ACCESS_DENIED); }
BOOL WINAPI ex_RetrieveUrlCacheEntryFileA(LPCSTR u, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD s, DWORD r) { STUB_FAIL_BOOL(ERROR_FILE_NOT_FOUND); }
BOOL WINAPI ex_RetrieveUrlCacheEntryFileW(LPCWSTR u, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD s, DWORD r) { STUB_FAIL_BOOL(ERROR_FILE_NOT_FOUND); }
BOOL WINAPI ex_UnlockUrlCacheEntryFileA(LPCSTR u, DWORD r) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_UnlockUrlCacheEntryFileW(LPCWSTR u, DWORD r) { STUB_SUCCESS_BOOL(); }
HANDLE WINAPI ex_RetrieveUrlCacheEntryStreamA(LPCSTR u, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD s, BOOL rr, DWORD r) { STUB_FAIL_PTR(ERROR_FILE_NOT_FOUND); }
HANDLE WINAPI ex_RetrieveUrlCacheEntryStreamW(LPCWSTR u, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD s, BOOL rr, DWORD r) { STUB_FAIL_PTR(ERROR_FILE_NOT_FOUND); }
BOOL WINAPI ex_ReadUrlCacheEntryStream(HANDLE h, DWORD l, LPVOID b, LPDWORD len, DWORD r) { if(len) *len=0; STUB_FAIL_BOOL(ERROR_IO_DEVICE); }
BOOL WINAPI ex_UnlockUrlCacheEntryStream(HANDLE h, DWORD r) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_GetUrlCacheEntryInfoA(LPCSTR u, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD s) { STUB_FAIL_BOOL(ERROR_FILE_NOT_FOUND); }
BOOL WINAPI ex_GetUrlCacheEntryInfoW(LPCWSTR u, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD s) { STUB_FAIL_BOOL(ERROR_FILE_NOT_FOUND); }
BOOL WINAPI ex_GetUrlCacheEntryInfoExA(LPCSTR u, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD is, LPSTR ru, LPDWORD rus, LPVOID r, DWORD f) { STUB_FAIL_BOOL(ERROR_FILE_NOT_FOUND); }
BOOL WINAPI ex_GetUrlCacheEntryInfoExW(LPCWSTR u, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD is, LPWSTR ru, LPDWORD rus, LPVOID r, DWORD f) { STUB_FAIL_BOOL(ERROR_FILE_NOT_FOUND); }
BOOL WINAPI ex_SetUrlCacheEntryInfoA(LPCSTR u, LPINTERNET_CACHE_ENTRY_INFOA i, DWORD fc) { STUB_FAIL_BOOL(ERROR_ACCESS_DENIED); }
BOOL WINAPI ex_SetUrlCacheEntryInfoW(LPCWSTR u, LPINTERNET_CACHE_ENTRY_INFOW i, DWORD fc) { STUB_FAIL_BOOL(ERROR_ACCESS_DENIED); }
GROUPID WINAPI ex_CreateUrlCacheGroup(DWORD f, LPVOID r) { STUB_FAIL_DWORD(0, ERROR_INVALID_PARAMETER); }
BOOL WINAPI ex_SetUrlCacheEntryGroupA(LPCSTR u, DWORD f, GROUPID g, LPBYTE ga, DWORD gs, LPVOID r) { STUB_FAIL_BOOL(ERROR_ACCESS_DENIED); }
BOOL WINAPI ex_SetUrlCacheEntryGroupW(LPCWSTR u, DWORD f, GROUPID g, LPBYTE ga, DWORD gs, LPVOID r) { STUB_FAIL_BOOL(ERROR_ACCESS_DENIED); }
HANDLE WINAPI ex_FindFirstUrlCacheEntryA(LPCSTR p, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD s) { STUB_FAIL_PTR(ERROR_FILE_NOT_FOUND); }
HANDLE WINAPI ex_FindFirstUrlCacheEntryW(LPCWSTR p, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD s) { STUB_FAIL_PTR(ERROR_FILE_NOT_FOUND); }
HANDLE WINAPI ex_FindFirstUrlCacheEntryExA(LPCSTR p, DWORD f, DWORD fl, GROUPID g, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD s, LPVOID ga, LPDWORD gs, LPVOID r) { STUB_FAIL_PTR(ERROR_FILE_NOT_FOUND); }
HANDLE WINAPI ex_FindFirstUrlCacheEntryExW(LPCWSTR p, DWORD f, DWORD fl, GROUPID g, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD s, LPVOID ga, LPDWORD gs, LPVOID r) { STUB_FAIL_PTR(ERROR_FILE_NOT_FOUND); }
BOOL WINAPI ex_FindNextUrlCacheEntryA(HANDLE h, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD s) { STUB_FAIL_BOOL(ERROR_NO_MORE_FILES); }
BOOL WINAPI ex_FindNextUrlCacheEntryW(HANDLE h, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD s) { STUB_FAIL_BOOL(ERROR_NO_MORE_FILES); }
BOOL WINAPI ex_FindNextUrlCacheEntryExA(HANDLE h, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD is, LPVOID ga, LPDWORD gs, LPVOID r) { STUB_FAIL_BOOL(ERROR_NO_MORE_FILES); }
BOOL WINAPI ex_FindNextUrlCacheEntryExW(HINTERNET h, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD is, LPVOID ga, LPDWORD gs, LPVOID r) { STUB_FAIL_BOOL(ERROR_NO_MORE_FILES); }
BOOL WINAPI ex_FindCloseUrlCache(HANDLE h) { STUB_SUCCESS_BOOL(); }
HANDLE WINAPI ex_FindFirstUrlCacheGroup(DWORD f, DWORD fl, LPVOID sc, DWORD scs, GROUPID* g, LPVOID r) { STUB_FAIL_PTR(ERROR_FILE_NOT_FOUND); }
BOOL WINAPI ex_FindNextUrlCacheGroup(HANDLE h, GROUPID* g, LPVOID r) { STUB_FAIL_BOOL(ERROR_NO_MORE_FILES); }
BOOL WINAPI ex_GetUrlCacheGroupAttributeA(GROUPID g, DWORD f, DWORD a, LPINTERNET_CACHE_GROUP_INFOA i, LPDWORD s, LPVOID r) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_GetUrlCacheGroupAttributeW(GROUPID g, DWORD f, DWORD a, LPINTERNET_CACHE_GROUP_INFOW i, LPDWORD s, LPVOID r) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_SetUrlCacheGroupAttributeA(GROUPID g, DWORD f, DWORD a, LPINTERNET_CACHE_GROUP_INFOA i, LPVOID r) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_SetUrlCacheGroupAttributeW(GROUPID g, DWORD f, DWORD a, LPINTERNET_CACHE_GROUP_INFOW i, LPVOID r) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_FtpCommandA(HINTERNET h, BOOL r, DWORD f, LPCSTR c, DWORD_PTR ctx, HINTERNET* ph) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpCommandW(HINTERNET h, BOOL r, DWORD f, LPCWSTR c, DWORD_PTR ctx, HINTERNET* ph) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpCreateDirectoryA(HINTERNET h, LPCSTR d) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpCreateDirectoryW(HINTERNET h, LPCWSTR d) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpDeleteFileA(HINTERNET h, LPCSTR f) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpDeleteFileW(HINTERNET h, LPCWSTR f) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
HINTERNET WINAPI ex_FtpFindFirstFileA(HINTERNET h, LPCSTR s, LPWIN32_FIND_DATAA d, DWORD f, DWORD_PTR ctx) { STUB_FAIL_PTR(ERROR_INTERNET_DISCONNECTED); }
HINTERNET WINAPI ex_FtpFindFirstFileW(HINTERNET h, LPCWSTR s, LPWIN32_FIND_DATAW d, DWORD f, DWORD_PTR ctx) { STUB_FAIL_PTR(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpGetCurrentDirectoryA(HINTERNET h, LPSTR d, LPDWORD s) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpGetCurrentDirectoryW(HINTERNET h, LPWSTR d, LPDWORD s) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpGetFileA(HINTERNET h, LPCSTR r, LPCSTR n, BOOL fe, DWORD a, DWORD f, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpGetFileW(HINTERNET h, LPCWSTR r, LPCWSTR n, BOOL fe, DWORD a, DWORD f, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpGetFileEx(HINTERNET h, LPCSTR r, LPCWSTR n, BOOL fe, DWORD a, DWORD f, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
DWORD WINAPI ex_FtpGetFileSize(HINTERNET h, LPDWORD s) { STUB_FAIL_DWORD(INVALID_FILE_SIZE, ERROR_INTERNET_DISCONNECTED); }
HINTERNET WINAPI ex_FtpOpenFileA(HINTERNET h, LPCSTR f, DWORD a, DWORD fl, DWORD_PTR ctx) { STUB_FAIL_PTR(ERROR_INTERNET_DISCONNECTED); }
HINTERNET WINAPI ex_FtpOpenFileW(HINTERNET h, LPCWSTR f, DWORD a, DWORD fl, DWORD_PTR ctx) { STUB_FAIL_PTR(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpPutFileA(HINTERNET h, LPCSTR l, LPCSTR r, DWORD f, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpPutFileW(HINTERNET h, LPCWSTR l, LPCWSTR r, DWORD f, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpPutFileEx(HINTERNET h, LPCWSTR l, LPCSTR r, DWORD f, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpRemoveDirectoryA(HINTERNET h, LPCSTR d) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpRemoveDirectoryW(HINTERNET h, LPCWSTR d) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpRenameFileA(HINTERNET h, LPCSTR e, LPCSTR n) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpRenameFileW(HINTERNET h, LPCWSTR e, LPCWSTR n) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpSetCurrentDirectoryA(HINTERNET h, LPCSTR d) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_FtpSetCurrentDirectoryW(HINTERNET h, LPCWSTR d) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_GopherCreateLocatorA(LPCSTR h, INTERNET_PORT p, LPCSTR d, LPCSTR s, DWORD t, LPSTR l, LPDWORD bl) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_GopherCreateLocatorW(LPCWSTR h, INTERNET_PORT p, LPCWSTR d, LPCWSTR s, DWORD t, LPWSTR l, LPDWORD bl) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
HINTERNET WINAPI ex_GopherFindFirstFileA(HINTERNET h, LPCSTR l, LPCSTR s, LPGOPHER_FIND_DATAA d, DWORD f, DWORD_PTR ctx) { STUB_FAIL_PTR(ERROR_NOT_SUPPORTED); }
HINTERNET WINAPI ex_GopherFindFirstFileW(HINTERNET h, LPCWSTR l, LPCWSTR s, LPGOPHER_FIND_DATAW d, DWORD f, DWORD_PTR ctx) { STUB_FAIL_PTR(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_GopherGetAttributeA(HINTERNET h, LPCSTR l, LPCSTR a, LPBYTE b, DWORD bl, LPDWORD cr, GOPHER_ATTRIBUTE_ENUMERATOR e, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_GopherGetAttributeW(HINTERNET h, LPCWSTR l, LPCWSTR a, LPBYTE b, DWORD bl, LPDWORD cr, GOPHER_ATTRIBUTE_ENUMERATOR e, DWORD_PTR ctx) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_GopherGetLocatorTypeA(LPCSTR l, LPDWORD t) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_GopherGetLocatorTypeW(LPCWSTR l, LPDWORD t) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
HINTERNET WINAPI ex_GopherOpenFileA(HINTERNET h, LPCSTR l, LPCSTR v, DWORD f, DWORD_PTR ctx) { STUB_FAIL_PTR(ERROR_NOT_SUPPORTED); }
HINTERNET WINAPI ex_GopherOpenFileW(HINTERNET h, LPCWSTR l, LPCWSTR v, DWORD f, DWORD_PTR ctx) { STUB_FAIL_PTR(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpWebSocketClose(HINTERNET h, USHORT s, PVOID r, DWORD rl) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
HINTERNET WINAPI ex_HttpWebSocketCompleteUpgrade(HINTERNET h, DWORD_PTR ctx) { STUB_FAIL_PTR(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpWebSocketQueryCloseStatus(HINTERNET h, PUSHORT s, PVOID r, DWORD rl, PDWORD rl_read) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpWebSocketReceive(HINTERNET h, PVOID b, DWORD bl, PDWORD bread, PWEB_SOCKET_BUFFER_TYPE t) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpWebSocketSend(HINTERNET h, WEB_SOCKET_BUFFER_TYPE t, PVOID b, DWORD bl) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpWebSocketShutdown(HINTERNET h, USHORT s, PVOID r, DWORD rl) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_DetectAutoProxyUrl(LPSTR pu, DWORD pul, DWORD df) { if(pu && pul>0) pu[0]='\0'; STUB_FAIL_BOOL(ERROR_INTERNET_AUTODETECTION_FAILED); }
BOOL WINAPI ex_HttpCheckDavCompliance(LPCWSTR u, LPCWSTR dq, LPVOID ib, DWORD ibs, LPVOID ob, DWORD obs, LPDWORD obsr) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpCloseDependencyHandle(HINTERNET h) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpDuplicateDependencyHandle(HINTERNET h, HINTERNET* ph) { if(ph) *ph=NULL; STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpGetServerCredentials() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpGetTunnelSocket() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpIndicatePageLoadComplete() { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_HttpIsHostHstsEnabled() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpOpenDependencyHandle() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpPushClose() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpPushEnable() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_HttpPushWait() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetAlgIdToStringA() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetAlgIdToStringW() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetAutodial(DWORD f, HWND h) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_InternetAutodialCallback() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetAutodialHangup(DWORD r) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetCanonicalizeUrlA(LPCSTR u, LPSTR b, LPDWORD s, DWORD f) { if (u && b && s && *s > 0) { strncpy_s(b, *s, u, _TRUNCATE); } STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetCanonicalizeUrlW(LPCWSTR u, LPWSTR b, LPDWORD s, DWORD f) { if (u && b && s && *s > 0) { wcsncpy_s(b, *s, u, _TRUNCATE); } STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetClearAllPerSiteCookieDecisions() { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetCombineUrlA(LPCSTR bu, LPCSTR ru, LPSTR b, LPDWORD s, DWORD f) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetCombineUrlW(LPCWSTR bu, LPCWSTR ru, LPWSTR b, LPDWORD s, DWORD f) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetConvertUrlFromWireToWideChar() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetCreateUrlA(LPURL_COMPONENTSA c, DWORD f, LPSTR u, LPDWORD ul) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetCreateUrlW(LPURL_COMPONENTSW c, DWORD f, LPWSTR u, LPDWORD ul) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_InternetDial(HWND h, LPSTR c, DWORD f, LPDWORD con, DWORD r) { STUB_FAIL_DWORD(0, ERROR_INTERNET_DISCONNECTED); }
DWORD WINAPI ex_InternetDialA(HWND h, LPSTR c, DWORD f, DWORD_PTR* con, DWORD r) { STUB_FAIL_DWORD(0, ERROR_INTERNET_DISCONNECTED); }
DWORD WINAPI ex_InternetDialW(HWND h, LPWSTR c, DWORD f, DWORD_PTR* con, DWORD r) { STUB_FAIL_DWORD(0, ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_InternetEnumPerSiteCookieDecisionA(LPSTR s, unsigned long* ss, unsigned long* d, unsigned long i) { STUB_FAIL_BOOL(ERROR_NO_MORE_ITEMS); }
BOOL WINAPI ex_InternetEnumPerSiteCookieDecisionW(LPWSTR s, unsigned long* ss, unsigned long* d, unsigned long i) { STUB_FAIL_BOOL(ERROR_NO_MORE_ITEMS); }
DWORD WINAPI ex_InternetErrorDlg(HWND h, HINTERNET r, DWORD e, DWORD f, LPVOID* d) { STUB_FAIL_DWORD(0, e); }
BOOL WINAPI ex_InternetFindNextFileA(HINTERNET h, LPVOID d) { STUB_FAIL_BOOL(ERROR_NO_MORE_FILES); }
BOOL WINAPI ex_InternetFindNextFileW(HINTERNET h, LPVOID d) { STUB_FAIL_BOOL(ERROR_NO_MORE_FILES); }
BOOL WINAPI ex_InternetFortezzaCommand() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetFreeCookies(HANDLE h, DWORD f) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetFreeProxyInfoList() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetGetLastResponseInfoA(LPDWORD e, LPSTR b, LPDWORD s) { STUB_FAIL_BOOL(ERROR_INTERNET_INTERNAL_ERROR); }
BOOL WINAPI ex_InternetGetLastResponseInfoW(LPDWORD e, LPWSTR b, LPDWORD s) { STUB_FAIL_BOOL(ERROR_INTERNET_INTERNAL_ERROR); }
BOOL WINAPI ex_InternetGetPerSiteCookieDecisionA(LPCSTR h, unsigned long* r) { STUB_FAIL_BOOL(ERROR_NO_MORE_ITEMS); }
BOOL WINAPI ex_InternetGetPerSiteCookieDecisionW(LPCWSTR h, unsigned long* r) { STUB_FAIL_BOOL(ERROR_NO_MORE_ITEMS); }
BOOL WINAPI ex_InternetGetProxyForUrl() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_InternetHangUp(DWORD_PTR c, DWORD r) { STUB_FAIL_DWORD(0, ERROR_SUCCESS); }
BOOL WINAPI ex_InternetInitializeAutoProxyDll(DWORD r) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetLockRequestFile(HINTERNET h, HANDLE* l) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetQueryFortezzaStatus() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetSecurityProtocolToStringA() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetSecurityProtocolToStringW() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_InternetSetFilePointer(HINTERNET h, LONG d, PVOID r, DWORD m, DWORD_PTR ctx) { STUB_FAIL_DWORD(0, ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetSetPerSiteCookieDecisionA(LPCSTR h, DWORD d) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetSetPerSiteCookieDecisionW(LPCWSTR h, DWORD d) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetSetSecureLegacyServersAppCompat() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetUnlockRequestFile(HANDLE h) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetWriteFileExA() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetWriteFileExW() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_IsHostInProxyBypassList() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_PrivacyGetZonePreferenceW(DWORD z, DWORD t, LPDWORD pt, LPWSTR b, LPDWORD s) { STUB_FAIL_DWORD(ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_PrivacySetZonePreferenceW(DWORD z, DWORD t, DWORD tmpl, LPCWSTR p) { STUB_FAIL_DWORD(ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED); }
HRESULT WINAPI ex_DllCanUnloadNow(void) { STUB_LOG; return S_FALSE; }
HRESULT WINAPI ex_DllGetClassObject(REFCLSID c, REFIID i, LPVOID* ppv) { if (ppv) *ppv = NULL; STUB_LOG; return E_FAIL; }
HRESULT WINAPI ex_DllInstall(BOOL b, PCWSTR c) { STUB_LOG; return S_OK; }
HRESULT WINAPI ex_DllRegisterServer(void) { STUB_LOG; return S_OK; }
HRESULT WINAPI ex_DllUnregisterServer(void) { STUB_LOG; return S_OK; }
BOOL WINAPI ex_InternetGetConnectedStateExA(LPDWORD f, LPSTR n, DWORD bl, DWORD r) { return ex_InternetGetConnectedState(f, r); }
BOOL WINAPI ex_InternetGetConnectedStateExW(LPDWORD f, LPWSTR n, DWORD bl, DWORD r) { return ex_InternetGetConnectedState(f, r); }
BOOL WINAPI ex_InternetGetCookieA(LPCSTR u, LPCSTR n, LPSTR d, LPDWORD s) { LogInfo("InternetGetCookieA(Url: %s)", u); SetLastError(ERROR_NO_MORE_ITEMS); return FALSE; }
BOOL WINAPI ex_InternetGetCookieW(LPCWSTR u, LPCWSTR n, LPWSTR d, LPDWORD s) { LogInfo("InternetGetCookieW(Url: %S)", u); SetLastError(ERROR_NO_MORE_ITEMS); return FALSE; }
BOOL WINAPI ex_InternetGetCookieExA(LPCSTR u, LPCSTR n, LPSTR d, LPDWORD s, DWORD f, LPVOID r) { LogInfo("InternetGetCookieExA(Url: %s)", u); SetLastError(ERROR_NO_MORE_ITEMS); return FALSE; }
BOOL WINAPI ex_InternetGetCookieExW(LPCWSTR u, LPCWSTR n, LPWSTR d, LPDWORD s, DWORD f, LPVOID r) { LogInfo("InternetGetCookieExW(Url: %S)", u); SetLastError(ERROR_NO_MORE_ITEMS); return FALSE; }
BOOL WINAPI ex_InternetSetCookieA(LPCSTR u, LPCSTR n, LPCSTR d) { LogInfo("InternetSetCookieA(Url: %s)", u); return TRUE; }
BOOL WINAPI ex_InternetSetCookieW(LPCWSTR u, LPCWSTR n, LPCWSTR d) { LogInfo("InternetSetCookieW(Url: %S)", u); return TRUE; }
DWORD WINAPI ex_InternetSetCookieExA(LPCSTR u, LPCSTR n, LPCSTR d, DWORD f, DWORD_PTR r) { LogInfo("InternetSetCookieExA(Url: %s)", u); return INTERNET_COOKIE_SENT_OK; }
DWORD WINAPI ex_InternetSetCookieExW(LPCWSTR u, LPCWSTR n, LPCWSTR d, DWORD f, DWORD_PTR r) { LogInfo("InternetSetCookieExW(Url: %S)", u); return INTERNET_COOKIE_SENT_OK; }
DWORD WINAPI ex_InternetGetCookieEx2(PCWSTR u, PCWSTR n, DWORD f, INTERNET_COOKIE2** c, PDWORD cd) { if (c) *c = NULL; if (cd) *cd = 0; SetLastError(ERROR_NO_MORE_ITEMS); return ERROR_NO_MORE_ITEMS; }
DWORD WINAPI ex_InternetSetCookieEx2(PCWSTR u, const INTERNET_COOKIE2* c, PCWSTR p, DWORD f, PDWORD s) { if (s) *s = 0; return INTERNET_COOKIE_SENT_OK; }
BOOL WINAPI ex_InternetGoOnlineA(LPSTR u, HWND h, DWORD f) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_InternetGoOnlineW(LPWSTR u, HWND h, DWORD f) { STUB_FAIL_BOOL(ERROR_INTERNET_DISCONNECTED); }
BOOL WINAPI ex_InternetSetDialStateA(LPCSTR c, DWORD s, DWORD r) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetSetDialStateW(LPCWSTR c, DWORD s, DWORD r) { STUB_SUCCESS_BOOL(); }
BOOL WINAPI ex_InternetTimeFromSystemTimeA(const SYSTEMTIME* pst, DWORD rfc, LPSTR t, DWORD s) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetTimeFromSystemTimeW(const SYSTEMTIME* pst, DWORD rfc, LPWSTR t, DWORD s) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetTimeToSystemTimeA(LPCSTR t, SYSTEMTIME* pst, DWORD r) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetTimeToSystemTimeW(LPCWSTR t, SYSTEMTIME* pst, DWORD r) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_InternetConfirmZoneCrossingA(HWND h, LPSTR up, LPSTR un, BOOL p) { STUB_LOG; return 0; }
DWORD WINAPI ex_InternetConfirmZoneCrossingW(HWND h, LPWSTR up, LPWSTR un, BOOL p) { STUB_LOG; return 0; }
BOOL WINAPI ex_InternetGetCertByURLA() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetGetSecurityInfoByURLA() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetGetSecurityInfoByURLW() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetShowSecurityInfoByURLA(HWND hWnd, LPCSTR lpszUrl) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetShowSecurityInfoByURLW(HWND hWnd, LPCWSTR lpszUrl) { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
BOOL WINAPI ex_InternetGetConnectedStateEx(LPDWORD f, LPSTR n, DWORD bl, DWORD r) { return ex_InternetGetConnectedStateExA(f, n, bl, r); }
BOOL WINAPI ex_InternetGetCookie(LPCSTR u, LPCSTR n, LPSTR d, LPDWORD s) { return ex_InternetGetCookieA(u, n, d, s); }
BOOL WINAPI ex_InternetGetCookieEx(LPCSTR u, LPCSTR n, LPSTR d, LPDWORD s, DWORD f, LPVOID r) { return ex_InternetGetCookieExA(u, n, d, s, f, r); }
BOOL WINAPI ex_InternetSetCookie(LPCSTR u, LPCSTR n, LPCSTR d) { return ex_InternetSetCookieA(u, n, d); }
DWORD WINAPI ex_InternetSetCookieEx(LPCSTR u, LPCSTR n, LPCSTR d, DWORD f, DWORD_PTR r) { return ex_InternetSetCookieExA(u, n, d, f, r); }
BOOL WINAPI ex_InternetGoOnline(LPSTR u, HWND h, DWORD f) { return ex_InternetGoOnlineA(u, h, f); }
BOOL WINAPI ex_InternetSetDialState(LPCSTR c, DWORD s, DWORD r) { return ex_InternetSetDialStateA(c, s, r); }
BOOL WINAPI ex_InternetTimeFromSystemTime(const SYSTEMTIME* pst, DWORD rfc, LPSTR t, DWORD s) { return ex_InternetTimeFromSystemTimeA(pst, rfc, t, s); }
BOOL WINAPI ex_InternetTimeToSystemTime(LPCSTR t, SYSTEMTIME* pst, DWORD r) { return ex_InternetTimeToSystemTimeA(t, pst, r); }
DWORD WINAPI ex_InternetConfirmZoneCrossing(HWND h, LPSTR up, LPSTR un, BOOL p) { return ex_InternetConfirmZoneCrossingA(h, up, un, p); }
BOOL WINAPI ex_InternetGetCertByURL(LPCSTR u, PCCERT_CONTEXT* c, DWORD f) { return ex_InternetGetCertByURLA(); }
BOOL WINAPI ex_InternetGetSecurityInfoByURL(LPCWSTR u, PCCERT_CHAIN_CONTEXT* c, DWORD* f) { return ex_InternetGetSecurityInfoByURLW(); }
BOOL WINAPI ex_InternetShowSecurityInfoByURL(HWND hWnd, LPCWSTR lpszUrl) { return ex_InternetShowSecurityInfoByURLW(hWnd, lpszUrl); }
BOOL WINAPI ex_DeleteUrlCacheEntry(LPCSTR u) { return ex_DeleteUrlCacheEntryA(u); }
BOOL WINAPI ex_SetUrlCacheEntryGroup(LPCSTR u, DWORD f, GROUPID g, LPBYTE ga, DWORD gs, LPVOID r) { return ex_SetUrlCacheEntryGroupA(u, f, g, ga, gs, r); }
BOOL WINAPI ex_UnlockUrlCacheEntryFile(LPCSTR u, DWORD r) { return ex_UnlockUrlCacheEntryFileA(u, r); }

// ============================================================================
// DLLMAIN
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
#if ENABLE_FILE_LOGGING
        InitializeCriticalSection(&g_log_lock);
#endif
#if ENABLE_MEMORY_TRACKING
        InitializeCriticalSection(&g_memory_lock);
#endif
        InitializeCriticalSection(&g_hinternet_list_lock);
        g_locks_initialized = TRUE;
#if ENABLE_DEBUG_CONSOLE
        if (AllocConsole()) { FILE* f; freopen_s(&f, "CONOUT$", "w", stdout); SetConsoleTitleA("WinINet Stub Debug Console v1.0.2"); }
#endif
#if ENABLE_FILE_LOGGING
        { char p[MAX_PATH]; GetModuleFileNameA(NULL, p, MAX_PATH); char* s=strrchr(p, '\\'); if(s)*(s+1)='\0'; strcat_s(p, "wininet_stub.log"); fopen_s(&g_log_file, p, "a"); }
#endif
        LogInfo("=== WININET STUB v1.0.2 LOADED ==="); LogInfo("Build: %s %s", __DATE__, __TIME__);
        break;
    case DLL_PROCESS_DETACH:
        LogInfo("=== WININET STUB v1.0.2 UNLOADING ===");
        if (g_locks_initialized) {
            CleanupObjectList(&g_hinternet_list, &g_hinternet_list_lock, "HINTERNET Handles");
#if ENABLE_MEMORY_TRACKING
            ReportMemoryLeaks();
#endif
            DeleteCriticalSection(&g_hinternet_list_lock);
#if ENABLE_MEMORY_TRACKING
            DeleteCriticalSection(&g_memory_lock);
#endif
#if ENABLE_FILE_LOGGING
            if (g_log_file) { fclose(g_log_file); g_log_file = NULL; }
            DeleteCriticalSection(&g_log_lock);
#endif
            g_locks_initialized = FALSE;
        }
#if ENABLE_DEBUG_CONSOLE
        printf("\nWinINet Stub Unloading complete...\n"); FreeConsole();
#endif
        break;
    }
    return TRUE;
}

#ifdef __cplusplus
}

#endif
