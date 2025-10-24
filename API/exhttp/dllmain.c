#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// === ФАЛЛБЕКИ ДЛЯ СУМІСНОСТІ ЗІ СТАРИМИ SDK / MINGW ===
// ============================================================================

#ifndef WINHTTP_FLAG_SECURE_DEFAULTS
#define WINHTTP_FLAG_SECURE_DEFAULTS 0x30000000
#endif

#if !defined(WINHTTPAPI)
#define WINHTTPAPI DECLSPEC_IMPORT
#endif

#ifndef __WINHTTP_PROXY_SETTINGS_TYPE_DEFINED__
#define __WINHTTP_PROXY_SETTINGS_TYPE_DEFINED__
typedef enum _WINHTTP_PROXY_SETTINGS_TYPE {
    WinHttpProxySettingsTypeUnknown,
    WinHttpProxySettingsTypeWsl,
    WinHttpProxySettingsTypeWsa
} WINHTTP_PROXY_SETTINGS_TYPE, *PWINHTTP_PROXY_SETTINGS_TYPE;

typedef struct _WINHTTP_PROXY_SETTINGS_PARAM {
    ULONGLONG ullFlags;
    PCWSTR pcwszConnectionName;
    PCWSTR pcwszProbeHost;
} WINHTTP_PROXY_SETTINGS_PARAM, *PWINHTTP_PROXY_SETTINGS_PARAM;
#endif

#ifndef __WINHTTP_EXTENDED_HEADER_DEFINED__
#define __WINHTTP_EXTENDED_HEADER_DEFINED__
#pragma warning(push)
#pragma warning(disable:4201) // nameless unions
typedef struct _WINHTTP_EXTENDED_HEADER {
    union { PCWSTR pwszName; PCSTR pszName; };
    union { PCWSTR pwszValue; PCSTR pszValue; };
} WINHTTP_EXTENDED_HEADER, *PWINHTTP_EXTENDED_HEADER;
#pragma warning(pop)
typedef union _WINHTTP_HEADER_NAME { PCWSTR pwszName; PCSTR pszName; } WINHTTP_HEADER_NAME, *PWINHTTP_HEADER_NAME;
#endif

#ifndef __WINHTTP_QUERY_CONNECTION_GROUP_RESULT_DEFINED__
#define __WINHTTP_QUERY_CONNECTION_GROUP_RESULT_DEFINED__
typedef struct _WINHTTP_CONNECTION_GROUP { ULONG cConnections; GUID guidGroup; } WINHTTP_CONNECTION_GROUP, *PWINHTTP_CONNECTION_GROUP;
typedef struct _WINHTTP_HOST_CONNECTION_GROUP { PCWSTR pwszHost; ULONG cConnectionGroups; PWINHTTP_CONNECTION_GROUP pConnectionGroups; } WINHTTP_HOST_CONNECTION_GROUP, *PWINHTTP_HOST_CONNECTION_GROUP;
typedef struct _WINHTTP_QUERY_CONNECTION_GROUP_RESULT { ULONG cHosts; PWINHTTP_HOST_CONNECTION_GROUP pHostConnectionGroups; } WINHTTP_QUERY_CONNECTION_GROUP_RESULT, *PWINHTTP_QUERY_CONNECTION_GROUP_RESULT;
#endif

#ifndef __WINHTTP_PROXY_CHANGE_DEFINED__
#define __WINHTTP_PROXY_CHANGE_DEFINED__
typedef PVOID WINHTTP_PROXY_CHANGE_REGISTRATION_HANDLE;
typedef VOID(CALLBACK *WINHTTP_PROXY_CHANGE_CALLBACK)(_In_ ULONGLONG ullFlags, _In_ PVOID pvContext);
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
#define MAGIC_SESSION   0xDEADBEEF
#define MAGIC_CONNECT   0xCAFEBABE
#define MAGIC_REQUEST   0xFEEDFACE
#define MAGIC_WEBSOCKET 0xBADDCAFE
#define MAGIC_RESOLVER  0xC0FFEE00

typedef struct _FAKE_HANDLE { DWORD magic; char type_name[16]; struct _FAKE_HANDLE* parent; } FAKE_HANDLE;
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
#if ENABLE_FILE_LOGGING
if (g_log_file && g_locks_initialized) { EnterCriticalSection(&g_log_lock); fprintf(g_log_file, "%s [%s] [%s] ", timestamp, GetLogLevelString(level), function); vfprintf(g_log_file, format, args); fprintf(g_log_file, "\n"); fflush(g_log_file); LeaveCriticalSection(&g_log_lock); }
#endif
#if ENABLE_DEBUG_CONSOLE
printf("[WINHTTP] %s [%s] [%s] ", timestamp, GetLogLevelString(level), function); vprintf(format, args); printf("\n");
#endif
va_end(args); }
#define LogError(fmt, ...)   LogMessageEx(LOG_LEVEL_ERROR, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogWarning(fmt, ...) LogMessageEx(LOG_LEVEL_WARNING, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogInfo(fmt, ...)    LogMessageEx(LOG_LEVEL_INFO, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogDebug(fmt, ...)   LogMessageEx(LOG_LEVEL_DEBUG, __FUNCTION__, fmt, ##__VA_ARGS__)
void LogHexBuffer(LogLevel level, const char* function, const char* prefix, const BYTE* buffer, DWORD size) { if (level > g_current_log_level) return; if (!buffer || size == 0) { LogMessageEx(level, function, "%s: <NULL or empty>", prefix); return; } char hex_str[257] = { 0 }; DWORD len = 0; DWORD bytes_to_log = (size > 128) ? 128 : size; for (DWORD i = 0; i < bytes_to_log; i++) { len += snprintf(hex_str + len, sizeof(hex_str) - len, "%02X", buffer[i]); } if (size > 128) { snprintf(hex_str + len, sizeof(hex_str) - len, "..."); } LogMessageEx(level, function, "%s (%lu bytes): %s", prefix, size, hex_str); }
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
void CleanupObjectList(OBJECT_NODE** list_head, CRITICAL_SECTION* lock, const char* list_name) { EnterCriticalSection(lock); OBJECT_NODE* current = *list_head; int count = 0; while (current) { OBJECT_NODE* next = current->next; LogWarning("Force-cleaning leaked object from '%s': %p (Thread: %lu)", list_name, current->object, current->thread_id); SAFE_FREE(current->object); SAFE_FREE(current); current = next; count++; } *list_head = NULL; LeaveCriticalSection(lock); }
static HINTERNET CreateFakeHandle(DWORD magic, const char* type_name, HINTERNET hParent) { FAKE_HANDLE* handle = (FAKE_HANDLE*)SAFE_ALLOC(sizeof(FAKE_HANDLE)); if (handle) { handle->magic = magic; strncpy_s(handle->type_name, sizeof(handle->type_name), type_name, _TRUNCATE); handle->parent = (FAKE_HANDLE*)hParent; if (AddObjectToList(&g_hinternet_list, &g_hinternet_list_lock, handle)) return (HINTERNET)handle; SAFE_FREE(handle); } LogError("Failed to create fake handle of type '%s'", type_name); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
static BOOL IsValidHandle(HINTERNET hInternet) { if (!FindObjectInList(g_hinternet_list, &g_hinternet_list_lock, hInternet)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; } return TRUE; }
const char* GetHandleTypeName(HINTERNET hInternet) { if (hInternet && FindObjectInList(g_hinternet_list, &g_hinternet_list_lock, hInternet)) { return ((FAKE_HANDLE*)hInternet)->type_name; } return "INVALID"; }
const char* GetOptionName(DWORD dwOption) { switch (dwOption) { case WINHTTP_OPTION_CALLBACK: return "WINHTTP_OPTION_CALLBACK"; case WINHTTP_OPTION_RESOLVE_TIMEOUT: return "WINHTTP_OPTION_RESOLVE_TIMEOUT"; case WINHTTP_OPTION_CONNECT_TIMEOUT: return "WINHTTP_OPTION_CONNECT_TIMEOUT"; case WINHTTP_OPTION_CONNECT_RETRIES: return "WINHTTP_OPTION_CONNECT_RETRIES"; case WINHTTP_OPTION_SEND_TIMEOUT: return "WINHTTP_OPTION_SEND_TIMEOUT"; case WINHTTP_OPTION_RECEIVE_TIMEOUT: return "WINHTTP_OPTION_RECEIVE_TIMEOUT"; case WINHTTP_OPTION_USER_AGENT: return "WINHTTP_OPTION_USER_AGENT"; case WINHTTP_OPTION_SECURITY_FLAGS: return "WINHTTP_OPTION_SECURITY_FLAGS"; case WINHTTP_OPTION_PROXY: return "WINHTTP_OPTION_PROXY"; case WINHTTP_OPTION_SECURE_PROTOCOLS: return "WINHTTP_OPTION_SECURE_PROTOCOLS"; case WINHTTP_OPTION_ENABLE_FEATURE: return "WINHTTP_OPTION_ENABLE_FEATURE"; case WINHTTP_OPTION_DISABLE_FEATURE: return "WINHTTP_OPTION_DISABLE_FEATURE"; case WINHTTP_OPTION_REDIRECT_POLICY: return "WINHTTP_OPTION_REDIRECT_POLICY"; case WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET: return "WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET"; case WINHTTP_OPTION_DECOMPRESSION: return "WINHTTP_OPTION_DECOMPRESSION"; case WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL: return "WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL"; default: return "UNKNOWN_OPTION"; } }
const char* GetQueryHeaderName(DWORD dwInfoLevel) { switch (dwInfoLevel & 0x0000FFFF) { case WINHTTP_QUERY_STATUS_CODE: return "WINHTTP_QUERY_STATUS_CODE"; case WINHTTP_QUERY_STATUS_TEXT: return "WINHTTP_QUERY_STATUS_TEXT"; case WINHTTP_QUERY_CONTENT_TYPE: return "WINHTTP_QUERY_CONTENT_TYPE"; case WINHTTP_QUERY_CONTENT_LENGTH: return "WINHTTP_QUERY_CONTENT_LENGTH"; case WINHTTP_QUERY_SERVER: return "WINHTTP_QUERY_SERVER"; case WINHTTP_QUERY_LOCATION: return "WINHTTP_QUERY_LOCATION"; case WINHTTP_QUERY_SET_COOKIE: return "WINHTTP_QUERY_SET_COOKIE"; case WINHTTP_QUERY_RAW_HEADERS_CRLF: return "WINHTTP_QUERY_RAW_HEADERS_CRLF"; case WINHTTP_QUERY_CUSTOM: return "WINHTTP_QUERY_CUSTOM"; default: return "UNKNOWN_HEADER"; } }
void GetFlagsString(char* buffer, size_t size, DWORD flags, const char* flag_names[], const DWORD flag_values[], int count) { buffer[0] = '\0'; BOOL first = TRUE; for (int i = 0; i < count; i++) { if ((flags & flag_values[i])) { if (!first) strcat_s(buffer, size, " | "); strcat_s(buffer, size, flag_names[i]); first = FALSE; } } if (first) strcpy_s(buffer, size, "NONE"); }

// ============================================================================
// === ОСНОВНІ ФУНКЦІЇ (РОЗУМНІ ЗАГЛУШКИ) ===
// ============================================================================
HINTERNET WINAPI ex_WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags) { char flagsStr[128]; const char* flagNames[] = {"WINHTTP_FLAG_ASYNC", "WINHTTP_FLAG_SECURE_DEFAULTS"}; const DWORD flagValues[] = {WINHTTP_FLAG_ASYNC, WINHTTP_FLAG_SECURE_DEFAULTS}; GetFlagsString(flagsStr, sizeof(flagsStr), dwFlags, flagNames, flagValues, 2); LogInfo("WinHttpOpen(Agent: '%S', AccessType: %lu, Proxy: '%S', Bypass: '%S', Flags: 0x%lX [%s])", pszAgentW ? pszAgentW : L"<null>", dwAccessType, pszProxyW ? pszProxyW : L"<null>", pszProxyBypassW ? pszProxyBypassW : L"<null>", dwFlags, flagsStr); HINTERNET hSession = CreateFakeHandle(MAGIC_SESSION, "SESSION", NULL); LogInfo("  -> Created SESSION handle: %p", hSession); return hSession; }
BOOL WINAPI ex_WinHttpCloseHandle(HINTERNET hInternet) { LogInfo("WinHttpCloseHandle(hInternet: %p, Type: %s)", hInternet, GetHandleTypeName(hInternet)); if (RemoveObjectFromList(&g_hinternet_list, &g_hinternet_list_lock, hInternet)) { LogInfo("  -> Handle %p closed successfully.", hInternet); return TRUE; } return FALSE; }
HINTERNET WINAPI ex_WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved) { LogInfo("WinHttpConnect(hSession: %p, Server: '%S', Port: %u)", hSession, pswzServerName, nServerPort); if (!IsValidHandle(hSession)) { return NULL; } HINTERNET hConnect = CreateFakeHandle(MAGIC_CONNECT, "CONNECT", hSession); LogInfo("  -> Created CONNECT handle: %p", hConnect); return hConnect; }
HINTERNET WINAPI ex_WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR FAR * ppwszAcceptTypes, DWORD dwFlags) { char flagsStr[256]; const char* flagNames[] = {"WINHTTP_FLAG_SECURE", "WINHTTP_FLAG_BYPASS_PROXY_CACHE", "WINHTTP_FLAG_ESCAPE_DISABLE"}; const DWORD flagValues[] = {WINHTTP_FLAG_SECURE, WINHTTP_FLAG_BYPASS_PROXY_CACHE, WINHTTP_FLAG_ESCAPE_DISABLE}; GetFlagsString(flagsStr, sizeof(flagsStr), dwFlags, flagNames, flagValues, 3); LogInfo("WinHttpOpenRequest(hConnect: %p, Verb: '%S', Object: '%S', Flags: 0x%lX [%s])", hConnect, pwszVerb ? pwszVerb : L"GET", pwszObjectName ? pwszObjectName : L"/", dwFlags, flagsStr); if (!IsValidHandle(hConnect)) { return NULL; } HINTERNET hRequest = CreateFakeHandle(MAGIC_REQUEST, "REQUEST", hConnect); LogInfo("  -> Created REQUEST handle: %p", hRequest); return hRequest; }
BOOL WINAPI ex_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) { LogInfo("WinHttpSendRequest(hRequest: %p, HeadersLen: %lu, OptionalLen: %lu, TotalLen: %lu)", hRequest, dwHeadersLength, dwOptionalLength, dwTotalLength); if (!IsValidHandle(hRequest)) { return FALSE; } if (lpszHeaders && wcslen(lpszHeaders) > 0) { LogInfo("  Headers: %S", lpszHeaders); } if (lpOptional && dwOptionalLength > 0) { LogHexBuffer(LOG_LEVEL_INFO, __FUNCTION__, "  Optional Data", (const BYTE*)lpOptional, dwOptionalLength); } return TRUE; }
BOOL WINAPI ex_WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved) { LogInfo("WinHttpReceiveResponse(hRequest: %p)", hRequest); if (!IsValidHandle(hRequest)) { return FALSE; } return TRUE; }
BOOL WINAPI ex_WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) { LogDebug("WinHttpReadData(hRequest: %p, BytesToRead: %lu)", hRequest, dwNumberOfBytesToRead); if (!IsValidHandle(hRequest)) { return FALSE; } if (lpdwNumberOfBytesRead) { *lpdwNumberOfBytesRead = 0; } LogDebug("  -> Read 0 bytes (simulating end of stream)."); return TRUE; }
BOOL WINAPI ex_WinHttpWriteData(HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten) { LogInfo("WinHttpWriteData(hRequest: %p, BytesToWrite: %lu)", hRequest, dwNumberOfBytesToWrite); if (!IsValidHandle(hRequest)) { return FALSE; } LogHexBuffer(LOG_LEVEL_INFO, __FUNCTION__, "  Write Data", (const BYTE*)lpBuffer, dwNumberOfBytesToWrite); if (lpdwNumberOfBytesWritten) { *lpdwNumberOfBytesWritten = dwNumberOfBytesToWrite; } return TRUE; }
BOOL WINAPI ex_WinHttpQueryDataAvailable(HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable) { LogDebug("WinHttpQueryDataAvailable(hRequest: %p)", hRequest); if (!IsValidHandle(hRequest)) { return FALSE; } if (lpdwNumberOfBytesAvailable) { *lpdwNumberOfBytesAvailable = 0; } return TRUE; }
BOOL WINAPI ex_WinHttpQueryHeaders(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex) { const char* headerName = GetQueryHeaderName(dwInfoLevel); LogInfo("WinHttpQueryHeaders(hRequest: %p, InfoLevel: %s (%lu), Name: %S)", hRequest, headerName, dwInfoLevel, pwszName ? pwszName : L"<null>"); if (!IsValidHandle(hRequest)) { return FALSE; } const WCHAR* responseStr = NULL; DWORD responseNum = 0; BOOL isNumeric = FALSE; switch (dwInfoLevel & 0x0000FFFF) { case WINHTTP_QUERY_STATUS_CODE: responseNum = 200; isNumeric = TRUE; break; case WINHTTP_QUERY_STATUS_TEXT: responseStr = L"OK"; break; case WINHTTP_QUERY_CONTENT_TYPE: responseStr = L"text/html; charset=utf-8"; break; case WINHTTP_QUERY_SERVER: responseStr = L"WinHttp-Mock-Server/2.2"; break; case WINHTTP_QUERY_CONTENT_LENGTH: responseStr = L"0"; break; default: SetLastError(ERROR_WINHTTP_HEADER_NOT_FOUND); LogWarning("  -> Header not found or not emulated."); return FALSE; } if (isNumeric) { if (!lpBuffer || !lpdwBufferLength || *lpdwBufferLength < sizeof(DWORD)) { if(lpdwBufferLength) *lpdwBufferLength = sizeof(DWORD); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; } *(DWORD*)lpBuffer = responseNum; *lpdwBufferLength = sizeof(DWORD); LogInfo("  -> Returning numeric value: %lu", responseNum); } else { DWORD len = (DWORD)wcslen(responseStr) + 1; if (!lpBuffer || !lpdwBufferLength || *lpdwBufferLength < len * sizeof(WCHAR)) { if(lpdwBufferLength) *lpdwBufferLength = len * sizeof(WCHAR); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; } wcscpy_s((LPWSTR)lpBuffer, *lpdwBufferLength / sizeof(WCHAR), responseStr); *lpdwBufferLength = (len - 1) * sizeof(WCHAR); LogInfo("  -> Returning string value: '%S'", responseStr); } return TRUE; }
BOOL WINAPI ex_WinHttpSetOption(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength) { LogInfo("WinHttpSetOption(hInternet: %p, Option: %s (%lu), BufferLength: %lu)", hInternet, GetOptionName(dwOption), dwOption, dwBufferLength); if (hInternet && !IsValidHandle(hInternet)) { return FALSE; } switch (dwOption) { case WINHTTP_OPTION_CONNECT_TIMEOUT: case WINHTTP_OPTION_SEND_TIMEOUT: case WINHTTP_OPTION_RECEIVE_TIMEOUT: if (lpBuffer && dwBufferLength >= sizeof(DWORD)) LogInfo("  -> Timeout Value: %d ms", *(DWORD*)lpBuffer); break; case WINHTTP_OPTION_USER_AGENT: if (lpBuffer) LogInfo("  -> User-Agent: '%S'", (LPCWSTR)lpBuffer); break; case WINHTTP_OPTION_SECURE_PROTOCOLS: { char flagsStr[256]; const char* flagNames[] = {"TLS1.3", "TLS1.2", "TLS1.1", "TLS1.0", "SSL3", "SSL2"}; const DWORD flagValues[] = {WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1, WINHTTP_FLAG_SECURE_PROTOCOL_SSL3, WINHTTP_FLAG_SECURE_PROTOCOL_SSL2}; if(lpBuffer) GetFlagsString(flagsStr, sizeof(flagsStr), *(DWORD*)lpBuffer, flagNames, flagValues, 6); else strcpy_s(flagsStr, sizeof(flagsStr), "UNKNOWN"); LogInfo("  -> Secure Protocols: 0x%lX [%s]", lpBuffer ? *(DWORD*)lpBuffer : 0, flagsStr); break; } } return TRUE; }

// ============================================================================
// === ДОДАТКОВЕ ПОКРИТТЯ API (ПРОСТІ ЗАГЛУШКИ) ===
// ============================================================================
#define STUB_LOG LogDebug("STUB: %s called", __FUNCTION__)

// Функції з дампу, яких не було в headers
DWORD WINAPI ex_WinHttpCreateProxyList(void) { STUB_LOG; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpCreateProxyManager(void) { STUB_LOG; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpCreateProxyResult(void) { STUB_LOG; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpCreateUiCompatibleProxyString(void) { STUB_LOG; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpRefreshProxySettings(void) { STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpResolverGetProxyForUrl(void) { STUB_LOG; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpSetSecureLegacyServersAppCompat(void) { STUB_LOG; return ERROR_SUCCESS; }

// Решта функцій
HRESULT WINAPI ex_DllCanUnloadNow(void) { STUB_LOG; return S_FALSE; }
HRESULT WINAPI ex_DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) { STUB_LOG; return CLASS_E_CLASSNOTAVAILABLE; }
DWORD WINAPI ex_Private1(void) { STUB_LOG; return 0; }
DWORD WINAPI ex_SvchostPushServiceGlobals(LPVOID lpGlobals) { STUB_LOG; return 0; }
DWORD WINAPI ex_WinHttpAutoProxySvcMain(DWORD dwNumServicesArgs, LPWSTR* lpServiceArgVectors) { STUB_LOG; return 0; }
DWORD WINAPI ex_WinHttpPacJsWorkerMain(LPVOID p1) { STUB_LOG; return 0; }
WINHTTP_STATUS_CALLBACK WINAPI ex_WinHttpSetStatusCallback(HINTERNET h, WINHTTP_STATUS_CALLBACK c, DWORD f, DWORD_PTR r) { STUB_LOG; LogInfo("  -> Callback: %p, Flags: 0x%lX", c, f); if(h && !IsValidHandle(h)) return WINHTTP_INVALID_STATUS_CALLBACK; return NULL; }
BOOL WINAPI ex_WinHttpTimeFromSystemTime(const SYSTEMTIME* s, LPWSTR t) { STUB_LOG; if (!s || !t) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } wsprintfW(t, L"Mon, 01 Jan 2000 00:00:00 GMT"); return TRUE; }
BOOL WINAPI ex_WinHttpTimeToSystemTime(LPCWSTR t, SYSTEMTIME* s) { STUB_LOG; if (!t || !s) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } ZeroMemory(s, sizeof(SYSTEMTIME)); s->wYear=2000; s->wMonth=1; s->wDay=1; return TRUE; }
BOOL WINAPI ex_WinHttpCrackUrl(LPCWSTR u, DWORD l, DWORD f, LPURL_COMPONENTS c) { STUB_LOG; if (!u || !c || c->dwStructSize < sizeof(URL_COMPONENTS)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } ZeroMemory(c, c->dwStructSize); c->dwStructSize = sizeof(URL_COMPONENTS); return TRUE; }
BOOL WINAPI ex_WinHttpCreateUrl(LPURL_COMPONENTS c, DWORD f, LPWSTR u, LPDWORD l) { STUB_LOG; if (!c || !l) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } if (!u || *l < 8) { *l = 8; SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; } wcscpy_s(u, *l, L"http://"); *l = 7; return TRUE; }
BOOL WINAPI ex_WinHttpCheckPlatform(void) { STUB_LOG; return TRUE; }
BOOL WINAPI ex_WinHttpGetDefaultProxyConfiguration(WINHTTP_PROXY_INFO* p) { STUB_LOG; if (p) { ZeroMemory(p, sizeof(WINHTTP_PROXY_INFO)); p->dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY; } return TRUE; }
BOOL WINAPI ex_WinHttpSetDefaultProxyConfiguration(WINHTTP_PROXY_INFO* p) { STUB_LOG; return TRUE; }
DWORD WINAPI ex_WinHttpReadDataEx(HINTERNET h, LPVOID b, DWORD r, LPDWORD br, ULONGLONG f, DWORD cb, PVOID pv) { STUB_LOG; return ex_WinHttpReadData(h, b, r, br); }
BOOL WINAPI ex_WinHttpSetTimeouts(HINTERNET h, int r, int c, int s, int v) { LogInfo("%s(h=%p, Res:%d, Con:%d, Snd:%d, Rcv:%d)",__FUNCTION__,h,r,c,s,v); return TRUE; }
DWORD WINAPI ex_WinHttpIsHostInProxyBypassList(const WINHTTP_PROXY_INFO *p, PCWSTR h, INTERNET_SCHEME s, INTERNET_PORT n, BOOL *f) { STUB_LOG; if(f) *f=FALSE; return ERROR_SUCCESS; }
BOOL WINAPI ex_WinHttpAddRequestHeaders(HINTERNET h, LPCWSTR s, DWORD l, DWORD m) { LogInfo("%s(h=%p, Modifiers:0x%lX, Headers:'%S')",__FUNCTION__,h,m,s); return TRUE; }
DWORD WINAPI ex_WinHttpAddRequestHeadersEx(HINTERNET h, DWORD m, ULONGLONG f, ULONGLONG e, DWORD c, WINHTTP_EXTENDED_HEADER *p) { STUB_LOG; return ERROR_SUCCESS; }
BOOL WINAPI ex_WinHttpSetCredentials(HINTERNET h, DWORD t, DWORD s, LPCWSTR u, LPCWSTR pw, LPVOID pa) { STUB_LOG; return TRUE; }
BOOL WINAPI ex_WinHttpQueryAuthSchemes(HINTERNET h, LPDWORD s, LPDWORD f, LPDWORD t) { STUB_LOG; if(s) *s=0; if(f) *f=0; if(t) *t=0; return TRUE; }
BOOL WINAPI ex_WinHttpQueryAuthParams(HINTERNET h, DWORD a, LPVOID* p) { STUB_LOG; if(p) *p=NULL; return TRUE; }
BOOL WINAPI ex_WinHttpQueryOption(HINTERNET h, DWORD o, LPVOID b, LPDWORD l) { STUB_LOG; if (l) *l = 0; SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
DWORD WINAPI ex_WinHttpQueryHeadersEx(HINTERNET h, DWORD l, ULONGLONG f, UINT cp, PDWORD i, PWINHTTP_HEADER_NAME n, PVOID b, PDWORD bl, PWINHTTP_EXTENDED_HEADER *ph, PDWORD hc) { STUB_LOG; if(bl) *bl=0; if(hc) *hc=0; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpQueryConnectionGroup(HINTERNET h, const GUID *g, ULONGLONG f, PWINHTTP_QUERY_CONNECTION_GROUP_RESULT *r) { STUB_LOG; return ERROR_NOT_SUPPORTED; }
VOID WINAPI ex_WinHttpFreeQueryConnectionGroupResult(PWINHTTP_QUERY_CONNECTION_GROUP_RESULT r) { STUB_LOG; }
BOOL WINAPI ex_WinHttpDetectAutoProxyConfigUrl(DWORD f, LPWSTR *u) { STUB_LOG; if(u) *u = NULL; SetLastError(ERROR_WINHTTP_AUTODETECTION_FAILED); return FALSE; }
BOOL WINAPI ex_WinHttpGetProxyForUrl(HINTERNET h, LPCWSTR u, WINHTTP_AUTOPROXY_OPTIONS* o, WINHTTP_PROXY_INFO* i) { STUB_LOG; SetLastError(ERROR_WINHTTP_AUTODETECTION_FAILED); return FALSE; }
DWORD WINAPI ex_WinHttpCreateProxyResolver(HINTERNET h, HINTERNET *r) { STUB_LOG; if(r) *r = CreateFakeHandle(MAGIC_RESOLVER, "RESOLVER", h); return ERROR_SUCCESS; }
VOID WINAPI ex_WinHttpFreeProxyResolver(HINTERNET r) { STUB_LOG; ex_WinHttpCloseHandle(r); }
DWORD WINAPI ex_WinHttpGetProxyForUrlEx(HINTERNET h, PCWSTR u, WINHTTP_AUTOPROXY_OPTIONS *o, DWORD_PTR c) { STUB_LOG; return ERROR_WINHTTP_AUTODETECTION_FAILED; }
DWORD WINAPI ex_WinHttpGetProxyForUrlEx2(HINTERNET h, PCWSTR u, WINHTTP_AUTOPROXY_OPTIONS *o, DWORD cb, BYTE *p, DWORD_PTR c) { STUB_LOG; return ERROR_WINHTTP_AUTODETECTION_FAILED; }
DWORD WINAPI ex_WinHttpGetProxyResult(HINTERNET h, WINHTTP_PROXY_RESULT *p) { STUB_LOG; return ERROR_WINHTTP_INCORRECT_HANDLE_STATE; }
VOID WINAPI ex_WinHttpFreeProxyResult(WINHTTP_PROXY_RESULT *p) { STUB_LOG; }
DWORD WINAPI ex_WinHttpResetAutoProxy(HINTERNET h, DWORD f) { STUB_LOG; return ERROR_SUCCESS; }
BOOL WINAPI ex_WinHttpGetIEProxyConfigForCurrentUser(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* p) { STUB_LOG; if (p) ZeroMemory(p, sizeof(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG)); return TRUE; }
DWORD WINAPI ex_WinHttpWriteProxySettings(HINTERNET h, BOOL f, WINHTTP_PROXY_SETTINGS *p) { STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpReadProxySettings(HINTERNET h, PCWSTR n, BOOL f1, BOOL f2, DWORD *v, BOOL *r, WINHTTP_PROXY_SETTINGS *p) { STUB_LOG; if(v) *v=1; if(r) *r=TRUE; if(p) ZeroMemory(p, sizeof(WINHTTP_PROXY_SETTINGS)); return ERROR_SUCCESS; }
VOID WINAPI ex_WinHttpFreeProxySettings(WINHTTP_PROXY_SETTINGS *p) { STUB_LOG; }
DWORD WINAPI ex_WinHttpGetProxySettingsVersion(HINTERNET h, DWORD *v) { STUB_LOG; if(v) *v=1; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpSetProxySettingsPerUser(BOOL f) { STUB_LOG; return ERROR_SUCCESS; }
HINTERNET WINAPI ex_WinHttpWebSocketCompleteUpgrade(HINTERNET h, DWORD_PTR c) { STUB_LOG; if (!IsValidHandle(h)) return NULL; return CreateFakeHandle(MAGIC_WEBSOCKET, "WEBSOCKET", h); }
DWORD WINAPI ex_WinHttpWebSocketSend(HINTERNET h, WINHTTP_WEB_SOCKET_BUFFER_TYPE t, PVOID b, DWORD l) { STUB_LOG; if (!IsValidHandle(h)) return ERROR_INVALID_HANDLE; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpWebSocketReceive(HINTERNET h, PVOID b, DWORD l, DWORD *br, WINHTTP_WEB_SOCKET_BUFFER_TYPE *t) { STUB_LOG; if (!IsValidHandle(h)) return ERROR_INVALID_HANDLE; if (br) *br = 0; if (t) *t=WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE; return ERROR_WINHTTP_TIMEOUT; }
DWORD WINAPI ex_WinHttpWebSocketShutdown(HINTERNET h, USHORT s, PVOID r, DWORD l) { STUB_LOG; if (!IsValidHandle(h)) return ERROR_INVALID_HANDLE; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpWebSocketClose(HINTERNET h, USHORT s, PVOID r, DWORD l) { STUB_LOG; if (!IsValidHandle(h)) return ERROR_INVALID_HANDLE; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpWebSocketQueryCloseStatus(HINTERNET h, USHORT *s, PVOID r, DWORD l, DWORD *c) { STUB_LOG; if (!IsValidHandle(h)) return ERROR_INVALID_HANDLE; if(s)*s=WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS; if(c)*c=0; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpRegisterProxyChangeNotification(ULONGLONG f, WINHTTP_PROXY_CHANGE_CALLBACK cb, PVOID c, WINHTTP_PROXY_CHANGE_REGISTRATION_HANDLE* rh) { STUB_LOG; if(rh) *rh = (WINHTTP_PROXY_CHANGE_REGISTRATION_HANDLE)0xDEADBEEF; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpUnregisterProxyChangeNotification(WINHTTP_PROXY_CHANGE_REGISTRATION_HANDLE rh) { STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpGetProxySettingsEx(HINTERNET h, WINHTTP_PROXY_SETTINGS_TYPE t, PWINHTTP_PROXY_SETTINGS_PARAM p, DWORD_PTR c) { STUB_LOG; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpGetProxySettingsResultEx(HINTERNET h, PVOID p) { STUB_LOG; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpFreeProxySettingsEx(WINHTTP_PROXY_SETTINGS_TYPE t, PVOID p) { STUB_LOG; return ERROR_SUCCESS; }
HINTERNET WINAPI ex_WinHttpProtocolCompleteUpgrade(HINTERNET h, DWORD_PTR c) { STUB_LOG; return NULL; }
DWORD WINAPI ex_WinHttpProtocolSend(HINTERNET h, ULONGLONG f, PVOID b, DWORD l) { STUB_LOG; return ERROR_INVALID_HANDLE; }
DWORD WINAPI ex_WinHttpProtocolReceive(HINTERNET h, ULONGLONG f, PVOID b, DWORD l, DWORD *br) { STUB_LOG; return ERROR_INVALID_HANDLE; }
DWORD WINAPI ex_WinHttpGetProxyResultEx(HINTERNET h, void *p) { STUB_LOG; return ERROR_WINHTTP_INCORRECT_HANDLE_STATE; }
VOID WINAPI ex_WinHttpFreeProxyResultEx(void *p) { STUB_LOG; }
DWORD WINAPI ex_WinHttpGetProxyForUrlHvsi(LPVOID p1, LPVOID p2, LPVOID p3, LPVOID p4) { STUB_LOG; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpGetTunnelSocket(HINTERNET h, SOCKET* s) { STUB_LOG; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpProbeConnectivity(LPVOID p1, LPVOID p2, LPVOID p3) { STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpReadProxySettingsHvsi(LPVOID p1, LPVOID p2, LPVOID p3, LPVOID p4) { STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpSaveProxyCredentials(LPVOID p1, LPVOID p2, LPVOID p3) { STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpSetSecureProtocols(HINTERNET h, DWORD p) { STUB_LOG; return ERROR_SUCCESS; }
BOOL WINAPI ex_WinHttpQueryCertificate(HINTERNET h, DWORD l, LPVOID b, LPDWORD bl) { STUB_LOG; SetLastError(ERROR_WINHTTP_INCORRECT_HANDLE_STATE); return FALSE; }
BOOL WINAPI ex_WinHttpSetClientCertificate(HINTERNET h, DWORD i, LPVOID c) { STUB_LOG; return TRUE; }
DWORD WINAPI ex_WinHttpConnectionDeletePolicyEntries(LPVOID p1){ STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionDeleteProxyInfo(LPVOID p1){ STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionFreeNameList(LPVOID p1){ STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionFreeProxyInfo(LPVOID p1){ STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionFreeProxyList(LPVOID p1){ STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionGetNameList(LPVOID p1){ STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionGetProxyInfo(LPVOID p1){ STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionGetProxyList(LPVOID p1){ STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionOnlyConvert(LPVOID p1, LPVOID p2){ STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionOnlyReceive(LPVOID p1, LPVOID p2){ STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionOnlySend(LPVOID p1, LPVOID p2){ STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionSetPolicyEntries(LPVOID p1){ STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionSetProxyInfo(LPVOID p1){ STUB_LOG; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionUpdateIfIndexTable(LPVOID p1){ STUB_LOG; return ERROR_SUCCESS; }

// ============================================================================
// === DLL MAIN ===
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
        if (AllocConsole()) {
            FILE* fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
            SetConsoleTitleA("WinHttp Stub Debug Console v1.0");
        }
#endif
#if ENABLE_FILE_LOGGING
        {
            char log_path[MAX_PATH]; char exe_path[MAX_PATH]; GetModuleFileNameA(NULL, exe_path, MAX_PATH);
            char* last_slash = strrchr(exe_path, '\\'); if (last_slash) *(last_slash + 1) = '\0';
            snprintf(log_path, MAX_PATH, "%swinhttp_mock.log", exe_path);
            fopen_s(&g_log_file, log_path, "a");
        }
#endif
        LogInfo("=== WINHTTP STUB v1.0 LOADED ==="); LogInfo("Build: %s %s", __DATE__, __TIME__);
        break;
    case DLL_PROCESS_DETACH:
        LogInfo("=== WINHTTP STUB v1.0 UNLOADING ===");
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
            if (g_log_file) { LogInfo("Closing log file."); fclose(g_log_file); g_log_file = NULL; }
            DeleteCriticalSection(&g_log_lock);
#endif
            g_locks_initialized = FALSE;
        }
#if ENABLE_DEBUG_CONSOLE
        printf("\nWinHttp Stub Unloading complete...\n"); FreeConsole();
#endif
        break;
    }
    return TRUE;
}

#ifdef __cplusplus
}
#endif