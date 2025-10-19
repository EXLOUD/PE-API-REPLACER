#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <stdio.h>

// ============================================================================
// НАЛАШТУВАННЯ ЛОГУВАННЯ
// ============================================================================
#define ENABLE_DEBUG_CONSOLE 0  // 1 = показувати консоль для дебагу, 0 = без консолі
#define ENABLE_FILE_LOGGING  0  // 1 = писати лог у файл, 0 = без файлу

// ============================================================================
// СИСТЕМА ЛОГУВАННЯ
// ============================================================================

#if ENABLE_FILE_LOGGING
static FILE* g_log_file = NULL;
static CRITICAL_SECTION g_log_lock;
#endif

#if ENABLE_FILE_LOGGING || ENABLE_DEBUG_CONSOLE
    #define LOG_FUNC_CALL() LogMessage("[%s]", __FUNCTION__)
#else
    #define LOG_FUNC_CALL() ((void)0)
#endif

void GetTimestamp(char* buffer, size_t bufferSize) {
    #if ENABLE_FILE_LOGGING || ENABLE_DEBUG_CONSOLE
    SYSTEMTIME st;
    GetLocalTime(&st);
    sprintf_s(buffer, bufferSize, "[%02d:%02d:%02d.%03d]", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    #endif
}

void LogMessage(const char* format, ...) {
    #if ENABLE_FILE_LOGGING || ENABLE_DEBUG_CONSOLE
    char t[20];
    GetTimestamp(t,sizeof(t));
    va_list args;
    va_start(args, format);

    #if ENABLE_FILE_LOGGING
    if (g_log_file) {
        EnterCriticalSection(&g_log_lock);
        fprintf(g_log_file, "%s ", t);
        vfprintf(g_log_file, format, args);
        fprintf(g_log_file, "\n");
        fflush(g_log_file);
        LeaveCriticalSection(&g_log_lock);
    }
    #endif

    #if ENABLE_DEBUG_CONSOLE
    printf("[WININET] %s ", t);
    vprintf(format, args);
    printf("\n");
    #endif

    va_end(args);
    #endif
}

// ============================================================================
// ТИПИ ТА ВИЗНАЧЕННЯ
// ============================================================================

#ifndef LPINTERNET_CACHE_CONFIG_INFOA
typedef void* LPINTERNET_CACHE_CONFIG_INFOA;
typedef void* LPINTERNET_CACHE_CONFIG_INFOW;
#endif

#ifndef WEB_SOCKET_BUFFER_TYPE
typedef DWORD WEB_SOCKET_BUFFER_TYPE;
typedef DWORD* PWEB_SOCKET_BUFFER_TYPE;
#endif

#ifndef INTERNET_COOKIE_SENT_OK
#define INTERNET_COOKIE_SENT_OK 0
#endif

// ============================================================================
// МАКРОСИ ВІДПОВІДЕЙ (з логуванням)
// ============================================================================

#define OFFLINE_NULL() do { LogMessage("  -> OFFLINE (NULL)"); SetLastError(ERROR_INTERNET_DISCONNECTED); return NULL; } while(0)
#define OFFLINE_FALSE() do { LogMessage("  -> OFFLINE (FALSE)"); SetLastError(ERROR_INTERNET_DISCONNECTED); return FALSE; } while(0)
#define CANNOT_CONNECT_NULL() do { LogMessage("  -> CANNOT_CONNECT (NULL)"); SetLastError(ERROR_INTERNET_CANNOT_CONNECT); return NULL; } while(0)
#define CANNOT_CONNECT_FALSE() do { LogMessage("  -> CANNOT_CONNECT (FALSE)"); SetLastError(ERROR_INTERNET_CANNOT_CONNECT); return FALSE; } while(0)
#define BOOL_FALSE() do { LogMessage("  -> INTERNAL_ERROR (FALSE)"); SetLastError(ERROR_INTERNET_INTERNAL_ERROR); return FALSE; } while(0)
#define BOOL_TRUE() do { LogMessage("  -> SUCCESS (TRUE)"); return TRUE; } while(0)
#define POINTER_NULL() do { LogMessage("  -> INTERNAL_ERROR (NULL)"); SetLastError(ERROR_INTERNET_INTERNAL_ERROR); return NULL; } while(0)
#define DWORD_VAL(val) do { LogMessage("  -> SUCCESS (%lu)", (DWORD)(val)); return val; } while(0)
#define HRESULT_FAIL() do { LogMessage("  -> E_FAIL"); return E_FAIL; } while(0)
#define HRESULT_OK() do { LogMessage("  -> S_OK"); return S_OK; } while(0)
#define VOID_RETURN() do { LogMessage("  -> VOID"); return; } while(0)

// ============================================================================
// ОСНОВНІ ФУНКЦІЇ ПЕРЕВІРКИ З'ЄДНАННЯ
// ============================================================================

BOOL WINAPI ex_InternetGetConnectedState(LPDWORD lpdwFlags, DWORD dwReserved) {
    LOG_FUNC_CALL();
    if (lpdwFlags) {
        *lpdwFlags = INTERNET_CONNECTION_OFFLINE;
    }
    SetLastError(ERROR_INTERNET_DISCONNECTED);
    LogMessage("  -> OFFLINE (FALSE), flags set to INTERNET_CONNECTION_OFFLINE");
    return FALSE;
}

BOOL WINAPI ex_InternetGetConnectedStateExA(LPDWORD lpdwFlags, LPSTR lpszConnectionName, DWORD dwBufLen, DWORD dwReserved) {
    LOG_FUNC_CALL();
    if (lpdwFlags) *lpdwFlags = INTERNET_CONNECTION_OFFLINE;
    if (lpszConnectionName && dwBufLen > 0) lpszConnectionName[0] = '\0';
    SetLastError(ERROR_INTERNET_DISCONNECTED);
    LogMessage("  -> OFFLINE (FALSE), flags set to INTERNET_CONNECTION_OFFLINE");
    return FALSE;
}

BOOL WINAPI ex_InternetGetConnectedStateExW(LPDWORD lpdwFlags, LPWSTR lpszConnectionName, DWORD dwBufLen, DWORD dwReserved) {
    LOG_FUNC_CALL();
    if (lpdwFlags) *lpdwFlags = INTERNET_CONNECTION_OFFLINE;
    if (lpszConnectionName && dwBufLen > 0) lpszConnectionName[0] = L'\0';
    SetLastError(ERROR_INTERNET_DISCONNECTED);
    LogMessage("  -> OFFLINE (FALSE), flags set to INTERNET_CONNECTION_OFFLINE");
    return FALSE;
}

BOOL WINAPI ex_InternetGetConnectedStateEx(LPDWORD lpdwFlags, LPSTR lpszConnectionName, DWORD dwBufLen, DWORD dwReserved) {
    LOG_FUNC_CALL();
    return ex_InternetGetConnectedStateExA(lpdwFlags, lpszConnectionName, dwBufLen, dwReserved);
}

BOOL WINAPI ex_InternetCheckConnectionA(LPCSTR lpszUrl, DWORD dwFlags, DWORD dwReserved) {
    LOG_FUNC_CALL();
    LogMessage("  URL: %s", lpszUrl ? lpszUrl : "NULL");
    CANNOT_CONNECT_FALSE();
}

BOOL WINAPI ex_InternetCheckConnectionW(LPCWSTR lpszUrl, DWORD dwFlags, DWORD dwReserved) {
    LOG_FUNC_CALL();
    LogMessage("  URL: %S", lpszUrl ? lpszUrl : L"NULL");
    CANNOT_CONNECT_FALSE();
}

DWORD WINAPI ex_InternetAttemptConnect(DWORD dwReserved) {
    LOG_FUNC_CALL();
    LogMessage("  -> ERROR_INTERNET_DISCONNECTED");
    return ERROR_INTERNET_DISCONNECTED;
}

// ============================================================================
// ВСІ ІНШІ ФУНКЦІЇ З ЛОГУВАННЯМ
// ============================================================================

HINTERNET WINAPI ex_InternetOpenA(LPCSTR a, DWORD at, LPCSTR p, LPCSTR pb, DWORD f) { LOG_FUNC_CALL(); LogMessage("  Agent: %s", a ? a : "NULL"); OFFLINE_NULL(); }
HINTERNET WINAPI ex_InternetOpenW(LPCWSTR a, DWORD at, LPCWSTR p, LPCWSTR pb, DWORD f) { LOG_FUNC_CALL(); LogMessage("  Agent: %S", a ? a : L"NULL"); OFFLINE_NULL(); }
HINTERNET WINAPI ex_InternetConnectA(HINTERNET h, LPCSTR s, INTERNET_PORT p, LPCSTR u, LPCSTR pw, DWORD svc, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); LogMessage("  Server: %s", s ? s : "NULL"); CANNOT_CONNECT_NULL(); }
HINTERNET WINAPI ex_InternetConnectW(HINTERNET h, LPCWSTR s, INTERNET_PORT p, LPCWSTR u, LPCWSTR pw, DWORD svc, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); LogMessage("  Server: %S", s ? s : L"NULL"); CANNOT_CONNECT_NULL(); }
HINTERNET WINAPI ex_InternetOpenUrlA(HINTERNET h, LPCSTR u, LPCSTR hdr, DWORD hdrlen, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); LogMessage("  URL: %s", u ? u : "NULL"); OFFLINE_NULL(); }
HINTERNET WINAPI ex_InternetOpenUrlW(HINTERNET h, LPCWSTR u, LPCWSTR hdr, DWORD hdrlen, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); LogMessage("  URL: %S", u ? u : L"NULL"); OFFLINE_NULL(); }
HINTERNET WINAPI ex_HttpOpenRequestA(HINTERNET h, LPCSTR v, LPCSTR o, LPCSTR ver, LPCSTR r, LPCSTR* a, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); CANNOT_CONNECT_NULL(); }
HINTERNET WINAPI ex_HttpOpenRequestW(HINTERNET h, LPCWSTR v, LPCWSTR o, LPCWSTR ver, LPCWSTR r, LPCWSTR* a, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); CANNOT_CONNECT_NULL(); }
BOOL WINAPI ex_HttpSendRequestA(HINTERNET h, LPCSTR hdr, DWORD hdrlen, LPVOID opt, DWORD optlen) { LOG_FUNC_CALL(); CANNOT_CONNECT_FALSE(); }
BOOL WINAPI ex_HttpSendRequestW(HINTERNET h, LPCWSTR hdr, DWORD hdrlen, LPVOID opt, DWORD optlen) { LOG_FUNC_CALL(); CANNOT_CONNECT_FALSE(); }
BOOL WINAPI ex_HttpSendRequestExA(HINTERNET h, LPINTERNET_BUFFERSA bi, LPINTERNET_BUFFERSA bo, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); SetLastError(ERROR_INTERNET_CONNECTION_RESET); LogMessage("  -> CONNECTION_RESET (FALSE)"); return FALSE; }
BOOL WINAPI ex_HttpSendRequestExW(HINTERNET h, LPINTERNET_BUFFERSW bi, LPINTERNET_BUFFERSW bo, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); SetLastError(ERROR_INTERNET_CONNECTION_RESET); LogMessage("  -> CONNECTION_RESET (FALSE)"); return FALSE; }
BOOL WINAPI ex_HttpEndRequestA(HINTERNET h, LPINTERNET_BUFFERSA bo, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); OFFLINE_FALSE(); }
BOOL WINAPI ex_HttpEndRequestW(HINTERNET h, LPINTERNET_BUFFERSW bo, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); OFFLINE_FALSE(); }
BOOL WINAPI ex_HttpQueryInfoA(HINTERNET h, DWORD il, LPVOID b, LPDWORD bl, LPDWORD idx) { LOG_FUNC_CALL(); OFFLINE_FALSE(); }
BOOL WINAPI ex_HttpQueryInfoW(HINTERNET h, DWORD il, LPVOID b, LPDWORD bl, LPDWORD idx) { LOG_FUNC_CALL(); OFFLINE_FALSE(); }
BOOL WINAPI ex_HttpAddRequestHeadersA(HINTERNET h, LPCSTR hdr, DWORD len, DWORD mod) { LOG_FUNC_CALL(); OFFLINE_FALSE(); }
BOOL WINAPI ex_HttpAddRequestHeadersW(HINTERNET h, LPCWSTR hdr, DWORD len, DWORD mod) { LOG_FUNC_CALL(); OFFLINE_FALSE(); }
BOOL WINAPI ex_InternetReadFile(HINTERNET h, LPVOID b, DWORD br, LPDWORD bread) { LOG_FUNC_CALL(); if (bread) *bread = 0; OFFLINE_FALSE(); }
BOOL WINAPI ex_InternetReadFileExA(HINTERNET h, LPINTERNET_BUFFERSA bo, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); OFFLINE_FALSE(); }
BOOL WINAPI ex_InternetReadFileExW(HINTERNET h, LPINTERNET_BUFFERSW bo, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); OFFLINE_FALSE(); }
BOOL WINAPI ex_InternetQueryDataAvailable(HINTERNET h, LPDWORD ba, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); if (ba) *ba = 0; OFFLINE_FALSE(); }
BOOL WINAPI ex_InternetWriteFile(HINTERNET h, LPCVOID b, DWORD bw, LPDWORD bwritten) { LOG_FUNC_CALL(); if (bwritten) *bwritten = 0; OFFLINE_FALSE(); }
BOOL WINAPI ex_InternetCloseHandle(HINTERNET h) { LOG_FUNC_CALL(); BOOL_TRUE(); }
INTERNET_STATUS_CALLBACK WINAPI ex_InternetSetStatusCallback(HINTERNET h, INTERNET_STATUS_CALLBACK cb) { LOG_FUNC_CALL(); LogMessage("  -> NULL"); return NULL; }
INTERNET_STATUS_CALLBACK WINAPI ex_InternetSetStatusCallbackA(HINTERNET h, INTERNET_STATUS_CALLBACK cb) { LOG_FUNC_CALL(); return ex_InternetSetStatusCallback(h, cb); }
INTERNET_STATUS_CALLBACK WINAPI ex_InternetSetStatusCallbackW(HINTERNET h, INTERNET_STATUS_CALLBACK cb) { LOG_FUNC_CALL(); return ex_InternetSetStatusCallback(h, cb); }
BOOL WINAPI ex_InternetSetOptionA(HINTERNET h, DWORD o, LPVOID b, DWORD bl) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetSetOptionW(HINTERNET h, DWORD o, LPVOID b, DWORD bl) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetSetOptionExA(HINTERNET h, DWORD o, LPVOID b, DWORD bl, DWORD fl) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetSetOptionExW(HINTERNET h, DWORD o, LPVOID b, DWORD bl, DWORD fl) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetQueryOptionA(HINTERNET h, DWORD o, LPVOID b, LPDWORD bl) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetQueryOptionW(HINTERNET h, DWORD o, LPVOID b, LPDWORD bl) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_DeleteUrlCacheEntryA(LPCSTR u) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_DeleteUrlCacheEntryW(LPCWSTR u) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_DeleteUrlCacheEntry(LPCSTR u) { LOG_FUNC_CALL(); return ex_DeleteUrlCacheEntryA(u); }
BOOL WINAPI ex_DeleteUrlCacheGroup(GROUPID g, DWORD f, LPVOID r) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_CreateUrlCacheEntryA(LPCSTR u, DWORD s, LPCSTR e, LPSTR f, DWORD r) { LOG_FUNC_CALL(); if (f) f[0] = '\0'; BOOL_FALSE(); }
BOOL WINAPI ex_CreateUrlCacheEntryW(LPCWSTR u, DWORD s, LPCWSTR e, LPWSTR f, DWORD r) { LOG_FUNC_CALL(); if (f) f[0] = L'\0'; BOOL_FALSE(); }
BOOL WINAPI ex_CommitUrlCacheEntryA(LPCSTR u, LPCSTR l, FILETIME et, FILETIME lmt, DWORD cet, LPBYTE h, DWORD hs, LPCSTR fe, LPCSTR ou) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_CommitUrlCacheEntryW(LPCWSTR u, LPCWSTR l, FILETIME et, FILETIME lmt, DWORD cet, LPWSTR h, DWORD hs, LPCWSTR fe, LPCWSTR ou) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_RetrieveUrlCacheEntryFileA(LPCSTR u, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD s, DWORD r) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); BOOL_FALSE(); }
BOOL WINAPI ex_RetrieveUrlCacheEntryFileW(LPCWSTR u, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD s, DWORD r) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); BOOL_FALSE(); }
BOOL WINAPI ex_UnlockUrlCacheEntryFileA(LPCSTR u, DWORD r) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_UnlockUrlCacheEntryFileW(LPCWSTR u, DWORD r) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_UnlockUrlCacheEntryStream(HANDLE h, DWORD r) { LOG_FUNC_CALL(); BOOL_TRUE(); }
HANDLE WINAPI ex_RetrieveUrlCacheEntryStreamA(LPCSTR u, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD s, BOOL rr, DWORD r) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); POINTER_NULL(); }
HANDLE WINAPI ex_RetrieveUrlCacheEntryStreamW(LPCWSTR u, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD s, BOOL rr, DWORD r) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); POINTER_NULL(); }
BOOL WINAPI ex_ReadUrlCacheEntryStream(HANDLE h, DWORD l, LPVOID b, LPDWORD len, DWORD r) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_GetUrlCacheEntryInfoA(LPCSTR u, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD s) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); BOOL_FALSE(); }
BOOL WINAPI ex_GetUrlCacheEntryInfoW(LPCWSTR u, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD s) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); BOOL_FALSE(); }
BOOL WINAPI ex_GetUrlCacheEntryInfoExA(LPCSTR u, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD is, LPSTR ru, LPDWORD rus, LPVOID r, DWORD f) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); BOOL_FALSE(); }
BOOL WINAPI ex_GetUrlCacheEntryInfoExW(LPCWSTR u, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD is, LPWSTR ru, LPDWORD rus, LPVOID r, DWORD f) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); BOOL_FALSE(); }
BOOL WINAPI ex_SetUrlCacheEntryInfoA(LPCSTR u, LPINTERNET_CACHE_ENTRY_INFOA i, DWORD fc) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_SetUrlCacheEntryInfoW(LPCWSTR u, LPINTERNET_CACHE_ENTRY_INFOW i, DWORD fc) { LOG_FUNC_CALL(); BOOL_FALSE(); }
GROUPID WINAPI ex_CreateUrlCacheGroup(DWORD f, LPVOID r) { LOG_FUNC_CALL(); DWORD_VAL(0); }
BOOL WINAPI ex_SetUrlCacheEntryGroupA(LPCSTR u, DWORD f, GROUPID g, LPBYTE ga, DWORD gs, LPVOID r) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_SetUrlCacheEntryGroupW(LPCWSTR u, DWORD f, GROUPID g, LPBYTE ga, DWORD gs, LPVOID r) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_SetUrlCacheEntryGroup(LPCSTR u, DWORD f, GROUPID g, LPBYTE ga, DWORD gs, LPVOID r) { LOG_FUNC_CALL(); return ex_SetUrlCacheEntryGroupA(u, f, g, ga, gs, r); }
HANDLE WINAPI ex_FindFirstUrlCacheEntryA(LPCSTR p, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD s) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); POINTER_NULL(); }
HANDLE WINAPI ex_FindFirstUrlCacheEntryW(LPCWSTR p, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD s) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); POINTER_NULL(); }
HANDLE WINAPI ex_FindFirstUrlCacheEntryExA(LPCSTR p, DWORD f, DWORD fl, GROUPID g, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD s, LPVOID ga, LPDWORD gs, LPVOID r) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); POINTER_NULL(); }
HANDLE WINAPI ex_FindFirstUrlCacheEntryExW(LPCWSTR p, DWORD f, DWORD fl, GROUPID g, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD s, LPVOID ga, LPDWORD gs, LPVOID r) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); POINTER_NULL(); }
BOOL WINAPI ex_FindNextUrlCacheEntryA(HANDLE h, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD s) { LOG_FUNC_CALL(); SetLastError(ERROR_NO_MORE_FILES); BOOL_FALSE(); }
BOOL WINAPI ex_FindNextUrlCacheEntryW(HANDLE h, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD s) { LOG_FUNC_CALL(); SetLastError(ERROR_NO_MORE_FILES); BOOL_FALSE(); }
BOOL WINAPI ex_FindNextUrlCacheEntryExA(HANDLE h, LPINTERNET_CACHE_ENTRY_INFOA i, LPDWORD is, LPVOID ga, LPDWORD gs, LPVOID r) { LOG_FUNC_CALL(); SetLastError(ERROR_NO_MORE_FILES); BOOL_FALSE(); }
BOOL WINAPI ex_FindNextUrlCacheEntryExW(HANDLE h, LPINTERNET_CACHE_ENTRY_INFOW i, LPDWORD is, LPVOID ga, LPDWORD gs, LPVOID r) { LOG_FUNC_CALL(); SetLastError(ERROR_NO_MORE_FILES); BOOL_FALSE(); }
BOOL WINAPI ex_FindCloseUrlCache(HANDLE h) { LOG_FUNC_CALL(); BOOL_TRUE(); }
HANDLE WINAPI ex_FindFirstUrlCacheGroup(DWORD f, DWORD fl, LPVOID sc, DWORD scs, GROUPID* g, LPVOID r) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); POINTER_NULL(); }
BOOL WINAPI ex_FindNextUrlCacheGroup(HANDLE h, GROUPID* g, LPVOID r) { LOG_FUNC_CALL(); SetLastError(ERROR_NO_MORE_FILES); BOOL_FALSE(); }
BOOL WINAPI ex_GetUrlCacheGroupAttributeA(GROUPID g, DWORD f, DWORD a, LPINTERNET_CACHE_GROUP_INFOA i, LPDWORD s, LPVOID r) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_GetUrlCacheGroupAttributeW(GROUPID g, DWORD f, DWORD a, LPINTERNET_CACHE_GROUP_INFOW i, LPDWORD s, LPVOID r) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_SetUrlCacheGroupAttributeA(GROUPID g, DWORD f, DWORD a, LPINTERNET_CACHE_GROUP_INFOA i, LPVOID r) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_SetUrlCacheGroupAttributeW(GROUPID g, DWORD f, DWORD a, LPINTERNET_CACHE_GROUP_INFOW i, LPVOID r) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheCheckManifest() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheCloseHandle() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheCreateAndCommitFile() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheDeleteGroup() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheDeleteIEGroup() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheDuplicateHandle() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheFinalize() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheFreeDownloadList() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheFreeGroupList() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheFreeIESpace() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheFreeSpace() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheGetDownloadList() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheGetFallbackUrl() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheGetGroupList() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheGetIEGroupList() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheGetInfo() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheGetManifestUrl() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_AppCacheLookup() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_CommitUrlCacheEntryBinaryBlob() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_CreateUrlCacheContainerA() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_CreateUrlCacheContainerW() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_CreateUrlCacheEntryExW() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_DeleteIE3Cache() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_DeleteUrlCacheContainerA() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_DeleteUrlCacheContainerW() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_DeleteWpadCacheForNetworks() { LOG_FUNC_CALL(); BOOL_FALSE(); }
HANDLE WINAPI ex_FindFirstUrlCacheContainerA(LPDWORD m, LPVOID b, LPDWORD bs, DWORD o) { LOG_FUNC_CALL(); POINTER_NULL(); }
HANDLE WINAPI ex_FindFirstUrlCacheContainerW(LPDWORD m, LPVOID b, LPDWORD bs, DWORD o) { LOG_FUNC_CALL(); POINTER_NULL(); }
BOOL WINAPI ex_FindNextUrlCacheContainerA(HANDLE h, LPVOID b, LPDWORD bs) { LOG_FUNC_CALL(); SetLastError(ERROR_NO_MORE_FILES); BOOL_FALSE(); }
BOOL WINAPI ex_FindNextUrlCacheContainerW(HANDLE h, LPVOID b, LPDWORD bs) { LOG_FUNC_CALL(); SetLastError(ERROR_NO_MORE_FILES); BOOL_FALSE(); }
BOOL WINAPI ex_FreeUrlCacheSpaceA(LPCSTR p, DWORD s, DWORD f) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_FreeUrlCacheSpaceW(LPCWSTR p, DWORD s, DWORD f) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_GetUrlCacheConfigInfoA(LPINTERNET_CACHE_CONFIG_INFOA i, LPDWORD s, DWORD fc) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_GetUrlCacheConfigInfoW(LPINTERNET_CACHE_CONFIG_INFOW i, LPDWORD s, DWORD fc) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_GetUrlCacheEntryBinaryBlob() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_GetUrlCacheHeaderData() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_IncrementUrlCacheHeaderData() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_IsUrlCacheEntryExpiredA(LPCSTR u, DWORD f, LPFILETIME l) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_IsUrlCacheEntryExpiredW(LPCWSTR u, DWORD f, LPFILETIME l) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_LoadUrlCacheContent() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_ReadUrlCacheEntryStreamEx() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_RegisterUrlCacheNotification() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_RunOnceUrlCache() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_SetUrlCacheConfigInfoA(LPINTERNET_CACHE_CONFIG_INFOA i, DWORD fc) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_SetUrlCacheConfigInfoW(LPINTERNET_CACHE_CONFIG_INFOW i, DWORD fc) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_SetUrlCacheHeaderData() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UpdateUrlCacheContentPath() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheCheckEntriesExist() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheCloseEntryHandle() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheContainerSetEntryMaximumAge() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheCreateContainer() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheFindFirstEntry() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheFindNextEntry() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheFreeEntryInfo() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheFreeGlobalSpace() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheGetContentPaths() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheGetEntryInfo() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheGetGlobalCacheSize() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheGetGlobalLimit() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheReadEntryStream() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheReloadSettings() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheRetrieveEntryFile() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheRetrieveEntryStream() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheServer() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheSetGlobalLimit() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlCacheUpdateEntryExtraData() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_UrlZonesDetach() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex__GetFileExtensionFromUrl() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpCommandA(HINTERNET h, BOOL r, DWORD f, LPCSTR c, DWORD_PTR ctx, HINTERNET* ph) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpCommandW(HINTERNET h, BOOL r, DWORD f, LPCWSTR c, DWORD_PTR ctx, HINTERNET* ph) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpCreateDirectoryA(HINTERNET h, LPCSTR d) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpCreateDirectoryW(HINTERNET h, LPCWSTR d) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpDeleteFileA(HINTERNET h, LPCSTR f) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpDeleteFileW(HINTERNET h, LPCWSTR f) { LOG_FUNC_CALL(); BOOL_FALSE(); }
HINTERNET WINAPI ex_FtpFindFirstFileA(HINTERNET h, LPCSTR s, LPWIN32_FIND_DATAA d, DWORD f, DWORD_PTR ctx) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); POINTER_NULL(); }
HINTERNET WINAPI ex_FtpFindFirstFileW(HINTERNET h, LPCWSTR s, LPWIN32_FIND_DATAW d, DWORD f, DWORD_PTR ctx) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); POINTER_NULL(); }
BOOL WINAPI ex_FtpGetCurrentDirectoryA(HINTERNET h, LPSTR d, LPDWORD s) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpGetCurrentDirectoryW(HINTERNET h, LPWSTR d, LPDWORD s) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpGetFileA(HINTERNET h, LPCSTR r, LPCSTR n, BOOL fe, DWORD a, DWORD f, DWORD_PTR ctx) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpGetFileW(HINTERNET h, LPCWSTR r, LPCWSTR n, BOOL fe, DWORD a, DWORD f, DWORD_PTR ctx) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpGetFileEx(HINTERNET h, LPCSTR r, LPCWSTR n, BOOL fe, DWORD a, DWORD f, DWORD_PTR ctx) { LOG_FUNC_CALL(); BOOL_FALSE(); }
DWORD WINAPI ex_FtpGetFileSize(HINTERNET h, LPDWORD s) { LOG_FUNC_CALL(); DWORD_VAL(INVALID_FILE_SIZE); }
HINTERNET WINAPI ex_FtpOpenFileA(HINTERNET h, LPCSTR f, DWORD a, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); POINTER_NULL(); }
HINTERNET WINAPI ex_FtpOpenFileW(HINTERNET h, LPCWSTR f, DWORD a, DWORD fl, DWORD_PTR ctx) { LOG_FUNC_CALL(); POINTER_NULL(); }
BOOL WINAPI ex_FtpPutFileA(HINTERNET h, LPCSTR l, LPCSTR r, DWORD f, DWORD_PTR ctx) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpPutFileW(HINTERNET h, LPCWSTR l, LPCWSTR r, DWORD f, DWORD_PTR ctx) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpPutFileEx(HINTERNET h, LPCWSTR l, LPCSTR r, DWORD f, DWORD_PTR ctx) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpRemoveDirectoryA(HINTERNET h, LPCSTR d) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpRemoveDirectoryW(HINTERNET h, LPCWSTR d) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpRenameFileA(HINTERNET h, LPCSTR e, LPCSTR n) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpRenameFileW(HINTERNET h, LPCWSTR e, LPCWSTR n) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpSetCurrentDirectoryA(HINTERNET h, LPCSTR d) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_FtpSetCurrentDirectoryW(HINTERNET h, LPCWSTR d) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_GopherCreateLocatorA(LPCSTR h, INTERNET_PORT p, LPCSTR d, LPCSTR s, DWORD t, LPSTR l, LPDWORD bl) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_GopherCreateLocatorW(LPCWSTR h, INTERNET_PORT p, LPCWSTR d, LPCWSTR s, DWORD t, LPWSTR l, LPDWORD bl) { LOG_FUNC_CALL(); BOOL_FALSE(); }
HINTERNET WINAPI ex_GopherFindFirstFileA(HINTERNET h, LPCSTR l, LPCSTR s, LPGOPHER_FIND_DATAA d, DWORD f, DWORD_PTR ctx) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); POINTER_NULL(); }
HINTERNET WINAPI ex_GopherFindFirstFileW(HINTERNET h, LPCWSTR l, LPCWSTR s, LPGOPHER_FIND_DATAW d, DWORD f, DWORD_PTR ctx) { LOG_FUNC_CALL(); SetLastError(ERROR_FILE_NOT_FOUND); POINTER_NULL(); }
BOOL WINAPI ex_GopherGetAttributeA(HINTERNET h, LPCSTR l, LPCSTR a, LPBYTE b, DWORD bl, LPDWORD cr, GOPHER_ATTRIBUTE_ENUMERATOR e, DWORD_PTR ctx) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_GopherGetAttributeW(HINTERNET h, LPCWSTR l, LPCWSTR a, LPBYTE b, DWORD bl, LPDWORD cr, GOPHER_ATTRIBUTE_ENUMERATOR e, DWORD_PTR ctx) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_GopherGetLocatorTypeA(LPCSTR l, LPDWORD t) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_GopherGetLocatorTypeW(LPCWSTR l, LPDWORD t) { LOG_FUNC_CALL(); BOOL_FALSE(); }
HINTERNET WINAPI ex_GopherOpenFileA(HINTERNET h, LPCSTR l, LPCSTR v, DWORD f, DWORD_PTR ctx) { LOG_FUNC_CALL(); POINTER_NULL(); }
HINTERNET WINAPI ex_GopherOpenFileW(HINTERNET h, LPCWSTR l, LPCWSTR v, DWORD f, DWORD_PTR ctx) { LOG_FUNC_CALL(); POINTER_NULL(); }
BOOL WINAPI ex_HttpWebSocketClose(HINTERNET h, USHORT s, PVOID r, DWORD rl) { LOG_FUNC_CALL(); BOOL_FALSE(); }
HINTERNET WINAPI ex_HttpWebSocketCompleteUpgrade(HINTERNET h, DWORD_PTR ctx) { LOG_FUNC_CALL(); POINTER_NULL(); }
BOOL WINAPI ex_HttpWebSocketQueryCloseStatus(HINTERNET h, PUSHORT s, PVOID r, DWORD rl, PDWORD rl_read) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_HttpWebSocketReceive(HINTERNET h, PVOID b, DWORD bl, PDWORD bread, PWEB_SOCKET_BUFFER_TYPE t) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_HttpWebSocketSend(HINTERNET h, WEB_SOCKET_BUFFER_TYPE t, PVOID b, DWORD bl) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_HttpWebSocketShutdown(HINTERNET h, USHORT s, PVOID r, DWORD rl) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_DetectAutoProxyUrl(LPSTR pu, DWORD pul, DWORD df) { LOG_FUNC_CALL(); if (pu && pul > 0) pu[0] = '\0'; BOOL_FALSE(); }
BOOL WINAPI ex_HttpCheckDavCompliance(LPCWSTR u, LPCWSTR dq, LPVOID ib, DWORD ibs, LPVOID ob, DWORD obs, LPDWORD obsr) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_HttpCloseDependencyHandle(HINTERNET h) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_HttpDuplicateDependencyHandle(HINTERNET h, HINTERNET* ph) { LOG_FUNC_CALL(); if (ph) *ph = NULL; BOOL_FALSE(); }
BOOL WINAPI ex_HttpGetServerCredentials() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_HttpGetTunnelSocket() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_HttpIndicatePageLoadComplete() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_HttpIsHostHstsEnabled() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_HttpOpenDependencyHandle() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_HttpPushClose() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_HttpPushEnable() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_HttpPushWait() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetAlgIdToStringA() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetAlgIdToStringW() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetAutodial(DWORD f, HWND h) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetAutodialCallback() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetAutodialHangup(DWORD r) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetCanonicalizeUrlA(LPCSTR u, LPSTR b, LPDWORD s, DWORD f) { LOG_FUNC_CALL(); if (u && b && s) { strncpy_s(b, *s, u, _TRUNCATE); } BOOL_TRUE(); }
BOOL WINAPI ex_InternetCanonicalizeUrlW(LPCWSTR u, LPWSTR b, LPDWORD s, DWORD f) { LOG_FUNC_CALL(); if (u && b && s) { wcsncpy_s(b, *s, u, _TRUNCATE); } BOOL_TRUE(); }
BOOL WINAPI ex_InternetClearAllPerSiteCookieDecisions() { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetCombineUrlA(LPCSTR bu, LPCSTR ru, LPSTR b, LPDWORD s, DWORD f) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetCombineUrlW(LPCWSTR bu, LPCWSTR ru, LPWSTR b, LPDWORD s, DWORD f) { LOG_FUNC_CALL(); BOOL_FALSE(); }
DWORD WINAPI ex_InternetConfirmZoneCrossingA(HWND h, LPSTR up, LPSTR un, BOOL p) { LOG_FUNC_CALL(); DWORD_VAL(0); }
DWORD WINAPI ex_InternetConfirmZoneCrossingW(HWND h, LPWSTR up, LPWSTR un, BOOL p) { LOG_FUNC_CALL(); DWORD_VAL(0); }
DWORD WINAPI ex_InternetConfirmZoneCrossing(HWND h, LPSTR up, LPSTR un, BOOL p) { LOG_FUNC_CALL(); return ex_InternetConfirmZoneCrossingA(h, up, un, p); }
BOOL WINAPI ex_InternetConvertUrlFromWireToWideChar() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetCrackUrlA(LPCSTR u, DWORD ul, DWORD f, LPURL_COMPONENTSA c) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetCrackUrlW(LPCWSTR u, DWORD ul, DWORD f, LPURL_COMPONENTSW c) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetCreateUrlA(LPURL_COMPONENTSA c, DWORD f, LPSTR u, LPDWORD ul) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetCreateUrlW(LPURL_COMPONENTSW c, DWORD f, LPWSTR u, LPDWORD ul) { LOG_FUNC_CALL(); BOOL_FALSE(); }
DWORD WINAPI ex_InternetDial(HWND h, LPSTR c, DWORD f, LPDWORD con, DWORD r) { LOG_FUNC_CALL(); DWORD_VAL(0); }
DWORD WINAPI ex_InternetDialA(HWND h, LPSTR c, DWORD f, DWORD_PTR* con, DWORD r) { LOG_FUNC_CALL(); DWORD_VAL(0); }
DWORD WINAPI ex_InternetDialW(HWND h, LPWSTR c, DWORD f, DWORD_PTR* con, DWORD r) { LOG_FUNC_CALL(); DWORD_VAL(0); }
BOOL WINAPI ex_InternetEnumPerSiteCookieDecisionA(LPSTR s, unsigned long* ss, unsigned long* d, unsigned long i) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetEnumPerSiteCookieDecisionW(LPWSTR s, unsigned long* ss, unsigned long* d, unsigned long i) { LOG_FUNC_CALL(); BOOL_FALSE(); }
DWORD WINAPI ex_InternetErrorDlg(HWND h, HINTERNET r, DWORD e, DWORD f, LPVOID* d) { LOG_FUNC_CALL(); DWORD_VAL(0); }
BOOL WINAPI ex_InternetFindNextFileA(HINTERNET h, LPVOID d) { LOG_FUNC_CALL(); SetLastError(ERROR_NO_MORE_FILES); BOOL_FALSE(); }
BOOL WINAPI ex_InternetFindNextFileW(HINTERNET h, LPVOID d) { LOG_FUNC_CALL(); SetLastError(ERROR_NO_MORE_FILES); BOOL_FALSE(); }
BOOL WINAPI ex_InternetFortezzaCommand() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetFreeCookies(HANDLE h, DWORD f) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetFreeProxyInfoList() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetCertByURLA() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetCertByURL(LPCSTR u, PCCERT_CONTEXT* c, DWORD f) { LOG_FUNC_CALL(); return ex_InternetGetCertByURLA(); }
BOOL WINAPI ex_InternetGetCookieA(LPCSTR u, LPCSTR n, LPSTR d, LPDWORD s) { LOG_FUNC_CALL(); SetLastError(ERROR_NO_MORE_ITEMS); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetCookieW(LPCWSTR u, LPCWSTR n, LPWSTR d, LPDWORD s) { LOG_FUNC_CALL(); SetLastError(ERROR_NO_MORE_ITEMS); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetCookieEx2() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetCookieExA(LPCSTR u, LPCSTR n, LPSTR d, LPDWORD s, DWORD f, LPVOID r) { LOG_FUNC_CALL(); SetLastError(ERROR_NO_MORE_ITEMS); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetCookieExW(LPCWSTR u, LPCWSTR n, LPWSTR d, LPDWORD s, DWORD f, LPVOID r) { LOG_FUNC_CALL(); SetLastError(ERROR_NO_MORE_ITEMS); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetLastResponseInfoA(LPDWORD e, LPSTR b, LPDWORD s) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetLastResponseInfoW(LPDWORD e, LPWSTR b, LPDWORD s) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetPerSiteCookieDecisionA(LPCSTR h, unsigned long* r) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetPerSiteCookieDecisionW(LPCWSTR h, unsigned long* r) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetProxyForUrl() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetSecurityInfoByURLA() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetSecurityInfoByURLW() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGetSecurityInfoByURL(LPCWSTR u, PCCERT_CHAIN_CONTEXT* c, DWORD *f) { LOG_FUNC_CALL(); return ex_InternetGetSecurityInfoByURLW(); }
BOOL WINAPI ex_InternetGoOnlineA(LPSTR u, HWND h, DWORD f) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGoOnlineW(LPWSTR u, HWND h, DWORD f) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetGoOnline(LPSTR u, HWND h, DWORD f) { LOG_FUNC_CALL(); return ex_InternetGoOnlineA(u, h, f); }
DWORD WINAPI ex_InternetHangUp(DWORD_PTR c, DWORD r) { LOG_FUNC_CALL(); DWORD_VAL(0); }
BOOL WINAPI ex_InternetInitializeAutoProxyDll(DWORD r) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetLockRequestFile(HINTERNET h, HANDLE* l) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetQueryFortezzaStatus() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetSecurityProtocolToStringA() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetSecurityProtocolToStringW() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetSetCookieA(LPCSTR u, LPCSTR n, LPCSTR d) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetSetCookieW(LPCWSTR u, LPCWSTR n, LPCWSTR d) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetSetCookieEx2() { LOG_FUNC_CALL(); BOOL_FALSE(); }
DWORD WINAPI ex_InternetSetCookieExA(LPCSTR u, LPCSTR n, LPCSTR d, DWORD f, DWORD_PTR r) { LOG_FUNC_CALL(); return INTERNET_COOKIE_SENT_OK; }
DWORD WINAPI ex_InternetSetCookieExW(LPCWSTR u, LPCWSTR n, LPCWSTR d, DWORD f, DWORD_PTR r) { LOG_FUNC_CALL(); return INTERNET_COOKIE_SENT_OK; }
BOOL WINAPI ex_InternetSetDialStateA(LPCSTR c, DWORD s, DWORD r) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetSetDialStateW(LPCWSTR c, DWORD s, DWORD r) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetSetDialState(LPCSTR c, DWORD s, DWORD r) { LOG_FUNC_CALL(); return ex_InternetSetDialStateA(c, s, r); }
DWORD WINAPI ex_InternetSetFilePointer(HINTERNET h, LONG d, PVOID r, DWORD m, DWORD_PTR ctx) { LOG_FUNC_CALL(); DWORD_VAL(0); }
BOOL WINAPI ex_InternetSetPerSiteCookieDecisionA(LPCSTR h, DWORD d) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetSetPerSiteCookieDecisionW(LPCWSTR h, DWORD d) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetSetSecureLegacyServersAppCompat() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetShowSecurityInfoByURLA() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetShowSecurityInfoByURLW() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetShowSecurityInfoByURL(HWND h, LPCWSTR u) { LOG_FUNC_CALL(); return ex_InternetShowSecurityInfoByURLW(); }
BOOL WINAPI ex_InternetTimeFromSystemTimeA(const SYSTEMTIME* pst, DWORD rfc, LPSTR t, DWORD s) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetTimeFromSystemTimeW(const SYSTEMTIME* pst, DWORD rfc, LPWSTR t, DWORD s) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetTimeFromSystemTime(const SYSTEMTIME* pst, DWORD rfc, LPSTR t, DWORD s) { LOG_FUNC_CALL(); return ex_InternetTimeFromSystemTimeA(pst, rfc, t, s); }
BOOL WINAPI ex_InternetTimeToSystemTimeA(LPCSTR t, SYSTEMTIME* pst, DWORD r) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetTimeToSystemTimeW(LPCWSTR t, SYSTEMTIME* pst, DWORD r) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetTimeToSystemTime(LPCSTR t, SYSTEMTIME* pst, DWORD r) { LOG_FUNC_CALL(); return ex_InternetTimeToSystemTimeA(t, pst, r); }
BOOL WINAPI ex_InternetUnlockRequestFile(HANDLE h) { LOG_FUNC_CALL(); BOOL_TRUE(); }
BOOL WINAPI ex_InternetWriteFileExA() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_InternetWriteFileExW() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_IsHostInProxyBypassList() { LOG_FUNC_CALL(); BOOL_FALSE(); }
DWORD WINAPI ex_PrivacyGetZonePreferenceW(DWORD z, DWORD t, LPDWORD pt, LPWSTR b, LPDWORD s) { LOG_FUNC_CALL(); DWORD_VAL(0); }
DWORD WINAPI ex_PrivacySetZonePreferenceW(DWORD z, DWORD t, DWORD tmpl, LPCWSTR p) { LOG_FUNC_CALL(); DWORD_VAL(0); }
BOOL WINAPI ex_UnlockUrlCacheEntryFile(LPCSTR u, DWORD r) { LOG_FUNC_CALL(); return ex_UnlockUrlCacheEntryFileA(u, r); }
BOOL WINAPI ex_CreateMD5SSOHash(PWSTR ci, PWSTR r, PWSTR t, PBYTE h) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_DispatchAPICall() { LOG_FUNC_CALL(); BOOL_FALSE(); }
HRESULT WINAPI ex_DllCanUnloadNow(void) { LOG_FUNC_CALL(); return S_FALSE; }
HRESULT WINAPI ex_DllGetClassObject(REFCLSID c, REFIID i, LPVOID* ppv) { LOG_FUNC_CALL(); if (ppv) *ppv = NULL; return E_FAIL; }
HRESULT WINAPI ex_DllInstall(BOOL b, PCWSTR c) { LOG_FUNC_CALL(); HRESULT_OK(); }
HRESULT WINAPI ex_DllRegisterServer(void) { LOG_FUNC_CALL(); HRESULT_OK(); }
HRESULT WINAPI ex_DllUnregisterServer(void) { LOG_FUNC_CALL(); HRESULT_OK(); }
BOOL WINAPI ex_ForceNexusLookup() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_ForceNexusLookupExW() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_GetProxyDllInfo() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_ParseX509EncodedCertificateForListBoxEntry() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_ResumeSuspendedDownload(HINTERNET h, DWORD r) { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_ShowCertificate() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_ShowClientAuthCerts() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_ShowSecurityInfo() { LOG_FUNC_CALL(); BOOL_FALSE(); }
BOOL WINAPI ex_ShowX509EncodedCertificate() { LOG_FUNC_CALL(); BOOL_FALSE(); }

// ============================================================================
// DLLMAIN
// ============================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        #if ENABLE_DEBUG_CONSOLE
        if (AllocConsole()) {
            FILE* fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
            freopen_s(&fDummy, "CONOUT$", "w", stderr);
            freopen_s(&fDummy, "CONIN$", "r", stdin);
            SetConsoleTitleA("WinINet Stub Debug Console");
        }
        #endif

        #if ENABLE_FILE_LOGGING
        InitializeCriticalSection(&g_log_lock);
        char log_path[MAX_PATH];
        if (GetTempPathA(MAX_PATH, log_path) > 0) {
            strcat_s(log_path, MAX_PATH, "wininet_stub_log.txt");
            fopen_s(&g_log_file, log_path, "a");
            #if ENABLE_DEBUG_CONSOLE
            if (g_log_file) {
                 printf("[WININET] Log file created at: %s\n", log_path);
            } else {
                 printf("[WININET] ERROR: Could not create log file at: %s\n", log_path);
            }
            #endif
        }
        #endif

        LogMessage("=== WinINet Stub Loaded ===");
        break;

    case DLL_PROCESS_DETACH:
        LogMessage("=== WinINet Stub Unloading ===");

        #if ENABLE_FILE_LOGGING
        if (g_log_file) {
            fclose(g_log_file);
            g_log_file = NULL;
        }
        DeleteCriticalSection(&g_log_lock);
        #endif

        #if ENABLE_DEBUG_CONSOLE
        FreeConsole();
        #endif
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}