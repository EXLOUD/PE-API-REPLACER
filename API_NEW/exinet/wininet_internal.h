#ifndef _WININET_INTERNAL_H_
#define _WININET_INTERNAL_H_

// ============================================================
// Build / behavior switches
// ============================================================
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#define ENABLE_DEBUG_CONSOLE 1
#define ENABLE_FILE_LOGGING  0

// 1 = інтернет дозволено, 0 = емулювати "інтернету немає"
#define EMULATE_INTERNET_ONLINE 0

// Для iphlpapi (GetAdaptersAddresses) і деяких API достатньо Vista/Win7+.
// Можеш підняти/опустити якщо потрібно.
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

// ============================================================
// Includes (ВАЖЛИВИЙ ПОРЯДОК)
// winsock2.h MUST be included before windows.h
// ============================================================
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <wininet.h>
#include <winerror.h>

// Якщо хочеш реально викликати GetAdaptersAddresses у InternetGetConnectedStateEx*
// (і щоб iphlpapi.dll був у імпортах) — лишай цей include.
#include <iphlpapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// ============================================================
// Link with your custom winsock layer
// ============================================================
#pragma comment(lib, "exws2.lib")

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// Internal handle types / structures
// ============================================================

typedef enum {
    HANDLE_ROOT         = INTERNET_HANDLE_TYPE_INTERNET,
    HANDLE_HTTP_CONNECT = INTERNET_HANDLE_TYPE_CONNECT_HTTP,
    HANDLE_HTTP_REQUEST = INTERNET_HANDLE_TYPE_HTTP_REQUEST,
    HANDLE_FTP_CONNECT  = INTERNET_HANDLE_TYPE_CONNECT_FTP,
    HANDLE_FTP_FILE     = INTERNET_HANDLE_TYPE_FTP_FILE
} HandleType;

typedef struct _HEADER {
    HandleType   type;
    HINTERNET    parent;
    SOCKET       sock;

    char         host[INTERNET_MAX_HOST_NAME_LENGTH];
    INTERNET_PORT port;
    DWORD        flags;
    DWORD_PTR    context;

    char         verb[16];
    char         path[INTERNET_MAX_PATH_LENGTH];

    char*        request_headers;
    DWORD        request_headers_len;

    DWORD        status_code;
    char         status_text[64];

    char*        response_headers;
    DWORD        response_headers_len;
    BOOL         headers_received;

    DWORD        content_length;   // (DWORD)-1 if unknown
    DWORD        content_read;

    char         content_type[128];

    BOOL         chunked;

    char*        overflow_buffer;
    DWORD        overflow_size;

    void*        user_data;

    // (якщо використовуєш chunked upload/download стан)
    BOOL         send_chunked_request;
    DWORD        chunk_remaining;
    BOOL         chunk_eof;
} HEADER;

// ============================================================
// Globals / helpers
// ============================================================
extern BOOL g_wsInitialized;
extern HINSTANCE g_hInst;

BOOL InitWinsock(void);
void CleanupWinsock(void);
void Log(const char* fmt, ...);

// ============================================================
// Stub macros
// ============================================================
#define STUB_TRUE(name)  BOOL WINAPI ex_##name(void) { Log(#name " (stub)"); return TRUE; }
#define STUB_FALSE(name) BOOL WINAPI ex_##name(void) { Log(#name " (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
#define STUB_NULL(name)  void* WINAPI ex_##name(void) { Log(#name " (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
#define STUB_OK(name)    DWORD WINAPI ex_##name(void) { Log(#name " (stub)"); return ERROR_SUCCESS; }

// ============================================================
// Function declarations (EXINET exports / internal calls between .c files)
// ============================================================

// --- Core session/connection/request ---
HINTERNET WINAPI ex_InternetOpenA(
    LPCSTR lpszAgent, DWORD dwAccessType,
    LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);

HINTERNET WINAPI ex_InternetOpenW(
    LPCWSTR lpszAgent, DWORD dwAccessType,
    LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags);

HINTERNET WINAPI ex_InternetConnectA(
    HINTERNET hInternet, LPCSTR lpszServerName,
    INTERNET_PORT nServerPort, LPCSTR lpszUserName,
    LPCSTR lpszPassword, DWORD dwService,
    DWORD dwFlags, DWORD_PTR dwContext);

HINTERNET WINAPI ex_InternetConnectW(
    HINTERNET hInternet, LPCWSTR lpszServerName,
    INTERNET_PORT nServerPort, LPCWSTR lpszUserName,
    LPCWSTR lpszPassword, DWORD dwService,
    DWORD dwFlags, DWORD_PTR dwContext);

HINTERNET WINAPI ex_HttpOpenRequestA(
    HINTERNET hConnect, LPCSTR lpszVerb,
    LPCSTR lpszObjectName, LPCSTR lpszVersion,
    LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes,
    DWORD dwFlags, DWORD_PTR dwContext);

HINTERNET WINAPI ex_HttpOpenRequestW(
    HINTERNET hConnect, LPCWSTR lpszVerb,
    LPCWSTR lpszObjectName, LPCWSTR lpszVersion,
    LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes,
    DWORD dwFlags, DWORD_PTR dwContext);

BOOL WINAPI ex_HttpAddRequestHeadersA(
    HINTERNET hRequest, LPCSTR lpszHeaders,
    DWORD dwHeadersLength, DWORD dwModifiers);

BOOL WINAPI ex_HttpAddRequestHeadersW(
    HINTERNET hRequest, LPCWSTR lpszHeaders,
    DWORD dwHeadersLength, DWORD dwModifiers);

BOOL WINAPI ex_HttpSendRequestA(
    HINTERNET hRequest, LPCSTR lpszHeaders,
    DWORD dwHeadersLength, LPVOID lpOptional,
    DWORD dwOptionalLength);

BOOL WINAPI ex_HttpSendRequestW(
    HINTERNET hRequest, LPCWSTR lpszHeaders,
    DWORD dwHeadersLength, LPVOID lpOptional,
    DWORD dwOptionalLength);

BOOL WINAPI ex_HttpQueryInfoA(
    HINTERNET hRequest, DWORD dwInfoLevel,
    LPVOID lpBuffer, LPDWORD lpdwBufferLength,
    LPDWORD lpdwIndex);

BOOL WINAPI ex_HttpQueryInfoW(
    HINTERNET hRequest, DWORD dwInfoLevel,
    LPVOID lpBuffer, LPDWORD lpdwBufferLength,
    LPDWORD lpdwIndex);

// Extended HTTP (chunked upload path in stubs.c)
BOOL WINAPI ex_HttpSendRequestExA(
    HINTERNET hRequest,
    LPINTERNET_BUFFERSA lpBuffersIn,
    LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD dwFlags, DWORD_PTR dwContext);

BOOL WINAPI ex_HttpSendRequestExW(
    HINTERNET hRequest,
    LPINTERNET_BUFFERSW lpBuffersIn,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD dwFlags, DWORD_PTR dwContext);

BOOL WINAPI ex_HttpEndRequestA(
    HINTERNET hRequest,
    LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD dwFlags, DWORD_PTR dwContext);

BOOL WINAPI ex_HttpEndRequestW(
    HINTERNET hRequest,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD dwFlags, DWORD_PTR dwContext);

// --- Read/Write/Close ---
BOOL WINAPI ex_InternetReadFile(
    HINTERNET hFile, LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead);

BOOL WINAPI ex_InternetReadFileExA(
    HINTERNET hFile, LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD dwFlags, DWORD_PTR dwContext);

BOOL WINAPI ex_InternetReadFileExW(
    HINTERNET hFile, LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD dwFlags, DWORD_PTR dwContext);

BOOL WINAPI ex_InternetWriteFile(
    HINTERNET hFile, LPCVOID lpBuffer,
    DWORD dwNumberOfBytesToWrite,
    LPDWORD lpdwNumberOfBytesWritten);

BOOL WINAPI ex_InternetWriteFileExA(
    HINTERNET hFile, LPINTERNET_BUFFERSA lpBuffersIn,
    DWORD dwFlags, DWORD_PTR dwContext);

BOOL WINAPI ex_InternetWriteFileExW(
    HINTERNET hFile, LPINTERNET_BUFFERSW lpBuffersIn,
    DWORD dwFlags, DWORD_PTR dwContext);

BOOL WINAPI ex_InternetQueryDataAvailable(
    HINTERNET hFile, LPDWORD lpdwNumberOfBytesAvailable,
    DWORD dwFlags, DWORD_PTR dwContext);

DWORD WINAPI ex_InternetSetFilePointer(
    HINTERNET hFile, LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh,
    DWORD dwMoveMethod, DWORD_PTR dwContext);

BOOL WINAPI ex_InternetCloseHandle(HINTERNET hInternet);

// --- Options ---
BOOL WINAPI ex_InternetQueryOptionA(
    HINTERNET hInternet, DWORD dwOption,
    LPVOID lpBuffer, LPDWORD lpdwBufferLength);

BOOL WINAPI ex_InternetQueryOptionW(
    HINTERNET hInternet, DWORD dwOption,
    LPVOID lpBuffer, LPDWORD lpdwBufferLength);

BOOL WINAPI ex_InternetSetOptionA(
    HINTERNET hInternet, DWORD dwOption,
    LPVOID lpBuffer, DWORD dwBufferLength);

BOOL WINAPI ex_InternetSetOptionW(
    HINTERNET hInternet, DWORD dwOption,
    LPVOID lpBuffer, DWORD dwBufferLength);

BOOL WINAPI ex_InternetSetOptionExA(
    HINTERNET hInternet, DWORD dwOption,
    LPVOID lpBuffer, DWORD dwBufferLength, DWORD dwFlags);

BOOL WINAPI ex_InternetSetOptionExW(
    HINTERNET hInternet, DWORD dwOption,
    LPVOID lpBuffer, DWORD dwBufferLength, DWORD dwFlags);

// --- Convenience URL open ---
HINTERNET WINAPI ex_InternetOpenUrlA(
    HINTERNET hInternet, LPCSTR lpszUrl,
    LPCSTR lpszHeaders, DWORD dwHeadersLength,
    DWORD dwFlags, DWORD_PTR dwContext);

HINTERNET WINAPI ex_InternetOpenUrlW(
    HINTERNET hInternet, LPCWSTR lpszUrl,
    LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    DWORD dwFlags, DWORD_PTR dwContext);

// --- Connection state / check ---
BOOL WINAPI ex_InternetGetConnectedState(LPDWORD lpdwFlags, DWORD dwReserved);

BOOL WINAPI ex_InternetGetConnectedStateExA(
    LPDWORD lpdwFlags, LPSTR lpszConnectionName,
    DWORD cchNameLen, DWORD dwReserved);

BOOL WINAPI ex_InternetGetConnectedStateExW(
    LPDWORD lpdwFlags, LPWSTR lpszConnectionName,
    DWORD cchNameLen, DWORD dwReserved);

DWORD WINAPI ex_InternetAttemptConnect(DWORD dwReserved);

BOOL WINAPI ex_InternetCheckConnectionA(LPCSTR lpszUrl, DWORD dwFlags, DWORD dwReserved);
BOOL WINAPI ex_InternetCheckConnectionW(LPCWSTR lpszUrl, DWORD dwFlags, DWORD dwReserved);

// --- URL helper functions ---
BOOL WINAPI ex_InternetCrackUrlA(LPCSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSA lpUrlComponents);
BOOL WINAPI ex_InternetCrackUrlW(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents);
BOOL WINAPI ex_InternetCreateUrlA(LPURL_COMPONENTSA lpUrlComponents, DWORD dwFlags, LPSTR lpszUrl, LPDWORD lpdwUrlLength);
BOOL WINAPI ex_InternetCreateUrlW(LPURL_COMPONENTSW lpUrlComponents, DWORD dwFlags, LPWSTR lpszUrl, LPDWORD lpdwUrlLength);
BOOL WINAPI ex_InternetCanonicalizeUrlA(LPCSTR lpszUrl, LPSTR lpszBuffer, LPDWORD lpdwBufferLength, DWORD dwFlags);
BOOL WINAPI ex_InternetCanonicalizeUrlW(LPCWSTR lpszUrl, LPWSTR lpszBuffer, LPDWORD lpdwBufferLength, DWORD dwFlags);
BOOL WINAPI ex_InternetCombineUrlA(LPCSTR lpszBaseUrl, LPCSTR lpszRelativeUrl, LPSTR lpszBuffer, LPDWORD lpdwBufferLength, DWORD dwFlags);
BOOL WINAPI ex_InternetCombineUrlW(LPCWSTR lpszBaseUrl, LPCWSTR lpszRelativeUrl, LPWSTR lpszBuffer, LPDWORD lpdwBufferLength, DWORD dwFlags);

// --- FTP minimal declarations (your project has stubs) ---
HINTERNET WINAPI ex_FtpOpenFileA(HINTERNET hConnect, LPCSTR lpszFileName, DWORD dwAccess, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI ex_FtpOpenFileW(HINTERNET hConnect, LPCWSTR lpszFileName, DWORD dwAccess, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI ex_FtpPutFileA(HINTERNET hConnect, LPCSTR lpszLocalFile, LPCSTR lpszNewRemoteFile, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI ex_FtpPutFileW(HINTERNET hConnect, LPCWSTR lpszLocalFile, LPCWSTR lpszNewRemoteFile, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI ex_FtpGetFileA(HINTERNET hConnect, LPCSTR lpszRemoteFile, LPCSTR lpszNewFile, BOOL fFailIfExists,
                           DWORD dwFlagsAndAttributes, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI ex_FtpGetFileW(HINTERNET hConnect, LPCWSTR lpszRemoteFile, LPCWSTR lpszNewFile, BOOL fFailIfExists,
                           DWORD dwFlagsAndAttributes, DWORD dwFlags, DWORD_PTR dwContext);

// --- Cookies (your stubs) ---
BOOL WINAPI ex_InternetGetCookieA(LPCSTR lpszUrl, LPCSTR lpszCookieName, LPSTR lpszCookieData, LPDWORD lpdwSize);
BOOL WINAPI ex_InternetGetCookieW(LPCWSTR lpszUrl, LPCWSTR lpszCookieName, LPWSTR lpszCookieData, LPDWORD lpdwSize);
BOOL WINAPI ex_InternetSetCookieA(LPCSTR lpszUrl, LPCSTR lpszCookieName, LPCSTR lpszCookieData);
BOOL WINAPI ex_InternetSetCookieW(LPCWSTR lpszUrl, LPCWSTR lpszCookieName, LPCWSTR lpszCookieData);
BOOL WINAPI ex_InternetGetCookieExA(LPCSTR url, LPCSTR name, LPSTR data, LPDWORD size, DWORD flags, LPVOID reserved);
BOOL WINAPI ex_InternetGetCookieExW(LPCWSTR url, LPCWSTR name, LPWSTR data, LPDWORD size, DWORD flags, LPVOID reserved);
DWORD WINAPI ex_InternetSetCookieExA(LPCSTR lpszUrl, LPCSTR lpszCookieName, LPCSTR lpszCookieData, DWORD dwFlags, DWORD_PTR dwReserved);
DWORD WINAPI ex_InternetSetCookieExW(LPCWSTR lpszUrl, LPCWSTR lpszCookieName, LPCWSTR lpszCookieData, DWORD dwFlags, DWORD_PTR dwReserved);

// --- Cache (your stubs) ---
BOOL WINAPI ex_CommitUrlCacheEntryA(LPCSTR lpszUrlName, LPCSTR lpszLocalFileName, FILETIME ExpireTime, FILETIME LastModifiedTime,
                                   DWORD CacheEntryType, LPBYTE lpHeaderInfo, DWORD dwHeaderSize, LPCSTR lpszFileExtension, LPCSTR lpszOriginalUrl);
BOOL WINAPI ex_CommitUrlCacheEntryW(LPCWSTR lpszUrlName, LPCWSTR lpszLocalFileName, FILETIME ExpireTime, FILETIME LastModifiedTime,
                                   DWORD CacheEntryType, LPBYTE lpHeaderInfo, DWORD dwHeaderSize, LPCWSTR lpszFileExtension, LPCWSTR lpszOriginalUrl);
BOOL WINAPI ex_CreateUrlCacheEntryA(LPCSTR lpszUrlName, DWORD dwExpectedFileSize, LPCSTR lpszFileExtension, LPSTR lpszFileName, DWORD dwReserved);
BOOL WINAPI ex_CreateUrlCacheEntryW(LPCWSTR lpszUrlName, DWORD dwExpectedFileSize, LPCWSTR lpszFileExtension, LPWSTR lpszFileName, DWORD dwReserved);
BOOL WINAPI ex_DeleteUrlCacheEntryA(LPCSTR lpszUrlName);
BOOL WINAPI ex_DeleteUrlCacheEntryW(LPCWSTR lpszUrlName);
BOOL WINAPI ex_GetUrlCacheEntryInfoA(LPCSTR lpszUrlName, LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo, LPDWORD lpdwCacheEntryInfoBufferSize);
BOOL WINAPI ex_GetUrlCacheEntryInfoW(LPCWSTR lpszUrlName, LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo, LPDWORD lpdwCacheEntryInfoBufferSize);

// --- DLL entry points / COM stubs ---
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

HRESULT WINAPI ex_DllCanUnloadNow(void);
HRESULT WINAPI ex_DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv);
HRESULT WINAPI ex_DllInstall(BOOL bInstall, LPCWSTR pszCmdLine);
HRESULT WINAPI ex_DllRegisterServer(void);
HRESULT WINAPI ex_DllUnregisterServer(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _WININET_INTERNAL_H_