#include "wininet_internal.h"

// --- Реалізація функцій Cache ---

BOOL WINAPI ex_CommitUrlCacheEntryA(LPCSTR u, LPCSTR f, FILETIME e, FILETIME m, DWORD t, LPBYTE h, DWORD hs, LPCSTR ext, LPCSTR o) {
    Log("CommitUrlCacheEntryA: %s", u);
    return TRUE;
}

BOOL WINAPI ex_CommitUrlCacheEntryW(LPCWSTR u, LPCWSTR f, FILETIME e, FILETIME m, DWORD t, LPBYTE h, DWORD hs, LPCWSTR ext, LPCWSTR o) {
    Log("CommitUrlCacheEntryW"); 
    return TRUE;
}

BOOL WINAPI ex_CreateUrlCacheEntryA(LPCSTR lpszUrlName, DWORD dwExpectedFileSize, LPCSTR lpszFileExtension, LPSTR lpszFileName, DWORD dwReserved) {
    if (lpszFileName) strcpy(lpszFileName, "C:\\Windows\\Temp\\dummy.tmp");
    Log("CreateUrlCacheEntryA: %s", lpszUrlName);
    return TRUE;
}

BOOL WINAPI ex_CreateUrlCacheEntryW(LPCWSTR lpszUrlName, DWORD dwExpectedFileSize, LPCWSTR lpszFileExtension, LPWSTR lpszFileName, DWORD dwReserved) {
    if (lpszFileName) wcscpy(lpszFileName, L"C:\\Windows\\Temp\\dummy.tmp");
    Log("CreateUrlCacheEntryW");
    return TRUE;
}

// --- Ручна реалізація заглушок (замість STUB_FALSE), щоб уникнути конфліктів типів ---

BOOL WINAPI ex_DeleteUrlCacheEntryA(LPCSTR lpszUrlName) { 
    Log("DeleteUrlCacheEntryA called"); 
    return FALSE; 
}

BOOL WINAPI ex_DeleteUrlCacheEntryW(LPCWSTR lpszUrlName) { 
    Log("DeleteUrlCacheEntryW called"); 
    return FALSE; 
}

BOOL WINAPI ex_GetUrlCacheEntryInfoA(LPCSTR lpszUrlName, LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo, LPDWORD lpdwCacheEntryInfoBufferSize) { 
    Log("GetUrlCacheEntryInfoA called"); 
    return FALSE; 
}

BOOL WINAPI ex_GetUrlCacheEntryInfoW(LPCWSTR lpszUrlName, LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo, LPDWORD lpdwCacheEntryInfoBufferSize) { 
    Log("GetUrlCacheEntryInfoW called"); 
    return FALSE; 
}

// --- Cookies ---

BOOL WINAPI ex_InternetGetCookieA(LPCSTR lpszUrl, LPCSTR lpszCookieName, LPSTR lpszCookieData, LPDWORD lpdwSize) {
    Log("InternetGetCookieA: %s", lpszUrl);
    if (lpdwSize) *lpdwSize = 0;
    return FALSE; // Cookies not found
}

BOOL WINAPI ex_InternetGetCookieW(LPCWSTR lpszUrl, LPCWSTR lpszCookieName, LPWSTR lpszCookieData, LPDWORD lpdwSize) {
    Log("InternetGetCookieW");
    if (lpdwSize) *lpdwSize = 0;
    return FALSE;
}

BOOL WINAPI ex_InternetSetCookieA(LPCSTR lpszUrl, LPCSTR lpszCookieName, LPCSTR lpszCookieData) {
    Log("InternetSetCookieA: %s", lpszUrl);
    return TRUE;
}

BOOL WINAPI ex_InternetSetCookieW(LPCWSTR lpszUrl, LPCWSTR lpszCookieName, LPCWSTR lpszCookieData) {
    Log("InternetSetCookieW");
    return TRUE;
}

BOOL WINAPI ex_InternetGetCookieExA(LPCSTR url, LPCSTR name, LPSTR data, LPDWORD size, DWORD flags, LPVOID reserved) {
    return ex_InternetGetCookieA(url, name, data, size);
}

BOOL WINAPI ex_InternetGetCookieExW(LPCWSTR url, LPCWSTR name, LPWSTR data, LPDWORD size, DWORD flags, LPVOID reserved) {
    return ex_InternetGetCookieW(url, name, data, size);
}