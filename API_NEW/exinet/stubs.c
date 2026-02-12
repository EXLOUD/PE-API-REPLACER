#include "wininet_internal.h"

// ============================================================
// STUBS.C - Заглушки з правильними сигнатурами з wininet.h
// ============================================================

// ============================================================
// URL Parsing Functions
// ============================================================

BOOL WINAPI ex_InternetCrackUrlA(
    LPCSTR lpszUrl,
    DWORD dwUrlLength,
    DWORD dwFlags,
    LPURL_COMPONENTSA lpUrlComponents)
{
    Log("InternetCrackUrlA: %s", lpszUrl ? lpszUrl : "NULL");
    
    if (!lpszUrl || !lpUrlComponents) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    // Простий парсинг
    const char* p = lpszUrl;
    
    // Scheme
    if (_strnicmp(p, "https://", 8) == 0) {
        if (lpUrlComponents->lpszScheme && lpUrlComponents->dwSchemeLength > 5) {
            strcpy(lpUrlComponents->lpszScheme, "https");
            lpUrlComponents->dwSchemeLength = 5;
        }
        lpUrlComponents->nScheme = INTERNET_SCHEME_HTTPS;
        lpUrlComponents->nPort = INTERNET_DEFAULT_HTTPS_PORT;
        p += 8;
    } else if (_strnicmp(p, "http://", 7) == 0) {
        if (lpUrlComponents->lpszScheme && lpUrlComponents->dwSchemeLength > 4) {
            strcpy(lpUrlComponents->lpszScheme, "http");
            lpUrlComponents->dwSchemeLength = 4;
        }
        lpUrlComponents->nScheme = INTERNET_SCHEME_HTTP;
        lpUrlComponents->nPort = INTERNET_DEFAULT_HTTP_PORT;
        p += 7;
    } else if (_strnicmp(p, "ftp://", 6) == 0) {
        if (lpUrlComponents->lpszScheme && lpUrlComponents->dwSchemeLength > 3) {
            strcpy(lpUrlComponents->lpszScheme, "ftp");
            lpUrlComponents->dwSchemeLength = 3;
        }
        lpUrlComponents->nScheme = INTERNET_SCHEME_FTP;
        lpUrlComponents->nPort = INTERNET_DEFAULT_FTP_PORT;
        p += 6;
    }
    
    // Host
    const char* host_start = p;
    while (*p && *p != ':' && *p != '/' && *p != '?' && *p != '#') p++;
    
    if (lpUrlComponents->lpszHostName && lpUrlComponents->dwHostNameLength > 0) {
        size_t len = p - host_start;
        if (len >= lpUrlComponents->dwHostNameLength) len = lpUrlComponents->dwHostNameLength - 1;
        strncpy(lpUrlComponents->lpszHostName, host_start, len);
        lpUrlComponents->lpszHostName[len] = '\0';
        lpUrlComponents->dwHostNameLength = (DWORD)len;
    }
    
    // Port
    if (*p == ':') {
        p++;
        lpUrlComponents->nPort = (INTERNET_PORT)atoi(p);
        while (*p >= '0' && *p <= '9') p++;
    }
    
    // Path
    if (lpUrlComponents->lpszUrlPath && lpUrlComponents->dwUrlPathLength > 0) {
        if (*p == '/' || *p == '\0') {
            const char* path_start = p;
            const char* path_end = p;
            while (*path_end && *path_end != '?' && *path_end != '#') path_end++;
            
            size_t len = path_end - path_start;
            if (len == 0) {
                strcpy(lpUrlComponents->lpszUrlPath, "/");
                lpUrlComponents->dwUrlPathLength = 1;
            } else {
                if (len >= lpUrlComponents->dwUrlPathLength) len = lpUrlComponents->dwUrlPathLength - 1;
                strncpy(lpUrlComponents->lpszUrlPath, path_start, len);
                lpUrlComponents->lpszUrlPath[len] = '\0';
                lpUrlComponents->dwUrlPathLength = (DWORD)len;
            }
            p = path_end;
        }
    }
    
    // Extra Info (query string)
    if (lpUrlComponents->lpszExtraInfo && lpUrlComponents->dwExtraInfoLength > 0) {
        if (*p == '?' || *p == '#') {
            size_t len = strlen(p);
            if (len >= lpUrlComponents->dwExtraInfoLength) len = lpUrlComponents->dwExtraInfoLength - 1;
            strncpy(lpUrlComponents->lpszExtraInfo, p, len);
            lpUrlComponents->lpszExtraInfo[len] = '\0';
            lpUrlComponents->dwExtraInfoLength = (DWORD)len;
        } else {
            lpUrlComponents->lpszExtraInfo[0] = '\0';
            lpUrlComponents->dwExtraInfoLength = 0;
        }
    }
    
    return TRUE;
}

BOOL WINAPI ex_InternetCrackUrlW(
    LPCWSTR lpszUrl,
    DWORD dwUrlLength,
    DWORD dwFlags,
    LPURL_COMPONENTSW lpUrlComponents)
{
    Log("InternetCrackUrlW");
    
    if (!lpszUrl || !lpUrlComponents) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    // Конвертуємо URL в ANSI
    char urlA[INTERNET_MAX_URL_LENGTH];
    WideCharToMultiByte(CP_ACP, 0, lpszUrl, -1, urlA, sizeof(urlA), NULL, NULL);
    
    // Створюємо тимчасові ANSI буфери
    char schemeA[64] = {0};
    char hostA[INTERNET_MAX_HOST_NAME_LENGTH] = {0};
    char userA[INTERNET_MAX_USER_NAME_LENGTH] = {0};
    char passA[INTERNET_MAX_PASSWORD_LENGTH] = {0};
    char pathA[INTERNET_MAX_PATH_LENGTH] = {0};
    char extraA[INTERNET_MAX_PATH_LENGTH] = {0};
    
    URL_COMPONENTSA compA = {0};
    compA.dwStructSize = sizeof(compA);
    compA.lpszScheme = schemeA;
    compA.dwSchemeLength = sizeof(schemeA);
    compA.lpszHostName = hostA;
    compA.dwHostNameLength = sizeof(hostA);
    compA.lpszUserName = userA;
    compA.dwUserNameLength = sizeof(userA);
    compA.lpszPassword = passA;
    compA.dwPasswordLength = sizeof(passA);
    compA.lpszUrlPath = pathA;
    compA.dwUrlPathLength = sizeof(pathA);
    compA.lpszExtraInfo = extraA;
    compA.dwExtraInfoLength = sizeof(extraA);
    
    if (!ex_InternetCrackUrlA(urlA, 0, dwFlags, &compA)) {
        return FALSE;
    }
    
    // Копіюємо результати
    lpUrlComponents->nScheme = compA.nScheme;
    lpUrlComponents->nPort = compA.nPort;
    
    if (lpUrlComponents->lpszScheme && lpUrlComponents->dwSchemeLength > 0) {
        MultiByteToWideChar(CP_ACP, 0, schemeA, -1, lpUrlComponents->lpszScheme, lpUrlComponents->dwSchemeLength);
        lpUrlComponents->dwSchemeLength = (DWORD)wcslen(lpUrlComponents->lpszScheme);
    }
    if (lpUrlComponents->lpszHostName && lpUrlComponents->dwHostNameLength > 0) {
        MultiByteToWideChar(CP_ACP, 0, hostA, -1, lpUrlComponents->lpszHostName, lpUrlComponents->dwHostNameLength);
        lpUrlComponents->dwHostNameLength = (DWORD)wcslen(lpUrlComponents->lpszHostName);
    }
    if (lpUrlComponents->lpszUrlPath && lpUrlComponents->dwUrlPathLength > 0) {
        MultiByteToWideChar(CP_ACP, 0, pathA, -1, lpUrlComponents->lpszUrlPath, lpUrlComponents->dwUrlPathLength);
        lpUrlComponents->dwUrlPathLength = (DWORD)wcslen(lpUrlComponents->lpszUrlPath);
    }
    if (lpUrlComponents->lpszExtraInfo && lpUrlComponents->dwExtraInfoLength > 0) {
        MultiByteToWideChar(CP_ACP, 0, extraA, -1, lpUrlComponents->lpszExtraInfo, lpUrlComponents->dwExtraInfoLength);
        lpUrlComponents->dwExtraInfoLength = (DWORD)wcslen(lpUrlComponents->lpszExtraInfo);
    }
    
    return TRUE;
}

BOOL WINAPI ex_InternetCreateUrlA(
    LPURL_COMPONENTSA lpUrlComponents,
    DWORD dwFlags,
    LPSTR lpszUrl,
    LPDWORD lpdwUrlLength)
{
    Log("InternetCreateUrlA");
    
    if (!lpUrlComponents || !lpdwUrlLength) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    char temp[INTERNET_MAX_URL_LENGTH];
    int len = snprintf(temp, sizeof(temp), "%s://%s:%d%s%s",
        lpUrlComponents->lpszScheme ? lpUrlComponents->lpszScheme : "http",
        lpUrlComponents->lpszHostName ? lpUrlComponents->lpszHostName : "",
        (int)lpUrlComponents->nPort,
        lpUrlComponents->lpszUrlPath ? lpUrlComponents->lpszUrlPath : "/",
        lpUrlComponents->lpszExtraInfo ? lpUrlComponents->lpszExtraInfo : "");
    
    if (lpszUrl && *lpdwUrlLength > (DWORD)len) {
        strcpy(lpszUrl, temp);
        *lpdwUrlLength = (DWORD)len;
        return TRUE;
    }
    
    *lpdwUrlLength = (DWORD)len + 1;
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return FALSE;
}

BOOL WINAPI ex_InternetCreateUrlW(
    LPURL_COMPONENTSW lpUrlComponents,
    DWORD dwFlags,
    LPWSTR lpszUrl,
    LPDWORD lpdwUrlLength)
{
    Log("InternetCreateUrlW");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI ex_InternetCanonicalizeUrlA(
    LPCSTR lpszUrl,
    LPSTR lpszBuffer,
    LPDWORD lpdwBufferLength,
    DWORD dwFlags)
{
    Log("InternetCanonicalizeUrlA: %s", lpszUrl ? lpszUrl : "NULL");
    
    if (!lpszUrl || !lpdwBufferLength) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    DWORD len = (DWORD)strlen(lpszUrl);
    if (lpszBuffer && *lpdwBufferLength > len) {
        strcpy(lpszBuffer, lpszUrl);
        *lpdwBufferLength = len;
        return TRUE;
    }
    
    *lpdwBufferLength = len + 1;
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return FALSE;
}

BOOL WINAPI ex_InternetCanonicalizeUrlW(
    LPCWSTR lpszUrl,
    LPWSTR lpszBuffer,
    LPDWORD lpdwBufferLength,
    DWORD dwFlags)
{
    Log("InternetCanonicalizeUrlW");
    
    if (!lpszUrl || !lpdwBufferLength) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    DWORD len = (DWORD)wcslen(lpszUrl);
    if (lpszBuffer && *lpdwBufferLength > len) {
        wcscpy(lpszBuffer, lpszUrl);
        *lpdwBufferLength = len;
        return TRUE;
    }
    
    *lpdwBufferLength = len + 1;
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return FALSE;
}

BOOL WINAPI ex_InternetCombineUrlA(
    LPCSTR lpszBaseUrl,
    LPCSTR lpszRelativeUrl,
    LPSTR lpszBuffer,
    LPDWORD lpdwBufferLength,
    DWORD dwFlags)
{
    Log("InternetCombineUrlA");
    
    if (!lpdwBufferLength) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    // Простий випадок - якщо relative є абсолютним URL
    if (lpszRelativeUrl && (strstr(lpszRelativeUrl, "://") != NULL)) {
        DWORD len = (DWORD)strlen(lpszRelativeUrl);
        if (lpszBuffer && *lpdwBufferLength > len) {
            strcpy(lpszBuffer, lpszRelativeUrl);
            *lpdwBufferLength = len;
            return TRUE;
        }
        *lpdwBufferLength = len + 1;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    
    // Якщо relative починається з /, беремо схему+хост з base
    if (lpszBaseUrl && lpszRelativeUrl && lpszRelativeUrl[0] == '/') {
        char temp[INTERNET_MAX_URL_LENGTH];
        const char* schemeEnd = strstr(lpszBaseUrl, "://");
        if (schemeEnd) {
            schemeEnd += 3;
            const char* hostEnd = strchr(schemeEnd, '/');
            if (!hostEnd) hostEnd = schemeEnd + strlen(schemeEnd);
            
            size_t baseLen = hostEnd - lpszBaseUrl;
            strncpy(temp, lpszBaseUrl, baseLen);
            temp[baseLen] = '\0';
            strcat(temp, lpszRelativeUrl);
            
            DWORD len = (DWORD)strlen(temp);
            if (lpszBuffer && *lpdwBufferLength > len) {
                strcpy(lpszBuffer, temp);
                *lpdwBufferLength = len;
                return TRUE;
            }
            *lpdwBufferLength = len + 1;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
    }
    
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI ex_InternetCombineUrlW(
    LPCWSTR lpszBaseUrl,
    LPCWSTR lpszRelativeUrl,
    LPWSTR lpszBuffer,
    LPDWORD lpdwBufferLength,
    DWORD dwFlags)
{
    Log("InternetCombineUrlW");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

// ============================================================
// Time Conversion Functions
// ============================================================

BOOL WINAPI ex_InternetTimeFromSystemTimeA(
    const SYSTEMTIME* pst,
    DWORD dwRFC,
    LPSTR lpszTime,
    DWORD cbTime)
{
    Log("InternetTimeFromSystemTimeA");
    
    if (!pst || !lpszTime || cbTime < 30) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    static const char* days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    
    // RFC 1123 format: "Sun, 06 Nov 1994 08:49:37 GMT"
    snprintf(lpszTime, cbTime, "%s, %02d %s %04d %02d:%02d:%02d GMT",
        days[pst->wDayOfWeek % 7],
        pst->wDay,
        months[(pst->wMonth - 1) % 12],
        pst->wYear,
        pst->wHour,
        pst->wMinute,
        pst->wSecond);
    
    return TRUE;
}

BOOL WINAPI ex_InternetTimeFromSystemTimeW(
    const SYSTEMTIME* pst,
    DWORD dwRFC,
    LPWSTR lpszTime,
    DWORD cbTime)
{
    char buf[64];
    if (!ex_InternetTimeFromSystemTimeA(pst, dwRFC, buf, sizeof(buf))) {
        return FALSE;
    }
    MultiByteToWideChar(CP_ACP, 0, buf, -1, lpszTime, cbTime / sizeof(WCHAR));
    return TRUE;
}

BOOL WINAPI ex_InternetTimeFromSystemTime(
    const SYSTEMTIME* pst,
    DWORD dwRFC,
    LPSTR lpszTime,
    DWORD cbTime)
{
    return ex_InternetTimeFromSystemTimeA(pst, dwRFC, lpszTime, cbTime);
}

BOOL WINAPI ex_InternetTimeToSystemTimeA(
    LPCSTR lpszTime,
    SYSTEMTIME* pst,
    DWORD dwReserved)
{
    Log("InternetTimeToSystemTimeA: %s", lpszTime ? lpszTime : "NULL");
    
    if (!lpszTime || !pst) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    memset(pst, 0, sizeof(SYSTEMTIME));
    GetSystemTime(pst); // Return current time as fallback
    
    return TRUE;
}

BOOL WINAPI ex_InternetTimeToSystemTimeW(
    LPCWSTR lpszTime,
    SYSTEMTIME* pst,
    DWORD dwReserved)
{
    if (!lpszTime) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    char buf[128];
    WideCharToMultiByte(CP_ACP, 0, lpszTime, -1, buf, sizeof(buf), NULL, NULL);
    return ex_InternetTimeToSystemTimeA(buf, pst, dwReserved);
}

BOOL WINAPI ex_InternetTimeToSystemTime(
    LPCSTR lpszTime,
    SYSTEMTIME* pst,
    DWORD dwReserved)
{
    return ex_InternetTimeToSystemTimeA(lpszTime, pst, dwReserved);
}

// ============================================================
// Error & Response Info
// ============================================================

BOOL WINAPI ex_InternetGetLastResponseInfoA(
    LPDWORD lpdwError,
    LPSTR lpszBuffer,
    LPDWORD lpdwBufferLength)
{
    Log("InternetGetLastResponseInfoA");
    
    if (lpdwError) *lpdwError = 0;
    if (lpdwBufferLength) {
        if (lpszBuffer && *lpdwBufferLength > 0) {
            lpszBuffer[0] = '\0';
        }
        *lpdwBufferLength = 0;
    }
    return TRUE;
}

BOOL WINAPI ex_InternetGetLastResponseInfoW(
    LPDWORD lpdwError,
    LPWSTR lpszBuffer,
    LPDWORD lpdwBufferLength)
{
    Log("InternetGetLastResponseInfoW");
    
    if (lpdwError) *lpdwError = 0;
    if (lpdwBufferLength) {
        if (lpszBuffer && *lpdwBufferLength > 0) {
            lpszBuffer[0] = L'\0';
        }
        *lpdwBufferLength = 0;
    }
    return TRUE;
}

// ============================================================
// Status Callback
// ============================================================

typedef VOID (CALLBACK * INTERNET_STATUS_CALLBACK)(
    HINTERNET hInternet,
    DWORD_PTR dwContext,
    DWORD dwInternetStatus,
    LPVOID lpvStatusInformation,
    DWORD dwStatusInformationLength
);

INTERNET_STATUS_CALLBACK WINAPI ex_InternetSetStatusCallbackA(
    HINTERNET hInternet,
    INTERNET_STATUS_CALLBACK lpfnInternetCallback)
{
    Log("InternetSetStatusCallbackA");
    return NULL;
}

INTERNET_STATUS_CALLBACK WINAPI ex_InternetSetStatusCallbackW(
    HINTERNET hInternet,
    INTERNET_STATUS_CALLBACK lpfnInternetCallback)
{
    Log("InternetSetStatusCallbackW");
    return NULL;
}

INTERNET_STATUS_CALLBACK WINAPI ex_InternetSetStatusCallback(
    HINTERNET hInternet,
    INTERNET_STATUS_CALLBACK lpfnInternetCallback)
{
    return ex_InternetSetStatusCallbackA(hInternet, lpfnInternetCallback);
}

// ============================================================
// File Operations
// ============================================================

BOOL WINAPI ex_InternetFindNextFileA(
    HINTERNET hFind,
    LPVOID lpvFindData)
{
    Log("InternetFindNextFileA");
    SetLastError(ERROR_NO_MORE_FILES);
    return FALSE;
}

BOOL WINAPI ex_InternetFindNextFileW(
    HINTERNET hFind,
    LPVOID lpvFindData)
{
    Log("InternetFindNextFileW");
    SetLastError(ERROR_NO_MORE_FILES);
    return FALSE;
}

DWORD WINAPI ex_InternetSetFilePointer(
    HINTERNET hFile,
    LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh,
    DWORD dwMoveMethod,
    DWORD_PTR dwContext)
{
    Log("InternetSetFilePointer");
    SetLastError(ERROR_INTERNET_INVALID_OPERATION);
    return INVALID_SET_FILE_POINTER;
}

BOOL WINAPI ex_InternetWriteFile(
    HINTERNET hFile,
    LPCVOID lpBuffer,
    DWORD dwNumberOfBytesToWrite,
    LPDWORD lpdwNumberOfBytesWritten)
{
    Log("InternetWriteFile");
    
    if (!hFile || !lpdwNumberOfBytesWritten) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    HEADER* h = (HEADER*)hFile;
    
    if (h->sock == INVALID_SOCKET) {
        SetLastError(ERROR_INTERNET_INCORRECT_HANDLE_STATE);
        return FALSE;
    }
    
    int sent = send(h->sock, (const char*)lpBuffer, (int)dwNumberOfBytesToWrite, 0);
    if (sent == SOCKET_ERROR) {
        SetLastError(ERROR_INTERNET_CONNECTION_ABORTED);
        return FALSE;
    }
    
    *lpdwNumberOfBytesWritten = (DWORD)sent;
    return TRUE;
}

BOOL WINAPI ex_InternetWriteFileExA(
    HINTERNET hFile,
    LPINTERNET_BUFFERSA lpBuffersIn,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    Log("InternetWriteFileExA");
    
    if (!hFile || !lpBuffersIn) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    DWORD bytesWritten = 0;
    return ex_InternetWriteFile(hFile, lpBuffersIn->lpvBuffer, 
                                 lpBuffersIn->dwBufferLength, &bytesWritten);
}

BOOL WINAPI ex_InternetWriteFileExW(
    HINTERNET hFile,
    LPINTERNET_BUFFERSW lpBuffersIn,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    Log("InternetWriteFileExW");
    
    if (!hFile || !lpBuffersIn) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    DWORD bytesWritten = 0;
    return ex_InternetWriteFile(hFile, lpBuffersIn->lpvBuffer, 
                                 lpBuffersIn->dwBufferLength, &bytesWritten);
}

BOOL WINAPI ex_InternetReadFileExA(
    HINTERNET hFile,
    LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    Log("InternetReadFileExA");
    
    if (!hFile || !lpBuffersOut) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    DWORD bytesRead = 0;
    BOOL result = ex_InternetReadFile(hFile, lpBuffersOut->lpvBuffer, 
                                       lpBuffersOut->dwBufferLength, &bytesRead);
    lpBuffersOut->dwBufferLength = bytesRead;
    return result;
}

BOOL WINAPI ex_InternetReadFileExW(
    HINTERNET hFile,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    Log("InternetReadFileExW");
    
    if (!hFile || !lpBuffersOut) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    DWORD bytesRead = 0;
    BOOL result = ex_InternetReadFile(hFile, lpBuffersOut->lpvBuffer, 
                                       lpBuffersOut->dwBufferLength, &bytesRead);
    lpBuffersOut->dwBufferLength = bytesRead;
    return result;
}

BOOL WINAPI ex_InternetLockRequestFile(
    HINTERNET hInternet,
    HANDLE* lphLockRequestInfo)
{
    Log("InternetLockRequestFile");
    if (lphLockRequestInfo) *lphLockRequestInfo = NULL;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI ex_InternetUnlockRequestFile(
    HANDLE hLockRequestInfo)
{
    Log("InternetUnlockRequestFile");
    return TRUE;
}

// ============================================================
// Autodial Functions
// ============================================================

DWORD WINAPI ex_InternetDialA(
    HWND hwndParent,
    LPSTR lpszConnectoid,
    DWORD dwFlags,
    DWORD_PTR* lpdwConnection,
    DWORD dwReserved)
{
    Log("InternetDialA");
    if (lpdwConnection) *lpdwConnection = 1;
    return ERROR_SUCCESS;
}

DWORD WINAPI ex_InternetDialW(
    HWND hwndParent,
    LPWSTR lpszConnectoid,
    DWORD dwFlags,
    DWORD_PTR* lpdwConnection,
    DWORD dwReserved)
{
    Log("InternetDialW");
    if (lpdwConnection) *lpdwConnection = 1;
    return ERROR_SUCCESS;
}

DWORD WINAPI ex_InternetDial(
    HWND hwndParent,
    LPSTR lpszConnectoid,
    DWORD dwFlags,
    LPDWORD lpdwConnection,
    DWORD dwReserved)
{
    Log("InternetDial");
    if (lpdwConnection) *lpdwConnection = 1;
    return ERROR_SUCCESS;
}

DWORD WINAPI ex_InternetHangUp(
    DWORD_PTR dwConnection,
    DWORD dwReserved)
{
    Log("InternetHangUp");
    return ERROR_SUCCESS;
}

BOOL WINAPI ex_InternetAutodial(
    DWORD dwFlags,
    HWND hwndParent)
{
    Log("InternetAutodial");
    return TRUE;
}

BOOL WINAPI ex_InternetAutodialHangup(
    DWORD dwReserved)
{
    Log("InternetAutodialHangup");
    return TRUE;
}

BOOL WINAPI ex_InternetAutodialCallback(
    DWORD dwReserved)
{
    Log("InternetAutodialCallback");
    return TRUE;
}

BOOL WINAPI ex_InternetGoOnlineA(
    LPCSTR lpszURL,
    HWND hwndParent,
    DWORD dwFlags)
{
    Log("InternetGoOnlineA");
    return TRUE;
}

BOOL WINAPI ex_InternetGoOnlineW(
    LPCWSTR lpszURL,
    HWND hwndParent,
    DWORD dwFlags)
{
    Log("InternetGoOnlineW");
    return TRUE;
}

BOOL WINAPI ex_InternetGoOnline(
    LPSTR lpszURL,
    HWND hwndParent,
    DWORD dwFlags)
{
    Log("InternetGoOnline");
    return TRUE;
}

DWORD WINAPI ex_InternetAttemptConnect(DWORD dwReserved)
{
#if !EMULATE_INTERNET_ONLINE
 Log("InternetAttemptConnect: OFFLINE");
 SetLastError(ERROR_INTERNET_DISCONNECTED);
 return ERROR_INTERNET_DISCONNECTED;
#else
 Log("InternetAttemptConnect: ONLINE");
 return ERROR_SUCCESS;
#endif
}

BOOL WINAPI ex_InternetSetDialStateA(
    LPCSTR lpszConnectoid,
    DWORD dwState,
    DWORD dwReserved)
{
    Log("InternetSetDialStateA");
    return TRUE;
}

BOOL WINAPI ex_InternetSetDialStateW(
    LPCWSTR lpszConnectoid,
    DWORD dwState,
    DWORD dwReserved)
{
    Log("InternetSetDialStateW");
    return TRUE;
}

BOOL WINAPI ex_InternetSetDialState(
    LPCSTR lpszConnectoid,
    DWORD dwState,
    DWORD dwReserved)
{
    return ex_InternetSetDialStateA(lpszConnectoid, dwState, dwReserved);
}

// ============================================================
// Connection State (without A/W suffix)
// ============================================================

BOOL WINAPI ex_InternetGetConnectedStateEx(
    LPDWORD lpdwFlags,
    LPSTR lpszConnectionName,
    DWORD dwNameLen,
    DWORD dwReserved)
{
    Log("InternetGetConnectedStateEx");
    return ex_InternetGetConnectedStateExA(lpdwFlags, lpszConnectionName, dwNameLen, dwReserved);
}

// ============================================================
// HTTP Extended Functions
// ============================================================

BOOL WINAPI ex_HttpSendRequestExA(
 HINTERNET hRequest,
 LPINTERNET_BUFFERSA lpBuffersIn,
 LPINTERNET_BUFFERSA lpBuffersOut,
 DWORD dwFlags,
 DWORD_PTR dwContext)
{
#if !EMULATE_INTERNET_ONLINE
 Log("HttpSendRequestExA: OFFLINE mode - blocked");
 SetLastError(ERROR_INTERNET_DISCONNECTED);
 return FALSE;
#endif

 Log("HttpSendRequestExA");
 if (!hRequest) {
  SetLastError(ERROR_INVALID_HANDLE);
  return FALSE;
 }

 HEADER* h = (HEADER*)hRequest;

 // Connect if not connected
 if (h->sock == INVALID_SOCKET) {
  struct hostent* he = gethostbyname(h->host);
  if (!he) {
   SetLastError(ERROR_INTERNET_NAME_NOT_RESOLVED);
   return FALSE;
  }

  h->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (h->sock == INVALID_SOCKET) {
   SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
   return FALSE;
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(h->port);
  memcpy(&addr.sin_addr, he->h_addr, he->h_length);

  if (connect(h->sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
   closesocket(h->sock);
   h->sock = INVALID_SOCKET;
   SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
   return FALSE;
  }
 }

 // Send initial headers (chunked upload)
 char request[4096];
 int len = snprintf(request, sizeof(request),
  "%s %s HTTP/1.1\r\n"
  "Host: %s\r\n"
  "Transfer-Encoding: chunked\r\n"
  "\r\n",
  h->verb, h->path, h->host);

 send(h->sock, request, len, 0);
 return TRUE;
}

BOOL WINAPI ex_HttpSendRequestExW(
    HINTERNET hRequest,
    LPINTERNET_BUFFERSW lpBuffersIn,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    Log("HttpSendRequestExW");
    return ex_HttpSendRequestExA(hRequest, NULL, NULL, dwFlags, dwContext);
}

BOOL WINAPI ex_HttpEndRequestA(
    HINTERNET hRequest,
    LPINTERNET_BUFFERSA lpBuffersOut,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    Log("HttpEndRequestA");
    
    if (!hRequest) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    
    HEADER* h = (HEADER*)hRequest;
    
    // Send final chunk marker
    if (h->sock != INVALID_SOCKET) {
        send(h->sock, "0\r\n\r\n", 5, 0);
    }
    
    return TRUE;
}

BOOL WINAPI ex_HttpEndRequestW(
    HINTERNET hRequest,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    Log("HttpEndRequestW");
    return ex_HttpEndRequestA(hRequest, NULL, dwFlags, dwContext);
}

// ============================================================
// UI Functions
// ============================================================

DWORD WINAPI ex_InternetErrorDlg(
    HWND hWnd,
    HINTERNET hRequest,
    DWORD dwError,
    DWORD dwFlags,
    LPVOID* lppvData)
{
    Log("InternetErrorDlg: error=%lu", (unsigned long)dwError);
    return ERROR_CANCELLED;
}

DWORD WINAPI ex_InternetConfirmZoneCrossingA(
    HWND hWnd,
    LPSTR szUrlPrev,
    LPSTR szUrlNew,
    BOOL bPost)
{
    Log("InternetConfirmZoneCrossingA");
    return ERROR_SUCCESS;
}

DWORD WINAPI ex_InternetConfirmZoneCrossingW(
    HWND hWnd,
    LPWSTR szUrlPrev,
    LPWSTR szUrlNew,
    BOOL bPost)
{
    Log("InternetConfirmZoneCrossingW");
    return ERROR_SUCCESS;
}

DWORD WINAPI ex_InternetConfirmZoneCrossing(
    HWND hWnd,
    LPSTR szUrlPrev,
    LPSTR szUrlNew,
    BOOL bPost)
{
    return ex_InternetConfirmZoneCrossingA(hWnd, szUrlPrev, szUrlNew, bPost);
}

// ============================================================
// URL Cache Functions
// ============================================================

HANDLE WINAPI ex_FindFirstUrlCacheEntryA(
    LPCSTR lpszUrlSearchPattern,
    LPINTERNET_CACHE_ENTRY_INFOA lpFirstCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo)
{
    Log("FindFirstUrlCacheEntryA");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return NULL;
}

HANDLE WINAPI ex_FindFirstUrlCacheEntryW(
    LPCWSTR lpszUrlSearchPattern,
    LPINTERNET_CACHE_ENTRY_INFOW lpFirstCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo)
{
    Log("FindFirstUrlCacheEntryW");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return NULL;
}

BOOL WINAPI ex_FindNextUrlCacheEntryA(
    HANDLE hEnumHandle,
    LPINTERNET_CACHE_ENTRY_INFOA lpNextCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo)
{
    Log("FindNextUrlCacheEntryA");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

BOOL WINAPI ex_FindNextUrlCacheEntryW(
    HANDLE hEnumHandle,
    LPINTERNET_CACHE_ENTRY_INFOW lpNextCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo)
{
    Log("FindNextUrlCacheEntryW");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

BOOL WINAPI ex_FindCloseUrlCache(
    HANDLE hEnumHandle)
{
    Log("FindCloseUrlCache");
    return TRUE;
}

HANDLE WINAPI ex_FindFirstUrlCacheEntryExA(
    LPCSTR lpszUrlSearchPattern,
    DWORD dwFlags,
    DWORD dwFilter,
    GROUPID GroupId,
    LPINTERNET_CACHE_ENTRY_INFOA lpFirstCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo,
    LPVOID lpGroupAttributes,
    LPDWORD lpcbGroupAttributes,
    LPVOID lpReserved)
{
    Log("FindFirstUrlCacheEntryExA");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return NULL;
}

HANDLE WINAPI ex_FindFirstUrlCacheEntryExW(
    LPCWSTR lpszUrlSearchPattern,
    DWORD dwFlags,
    DWORD dwFilter,
    GROUPID GroupId,
    LPINTERNET_CACHE_ENTRY_INFOW lpFirstCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo,
    LPVOID lpGroupAttributes,
    LPDWORD lpcbGroupAttributes,
    LPVOID lpReserved)
{
    Log("FindFirstUrlCacheEntryExW");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return NULL;
}

BOOL WINAPI ex_FindNextUrlCacheEntryExA(
    HANDLE hEnumHandle,
    LPINTERNET_CACHE_ENTRY_INFOA lpNextCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo,
    LPVOID lpGroupAttributes,
    LPDWORD lpcbGroupAttributes,
    LPVOID lpReserved)
{
    Log("FindNextUrlCacheEntryExA");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

BOOL WINAPI ex_FindNextUrlCacheEntryExW(
    HANDLE hEnumHandle,
    LPINTERNET_CACHE_ENTRY_INFOW lpNextCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo,
    LPVOID lpGroupAttributes,
    LPDWORD lpcbGroupAttributes,
    LPVOID lpReserved)
{
    Log("FindNextUrlCacheEntryExW");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

BOOL WINAPI ex_RetrieveUrlCacheEntryFileA(
    LPCSTR lpszUrlName,
    LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo,
    DWORD dwReserved)
{
    Log("RetrieveUrlCacheEntryFileA");
    SetLastError(ERROR_FILE_NOT_FOUND);
    return FALSE;
}

BOOL WINAPI ex_RetrieveUrlCacheEntryFileW(
    LPCWSTR lpszUrlName,
    LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo,
    DWORD dwReserved)
{
    Log("RetrieveUrlCacheEntryFileW");
    SetLastError(ERROR_FILE_NOT_FOUND);
    return FALSE;
}

HANDLE WINAPI ex_RetrieveUrlCacheEntryStreamA(
    LPCSTR lpszUrlName,
    LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo,
    BOOL fRandomRead,
    DWORD dwReserved)
{
    Log("RetrieveUrlCacheEntryStreamA");
    SetLastError(ERROR_FILE_NOT_FOUND);
    return NULL;
}

HANDLE WINAPI ex_RetrieveUrlCacheEntryStreamW(
    LPCWSTR lpszUrlName,
    LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo,
    BOOL fRandomRead,
    DWORD dwReserved)
{
    Log("RetrieveUrlCacheEntryStreamW");
    SetLastError(ERROR_FILE_NOT_FOUND);
    return NULL;
}

BOOL WINAPI ex_ReadUrlCacheEntryStream(
    HANDLE hUrlCacheStream,
    DWORD dwLocation,
    LPVOID lpBuffer,
    LPDWORD lpdwLen,
    DWORD Reserved)
{
    Log("ReadUrlCacheEntryStream");
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
}

BOOL WINAPI ex_ReadUrlCacheEntryStreamEx(
    HANDLE hUrlCacheStream,
    DWORDLONG qwLocation,
    LPVOID lpBuffer,
    LPDWORD lpdwLen)
{
    Log("ReadUrlCacheEntryStreamEx");
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
}

BOOL WINAPI ex_UnlockUrlCacheEntryStream(
    HANDLE hUrlCacheStream,
    DWORD Reserved)
{
    Log("UnlockUrlCacheEntryStream");
    return TRUE;
}

BOOL WINAPI ex_UnlockUrlCacheEntryFileA(
    LPCSTR lpszUrlName,
    DWORD dwReserved)
{
    Log("UnlockUrlCacheEntryFileA");
    return TRUE;
}

BOOL WINAPI ex_UnlockUrlCacheEntryFileW(
    LPCWSTR lpszUrlName,
    DWORD dwReserved)
{
    Log("UnlockUrlCacheEntryFileW");
    return TRUE;
}

BOOL WINAPI ex_UnlockUrlCacheEntryFile(
    LPCSTR lpszUrlName,
    DWORD dwReserved)
{
    return ex_UnlockUrlCacheEntryFileA(lpszUrlName, dwReserved);
}

BOOL WINAPI ex_GetUrlCacheEntryInfoExA(
    LPCSTR lpszUrl,
    LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo,
    LPSTR lpszRedirectUrl,
    LPDWORD lpcbRedirectUrl,
    LPVOID lpReserved,
    DWORD dwFlags)
{
    Log("GetUrlCacheEntryInfoExA");
    SetLastError(ERROR_FILE_NOT_FOUND);
    return FALSE;
}

BOOL WINAPI ex_GetUrlCacheEntryInfoExW(
    LPCWSTR lpszUrl,
    LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo,
    LPDWORD lpcbCacheEntryInfo,
    LPWSTR lpszRedirectUrl,
    LPDWORD lpcbRedirectUrl,
    LPVOID lpReserved,
    DWORD dwFlags)
{
    Log("GetUrlCacheEntryInfoExW");
    SetLastError(ERROR_FILE_NOT_FOUND);
    return FALSE;
}

BOOL WINAPI ex_SetUrlCacheEntryInfoA(
    LPCSTR lpszUrlName,
    LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo,
    DWORD dwFieldControl)
{
    Log("SetUrlCacheEntryInfoA");
    return TRUE;
}

BOOL WINAPI ex_SetUrlCacheEntryInfoW(
    LPCWSTR lpszUrlName,
    LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo,
    DWORD dwFieldControl)
{
    Log("SetUrlCacheEntryInfoW");
    return TRUE;
}

// ============================================================
// Cache Groups
// ============================================================

GROUPID WINAPI ex_CreateUrlCacheGroup(
    DWORD dwFlags,
    LPVOID lpReserved)
{
    Log("CreateUrlCacheGroup");
    static GROUPID nextGroup = 1;
    return nextGroup++;
}

BOOL WINAPI ex_DeleteUrlCacheGroup(
    GROUPID GroupId,
    DWORD dwFlags,
    LPVOID lpReserved)
{
    Log("DeleteUrlCacheGroup");
    return TRUE;
}

HANDLE WINAPI ex_FindFirstUrlCacheGroup(
    DWORD dwFlags,
    DWORD dwFilter,
    LPVOID lpSearchCondition,
    DWORD dwSearchCondition,
    GROUPID* lpGroupId,
    LPVOID lpReserved)
{
    Log("FindFirstUrlCacheGroup");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return NULL;
}

BOOL WINAPI ex_FindNextUrlCacheGroup(
    HANDLE hFind,
    GROUPID* lpGroupId,
    LPVOID lpReserved)
{
    Log("FindNextUrlCacheGroup");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

BOOL WINAPI ex_GetUrlCacheGroupAttributeA(
    GROUPID gid,
    DWORD dwFlags,
    DWORD dwAttributes,
    LPINTERNET_CACHE_GROUP_INFOA lpGroupInfo,
    LPDWORD lpcbGroupInfo,
    LPVOID lpReserved)
{
    Log("GetUrlCacheGroupAttributeA");
    SetLastError(ERROR_FILE_NOT_FOUND);
    return FALSE;
}

BOOL WINAPI ex_GetUrlCacheGroupAttributeW(
    GROUPID gid,
    DWORD dwFlags,
    DWORD dwAttributes,
    LPINTERNET_CACHE_GROUP_INFOW lpGroupInfo,
    LPDWORD lpcbGroupInfo,
    LPVOID lpReserved)
{
    Log("GetUrlCacheGroupAttributeW");
    SetLastError(ERROR_FILE_NOT_FOUND);
    return FALSE;
}

BOOL WINAPI ex_SetUrlCacheGroupAttributeA(
    GROUPID gid,
    DWORD dwFlags,
    DWORD dwAttributes,
    LPINTERNET_CACHE_GROUP_INFOA lpGroupInfo,
    LPVOID lpReserved)
{
    Log("SetUrlCacheGroupAttributeA");
    return TRUE;
}

BOOL WINAPI ex_SetUrlCacheGroupAttributeW(
    GROUPID gid,
    DWORD dwFlags,
    DWORD dwAttributes,
    LPINTERNET_CACHE_GROUP_INFOW lpGroupInfo,
    LPVOID lpReserved)
{
    Log("SetUrlCacheGroupAttributeW");
    return TRUE;
}

BOOL WINAPI ex_SetUrlCacheEntryGroupA(
    LPCSTR lpszUrlName,
    DWORD dwFlags,
    GROUPID GroupId,
    LPBYTE pbGroupAttributes,
    DWORD cbGroupAttributes,
    LPVOID lpReserved)
{
    Log("SetUrlCacheEntryGroupA");
    return TRUE;
}

BOOL WINAPI ex_SetUrlCacheEntryGroupW(
    LPCWSTR lpszUrlName,
    DWORD dwFlags,
    GROUPID GroupId,
    LPBYTE pbGroupAttributes,
    DWORD cbGroupAttributes,
    LPVOID lpReserved)
{
    Log("SetUrlCacheEntryGroupW");
    return TRUE;
}

BOOL WINAPI ex_SetUrlCacheEntryGroup(
    LPCSTR lpszUrlName,
    DWORD dwFlags,
    GROUPID GroupId,
    LPBYTE pbGroupAttributes,
    DWORD cbGroupAttributes,
    LPVOID lpReserved)
{
    return ex_SetUrlCacheEntryGroupA(lpszUrlName, dwFlags, GroupId, 
                                      pbGroupAttributes, cbGroupAttributes, lpReserved);
}

// ============================================================
// Delete URL Cache Entry (without suffix)
// ============================================================

BOOL WINAPI ex_DeleteUrlCacheEntry(LPCSTR lpszUrlName)
{
    Log("DeleteUrlCacheEntry");
    return ex_DeleteUrlCacheEntryA(lpszUrlName);
}

// ============================================================
// Cookie Extended Functions
// ============================================================

DWORD WINAPI ex_InternetSetCookieExA(
    LPCSTR lpszUrl,
    LPCSTR lpszCookieName,
    LPCSTR lpszCookieData,
    DWORD dwFlags,
    DWORD_PTR dwReserved)
{
    Log("InternetSetCookieExA: %s", lpszUrl ? lpszUrl : "NULL");
    return TRUE;
}

DWORD WINAPI ex_InternetSetCookieExW(
    LPCWSTR lpszUrl,
    LPCWSTR lpszCookieName,
    LPCWSTR lpszCookieData,
    DWORD dwFlags,
    DWORD_PTR dwReserved)
{
    Log("InternetSetCookieExW");
    return TRUE;
}

VOID WINAPI ex_InternetFreeCookies(
    LPVOID pCookies,
    DWORD dwCookieCount)
{
    Log("InternetFreeCookies");
    if (pCookies) free(pCookies);
}

DWORD WINAPI ex_InternetGetCookieEx2(
    LPCWSTR pcwszUrl,
    LPCWSTR pcwszCookieName,
    DWORD dwFlags,
    LPVOID* ppCookies,
    DWORD* pdwCookieCount)
{
    Log("InternetGetCookieEx2");
    if (ppCookies) *ppCookies = NULL;
    if (pdwCookieCount) *pdwCookieCount = 0;
    return ERROR_SUCCESS;
}

DWORD WINAPI ex_InternetSetCookieEx2(
    LPCWSTR pcwszUrl,
    LPCVOID pCookie,
    LPCWSTR pcwszP3PPolicy,
    DWORD dwFlags,
    DWORD* pdwCookieState)
{
    Log("InternetSetCookieEx2");
    if (pdwCookieState) *pdwCookieState = 1;
    return ERROR_SUCCESS;
}

// ============================================================
// Per-Site Cookie Decisions
// ============================================================

BOOL WINAPI ex_InternetSetPerSiteCookieDecisionA(
    LPCSTR pchHostName,
    DWORD dwDecision)
{
    Log("InternetSetPerSiteCookieDecisionA");
    return TRUE;
}

BOOL WINAPI ex_InternetSetPerSiteCookieDecisionW(
    LPCWSTR pchHostName,
    DWORD dwDecision)
{
    Log("InternetSetPerSiteCookieDecisionW");
    return TRUE;
}

BOOL WINAPI ex_InternetGetPerSiteCookieDecisionA(
    LPCSTR pchHostName,
    unsigned long* pResult)
{
    Log("InternetGetPerSiteCookieDecisionA");
    if (pResult) *pResult = 0;
    return FALSE;
}

BOOL WINAPI ex_InternetGetPerSiteCookieDecisionW(
    LPCWSTR pchHostName,
    unsigned long* pResult)
{
    Log("InternetGetPerSiteCookieDecisionW");
    if (pResult) *pResult = 0;
    return FALSE;
}

BOOL WINAPI ex_InternetClearAllPerSiteCookieDecisions(void)
{
    Log("InternetClearAllPerSiteCookieDecisions");
    return TRUE;
}

BOOL WINAPI ex_InternetEnumPerSiteCookieDecisionA(
    LPSTR pszSiteName,
    unsigned long* pcSiteNameSize,
    unsigned long* pdwDecision,
    unsigned long dwIndex)
{
    Log("InternetEnumPerSiteCookieDecisionA");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

BOOL WINAPI ex_InternetEnumPerSiteCookieDecisionW(
    LPWSTR pszSiteName,
    unsigned long* pcSiteNameSize,
    unsigned long* pdwDecision,
    unsigned long dwIndex)
{
    Log("InternetEnumPerSiteCookieDecisionW");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

// ============================================================
// Privacy Settings
// ============================================================

DWORD WINAPI ex_PrivacySetZonePreferenceW(
    DWORD dwZone,
    DWORD dwType,
    DWORD dwTemplate,
    LPCWSTR pszPreference)
{
    Log("PrivacySetZonePreferenceW");
    return ERROR_SUCCESS;
}

DWORD WINAPI ex_PrivacyGetZonePreferenceW(
    DWORD dwZone,
    DWORD dwType,
    LPDWORD pdwTemplate,
    LPWSTR pszBuffer,
    LPDWORD pdwBufferLength)
{
    Log("PrivacyGetZonePreferenceW");
    if (pdwTemplate) *pdwTemplate = PRIVACY_TEMPLATE_MEDIUM;
    return ERROR_SUCCESS;
}

// ============================================================
// Gopher Functions (Deprecated)
// ============================================================

BOOL WINAPI ex_GopherCreateLocatorA(
    LPCSTR lpszHost,
    INTERNET_PORT nServerPort,
    LPCSTR lpszDisplayString,
    LPCSTR lpszSelectorString,
    DWORD dwGopherType,
    LPSTR lpszLocator,
    LPDWORD lpdwBufferLength)
{
    Log("GopherCreateLocatorA (deprecated)");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI ex_GopherCreateLocatorW(
    LPCWSTR lpszHost,
    INTERNET_PORT nServerPort,
    LPCWSTR lpszDisplayString,
    LPCWSTR lpszSelectorString,
    DWORD dwGopherType,
    LPWSTR lpszLocator,
    LPDWORD lpdwBufferLength)
{
    Log("GopherCreateLocatorW (deprecated)");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI ex_GopherGetLocatorTypeA(
    LPCSTR lpszLocator,
    LPDWORD lpdwGopherType)
{
    Log("GopherGetLocatorTypeA (deprecated)");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI ex_GopherGetLocatorTypeW(
    LPCWSTR lpszLocator,
    LPDWORD lpdwGopherType)
{
    Log("GopherGetLocatorTypeW (deprecated)");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

HINTERNET WINAPI ex_GopherFindFirstFileA(
    HINTERNET hConnect,
    LPCSTR lpszLocator,
    LPCSTR lpszSearchString,
    LPGOPHER_FIND_DATAA lpFindData,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    Log("GopherFindFirstFileA (deprecated)");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

HINTERNET WINAPI ex_GopherFindFirstFileW(
    HINTERNET hConnect,
    LPCWSTR lpszLocator,
    LPCWSTR lpszSearchString,
    LPGOPHER_FIND_DATAW lpFindData,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    Log("GopherFindFirstFileW (deprecated)");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

HINTERNET WINAPI ex_GopherOpenFileA(
    HINTERNET hConnect,
    LPCSTR lpszLocator,
    LPCSTR lpszView,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    Log("GopherOpenFileA (deprecated)");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

HINTERNET WINAPI ex_GopherOpenFileW(
    HINTERNET hConnect,
    LPCWSTR lpszLocator,
    LPCWSTR lpszView,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    Log("GopherOpenFileW (deprecated)");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

BOOL WINAPI ex_GopherGetAttributeA(
    HINTERNET hConnect,
    LPCSTR lpszLocator,
    LPCSTR lpszAttributeName,
    LPBYTE lpBuffer,
    DWORD dwBufferLength,
    LPDWORD lpdwCharactersReturned,
    LPVOID lpfnEnumerator,
    DWORD_PTR dwContext)
{
    Log("GopherGetAttributeA (deprecated)");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI ex_GopherGetAttributeW(
    HINTERNET hConnect,
    LPCWSTR lpszLocator,
    LPCWSTR lpszAttributeName,
    LPBYTE lpBuffer,
    DWORD dwBufferLength,
    LPDWORD lpdwCharactersReturned,
    LPVOID lpfnEnumerator,
    DWORD_PTR dwContext)
{
    Log("GopherGetAttributeW (deprecated)");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

// ============================================================
// Misc Functions
// ============================================================

BOOL WINAPI ex_InternetInitializeAutoProxyDll(
    DWORD dwReserved)
{
    Log("InternetInitializeAutoProxyDll");
    return TRUE;
}

BOOL WINAPI ex_DetectAutoProxyUrl(
    LPSTR pszAutoProxyUrl,
    DWORD cchAutoProxyUrl,
    DWORD dwDetectFlags)
{
    Log("DetectAutoProxyUrl");
    if (pszAutoProxyUrl && cchAutoProxyUrl > 0) {
        pszAutoProxyUrl[0] = '\0';
    }
    return FALSE;
}

BOOL WINAPI ex_CreateMD5SSOHash(
    LPWSTR pszChallengeInfo,
    LPWSTR pwszRealm,
    LPWSTR pwszTarget,
    LPBYTE pbHexHash)
{
    Log("CreateMD5SSOHash");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI ex_ResumeSuspendedDownload(
    HINTERNET hRequest,
    DWORD dwResultCode)
{
    Log("ResumeSuspendedDownload");
    return TRUE;
}

BOOL WINAPI ex_DeleteWpadCacheForNetworks(
    DWORD dwFlags)
{
    Log("DeleteWpadCacheForNetworks");
    return TRUE;
}

DWORD WINAPI ex_HttpIsHostHstsEnabled(
    LPCWSTR pcwszUrl,
    BOOL* pfIsHsts)
{
    Log("HttpIsHostHstsEnabled");
    if (pfIsHsts) *pfIsHsts = FALSE;
    return ERROR_SUCCESS;
}

BOOL WINAPI ex_FreeUrlCacheSpaceA(
    LPCSTR lpszCachePath,
    DWORD dwSize,
    DWORD dwFilter)
{
    Log("FreeUrlCacheSpaceA");
    return TRUE;
}

BOOL WINAPI ex_FreeUrlCacheSpaceW(
    LPCWSTR lpszCachePath,
    DWORD dwSize,
    DWORD dwFilter)
{
    Log("FreeUrlCacheSpaceW");
    return TRUE;
}

BOOL WINAPI ex_GetUrlCacheConfigInfoA(
    LPVOID lpCacheConfigInfo,
    LPDWORD lpcbCacheConfigInfo,
    DWORD dwFieldControl)
{
    Log("GetUrlCacheConfigInfoA");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI ex_GetUrlCacheConfigInfoW(
    LPVOID lpCacheConfigInfo,
    LPDWORD lpcbCacheConfigInfo,
    DWORD dwFieldControl)
{
    Log("GetUrlCacheConfigInfoW");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI ex_SetUrlCacheConfigInfoA(
    LPVOID lpCacheConfigInfo,
    DWORD dwFieldControl)
{
    Log("SetUrlCacheConfigInfoA");
    return TRUE;
}

BOOL WINAPI ex_SetUrlCacheConfigInfoW(
    LPVOID lpCacheConfigInfo,
    DWORD dwFieldControl)
{
    Log("SetUrlCacheConfigInfoW");
    return TRUE;
}

// ============================================================
// InternetSetOptionEx
// ============================================================

BOOL WINAPI ex_InternetSetOptionExA(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    DWORD dwBufferLength,
    DWORD dwFlags)
{
    Log("InternetSetOptionExA: option=%lu", (unsigned long)dwOption);
    return ex_InternetSetOptionA(hInternet, dwOption, lpBuffer, dwBufferLength);
}

BOOL WINAPI ex_InternetSetOptionExW(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    DWORD dwBufferLength,
    DWORD dwFlags)
{
    Log("InternetSetOptionExW: option=%lu", (unsigned long)dwOption);
    return ex_InternetSetOptionW(hInternet, dwOption, lpBuffer, dwBufferLength);
}

// ============================================================
// FindFirstUrlCacheContainer
// ============================================================

HANDLE WINAPI ex_FindFirstUrlCacheContainerA(
    LPDWORD pdwModified,
    LPVOID lpContainerInfo,
    LPDWORD lpcbContainerInfo,
    DWORD dwOptions)
{
    Log("FindFirstUrlCacheContainerA");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return NULL;
}

HANDLE WINAPI ex_FindFirstUrlCacheContainerW(
    LPDWORD pdwModified,
    LPVOID lpContainerInfo,
    LPDWORD lpcbContainerInfo,
    DWORD dwOptions)
{
    Log("FindFirstUrlCacheContainerW");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return NULL;
}

BOOL WINAPI ex_FindNextUrlCacheContainerA(
    HANDLE hEnumHandle,
    LPVOID lpContainerInfo,
    LPDWORD lpcbContainerInfo)
{
    Log("FindNextUrlCacheContainerA");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

BOOL WINAPI ex_FindNextUrlCacheContainerW(
    HANDLE hEnumHandle,
    LPVOID lpContainerInfo,
    LPDWORD lpcbContainerInfo)
{
    Log("FindNextUrlCacheContainerW");
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}

// ============================================================
// HTTP WebSocket Functions
// ============================================================

DWORD WINAPI ex_HttpWebSocketClose(
    HINTERNET hWebSocket,
    USHORT usStatus,
    PVOID pvReason,
    DWORD dwReasonLength)
{
    Log("HttpWebSocketClose");
    return ERROR_SUCCESS;
}

HINTERNET WINAPI ex_HttpWebSocketCompleteUpgrade(
    HINTERNET hRequest,
    DWORD_PTR dwContext)
{
    Log("HttpWebSocketCompleteUpgrade");
    return NULL;
}

DWORD WINAPI ex_HttpWebSocketQueryCloseStatus(
    HINTERNET hWebSocket,
    USHORT* pusStatus,
    PVOID pvReason,
    DWORD dwReasonLength,
    DWORD* pdwReasonLengthConsumed)
{
    Log("HttpWebSocketQueryCloseStatus");
    return ERROR_INVALID_OPERATION;
}

DWORD WINAPI ex_HttpWebSocketReceive(
    HINTERNET hWebSocket,
    PVOID pvBuffer,
    DWORD dwBufferLength,
    DWORD* pdwBytesRead,
    PVOID* ppBufferType)
{
    Log("HttpWebSocketReceive");
    return ERROR_INVALID_OPERATION;
}

DWORD WINAPI ex_HttpWebSocketSend(
    HINTERNET hWebSocket,
    DWORD BufferType,
    PVOID pvBuffer,
    DWORD dwBufferLength)
{
    Log("HttpWebSocketSend");
    return ERROR_INVALID_OPERATION;
}

DWORD WINAPI ex_HttpWebSocketShutdown(
    HINTERNET hWebSocket,
    USHORT usStatus,
    PVOID pvReason,
    DWORD dwReasonLength)
{
    Log("HttpWebSocketShutdown");
    return ERROR_SUCCESS;
}

// ============================================================
// FTP Extended
// ============================================================

BOOL WINAPI ex_FtpGetFileEx(
    HINTERNET hFtpSession,
    LPCSTR lpszRemoteFile,
    LPCWSTR lpszNewFile,
    BOOL fFailIfExists,
    DWORD dwFlagsAndAttributes,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    Log("FtpGetFileEx (stub)");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI ex_FtpPutFileEx(
    HINTERNET hFtpSession,
    LPCWSTR lpszLocalFile,
    LPCSTR lpszNewRemoteFile,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    Log("FtpPutFileEx (stub)");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

// ============================================================
// Misc Simple Stubs (using macros where possible)
// ============================================================

BOOL WINAPI ex_AppCacheCheckManifest(void) { Log("AppCacheCheckManifest (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheCloseHandle(void) { Log("AppCacheCloseHandle (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheCreateAndCommitFile(void) { Log("AppCacheCreateAndCommitFile (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheDeleteGroup(void) { Log("AppCacheDeleteGroup (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheDeleteIEGroup(void) { Log("AppCacheDeleteIEGroup (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheDuplicateHandle(void) { Log("AppCacheDuplicateHandle (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheFinalize(void) { Log("AppCacheFinalize (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheFreeDownloadList(void) { Log("AppCacheFreeDownloadList (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheFreeGroupList(void) { Log("AppCacheFreeGroupList (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheFreeIESpace(void) { Log("AppCacheFreeIESpace (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheFreeSpace(void) { Log("AppCacheFreeSpace (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheGetDownloadList(void) { Log("AppCacheGetDownloadList (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheGetFallbackUrl(void) { Log("AppCacheGetFallbackUrl (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheGetGroupList(void) { Log("AppCacheGetGroupList (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheGetIEGroupList(void) { Log("AppCacheGetIEGroupList (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheGetInfo(void) { Log("AppCacheGetInfo (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheGetManifestUrl(void) { Log("AppCacheGetManifestUrl (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_AppCacheLookup(void) { Log("AppCacheLookup (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }

BOOL WINAPI ex_CommitUrlCacheEntryBinaryBlob(void) { Log("CommitUrlCacheEntryBinaryBlob (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_CreateUrlCacheContainerA(void) { Log("CreateUrlCacheContainerA (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_CreateUrlCacheContainerW(void) { Log("CreateUrlCacheContainerW (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_CreateUrlCacheEntryExW(void) { Log("CreateUrlCacheEntryExW (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_DeleteIE3Cache(void) { Log("DeleteIE3Cache (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_DeleteUrlCacheContainerA(void) { Log("DeleteUrlCacheContainerA (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_DeleteUrlCacheContainerW(void) { Log("DeleteUrlCacheContainerW (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_DispatchAPICall(void) { Log("DispatchAPICall (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_ForceNexusLookup(void) { Log("ForceNexusLookup (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_ForceNexusLookupExW(void) { Log("ForceNexusLookupExW (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_GetProxyDllInfo(void) { Log("GetProxyDllInfo (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_GetUrlCacheEntryBinaryBlob(void) { Log("GetUrlCacheEntryBinaryBlob (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_GetUrlCacheHeaderData(void) { Log("GetUrlCacheHeaderData (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_HttpCheckDavCompliance(void) { Log("HttpCheckDavCompliance (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_HttpCloseDependencyHandle(void) { Log("HttpCloseDependencyHandle (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_HttpDuplicateDependencyHandle(void) { Log("HttpDuplicateDependencyHandle (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_HttpGetServerCredentials(void) { Log("HttpGetServerCredentials (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
void* WINAPI ex_HttpGetTunnelSocket(void) { Log("HttpGetTunnelSocket (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
BOOL WINAPI ex_HttpIndicatePageLoadComplete(void) { Log("HttpIndicatePageLoadComplete (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
void* WINAPI ex_HttpOpenDependencyHandle(void) { Log("HttpOpenDependencyHandle (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
BOOL WINAPI ex_HttpPushClose(void) { Log("HttpPushClose (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_HttpPushEnable(void) { Log("HttpPushEnable (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_HttpPushWait(void) { Log("HttpPushWait (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_IncrementUrlCacheHeaderData(void) { Log("IncrementUrlCacheHeaderData (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetAlgIdToStringA(void) { Log("InternetAlgIdToStringA (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetAlgIdToStringW(void) { Log("InternetAlgIdToStringW (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetConvertUrlFromWireToWideChar(void) { Log("InternetConvertUrlFromWireToWideChar (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetFortezzaCommand(void) { Log("InternetFortezzaCommand (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetFreeProxyInfoList(void) { Log("InternetFreeProxyInfoList (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetGetCertByURL(void) { Log("InternetGetCertByURL (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetGetCertByURLA(void) { Log("InternetGetCertByURLA (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetGetProxyForUrl(void) { Log("InternetGetProxyForUrl (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetGetSecurityInfoByURL(void) { Log("InternetGetSecurityInfoByURL (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetGetSecurityInfoByURLA(void) { Log("InternetGetSecurityInfoByURLA (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetGetSecurityInfoByURLW(void) { Log("InternetGetSecurityInfoByURLW (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetQueryFortezzaStatus(void) { Log("InternetQueryFortezzaStatus (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetSecurityProtocolToStringA(void) { Log("InternetSecurityProtocolToStringA (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetSecurityProtocolToStringW(void) { Log("InternetSecurityProtocolToStringW (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetSetSecureLegacyServersAppCompat(void) { Log("InternetSetSecureLegacyServersAppCompat (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetShowSecurityInfoByURL(void) { Log("InternetShowSecurityInfoByURL (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetShowSecurityInfoByURLA(void) { Log("InternetShowSecurityInfoByURLA (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_InternetShowSecurityInfoByURLW(void) { Log("InternetShowSecurityInfoByURLW (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_IsHostInProxyBypassList(void) { Log("IsHostInProxyBypassList (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_IsUrlCacheEntryExpiredA(void) { Log("IsUrlCacheEntryExpiredA (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_IsUrlCacheEntryExpiredW(void) { Log("IsUrlCacheEntryExpiredW (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_LoadUrlCacheContent(void) { Log("LoadUrlCacheContent (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_ParseX509EncodedCertificateForListBoxEntry(void) { Log("ParseX509EncodedCertificateForListBoxEntry (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_RegisterUrlCacheNotification(void) { Log("RegisterUrlCacheNotification (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_RunOnceUrlCache(void) { Log("RunOnceUrlCache (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_SetUrlCacheHeaderData(void) { Log("SetUrlCacheHeaderData (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_ShowCertificate(void) { Log("ShowCertificate (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_ShowClientAuthCerts(void) { Log("ShowClientAuthCerts (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_ShowSecurityInfo(void) { Log("ShowSecurityInfo (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_ShowX509EncodedCertificate(void) { Log("ShowX509EncodedCertificate (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UpdateUrlCacheContentPath(void) { Log("UpdateUrlCacheContentPath (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlCacheCheckEntriesExist(void) { Log("UrlCacheCheckEntriesExist (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlCacheCloseEntryHandle(void) { Log("UrlCacheCloseEntryHandle (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlCacheContainerSetEntryMaximumAge(void) { Log("UrlCacheContainerSetEntryMaximumAge (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlCacheCreateContainer(void) { Log("UrlCacheCreateContainer (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
void* WINAPI ex_UrlCacheFindFirstEntry(void) { Log("UrlCacheFindFirstEntry (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
BOOL WINAPI ex_UrlCacheFindNextEntry(void) { Log("UrlCacheFindNextEntry (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlCacheFreeEntryInfo(void) { Log("UrlCacheFreeEntryInfo (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlCacheFreeGlobalSpace(void) { Log("UrlCacheFreeGlobalSpace (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlCacheGetContentPaths(void) { Log("UrlCacheGetContentPaths (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlCacheGetEntryInfo(void) { Log("UrlCacheGetEntryInfo (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlCacheGetGlobalCacheSize(void) { Log("UrlCacheGetGlobalCacheSize (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlCacheGetGlobalLimit(void) { Log("UrlCacheGetGlobalLimit (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
void* WINAPI ex_UrlCacheReadEntryStream(void) { Log("UrlCacheReadEntryStream (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
BOOL WINAPI ex_UrlCacheReloadSettings(void) { Log("UrlCacheReloadSettings (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlCacheRetrieveEntryFile(void) { Log("UrlCacheRetrieveEntryFile (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
void* WINAPI ex_UrlCacheRetrieveEntryStream(void) { Log("UrlCacheRetrieveEntryStream (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
BOOL WINAPI ex_UrlCacheServer(void) { Log("UrlCacheServer (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlCacheSetGlobalLimit(void) { Log("UrlCacheSetGlobalLimit (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlCacheUpdateEntryExtraData(void) { Log("UrlCacheUpdateEntryExtraData (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL WINAPI ex_UrlZonesDetach(void) { Log("UrlZonesDetach (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
void* WINAPI ex__GetFileExtensionFromUrl(void) { Log("_GetFileExtensionFromUrl (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }