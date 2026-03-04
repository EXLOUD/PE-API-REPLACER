#include "wininet_internal.h"

// Допоміжні заглушки для коннекту
HINTERNET Internal_FTP_Connect(HEADER* session, LPCSTR server, INTERNET_PORT port, LPCSTR user, LPCSTR pass, DWORD service, DWORD flags, DWORD_PTR context) {
    HEADER* h = (HEADER*)calloc(1, sizeof(HEADER));
    if(!h) return NULL;
    h->type = HANDLE_FTP_CONNECT;
    h->parent = (HINTERNET)session;
    h->context = context;
    Log("FTP Connect simulated");
    return (HINTERNET)h;
}

void Internal_FTP_Close(HEADER* h) {
    free(h);
}

// Реалізація функцій, оголошених у header
BOOL WINAPI ex_FtpCreateDirectoryA(HINTERNET hConnect, LPCSTR lpszDirectory) { Log("FtpCreateDirectoryA stub"); return FALSE; }
BOOL WINAPI ex_FtpCreateDirectoryW(HINTERNET hConnect, LPCWSTR lpszDirectory) { Log("FtpCreateDirectoryW stub"); return FALSE; }
BOOL WINAPI ex_FtpRemoveDirectoryA(HINTERNET hConnect, LPCSTR lpszDirectory) { Log("FtpRemoveDirectoryA stub"); return FALSE; }
BOOL WINAPI ex_FtpRemoveDirectoryW(HINTERNET hConnect, LPCWSTR lpszDirectory) { Log("FtpRemoveDirectoryW stub"); return FALSE; }
BOOL WINAPI ex_FtpSetCurrentDirectoryA(HINTERNET hConnect, LPCSTR lpszDirectory) { Log("FtpSetCurrentDirectoryA stub"); return FALSE; }
BOOL WINAPI ex_FtpSetCurrentDirectoryW(HINTERNET hConnect, LPCWSTR lpszDirectory) { Log("FtpSetCurrentDirectoryW stub"); return FALSE; }
BOOL WINAPI ex_FtpGetCurrentDirectoryA(HINTERNET hConnect, LPSTR lpszCurrentDirectory, LPDWORD lpdwCurrentDirectory) { Log("FtpGetCurrentDirectoryA stub"); return FALSE; }
BOOL WINAPI ex_FtpGetCurrentDirectoryW(HINTERNET hConnect, LPWSTR lpszCurrentDirectory, LPDWORD lpdwCurrentDirectory) { Log("FtpGetCurrentDirectoryW stub"); return FALSE; }
BOOL WINAPI ex_FtpDeleteFileA(HINTERNET hConnect, LPCSTR lpszFileName) { Log("FtpDeleteFileA stub"); return FALSE; }
BOOL WINAPI ex_FtpDeleteFileW(HINTERNET hConnect, LPCWSTR lpszFileName) { Log("FtpDeleteFileW stub"); return FALSE; }
BOOL WINAPI ex_FtpRenameFileA(HINTERNET hConnect, LPCSTR lpszExisting, LPCSTR lpszNew) { Log("FtpRenameFileA stub"); return FALSE; }
BOOL WINAPI ex_FtpRenameFileW(HINTERNET hConnect, LPCWSTR lpszExisting, LPCWSTR lpszNew) { Log("FtpRenameFileW stub"); return FALSE; }

// Реалізація інших функцій, що мають прототипи
HINTERNET WINAPI ex_FtpOpenFileA(HINTERNET hConnect, LPCSTR lpszFileName, DWORD dwAccess, DWORD dwFlags, DWORD_PTR dwContext) { Log("FtpOpenFileA stub"); return NULL; }
HINTERNET WINAPI ex_FtpOpenFileW(HINTERNET hConnect, LPCWSTR lpszFileName, DWORD dwAccess, DWORD dwFlags, DWORD_PTR dwContext) { Log("FtpOpenFileW stub"); return NULL; }
BOOL WINAPI ex_FtpPutFileA(HINTERNET hConnect, LPCSTR lpszLocalFile, LPCSTR lpszNewRemoteFile, DWORD dwFlags, DWORD_PTR dwContext) { Log("FtpPutFileA stub"); return FALSE; }
BOOL WINAPI ex_FtpPutFileW(HINTERNET hConnect, LPCWSTR lpszLocalFile, LPCWSTR lpszNewRemoteFile, DWORD dwFlags, DWORD_PTR dwContext) { Log("FtpPutFileW stub"); return FALSE; }
BOOL WINAPI ex_FtpGetFileA(HINTERNET hConnect, LPCSTR lpszRemoteFile, LPCSTR lpszNewFile, BOOL fFailIfExists, DWORD dwFlagsAndAttributes, DWORD dwFlags, DWORD_PTR dwContext) { Log("FtpGetFileA stub"); return FALSE; }
BOOL WINAPI ex_FtpGetFileW(HINTERNET hConnect, LPCWSTR lpszRemoteFile, LPCWSTR lpszNewFile, BOOL fFailIfExists, DWORD dwFlagsAndAttributes, DWORD dwFlags, DWORD_PTR dwContext) { Log("FtpGetFileW stub"); return FALSE; }
BOOL WINAPI ex_FtpCommandA(HINTERNET hConnect, BOOL fExpectResponse, DWORD dwFlags, LPCSTR lpszCommand, DWORD_PTR dwContext, HINTERNET* phFtpCommand) { Log("FtpCommandA stub"); return FALSE; }
BOOL WINAPI ex_FtpCommandW(HINTERNET hConnect, BOOL fExpectResponse, DWORD dwFlags, LPCWSTR lpszCommand, DWORD_PTR dwContext, HINTERNET* phFtpCommand) { Log("FtpCommandW stub"); return FALSE; }
DWORD WINAPI ex_FtpGetFileSize(HINTERNET hFile, LPDWORD lpdwFileSizeHigh) { Log("FtpGetFileSize stub"); return 0; }
HINTERNET WINAPI ex_FtpFindFirstFileA(HINTERNET hConnect, LPCSTR lpszSearchFile, LPWIN32_FIND_DATAA lpFindFileData, DWORD dwFlags, DWORD_PTR dwContext) { Log("FtpFindFirstFileA stub"); return NULL; }
HINTERNET WINAPI ex_FtpFindFirstFileW(HINTERNET hConnect, LPCWSTR lpszSearchFile, LPWIN32_FIND_DATAW lpFindFileData, DWORD dwFlags, DWORD_PTR dwContext) { Log("FtpFindFirstFileW stub"); return NULL; }