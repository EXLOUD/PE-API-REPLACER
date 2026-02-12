/*
 * SENSAPI.DLL Emulator - Configurable Network State
 * 
 * System Event Notification Service API
 * This emulator allows you to control network availability via NETWORK_ONLINE constant.
 *
 * Configuration:
 *   NETWORK_ONLINE = 0 : IsNetworkAlive() returns FALSE (offline mode)
 *   NETWORK_ONLINE = 1 : IsNetworkAlive() returns TRUE  (online mode)
 *
 * Note: IsDestinationReachable() always returns FALSE regardless of the setting.
 *
 * Copyright (c) 2026
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>

/* SENSAPI constants and structures */
#define NETWORK_ALIVE_LAN       0x00000001
#define NETWORK_ALIVE_WAN       0x00000002
#define NETWORK_ALIVE_AOL       0x00000004
#define NETWORK_ALIVE_INTERNET  0x00000008

typedef struct tagQOCINFO {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwInSpeed;
    DWORD dwOutSpeed;
} QOCINFO, *LPQOCINFO;

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

/* Network emulation mode:
 * 0 = Network OFFLINE (IsNetworkAlive returns FALSE)
 * 1 = Network ONLINE  (IsNetworkAlive returns TRUE)
 * Note: IsDestinationReachable always returns FALSE regardless of this setting
 */
#define NETWORK_ONLINE          1

#define ENABLE_DEBUG_CONSOLE    1
#define ENABLE_FILE_LOGGING     0

/* ============================================================================
 * GLOBALS
 * ============================================================================ */
#if ENABLE_DEBUG_CONSOLE
static HANDLE g_hConsole = NULL;
#endif
#if ENABLE_FILE_LOGGING
static FILE* g_logFile = NULL;
#endif
static volatile LONG g_initDone = 0;

/* ============================================================================
 * LOGGING
 * ============================================================================ */
typedef enum { LOG_ERROR = 0, LOG_WARN, LOG_INFO, LOG_DEBUG } LogLevel;
static LogLevel g_logLevel = LOG_DEBUG;

static void Log(LogLevel level, const char* func, const char* fmt, ...) {
    if (level > g_logLevel || !g_initDone) return;
    
    char buf[1024], msg[512], ts[24];
    SYSTEMTIME st;
    va_list args;
    
    GetLocalTime(&st);
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d.%03d", 
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    
    const char* lvl = (level == LOG_ERROR) ? "ERR" : 
                      (level == LOG_WARN)  ? "WRN" : 
                      (level == LOG_INFO)  ? "INF" : "DBG";
    snprintf(buf, sizeof(buf), "[%s][%s][%s] %s\n", ts, lvl, func, msg);
    
#if ENABLE_DEBUG_CONSOLE
    printf("%s", buf);
#endif

#if ENABLE_FILE_LOGGING
    if (g_logFile) {
        fputs(buf, g_logFile);
        fflush(g_logFile);
    }
#endif
}

#define LogE(fmt, ...) Log(LOG_ERROR, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogW(fmt, ...) Log(LOG_WARN,  __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogI(fmt, ...) Log(LOG_INFO,  __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogD(fmt, ...) Log(LOG_DEBUG, __FUNCTION__, fmt, ##__VA_ARGS__)

/* ============================================================================
 * API IMPLEMENTATIONS
 * ============================================================================ */

/*
 * IsNetworkAlive
 * 
 * Determines whether the local system is connected to a network.
 * 
 * Returns:
 *   TRUE  - Network is available
 *   FALSE - Network is NOT available (our case)
 *
 * lpdwFlags receives the type of network:
 *   NETWORK_ALIVE_LAN (0x01) - LAN connection
 *   NETWORK_ALIVE_WAN (0x02) - WAN connection  
 *   NETWORK_ALIVE_AOL (0x04) - AOL connection
 *   NETWORK_ALIVE_INTERNET (0x08) - Internet connection (Vista+)
 */
BOOL WINAPI ex_IsNetworkAlive(LPDWORD lpdwFlags)
{
    LogI("IsNetworkAlive(lpdwFlags=%p)", lpdwFlags);
    
#if NETWORK_ONLINE
    /* Network ONLINE mode */
    if (lpdwFlags) {
        /* Report LAN connection available */
        *lpdwFlags = NETWORK_ALIVE_LAN;
        LogD("  *lpdwFlags = 0x%08X (NETWORK_ALIVE_LAN)", *lpdwFlags);
    }
    
    LogI("  -> TRUE (network IS alive)");
    SetLastError(ERROR_SUCCESS);
    return TRUE;
#else
    /* Network OFFLINE mode */
    if (lpdwFlags) {
        *lpdwFlags = 0;  /* No network type - disconnected */
        LogD("  *lpdwFlags = 0 (no network)");
    }
    
    LogI("  -> FALSE (network is NOT alive)");
    SetLastError(ERROR_SUCCESS);  /* No error, just no network */
    return FALSE;
#endif
}

/*
 * IsDestinationReachableA (ANSI version)
 * 
 * Determines whether the specified destination can be reached.
 *
 * Parameters:
 *   lpszDestination - Host name or IP address to check
 *   lpQOCInfo       - Optional pointer to receive quality of connection info
 *
 * Returns:
 *   TRUE  - Destination is reachable
 *   FALSE - Destination is NOT reachable (our case)
 */
BOOL WINAPI ex_IsDestinationReachableA(LPCSTR lpszDestination, LPQOCINFO lpQOCInfo)
{
    LogI("IsDestinationReachableA(dest=\"%s\", lpQOCInfo=%p)", 
         lpszDestination ? lpszDestination : "(null)", lpQOCInfo);
    
    if (lpQOCInfo) {
        LogD("  Input QOCINFO.dwSize = %lu", lpQOCInfo->dwSize);
        
        /* Clear the structure but preserve dwSize */
        DWORD size = lpQOCInfo->dwSize;
        if (size >= sizeof(QOCINFO)) {
            lpQOCInfo->dwFlags = 0;
            lpQOCInfo->dwInSpeed = 0;
            lpQOCInfo->dwOutSpeed = 0;
        }
        
        LogD("  Output: dwFlags=0, dwInSpeed=0, dwOutSpeed=0");
    }
    
    LogI("  -> FALSE (destination \"%s\" is NOT reachable)", 
         lpszDestination ? lpszDestination : "(null)");
    
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    
    return FALSE;
}

/*
 * IsDestinationReachableW (Unicode version)
 */
BOOL WINAPI ex_IsDestinationReachableW(LPCWSTR lpszDestination, LPQOCINFO lpQOCInfo)
{
    LogI("IsDestinationReachableW(dest=\"%S\", lpQOCInfo=%p)", 
         lpszDestination ? lpszDestination : L"(null)", lpQOCInfo);
    
    if (lpQOCInfo) {
        LogD("  Input QOCINFO.dwSize = %lu", lpQOCInfo->dwSize);
        
        DWORD size = lpQOCInfo->dwSize;
        if (size >= sizeof(QOCINFO)) {
            lpQOCInfo->dwFlags = 0;
            lpQOCInfo->dwInSpeed = 0;
            lpQOCInfo->dwOutSpeed = 0;
        }
        
        LogD("  Output: dwFlags=0, dwInSpeed=0, dwOutSpeed=0");
    }
    
    LogI("  -> FALSE (destination \"%S\" is NOT reachable)", 
         lpszDestination ? lpszDestination : L"(null)");
    
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    
    return FALSE;
}

/* ============================================================================
 * DLL ENTRY POINT
 * ============================================================================ */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    (void)lpReserved;
    
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        
#if ENABLE_DEBUG_CONSOLE
        /* Try to attach to existing console (from iphlpapi) */
        if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
            /* If none exists - create new one */
            if (AllocConsole()) {
                FILE* fDummy;
                freopen_s(&fDummy, "CONOUT$", "w", stdout);
                freopen_s(&fDummy, "CONOUT$", "w", stderr);
                freopen_s(&fDummy, "CONIN$", "r", stdin);
                SetConsoleTitleA("SENSAPI Emulator - Network Disconnected");
            }
        } else {
            /* Attached to existing - redirect stdout */
            FILE* fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
            freopen_s(&fDummy, "CONOUT$", "w", stderr);
        }
        g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
#endif
        
#if ENABLE_FILE_LOGGING
        char path[MAX_PATH], tmp[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tmp) > 0) {
            snprintf(path, MAX_PATH, "%ssensapi_%lu.log", tmp, GetCurrentProcessId());
            g_logFile = fopen(path, "w");
        }
#endif
        
        g_initDone = 1;
        
        printf("\n");
        printf("========================================\n");
#if NETWORK_ONLINE
        printf("   SENSAPI EMULATOR - ONLINE MODE\n");
        printf("   IsNetworkAlive() -> TRUE\n");
#else
        printf("   SENSAPI EMULATOR - OFFLINE MODE\n");
        printf("   IsNetworkAlive() -> FALSE\n");
#endif
        printf("   IsDestinationReachable() -> FALSE\n");
        printf("========================================\n\n");
        
#if NETWORK_ONLINE
        LogI("SENSAPI.DLL loaded - Network emulation: ONLINE");
#else
        LogI("SENSAPI.DLL loaded - Network emulation: OFFLINE");
#endif
        
        break;
    }
    
    case DLL_PROCESS_DETACH:
    {
        if (g_initDone) {
            LogI("SENSAPI.DLL unloading");
            
#if ENABLE_FILE_LOGGING
            if (g_logFile) {
                fclose(g_logFile);
                g_logFile = NULL;
            }
#endif
        }
        break;
    }
    
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    
    return TRUE;
}

#ifdef __cplusplus
}
#endif