#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sensapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// === НАЛАГОДЖУВАЛЬНІ КОНСТАНТИ ===
// ============================================================================
#define ENABLE_DEBUG_CONSOLE    0 
#define ENABLE_FILE_LOGGING     0
#define ENABLE_MEMORY_TRACKING  1 

// ============================================================================
// === СТРУКТУРИ ТА ТИПИ ДЛЯ ЛОГУВАННЯ ===
// ============================================================================
typedef enum { LOG_LEVEL_ERROR = 0, LOG_LEVEL_WARNING, LOG_LEVEL_INFO, LOG_LEVEL_DEBUG } LogLevel;
#if ENABLE_MEMORY_TRACKING
typedef struct _MEMORY_BLOCK { void* ptr; size_t size; char function[64]; DWORD thread_id; struct _MEMORY_BLOCK* next; } MEMORY_BLOCK;
#endif

// ============================================================================
// === ГЛОБАЛЬНІ ЗМІННІ ===
// ============================================================================
#if ENABLE_FILE_LOGGING
static FILE* g_log_file = NULL; static CRITICAL_SECTION g_log_lock;
#endif
#if ENABLE_MEMORY_TRACKING
static MEMORY_BLOCK* g_memory_list = NULL; static CRITICAL_SECTION g_memory_lock;
#endif
static BOOL g_locks_initialized = FALSE; static LogLevel g_current_log_level = LOG_LEVEL_DEBUG;

// ============================================================================
// === ФУНКЦІЇ ЛОГУВАННЯ ТА УПРАВЛІННЯ ПАМ'ЯТТЮ ===
// ============================================================================
void GetTimestamp(char* buffer, size_t bufferSize) { if (!buffer || bufferSize < 20) return; SYSTEMTIME st; GetLocalTime(&st); snprintf(buffer, bufferSize, "[%02d:%02d:%02d.%03d]", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds); }
const char* GetLogLevelString(LogLevel level) { switch (level) { case LOG_LEVEL_ERROR: return "ERROR"; case LOG_LEVEL_WARNING: return "WARN "; case LOG_LEVEL_INFO: return "INFO "; case LOG_LEVEL_DEBUG: return "DEBUG"; default: return "?????"; } }
void LogMessageEx(LogLevel level, const char* function, const char* format, ...) { if (level > g_current_log_level) return; char timestamp[20] = { 0 }; GetTimestamp(timestamp, sizeof(timestamp)); va_list args; va_start(args, format);
#if ENABLE_FILE_LOGGING
if (g_log_file && g_locks_initialized) { EnterCriticalSection(&g_log_lock); fprintf(g_log_file, "%s [%s] [%s] ", timestamp, GetLogLevelString(level), function); vfprintf(g_log_file, format, args); fprintf(g_log_file, "\n"); fflush(g_log_file); LeaveCriticalSection(&g_log_lock); }
#endif
#if ENABLE_DEBUG_CONSOLE
printf("[SENSAPI] %s [%s] [%s] ", timestamp, GetLogLevelString(level), function); vprintf(format, args); printf("\n");
#endif
va_end(args); }
#define LogError(fmt, ...)   LogMessageEx(LOG_LEVEL_ERROR, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogWarning(fmt, ...) LogMessageEx(LOG_LEVEL_WARNING, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogInfo(fmt, ...)    LogMessageEx(LOG_LEVEL_INFO, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogDebug(fmt, ...)   LogMessageEx(LOG_LEVEL_DEBUG, __FUNCTION__, fmt, ##__VA_ARGS__)
#if ENABLE_MEMORY_TRACKING
void ReportMemoryLeaks() { LogInfo("No memory tracking implemented for this simple stub."); }
#else
#define ReportMemoryLeaks()
#endif

// ============================================================================
// === ЕКСПОРТОВАНІ ФУНКЦІЇ - ЗАВЖДИ ОФЛАЙН (v1.0) ===
// ============================================================================

BOOL WINAPI ex_IsDestinationReachableA(
    LPCSTR lpszDestination,
    LPQOCINFO lpQOCInfo)
{
    LogInfo("IsDestinationReachableA(Destination: '%s')", lpszDestination ? lpszDestination : "<null>");
    if (lpQOCInfo) {
        ZeroMemory(lpQOCInfo, sizeof(QOCINFO));
        lpQOCInfo->dwSize = sizeof(QOCINFO);
        lpQOCInfo->dwFlags = 0;
        lpQOCInfo->dwInSpeed = 0;
        lpQOCInfo->dwOutSpeed = 0;
    }
    LogWarning(" -> Returning FALSE (Destination is UNREACHABLE).");
    return FALSE;
}

BOOL WINAPI ex_IsDestinationReachableW(
    LPCWSTR lpszDestination,
    LPQOCINFO lpQOCInfo)
{
    LogInfo("IsDestinationReachableW(Destination: '%S')", lpszDestination ? lpszDestination : L"<null>");
    if (lpQOCInfo) {
        ZeroMemory(lpQOCInfo, sizeof(QOCINFO));
        lpQOCInfo->dwSize = sizeof(QOCINFO);
        lpQOCInfo->dwFlags = 0;
        lpQOCInfo->dwInSpeed = 0;
        lpQOCInfo->dwOutSpeed = 0;
    }
    LogWarning(" -> Returning FALSE (Destination is UNREACHABLE).");
    return FALSE;
}

BOOL WINAPI ex_IsNetworkAlive(
    LPDWORD lpdwFlags)
{
    LogInfo("IsNetworkAlive called.");
    if (lpdwFlags) {
        *lpdwFlags = NETWORK_ALIVE_LAN; 
        LogInfo(" -> Setting flags to NETWORK_ALIVE_LAN (0x%lX).", NETWORK_ALIVE_LAN);
    }
    LogWarning(" -> Returning FALSE (Network connection is limited/dead).");
    return FALSE;
}

// ============================================================================
// === DLLMAIN ===
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
        g_locks_initialized = TRUE;
#if ENABLE_DEBUG_CONSOLE
        if (AllocConsole()) {
            FILE* fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
            SetConsoleTitleA("SensApi Stub Debug Console v1.0");
        }
#endif
#if ENABLE_FILE_LOGGING
        {
            char log_path[MAX_PATH]; char exe_path[MAX_PATH]; GetModuleFileNameA(NULL, exe_path, MAX_PATH);
            char* last_slash = strrchr(exe_path, '\\'); if (last_slash) *(last_slash + 1) = '\0';
            snprintf(log_path, MAX_PATH, "%ssensapi_mock.log", exe_path);
            fopen_s(&g_log_file, log_path, "a");
        }
#endif
        LogInfo("=== SENSAPI STUB v1.0 LOADED ==="); LogInfo("Build: %s %s", __DATE__, __TIME__);
        break;

    case DLL_PROCESS_DETACH:
        LogInfo("=== SENSAPI STUB v1.0 UNLOADING ===");
        if (g_locks_initialized) {
#if ENABLE_MEMORY_TRACKING
            ReportMemoryLeaks();
#endif
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
        printf("\nSensApi Stub Unloading complete...\n");
        FreeConsole();
#endif
        break;
    }
    return TRUE;
}

#ifdef __cplusplus
}
#endif