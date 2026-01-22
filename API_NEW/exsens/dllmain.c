// ============================================================================
// === SENSAPI EMULATOR - v1.0.3 ===
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sensapi.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "exws2.lib")

// ============================================================================
// === КОНСТАНТИ СЕНСОРІВ МЕРЕЖІ ===
// ============================================================================
#ifndef NETWORK_ALIVE_LAN
#define NETWORK_ALIVE_LAN       0x00000001
#endif

#ifndef NETWORK_ALIVE_INTERNET
#define NETWORK_ALIVE_INTERNET  0x00000002
#endif

#ifndef NETWORK_ALIVE_BOTH
#define NETWORK_ALIVE_BOTH      (NETWORK_ALIVE_LAN | NETWORK_ALIVE_INTERNET)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// === НАЛАГОДЖУВАЛЬНІ КОНСТАНТИ ===
// ============================================================================
#define ENABLE_DEBUG_CONSOLE    0
#define ENABLE_FILE_LOGGING     0
#define ENABLE_MEMORY_TRACKING  0

// ============================================================================
// === СТРУКТУРИ ТА ТИПИ ДЛЯ ЛОГУВАННЯ ===
// ============================================================================
typedef enum { 
    LOG_LEVEL_ERROR = 0, 
    LOG_LEVEL_WARNING, 
    LOG_LEVEL_INFO, 
    LOG_LEVEL_DEBUG 
} LogLevel;

#if ENABLE_MEMORY_TRACKING
typedef struct _MEMORY_BLOCK { 
    void* ptr; 
    size_t size; 
    char function[64]; 
    DWORD thread_id; 
    struct _MEMORY_BLOCK* next; 
} MEMORY_BLOCK;
#endif

// ============================================================================
// === ГЛОБАЛЬНІ ЗМІННІ ===
// ============================================================================
#if ENABLE_FILE_LOGGING
static FILE* g_log_file = NULL; 
static CRITICAL_SECTION g_log_lock;
#endif

#if ENABLE_MEMORY_TRACKING
static MEMORY_BLOCK* g_memory_list = NULL; 
static CRITICAL_SECTION g_memory_lock;
static size_t g_total_allocated = 0;
static size_t g_total_freed = 0;
#endif

static BOOL g_locks_initialized = FALSE; 
static LogLevel g_current_log_level = LOG_LEVEL_DEBUG;
static CRITICAL_SECTION g_state_lock;

// Стан мережі
typedef struct {
    BOOL isNetworkAlive;
    BOOL isInternetAvailable;
    BOOL isLANAvailable;
    DWORD dwInSpeed;      // Швидкість вхідних даних (біт/сек)
    DWORD dwOutSpeed;     // Швидкість вихідних даних (біт/сек)
} NetworkState;

static NetworkState g_NetworkState = {
    .isNetworkAlive = FALSE,        // ← МЕРЕЖА МЕРТВА!
    .isInternetAvailable = FALSE,   // ← ІНТЕРНЕТ НЕДОСТУПНИЙ!
    .isLANAvailable = FALSE,        // ← LAN НЕДОСТУПНИЙ!
    .dwInSpeed = 0,                 // ← НЕМА ШВИДКОСТІ
    .dwOutSpeed = 0                 // ← НЕМА ШВИДКОСТІ
};

// ============================================================================
// === ФУНКЦІЇ ЛОГУВАННЯ ===
// ============================================================================

void GetTimestamp(char* buffer, size_t bufferSize) {
    if (!buffer || bufferSize < 20) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buffer, bufferSize, "[%02d:%02d:%02d.%03d]", 
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

const char* GetLogLevelString(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_WARNING: return "WARN ";
        case LOG_LEVEL_INFO: return "INFO ";
        case LOG_LEVEL_DEBUG: return "DEBUG";
        default: return "?????";
    }
}

void LogMessageEx(LogLevel level, const char* function, const char* format, ...) {
    if (level > g_current_log_level) return;
    
    char timestamp[20] = { 0 };
    GetTimestamp(timestamp, sizeof(timestamp));
    va_list args;
    va_start(args, format);

#if ENABLE_FILE_LOGGING
    if (g_log_file && g_locks_initialized) {
        EnterCriticalSection(&g_log_lock);
        fprintf(g_log_file, "%s [%s] [%s] ", timestamp, GetLogLevelString(level), function);
        vfprintf(g_log_file, format, args);
        fprintf(g_log_file, "\n");
        fflush(g_log_file);
        LeaveCriticalSection(&g_log_lock);
    }
#endif

#if ENABLE_DEBUG_CONSOLE
    printf("[SENSAPI] %s [%s] [%s] ", timestamp, GetLogLevelString(level), function);
    vprintf(format, args);
    printf("\n");
#endif

    va_end(args);
}

#define LogError(fmt, ...)   LogMessageEx(LOG_LEVEL_ERROR, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogWarning(fmt, ...) LogMessageEx(LOG_LEVEL_WARNING, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogInfo(fmt, ...)    LogMessageEx(LOG_LEVEL_INFO, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogDebug(fmt, ...)   LogMessageEx(LOG_LEVEL_DEBUG, __FUNCTION__, fmt, ##__VA_ARGS__)

// ============================================================================
// === УПРАВЛІННЯ ПАМ'ЯТТЮ ===
// ============================================================================

#if ENABLE_MEMORY_TRACKING
void* TrackedAlloc(size_t size, const char* function) {
    if (size == 0) return NULL;
    
    void* ptr = malloc(size);
    if (!ptr) {
        LogError("Failed to allocate %zu bytes", size);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    
    memset(ptr, 0, size);
    
    if (g_locks_initialized) {
        EnterCriticalSection(&g_memory_lock);
        MEMORY_BLOCK* block = (MEMORY_BLOCK*)malloc(sizeof(MEMORY_BLOCK));
        if (block) {
            block->ptr = ptr;
            block->size = size;
            strncpy_s(block->function, sizeof(block->function), function, _TRUNCATE);
            block->thread_id = GetCurrentThreadId();
            block->next = g_memory_list;
            g_memory_list = block;
            g_total_allocated += size;
        }
        LeaveCriticalSection(&g_memory_lock);
    }
    
    LogDebug("Allocated %zu bytes at %p", size, ptr);
    return ptr;
}

BOOL TrackedFree(void* ptr, const char* function) {
    if (!ptr) return TRUE;
    
    BOOL found = FALSE;
    if (g_locks_initialized) {
        EnterCriticalSection(&g_memory_lock);
        MEMORY_BLOCK** current = &g_memory_list;
        while (*current) {
            if ((*current)->ptr == ptr) {
                MEMORY_BLOCK* block = *current;
                *current = block->next;
                g_total_freed += block->size;
                LogDebug("Freed %zu bytes from %p (allocated in %s)", block->size, ptr, block->function);
                free(block->ptr);
                free(block);
                found = TRUE;
                break;
            }
            current = &(*current)->next;
        }
        LeaveCriticalSection(&g_memory_lock);
    }
    
    if (!found) {
        LogWarning("Attempt to free untracked/already freed memory: %p", ptr);
        free(ptr);
    }
    
    return found;
}

void ReportMemoryLeaks() {
    if (!g_locks_initialized) return;
    
    EnterCriticalSection(&g_memory_lock);
    if (g_memory_list) {
        LogError("=== MEMORY LEAKS DETECTED ===");
        LogError("Total leaked: %zu bytes", g_total_allocated - g_total_freed);
        MEMORY_BLOCK* current = g_memory_list;
        while (current) {
            LogError("  Leak: %zu bytes from %s (thread %lu): %p", 
                    current->size, current->function, current->thread_id, current->ptr);
            current = current->next;
        }
    } else {
        LogInfo("No memory leaks detected.");
    }
    LeaveCriticalSection(&g_memory_lock);
}

#define SAFE_ALLOC(size) TrackedAlloc(size, __FUNCTION__)
#define SAFE_FREE(ptr) TrackedFree(ptr, __FUNCTION__)
#else
#define SAFE_ALLOC(size) calloc(1, size)
#define SAFE_FREE(ptr) free(ptr)
#define ReportMemoryLeaks()
#endif

// ============================================================================
// === ДОПОМІЖНІ ФУНКЦІЇ ===
// ============================================================================

/**
 * Перевірити, чи IP адреса в локальній підмережі
 */
BOOL IsLocalNetworkAddress(const char* pszDestination) {
    if (!pszDestination) return FALSE;
    
    DWORD dwAddr = inet_addr(pszDestination);
    if (dwAddr == INADDR_NONE) return FALSE;
    
    // Перевіряємо локальні адреси
    BYTE* bytes = (BYTE*)&dwAddr;
    
    // 127.x.x.x - loopback
    if (bytes[0] == 127) return TRUE;
    
    // 192.168.x.x - приватна мережа
    if (bytes[0] == 192 && bytes[1] == 168) return TRUE;
    
    // 10.x.x.x - приватна мережа
    if (bytes[0] == 10) return TRUE;
    
    // 172.16.x.x - 172.31.x.x - приватна мережа
    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return TRUE;
    
    return FALSE;
}

/**
 * Отримати прапори для адреси
 */
DWORD GetFlagsForDestination(const char* pszDestination) {
    if (IsLocalNetworkAddress(pszDestination)) {
        LogDebug("Destination %s is in LOCAL network", pszDestination);
        return NETWORK_ALIVE_LAN;
    }
    
    // Для інших адрес - інтернет
    LogDebug("Destination %s is INTERNET address", pszDestination);
    return NETWORK_ALIVE_INTERNET;
}

// ============================================================================
// === ЕКСПОРТОВАНІ ФУНКЦІЇ ===
// ============================================================================

/**
 * IsDestinationReachableA - ANSI версія
 * Перевіряє, чи можна дістатися до адреси
 */
BOOL WINAPI ex_IsDestinationReachableA(
    LPCSTR lpszDestination,
    LPQOCINFO lpQOCInfo)
{
    LogInfo("IsDestinationReachableA(Destination: '%s')", 
            lpszDestination ? lpszDestination : "<null>");
    
    if (!lpszDestination) {
        LogError(" -> Invalid parameter: lpszDestination is NULL");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    EnterCriticalSection(&g_state_lock);
    
    // ← ЗАВЖДИ НЕДОСТУПНО!
    if (lpQOCInfo) {
        ZeroMemory(lpQOCInfo, sizeof(QOCINFO));
        lpQOCInfo->dwSize = sizeof(QOCINFO);
        lpQOCInfo->dwFlags = 0;      // ← БЕЗ ПРАПОРІВ
        lpQOCInfo->dwInSpeed = 0;    // ← НЕМА ШВИДКОСТІ
        lpQOCInfo->dwOutSpeed = 0;   // ← НЕМА ШВИДКОСТІ
        
        LogDebug(" -> QOC Info: Flags=0x%X, InSpeed=%lu, OutSpeed=%lu",
                0, 0, 0);
    }
    
    LeaveCriticalSection(&g_state_lock);
    
    LogError(" -> Destination '%s' is UNREACHABLE - NO NETWORK", lpszDestination);
    return FALSE;  // ← ЗАВЖДИ FALSE!
}

/**
 * IsDestinationReachableW - ВИПРАВЛЕНА ВЕРСІЯ
 */
BOOL WINAPI ex_IsDestinationReachableW(
    LPCWSTR lpszDestination,
    LPQOCINFO lpQOCInfo)
{
    LogInfo("IsDestinationReachableW(Destination: '%S')", 
            lpszDestination ? lpszDestination : L"<null>");
    
    if (!lpszDestination) {
        LogError(" -> Invalid parameter: lpszDestination is NULL");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    // Конвертуємо з Unicode в ANSI
    size_t len = wcslen(lpszDestination) + 1;
    char* pszDestA = SAFE_ALLOC(len);
    if (!pszDestA) {
        LogError(" -> Failed to allocate memory for ANSI conversion");
        return FALSE;
    }
    
    wcstombs_s(NULL, pszDestA, len, lpszDestination, len - 1);
    
    // Викликаємо ANSI версію (яка тепер повертає FALSE)
    BOOL bResult = ex_IsDestinationReachableA(pszDestA, lpQOCInfo);
    
    SAFE_FREE(pszDestA);
    return bResult;  // ← ЗАВЖДИ FALSE!
}

/**
 * IsNetworkAlive
 * Перевіряє, чи мережа жива
 */
BOOL WINAPI ex_IsNetworkAlive(LPDWORD lpdwFlags)
{
    LogInfo("IsNetworkAlive() called");
    
    EnterCriticalSection(&g_state_lock);
    
    BOOL bResult = g_NetworkState.isNetworkAlive;
    
    if (lpdwFlags) {
        *lpdwFlags = 0;  // ← НЕМА НІЯКИХ ПРАПОРІВ
        
        if (g_NetworkState.isLANAvailable) {
            *lpdwFlags |= NETWORK_ALIVE_LAN;
            LogDebug(" -> LAN is available");
        }
        
        if (g_NetworkState.isInternetAvailable) {
            *lpdwFlags |= NETWORK_ALIVE_INTERNET;
            LogDebug(" -> Internet is available");
        }
        
        // БІЛЬШЕ НЕ робимо fallback на LAN!
        LogInfo(" -> Flags set to 0x%lX (NO NETWORK)", *lpdwFlags);
    }
    
    LeaveCriticalSection(&g_state_lock);
    
    // ← МЕРЕЖА МЕРТВА!
    LogError(" -> Network is DEAD - NO CONNECTIVITY");
    return FALSE;
}

// ============================================================================
// === УПРАВЛІННЯ СТАНОМ МЕРЕЖІ (для тестування) ===
// ============================================================================

/**
 * Функція для зміни стану мережи (внутрішня, для тестування)
 */
void SetNetworkState(BOOL isAlive, BOOL isLAN, BOOL isInternet) {
    EnterCriticalSection(&g_state_lock);
    g_NetworkState.isNetworkAlive = isAlive;
    g_NetworkState.isLANAvailable = isLAN;
    g_NetworkState.isInternetAvailable = isInternet;
    LeaveCriticalSection(&g_state_lock);
    
    LogInfo("Network state changed: Alive=%s, LAN=%s, Internet=%s",
            isAlive ? "YES" : "NO", isLAN ? "YES" : "NO", isInternet ? "YES" : "NO");
}

// ============================================================================
// === DLLMAIN ===
// ============================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        
#if ENABLE_FILE_LOGGING
        InitializeCriticalSection(&g_log_lock);
#endif

#if ENABLE_MEMORY_TRACKING
        InitializeCriticalSection(&g_memory_lock);
#endif

        InitializeCriticalSection(&g_state_lock);
        g_locks_initialized = TRUE;
        
#if ENABLE_DEBUG_CONSOLE
        if (AllocConsole()) {
            FILE* fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
            SetConsoleTitleA("SENSAPI Emulator v1.0.3 Debug Console");
        }
#endif

#if ENABLE_FILE_LOGGING
        {
            char log_path[MAX_PATH];
            char exe_path[MAX_PATH];
            GetModuleFileNameA(NULL, exe_path, MAX_PATH);
            char* last_slash = strrchr(exe_path, '\\');
            if (last_slash) *(last_slash + 1) = '\0';
            snprintf(log_path, MAX_PATH, "%ssensapi_mock.log", exe_path);
            fopen_s(&g_log_file, log_path, "a");
        }
#endif

		LogInfo("=== SENSAPI EMULATOR v1.0.3 LOADED (OFFLINE MODE) ===");
		LogInfo("Build: %s %s", __DATE__, __TIME__);
		LogInfo("Network Status: *** DEAD ***");
		LogInfo("Internet: NOT AVAILABLE");
		LogInfo("LAN: NOT AVAILABLE");
		LogInfo("Speed: 0 Mbps (NO CONNECTIVITY)");
        
        break;

    case DLL_PROCESS_DETACH:
        LogInfo("=== SENSAPI EMULATOR v1.0.3 UNLOADING ===");
        
        if (g_locks_initialized) {
#if ENABLE_MEMORY_TRACKING
            ReportMemoryLeaks();
#endif

#if ENABLE_FILE_LOGGING
            if (g_log_file) {
                LogInfo("Closing log file.");
                fclose(g_log_file);
                g_log_file = NULL;
            }
            DeleteCriticalSection(&g_log_lock);
#endif

#if ENABLE_MEMORY_TRACKING
            DeleteCriticalSection(&g_memory_lock);
#endif

            DeleteCriticalSection(&g_state_lock);
            g_locks_initialized = FALSE;
        }
        
#if ENABLE_DEBUG_CONSOLE
        printf("\nSENSAPI Emulator Unloading complete...\n");
        FreeConsole();
#endif
        
        break;
    }
    return TRUE;
}

#ifdef __cplusplus
}
#endif