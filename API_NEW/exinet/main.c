#define _CRT_SECURE_NO_WARNINGS
#include "wininet_internal.h"

// Глобальні змінні
HINSTANCE g_hInst = NULL;
BOOL g_wsInitialized = FALSE;

// Змінні для безпечного логування
static BOOL g_consoleInitialized = FALSE;
static BOOL g_insideDllMain = FALSE;  

// Ініціалізація WinSock через exws2.lib
BOOL InitWinsock(void) {
    if (g_wsInitialized) return TRUE;
    
    WSADATA wsaData;
    int result = WSAStartup(0x0202, &wsaData);  // WinSock 2.2
    
    if (result == 0) {
        g_wsInitialized = TRUE;
        Log("WinSock initialized via exws2.lib (version %d.%d)", 
            LOBYTE(wsaData.wVersion), HIBYTE(wsaData.wVersion));
        return TRUE;
    }
    
    Log("WSAStartup failed with error: %d", result);
    return FALSE;
}

void CleanupWinsock(void) {
    if (g_wsInitialized) {
        WSACleanup();
        g_wsInitialized = FALSE;
        Log("WinSock cleanup done");
    }
}

static void InitConsole_Safe(void) {
    if (g_consoleInitialized) return;
    
    if (g_insideDllMain) return;
    
    if (ENABLE_DEBUG_CONSOLE) {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
        SetConsoleTitleA("WinINet Emulator (exws2.lib)");
        
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        
        g_consoleInitialized = TRUE;
    }
}

void Log(const char* fmt, ...) {
    if (!ENABLE_DEBUG_CONSOLE && !ENABLE_FILE_LOGGING) return;

    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (ENABLE_FILE_LOGGING && !g_insideDllMain) {
        char path[MAX_PATH];
        if (GetTempPathA(MAX_PATH, path)) {
            strcat(path, "wininet_debug.log");
            FILE* f = fopen(path, "a");
            if (f) {
                SYSTEMTIME st;
                GetLocalTime(&st);
                fprintf(f, "[%02d:%02d:%02d.%03d] %s\n", 
                        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);
                fclose(f);
            }
        }
    }

    if (ENABLE_DEBUG_CONSOLE) {
        if (!g_consoleInitialized && !g_insideDllMain) {
            InitConsole_Safe();
        }
        
        char dbgBuf[2100];
        snprintf(dbgBuf, sizeof(dbgBuf), "[WININET] %s\n", buf);
        
        OutputDebugStringA(dbgBuf);
        
        if (g_consoleInitialized) {
            printf("%s", dbgBuf);
        }
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hInst = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
        
        g_insideDllMain = TRUE;
        
        if (ENABLE_DEBUG_CONSOLE) {
            OutputDebugStringA("[WININET] === WinINet Emulator Loaded ===\n");
            OutputDebugStringA("[WININET] Using static linking with exws2.lib\n");
        }
        
        g_insideDllMain = FALSE;
        
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        g_insideDllMain = TRUE;
        
        if (ENABLE_DEBUG_CONSOLE) {
            OutputDebugStringA("[WININET] === WinINet Emulator Unloaded ===\n");
        }
        
        CleanupWinsock();
        
        g_insideDllMain = FALSE;
    }
    return TRUE;
}

// COM заглушки
HRESULT WINAPI ex_DllCanUnloadNow(void) { return S_FALSE; }
HRESULT WINAPI ex_DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) { *ppv = NULL; return CLASS_E_CLASSNOTAVAILABLE; }
HRESULT WINAPI ex_DllInstall(BOOL bInstall, LPCWSTR pszCmdLine) { return S_OK; }
HRESULT WINAPI ex_DllRegisterServer(void) { return S_OK; }
HRESULT WINAPI ex_DllUnregisterServer(void) { return S_OK; }