#define _CRT_SECURE_NO_WARNINGS
#include "wininet_internal.h"

// Глобальні змінні
HINSTANCE g_hInst = NULL;
BOOL g_wsInitialized = FALSE;

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

// Функція логування
void Log(const char* fmt, ...) {
    if (!ENABLE_DEBUG_CONSOLE && !ENABLE_FILE_LOGGING) return;

    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    // 1. Логування у файл
    if (ENABLE_FILE_LOGGING) {
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

    // 2. Логування в консоль
    if (ENABLE_DEBUG_CONSOLE) {
        char dbgBuf[2100];
        snprintf(dbgBuf, sizeof(dbgBuf), "[WININET] %s\n", buf);
        OutputDebugStringA(dbgBuf);
        printf("%s", dbgBuf);
    }
}

// Точка входу в DLL
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hInst = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
        
        // Ініціалізація консолі
        if (ENABLE_DEBUG_CONSOLE) {
            AllocConsole();
            freopen("CONOUT$", "w", stdout);
            freopen("CONOUT$", "w", stderr);
            SetConsoleTitleA("WinINet Emulator (exws2.lib)");
            
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }
        
        Log("=== WinINet Emulator Loaded ===");
        Log("Using static linking with exws2.lib");
        
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        Log("=== WinINet Emulator Unloaded ===");
        CleanupWinsock();
    }
    return TRUE;
}

// COM заглушки
HRESULT WINAPI ex_DllCanUnloadNow(void) { return S_FALSE; }
HRESULT WINAPI ex_DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) { *ppv = NULL; return CLASS_E_CLASSNOTAVAILABLE; }
HRESULT WINAPI ex_DllInstall(BOOL bInstall, LPCWSTR pszCmdLine) { return S_OK; }
HRESULT WINAPI ex_DllRegisterServer(void) { return S_OK; }
HRESULT WINAPI ex_DllUnregisterServer(void) { return S_OK; }