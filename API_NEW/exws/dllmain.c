#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// ============================================================================
// EXWS - wsock32.dll Pure Proxy Emulator
// ============================================================================
// This is a pure forwarding proxy DLL.
// All logic is defined in ws_32.def file which forwards calls to:
// - exws2.dll (Winsock 2.x functions)
// - EXMSW.dll (MSWSOCK functions)
//
// DllMain handles attach/detach notifications.
// Currently no initialization is needed, but structure is present
// for future extensibility.
// ============================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;
    
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            // Called when DLL is loaded into process
            // Optimize: disable thread notifications
            DisableThreadLibraryCalls(hModule);
            break;
            
        case DLL_PROCESS_DETACH:
            // Called when DLL is unloaded from process
            // No cleanup needed for pure proxy
            break;
            
        case DLL_THREAD_ATTACH:
            // Not called due to DisableThreadLibraryCalls
            break;
            
        case DLL_THREAD_DETACH:
            // Not called due to DisableThreadLibraryCalls
            break;
    }
    
    return TRUE;
}