#include <windows.h>
#include <sensapi.h>

// ============================================================================
// ЕКСПОРТОВАНІ ФУНКЦІЇ - ЗАВЖДИ ОФЛАЙН
// ============================================================================

BOOL WINAPI IsDestinationReachableA(
    LPCSTR lpszDestination,
    LPQOCINFO lpQOCInfo)
{
    // Завжди повертаємо, що destination НЕДОСЯЖНИЙ
    if (lpQOCInfo) {
        ZeroMemory(lpQOCInfo, sizeof(QOCINFO));
        lpQOCInfo->dwSize = sizeof(QOCINFO);
        lpQOCInfo->dwFlags = 0; // Немає з'єднання
        lpQOCInfo->dwInSpeed = 0;
        lpQOCInfo->dwOutSpeed = 0;
    }
    return FALSE; // Недосяжний
}

BOOL WINAPI IsDestinationReachableW(
    LPCWSTR lpszDestination,
    LPQOCINFO lpQOCInfo)
{
    // Завжди повертаємо, що destination НЕДОСЯЖНИЙ
    if (lpQOCInfo) {
        ZeroMemory(lpQOCInfo, sizeof(QOCINFO));
        lpQOCInfo->dwSize = sizeof(QOCINFO);
        lpQOCInfo->dwFlags = 0; // Немає з'єднання
        lpQOCInfo->dwInSpeed = 0;
        lpQOCInfo->dwOutSpeed = 0;
    }
    return FALSE; // Недосяжний
}

BOOL WINAPI IsNetworkAlive(
    LPDWORD lpdwFlags)
{
    // Завжди повертаємо що мережі НЕМАЄ
    if (lpdwFlags) {
        *lpdwFlags = 0; // Жодних мережевих з'єднань
    }
    return FALSE; // Мережа мертва
}

// ============================================================================
// DLL ENTRY POINT
// ============================================================================

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}