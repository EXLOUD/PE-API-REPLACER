#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Ця бібліотека є чистим проксі.
// Уся логіка перенаправлення визначена у файлі wsock32.def.
// DllMain потрібен лише для того, щоб компонувальник успішно створив DLL.

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(ul_reason_for_call);
    UNREFERENCED_PARAMETER(lpReserved);
    return TRUE;
}