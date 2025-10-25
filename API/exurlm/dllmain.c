#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <wininet.h>

// --- Константи для керування логуванням (1 = увімкнено, 0 = вимкнено) ---
#define ENABLE_DEBUG_CONSOLE 0
#define ENABLE_FILE_LOGGING  0

// --- Попередні оголошення для типів, що використовуються в параметрах функцій ---
typedef interface IBindStatusCallback IBindStatusCallback;
typedef IBindStatusCallback *LPBINDSTATUSCALLBACK;
typedef interface IStream IStream;
typedef IStream* LPSTREAM;
typedef interface IMoniker IMoniker;
typedef IMoniker* LPMONIKER;
typedef interface IBindCtx IBindCtx;
typedef IBindCtx* LPBC;
typedef interface IUri IUri;
typedef interface IServiceProvider IServiceProvider;
typedef interface IInternetSecurityManager IInternetSecurityManager;
typedef interface IInternetZoneManager IInternetZoneManager;

// --- Глобальні змінні для логування ---
#if ENABLE_FILE_LOGGING
static FILE* hLogFile = NULL;
static CRITICAL_SECTION csLog;
#endif

// --- Функція логування ---
void LogMessageW(const wchar_t* format, ...) {
#if ENABLE_DEBUG_CONSOLE || ENABLE_FILE_LOGGING
    wchar_t buffer[4096];
    va_list args;
    va_start(args, format);
    vswprintf_s(buffer, _countof(buffer), format, args);
    va_end(args);

#if ENABLE_FILE_LOGGING
    EnterCriticalSection(&csLog);
    if (hLogFile) {
        fwprintf(hLogFile, L"[STUB] %s\n", buffer);
        fflush(hLogFile);
    }
    LeaveCriticalSection(&csLog);
#endif

#if ENABLE_DEBUG_CONSOLE
    wprintf(L"[STUB] %s\n", buffer);
#endif
#endif
}

// --- Ядро логування (майбутнє ядро Smart-Stub) ---
void SmartStub_Log(const char* funcName) {
    wchar_t wFunc[256];
    MultiByteToWideChar(CP_UTF8, 0, funcName, -1, wFunc, 256);
    LogMessageW(L"[CALL] %s (Generic STUB)", wFunc);
}

// --- Точка входу DLL ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            DisableThreadLibraryCalls(hModule);

#if ENABLE_DEBUG_CONSOLE
            if (AllocConsole()) {
                FILE* pConsole;
                freopen_s(&pConsole, "CONOUT$", "w", stdout);
                SetConsoleTitleW(L"urlmon.dll Stub Debug Console");
            }
#endif

#if ENABLE_FILE_LOGGING
            InitializeCriticalSection(&csLog);
            wchar_t temp_path[MAX_PATH], log_path[MAX_PATH];
            if (GetTempPathW(MAX_PATH, temp_path) > 0) {
                swprintf_s(log_path, MAX_PATH, L"%surlmon_stub_log.txt", temp_path);
                // Відкриваємо файл у режимі дозапису з кодуванням UTF-8
                _wfopen_s(&hLogFile, log_path, L"a, ccs=UTF-8");
            }
#endif
            LogMessageW(L"**************************************************");
            LogMessageW(L"* Stub urlmon.dll ATTACHED                     *");
            LogMessageW(L"**************************************************");
            break;
        }
        case DLL_PROCESS_DETACH: {
            LogMessageW(L"**************************************************");
            LogMessageW(L"* Stub urlmon.dll DETACHING                    *");
            LogMessageW(L"**************************************************");
#if ENABLE_FILE_LOGGING
            if (hLogFile) {
                fclose(hLogFile);
                hLogFile = NULL;
            }
            DeleteCriticalSection(&csLog);
#endif
#if ENABLE_DEBUG_CONSOLE
            FreeConsole();
#endif
            break;
        }
    }
    return TRUE;
}

// --- Універсальна безпечна заглушка ---
// Кожна невідома функція буде реалізована через неї, щоб гарантувати стабільність.
HRESULT __stdcall GenericStub_HRESULT(const char* funcName) {
    SmartStub_Log(funcName);
    return E_NOTIMPL;
}
BOOL __stdcall GenericStub_BOOL(const char* funcName) {
    SmartStub_Log(funcName);
    return FALSE;
}
DWORD __stdcall GenericStub_DWORD(const char* funcName) {
    SmartStub_Log(funcName);
    return 0;
}
void __stdcall GenericStub_VOID(const char* funcName) {
    SmartStub_Log(funcName);
}
HWND __stdcall GenericStub_HWND(const char* funcName) {
    SmartStub_Log(funcName);
    return NULL;
}
WORD __stdcall GenericStub_WORD(const char* funcName) {
    SmartStub_Log(funcName);
    return 0;
}


// --- ЯВНА РЕАЛІЗАЦІЯ КОЖНОЇ ФУНКЦІЇ ---
HRESULT __stdcall ex_URLDownloadToFileW(LPUNKNOWN pCaller, LPCWSTR szURL, LPCWSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB) {
    LogMessageW(L"[CALL] URLDownloadToFileW (URL='%s', FileName='%s') - BLOCKED", szURL, szFileName);
    
    if (szFileName && szFileName[0]) {
        if (DeleteFileW(szFileName)) {
            LogMessageW(L"[INFO] Deleted file: %s", szFileName);
        }

        wchar_t tmpFile[MAX_PATH + 10];
        swprintf_s(tmpFile, MAX_PATH + 10, L"%s.tmp", szFileName);
        if (DeleteFileW(tmpFile)) {
            LogMessageW(L"[INFO] Deleted temp file: %s", tmpFile);
        }
    }
    
    return INET_E_DOWNLOAD_FAILURE;
}

HRESULT __stdcall ex_URLDownloadToFileA(LPUNKNOWN pCaller, LPCSTR szURL, LPCSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB) {
    LogMessageW(L"[CALL] URLDownloadToFileA (Thunking to W)");
    wchar_t wszURL[2048], wszFileName[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, szURL, -1, wszURL, 2048);
    MultiByteToWideChar(CP_ACP, 0, szFileName, -1, wszFileName, MAX_PATH);
    return ex_URLDownloadToFileW(pCaller, wszURL, wszFileName, dwReserved, lpfnCB);
}

HRESULT __stdcall ex_CoInternetCreateSecurityManager(IServiceProvider* pSP, IInternetSecurityManager** ppSM, DWORD dwReserved) {
    SmartStub_Log("CoInternetCreateSecurityManager");
    if (ppSM) *ppSM = NULL;
    return E_NOINTERFACE;
}
HRESULT __stdcall ex_DllCanUnloadNow() { SmartStub_Log("DllCanUnloadNow"); return S_OK; }
HRESULT __stdcall ex_DllGetClassObject(REFCLSID r, REFIID i, LPVOID* pp) { SmartStub_Log("DllGetClassObject"); return CLASS_E_CLASSNOTAVAILABLE; }
HRESULT __stdcall ex_DllRegisterServer() { SmartStub_Log("DllRegisterServer"); return S_OK; }
HRESULT __stdcall ex_DllUnregisterServer() { SmartStub_Log("DllUnregisterServer"); return S_OK; }
BOOL __stdcall ex_IsLoggingEnabledA(LPCSTR u) { SmartStub_Log("IsLoggingEnabledA"); return FALSE; }
BOOL __stdcall ex_IsLoggingEnabledW(LPCWSTR u) { SmartStub_Log("IsLoggingEnabledW"); return FALSE; }
DWORD __stdcall ex_CDLGetLongPathNameW(LPCWSTR s, LPWSTR l, DWORD c) { SmartStub_Log("CDLGetLongPathNameW"); return 0; }
DWORD __stdcall ex_CDLGetLongPathNameA(LPCSTR s, LPSTR l, DWORD c) { SmartStub_Log("CDLGetLongPathNameA"); return 0; }

// Усі інші функції як безпечні заглушки
HRESULT __stdcall ex_AsyncGetClassBits() { return GenericStub_HRESULT("AsyncGetClassBits"); }
HRESULT __stdcall ex_AsyncInstallDistributionUnit() { return GenericStub_HRESULT("AsyncInstallDistributionUnit"); }
HRESULT __stdcall ex_BindAsyncMoniker() { return GenericStub_HRESULT("BindAsyncMoniker"); }
HRESULT __stdcall ex_CAuthenticateHostUI_CreateInstance() { return GenericStub_HRESULT("CAuthenticateHostUI_CreateInstance"); }
HRESULT __stdcall ex_CORPolicyProvider() { return GenericStub_HRESULT("CORPolicyProvider"); }
HRESULT __stdcall ex_CoGetClassObjectFromURL() { return GenericStub_HRESULT("CoGetClassObjectFromURL"); }
HRESULT __stdcall ex_CoInstall() { return GenericStub_HRESULT("CoInstall"); }
HRESULT __stdcall ex_CoInternetCanonicalizeIUri() { return GenericStub_HRESULT("CoInternetCanonicalizeIUri"); }
HRESULT __stdcall ex_CoInternetCombineIUri() { return GenericStub_HRESULT("CoInternetCombineIUri"); }
HRESULT __stdcall ex_CoInternetCombineUrl() { return GenericStub_HRESULT("CoInternetCombineUrl"); }
HRESULT __stdcall ex_CoInternetCombineUrlEx() { return GenericStub_HRESULT("CoInternetCombineUrlEx"); }
HRESULT __stdcall ex_CoInternetCompareUrl() { return GenericStub_HRESULT("CoInternetCompareUrl"); }
HRESULT __stdcall ex_CoInternetCreateZoneManager() { return GenericStub_HRESULT("CoInternetCreateZoneManager"); }
HRESULT __stdcall ex_CoInternetFeatureSettingsChanged() { return GenericStub_HRESULT("CoInternetFeatureSettingsChanged"); }
HRESULT __stdcall ex_CoInternetGetMobileBrowserAppCompatMode() { return GenericStub_HRESULT("CoInternetGetMobileBrowserAppCompatMode"); }
HRESULT __stdcall ex_CoInternetGetMobileBrowserForceDesktopMode() { return GenericStub_HRESULT("CoInternetGetMobileBrowserForceDesktopMode"); }
HRESULT __stdcall ex_CoInternetGetProtocolFlags() { return GenericStub_HRESULT("CoInternetGetProtocolFlags"); }
HRESULT __stdcall ex_CoInternetGetSecurityUrl() { return GenericStub_HRESULT("CoInternetGetSecurityUrl"); }
HRESULT __stdcall ex_CoInternetGetSecurityUrlEx() { return GenericStub_HRESULT("CoInternetGetSecurityUrlEx"); }
HRESULT __stdcall ex_CoInternetGetSession() { return GenericStub_HRESULT("CoInternetGetSession"); }
HRESULT __stdcall ex_CoInternetIsFeatureEnabled() { return GenericStub_HRESULT("CoInternetIsFeatureEnabled"); }
HRESULT __stdcall ex_CoInternetIsFeatureEnabledForIUri() { return GenericStub_HRESULT("CoInternetIsFeatureEnabledForIUri"); }
HRESULT __stdcall ex_CoInternetIsFeatureEnabledForUrl() { return GenericStub_HRESULT("CoInternetIsFeatureEnabledForUrl"); }
HRESULT __stdcall ex_CoInternetIsFeatureZoneElevationEnabled() { return GenericStub_HRESULT("CoInternetIsFeatureZoneElevationEnabled"); }
HRESULT __stdcall ex_CoInternetParseIUri() { return GenericStub_HRESULT("CoInternetParseIUri"); }
HRESULT __stdcall ex_CoInternetParseUrl() { return GenericStub_HRESULT("CoInternetParseUrl"); }
HRESULT __stdcall ex_CoInternetQueryInfo() { return GenericStub_HRESULT("CoInternetQueryInfo"); }
HRESULT __stdcall ex_CoInternetSetFeatureEnabled() { return GenericStub_HRESULT("CoInternetSetFeatureEnabled"); }
HRESULT __stdcall ex_CoInternetSetMobileBrowserAppCompatMode() { return GenericStub_HRESULT("CoInternetSetMobileBrowserAppCompatMode"); }
HRESULT __stdcall ex_CoInternetSetMobileBrowserForceDesktopMode() { return GenericStub_HRESULT("CoInternetSetMobileBrowserForceDesktopMode"); }
HRESULT __stdcall ex_CompareSecurityIds() { return GenericStub_HRESULT("CompareSecurityIds"); }
HRESULT __stdcall ex_CompatFlagsFromClsid() { return GenericStub_HRESULT("CompatFlagsFromClsid"); }
HRESULT __stdcall ex_CopyBindInfo() { return GenericStub_HRESULT("CopyBindInfo"); }
HRESULT __stdcall ex_CopyStgMedium() { return GenericStub_HRESULT("CopyStgMedium"); }
HRESULT __stdcall ex_CreateAsyncBindCtx() { return GenericStub_HRESULT("CreateAsyncBindCtx"); }
HRESULT __stdcall ex_CreateAsyncBindCtxEx() { return GenericStub_HRESULT("CreateAsyncBindCtxEx"); }
HRESULT __stdcall ex_CreateFormatEnumerator() { return GenericStub_HRESULT("CreateFormatEnumerator"); }
HRESULT __stdcall ex_CreateIUriBuilder() { return GenericStub_HRESULT("CreateIUriBuilder"); }
HRESULT __stdcall ex_CreateURLMoniker() { return GenericStub_HRESULT("CreateURLMoniker"); }
HRESULT __stdcall ex_CreateURLMonikerEx() { return GenericStub_HRESULT("CreateURLMonikerEx"); }
HRESULT __stdcall ex_CreateURLMonikerEx2() { return GenericStub_HRESULT("CreateURLMonikerEx2"); }
HRESULT __stdcall ex_CreateUri() { return GenericStub_HRESULT("CreateUri"); }
HRESULT __stdcall ex_CreateUriFromMultiByteString() { return GenericStub_HRESULT("CreateUriFromMultiByteString"); }
HRESULT __stdcall ex_CreateUriPriv() { return GenericStub_HRESULT("CreateUriPriv"); }
HRESULT __stdcall ex_CreateUriWithFragment() { return GenericStub_HRESULT("CreateUriWithFragment"); }
HRESULT __stdcall ex_DllInstall() { return GenericStub_HRESULT("DllInstall"); }
HRESULT __stdcall ex_DllRegisterServerEx() { return GenericStub_HRESULT("DllRegisterServerEx"); }
HRESULT __stdcall ex_Extract() { return GenericStub_HRESULT("Extract"); }
HRESULT __stdcall ex_FaultInIEFeature() { return GenericStub_HRESULT("FaultInIEFeature"); }
BOOL __stdcall ex_FileBearsMarkOfTheWeb() { return GenericStub_BOOL("FileBearsMarkOfTheWeb"); }
HRESULT __stdcall ex_FindMediaType() { return GenericStub_HRESULT("FindMediaType"); }
HRESULT __stdcall ex_FindMediaTypeClass() { return GenericStub_HRESULT("FindMediaTypeClass"); }
HRESULT __stdcall ex_FindMimeFromData() { return GenericStub_HRESULT("FindMimeFromData"); }
HRESULT __stdcall ex_GetAddSitesFileUrl() { return GenericStub_HRESULT("GetAddSitesFileUrl"); }
HRESULT __stdcall ex_GetClassFileOrMime() { return GenericStub_HRESULT("GetClassFileOrMime"); }
HRESULT __stdcall ex_GetClassURL() { return GenericStub_HRESULT("GetClassURL"); }
HRESULT __stdcall ex_GetComponentIDFromCLSSPEC() { return GenericStub_HRESULT("GetComponentIDFromCLSSPEC"); }
HRESULT __stdcall ex_GetIDNFlagsForUri() { return GenericStub_HRESULT("GetIDNFlagsForUri"); }
HRESULT __stdcall ex_GetIUriPriv() { return GenericStub_HRESULT("GetIUriPriv"); }
HRESULT __stdcall ex_GetIUriPriv2() { return GenericStub_HRESULT("GetIUriPriv2"); }
HRESULT __stdcall ex_GetLabelsFromNamedHost() { return GenericStub_HRESULT("GetLabelsFromNamedHost"); }
HRESULT __stdcall ex_GetMarkOfTheWeb() { return GenericStub_HRESULT("GetMarkOfTheWeb"); }
WORD __stdcall ex_GetPortFromUrlScheme() { return GenericStub_WORD("GetPortFromUrlScheme"); }
HRESULT __stdcall ex_GetPropertyFromName() { return GenericStub_HRESULT("GetPropertyFromName"); }
HRESULT __stdcall ex_GetPropertyName() { return GenericStub_HRESULT("GetPropertyName"); }
HRESULT __stdcall ex_GetSoftwareUpdateInfo() { return GenericStub_HRESULT("GetSoftwareUpdateInfo"); }
HWND __stdcall ex_GetUrlmonThreadNotificationHwnd() { return GenericStub_HWND("GetUrlmonThreadNotificationHwnd"); }
HRESULT __stdcall ex_GetZoneFromAlternateDataStreamEx() { return GenericStub_HRESULT("GetZoneFromAlternateDataStreamEx"); }
HRESULT __stdcall ex_HlinkGoBack() { return GenericStub_HRESULT("HlinkGoBack"); }
HRESULT __stdcall ex_HlinkGoForward() { return GenericStub_HRESULT("HlinkGoForward"); }
HRESULT __stdcall ex_HlinkNavigateMoniker() { return GenericStub_HRESULT("HlinkNavigateMoniker"); }
HRESULT __stdcall ex_HlinkNavigateString() { return GenericStub_HRESULT("HlinkNavigateString"); }
HRESULT __stdcall ex_HlinkSimpleNavigateToMoniker() { return GenericStub_HRESULT("HlinkSimpleNavigateToMoniker"); }
HRESULT __stdcall ex_HlinkSimpleNavigateToString() { return GenericStub_HRESULT("HlinkSimpleNavigateToString"); }
HRESULT __stdcall ex_IECompatLogCSSFix() { return GenericStub_HRESULT("IECompatLogCSSFix"); }
HRESULT __stdcall ex_IEGetUserPrivateNamespaceName() { return GenericStub_HRESULT("IEGetUserPrivateNamespaceName"); }
HRESULT __stdcall ex_IEInstallScope() { return GenericStub_HRESULT("IEInstallScope"); }
HRESULT __stdcall ex_IntlPercentEncodeNormalize() { return GenericStub_HRESULT("IntlPercentEncodeNormalize"); }
BOOL __stdcall ex_IsAsyncMoniker() { return GenericStub_BOOL("IsAsyncMoniker"); }
BOOL __stdcall ex_IsDWORDProperty() { return GenericStub_BOOL("IsDWORDProperty"); }
BOOL __stdcall ex_IsIntranetAvailable() { return GenericStub_BOOL("IsIntranetAvailable"); }
BOOL __stdcall ex_IsJITInProgress() { return GenericStub_BOOL("IsJITInProgress"); }
BOOL __stdcall ex_IsStringProperty() { return GenericStub_BOOL("IsStringProperty"); }
HRESULT __stdcall ex_IsValidURL() { return GenericStub_HRESULT("IsValidURL"); }
HRESULT __stdcall ex_MkParseDisplayNameEx() { return GenericStub_HRESULT("MkParseDisplayNameEx"); }
HRESULT __stdcall ex_ObtainUserAgentString() { return GenericStub_HRESULT("ObtainUserAgentString"); }
HRESULT __stdcall ex_PrivateCoInstall() { return GenericStub_HRESULT("PrivateCoInstall"); }
HRESULT __stdcall ex_QueryAssociations() { return GenericStub_HRESULT("QueryAssociations"); }
HRESULT __stdcall ex_QueryClsidAssociation() { return GenericStub_HRESULT("QueryClsidAssociation"); }
HRESULT __stdcall ex_RegisterBindStatusCallback() { return GenericStub_HRESULT("RegisterBindStatusCallback"); }
HRESULT __stdcall ex_RegisterFormatEnumerator() { return GenericStub_HRESULT("RegisterFormatEnumerator"); }
HRESULT __stdcall ex_RegisterMediaTypeClass() { return GenericStub_HRESULT("RegisterMediaTypeClass"); }
HRESULT __stdcall ex_RegisterMediaTypes() { return GenericStub_HRESULT("RegisterMediaTypes"); }
HRESULT __stdcall ex_RegisterWebPlatformPermanentSecurityManager() { return GenericStub_HRESULT("RegisterWebPlatformPermanentSecurityManager"); }
void __stdcall ex_ReleaseBindInfo() { return GenericStub_VOID("ReleaseBindInfo"); }
HRESULT __stdcall ex_RestrictHTTP2() { return GenericStub_HRESULT("RestrictHTTP2"); }
HRESULT __stdcall ex_RevokeBindStatusCallback() { return GenericStub_HRESULT("RevokeBindStatusCallback"); }
HRESULT __stdcall ex_RevokeFormatEnumerator() { return GenericStub_HRESULT("RevokeFormatEnumerator"); }
HRESULT __stdcall ex_SetAccessForIEAppContainer() { return GenericStub_HRESULT("SetAccessForIEAppContainer"); }
HRESULT __stdcall ex_SetSoftwareUpdateAdvertisementState() { return GenericStub_HRESULT("SetSoftwareUpdateAdvertisementState"); }
HRESULT __stdcall ex_ShouldDisplayPunycodeForUri() { return GenericStub_HRESULT("ShouldDisplayPunycodeForUri"); }
HRESULT __stdcall ex_ShouldShowIntranetWarningSecband() { return GenericStub_HRESULT("ShouldShowIntranetWarningSecband"); }
HRESULT __stdcall ex_ShowTrustAlertDialog() { return GenericStub_HRESULT("ShowTrustAlertDialog"); }
HRESULT __stdcall ex_URLDownloadA() { return GenericStub_HRESULT("URLDownloadA"); }
HRESULT __stdcall ex_URLDownloadToCacheFileA() { return GenericStub_HRESULT("URLDownloadToCacheFileA"); }
HRESULT __stdcall ex_URLDownloadToCacheFileW() { return GenericStub_HRESULT("URLDownloadToCacheFileW"); }
HRESULT __stdcall ex_URLDownloadW() { return GenericStub_HRESULT("URLDownloadW"); }
HRESULT __stdcall ex_URLOpenBlockingStreamA() { return GenericStub_HRESULT("URLOpenBlockingStreamA"); }
HRESULT __stdcall ex_URLOpenBlockingStreamW() { return GenericStub_HRESULT("URLOpenBlockingStreamW"); }
HRESULT __stdcall ex_URLOpenPullStreamA() { return GenericStub_HRESULT("URLOpenPullStreamA"); }
HRESULT __stdcall ex_URLOpenPullStreamW() { return GenericStub_HRESULT("URLOpenPullStreamW"); }
HRESULT __stdcall ex_URLOpenStreamA() { return GenericStub_HRESULT("URLOpenStreamA"); }
HRESULT __stdcall ex_URLOpenStreamW() { return GenericStub_HRESULT("URLOpenStreamW"); }
HRESULT __stdcall ex_UnregisterWebPlatformPermanentSecurityManager() { return GenericStub_HRESULT("UnregisterWebPlatformPermanentSecurityManager"); }
HRESULT __stdcall ex_UrlMkBuildVersion() { return GenericStub_HRESULT("UrlMkBuildVersion"); }
HRESULT __stdcall ex_UrlMkGetSessionOption() { return GenericStub_HRESULT("UrlMkGetSessionOption"); }
HRESULT __stdcall ex_UrlMkSetSessionOption() { return GenericStub_HRESULT("UrlMkSetSessionOption"); }
HRESULT __stdcall ex_UrlmonCleanupCurrentThread() { return GenericStub_HRESULT("UrlmonCleanupCurrentThread"); }
HRESULT __stdcall ex_WriteHitLogging() { return GenericStub_HRESULT("WriteHitLogging"); }
HRESULT __stdcall ex_ZonesReInit() { return GenericStub_HRESULT("ZonesReInit"); }