#include <windows.h>
#include <winhttp.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

    // ============================================================================
    // STRUCTURES AND CONSTANTS
    // ============================================================================

    typedef struct {
        DWORD magic;
        DWORD type;
        DWORD reserved;
    } FAKE_HANDLE;

#define MAGIC_SESSION   0xDEADBEEF
#define MAGIC_CONNECT   0xCAFEBABE  
#define MAGIC_REQUEST   0xFEEDFACE
#define MAGIC_WEBSOCKET 0xBADDCAFE
#define MAGIC_RESOLVER  0xC0FFEE00

    static LONG g_handleCounter = 0x1000;

    // ============================================================================
    // HANDLE MANAGEMENT
    // ============================================================================

    static HINTERNET CreateFakeHandle(DWORD type) {
        FAKE_HANDLE* handle = (FAKE_HANDLE*)malloc(sizeof(FAKE_HANDLE));
        if (handle) {
            handle->magic = type;
            handle->type = InterlockedIncrement(&g_handleCounter);
            handle->reserved = 0;
            return (HINTERNET)handle;
        }
        return NULL;
    }

    static BOOL IsValidHandle(HINTERNET handle) {
        if (!handle) return FALSE;
        FAKE_HANDLE* fh = (FAKE_HANDLE*)handle;
        return (fh->magic == MAGIC_SESSION ||
            fh->magic == MAGIC_CONNECT ||
            fh->magic == MAGIC_REQUEST ||
            fh->magic == MAGIC_WEBSOCKET ||
            fh->magic == MAGIC_RESOLVER);
    }

    // ============================================================================
    // MAIN FUNCTIONS
    // ============================================================================

    HINTERNET WINAPI ex_WinHttpOpen(
        LPCWSTR pszAgentW,
        DWORD dwAccessType,
        LPCWSTR pszProxyW,
        LPCWSTR pszProxyBypassW,
        DWORD dwFlags)
    {
        return CreateFakeHandle(MAGIC_SESSION);
    }

    BOOL WINAPI ex_WinHttpCloseHandle(HINTERNET hInternet)
    {
        if (IsValidHandle(hInternet)) {
            free(hInternet);
            return TRUE;
        }
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    HINTERNET WINAPI ex_WinHttpConnect(
        HINTERNET hSession,
        LPCWSTR pswzServerName,
        INTERNET_PORT nServerPort,
        DWORD dwReserved)
    {
        if (!IsValidHandle(hSession)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return NULL;
        }
        return CreateFakeHandle(MAGIC_CONNECT);
    }

    HINTERNET WINAPI ex_WinHttpOpenRequest(
        HINTERNET hConnect,
        LPCWSTR pwszVerb,
        LPCWSTR pwszObjectName,
        LPCWSTR pwszVersion,
        LPCWSTR pwszReferrer,
        LPCWSTR* ppwszAcceptTypes,
        DWORD dwFlags)
    {
        if (!IsValidHandle(hConnect)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return NULL;
        }
        return CreateFakeHandle(MAGIC_REQUEST);
    }

    BOOL WINAPI ex_WinHttpSendRequest(
        HINTERNET hRequest,
        LPCWSTR lpszHeaders,
        DWORD dwHeadersLength,
        LPVOID lpOptional,
        DWORD dwOptionalLength,
        DWORD dwTotalLength,
        DWORD_PTR dwContext)
    {
        if (!IsValidHandle(hRequest)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpReceiveResponse(
        HINTERNET hRequest,
        LPVOID lpReserved)
    {
        if (!IsValidHandle(hRequest)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpReadData(
        HINTERNET hRequest,
        LPVOID lpBuffer,
        DWORD dwNumberOfBytesToRead,
        LPDWORD lpdwNumberOfBytesRead)
    {
        if (!IsValidHandle(hRequest)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        if (lpdwNumberOfBytesRead) {
            *lpdwNumberOfBytesRead = 0;
        }
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpReadDataEx(
        HINTERNET hRequest,
        LPVOID lpBuffer,
        DWORD dwNumberOfBytesToRead,
        LPDWORD lpdwNumberOfBytesRead,
        ULONGLONG ullFlags,
        DWORD_PTR dwContext)
    {
        return ex_WinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    }

    BOOL WINAPI ex_WinHttpWriteData(
        HINTERNET hRequest,
        LPCVOID lpBuffer,
        DWORD dwNumberOfBytesToWrite,
        LPDWORD lpdwNumberOfBytesWritten)
    {
        if (!IsValidHandle(hRequest)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        if (lpdwNumberOfBytesWritten) {
            *lpdwNumberOfBytesWritten = dwNumberOfBytesToWrite;
        }
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpQueryDataAvailable(
        HINTERNET hRequest,
        LPDWORD lpdwNumberOfBytesAvailable)
    {
        if (!IsValidHandle(hRequest)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        if (lpdwNumberOfBytesAvailable) {
            *lpdwNumberOfBytesAvailable = 0;
        }
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpQueryHeaders(
        HINTERNET hRequest,
        DWORD dwInfoLevel,
        LPCWSTR pwszName,
        LPVOID lpBuffer,
        LPDWORD lpdwBufferLength,
        LPDWORD lpdwIndex)
    {
        if (!IsValidHandle(hRequest)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }

        if (lpdwBufferLength && *lpdwBufferLength == 0) {
            *lpdwBufferLength = 2;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }

        if (lpBuffer && lpdwBufferLength && *lpdwBufferLength >= 2) {
            ((WCHAR*)lpBuffer)[0] = L'\0';
            *lpdwBufferLength = 2;
        }

        return TRUE;
    }

    DWORD WINAPI ex_WinHttpQueryHeadersEx(
        HINTERNET hRequest,
        DWORD dwInfoLevel,
        ULONGLONG ullFlags,
        LPCWSTR pwszName,
        LPVOID lpBuffer,
        LPDWORD lpdwBufferLength,
        LPVOID* ppvExtraBuffer,
        LPDWORD lpdwExtraBufferLength)
    {
        if (!IsValidHandle(hRequest)) {
            return ERROR_INVALID_HANDLE;
        }
        if (lpdwBufferLength) {
            *lpdwBufferLength = 0;
        }
        return ERROR_SUCCESS;
    }

    BOOL WINAPI ex_WinHttpAddRequestHeaders(
        HINTERNET hRequest,
        LPCWSTR lpszHeaders,
        DWORD dwHeadersLength,
        DWORD dwModifiers)
    {
        if (!IsValidHandle(hRequest)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        return TRUE;
    }

    DWORD WINAPI ex_WinHttpAddRequestHeadersEx(
        HINTERNET hRequest,
        DWORD dwModifiers,
        ULONGLONG ullFlags,
        ULONGLONG ullExtra,
        DWORD cHeaders,
        LPVOID pHeaders)
    {
        if (!IsValidHandle(hRequest)) {
            return ERROR_INVALID_HANDLE;
        }
        return ERROR_SUCCESS;
    }

    BOOL WINAPI ex_WinHttpSetOption(
        HINTERNET hInternet,
        DWORD dwOption,
        LPVOID lpBuffer,
        DWORD dwBufferLength)
    {
        if (hInternet && !IsValidHandle(hInternet)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpQueryOption(
        HINTERNET hInternet,
        DWORD dwOption,
        LPVOID lpBuffer,
        LPDWORD lpdwBufferLength)
    {
        if (hInternet && !IsValidHandle(hInternet)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        if (lpdwBufferLength) {
            *lpdwBufferLength = 0;
        }
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    BOOL WINAPI ex_WinHttpSetTimeouts(
        HINTERNET hInternet,
        int nResolveTimeout,
        int nConnectTimeout,
        int nSendTimeout,
        int nReceiveTimeout)
    {
        if (!IsValidHandle(hInternet)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        return TRUE;
    }

    WINHTTP_STATUS_CALLBACK WINAPI ex_WinHttpSetStatusCallback(
        HINTERNET hInternet,
        WINHTTP_STATUS_CALLBACK lpfnInternetCallback,
        DWORD dwNotificationFlags,
        DWORD_PTR dwReserved)
    {
        if (hInternet && !IsValidHandle(hInternet)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return WINHTTP_INVALID_STATUS_CALLBACK;
        }
        return NULL;
    }

    // ============================================================================
    // AUTHENTICATION
    // ============================================================================

    BOOL WINAPI ex_WinHttpQueryAuthSchemes(
        HINTERNET hRequest,
        LPDWORD lpdwSupportedSchemes,
        LPDWORD lpdwFirstScheme,
        LPDWORD pdwAuthTarget)
    {
        if (!IsValidHandle(hRequest)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        if (lpdwSupportedSchemes) *lpdwSupportedSchemes = 0;
        if (lpdwFirstScheme) *lpdwFirstScheme = 0;
        if (pdwAuthTarget) *pdwAuthTarget = 0;
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpQueryAuthParams(
        HINTERNET hRequest,
        DWORD AuthScheme,
        LPVOID* pAuthParams)
    {
        if (!IsValidHandle(hRequest)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        if (pAuthParams) *pAuthParams = NULL;
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpSetCredentials(
        HINTERNET hRequest,
        DWORD AuthTargets,
        DWORD AuthScheme,
        LPCWSTR pwszUserName,
        LPCWSTR pwszPassword,
        LPVOID pAuthParams)
    {
        if (!IsValidHandle(hRequest)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpQueryCertificate(
        HINTERNET hRequest,
        DWORD dwInfoLevel,
        LPVOID lpBuffer,
        LPDWORD lpdwBufferLength)
    {
        if (!IsValidHandle(hRequest)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        SetLastError(ERROR_WINHTTP_INCORRECT_HANDLE_STATE);
        return FALSE;
    }

    BOOL WINAPI ex_WinHttpSetClientCertificate(
        HINTERNET hRequest,
        DWORD dwCertIndex,
        LPVOID lpCertContext)
    {
        if (!IsValidHandle(hRequest)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        return TRUE;
    }

    // ============================================================================
    // PROXY
    // ============================================================================

    BOOL WINAPI ex_WinHttpGetProxyForUrl(
        HINTERNET hSession,
        LPCWSTR lpcwszUrl,
        WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions,
        WINHTTP_PROXY_INFO* pProxyInfo)
    {
        if (!IsValidHandle(hSession)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        SetLastError(ERROR_WINHTTP_AUTODETECTION_FAILED);
        return FALSE;
    }

    DWORD WINAPI ex_WinHttpGetProxyForUrlEx(
        HINTERNET hResolver,
        PCWSTR pcwszUrl,
        WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions,
        DWORD_PTR pContext)
    {
        return ERROR_WINHTTP_AUTODETECTION_FAILED;
    }

    DWORD WINAPI ex_WinHttpGetProxyForUrlEx2(
        HINTERNET hResolver,
        PCWSTR pcwszUrl,
        WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions,
        DWORD cbInterfaceSelectionContext,
        BYTE* pInterfaceSelectionContext,
        DWORD_PTR pContext)
    {
        return ERROR_WINHTTP_AUTODETECTION_FAILED;
    }

    DWORD WINAPI ex_WinHttpGetProxyForUrlHvsi(
        LPVOID p1, LPVOID p2, LPVOID p3, LPVOID p4)
    {
        return ERROR_NOT_SUPPORTED;
    }

    DWORD WINAPI ex_WinHttpGetProxyResult(
        HINTERNET hResolver,
        WINHTTP_PROXY_RESULT* pProxyResult)
    {
        return ERROR_WINHTTP_INCORRECT_HANDLE_STATE;
    }

    DWORD WINAPI ex_WinHttpGetProxyResultEx(
        HINTERNET hResolver,
        WINHTTP_PROXY_RESULT_EX* pProxyResultEx)
    {
        return ERROR_WINHTTP_INCORRECT_HANDLE_STATE;
    }

    VOID WINAPI ex_WinHttpFreeProxyResult(WINHTTP_PROXY_RESULT* pProxyResult)
    {
    }

    VOID WINAPI ex_WinHttpFreeProxyResultEx(WINHTTP_PROXY_RESULT_EX* pProxyResultEx)
    {
    }

    VOID WINAPI ex_WinHttpFreeProxySettings(WINHTTP_PROXY_SETTINGS* pProxySettings)
    {
    }

    DWORD WINAPI ex_WinHttpFreeProxySettingsEx(LPVOID p1)
    {
        return ERROR_SUCCESS;
    }

    BOOL WINAPI ex_WinHttpGetDefaultProxyConfiguration(WINHTTP_PROXY_INFO* pProxyInfo)
    {
        if (pProxyInfo) {
            ZeroMemory(pProxyInfo, sizeof(WINHTTP_PROXY_INFO));
            pProxyInfo->dwAccessType = 1;
        }
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpSetDefaultProxyConfiguration(WINHTTP_PROXY_INFO* pProxyInfo)
    {
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpGetIEProxyConfigForCurrentUser(
        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* pProxyConfig)
    {
        if (pProxyConfig) {
            ZeroMemory(pProxyConfig, sizeof(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG));
        }
        return TRUE;
    }

    DWORD WINAPI ex_WinHttpResetAutoProxy(
        HINTERNET hSession,
        DWORD dwFlags)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpSetProxySettingsPerUser(BOOL fProxySettingsPerUser)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpGetProxySettingsEx(
        HINTERNET hSession,
        LPCWSTR pcwszUrl,
        LPVOID pProxySettingsParam,
        DWORD_PTR pContext)
    {
        return ERROR_NOT_SUPPORTED;
    }

    DWORD WINAPI ex_WinHttpGetProxySettingsResultEx(LPVOID p1, LPVOID p2)
    {
        return ERROR_NOT_SUPPORTED;
    }

    DWORD WINAPI ex_WinHttpGetProxySettingsVersion(
        HINTERNET hSession,
        LPDWORD pdwProxySettingsVersion)
    {
        if (pdwProxySettingsVersion) {
            *pdwProxySettingsVersion = 1;
        }
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpReadProxySettings(
        HINTERNET hSession,
        PCWSTR pcwszConnectionName,
        BOOL fFallBackToDefaultSettings,
        BOOL fSetAutoDiscoverForDefaultSettings,
        DWORD* pdwSettingsVersion,
        BOOL* pfDefaultSettingsAreReturned,
        WINHTTP_PROXY_SETTINGS* pProxySettings)
    {
        if (pdwSettingsVersion) *pdwSettingsVersion = 1;
        if (pfDefaultSettingsAreReturned) *pfDefaultSettingsAreReturned = TRUE;
        if (pProxySettings) {
            ZeroMemory(pProxySettings, sizeof(WINHTTP_PROXY_SETTINGS));
        }
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpReadProxySettingsHvsi(
        LPVOID p1, LPVOID p2, LPVOID p3, LPVOID p4)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpWriteProxySettings(
        HINTERNET hSession,
        BOOL fForceUpdate,
        WINHTTP_PROXY_SETTINGS* pProxySettings)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpRegisterProxyChangeNotification(
        DWORD dwFlags,
        LPVOID pCallback,
        LPVOID pContext,
        LPVOID* phNotification)
    {
        if (phNotification) {
            *phNotification = CreateFakeHandle(MAGIC_SESSION);
        }
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpUnregisterProxyChangeNotification(LPVOID hNotification)
    {
        if (IsValidHandle((HINTERNET)hNotification)) {
            free(hNotification);
        }
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpCreateProxyResolver(
        HINTERNET hSession,
        HINTERNET* phResolver)
    {
        if (!IsValidHandle(hSession)) {
            return ERROR_INVALID_HANDLE;
        }
        if (phResolver) {
            *phResolver = CreateFakeHandle(MAGIC_RESOLVER);
        }
        return ERROR_SUCCESS;
    }

    VOID WINAPI ex_WinHttpFreeProxyResolver(HINTERNET hResolver)
    {
        if (IsValidHandle(hResolver)) {
            free(hResolver);
        }
    }

    // ============================================================================
    // WEBSOCKET
    // ============================================================================

    HINTERNET WINAPI ex_WinHttpWebSocketCompleteUpgrade(
        HINTERNET hRequest,
        DWORD_PTR pContext)
    {
        if (!IsValidHandle(hRequest)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return NULL;
        }
        return CreateFakeHandle(MAGIC_WEBSOCKET);
    }

    DWORD WINAPI ex_WinHttpWebSocketSend(
        HINTERNET hWebSocket,
        WINHTTP_WEB_SOCKET_BUFFER_TYPE eBufferType,
        void* pvBuffer,
        DWORD dwBufferLength)
    {
        if (!IsValidHandle(hWebSocket)) {
            return ERROR_INVALID_HANDLE;
        }
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpWebSocketReceive(
        HINTERNET hWebSocket,
        void* pvBuffer,
        DWORD dwBufferLength,
        DWORD* pdwBytesRead,
        WINHTTP_WEB_SOCKET_BUFFER_TYPE* peBufferType)
    {
        if (!IsValidHandle(hWebSocket)) {
            return ERROR_INVALID_HANDLE;
        }
        if (pdwBytesRead) *pdwBytesRead = 0;
        if (peBufferType) *peBufferType = (WINHTTP_WEB_SOCKET_BUFFER_TYPE)0;
        return ERROR_WINHTTP_TIMEOUT;
    }

    DWORD WINAPI ex_WinHttpWebSocketClose(
        HINTERNET hWebSocket,
        USHORT usStatus,
        LPVOID pvReason,
        DWORD dwReasonLength)
    {
        if (!IsValidHandle(hWebSocket)) {
            return ERROR_INVALID_HANDLE;
        }
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpWebSocketShutdown(
        HINTERNET hWebSocket,
        USHORT usStatus,
        LPVOID pvReason,
        DWORD dwReasonLength)
    {
        if (!IsValidHandle(hWebSocket)) {
            return ERROR_INVALID_HANDLE;
        }
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpWebSocketQueryCloseStatus(
        HINTERNET hWebSocket,
        USHORT* pusStatus,
        LPVOID pvReason,
        DWORD dwReasonLength,
        LPDWORD pdwReasonLengthConsumed)
    {
        if (!IsValidHandle(hWebSocket)) {
            return ERROR_INVALID_HANDLE;
        }
        if (pusStatus) *pusStatus = 0;
        if (pdwReasonLengthConsumed) *pdwReasonLengthConsumed = 0;
        return ERROR_SUCCESS;
    }

    // ============================================================================
    // URL FUNCTIONS
    // ============================================================================

    BOOL WINAPI ex_WinHttpCrackUrl(
        LPCWSTR pwszUrl,
        DWORD dwUrlLength,
        DWORD dwFlags,
        LPURL_COMPONENTS lpUrlComponents)
    {
        if (!pwszUrl || !lpUrlComponents) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        ZeroMemory(lpUrlComponents, sizeof(URL_COMPONENTS));
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpCreateUrl(
        LPURL_COMPONENTS lpUrlComponents,
        DWORD dwFlags,
        LPWSTR pwszUrl,
        LPDWORD pdwUrlLength)
    {
        if (!lpUrlComponents || !pdwUrlLength) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }

        if (!pwszUrl || *pdwUrlLength < 8) {
            *pdwUrlLength = 8;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }

        wcscpy_s(pwszUrl, *pdwUrlLength, L"http://");
        *pdwUrlLength = 8;
        return TRUE;
    }

    // ============================================================================
    // OTHER FUNCTIONS
    // ============================================================================

    BOOL WINAPI ex_WinHttpCheckPlatform(void)
    {
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpDetectAutoProxyConfigUrl(
        DWORD dwAutoDetectFlags,
        LPWSTR* ppwszAutoConfigUrl)
    {
        if (ppwszAutoConfigUrl) {
            *ppwszAutoConfigUrl = NULL;
        }
        SetLastError(ERROR_WINHTTP_AUTODETECTION_FAILED);
        return FALSE;
    }

    BOOL WINAPI ex_WinHttpTimeFromSystemTime(
        const SYSTEMTIME* pst,
        LPWSTR pwszTime)
    {
        if (!pst || !pwszTime) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        wsprintfW(pwszTime, L"Mon, 01 Jan 2000 00:00:00 GMT");
        return TRUE;
    }

    BOOL WINAPI ex_WinHttpTimeToSystemTime(
        LPCWSTR pwszTime,
        SYSTEMTIME* pst)
    {
        if (!pwszTime || !pst) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        ZeroMemory(pst, sizeof(SYSTEMTIME));
        pst->wYear = 2000;
        pst->wMonth = 1;
        pst->wDay = 1;
        return TRUE;
    }

    DWORD WINAPI ex_WinHttpQueryConnectionGroup(
        HINTERNET hInternet,
        LPVOID pGuid,
        LPVOID ppvResolverHandle,
        LPVOID ppProxyInfo)
    {
        return ERROR_NOT_SUPPORTED;
    }

    VOID WINAPI ex_WinHttpFreeQueryConnectionGroupResult(LPVOID pResult)
    {
    }

    DWORD WINAPI ex_WinHttpGetTunnelSocket(
        HINTERNET hRequest,
        SOCKET* pSocket)
    {
        return ERROR_NOT_SUPPORTED;
    }

    DWORD WINAPI ex_WinHttpProbeConnectivity(
        LPVOID p1, LPVOID p2, LPVOID p3)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpSaveProxyCredentials(
        LPVOID p1, LPVOID p2, LPVOID p3)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpSetSecureProtocols(
        HINTERNET hInternet, DWORD dwProtocols)
    {
        return ERROR_SUCCESS;
    }

    // ============================================================================
    // CONNECTION FUNCTIONS
    // ============================================================================

    DWORD WINAPI ex_WinHttpConnectionDeletePolicyEntries(LPVOID p1)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpConnectionDeleteProxyInfo(LPVOID p1)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpConnectionFreeNameList(LPVOID p1)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpConnectionFreeProxyInfo(LPVOID p1)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpConnectionFreeProxyList(LPVOID p1)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpConnectionGetNameList(LPVOID p1)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpConnectionGetProxyInfo(LPVOID p1)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpConnectionGetProxyList(LPVOID p1)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpConnectionOnlyConvert(LPVOID p1, LPVOID p2)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpConnectionOnlyReceive(LPVOID p1, LPVOID p2)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpConnectionOnlySend(LPVOID p1, LPVOID p2)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpConnectionSetPolicyEntries(LPVOID p1)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpConnectionSetProxyInfo(LPVOID p1)
    {
        return ERROR_SUCCESS;
    }

    DWORD WINAPI ex_WinHttpConnectionUpdateIfIndexTable(LPVOID p1)
    {
        return ERROR_SUCCESS;
    }

    // ============================================================================
    // COM/SERVICE FUNCTIONS
    // ============================================================================

    HRESULT WINAPI ex_DllCanUnloadNow(void)
    {
        return S_FALSE;
    }

    HRESULT WINAPI ex_DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
    {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    DWORD WINAPI ex_Private1(void)
    {
        return 0;
    }

    DWORD WINAPI ex_SvchostPushServiceGlobals(LPVOID lpGlobals)
    {
        return 0;
    }

    DWORD WINAPI ex_WinHttpAutoProxySvcMain(DWORD dwNumServicesArgs, LPWSTR* lpServiceArgVectors)
    {
        return 0;
    }

    DWORD WINAPI ex_WinHttpPacJsWorkerMain(LPVOID p1)
    {
        return 0;
    }

    // ============================================================================
    // DLL ENTRY POINT
    // ============================================================================

    BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
    {
        switch (ul_reason_for_call)
        {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;

        case DLL_PROCESS_DETACH:
            break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;
        }
        return TRUE;
    }

#ifdef __cplusplus
}
#endif