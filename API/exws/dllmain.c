// ============================================================================
// mswsock_stub.c - Емулятор MSWSOCK.DLL v1.0
// Stub-бібліотека для Microsoft Windows Sockets Provider
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include <ws2spi.h>
#include <nspapi.h>
#include <winternl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Визначення для WSHGetSockaddrType, відсутні в деяких SDK (ПРАВИЛЬНА ВЕРСІЯ)
// Спочатку визначаємо переліки (enum), які будуть членами структури
typedef enum {
    SockaddrAddressInfoNormal,
    SockaddrAddressInfoLoopback,
    SockaddrAddressInfoBroadcast,
    SockaddrAddressInfoWildcard
} SOCKADDR_ADDRESS_INFO;

typedef enum {
    SockaddrEndpointInfoNormal,
    SockaddrEndpointInfoLoopback,
    SockaddrEndpointInfoBroadcast,
    SockaddrEndpointInfoWildcard
} SOCKADDR_ENDPOINT_INFO;

// А тепер визначаємо саму СТРУКТУРУ
typedef struct _SOCKADDR_INFO {
    SOCKADDR_ADDRESS_INFO AddressInfo;
    SOCKADDR_ENDPOINT_INFO EndpointInfo;
} SOCKADDR_INFO, *PSOCKADDR_INFO;

// Визначаємо константи, які використовуються у вашому коді
#define SockaddrInfoNormal       SockaddrAddressInfoNormal
#define SockaddrEndpointRelevant SockaddrEndpointInfoNormal

// Визначення для WSHGetWinsockMapping, відсутнє в деяких SDK
typedef struct _WINSOCK_MAPPING {
    DWORD Rows;
    DWORD Columns;
} WINSOCK_MAPPING, *PWINSOCK_MAPPING;

// Визначення для NPLoadNameSpaces, відсутнє в деяких SDK
typedef struct _NS_ROUTINE {
    DWORD        dwFunctionCount;
    LPVOID*      lpfnFunctions; // Використовуємо LPVOID* для загальної сумісності
} NS_ROUTINE, *PNS_ROUTINE, *LPNS_ROUTINE;

#pragma comment(lib, "kernel32.lib")

static inline unsigned short my_htons(unsigned short hostshort) {
    return ((hostshort & 0xff) << 8) | ((hostshort & 0xff00) >> 8);
}

static inline unsigned long my_htonl(unsigned long hostlong) {
    return ((hostlong & 0xff) << 24) | ((hostlong & 0xff00) << 8) |
           ((hostlong & 0xff0000) >> 8) | ((hostlong & 0xff000000) >> 24);
}

static inline unsigned short my_ntohs(unsigned short netshort) {
    return my_htons(netshort);
}

static inline unsigned long my_ntohl(unsigned long netlong) {
    return my_htonl(netlong);
}

// Перевизначаємо стандартні імена
#define htons(x) my_htons(x)
#define htonl(x) my_htonl(x)
#define ntohs(x) my_ntohs(x)
#define ntohl(x) my_ntohl(x)


// === НАЛАГОДЖУВАЛЬНІ КОНСТАНТИ ===
#define ENABLE_DEBUG_CONSOLE 0
#define ENABLE_FILE_LOGGING  0

// === ГЛОБАЛЬНІ ЗМІННІ ===
static volatile LONG g_InitCount = 0;
static DWORD g_tlsError = TLS_OUT_OF_INDEXES;

#if ENABLE_FILE_LOGGING
static FILE* g_LogFile = NULL;
static CRITICAL_SECTION g_LogCS;
#endif

// === ДОПОМІЖНІ ФУНКЦІЇ ===

void SetMSWSockError(int error) {
    if (g_tlsError != TLS_OUT_OF_INDEXES) {
        TlsSetValue(g_tlsError, (LPVOID)(LONG_PTR)error);
    }
}

void LogMessage(const char* format, ...) {
#if ENABLE_DEBUG_CONSOLE || ENABLE_FILE_LOGGING
    char buffer[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    #if ENABLE_DEBUG_CONSOLE
    printf("[MSWSOCK] %s\n", buffer);
    fflush(stdout);
    #endif
    
    #if ENABLE_FILE_LOGGING
    if (g_LogFile) {
        EnterCriticalSection(&g_LogCS);
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_LogFile, "[%02d:%02d:%02d.%03d] %s\n", 
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buffer);
        fflush(g_LogFile);
        LeaveCriticalSection(&g_LogCS);
    }
    #endif
#endif
}

// === ОСНОВНІ ФУНКЦІЇ MSWSOCK ===

// AcceptEx - розширена функція accept з overlapped I/O
BOOL PASCAL ex_AcceptEx(
    SOCKET sListenSocket,
    SOCKET sAcceptSocket,
    PVOID lpOutputBuffer,
    DWORD dwReceiveDataLength,
    DWORD dwLocalAddressLength,
    DWORD dwRemoteAddressLength,
    LPDWORD lpdwBytesReceived,
    LPOVERLAPPED lpOverlapped)
{
    LogMessage("AcceptEx(listen=%llu, accept=%llu) -> PENDING", 
               (UINT_PTR)sListenSocket, (UINT_PTR)sAcceptSocket);
    
    // В офлайн режимі просто симулюємо pending операцію
    if (lpOverlapped) {
        lpOverlapped->Internal = STATUS_PENDING;
        lpOverlapped->InternalHigh = 0;
        
        if (lpOverlapped->hEvent) {
            // Сигналізуємо про "завершення" через невеликий час
            SetEvent(lpOverlapped->hEvent);
        }
    }
    
    if (lpdwBytesReceived) {
        *lpdwBytesReceived = 0;
    }
    
    SetMSWSockError(WSA_IO_PENDING);
    return FALSE;
}

// GetAcceptExSockaddrs - отримання адрес з буфера AcceptEx
VOID PASCAL ex_GetAcceptExSockaddrs(
    PVOID lpOutputBuffer,
    DWORD dwReceiveDataLength,
    DWORD dwLocalAddressLength,
    DWORD dwRemoteAddressLength,
    LPSOCKADDR* LocalSockaddr,
    LPINT LocalSockaddrLength,
    LPSOCKADDR* RemoteSockaddr,
    LPINT RemoteSockaddrLength)
{
    LogMessage("GetAcceptExSockaddrs() called");
    
    // Повертаємо фейкові локальні адреси
    if (LocalSockaddr && LocalSockaddrLength) {
        static struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        local_addr.sin_port = htons(8080);
        
        *LocalSockaddr = (LPSOCKADDR)&local_addr;
        *LocalSockaddrLength = sizeof(local_addr);
    }
    
    if (RemoteSockaddr && RemoteSockaddrLength) {
        static struct sockaddr_in remote_addr;
        memset(&remote_addr, 0, sizeof(remote_addr));
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        remote_addr.sin_port = htons(12345);
        
        *RemoteSockaddr = (LPSOCKADDR)&remote_addr;
        *RemoteSockaddrLength = sizeof(remote_addr);
    }
}

// TransmitFile - високошвидкісна передача файлів через сокет
BOOL PASCAL ex_TransmitFile(
    SOCKET hSocket,
    HANDLE hFile,
    DWORD nNumberOfBytesToWrite,
    DWORD nNumberOfBytesPerSend,
    LPOVERLAPPED lpOverlapped,
    LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
    DWORD dwFlags)
{
    LogMessage("TransmitFile(socket=%llu, file=%p) -> BLOCKED", 
               (UINT_PTR)hSocket, hFile);
    
    // В офлайн режимі не можемо передавати файли
    if (lpOverlapped) {
        lpOverlapped->Internal = WSAENETDOWN;
        lpOverlapped->InternalHigh = 0;
        if (lpOverlapped->hEvent) {
            SetEvent(lpOverlapped->hEvent);
        }
    }
    
    SetMSWSockError(WSAENETDOWN);
    return FALSE;
}

// WSARecvEx - розширена функція recv
int PASCAL ex_WSARecvEx(
    SOCKET s,
    char* buf,
    int len,
    int* flags)
{
    LogMessage("WSARecvEx(socket=%llu, len=%d) -> BLOCKED", 
               (UINT_PTR)s, len);
    
    // В офлайн режимі блокуємо
    SetMSWSockError(WSAENETDOWN);
    return SOCKET_ERROR;
}

// === PROTOCOL ENUMERATION ===

INT WSAAPI ex_EnumProtocolsA(
    LPINT lpiProtocols,
    LPVOID lpProtocolBuffer,
    LPDWORD lpdwBufferLength)
{
    LogMessage("EnumProtocolsA() called");
    
    if (lpdwBufferLength) {
        *lpdwBufferLength = 0;
    }
    
    SetMSWSockError(0);
    return 0;  // Немає протоколів в офлайн режимі
}

INT WSAAPI ex_EnumProtocolsW(
    LPINT lpiProtocols,
    LPVOID lpProtocolBuffer,
    LPDWORD lpdwBufferLength)
{
    LogMessage("EnumProtocolsW() called");
    
    if (lpdwBufferLength) {
        *lpdwBufferLength = 0;
    }
    
    SetMSWSockError(0);
    return 0;
}

// === NAME SERVICE FUNCTIONS ===

INT WSAAPI ex_GetAddressByNameA(
    DWORD dwNameSpace,
    LPGUID lpServiceType,
    LPSTR lpServiceName,
    LPINT lpiProtocols,
    DWORD dwResolution,
    LPSERVICE_ASYNC_INFO lpServiceAsyncInfo,
    LPVOID lpCsaddrBuffer,
    LPDWORD lpdwBufferLength,
    LPSTR lpAliasBuffer,
    LPDWORD lpdwAliasBufferLength)
{
    LogMessage("GetAddressByNameA('%s') -> NOT FOUND", 
               lpServiceName ? lpServiceName : "NULL");
    
    SetMSWSockError(WSAHOST_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetAddressByNameW(
    DWORD dwNameSpace,
    LPGUID lpServiceType,
    LPWSTR lpServiceName,
    LPINT lpiProtocols,
    DWORD dwResolution,
    LPSERVICE_ASYNC_INFO lpServiceAsyncInfo,
    LPVOID lpCsaddrBuffer,
    LPDWORD lpdwBufferLength,
    LPWSTR lpAliasBuffer,
    LPDWORD lpdwAliasBufferLength)
{
    LogMessage("GetAddressByNameW() -> NOT FOUND");
    
    SetMSWSockError(WSAHOST_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetNameByTypeA(
    LPGUID lpServiceType,
    LPSTR lpServiceName,
    DWORD dwNameLength)
{
    LogMessage("GetNameByTypeA() called");
    
    if (lpServiceName && dwNameLength > 0) {
        lpServiceName[0] = '\0';
    }
    
    SetMSWSockError(WSATYPE_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetNameByTypeW(
    LPGUID lpServiceType,
    LPWSTR lpServiceName,
    DWORD dwNameLength)
{
    LogMessage("GetNameByTypeW() called");
    
    if (lpServiceName && dwNameLength > 0) {
        lpServiceName[0] = L'\0';
    }
    
    SetMSWSockError(WSATYPE_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetTypeByNameA(
    LPSTR lpServiceName,
    LPGUID lpServiceType)
{
    LogMessage("GetTypeByNameA('%s') called", 
               lpServiceName ? lpServiceName : "NULL");
    
    SetMSWSockError(WSATYPE_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetTypeByNameW(
    LPWSTR lpServiceName,
    LPGUID lpServiceType)
{
    LogMessage("GetTypeByNameW() called");
    
    SetMSWSockError(WSATYPE_NOT_FOUND);
    return SOCKET_ERROR;
}

// === SERVICE FUNCTIONS ===

INT WSAAPI ex_GetServiceA(
    DWORD dwNameSpace,
    LPGUID lpGuid,
    LPSTR lpServiceName,
    DWORD dwProperties,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferSize,
    LPSERVICE_ASYNC_INFO lpServiceAsyncInfo)
{
    LogMessage("GetServiceA() called");
    
    SetMSWSockError(WSASERVICE_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetServiceW(
    DWORD dwNameSpace,
    LPGUID lpGuid,
    LPWSTR lpServiceName,
    DWORD dwProperties,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferSize,
    LPSERVICE_ASYNC_INFO lpServiceAsyncInfo)
{
    LogMessage("GetServiceW() called");
    
    SetMSWSockError(WSASERVICE_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_SetServiceA(
    DWORD dwNameSpace,
    DWORD dwOperation,
    DWORD dwFlags,
    LPSERVICE_INFOA lpServiceInfo,
    LPSERVICE_ASYNC_INFO lpServiceAsyncInfo,
    LPDWORD lpdwStatusFlags)
{
    LogMessage("SetServiceA() called");
    
    SetMSWSockError(0);
    return 0;
}

INT WSAAPI ex_SetServiceW(
    DWORD dwNameSpace,
    DWORD dwOperation,
    DWORD dwFlags,
    LPSERVICE_INFOW lpServiceInfo,
    LPSERVICE_ASYNC_INFO lpServiceAsyncInfo,
    LPDWORD lpdwStatusFlags)
{
    LogMessage("SetServiceW() called");
    
    SetMSWSockError(0);
    return 0;
}

// === WSH (Windows Sockets Helper) TCP/IP FUNCTIONS ===

// IPv4 functions
INT WSAAPI ex_Tcpip4_WSHAddressToString(
    LPSOCKADDR Address,
    INT AddressLength,
    LPWSAPROTOCOL_INFOW ProtocolInfo,
    LPWSTR AddressString,
    LPDWORD AddressStringLength)
{
    LogMessage("Tcpip4_WSHAddressToString() called");
    
    if (AddressString && AddressStringLength && *AddressStringLength >= 16) {
        wcscpy_s(AddressString, *AddressStringLength, L"127.0.0.1");
        *AddressStringLength = 10;
        return 0;
    }
    
    SetMSWSockError(WSAEFAULT);
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHEnumProtocols(
    LPINT lpiProtocols,
    LPWSTR lpTransportKeyName,
    LPVOID lpProtocolBuffer,
    LPDWORD lpdwBufferLength)
{
    LogMessage("Tcpip4_WSHEnumProtocols() called");
    
    if (lpdwBufferLength) {
        *lpdwBufferLength = 0;
    }
    
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHGetBroadcastSockaddr(
    PVOID HelperDllSocketContext,
    PSOCKADDR Sockaddr,
    PINT SockaddrLength)
{
    LogMessage("Tcpip4_WSHGetBroadcastSockaddr() called");
    
    if (Sockaddr && SockaddrLength && *SockaddrLength >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in* addr = (struct sockaddr_in*)Sockaddr;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = htonl(INADDR_BROADCAST);
        addr->sin_port = 0;
        *SockaddrLength = sizeof(struct sockaddr_in);
        return 0;
    }
    
    SetMSWSockError(WSAEFAULT);
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHGetProviderGuid(
    LPWSTR ProviderName,
    LPGUID ProviderGuid)
{
    LogMessage("Tcpip4_WSHGetProviderGuid() called");
    
    if (ProviderGuid) {
        memset(ProviderGuid, 0, sizeof(GUID));
        return 0;
    }
    
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHGetSockaddrType(
    PSOCKADDR Sockaddr,
    DWORD SockaddrLength,
    PSOCKADDR_INFO SockaddrInfo)
{
    LogMessage("Tcpip4_WSHGetSockaddrType() called");
    
    if (SockaddrInfo) {
        SockaddrInfo->AddressInfo = SockaddrInfoNormal;
        SockaddrInfo->EndpointInfo = SockaddrEndpointRelevant;
        return 0;
    }
    
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHGetSocketInformation(
    PVOID HelperDllSocketContext,
    SOCKET SocketHandle,
    HANDLE TdiAddressObjectHandle,
    HANDLE TdiConnectionObjectHandle,
    INT Level,
    INT OptionName,
    PCHAR OptionValue,
    PINT OptionLength)
{
    LogMessage("Tcpip4_WSHGetSocketInformation(level=%d, opt=%d) called", 
               Level, OptionName);
    
    if (OptionValue && OptionLength && *OptionLength >= sizeof(int)) {
        *(int*)OptionValue = 0;
        *OptionLength = sizeof(int);
        return 0;
    }
    
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHGetWSAProtocolInfo(
    LPWSTR ProviderName,
    LPWSAPROTOCOL_INFOW* ProtocolInfo,
    LPDWORD ProtocolInfoEntries)
{
    LogMessage("Tcpip4_WSHGetWSAProtocolInfo() called");
    
    if (ProtocolInfoEntries) {
        *ProtocolInfoEntries = 0;
    }
    
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHGetWildcardSockaddr(
    PVOID HelperDllSocketContext,
    PSOCKADDR Sockaddr,
    PINT SockaddrLength)
{
    LogMessage("Tcpip4_WSHGetWildcardSockaddr() called");
    
    if (Sockaddr && SockaddrLength && *SockaddrLength >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in* addr = (struct sockaddr_in*)Sockaddr;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = htonl(INADDR_ANY);
        addr->sin_port = 0;
        *SockaddrLength = sizeof(struct sockaddr_in);
        return 0;
    }
    
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHGetWinsockMapping(
    PWINSOCK_MAPPING Mapping,
    DWORD MappingLength)
{
    LogMessage("Tcpip4_WSHGetWinsockMapping() called");
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHIoctl(
    PVOID HelperDllSocketContext,
    SOCKET SocketHandle,
    HANDLE TdiAddressObjectHandle,
    HANDLE TdiConnectionObjectHandle,
    DWORD IoControlCode,
    LPVOID InputBuffer,
    DWORD InputBufferLength,
    LPVOID OutputBuffer,
    DWORD OutputBufferLength,
    LPDWORD NumberOfBytesReturned,
    LPWSAOVERLAPPED Overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine,
    LPBOOL NeedsCompletion)
{
    LogMessage("Tcpip4_WSHIoctl(code=0x%lx) called", IoControlCode);
    
    if (NeedsCompletion) {
        *NeedsCompletion = FALSE;
    }
    
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHJoinLeaf(
    PVOID HelperDllSocketContext,
    SOCKET SocketHandle,
    HANDLE TdiAddressObjectHandle,
    HANDLE TdiConnectionObjectHandle,
    PVOID LeafHelperDllSocketContext,
    SOCKET LeafSocketHandle,
    PSOCKADDR Sockaddr,
    DWORD SockaddrLength,
    LPWSABUF CallerData,
    LPWSABUF CalleeData,
    LPQOS SocketQOS,
    LPQOS GroupQOS,
    DWORD Flags)
{
    LogMessage("Tcpip4_WSHJoinLeaf() called");
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHNotify(
    PVOID HelperDllSocketContext,
    SOCKET SocketHandle,
    HANDLE TdiAddressObjectHandle,
    HANDLE TdiConnectionObjectHandle,
    DWORD NotifyEvent)
{
    LogMessage("Tcpip4_WSHNotify(event=0x%lx) called", NotifyEvent);
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHOpenSocket(
    PINT AddressFamily,
    PINT SocketType,
    PINT Protocol,
    PUNICODE_STRING TransportDeviceName,
    PVOID HelperDllSocketContext,
    PDWORD NotificationEvents)
{
    LogMessage("Tcpip4_WSHOpenSocket(af=%d, type=%d, proto=%d) called",
               AddressFamily ? *AddressFamily : 0,
               SocketType ? *SocketType : 0,
               Protocol ? *Protocol : 0);
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHOpenSocket2(
    PINT AddressFamily,
    PINT SocketType,
    PINT Protocol,
    GROUP Group,
    DWORD Flags,
    PUNICODE_STRING TransportDeviceName,
    PVOID* HelperDllSocketContext,
    PDWORD NotificationEvents)
{
    LogMessage("Tcpip4_WSHOpenSocket2() called");
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHSetSocketInformation(
    PVOID HelperDllSocketContext,
    SOCKET SocketHandle,
    HANDLE TdiAddressObjectHandle,
    HANDLE TdiConnectionObjectHandle,
    INT Level,
    INT OptionName,
    PCHAR OptionValue,
    INT OptionLength)
{
    LogMessage("Tcpip4_WSHSetSocketInformation(level=%d, opt=%d) called",
               Level, OptionName);
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHStringToAddress(
    LPWSTR AddressString,
    DWORD AddressFamily,
    LPWSAPROTOCOL_INFOW ProtocolInfo,
    LPSOCKADDR Address,
    LPDWORD AddressLength)
{
    LogMessage("Tcpip4_WSHStringToAddress() called");
    
    if (Address && AddressLength && *AddressLength >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in* addr = (struct sockaddr_in*)Address;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr->sin_port = 0;
        *AddressLength = sizeof(struct sockaddr_in);
        return 0;
    }
    
    return SOCKET_ERROR;
}

// IPv6 functions - просто дублюємо IPv4 з мінімальними змінами
INT WSAAPI ex_Tcpip6_WSHAddressToString(
    LPSOCKADDR Address,
    INT AddressLength,
    LPWSAPROTOCOL_INFOW ProtocolInfo,
    LPWSTR AddressString,
    LPDWORD AddressStringLength)
{
    LogMessage("Tcpip6_WSHAddressToString() called");
    
    if (AddressString && AddressStringLength && *AddressStringLength >= 4) {
        wcscpy_s(AddressString, *AddressStringLength, L"::1");
        *AddressStringLength = 4;
        return 0;
    }
    
    return SOCKET_ERROR;
}

// Для всіх інших IPv6 функцій
INT WSAAPI ex_Tcpip6_WSHEnumProtocols(LPINT lpiProtocols, LPWSTR lpTransportKeyName, LPVOID lpProtocolBuffer, LPDWORD lpdwBufferLength) {
    return ex_Tcpip4_WSHEnumProtocols(lpiProtocols, lpTransportKeyName, lpProtocolBuffer, lpdwBufferLength);
}

INT WSAAPI ex_Tcpip6_WSHGetProviderGuid(LPWSTR ProviderName, LPGUID ProviderGuid) {
    return ex_Tcpip4_WSHGetProviderGuid(ProviderName, ProviderGuid);
}

INT WSAAPI ex_Tcpip6_WSHGetSockaddrType(PSOCKADDR Sockaddr, DWORD SockaddrLength, PSOCKADDR_INFO SockaddrInfo) {
    return ex_Tcpip4_WSHGetSockaddrType(Sockaddr, SockaddrLength, SockaddrInfo);
}

INT WSAAPI ex_Tcpip6_WSHGetSocketInformation(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, INT Level, INT OptionName, PCHAR OptionValue, PINT OptionLength) {
    return ex_Tcpip4_WSHGetSocketInformation(HelperDllSocketContext, SocketHandle, TdiAddressObjectHandle, TdiConnectionObjectHandle, Level, OptionName, OptionValue, OptionLength);
}

INT WSAAPI ex_Tcpip6_WSHGetWSAProtocolInfo(LPWSTR ProviderName, LPWSAPROTOCOL_INFOW* ProtocolInfo, LPDWORD ProtocolInfoEntries) {
    return ex_Tcpip4_WSHGetWSAProtocolInfo(ProviderName, ProtocolInfo, ProtocolInfoEntries);
}

INT WSAAPI ex_Tcpip6_WSHGetWildcardSockaddr(PVOID HelperDllSocketContext, PSOCKADDR Sockaddr, PINT SockaddrLength) {
    return ex_Tcpip4_WSHGetWildcardSockaddr(HelperDllSocketContext, Sockaddr, SockaddrLength);
}

INT WSAAPI ex_Tcpip6_WSHGetWinsockMapping(PWINSOCK_MAPPING Mapping, DWORD MappingLength) {
    return ex_Tcpip4_WSHGetWinsockMapping(Mapping, MappingLength);
}

INT WSAAPI ex_Tcpip6_WSHIoctl(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, DWORD IoControlCode, LPVOID InputBuffer, DWORD InputBufferLength, LPVOID OutputBuffer, DWORD OutputBufferLength, LPDWORD NumberOfBytesReturned, LPWSAOVERLAPPED Overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine, LPBOOL NeedsCompletion) {
    return ex_Tcpip4_WSHIoctl(HelperDllSocketContext, SocketHandle, TdiAddressObjectHandle, TdiConnectionObjectHandle, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, NumberOfBytesReturned, Overlapped, CompletionRoutine, NeedsCompletion);
}

INT WSAAPI ex_Tcpip6_WSHJoinLeaf(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, PVOID LeafHelperDllSocketContext, SOCKET LeafSocketHandle, PSOCKADDR Sockaddr, DWORD SockaddrLength, LPWSABUF CallerData, LPWSABUF CalleeData, LPQOS SocketQOS, LPQOS GroupQOS, DWORD Flags) {
    return ex_Tcpip4_WSHJoinLeaf(HelperDllSocketContext, SocketHandle, TdiAddressObjectHandle, TdiConnectionObjectHandle, LeafHelperDllSocketContext, LeafSocketHandle, Sockaddr, SockaddrLength, CallerData, CalleeData, SocketQOS, GroupQOS, Flags);
}

INT WSAAPI ex_Tcpip6_WSHNotify(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, DWORD NotifyEvent) {
    return ex_Tcpip4_WSHNotify(HelperDllSocketContext, SocketHandle, TdiAddressObjectHandle, TdiConnectionObjectHandle, NotifyEvent);
}

INT WSAAPI ex_Tcpip6_WSHOpenSocket(PINT AddressFamily, PINT SocketType, PINT Protocol, PUNICODE_STRING TransportDeviceName, PVOID HelperDllSocketContext, PDWORD NotificationEvents) {
    return ex_Tcpip4_WSHOpenSocket(AddressFamily, SocketType, Protocol, TransportDeviceName, HelperDllSocketContext, NotificationEvents);
}

INT WSAAPI ex_Tcpip6_WSHOpenSocket2(PINT AddressFamily, PINT SocketType, PINT Protocol, GROUP Group, DWORD Flags, PUNICODE_STRING TransportDeviceName, PVOID* HelperDllSocketContext, PDWORD NotificationEvents) {
    return ex_Tcpip4_WSHOpenSocket2(AddressFamily, SocketType, Protocol, Group, Flags, TransportDeviceName, HelperDllSocketContext, NotificationEvents);
}

INT WSAAPI ex_Tcpip6_WSHSetSocketInformation(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, INT Level, INT OptionName, PCHAR OptionValue, INT OptionLength) {
    return ex_Tcpip4_WSHSetSocketInformation(HelperDllSocketContext, SocketHandle, TdiAddressObjectHandle, TdiConnectionObjectHandle, Level, OptionName, OptionValue, OptionLength);
}

INT WSAAPI ex_Tcpip6_WSHStringToAddress(LPWSTR AddressString, DWORD AddressFamily, LPWSAPROTOCOL_INFOW ProtocolInfo, LPSOCKADDR Address, LPDWORD AddressLength) {
    return ex_Tcpip4_WSHStringToAddress(AddressString, AddressFamily, ProtocolInfo, Address, AddressLength);
}

// === MISC FUNCTIONS ===

INT WSAAPI ex_GetSocketErrorMessageW(
    INT ErrorCode,
    LPWSTR Buffer,
    INT BufferSize)
{
    LogMessage("GetSocketErrorMessageW(error=%d) called", ErrorCode);
    
    if (Buffer && BufferSize > 0) {
        swprintf_s(Buffer, BufferSize, L"Socket error %d", ErrorCode);
        return wcslen(Buffer);
    }
    
    return 0;
}

int WSAAPI ex_NPLoadNameSpaces(
    LPDWORD lpdwVersion,
    LPNS_ROUTINE lpnsrBuffer,
    LPDWORD lpdwBufferLength)
{
    LogMessage("NPLoadNameSpaces() called");
    
    if (lpdwBufferLength) {
        *lpdwBufferLength = 0;
    }
    
    return 0;
}

INT WSAAPI ex_NSPStartup(
    LPGUID lpProviderId,
    LPNSP_ROUTINE lpnspRoutines)
{
    LogMessage("NSPStartup() called");
    
    SetMSWSockError(0);
    return 0;
}

INT WSAAPI ex_WSPStartup(
    WORD wVersionRequested,
    LPWSPDATA lpWSPData,
    LPWSAPROTOCOL_INFOW lpProtocolInfo,
    WSPUPCALLTABLE UpcallTable,
    LPWSPPROC_TABLE lpProcTable)
{
    LogMessage("WSPStartup(version=%d.%d) called",
               HIBYTE(wVersionRequested), LOBYTE(wVersionRequested));
    
    if (lpWSPData) {
        lpWSPData->wVersion = MAKEWORD(2, 2);
        lpWSPData->wHighVersion = MAKEWORD(2, 2);
    }
    
    SetMSWSockError(0);
    return 0;
}

// === WSDP SERVICE FUNCTIONS ===

void WSAAPI ex_ProcessSocketNotifications(void)
{
    LogMessage("ProcessSocketNotifications() called");
}

DWORD WSAAPI ex_StartWsdpService(void)
{
    LogMessage("StartWsdpService() called");
    return ERROR_SERVICE_DISABLED;
}

BOOL WSAAPI ex_StopWsdpService(void)
{
    LogMessage("StopWsdpService() called");
    return TRUE;
}

// === CONFIGURATION MIGRATION ===

INT WSAAPI ex_MigrateWinsockConfiguration(
    DWORD dwFromVersion,
    DWORD dwToVersion,
    DWORD Reserved)
{
    LogMessage("MigrateWinsockConfiguration(from=%lu, to=%lu) called",
               dwFromVersion, dwToVersion);
    return 0;
}

INT WSAAPI ex_MigrateWinsockConfigurationEx(
    DWORD dwFromVersion,
    DWORD dwToVersion,
    LPWSTR lpszFromPath,
    LPWSTR lpszToPath,
    DWORD Reserved)
{
    LogMessage("MigrateWinsockConfigurationEx() called");
    return 0;
}

// === UNIX COMPATIBILITY FUNCTIONS ===

int WSAAPI ex_dn_expand(
    const unsigned char* msg,
    const unsigned char* eomorig,
    const unsigned char* comp_dn,
    char* exp_dn,
    int length)
{
    LogMessage("dn_expand() called");
    
    if (exp_dn && length > 0) {
        exp_dn[0] = '\0';
    }
    
    return -1;
}

struct netent* WSAAPI ex_getnetbyname(const char* name)
{
    LogMessage("getnetbyname('%s') called", name ? name : "NULL");
    return NULL;
}

unsigned long WSAAPI ex_inet_network(const char* cp)
{
    LogMessage("inet_network('%s') called", cp ? cp : "NULL");
    return INADDR_NONE;
}

int WSAAPI ex_rcmd(
    char** ahost,
    unsigned short rport,
    const char* locuser,
    const char* remuser,
    const char* cmd,
    int* fd2p)
{
    LogMessage("rcmd() called - BLOCKED");
    return -1;
}

int WSAAPI ex_rexec(
    char** ahost,
    int rport,
    const char* user,
    const char* passwd,
    const char* cmd,
    int* fd2p)
{
    LogMessage("rexec() called - BLOCKED");
    return -1;
}

int WSAAPI ex_rresvport(int* port)
{
    LogMessage("rresvport() called");
    return -1;
}

void WSAAPI ex_s_perror(const char* msg)
{
    LogMessage("s_perror('%s') called", msg ? msg : "NULL");
}

int WSAAPI ex_sethostname(const char* name, int namelen)
{
    LogMessage("sethostname('%.*s') called", namelen, name ? name : "NULL");
    return 0;
}

// === DLL ENTRY POINT ===

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            DisableThreadLibraryCalls(hModule);
            
            if (InterlockedIncrement(&g_InitCount) == 1) {
                g_tlsError = TlsAlloc();
                
                #if ENABLE_DEBUG_CONSOLE
                if (AllocConsole()) {
                    FILE* fDummy;
                    freopen_s(&fDummy, "CONOUT$", "w", stdout);
                    SetConsoleTitleA("MSWSOCK Stub Debug Console");
                    printf("=== MSWSOCK Stub v1.0 Loaded ===\n\n");
                }
                #endif
                
                #if ENABLE_FILE_LOGGING
                InitializeCriticalSection(&g_LogCS);
                char log_path[MAX_PATH];
                GetTempPathA(MAX_PATH, log_path);
                strcat_s(log_path, MAX_PATH, "mswsock_stub.log");
                fopen_s(&g_LogFile, log_path, "a");
                #endif
                
                LogMessage("=== MSWSOCK Stub v1.0 Initialized ===");
            }
            break;
        }
        
        case DLL_PROCESS_DETACH:
        {
            if (InterlockedDecrement(&g_InitCount) == 0) {
                LogMessage("=== MSWSOCK Stub v1.0 Unloading ===");
                
                if (g_tlsError != TLS_OUT_OF_INDEXES) {
                    TlsFree(g_tlsError);
                }
                
                #if ENABLE_FILE_LOGGING
                if (g_LogFile) {
                    fclose(g_LogFile);
                }
                DeleteCriticalSection(&g_LogCS);
                #endif
                
                #if ENABLE_DEBUG_CONSOLE
                FreeConsole();
                #endif
            }
            break;
        }
    }
    return TRUE;
}