// ============================================================================
// === WSOCK32 & MSWSOCK Stub v1.0.1 ===
// === Автор: EXLOUD ===
// === Призначення: Перенаправляє виклики ws2_32 на exws2.dll та ===
// === емулює функції mswsock.dll для офлайн-режиму. ===
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

#pragma comment(lib, "kernel32.lib")

// --- Додаткові визначення для сумісності з різними SDK ---
#ifndef _QOCINFO_DEFINED
#define _QOCINFO_DEFINED
typedef struct tagQOCINFO {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwInSpeed;
    DWORD dwOutSpeed;
} QOCINFO, *LPQOCINFO;
#endif

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

typedef struct _SOCKADDR_INFO {
    SOCKADDR_ADDRESS_INFO AddressInfo;
    SOCKADDR_ENDPOINT_INFO EndpointInfo;
} SOCKADDR_INFO, *PSOCKADDR_INFO;

#define SockaddrInfoNormal       SockaddrAddressInfoNormal
#define SockaddrEndpointRelevant SockaddrEndpointInfoNormal

typedef struct _WINSOCK_MAPPING {
    DWORD Rows;
    DWORD Columns;
} WINSOCK_MAPPING, *PWINSOCK_MAPPING;

typedef struct _NS_ROUTINE {
    DWORD        dwFunctionCount;
    LPVOID*      lpfnFunctions;
} NS_ROUTINE, *PNS_ROUTINE, *LPNS_ROUTINE;


// === НАЛАГОДЖУВАЛЬНІ КОНСТАНТИ ===
#define ENABLE_DEBUG_CONSOLE 0
#define ENABLE_FILE_LOGGING  0

// === ГЛОБАЛЬНІ ЗМІННІ ===
static volatile LONG g_InitCount = 0;
static DWORD g_tlsError = TLS_OUT_OF_INDEXES;

#if ENABLE_DEBUG_CONSOLE
static HANDLE g_hConsole = NULL;
#endif
#if ENABLE_FILE_LOGGING
static FILE* g_LogFile = NULL;
static CRITICAL_SECTION g_LogCS;
#endif

// === ДОПОМІЖНІ ФУНКЦІЇ ===
#undef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)

void SetMSWSockError(int error) {
    if (g_tlsError != TLS_OUT_OF_INDEXES) {
        TlsSetValue(g_tlsError, (LPVOID)(LONG_PTR)error);
    }
}

void LogMessage(const char* format, ...) {
#if ENABLE_DEBUG_CONSOLE || ENABLE_FILE_LOGGING
    char buffer[2048];
    SYSTEMTIME st;
    GetLocalTime(&st);
    int prefix_len = snprintf(buffer, sizeof(buffer), "[MSWSOCK][%02d:%02d:%02d.%03d] ",
                              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, format);
    vsnprintf(buffer + prefix_len, sizeof(buffer) - prefix_len, format, args);
    va_end(args);
    strcat_s(buffer, sizeof(buffer), "\n");

    #if ENABLE_DEBUG_CONSOLE
    if (g_hConsole) {
        DWORD written;
        WriteConsoleA(g_hConsole, buffer, (DWORD)strlen(buffer), &written, NULL);
    }
    #endif
    
    #if ENABLE_FILE_LOGGING
    if (g_LogFile) {
        EnterCriticalSection(&g_LogCS);
        fputs(buffer, g_LogFile);
        fflush(g_LogFile);
        LeaveCriticalSection(&g_LogCS);
    }
    #endif
#else
    UNREFERENCED_PARAMETER(format);
#endif
}

// === ОСНОВНІ ФУНКЦІЇ MSWSOCK ===

BOOL PASCAL FAR ex_AcceptEx(SOCKET sListenSocket, SOCKET sAcceptSocket, PVOID lpOutputBuffer, DWORD dwReceiveDataLength, DWORD dwLocalAddressLength, DWORD dwRemoteAddressLength, LPDWORD lpdwBytesReceived, LPOVERLAPPED lpOverlapped) {
    LogMessage("AcceptEx(listen=%llu, accept=%llu) -> SIMULATING PENDING", (UINT_PTR)sListenSocket, (UINT_PTR)sAcceptSocket);
    UNREFERENCED_PARAMETER(sListenSocket); UNREFERENCED_PARAMETER(sAcceptSocket); UNREFERENCED_PARAMETER(lpOutputBuffer); UNREFERENCED_PARAMETER(dwReceiveDataLength); UNREFERENCED_PARAMETER(dwLocalAddressLength); UNREFERENCED_PARAMETER(dwRemoteAddressLength);
    
    if (lpOverlapped) {
        lpOverlapped->Internal = (ULONG_PTR)STATUS_PENDING;
    }
    if (lpdwBytesReceived) {
        *lpdwBytesReceived = 0;
    }
    SetMSWSockError(WSA_IO_PENDING);
    return FALSE;
}

VOID PASCAL FAR ex_GetAcceptExSockaddrs(PVOID lpOutputBuffer, DWORD dwReceiveDataLength, DWORD dwLocalAddressLength, DWORD dwRemoteAddressLength, LPSOCKADDR* LocalSockaddr, LPINT LocalSockaddrLength, LPSOCKADDR* RemoteSockaddr, LPINT RemoteSockaddrLength) {
    LogMessage("GetAcceptExSockaddrs() called");
    UNREFERENCED_PARAMETER(lpOutputBuffer); UNREFERENCED_PARAMETER(dwReceiveDataLength); UNREFERENCED_PARAMETER(dwLocalAddressLength); UNREFERENCED_PARAMETER(dwRemoteAddressLength);
    
    static struct sockaddr_in generic_addr = { .sin_family = AF_INET, .sin_addr.s_addr = 0x0100007F, .sin_port = 0 }; // 127.0.0.1
    
    if (LocalSockaddr && LocalSockaddrLength) {
        *LocalSockaddr = (LPSOCKADDR)&generic_addr;
        *LocalSockaddrLength = sizeof(generic_addr);
    }
    if (RemoteSockaddr && RemoteSockaddrLength) {
        *RemoteSockaddr = (LPSOCKADDR)&generic_addr;
        *RemoteSockaddrLength = sizeof(generic_addr);
    }
}

BOOL PASCAL FAR ex_TransmitFile(SOCKET hSocket, HANDLE hFile, DWORD nNumberOfBytesToWrite, DWORD nNumberOfBytesPerSend, LPOVERLAPPED lpOverlapped, LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers, DWORD dwFlags) {
    LogMessage("TransmitFile(socket=%llu, file=%p) -> OFFLINE/BLOCKED", (UINT_PTR)hSocket, hFile);
    UNREFERENCED_PARAMETER(hSocket); UNREFERENCED_PARAMETER(hFile); UNREFERENCED_PARAMETER(nNumberOfBytesToWrite); UNREFERENCED_PARAMETER(nNumberOfBytesPerSend); UNREFERENCED_PARAMETER(lpTransmitBuffers); UNREFERENCED_PARAMETER(dwFlags);
    
    if (lpOverlapped) {
        lpOverlapped->Internal = (ULONG_PTR)WSAENETDOWN;
        if (lpOverlapped->hEvent) SetEvent(lpOverlapped->hEvent);
    }
    SetMSWSockError(WSAENETDOWN);
    return FALSE;
}

int PASCAL FAR ex_WSARecvEx(SOCKET s, char* buf, int len, int* flags) {
    LogMessage("WSARecvEx(socket=%llu, len=%d) -> OFFLINE/BLOCKED", (UINT_PTR)s, len);
    UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(buf); UNREFERENCED_PARAMETER(len); UNREFERENCED_PARAMETER(flags);
    SetMSWSockError(WSAENOTCONN);
    return SOCKET_ERROR;
}

// === ENUMERATION & NAME SERVICE ===

INT WSAAPI ex_EnumProtocolsA(LPINT lpiProtocols, LPVOID lpProtocolBuffer, LPDWORD lpdwBufferLength) {
    LogMessage("EnumProtocolsA() -> No protocols");
    UNREFERENCED_PARAMETER(lpiProtocols); UNREFERENCED_PARAMETER(lpProtocolBuffer);
    if (lpdwBufferLength) *lpdwBufferLength = 0;
    return 0;
}
INT WSAAPI ex_EnumProtocolsW(LPINT lpiProtocols, LPVOID lpProtocolBuffer, LPDWORD lpdwBufferLength) {
    LogMessage("EnumProtocolsW() -> No protocols");
    UNREFERENCED_PARAMETER(lpiProtocols); UNREFERENCED_PARAMETER(lpProtocolBuffer);
    if (lpdwBufferLength) *lpdwBufferLength = 0;
    return 0;
}

INT WSAAPI ex_GetAddressByNameA(DWORD dwNameSpace, LPGUID lpServiceType, LPSTR lpServiceName, LPINT lpiProtocols, DWORD dwResolution, LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, LPVOID lpCsaddrBuffer, LPDWORD lpdwBufferLength, LPSTR lpAliasBuffer, LPDWORD lpdwAliasBufferLength) {
    LogMessage("GetAddressByNameA('%s') -> NOT FOUND", lpServiceName ? lpServiceName : "NULL");
    UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(lpServiceType); UNREFERENCED_PARAMETER(lpiProtocols); UNREFERENCED_PARAMETER(dwResolution); UNREFERENCED_PARAMETER(lpServiceAsyncInfo); UNREFERENCED_PARAMETER(lpCsaddrBuffer); UNREFERENCED_PARAMETER(lpdwBufferLength); UNREFERENCED_PARAMETER(lpAliasBuffer); UNREFERENCED_PARAMETER(lpdwAliasBufferLength);
    SetMSWSockError(WSAHOST_NOT_FOUND); return SOCKET_ERROR;
}
INT WSAAPI ex_GetAddressByNameW(DWORD dwNameSpace, LPGUID lpServiceType, LPWSTR lpServiceName, LPINT lpiProtocols, DWORD dwResolution, LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, LPVOID lpCsaddrBuffer, LPDWORD lpdwBufferLength, LPWSTR lpAliasBuffer, LPDWORD lpdwAliasBufferLength) {
    LogMessage("GetAddressByNameW() -> NOT FOUND");
    UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(lpServiceType); UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(lpiProtocols); UNREFERENCED_PARAMETER(dwResolution); UNREFERENCED_PARAMETER(lpServiceAsyncInfo); UNREFERENCED_PARAMETER(lpCsaddrBuffer); UNREFERENCED_PARAMETER(lpdwBufferLength); UNREFERENCED_PARAMETER(lpAliasBuffer); UNREFERENCED_PARAMETER(lpdwAliasBufferLength);
    SetMSWSockError(WSAHOST_NOT_FOUND); return SOCKET_ERROR;
}
INT WSAAPI ex_GetNameByTypeA(LPGUID lpServiceType, LPSTR lpServiceName, DWORD dwNameLength) { UNREFERENCED_PARAMETER(lpServiceType); if (lpServiceName && dwNameLength > 0) lpServiceName[0] = '\0'; SetMSWSockError(WSATYPE_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_GetNameByTypeW(LPGUID lpServiceType, LPWSTR lpServiceName, DWORD dwNameLength) { UNREFERENCED_PARAMETER(lpServiceType); if (lpServiceName && dwNameLength > 0) lpServiceName[0] = L'\0'; SetMSWSockError(WSATYPE_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_GetTypeByNameA(LPSTR lpServiceName, LPGUID lpServiceType) { UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(lpServiceType); SetMSWSockError(WSATYPE_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_GetTypeByNameW(LPWSTR lpServiceName, LPGUID lpServiceType) { UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(lpServiceType); SetMSWSockError(WSATYPE_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_GetServiceA(DWORD dwNameSpace, LPGUID lpGuid, LPSTR lpServiceName, DWORD dwProperties, LPVOID lpBuffer, LPDWORD lpdwBufferSize, LPSERVICE_ASYNC_INFO lpServiceAsyncInfo) { UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(lpGuid); UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(dwProperties); UNREFERENCED_PARAMETER(lpBuffer); UNREFERENCED_PARAMETER(lpdwBufferSize); UNREFERENCED_PARAMETER(lpServiceAsyncInfo); SetMSWSockError(WSASERVICE_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_GetServiceW(DWORD dwNameSpace, LPGUID lpGuid, LPWSTR lpServiceName, DWORD dwProperties, LPVOID lpBuffer, LPDWORD lpdwBufferSize, LPSERVICE_ASYNC_INFO lpServiceAsyncInfo) { UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(lpGuid); UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(dwProperties); UNREFERENCED_PARAMETER(lpBuffer); UNREFERENCED_PARAMETER(lpdwBufferSize); UNREFERENCED_PARAMETER(lpServiceAsyncInfo); SetMSWSockError(WSASERVICE_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_SetServiceA(DWORD dwNameSpace, DWORD dwOperation, DWORD dwFlags, LPSERVICE_INFOA lpServiceInfo, LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, LPDWORD lpdwStatusFlags) { UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(dwOperation); UNREFERENCED_PARAMETER(dwFlags); UNREFERENCED_PARAMETER(lpServiceInfo); UNREFERENCED_PARAMETER(lpServiceAsyncInfo); UNREFERENCED_PARAMETER(lpdwStatusFlags); return NO_ERROR; }
INT WSAAPI ex_SetServiceW(DWORD dwNameSpace, DWORD dwOperation, DWORD dwFlags, LPSERVICE_INFOW lpServiceInfo, LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, LPDWORD lpdwStatusFlags) { UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(dwOperation); UNREFERENCED_PARAMETER(dwFlags); UNREFERENCED_PARAMETER(lpServiceInfo); UNREFERENCED_PARAMETER(lpServiceAsyncInfo); UNREFERENCED_PARAMETER(lpdwStatusFlags); return NO_ERROR; }

// === WSH (Windows Sockets Helper) FUNCTIONS ===
INT WSAAPI ex_Tcpip4_WSHAddressToString(LPSOCKADDR Address, INT AddressLength, LPWSAPROTOCOL_INFOW ProtocolInfo, LPWSTR AddressString, LPDWORD AddressStringLength) { LogMessage("Tcpip4_WSHAddressToString"); UNREFERENCED_PARAMETER(Address); UNREFERENCED_PARAMETER(AddressLength); UNREFERENCED_PARAMETER(ProtocolInfo); if (AddressString && AddressStringLength && *AddressStringLength >= 16) { wcscpy_s(AddressString, *AddressStringLength, L"127.0.0.1"); *AddressStringLength = 10; return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip4_WSHEnumProtocols(LPINT lpiProtocols, LPWSTR lpTransportKeyName, LPVOID lpProtocolBuffer, LPDWORD lpdwBufferLength) { LogMessage("Tcpip4_WSHEnumProtocols"); UNREFERENCED_PARAMETER(lpiProtocols); UNREFERENCED_PARAMETER(lpTransportKeyName); UNREFERENCED_PARAMETER(lpProtocolBuffer); if(lpdwBufferLength) *lpdwBufferLength = 0; return 0; }
INT WSAAPI ex_Tcpip4_WSHGetBroadcastSockaddr(PVOID HelperDllSocketContext, PSOCKADDR Sockaddr, PINT SockaddrLength) { LogMessage("Tcpip4_WSHGetBroadcastSockaddr"); UNREFERENCED_PARAMETER(HelperDllSocketContext); if (Sockaddr && SockaddrLength && *SockaddrLength >= sizeof(struct sockaddr_in)) { struct sockaddr_in* addr = (struct sockaddr_in*)Sockaddr; memset(addr, 0, sizeof(*addr)); addr->sin_family = AF_INET; addr->sin_addr.s_addr = 0xFFFFFFFF; *SockaddrLength = sizeof(struct sockaddr_in); return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip4_WSHGetProviderGuid(LPWSTR ProviderName, LPGUID ProviderGuid) { LogMessage("Tcpip4_WSHGetProviderGuid"); UNREFERENCED_PARAMETER(ProviderName); if (ProviderGuid) { memset(ProviderGuid, 0, sizeof(GUID)); return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip4_WSHGetSockaddrType(PSOCKADDR Sockaddr, DWORD SockaddrLength, PSOCKADDR_INFO SockaddrInfo) { LogMessage("Tcpip4_WSHGetSockaddrType"); UNREFERENCED_PARAMETER(Sockaddr); UNREFERENCED_PARAMETER(SockaddrLength); if (SockaddrInfo) { SockaddrInfo->AddressInfo = SockaddrInfoNormal; SockaddrInfo->EndpointInfo = SockaddrEndpointRelevant; return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip4_WSHGetSocketInformation(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, INT Level, INT OptionName, PCHAR OptionValue, PINT OptionLength) { LogMessage("Tcpip4_WSHGetSocketInformation"); UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(SocketHandle); UNREFERENCED_PARAMETER(TdiAddressObjectHandle); UNREFERENCED_PARAMETER(TdiConnectionObjectHandle); UNREFERENCED_PARAMETER(Level); UNREFERENCED_PARAMETER(OptionName); if (OptionValue && OptionLength && *OptionLength >= sizeof(int)) { *(int*)OptionValue = 0; *OptionLength = sizeof(int); return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip4_WSHGetWSAProtocolInfo(LPWSTR ProviderName, LPWSAPROTOCOL_INFOW* ProtocolInfo, LPDWORD ProtocolInfoEntries) { LogMessage("Tcpip4_WSHGetWSAProtocolInfo"); UNREFERENCED_PARAMETER(ProviderName); UNREFERENCED_PARAMETER(ProtocolInfo); if(ProtocolInfoEntries) *ProtocolInfoEntries = 0; return 0; }
INT WSAAPI ex_Tcpip4_WSHGetWildcardSockaddr(PVOID HelperDllSocketContext, PSOCKADDR Sockaddr, PINT SockaddrLength) { LogMessage("Tcpip4_WSHGetWildcardSockaddr"); UNREFERENCED_PARAMETER(HelperDllSocketContext); if (Sockaddr && SockaddrLength && *SockaddrLength >= sizeof(struct sockaddr_in)) { struct sockaddr_in* addr = (struct sockaddr_in*)Sockaddr; memset(addr, 0, sizeof(*addr)); addr->sin_family = AF_INET; addr->sin_addr.s_addr = 0; *SockaddrLength = sizeof(struct sockaddr_in); return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip4_WSHGetWinsockMapping(PWINSOCK_MAPPING Mapping, DWORD MappingLength) { LogMessage("Tcpip4_WSHGetWinsockMapping"); UNREFERENCED_PARAMETER(Mapping); UNREFERENCED_PARAMETER(MappingLength); return 0; }
INT WSAAPI ex_Tcpip4_WSHIoctl(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, DWORD IoControlCode, LPVOID InputBuffer, DWORD InputBufferLength, LPVOID OutputBuffer, DWORD OutputBufferLength, LPDWORD NumberOfBytesReturned, LPWSAOVERLAPPED Overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine, LPBOOL NeedsCompletion) { LogMessage("Tcpip4_WSHIoctl(code=0x%lx)", IoControlCode); UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(SocketHandle); UNREFERENCED_PARAMETER(TdiAddressObjectHandle); UNREFERENCED_PARAMETER(TdiConnectionObjectHandle); UNREFERENCED_PARAMETER(InputBuffer); UNREFERENCED_PARAMETER(InputBufferLength); UNREFERENCED_PARAMETER(OutputBuffer); UNREFERENCED_PARAMETER(OutputBufferLength); UNREFERENCED_PARAMETER(NumberOfBytesReturned); UNREFERENCED_PARAMETER(Overlapped); UNREFERENCED_PARAMETER(CompletionRoutine); if (NeedsCompletion) *NeedsCompletion = FALSE; return 0; }
INT WSAAPI ex_Tcpip4_WSHJoinLeaf(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, PVOID LeafHelperDllSocketContext, SOCKET LeafSocketHandle, PSOCKADDR Sockaddr, DWORD SockaddrLength, LPWSABUF CallerData, LPWSABUF CalleeData, LPQOS SocketQOS, LPQOS GroupQOS, DWORD Flags) { LogMessage("Tcpip4_WSHJoinLeaf"); UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(SocketHandle); UNREFERENCED_PARAMETER(TdiAddressObjectHandle); UNREFERENCED_PARAMETER(TdiConnectionObjectHandle); UNREFERENCED_PARAMETER(LeafHelperDllSocketContext); UNREFERENCED_PARAMETER(LeafSocketHandle); UNREFERENCED_PARAMETER(Sockaddr); UNREFERENCED_PARAMETER(SockaddrLength); UNREFERENCED_PARAMETER(CallerData); UNREFERENCED_PARAMETER(CalleeData); UNREFERENCED_PARAMETER(SocketQOS); UNREFERENCED_PARAMETER(GroupQOS); UNREFERENCED_PARAMETER(Flags); return 0; }
INT WSAAPI ex_Tcpip4_WSHNotify(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, DWORD NotifyEvent) { LogMessage("Tcpip4_WSHNotify(event=0x%lx)", NotifyEvent); UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(SocketHandle); UNREFERENCED_PARAMETER(TdiAddressObjectHandle); UNREFERENCED_PARAMETER(TdiConnectionObjectHandle); UNREFERENCED_PARAMETER(NotifyEvent); return 0; }
INT WSAAPI ex_Tcpip4_WSHOpenSocket(PINT AddressFamily, PINT SocketType, PINT Protocol, PUNICODE_STRING TransportDeviceName, PVOID* HelperDllSocketContext, PDWORD NotificationEvents) { LogMessage("Tcpip4_WSHOpenSocket"); UNREFERENCED_PARAMETER(AddressFamily); UNREFERENCED_PARAMETER(SocketType); UNREFERENCED_PARAMETER(Protocol); UNREFERENCED_PARAMETER(TransportDeviceName); UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(NotificationEvents); return 0; }
INT WSAAPI ex_Tcpip4_WSHOpenSocket2(PINT AddressFamily, PINT SocketType, PINT Protocol, GROUP Group, DWORD Flags, PUNICODE_STRING TransportDeviceName, PVOID* HelperDllSocketContext, PDWORD NotificationEvents) { LogMessage("Tcpip4_WSHOpenSocket2"); UNREFERENCED_PARAMETER(AddressFamily); UNREFERENCED_PARAMETER(SocketType); UNREFERENCED_PARAMETER(Protocol); UNREFERENCED_PARAMETER(Group); UNREFERENCED_PARAMETER(Flags); UNREFERENCED_PARAMETER(TransportDeviceName); UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(NotificationEvents); return 0; }
INT WSAAPI ex_Tcpip4_WSHSetSocketInformation(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, INT Level, INT OptionName, PCHAR OptionValue, INT OptionLength) { LogMessage("Tcpip4_WSHSetSocketInformation"); UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(SocketHandle); UNREFERENCED_PARAMETER(TdiAddressObjectHandle); UNREFERENCED_PARAMETER(TdiConnectionObjectHandle); UNREFERENCED_PARAMETER(Level); UNREFERENCED_PARAMETER(OptionName); UNREFERENCED_PARAMETER(OptionValue); UNREFERENCED_PARAMETER(OptionLength); return 0; }
INT WSAAPI ex_Tcpip4_WSHStringToAddress(LPWSTR AddressString, DWORD AddressFamily, LPWSAPROTOCOL_INFOW ProtocolInfo, LPSOCKADDR Address, LPDWORD AddressLength) { LogMessage("Tcpip4_WSHStringToAddress"); UNREFERENCED_PARAMETER(AddressString); UNREFERENCED_PARAMETER(AddressFamily); UNREFERENCED_PARAMETER(ProtocolInfo); if (Address && AddressLength && *AddressLength >= sizeof(struct sockaddr_in)) { struct sockaddr_in* addr = (struct sockaddr_in*)Address; memset(addr, 0, sizeof(*addr)); addr->sin_family = AF_INET; addr->sin_addr.s_addr = 0x0100007F; *AddressLength = sizeof(struct sockaddr_in); return 0; } return SOCKET_ERROR; }

INT WSAAPI ex_Tcpip6_WSHAddressToString(LPSOCKADDR Address, INT AddressLength, LPWSAPROTOCOL_INFOW ProtocolInfo, LPWSTR AddressString, LPDWORD AddressStringLength) { LogMessage("Tcpip6_WSHAddressToString"); UNREFERENCED_PARAMETER(Address); UNREFERENCED_PARAMETER(AddressLength); UNREFERENCED_PARAMETER(ProtocolInfo); if (AddressString && AddressStringLength && *AddressStringLength >= 4) { wcscpy_s(AddressString, *AddressStringLength, L"::1"); *AddressStringLength = 4; return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip6_WSHEnumProtocols(LPINT lpiProtocols, LPWSTR lpTransportKeyName, LPVOID lpProtocolBuffer, LPDWORD lpdwBufferLength) { return ex_Tcpip4_WSHEnumProtocols(lpiProtocols, lpTransportKeyName, lpProtocolBuffer, lpdwBufferLength); }
INT WSAAPI ex_Tcpip6_WSHGetProviderGuid(LPWSTR ProviderName, LPGUID ProviderGuid) { return ex_Tcpip4_WSHGetProviderGuid(ProviderName, ProviderGuid); }
INT WSAAPI ex_Tcpip6_WSHGetSockaddrType(PSOCKADDR Sockaddr, DWORD SockaddrLength, PSOCKADDR_INFO SockaddrInfo) { return ex_Tcpip4_WSHGetSockaddrType(Sockaddr, SockaddrLength, SockaddrInfo); }
INT WSAAPI ex_Tcpip6_WSHGetSocketInformation(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, INT Level, INT OptionName, PCHAR OptionValue, PINT OptionLength) { return ex_Tcpip4_WSHGetSocketInformation(HelperDllSocketContext, SocketHandle, TdiAddressObjectHandle, TdiConnectionObjectHandle, Level, OptionName, OptionValue, OptionLength); }
INT WSAAPI ex_Tcpip6_WSHGetWSAProtocolInfo(LPWSTR ProviderName, LPWSAPROTOCOL_INFOW* ProtocolInfo, LPDWORD ProtocolInfoEntries) { return ex_Tcpip4_WSHGetWSAProtocolInfo(ProviderName, ProtocolInfo, ProtocolInfoEntries); }
INT WSAAPI ex_Tcpip6_WSHGetWildcardSockaddr(PVOID HelperDllSocketContext, PSOCKADDR Sockaddr, PINT SockaddrLength) { return ex_Tcpip4_WSHGetWildcardSockaddr(HelperDllSocketContext, Sockaddr, SockaddrLength); }
INT WSAAPI ex_Tcpip6_WSHGetWinsockMapping(PWINSOCK_MAPPING Mapping, DWORD MappingLength) { return ex_Tcpip4_WSHGetWinsockMapping(Mapping, MappingLength); }
INT WSAAPI ex_Tcpip6_WSHIoctl(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, DWORD IoControlCode, LPVOID InputBuffer, DWORD InputBufferLength, LPVOID OutputBuffer, DWORD OutputBufferLength, LPDWORD NumberOfBytesReturned, LPWSAOVERLAPPED Overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine, LPBOOL NeedsCompletion) { return ex_Tcpip4_WSHIoctl(HelperDllSocketContext, SocketHandle, TdiAddressObjectHandle, TdiConnectionObjectHandle, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, NumberOfBytesReturned, Overlapped, CompletionRoutine, NeedsCompletion); }
INT WSAAPI ex_Tcpip6_WSHJoinLeaf(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, PVOID LeafHelperDllSocketContext, SOCKET LeafSocketHandle, PSOCKADDR Sockaddr, DWORD SockaddrLength, LPWSABUF CallerData, LPWSABUF CalleeData, LPQOS SocketQOS, LPQOS GroupQOS, DWORD Flags) { return ex_Tcpip4_WSHJoinLeaf(HelperDllSocketContext, SocketHandle, TdiAddressObjectHandle, TdiConnectionObjectHandle, LeafHelperDllSocketContext, LeafSocketHandle, Sockaddr, SockaddrLength, CallerData, CalleeData, SocketQOS, GroupQOS, Flags); }
INT WSAAPI ex_Tcpip6_WSHNotify(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, DWORD NotifyEvent) { return ex_Tcpip4_WSHNotify(HelperDllSocketContext, SocketHandle, TdiAddressObjectHandle, TdiConnectionObjectHandle, NotifyEvent); }
INT WSAAPI ex_Tcpip6_WSHOpenSocket(PINT AddressFamily, PINT SocketType, PINT Protocol, PUNICODE_STRING TransportDeviceName, PVOID* HelperDllSocketContext, PDWORD NotificationEvents) { return ex_Tcpip4_WSHOpenSocket(AddressFamily, SocketType, Protocol, TransportDeviceName, HelperDllSocketContext, NotificationEvents); }
INT WSAAPI ex_Tcpip6_WSHOpenSocket2(PINT AddressFamily, PINT SocketType, PINT Protocol, GROUP Group, DWORD Flags, PUNICODE_STRING TransportDeviceName, PVOID* HelperDllSocketContext, PDWORD NotificationEvents) { return ex_Tcpip4_WSHOpenSocket2(AddressFamily, SocketType, Protocol, Group, Flags, TransportDeviceName, HelperDllSocketContext, NotificationEvents); }
INT WSAAPI ex_Tcpip6_WSHSetSocketInformation(PVOID HelperDllSocketContext, SOCKET SocketHandle, HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle, INT Level, INT OptionName, PCHAR OptionValue, INT OptionLength) { return ex_Tcpip4_WSHSetSocketInformation(HelperDllSocketContext, SocketHandle, TdiAddressObjectHandle, TdiConnectionObjectHandle, Level, OptionName, OptionValue, OptionLength); }
INT WSAAPI ex_Tcpip6_WSHStringToAddress(LPWSTR AddressString, DWORD AddressFamily, LPWSAPROTOCOL_INFOW ProtocolInfo, LPSOCKADDR Address, LPDWORD AddressLength) { return ex_Tcpip4_WSHStringToAddress(AddressString, AddressFamily, ProtocolInfo, Address, AddressLength); }

// === MISC FUNCTIONS ===

INT WSAAPI ex_GetSocketErrorMessageW(INT ErrorCode, LPWSTR Buffer, INT BufferSize) { LogMessage("GetSocketErrorMessageW(%d)", ErrorCode); if (Buffer && BufferSize > 0) { swprintf_s(Buffer, BufferSize, L"Emulated Socket Error %d", ErrorCode); return (INT)wcslen(Buffer); } return 0; }
int WSAAPI ex_NPLoadNameSpaces(LPDWORD lpdwVersion, LPNS_ROUTINE lpnsrBuffer, LPDWORD lpdwBufferLength) { LogMessage("NPLoadNameSpaces"); UNREFERENCED_PARAMETER(lpdwVersion); UNREFERENCED_PARAMETER(lpnsrBuffer); if (lpdwBufferLength) *lpdwBufferLength = 0; return 0; }
INT WSAAPI ex_NSPStartup(LPGUID lpProviderId, LPNSP_ROUTINE lpnspRoutines) { LogMessage("NSPStartup"); UNREFERENCED_PARAMETER(lpProviderId); UNREFERENCED_PARAMETER(lpnspRoutines); return NO_ERROR; }
INT WSAAPI ex_WSPStartup(WORD wVersionRequested, LPWSPDATA lpWSPData, LPWSAPROTOCOL_INFOW lpProtocolInfo, WSPUPCALLTABLE UpcallTable, LPWSPPROC_TABLE lpProcTable) { LogMessage("WSPStartup"); UNREFERENCED_PARAMETER(lpProtocolInfo); UNREFERENCED_PARAMETER(UpcallTable); UNREFERENCED_PARAMETER(lpProcTable); if (lpWSPData) { lpWSPData->wVersion = wVersionRequested; lpWSPData->wHighVersion = MAKEWORD(2, 2); } return NO_ERROR; }
void WSAAPI ex_ProcessSocketNotifications(void) { LogMessage("ProcessSocketNotifications"); }
DWORD WSAAPI ex_StartWsdpService(void) { LogMessage("StartWsdpService"); return ERROR_SERVICE_DISABLED; }
BOOL WSAAPI ex_StopWsdpService(void) { LogMessage("StopWsdpService"); return TRUE; }
INT WSAAPI ex_MigrateWinsockConfiguration(DWORD dwFromVersion, DWORD dwToVersion, DWORD Reserved) { LogMessage("MigrateWinsockConfiguration"); UNREFERENCED_PARAMETER(dwFromVersion); UNREFERENCED_PARAMETER(dwToVersion); UNREFERENCED_PARAMETER(Reserved); return 0; }
INT WSAAPI ex_MigrateWinsockConfigurationEx(DWORD dwFromVersion, DWORD dwToVersion, LPWSTR lpszFromPath, LPWSTR lpszToPath, DWORD Reserved) { LogMessage("MigrateWinsockConfigurationEx"); UNREFERENCED_PARAMETER(dwFromVersion); UNREFERENCED_PARAMETER(dwToVersion); UNREFERENCED_PARAMETER(lpszFromPath); UNREFERENCED_PARAMETER(lpszToPath); UNREFERENCED_PARAMETER(Reserved); return 0; }

// === UNIX COMPATIBILITY ===
int WSAAPI ex_dn_expand(const unsigned char* msg, const unsigned char* eomorig, const unsigned char* comp_dn, char* exp_dn, int length) { LogMessage("dn_expand"); UNREFERENCED_PARAMETER(msg); UNREFERENCED_PARAMETER(eomorig); UNREFERENCED_PARAMETER(comp_dn); if (exp_dn && length > 0) exp_dn[0] = '\0'; return -1; }
struct netent* WSAAPI ex_getnetbyname(const char* name) { LogMessage("getnetbyname('%s')", name ? name : "NULL"); return NULL; }
unsigned long WSAAPI ex_inet_network(const char* cp) { LogMessage("inet_network('%s')", cp ? cp : "NULL"); UNREFERENCED_PARAMETER(cp); return INADDR_NONE; }
int WSAAPI ex_rcmd(char** ahost, unsigned short rport, const char* locuser, const char* remuser, const char* cmd, int* fd2p) { LogMessage("rcmd() - BLOCKED"); UNREFERENCED_PARAMETER(ahost); UNREFERENCED_PARAMETER(rport); UNREFERENCED_PARAMETER(locuser); UNREFERENCED_PARAMETER(remuser); UNREFERENCED_PARAMETER(cmd); UNREFERENCED_PARAMETER(fd2p); return -1; }
int WSAAPI ex_rexec(char** ahost, int rport, const char* user, const char* passwd, const char* cmd, int* fd2p) { LogMessage("rexec() - BLOCKED"); UNREFERENCED_PARAMETER(ahost); UNREFERENCED_PARAMETER(rport); UNREFERENCED_PARAMETER(user); UNREFERENCED_PARAMETER(passwd); UNREFERENCED_PARAMETER(cmd); UNREFERENCED_PARAMETER(fd2p); return -1; }
int WSAAPI ex_rresvport(int* port) { LogMessage("rresvport()"); UNREFERENCED_PARAMETER(port); return -1; }
void WSAAPI ex_s_perror(const char* msg) { LogMessage("s_perror('%s')", msg ? msg : "NULL"); UNREFERENCED_PARAMETER(msg); }
int WSAAPI ex_sethostname(const char* name, int namelen) { LogMessage("sethostname()"); UNREFERENCED_PARAMETER(name); UNREFERENCED_PARAMETER(namelen); return 0; }

// === DLL ENTRY POINT ===
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hModule); UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            if (InterlockedIncrement(&g_InitCount) == 1) {
                g_tlsError = TlsAlloc();
                #if ENABLE_DEBUG_CONSOLE
                if (AllocConsole()) {
                    g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
                    SetConsoleTitleA("MSWSOCK Stub Debug Console");
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
                if (g_LogFile) { fclose(g_LogFile); }
                DeleteCriticalSection(&g_LogCS);
                #endif
                #if ENABLE_DEBUG_CONSOLE
                if (g_hConsole) { FreeConsole(); }
                #endif
            }
            break;
        }
    }
    return TRUE;
}