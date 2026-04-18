// ============================================================================
// === EXMSW.DLL: MSWSOCK Implementation ===
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
#pragma comment(lib, "exws2.lib")

// ============================================================================
// Additional Definitions for SDK Compatibility
// ============================================================================
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

#define SockaddrInfoNormal SockaddrAddressInfoNormal
#define SockaddrEndpointRelevant SockaddrEndpointInfoNormal

typedef struct _WINSOCK_MAPPING { 
    DWORD Rows; 
    DWORD Columns; 
} WINSOCK_MAPPING, *PWINSOCK_MAPPING;

typedef struct _NS_ROUTINE { 
    DWORD dwFunctionCount; 
    LPVOID* lpfnFunctions; 
} NS_ROUTINE, *PNS_ROUTINE, *LPNS_ROUTINE;

// ============================================================================
// Debug Configuration
// ============================================================================
#define ENABLE_DEBUG_CONSOLE 0
#define ENABLE_FILE_LOGGING  0

// ============================================================================
// Global Variables
// ============================================================================
static volatile LONG g_InitCount = 0;
static DWORD g_tlsError = TLS_OUT_OF_INDEXES;

// ReactOS-style: Cache extension function pointers globally
// These are set on first successful retrieval and reused
static LPFN_ACCEPTEX g_pfnAcceptEx = NULL;
static LPFN_GETACCEPTEXSOCKADDRS g_pfnGetAcceptExSockaddrs = NULL;
static LPFN_TRANSMITFILE g_pfnTransmitFile = NULL;

// exws2.dll module handle for WSPStartup delegation
static HMODULE g_hexws2 = NULL;

// Function pointer types for exws2 functions
typedef int (WSAAPI *PFN_WSASTARTUP)(WORD, LPWSADATA);
typedef int (WSAAPI *PFN_WSACLEANUP)(void);

static PFN_WSASTARTUP pfn_WSAStartup = NULL;
static PFN_WSACLEANUP pfn_WSACleanup = NULL;

#if ENABLE_DEBUG_CONSOLE
static HANDLE g_hConsole = NULL;
#endif

#if ENABLE_FILE_LOGGING
static FILE* g_LogFile = NULL;
static CRITICAL_SECTION g_LogCS;
#endif

// ============================================================================
// Error Handling
// ============================================================================
static void SetMSWSockError(int error) {
    if (g_tlsError != TLS_OUT_OF_INDEXES) {
        TlsSetValue(g_tlsError, (LPVOID)(LONG_PTR)error);
    }
    WSASetLastError(error);
}

// ============================================================================
// Logging Functions
// ============================================================================
static void LogMessage(const char* format, ...) {
#if ENABLE_DEBUG_CONSOLE || ENABLE_FILE_LOGGING
    char buffer[2048];
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    int prefix_len = snprintf(buffer, sizeof(buffer), 
                              "[EXMSW][%02d:%02d:%02d.%03d] ",
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
    (void)format;
#endif
}

// ============================================================================
// exws2.dll Module Management (for WSPStartup)
// ============================================================================
static BOOL load_exws2_module(void) {
    if (g_hexws2 != NULL) {
        return TRUE;
    }
    
    LogMessage("Loading exws2.dll for WSPStartup...");
    g_hexws2 = LoadLibraryA("exws2.dll");
    
    if (g_hexws2 == NULL) {
        LogMessage("Failed to load exws2.dll (error: %lu)", GetLastError());
        return FALSE;
    }
    
    pfn_WSAStartup = (PFN_WSASTARTUP)GetProcAddress(g_hexws2, "WSAStartup");
    pfn_WSACleanup = (PFN_WSACLEANUP)GetProcAddress(g_hexws2, "WSACleanup");
    
    LogMessage("exws2.dll loaded: WSAStartup=%p, WSACleanup=%p", 
               pfn_WSAStartup, pfn_WSACleanup);
    
    return TRUE;
}

// ============================================================================
// Wrapper Functions for exws2 Import
// ============================================================================
int WSAAPI ex_wrapper_getsockopt(SOCKET s, int level, int optname, char* optval, int* optlen) {
    return getsockopt(s, level, optname, optval, optlen);
}

int WSAAPI ex_wrapper_recv(SOCKET s, char* buf, int len, int flags) {
    return recv(s, buf, len, flags);
}

int WSAAPI ex_wrapper_recvfrom(SOCKET s, char* buf, int len, int flags, 
                               struct sockaddr* from, int* fromlen) {
    return recvfrom(s, buf, len, flags, from, fromlen);
}

int WSAAPI ex_wrapper_setsockopt(SOCKET s, int level, int optname, 
                                 const char* optval, int optlen) {
    return setsockopt(s, level, optname, optval, optlen);
}

// ============================================================================
// Main MSWSOCK Extension Functions
// ReactOS-style: Query on each call but cache the result
// ============================================================================

/***********************************************************************
 *		AcceptEx
 *
 * ReactOS-style implementation with caching optimization.
 * Queries exws2 for the function pointer on first call using the
 * provided socket, then caches for future use.
 */
BOOL PASCAL FAR ex_AcceptEx(
    SOCKET sListenSocket,
    SOCKET sAcceptSocket,
    PVOID lpOutputBuffer,
    DWORD dwReceiveDataLength,
    DWORD dwLocalAddressLength,
    DWORD dwRemoteAddressLength,
    LPDWORD lpdwBytesReceived,
    LPOVERLAPPED lpOverlapped)
{
    LogMessage("AcceptEx(listen=%llu, accept=%llu)", 
               (ULONGLONG)sListenSocket, (ULONGLONG)sAcceptSocket);
    
    // If not cached yet, retrieve both AcceptEx and GetAcceptExSockaddrs
    if (g_pfnAcceptEx == NULL) {
        GUID AcceptExGUID = WSAID_ACCEPTEX;
        GUID GetAcceptExSockaddrsGUID = WSAID_GETACCEPTEXSOCKADDRS;
        DWORD cbBytesReturned;
        
        LogMessage("Retrieving AcceptEx function pointer from exws2...");
        
        // Get AcceptEx
        if (WSAIoctl(sListenSocket,
                     SIO_GET_EXTENSION_FUNCTION_POINTER,
                     &AcceptExGUID,
                     sizeof(AcceptExGUID),
                     &g_pfnAcceptEx,
                     sizeof(g_pfnAcceptEx),
                     &cbBytesReturned,
                     NULL,
                     NULL) == SOCKET_ERROR) {
            LogMessage("Failed to retrieve AcceptEx (error: %d)", WSAGetLastError());
            return FALSE;
        }
        
        // Get GetAcceptExSockaddrs (for GetAcceptExSockaddrs function)
        if (WSAIoctl(sListenSocket,
                     SIO_GET_EXTENSION_FUNCTION_POINTER,
                     &GetAcceptExSockaddrsGUID,
                     sizeof(GetAcceptExSockaddrsGUID),
                     &g_pfnGetAcceptExSockaddrs,
                     sizeof(g_pfnGetAcceptExSockaddrs),
                     &cbBytesReturned,
                     NULL,
                     NULL) == SOCKET_ERROR) {
            LogMessage("Failed to retrieve GetAcceptExSockaddrs (error: %d)", 
                       WSAGetLastError());
            g_pfnAcceptEx = NULL; // Reset on failure
            return FALSE;
        }
        
        LogMessage("Successfully cached: AcceptEx=%p, GetAcceptExSockaddrs=%p",
                   g_pfnAcceptEx, g_pfnGetAcceptExSockaddrs);
    }
    
    // Call cached function
    return g_pfnAcceptEx(sListenSocket,
                         sAcceptSocket,
                         lpOutputBuffer,
                         dwReceiveDataLength,
                         dwLocalAddressLength,
                         dwRemoteAddressLength,
                         lpdwBytesReceived,
                         lpOverlapped);
}

/***********************************************************************
 *		GetAcceptExSockaddrs
 *
 * Uses cached function pointer from AcceptEx.
 */
VOID PASCAL FAR ex_GetAcceptExSockaddrs(
    PVOID lpOutputBuffer,
    DWORD dwReceiveDataLength,
    DWORD dwLocalAddressLength,
    DWORD dwRemoteAddressLength,
    LPSOCKADDR* LocalSockaddr,
    LPINT LocalSockaddrLength,
    LPSOCKADDR* RemoteSockaddr,
    LPINT RemoteSockaddrLength)
{
    LogMessage("GetAcceptExSockaddrs");
    
    if (g_pfnGetAcceptExSockaddrs) {
        g_pfnGetAcceptExSockaddrs(lpOutputBuffer,
                                  dwReceiveDataLength,
                                  dwLocalAddressLength,
                                  dwRemoteAddressLength,
                                  LocalSockaddr,
                                  LocalSockaddrLength,
                                  RemoteSockaddr,
                                  RemoteSockaddrLength);
        return;
    }
    
    // Fallback: return generic localhost addresses
    LogMessage("GetAcceptExSockaddrs: No cached function, using fallback");
    
    static struct sockaddr_in generic_addr;
    memset(&generic_addr, 0, sizeof(generic_addr));
    generic_addr.sin_family = AF_INET;
    generic_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    generic_addr.sin_port = 0;
    
    if (LocalSockaddr && LocalSockaddrLength) {
        *LocalSockaddr = (LPSOCKADDR)&generic_addr;
        *LocalSockaddrLength = sizeof(generic_addr);
    }
    
    if (RemoteSockaddr && RemoteSockaddrLength) {
        *RemoteSockaddr = (LPSOCKADDR)&generic_addr;
        *RemoteSockaddrLength = sizeof(generic_addr);
    }
}

/***********************************************************************
 *		TransmitFile
 *
 * ReactOS-style: Query on each call with caching.
 */
BOOL PASCAL FAR ex_TransmitFile(
    SOCKET hSocket,
    HANDLE hFile,
    DWORD nNumberOfBytesToWrite,
    DWORD nNumberOfBytesPerSend,
    LPOVERLAPPED lpOverlapped,
    LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
    DWORD dwFlags)
{
    LogMessage("TransmitFile(socket=%llu, file=%p)", (ULONGLONG)hSocket, hFile);
    
    // If not cached, retrieve TransmitFile function pointer
    if (g_pfnTransmitFile == NULL) {
        GUID TransmitFileGUID = WSAID_TRANSMITFILE;
        DWORD cbBytesReturned;
        
        LogMessage("Retrieving TransmitFile function pointer from exws2...");
        
        if (WSAIoctl(hSocket,
                     SIO_GET_EXTENSION_FUNCTION_POINTER,
                     &TransmitFileGUID,
                     sizeof(TransmitFileGUID),
                     &g_pfnTransmitFile,
                     sizeof(g_pfnTransmitFile),
                     &cbBytesReturned,
                     NULL,
                     NULL) == SOCKET_ERROR) {
            LogMessage("Failed to retrieve TransmitFile (error: %d)", WSAGetLastError());
            return FALSE;
        }
        
        LogMessage("Successfully cached TransmitFile=%p", g_pfnTransmitFile);
    }
    
    // Call cached function
    return g_pfnTransmitFile(hSocket,
                             hFile,
                             nNumberOfBytesToWrite,
                             nNumberOfBytesPerSend,
                             lpOverlapped,
                             lpTransmitBuffers,
                             dwFlags);
}

/***********************************************************************
 *		WSARecvEx
 *
 * Deprecated function - not implemented.
 */
int WINAPI ex_WSARecvEx(SOCKET s, char* buf, int len, int* flags)
{
    LogMessage("WSARecvEx -> SOCKET_ERROR (stub)");
    return SOCKET_ERROR;
}

// ============================================================================
// Protocol Enumeration Functions - Delegate to exws2
// ============================================================================
INT WSAAPI ex_EnumProtocolsA(LPINT lpiProtocols, LPVOID lpProtocolBuffer, LPDWORD lpdwBufferLength) {
    LogMessage("EnumProtocolsA -> Delegating to WSAEnumProtocolsA");
    return WSAEnumProtocolsA(lpiProtocols, (LPWSAPROTOCOL_INFOA)lpProtocolBuffer, lpdwBufferLength);
}

INT WSAAPI ex_EnumProtocolsW(LPINT lpiProtocols, LPVOID lpProtocolBuffer, LPDWORD lpdwBufferLength) {
    LogMessage("EnumProtocolsW -> Delegating to WSAEnumProtocolsW");
    return WSAEnumProtocolsW(lpiProtocols, (LPWSAPROTOCOL_INFOW)lpProtocolBuffer, lpdwBufferLength);
}

// ============================================================================
// Name Service Functions (Deprecated - Stubs from ReactOS)
// ============================================================================
INT WSAAPI ex_GetAddressByNameA(DWORD dwNameSpace, LPGUID lpServiceType, LPSTR lpServiceName, 
                                LPINT lpiProtocols, DWORD dwResolution, 
                                LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, LPVOID lpCsaddrBuffer, 
                                LPDWORD lpdwBufferLength, LPSTR lpAliasBuffer, 
                                LPDWORD lpdwAliasBufferLength) {
    LogMessage("GetAddressByNameA -> SOCKET_ERROR (stub)");
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetAddressByNameW(DWORD dwNameSpace, LPGUID lpServiceType, LPWSTR lpServiceName, 
                                LPINT lpiProtocols, DWORD dwResolution, 
                                LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, LPVOID lpCsaddrBuffer, 
                                LPDWORD lpdwBufferLength, LPWSTR lpAliasBuffer, 
                                LPDWORD lpdwAliasBufferLength) {
    LogMessage("GetAddressByNameW -> SOCKET_ERROR (stub)");
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetNameByTypeA(LPGUID lpServiceType, LPSTR lpServiceName, DWORD dwNameLength) {
    LogMessage("GetNameByTypeA -> TRUE (stub)");
    return TRUE;
}

INT WSAAPI ex_GetNameByTypeW(LPGUID lpServiceType, LPWSTR lpServiceName, DWORD dwNameLength) {
    LogMessage("GetNameByTypeW -> TRUE (stub)");
    return TRUE;
}

INT WSAAPI ex_GetTypeByNameA(LPSTR lpServiceName, LPGUID lpServiceType) {
    LogMessage("GetTypeByNameA -> SOCKET_ERROR (stub)");
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetTypeByNameW(LPWSTR lpServiceName, LPGUID lpServiceType) {
    LogMessage("GetTypeByNameW -> SOCKET_ERROR (stub)");
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetServiceA(DWORD dwNameSpace, LPGUID lpGuid, LPSTR lpServiceName, 
                          DWORD dwProperties, LPVOID lpBuffer, LPDWORD lpdwBufferSize, 
                          LPSERVICE_ASYNC_INFO lpServiceAsyncInfo) {
    LogMessage("GetServiceA -> SOCKET_ERROR (stub)");
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetServiceW(DWORD dwNameSpace, LPGUID lpGuid, LPWSTR lpServiceName, 
                          DWORD dwProperties, LPVOID lpBuffer, LPDWORD lpdwBufferSize, 
                          LPSERVICE_ASYNC_INFO lpServiceAsyncInfo) {
    LogMessage("GetServiceW -> SOCKET_ERROR (stub)");
    return SOCKET_ERROR;
}

INT WSAAPI ex_SetServiceA(DWORD dwNameSpace, DWORD dwOperation, DWORD dwFlags, 
                          LPSERVICE_INFOA lpServiceInfo, 
                          LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, 
                          LPDWORD lpdwStatusFlags) {
    LogMessage("SetServiceA -> SOCKET_ERROR (deprecated stub)");
    return SOCKET_ERROR;
}

INT WSAAPI ex_SetServiceW(DWORD dwNameSpace, DWORD dwOperation, DWORD dwFlags, 
                          LPSERVICE_INFOW lpServiceInfo, 
                          LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, 
                          LPDWORD lpdwStatusFlags) {
    LogMessage("SetServiceW -> SOCKET_ERROR (deprecated stub)");
    return SOCKET_ERROR;
}

// ============================================================================
// WSH (Winsock Helper) Functions - IPv4
// Simplified implementations based on ReactOS stubs
// ============================================================================
INT WSAAPI ex_Tcpip4_WSHAddressToString(LPSOCKADDR Address, INT AddressLength, 
                                        LPWSAPROTOCOL_INFOW ProtocolInfo, 
                                        LPWSTR AddressString, LPDWORD AddressStringLength) {
    
    if (AddressString && AddressStringLength && *AddressStringLength >= 16) {
        wcscpy_s(AddressString, *AddressStringLength, L"127.0.0.1");
        *AddressStringLength = 10;
        return 0;
    }
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHEnumProtocols(LPINT lpiProtocols, LPWSTR lpTransportKeyName, 
                                     LPVOID lpProtocolBuffer, LPDWORD lpdwBufferLength) {
    if (lpdwBufferLength) *lpdwBufferLength = 0;
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHGetBroadcastSockaddr(PVOID HelperDllSocketContext, 
                                             PSOCKADDR Sockaddr, PINT SockaddrLength) {
    
    if (Sockaddr && SockaddrLength && *SockaddrLength >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in* addr = (struct sockaddr_in*)Sockaddr;
        memset(addr, 0, sizeof(*addr));
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = INADDR_BROADCAST;
        *SockaddrLength = sizeof(struct sockaddr_in);
        return 0;
    }
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHGetProviderGuid(LPWSTR ProviderName, LPGUID ProviderGuid) {
    if (ProviderGuid) {
        memset(ProviderGuid, 0, sizeof(GUID));
        return 0;
    }
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHGetSockaddrType(PSOCKADDR Sockaddr, DWORD SockaddrLength, 
                                       PSOCKADDR_INFO SockaddrInfo) {
    if (SockaddrInfo) {
        SockaddrInfo->AddressInfo = SockaddrInfoNormal;
        SockaddrInfo->EndpointInfo = SockaddrEndpointRelevant;
        return 0;
    }
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHGetSocketInformation(PVOID HelperDllSocketContext, SOCKET SocketHandle,
                                             HANDLE TdiAddressObjectHandle, 
                                             HANDLE TdiConnectionObjectHandle,
                                             INT Level, INT OptionName, 
                                             PCHAR OptionValue, PINT OptionLength) {
    
    if (OptionValue && OptionLength && *OptionLength >= sizeof(int)) {
        *(int*)OptionValue = 0;
        *OptionLength = sizeof(int);
        return 0;
    }
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHGetWSAProtocolInfo(LPWSTR ProviderName, 
                                          LPWSAPROTOCOL_INFOW* ProtocolInfo, 
                                          LPDWORD ProtocolInfoEntries) {
    if (ProtocolInfoEntries) *ProtocolInfoEntries = 0;
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHGetWildcardSockaddr(PVOID HelperDllSocketContext, 
                                           PSOCKADDR Sockaddr, PINT SockaddrLength) {
    
    if (Sockaddr && SockaddrLength && *SockaddrLength >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in* addr = (struct sockaddr_in*)Sockaddr;
        memset(addr, 0, sizeof(*addr));
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = INADDR_ANY;
        *SockaddrLength = sizeof(struct sockaddr_in);
        return 0;
    }
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHGetWinsockMapping(PWINSOCK_MAPPING Mapping, DWORD MappingLength) {
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHIoctl(PVOID HelperDllSocketContext, SOCKET SocketHandle,
                              HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle,
                              DWORD IoControlCode, LPVOID InputBuffer, DWORD InputBufferLength,
                              LPVOID OutputBuffer, DWORD OutputBufferLength, 
                              LPDWORD NumberOfBytesReturned, LPWSAOVERLAPPED Overlapped,
                              LPWSAOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine, 
                              LPBOOL NeedsCompletion) {
    
    if (NeedsCompletion) *NeedsCompletion = FALSE;
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHJoinLeaf(PVOID HelperDllSocketContext, SOCKET SocketHandle,
                                 HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle,
                                 PVOID LeafHelperDllSocketContext, SOCKET LeafSocketHandle,
                                 PSOCKADDR Sockaddr, DWORD SockaddrLength,
                                 LPWSABUF CallerData, LPWSABUF CalleeData,
                                 LPQOS SocketQOS, LPQOS GroupQOS, DWORD Flags) {
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHNotify(PVOID HelperDllSocketContext, SOCKET SocketHandle,
                               HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle,
                               DWORD NotifyEvent) {
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHOpenSocket(PINT AddressFamily, PINT SocketType, PINT Protocol,
                                   PUNICODE_STRING TransportDeviceName, 
                                   PVOID* HelperDllSocketContext, PDWORD NotificationEvents) {
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHOpenSocket2(PINT AddressFamily, PINT SocketType, PINT Protocol,
                                    GROUP Group, DWORD Flags, PUNICODE_STRING TransportDeviceName,
                                    PVOID* HelperDllSocketContext, PDWORD NotificationEvents) {
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHSetSocketInformation(PVOID HelperDllSocketContext, SOCKET SocketHandle,
                                             HANDLE TdiAddressObjectHandle, 
                                             HANDLE TdiConnectionObjectHandle,
                                             INT Level, INT OptionName, 
                                             PCHAR OptionValue, INT OptionLength) {
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHStringToAddress(LPWSTR AddressString, DWORD AddressFamily,
                                       LPWSAPROTOCOL_INFOW ProtocolInfo,
                                       LPSOCKADDR Address, LPDWORD AddressLength) {
    
    if (Address && AddressLength && *AddressLength >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in* addr = (struct sockaddr_in*)Address;
        memset(addr, 0, sizeof(*addr));
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        *AddressLength = sizeof(struct sockaddr_in);
        return 0;
    }
    return SOCKET_ERROR;
}

// ============================================================================
// WSH Functions - IPv6 (delegate to IPv4)
// ============================================================================
INT WSAAPI ex_Tcpip6_WSHAddressToString(LPSOCKADDR A, INT AL, LPWSAPROTOCOL_INFOW PI, 
                                       LPWSTR AS, LPDWORD ASL) {
    if (AS && ASL && *ASL >= 4) {
        wcscpy_s(AS, *ASL, L"::1");
        *ASL = 4;
        return 0;
    }
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip6_WSHEnumProtocols(LPINT l, LPWSTR n, LPVOID b, LPDWORD bl) {
    return ex_Tcpip4_WSHEnumProtocols(l, n, b, bl);
}

INT WSAAPI ex_Tcpip6_WSHGetProviderGuid(LPWSTR n, LPGUID g) {
    return ex_Tcpip4_WSHGetProviderGuid(n, g);
}

INT WSAAPI ex_Tcpip6_WSHGetSockaddrType(PSOCKADDR s, DWORD sl, PSOCKADDR_INFO si) {
    return ex_Tcpip4_WSHGetSockaddrType(s, sl, si);
}

INT WSAAPI ex_Tcpip6_WSHGetSocketInformation(PVOID h, SOCKET s, HANDLE ta, HANDLE tc, 
                                             INT l, INT o, PCHAR ov, PINT ol) {
    return ex_Tcpip4_WSHGetSocketInformation(h, s, ta, tc, l, o, ov, ol);
}

INT WSAAPI ex_Tcpip6_WSHGetWSAProtocolInfo(LPWSTR n, LPWSAPROTOCOL_INFOW* i, LPDWORD e) {
    return ex_Tcpip4_WSHGetWSAProtocolInfo(n, i, e);
}

INT WSAAPI ex_Tcpip6_WSHGetWildcardSockaddr(PVOID h, PSOCKADDR s, PINT sl) {
    return ex_Tcpip4_WSHGetWildcardSockaddr(h, s, sl);
}

INT WSAAPI ex_Tcpip6_WSHGetWinsockMapping(PWINSOCK_MAPPING m, DWORD ml) {
    return ex_Tcpip4_WSHGetWinsockMapping(m, ml);
}

INT WSAAPI ex_Tcpip6_WSHIoctl(PVOID h, SOCKET s, HANDLE ta, HANDLE tc, DWORD c, 
                              LPVOID i, DWORD il, LPVOID o, DWORD ol, 
                              LPDWORD nr, LPWSAOVERLAPPED ov, 
                              LPWSAOVERLAPPED_COMPLETION_ROUTINE cr, LPBOOL nc) {
    return ex_Tcpip4_WSHIoctl(h, s, ta, tc, c, i, il, o, ol, nr, ov, cr, nc);
}

INT WSAAPI ex_Tcpip6_WSHJoinLeaf(PVOID h, SOCKET s, HANDLE ta, HANDLE tc, PVOID lh, 
                                 SOCKET ls, PSOCKADDR sa, DWORD sl, LPWSABUF c1, 
                                 LPWSABUF c2, LPQOS sq, LPQOS gq, DWORD f) {
    return ex_Tcpip4_WSHJoinLeaf(h, s, ta, tc, lh, ls, sa, sl, c1, c2, sq, gq, f);
}

INT WSAAPI ex_Tcpip6_WSHNotify(PVOID h, SOCKET s, HANDLE ta, HANDLE tc, DWORD e) {
    return ex_Tcpip4_WSHNotify(h, s, ta, tc, e);
}

INT WSAAPI ex_Tcpip6_WSHOpenSocket(PINT af, PINT st, PINT p, PUNICODE_STRING t, 
                                   PVOID* c, PDWORD n) {
    return ex_Tcpip4_WSHOpenSocket(af, st, p, t, c, n);
}

INT WSAAPI ex_Tcpip6_WSHOpenSocket2(PINT af, PINT st, PINT p, GROUP g, DWORD f, 
                                    PUNICODE_STRING t, PVOID* c, PDWORD n) {
    return ex_Tcpip4_WSHOpenSocket2(af, st, p, g, f, t, c, n);
}

INT WSAAPI ex_Tcpip6_WSHSetSocketInformation(PVOID h, SOCKET s, HANDLE ta, HANDLE tc, 
                                             INT l, INT o, PCHAR ov, INT ol) {
    return ex_Tcpip4_WSHSetSocketInformation(h, s, ta, tc, l, o, ov, ol);
}

INT WSAAPI ex_Tcpip6_WSHStringToAddress(LPWSTR as, DWORD af, LPWSAPROTOCOL_INFOW pi, 
                                       LPSOCKADDR a, LPDWORD al) {
    return ex_Tcpip4_WSHStringToAddress(as, af, pi, a, al);
}

// ============================================================================
// Winsock Service Provider Interface (WSP) Functions
// ============================================================================
INT WSAAPI ex_WSPStartup(WORD wVersionRequested, LPWSPDATA lpWSPData, 
                         LPWSAPROTOCOL_INFOW lpProtocolInfo, 
                         WSPUPCALLTABLE UpcallTable, LPWSPPROC_TABLE lpProcTable) {
    LogMessage("WSPStartup(version=%04X)", wVersionRequested);
    
    
    if (!load_exws2_module()) {
        LogMessage("WSPStartup: Failed to load exws2.dll");
        return WSASYSNOTREADY;
    }
    
    if (pfn_WSAStartup) {
        WSADATA wsaData;
        int result = pfn_WSAStartup(wVersionRequested, &wsaData);
        
        if (result == 0) {
            LogMessage("WSPStartup: WSAStartup succeeded (version %d.%d)",
                       LOBYTE(wsaData.wVersion), HIBYTE(wsaData.wVersion));
            
            if (lpWSPData) {
                lpWSPData->wVersion = wsaData.wVersion;
                lpWSPData->wHighVersion = wsaData.wHighVersion;
                
                if (wsaData.szDescription[0] != '\0') {
                    MultiByteToWideChar(CP_ACP, 0, wsaData.szDescription, -1,
                                       lpWSPData->szDescription,
                                       sizeof(lpWSPData->szDescription) / sizeof(WCHAR));
                } else {
                    wcscpy_s(lpWSPData->szDescription, 
                            sizeof(lpWSPData->szDescription) / sizeof(WCHAR),
                            L"EXMSW Winsock Provider");
                }
            }
            
            return NO_ERROR;
        } else {
            LogMessage("WSPStartup: WSAStartup failed (error=%d)", result);
            return result;
        }
    }
    
    LogMessage("WSPStartup: Using fallback initialization");
    
    if (lpWSPData) {
        lpWSPData->wVersion = MAKEWORD(2, 2);
        lpWSPData->wHighVersion = MAKEWORD(2, 2);
        wcscpy_s(lpWSPData->szDescription, 
                sizeof(lpWSPData->szDescription) / sizeof(WCHAR),
                L"EXMSW Winsock Provider (Fallback)");
    }
    
    return NO_ERROR;
}

// ============================================================================
// Miscellaneous Functions (ReactOS-style stubs)
// ============================================================================
INT WSAAPI ex_GetSocketErrorMessageW(INT ErrorCode, LPWSTR Buffer, INT BufferSize) {
    LogMessage("GetSocketErrorMessageW(%d)", ErrorCode);
    
    if (Buffer && BufferSize > 0) {
        swprintf_s(Buffer, BufferSize, L"Socket Error %d", ErrorCode);
        return (INT)wcslen(Buffer);
    }
    return 0;
}

int WSAAPI ex_NPLoadNameSpaces(LPDWORD lpdwVersion, LPNS_ROUTINE lpnsrBuffer, 
                               LPDWORD lpdwBufferLength) {
    LogMessage("NPLoadNameSpaces -> TRUE (stub)");
    if (lpdwVersion) *lpdwVersion = 1;
    return TRUE;
}

INT WSAAPI ex_NSPStartup(LPGUID lpProviderId, LPNSP_ROUTINE lpnspRoutines) {
    LogMessage("NSPStartup");
    return NO_ERROR;
}

void WSAAPI ex_ProcessSocketNotifications(void) {
    LogMessage("ProcessSocketNotifications");
}

VOID WSAAPI ex_StartWsdpService(void) {
    LogMessage("StartWsdpService -> (stub)");
}

VOID WSAAPI ex_StopWsdpService(void) {
    LogMessage("StopWsdpService -> (stub)");
}

INT WSAAPI ex_MigrateWinsockConfiguration(DWORD dwFromVersion, DWORD dwToVersion, 
                                         DWORD Reserved) {
    LogMessage("MigrateWinsockConfiguration -> SOCKET_ERROR (stub)");
    return SOCKET_ERROR;
}

INT WSAAPI ex_MigrateWinsockConfigurationEx(DWORD dwFromVersion, DWORD dwToVersion, 
                                            LPWSTR lpszFromPath, LPWSTR lpszToPath, 
                                            DWORD Reserved) {
    LogMessage("MigrateWinsockConfigurationEx -> SOCKET_ERROR (stub)");
    return SOCKET_ERROR;
}

// ============================================================================
// Unix Compatibility Functions (Blocked for security - ReactOS style)
// ============================================================================
int WSAAPI ex_dn_expand(unsigned char* msg, unsigned char* eom, 
                        unsigned char* comp, unsigned char* exp, int l) {
    LogMessage("dn_expand -> SOCKET_ERROR (not implemented)");
    return SOCKET_ERROR;
}

struct netent* WSAAPI ex_getnetbyname(const char* name) {
    LogMessage("getnetbyname('%s') -> NULL", name ? name : "NULL");
    return NULL;
}

unsigned long WSAAPI ex_inet_network(const char* cp) {
    LogMessage("inet_network('%s') -> INADDR_NONE", cp ? cp : "NULL");
    return INADDR_NONE;
}

SOCKET WINAPI ex_rcmd(char** a, USHORT r, char* lc, char* rm, 
                   char* c, int* f) {
    LogMessage("rcmd() -> INVALID_SOCKET (stub)");
    return INVALID_SOCKET;
}

SOCKET WINAPI ex_rexec(char** a, int r, char* u, char* p, 
                    char* c, int* f) {
    LogMessage("rexec() -> INVALID_SOCKET (stub)");
    return INVALID_SOCKET;
}

SOCKET WINAPI ex_rresvport(int* port) {
    LogMessage("rresvport() -> INVALID_SOCKET (stub)");
    return INVALID_SOCKET;
}

void WSAAPI ex_s_perror(const char* msg) {
    LogMessage("s_perror('%s')", msg ? msg : "NULL");
}

int WINAPI ex_sethostname(char* name, int namelen) {
    LogMessage("sethostname() -> SOCKET_ERROR (stub)");
    return SOCKET_ERROR;
}

// ============================================================================
// DLL Entry Point
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            if (InterlockedIncrement(&g_InitCount) == 1) {
                g_tlsError = TlsAlloc();
                
                #if ENABLE_DEBUG_CONSOLE
                if (AllocConsole()) {
                    g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
                    SetConsoleTitleA("EXMSW Debug Console");
                }
                #endif
                
                #if ENABLE_FILE_LOGGING
                InitializeCriticalSection(&g_LogCS);
                char path[MAX_PATH];
                GetTempPathA(MAX_PATH, path);
                strcat_s(path, MAX_PATH, "exmsw.log");
                fopen_s(&g_LogFile, path, "a");
                #endif
                
                LogMessage("=== EXMSW ===");
            }
            break;
            
        case DLL_PROCESS_DETACH:
            if (InterlockedDecrement(&g_InitCount) == 0) {
                LogMessage("=== EXMSW Unloading ===");
                
                if (g_tlsError != TLS_OUT_OF_INDEXES) {
                    TlsFree(g_tlsError);
                }
                
                if (g_hexws2 != NULL) {
                    FreeLibrary(g_hexws2);
                    g_hexws2 = NULL;
                }
                
                #if ENABLE_FILE_LOGGING
                if (g_LogFile) {
                    fclose(g_LogFile);
                }
                DeleteCriticalSection(&g_LogCS);
                #endif
                
                #if ENABLE_DEBUG_CONSOLE
                if (g_hConsole) {
                    FreeConsole();
                }
                #endif
            }
            break;
    }
    
    return TRUE;
}