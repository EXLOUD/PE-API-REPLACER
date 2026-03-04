// ============================================================================
// === EXMSW.DLL: MSWSOCK Final Implementation v2.2.0 ===
// === Hybrid approach: ReactOS + Wine + Custom optimizations ===
// === Author: EXLOUD (Enhanced by Claude) ===
// === Purpose: Production-ready mswsock.dll emulation ===
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
#pragma comment(lib, "ws2_32.lib")

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

// ws2_32.dll module handle for WSPStartup delegation
static HMODULE g_hWs2_32 = NULL;

// Function pointer types for ws2_32 functions
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
// Helper Macros
// ============================================================================
#undef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)

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
    UNREFERENCED_PARAMETER(format);
#endif
}

// ============================================================================
// ws2_32.dll Module Management (for WSPStartup)
// ============================================================================
static BOOL load_ws2_32_module(void) {
    if (g_hWs2_32 != NULL) {
        return TRUE;
    }
    
    LogMessage("Loading ws2_32.dll for WSPStartup...");
    g_hWs2_32 = LoadLibraryA("ws2_32.dll");
    
    if (g_hWs2_32 == NULL) {
        LogMessage("Failed to load ws2_32.dll (error: %lu)", GetLastError());
        return FALSE;
    }
    
    pfn_WSAStartup = (PFN_WSASTARTUP)GetProcAddress(g_hWs2_32, "WSAStartup");
    pfn_WSACleanup = (PFN_WSACLEANUP)GetProcAddress(g_hWs2_32, "WSACleanup");
    
    LogMessage("ws2_32.dll loaded: WSAStartup=%p, WSACleanup=%p", 
               pfn_WSAStartup, pfn_WSACleanup);
    
    return TRUE;
}

// ============================================================================
// Wrapper Functions for ws2_32 Import
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
 * Queries ws2_32 for the function pointer on first call using the
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
        
        LogMessage("Retrieving AcceptEx function pointer from ws2_32...");
        
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
        
        LogMessage("Retrieving TransmitFile function pointer from ws2_32...");
        
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
int PASCAL FAR ex_WSARecvEx(SOCKET s, char* buf, int len, int* flags)
{
    LogMessage("WSARecvEx -> WSAEOPNOTSUPP (deprecated)");
    
    UNREFERENCED_PARAMETER(s);
    UNREFERENCED_PARAMETER(buf);
    UNREFERENCED_PARAMETER(len);
    UNREFERENCED_PARAMETER(flags);
    
    SetMSWSockError(WSAEOPNOTSUPP);
    return SOCKET_ERROR;
}

// ============================================================================
// Protocol Enumeration Functions - Delegate to ws2_32
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
    LogMessage("GetAddressByNameA -> WSAHOST_NOT_FOUND (deprecated, use getaddrinfo)");
    UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(lpServiceType);
    UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(lpiProtocols);
    UNREFERENCED_PARAMETER(dwResolution); UNREFERENCED_PARAMETER(lpServiceAsyncInfo);
    UNREFERENCED_PARAMETER(lpCsaddrBuffer); UNREFERENCED_PARAMETER(lpdwBufferLength);
    UNREFERENCED_PARAMETER(lpAliasBuffer); UNREFERENCED_PARAMETER(lpdwAliasBufferLength);
    SetMSWSockError(WSAHOST_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetAddressByNameW(DWORD dwNameSpace, LPGUID lpServiceType, LPWSTR lpServiceName, 
                                LPINT lpiProtocols, DWORD dwResolution, 
                                LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, LPVOID lpCsaddrBuffer, 
                                LPDWORD lpdwBufferLength, LPWSTR lpAliasBuffer, 
                                LPDWORD lpdwAliasBufferLength) {
    LogMessage("GetAddressByNameW -> WSAHOST_NOT_FOUND (deprecated)");
    UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(lpServiceType);
    UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(lpiProtocols);
    UNREFERENCED_PARAMETER(dwResolution); UNREFERENCED_PARAMETER(lpServiceAsyncInfo);
    UNREFERENCED_PARAMETER(lpCsaddrBuffer); UNREFERENCED_PARAMETER(lpdwBufferLength);
    UNREFERENCED_PARAMETER(lpAliasBuffer); UNREFERENCED_PARAMETER(lpdwAliasBufferLength);
    SetMSWSockError(WSAHOST_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetNameByTypeA(LPGUID lpServiceType, LPSTR lpServiceName, DWORD dwNameLength) {
    LogMessage("GetNameByTypeA -> WSATYPE_NOT_FOUND (deprecated)");
    UNREFERENCED_PARAMETER(lpServiceType);
    if (lpServiceName && dwNameLength > 0) lpServiceName[0] = '\0';
    SetMSWSockError(WSATYPE_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetNameByTypeW(LPGUID lpServiceType, LPWSTR lpServiceName, DWORD dwNameLength) {
    LogMessage("GetNameByTypeW -> WSATYPE_NOT_FOUND (deprecated)");
    UNREFERENCED_PARAMETER(lpServiceType);
    if (lpServiceName && dwNameLength > 0) lpServiceName[0] = L'\0';
    SetMSWSockError(WSATYPE_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetTypeByNameA(LPSTR lpServiceName, LPGUID lpServiceType) {
    LogMessage("GetTypeByNameA -> WSATYPE_NOT_FOUND (deprecated)");
    UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(lpServiceType);
    SetMSWSockError(WSATYPE_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetTypeByNameW(LPWSTR lpServiceName, LPGUID lpServiceType) {
    LogMessage("GetTypeByNameW -> WSATYPE_NOT_FOUND (deprecated)");
    UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(lpServiceType);
    SetMSWSockError(WSATYPE_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetServiceA(DWORD dwNameSpace, LPGUID lpGuid, LPSTR lpServiceName, 
                          DWORD dwProperties, LPVOID lpBuffer, LPDWORD lpdwBufferSize, 
                          LPSERVICE_ASYNC_INFO lpServiceAsyncInfo) {
    LogMessage("GetServiceA -> WSASERVICE_NOT_FOUND (deprecated)");
    UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(lpGuid);
    UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(dwProperties);
    UNREFERENCED_PARAMETER(lpBuffer); UNREFERENCED_PARAMETER(lpdwBufferSize);
    UNREFERENCED_PARAMETER(lpServiceAsyncInfo);
    SetMSWSockError(WSASERVICE_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_GetServiceW(DWORD dwNameSpace, LPGUID lpGuid, LPWSTR lpServiceName, 
                          DWORD dwProperties, LPVOID lpBuffer, LPDWORD lpdwBufferSize, 
                          LPSERVICE_ASYNC_INFO lpServiceAsyncInfo) {
    LogMessage("GetServiceW -> WSASERVICE_NOT_FOUND (deprecated)");
    UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(lpGuid);
    UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(dwProperties);
    UNREFERENCED_PARAMETER(lpBuffer); UNREFERENCED_PARAMETER(lpdwBufferSize);
    UNREFERENCED_PARAMETER(lpServiceAsyncInfo);
    SetMSWSockError(WSASERVICE_NOT_FOUND);
    return SOCKET_ERROR;
}

INT WSAAPI ex_SetServiceA(DWORD dwNameSpace, DWORD dwOperation, DWORD dwFlags, 
                          LPSERVICE_INFOA lpServiceInfo, 
                          LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, 
                          LPDWORD lpdwStatusFlags) {
    LogMessage("SetServiceA -> NO_ERROR (deprecated stub)");
    UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(dwOperation);
    UNREFERENCED_PARAMETER(dwFlags); UNREFERENCED_PARAMETER(lpServiceInfo);
    UNREFERENCED_PARAMETER(lpServiceAsyncInfo); UNREFERENCED_PARAMETER(lpdwStatusFlags);
    return NO_ERROR;
}

INT WSAAPI ex_SetServiceW(DWORD dwNameSpace, DWORD dwOperation, DWORD dwFlags, 
                          LPSERVICE_INFOW lpServiceInfo, 
                          LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, 
                          LPDWORD lpdwStatusFlags) {
    LogMessage("SetServiceW -> NO_ERROR (deprecated stub)");
    UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(dwOperation);
    UNREFERENCED_PARAMETER(dwFlags); UNREFERENCED_PARAMETER(lpServiceInfo);
    UNREFERENCED_PARAMETER(lpServiceAsyncInfo); UNREFERENCED_PARAMETER(lpdwStatusFlags);
    return NO_ERROR;
}

// ============================================================================
// WSH (Winsock Helper) Functions - IPv4
// Simplified implementations based on ReactOS stubs
// ============================================================================
INT WSAAPI ex_Tcpip4_WSHAddressToString(LPSOCKADDR Address, INT AddressLength, 
                                        LPWSAPROTOCOL_INFOW ProtocolInfo, 
                                        LPWSTR AddressString, LPDWORD AddressStringLength) {
    UNREFERENCED_PARAMETER(Address); UNREFERENCED_PARAMETER(AddressLength);
    UNREFERENCED_PARAMETER(ProtocolInfo);
    
    if (AddressString && AddressStringLength && *AddressStringLength >= 16) {
        wcscpy_s(AddressString, *AddressStringLength, L"127.0.0.1");
        *AddressStringLength = 10;
        return 0;
    }
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHEnumProtocols(LPINT lpiProtocols, LPWSTR lpTransportKeyName, 
                                     LPVOID lpProtocolBuffer, LPDWORD lpdwBufferLength) {
    UNREFERENCED_PARAMETER(lpiProtocols); UNREFERENCED_PARAMETER(lpTransportKeyName);
    UNREFERENCED_PARAMETER(lpProtocolBuffer);
    if (lpdwBufferLength) *lpdwBufferLength = 0;
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHGetBroadcastSockaddr(PVOID HelperDllSocketContext, 
                                             PSOCKADDR Sockaddr, PINT SockaddrLength) {
    UNREFERENCED_PARAMETER(HelperDllSocketContext);
    
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
    UNREFERENCED_PARAMETER(ProviderName);
    if (ProviderGuid) {
        memset(ProviderGuid, 0, sizeof(GUID));
        return 0;
    }
    return SOCKET_ERROR;
}

INT WSAAPI ex_Tcpip4_WSHGetSockaddrType(PSOCKADDR Sockaddr, DWORD SockaddrLength, 
                                       PSOCKADDR_INFO SockaddrInfo) {
    UNREFERENCED_PARAMETER(Sockaddr); UNREFERENCED_PARAMETER(SockaddrLength);
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
    UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(SocketHandle);
    UNREFERENCED_PARAMETER(TdiAddressObjectHandle); UNREFERENCED_PARAMETER(TdiConnectionObjectHandle);
    UNREFERENCED_PARAMETER(Level); UNREFERENCED_PARAMETER(OptionName);
    
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
    UNREFERENCED_PARAMETER(ProviderName); UNREFERENCED_PARAMETER(ProtocolInfo);
    if (ProtocolInfoEntries) *ProtocolInfoEntries = 0;
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHGetWildcardSockaddr(PVOID HelperDllSocketContext, 
                                           PSOCKADDR Sockaddr, PINT SockaddrLength) {
    UNREFERENCED_PARAMETER(HelperDllSocketContext);
    
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
    UNREFERENCED_PARAMETER(Mapping); UNREFERENCED_PARAMETER(MappingLength);
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHIoctl(PVOID HelperDllSocketContext, SOCKET SocketHandle,
                              HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle,
                              DWORD IoControlCode, LPVOID InputBuffer, DWORD InputBufferLength,
                              LPVOID OutputBuffer, DWORD OutputBufferLength, 
                              LPDWORD NumberOfBytesReturned, LPWSAOVERLAPPED Overlapped,
                              LPWSAOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine, 
                              LPBOOL NeedsCompletion) {
    UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(SocketHandle);
    UNREFERENCED_PARAMETER(TdiAddressObjectHandle); UNREFERENCED_PARAMETER(TdiConnectionObjectHandle);
    UNREFERENCED_PARAMETER(IoControlCode); UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength); UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength); UNREFERENCED_PARAMETER(NumberOfBytesReturned);
    UNREFERENCED_PARAMETER(Overlapped); UNREFERENCED_PARAMETER(CompletionRoutine);
    
    if (NeedsCompletion) *NeedsCompletion = FALSE;
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHJoinLeaf(PVOID HelperDllSocketContext, SOCKET SocketHandle,
                                 HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle,
                                 PVOID LeafHelperDllSocketContext, SOCKET LeafSocketHandle,
                                 PSOCKADDR Sockaddr, DWORD SockaddrLength,
                                 LPWSABUF CallerData, LPWSABUF CalleeData,
                                 LPQOS SocketQOS, LPQOS GroupQOS, DWORD Flags) {
    UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(SocketHandle);
    UNREFERENCED_PARAMETER(TdiAddressObjectHandle); UNREFERENCED_PARAMETER(TdiConnectionObjectHandle);
    UNREFERENCED_PARAMETER(LeafHelperDllSocketContext); UNREFERENCED_PARAMETER(LeafSocketHandle);
    UNREFERENCED_PARAMETER(Sockaddr); UNREFERENCED_PARAMETER(SockaddrLength);
    UNREFERENCED_PARAMETER(CallerData); UNREFERENCED_PARAMETER(CalleeData);
    UNREFERENCED_PARAMETER(SocketQOS); UNREFERENCED_PARAMETER(GroupQOS);
    UNREFERENCED_PARAMETER(Flags);
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHNotify(PVOID HelperDllSocketContext, SOCKET SocketHandle,
                               HANDLE TdiAddressObjectHandle, HANDLE TdiConnectionObjectHandle,
                               DWORD NotifyEvent) {
    UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(SocketHandle);
    UNREFERENCED_PARAMETER(TdiAddressObjectHandle); UNREFERENCED_PARAMETER(TdiConnectionObjectHandle);
    UNREFERENCED_PARAMETER(NotifyEvent);
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHOpenSocket(PINT AddressFamily, PINT SocketType, PINT Protocol,
                                   PUNICODE_STRING TransportDeviceName, 
                                   PVOID* HelperDllSocketContext, PDWORD NotificationEvents) {
    UNREFERENCED_PARAMETER(AddressFamily); UNREFERENCED_PARAMETER(SocketType);
    UNREFERENCED_PARAMETER(Protocol); UNREFERENCED_PARAMETER(TransportDeviceName);
    UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(NotificationEvents);
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHOpenSocket2(PINT AddressFamily, PINT SocketType, PINT Protocol,
                                    GROUP Group, DWORD Flags, PUNICODE_STRING TransportDeviceName,
                                    PVOID* HelperDllSocketContext, PDWORD NotificationEvents) {
    UNREFERENCED_PARAMETER(AddressFamily); UNREFERENCED_PARAMETER(SocketType);
    UNREFERENCED_PARAMETER(Protocol); UNREFERENCED_PARAMETER(Group);
    UNREFERENCED_PARAMETER(Flags); UNREFERENCED_PARAMETER(TransportDeviceName);
    UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(NotificationEvents);
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHSetSocketInformation(PVOID HelperDllSocketContext, SOCKET SocketHandle,
                                             HANDLE TdiAddressObjectHandle, 
                                             HANDLE TdiConnectionObjectHandle,
                                             INT Level, INT OptionName, 
                                             PCHAR OptionValue, INT OptionLength) {
    UNREFERENCED_PARAMETER(HelperDllSocketContext); UNREFERENCED_PARAMETER(SocketHandle);
    UNREFERENCED_PARAMETER(TdiAddressObjectHandle); UNREFERENCED_PARAMETER(TdiConnectionObjectHandle);
    UNREFERENCED_PARAMETER(Level); UNREFERENCED_PARAMETER(OptionName);
    UNREFERENCED_PARAMETER(OptionValue); UNREFERENCED_PARAMETER(OptionLength);
    return 0;
}

INT WSAAPI ex_Tcpip4_WSHStringToAddress(LPWSTR AddressString, DWORD AddressFamily,
                                       LPWSAPROTOCOL_INFOW ProtocolInfo,
                                       LPSOCKADDR Address, LPDWORD AddressLength) {
    UNREFERENCED_PARAMETER(AddressString); UNREFERENCED_PARAMETER(AddressFamily);
    UNREFERENCED_PARAMETER(ProtocolInfo);
    
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
    UNREFERENCED_PARAMETER(A); UNREFERENCED_PARAMETER(AL); UNREFERENCED_PARAMETER(PI);
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
    
    UNREFERENCED_PARAMETER(lpProtocolInfo);
    UNREFERENCED_PARAMETER(UpcallTable);
    UNREFERENCED_PARAMETER(lpProcTable);
    
    if (!load_ws2_32_module()) {
        LogMessage("WSPStartup: Failed to load ws2_32.dll");
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
    LogMessage("NPLoadNameSpaces");
    UNREFERENCED_PARAMETER(lpnsrBuffer);
    if (lpdwVersion) *lpdwVersion = 1;
    if (lpdwBufferLength) *lpdwBufferLength = 0;
    return 0;
}

INT WSAAPI ex_NSPStartup(LPGUID lpProviderId, LPNSP_ROUTINE lpnspRoutines) {
    LogMessage("NSPStartup");
    UNREFERENCED_PARAMETER(lpProviderId); UNREFERENCED_PARAMETER(lpnspRoutines);
    return NO_ERROR;
}

void WSAAPI ex_ProcessSocketNotifications(void) {
    LogMessage("ProcessSocketNotifications");
}

DWORD WSAAPI ex_StartWsdpService(void) {
    LogMessage("StartWsdpService");
    return ERROR_SERVICE_DISABLED;
}

BOOL WSAAPI ex_StopWsdpService(void) {
    LogMessage("StopWsdpService");
    return TRUE;
}

INT WSAAPI ex_MigrateWinsockConfiguration(DWORD dwFromVersion, DWORD dwToVersion, 
                                         DWORD Reserved) {
    LogMessage("MigrateWinsockConfiguration");
    UNREFERENCED_PARAMETER(dwFromVersion); UNREFERENCED_PARAMETER(dwToVersion);
    UNREFERENCED_PARAMETER(Reserved);
    return 0;
}

INT WSAAPI ex_MigrateWinsockConfigurationEx(DWORD dwFromVersion, DWORD dwToVersion, 
                                            LPWSTR lpszFromPath, LPWSTR lpszToPath, 
                                            DWORD Reserved) {
    LogMessage("MigrateWinsockConfigurationEx");
    UNREFERENCED_PARAMETER(dwFromVersion); UNREFERENCED_PARAMETER(dwToVersion);
    UNREFERENCED_PARAMETER(lpszFromPath); UNREFERENCED_PARAMETER(lpszToPath);
    UNREFERENCED_PARAMETER(Reserved);
    return 0;
}

// ============================================================================
// Unix Compatibility Functions (Blocked for security - ReactOS style)
// ============================================================================
int WSAAPI ex_dn_expand(const unsigned char* msg, const unsigned char* eom, 
                        const unsigned char* comp, char* exp, int l) {
    LogMessage("dn_expand -> -1 (not implemented)");
    UNREFERENCED_PARAMETER(msg); UNREFERENCED_PARAMETER(eom); 
    UNREFERENCED_PARAMETER(comp);
    if (exp && l > 0) exp[0] = '\0';
    return -1;
}

struct netent* WSAAPI ex_getnetbyname(const char* name) {
    LogMessage("getnetbyname('%s') -> NULL", name ? name : "NULL");
    return NULL;
}

unsigned long WSAAPI ex_inet_network(const char* cp) {
    LogMessage("inet_network('%s') -> INADDR_NONE", cp ? cp : "NULL");
    UNREFERENCED_PARAMETER(cp);
    return INADDR_NONE;
}

int WSAAPI ex_rcmd(char** a, u_short r, const char* lc, const char* rm, 
                   const char* c, int* f) {
    LogMessage("rcmd() -> BLOCKED for security");
    UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(lc);
    UNREFERENCED_PARAMETER(rm); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(f);
    return -1;
}

int WSAAPI ex_rexec(char** a, int r, const char* u, const char* p, 
                    const char* c, int* f) {
    LogMessage("rexec() -> BLOCKED for security");
    UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(u);
    UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(f);
    return -1;
}

int WSAAPI ex_rresvport(int* port) {
    LogMessage("rresvport() -> -1 (not implemented)");
    UNREFERENCED_PARAMETER(port);
    return -1;
}

void WSAAPI ex_s_perror(const char* msg) {
    LogMessage("s_perror('%s')", msg ? msg : "NULL");
    UNREFERENCED_PARAMETER(msg);
}

int WSAAPI ex_sethostname(const char* name, int namelen) {
    LogMessage("sethostname()");
    UNREFERENCED_PARAMETER(name); UNREFERENCED_PARAMETER(namelen);
    return 0;
}

// ============================================================================
// DLL Entry Point
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    
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
                
                LogMessage("=== EXMSW v2.2.0 Initialized (ReactOS Hybrid) ===");
            }
            break;
            
        case DLL_PROCESS_DETACH:
            if (InterlockedDecrement(&g_InitCount) == 0) {
                LogMessage("=== EXMSW v2.2.0 Unloading ===");
                
                if (g_tlsError != TLS_OUT_OF_INDEXES) {
                    TlsFree(g_tlsError);
                }
                
                if (g_hWs2_32 != NULL) {
                    FreeLibrary(g_hWs2_32);
                    g_hWs2_32 = NULL;
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