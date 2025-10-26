// ============================================================================
// === EXMSW.DLL: MSWSOCK Stub Implementation v1.0.1 (Clean) ===
// === Автор: EXLOUD ===
// === Призначення: Емуляція функцій mswsock.dll для офлайн-режиму. ===
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
    SockaddrAddressInfoNormal, SockaddrAddressInfoLoopback, SockaddrAddressInfoBroadcast, SockaddrAddressInfoWildcard
} SOCKADDR_ADDRESS_INFO;
typedef enum {
    SockaddrEndpointInfoNormal, SockaddrEndpointInfoLoopback, SockaddrEndpointInfoBroadcast, SockaddrEndpointInfoWildcard
} SOCKADDR_ENDPOINT_INFO;
typedef struct _SOCKADDR_INFO {
    SOCKADDR_ADDRESS_INFO AddressInfo; SOCKADDR_ENDPOINT_INFO EndpointInfo;
} SOCKADDR_INFO, *PSOCKADDR_INFO;
#define SockaddrInfoNormal SockaddrAddressInfoNormal
#define SockaddrEndpointRelevant SockaddrEndpointInfoNormal
typedef struct _WINSOCK_MAPPING { DWORD Rows; DWORD Columns; } WINSOCK_MAPPING, *PWINSOCK_MAPPING;
typedef struct _NS_ROUTINE { DWORD dwFunctionCount; LPVOID* lpfnFunctions; } NS_ROUTINE, *PNS_ROUTINE, *LPNS_ROUTINE;

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
    char buffer[2048]; SYSTEMTIME st; GetLocalTime(&st);
    int prefix_len = snprintf(buffer, sizeof(buffer), "[EXMSW][%02d:%02d:%02d.%03d] ",
                              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args; va_start(args, format);
    vsnprintf(buffer + prefix_len, sizeof(buffer) - prefix_len, format, args);
    va_end(args); strcat_s(buffer, sizeof(buffer), "\n");
    #if ENABLE_DEBUG_CONSOLE
    if (g_hConsole) { DWORD written; WriteConsoleA(g_hConsole, buffer, (DWORD)strlen(buffer), &written, NULL); }
    #endif
    #if ENABLE_FILE_LOGGING
    if (g_LogFile) { EnterCriticalSection(&g_LogCS); fputs(buffer, g_LogFile); fflush(g_LogFile); LeaveCriticalSection(&g_LogCS); }
    #endif
#else
    UNREFERENCED_PARAMETER(format);
#endif
}

// === ОБГОРТКИ ДЛЯ ФУНКЦІЙ, ЩО ІМПОРТУЮТЬСЯ З EXWS2.DLL ===
// Ці обгортки потрібні, щоб exmsw.def міг посилатися на власні реалізації,
// які, в свою чергу, просто викликають функції, оголошені в <winsock2.h>
// і реалізовані в exws2.dll.
int WSAAPI ex_wrapper_getsockopt(SOCKET s, int level, int optname, char* optval, int* optlen) {
    return getsockopt(s, level, optname, optval, optlen);
}
int WSAAPI ex_wrapper_recv(SOCKET s, char* buf, int len, int flags) {
    return recv(s, buf, len, flags);
}
int WSAAPI ex_wrapper_recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    return recvfrom(s, buf, len, flags, from, fromlen);
}
int WSAAPI ex_wrapper_setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen) {
    return setsockopt(s, level, optname, optval, optlen);
}

// === ОСНОВНІ ФУНКЦІЇ-ЗАГЛУШКИ MSWSOCK ===
BOOL PASCAL FAR ex_AcceptEx(SOCKET sListenSocket, SOCKET sAcceptSocket, PVOID lpOutputBuffer, DWORD dwReceiveDataLength, DWORD dwLocalAddressLength, DWORD dwRemoteAddressLength, LPDWORD lpdwBytesReceived, LPOVERLAPPED lpOverlapped) {
    LogMessage("AcceptEx(listen=%llu, accept=%llu) -> SIMULATING PENDING", (UINT_PTR)sListenSocket, (UINT_PTR)sAcceptSocket);
    UNREFERENCED_PARAMETER(sListenSocket); UNREFERENCED_PARAMETER(sAcceptSocket); UNREFERENCED_PARAMETER(lpOutputBuffer); UNREFERENCED_PARAMETER(dwReceiveDataLength); UNREFERENCED_PARAMETER(dwLocalAddressLength); UNREFERENCED_PARAMETER(dwRemoteAddressLength);
    if (lpOverlapped) { lpOverlapped->Internal = (ULONG_PTR)STATUS_PENDING; }
    if (lpdwBytesReceived) { *lpdwBytesReceived = 0; }
    SetMSWSockError(WSA_IO_PENDING); return FALSE;
}
VOID PASCAL FAR ex_GetAcceptExSockaddrs(PVOID lpOutputBuffer, DWORD dwReceiveDataLength, DWORD dwLocalAddressLength, DWORD dwRemoteAddressLength, LPSOCKADDR* LocalSockaddr, LPINT LocalSockaddrLength, LPSOCKADDR* RemoteSockaddr, LPINT RemoteSockaddrLength) {
    LogMessage("GetAcceptExSockaddrs() called");
    UNREFERENCED_PARAMETER(lpOutputBuffer); UNREFERENCED_PARAMETER(dwReceiveDataLength); UNREFERENCED_PARAMETER(dwLocalAddressLength); UNREFERENCED_PARAMETER(dwRemoteAddressLength);
    static struct sockaddr_in generic_addr; memset(&generic_addr, 0, sizeof(generic_addr));
    generic_addr.sin_family = AF_INET; generic_addr.sin_addr.s_addr = 0x0100007F; generic_addr.sin_port = 0;
    if (LocalSockaddr && LocalSockaddrLength) { *LocalSockaddr = (LPSOCKADDR)&generic_addr; *LocalSockaddrLength = sizeof(generic_addr); }
    if (RemoteSockaddr && RemoteSockaddrLength) { *RemoteSockaddr = (LPSOCKADDR)&generic_addr; *RemoteSockaddrLength = sizeof(generic_addr); }
}
BOOL PASCAL FAR ex_TransmitFile(SOCKET hSocket, HANDLE hFile, DWORD nNumberOfBytesToWrite, DWORD nNumberOfBytesPerSend, LPOVERLAPPED lpOverlapped, LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers, DWORD dwFlags) {
    LogMessage("TransmitFile(socket=%llu, file=%p) -> OFFLINE/BLOCKED", (UINT_PTR)hSocket, hFile);
    UNREFERENCED_PARAMETER(hSocket); UNREFERENCED_PARAMETER(hFile); UNREFERENCED_PARAMETER(nNumberOfBytesToWrite); UNREFERENCED_PARAMETER(nNumberOfBytesPerSend); UNREFERENCED_PARAMETER(lpTransmitBuffers); UNREFERENCED_PARAMETER(dwFlags);
    if (lpOverlapped) { lpOverlapped->Internal = (ULONG_PTR)WSAENETDOWN; if (lpOverlapped->hEvent) SetEvent(lpOverlapped->hEvent); }
    SetMSWSockError(WSAENETDOWN); return FALSE;
}
int PASCAL FAR ex_WSARecvEx(SOCKET s, char* buf, int len, int* flags) {
    LogMessage("WSARecvEx(socket=%llu, len=%d) -> OFFLINE/BLOCKED", (UINT_PTR)s, len);
    UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(buf); UNREFERENCED_PARAMETER(len); UNREFERENCED_PARAMETER(flags);
    SetMSWSockError(WSAENOTCONN); return SOCKET_ERROR;
}

// === ENUMERATION & NAME SERVICE (ЗАГЛУШКИ) ===
INT WSAAPI ex_EnumProtocolsA(LPINT lpiProtocols, LPVOID lpProtocolBuffer, LPDWORD lpdwBufferLength) { LogMessage("EnumProtocolsA() -> No protocols"); UNREFERENCED_PARAMETER(lpiProtocols); UNREFERENCED_PARAMETER(lpProtocolBuffer); if (lpdwBufferLength) *lpdwBufferLength = 0; return 0; }
INT WSAAPI ex_EnumProtocolsW(LPINT lpiProtocols, LPVOID lpProtocolBuffer, LPDWORD lpdwBufferLength) { LogMessage("EnumProtocolsW() -> No protocols"); UNREFERENCED_PARAMETER(lpiProtocols); UNREFERENCED_PARAMETER(lpProtocolBuffer); if (lpdwBufferLength) *lpdwBufferLength = 0; return 0; }
INT WSAAPI ex_GetAddressByNameA(DWORD dwNameSpace, LPGUID lpServiceType, LPSTR lpServiceName, LPINT lpiProtocols, DWORD dwResolution, LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, LPVOID lpCsaddrBuffer, LPDWORD lpdwBufferLength, LPSTR lpAliasBuffer, LPDWORD lpdwAliasBufferLength) { LogMessage("GetAddressByNameA('%s') -> NOT FOUND", lpServiceName ? lpServiceName : "NULL"); UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(lpServiceType); UNREFERENCED_PARAMETER(lpiProtocols); UNREFERENCED_PARAMETER(dwResolution); UNREFERENCED_PARAMETER(lpServiceAsyncInfo); UNREFERENCED_PARAMETER(lpCsaddrBuffer); UNREFERENCED_PARAMETER(lpdwBufferLength); UNREFERENCED_PARAMETER(lpAliasBuffer); UNREFERENCED_PARAMETER(lpdwAliasBufferLength); SetMSWSockError(WSAHOST_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_GetAddressByNameW(DWORD dwNameSpace, LPGUID lpServiceType, LPWSTR lpServiceName, LPINT lpiProtocols, DWORD dwResolution, LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, LPVOID lpCsaddrBuffer, LPDWORD lpdwBufferLength, LPWSTR lpAliasBuffer, LPDWORD lpdwAliasBufferLength) { LogMessage("GetAddressByNameW() -> NOT FOUND"); UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(lpServiceType); UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(lpiProtocols); UNREFERENCED_PARAMETER(dwResolution); UNREFERENCED_PARAMETER(lpServiceAsyncInfo); UNREFERENCED_PARAMETER(lpCsaddrBuffer); UNREFERENCED_PARAMETER(lpdwBufferLength); UNREFERENCED_PARAMETER(lpAliasBuffer); UNREFERENCED_PARAMETER(lpdwAliasBufferLength); SetMSWSockError(WSAHOST_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_GetNameByTypeA(LPGUID lpServiceType, LPSTR lpServiceName, DWORD dwNameLength) { UNREFERENCED_PARAMETER(lpServiceType); if (lpServiceName && dwNameLength > 0) lpServiceName[0] = '\0'; SetMSWSockError(WSATYPE_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_GetNameByTypeW(LPGUID lpServiceType, LPWSTR lpServiceName, DWORD dwNameLength) { UNREFERENCED_PARAMETER(lpServiceType); if (lpServiceName && dwNameLength > 0) lpServiceName[0] = L'\0'; SetMSWSockError(WSATYPE_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_GetTypeByNameA(LPSTR lpServiceName, LPGUID lpServiceType) { UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(lpServiceType); SetMSWSockError(WSATYPE_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_GetTypeByNameW(LPWSTR lpServiceName, LPGUID lpServiceType) { UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(lpServiceType); SetMSWSockError(WSATYPE_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_GetServiceA(DWORD dwNameSpace, LPGUID lpGuid, LPSTR lpServiceName, DWORD dwProperties, LPVOID lpBuffer, LPDWORD lpdwBufferSize, LPSERVICE_ASYNC_INFO lpServiceAsyncInfo) { UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(lpGuid); UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(dwProperties); UNREFERENCED_PARAMETER(lpBuffer); UNREFERENCED_PARAMETER(lpdwBufferSize); UNREFERENCED_PARAMETER(lpServiceAsyncInfo); SetMSWSockError(WSASERVICE_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_GetServiceW(DWORD dwNameSpace, LPGUID lpGuid, LPWSTR lpServiceName, DWORD dwProperties, LPVOID lpBuffer, LPDWORD lpdwBufferSize, LPSERVICE_ASYNC_INFO lpServiceAsyncInfo) { UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(lpGuid); UNREFERENCED_PARAMETER(lpServiceName); UNREFERENCED_PARAMETER(dwProperties); UNREFERENCED_PARAMETER(lpBuffer); UNREFERENCED_PARAMETER(lpdwBufferSize); UNREFERENCED_PARAMETER(lpServiceAsyncInfo); SetMSWSockError(WSASERVICE_NOT_FOUND); return SOCKET_ERROR; }
INT WSAAPI ex_SetServiceA(DWORD dwNameSpace, DWORD dwOperation, DWORD dwFlags, LPSERVICE_INFOA lpServiceInfo, LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, LPDWORD lpdwStatusFlags) { UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(dwOperation); UNREFERENCED_PARAMETER(dwFlags); UNREFERENCED_PARAMETER(lpServiceInfo); UNREFERENCED_PARAMETER(lpServiceAsyncInfo); UNREFERENCED_PARAMETER(lpdwStatusFlags); return NO_ERROR; }
INT WSAAPI ex_SetServiceW(DWORD dwNameSpace, DWORD dwOperation, DWORD dwFlags, LPSERVICE_INFOW lpServiceInfo, LPSERVICE_ASYNC_INFO lpServiceAsyncInfo, LPDWORD lpdwStatusFlags) { UNREFERENCED_PARAMETER(dwNameSpace); UNREFERENCED_PARAMETER(dwOperation); UNREFERENCED_PARAMETER(dwFlags); UNREFERENCED_PARAMETER(lpServiceInfo); UNREFERENCED_PARAMETER(lpServiceAsyncInfo); UNREFERENCED_PARAMETER(lpdwStatusFlags); return NO_ERROR; }

// === WSH (Windows Sockets Helper) FUNCTIONS (ЗАГЛУШКИ) ===
INT WSAAPI ex_Tcpip4_WSHAddressToString(LPSOCKADDR A, INT AL, LPWSAPROTOCOL_INFOW PI, LPWSTR AS, LPDWORD ASL) { LogMessage("Tcpip4_WSHAddressToString"); UNREFERENCED_PARAMETER(A); UNREFERENCED_PARAMETER(AL); UNREFERENCED_PARAMETER(PI); if (AS && ASL && *ASL >= 16) { wcscpy_s(AS, *ASL, L"127.0.0.1"); *ASL = 10; return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip4_WSHEnumProtocols(LPINT lpi, LPWSTR ltkn, LPVOID lpb, LPDWORD ldb) { LogMessage("Tcpip4_WSHEnumProtocols"); UNREFERENCED_PARAMETER(lpi); UNREFERENCED_PARAMETER(ltkn); UNREFERENCED_PARAMETER(lpb); if(ldb) *ldb = 0; return 0; }
INT WSAAPI ex_Tcpip4_WSHGetBroadcastSockaddr(PVOID H, PSOCKADDR S, PINT SL) { LogMessage("Tcpip4_WSHGetBroadcastSockaddr"); UNREFERENCED_PARAMETER(H); if (S && SL && *SL >= sizeof(struct sockaddr_in)) { struct sockaddr_in* a = (struct sockaddr_in*)S; memset(a, 0, sizeof(*a)); a->sin_family = AF_INET; a->sin_addr.s_addr = 0xFFFFFFFF; *SL = sizeof(struct sockaddr_in); return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip4_WSHGetProviderGuid(LPWSTR PN, LPGUID PG) { LogMessage("Tcpip4_WSHGetProviderGuid"); UNREFERENCED_PARAMETER(PN); if (PG) { memset(PG, 0, sizeof(GUID)); return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip4_WSHGetSockaddrType(PSOCKADDR S, DWORD SL, PSOCKADDR_INFO SI) { LogMessage("Tcpip4_WSHGetSockaddrType"); UNREFERENCED_PARAMETER(S); UNREFERENCED_PARAMETER(SL); if (SI) { SI->AddressInfo = SockaddrInfoNormal; SI->EndpointInfo = SockaddrEndpointRelevant; return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip4_WSHGetSocketInformation(PVOID H, SOCKET S, HANDLE TA, HANDLE TC, INT L, INT O, PCHAR OV, PINT OL) { LogMessage("Tcpip4_WSHGetSocketInformation"); UNREFERENCED_PARAMETER(H); UNREFERENCED_PARAMETER(S); UNREFERENCED_PARAMETER(TA); UNREFERENCED_PARAMETER(TC); UNREFERENCED_PARAMETER(L); UNREFERENCED_PARAMETER(O); if (OV && OL && *OL >= sizeof(int)) { *(int*)OV = 0; *OL = sizeof(int); return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip4_WSHGetWSAProtocolInfo(LPWSTR PN, LPWSAPROTOCOL_INFOW* PI, LPDWORD PE) { LogMessage("Tcpip4_WSHGetWSAProtocolInfo"); UNREFERENCED_PARAMETER(PN); UNREFERENCED_PARAMETER(PI); if(PE) *PE = 0; return 0; }
INT WSAAPI ex_Tcpip4_WSHGetWildcardSockaddr(PVOID H, PSOCKADDR S, PINT SL) { LogMessage("Tcpip4_WSHGetWildcardSockaddr"); UNREFERENCED_PARAMETER(H); if (S && SL && *SL >= sizeof(struct sockaddr_in)) { struct sockaddr_in* a = (struct sockaddr_in*)S; memset(a, 0, sizeof(*a)); a->sin_family = AF_INET; a->sin_addr.s_addr = 0; *SL = sizeof(struct sockaddr_in); return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip4_WSHGetWinsockMapping(PWINSOCK_MAPPING M, DWORD ML) { LogMessage("Tcpip4_WSHGetWinsockMapping"); UNREFERENCED_PARAMETER(M); UNREFERENCED_PARAMETER(ML); return 0; }
INT WSAAPI ex_Tcpip4_WSHIoctl(PVOID H, SOCKET S, HANDLE TA, HANDLE TC, DWORD C, LPVOID I, DWORD IL, LPVOID O, DWORD OL, LPDWORD NR, LPWSAOVERLAPPED OV, LPWSAOVERLAPPED_COMPLETION_ROUTINE CR, LPBOOL NC) { LogMessage("Tcpip4_WSHIoctl(code=0x%lx)", C); UNREFERENCED_PARAMETER(H); UNREFERENCED_PARAMETER(S); UNREFERENCED_PARAMETER(TA); UNREFERENCED_PARAMETER(TC); UNREFERENCED_PARAMETER(I); UNREFERENCED_PARAMETER(IL); UNREFERENCED_PARAMETER(O); UNREFERENCED_PARAMETER(OL); UNREFERENCED_PARAMETER(NR); UNREFERENCED_PARAMETER(OV); UNREFERENCED_PARAMETER(CR); if (NC) *NC = FALSE; return 0; }
INT WSAAPI ex_Tcpip4_WSHJoinLeaf(PVOID H, SOCKET S, HANDLE TA, HANDLE TC, PVOID LH, SOCKET LS, PSOCKADDR SA, DWORD SL, LPWSABUF CD1, LPWSABUF CD2, LPQOS SQ, LPQOS GQ, DWORD F) { LogMessage("Tcpip4_WSHJoinLeaf"); UNREFERENCED_PARAMETER(H); UNREFERENCED_PARAMETER(S); UNREFERENCED_PARAMETER(TA); UNREFERENCED_PARAMETER(TC); UNREFERENCED_PARAMETER(LH); UNREFERENCED_PARAMETER(LS); UNREFERENCED_PARAMETER(SA); UNREFERENCED_PARAMETER(SL); UNREFERENCED_PARAMETER(CD1); UNREFERENCED_PARAMETER(CD2); UNREFERENCED_PARAMETER(SQ); UNREFERENCED_PARAMETER(GQ); UNREFERENCED_PARAMETER(F); return 0; }
INT WSAAPI ex_Tcpip4_WSHNotify(PVOID H, SOCKET S, HANDLE TA, HANDLE TC, DWORD E) { LogMessage("Tcpip4_WSHNotify(event=0x%lx)", E); UNREFERENCED_PARAMETER(H); UNREFERENCED_PARAMETER(S); UNREFERENCED_PARAMETER(TA); UNREFERENCED_PARAMETER(TC); UNREFERENCED_PARAMETER(E); return 0; }
INT WSAAPI ex_Tcpip4_WSHOpenSocket(PINT AF, PINT ST, PINT P, PUNICODE_STRING TDN, PVOID* H, PDWORD NE) { LogMessage("Tcpip4_WSHOpenSocket"); UNREFERENCED_PARAMETER(AF); UNREFERENCED_PARAMETER(ST); UNREFERENCED_PARAMETER(P); UNREFERENCED_PARAMETER(TDN); UNREFERENCED_PARAMETER(H); UNREFERENCED_PARAMETER(NE); return 0; }
INT WSAAPI ex_Tcpip4_WSHOpenSocket2(PINT AF, PINT ST, PINT P, GROUP G, DWORD F, PUNICODE_STRING TDN, PVOID* H, PDWORD NE) { LogMessage("Tcpip4_WSHOpenSocket2"); UNREFERENCED_PARAMETER(AF); UNREFERENCED_PARAMETER(ST); UNREFERENCED_PARAMETER(P); UNREFERENCED_PARAMETER(G); UNREFERENCED_PARAMETER(F); UNREFERENCED_PARAMETER(TDN); UNREFERENCED_PARAMETER(H); UNREFERENCED_PARAMETER(NE); return 0; }
INT WSAAPI ex_Tcpip4_WSHSetSocketInformation(PVOID H, SOCKET S, HANDLE TA, HANDLE TC, INT L, INT O, PCHAR OV, INT OL) { LogMessage("Tcpip4_WSHSetSocketInformation"); UNREFERENCED_PARAMETER(H); UNREFERENCED_PARAMETER(S); UNREFERENCED_PARAMETER(TA); UNREFERENCED_PARAMETER(TC); UNREFERENCED_PARAMETER(L); UNREFERENCED_PARAMETER(O); UNREFERENCED_PARAMETER(OV); UNREFERENCED_PARAMETER(OL); return 0; }
INT WSAAPI ex_Tcpip4_WSHStringToAddress(LPWSTR AS, DWORD AF, LPWSAPROTOCOL_INFOW PI, LPSOCKADDR A, LPDWORD AL) { LogMessage("Tcpip4_WSHStringToAddress"); UNREFERENCED_PARAMETER(AS); UNREFERENCED_PARAMETER(AF); UNREFERENCED_PARAMETER(PI); if (A && AL && *AL >= sizeof(struct sockaddr_in)) { struct sockaddr_in* addr = (struct sockaddr_in*)A; memset(addr, 0, sizeof(*addr)); addr->sin_family = AF_INET; addr->sin_addr.s_addr = 0x0100007F; *AL = sizeof(struct sockaddr_in); return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip6_WSHAddressToString(LPSOCKADDR A, INT AL, LPWSAPROTOCOL_INFOW PI, LPWSTR AS, LPDWORD ASL) { LogMessage("Tcpip6_WSHAddressToString"); UNREFERENCED_PARAMETER(A); UNREFERENCED_PARAMETER(AL); UNREFERENCED_PARAMETER(PI); if (AS && ASL && *ASL >= 4) { wcscpy_s(AS, *ASL, L"::1"); *ASL = 4; return 0; } return SOCKET_ERROR; }
INT WSAAPI ex_Tcpip6_WSHEnumProtocols(LPINT l,LPWSTR n,LPVOID b,LPDWORD bl) { return ex_Tcpip4_WSHEnumProtocols(l,n,b,bl); }
INT WSAAPI ex_Tcpip6_WSHGetProviderGuid(LPWSTR n, LPGUID g) { return ex_Tcpip4_WSHGetProviderGuid(n,g); }
INT WSAAPI ex_Tcpip6_WSHGetSockaddrType(PSOCKADDR s, DWORD sl, PSOCKADDR_INFO si) { return ex_Tcpip4_WSHGetSockaddrType(s,sl,si); }
INT WSAAPI ex_Tcpip6_WSHGetSocketInformation(PVOID h,SOCKET s,HANDLE ta,HANDLE tc,INT l,INT o,PCHAR ov,PINT ol) { return ex_Tcpip4_WSHGetSocketInformation(h,s,ta,tc,l,o,ov,ol); }
INT WSAAPI ex_Tcpip6_WSHGetWSAProtocolInfo(LPWSTR n, LPWSAPROTOCOL_INFOW* i, LPDWORD e) { return ex_Tcpip4_WSHGetWSAProtocolInfo(n,i,e); }
INT WSAAPI ex_Tcpip6_WSHGetWildcardSockaddr(PVOID h, PSOCKADDR s, PINT sl) { return ex_Tcpip4_WSHGetWildcardSockaddr(h,s,sl); }
INT WSAAPI ex_Tcpip6_WSHGetWinsockMapping(PWINSOCK_MAPPING m, DWORD ml) { return ex_Tcpip4_WSHGetWinsockMapping(m,ml); }
INT WSAAPI ex_Tcpip6_WSHIoctl(PVOID h,SOCKET s,HANDLE ta,HANDLE tc,DWORD c,LPVOID i,DWORD il,LPVOID o,DWORD ol,LPDWORD nr,LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE cr,LPBOOL nc) { return ex_Tcpip4_WSHIoctl(h,s,ta,tc,c,i,il,o,ol,nr,ov,cr,nc); }
INT WSAAPI ex_Tcpip6_WSHJoinLeaf(PVOID h,SOCKET s,HANDLE ta,HANDLE tc,PVOID lh,SOCKET ls,PSOCKADDR sa,DWORD sl,LPWSABUF c1,LPWSABUF c2,LPQOS sq,LPQOS gq,DWORD f) { return ex_Tcpip4_WSHJoinLeaf(h,s,ta,tc,lh,ls,sa,sl,c1,c2,sq,gq,f); }
INT WSAAPI ex_Tcpip6_WSHNotify(PVOID h, SOCKET s, HANDLE ta, HANDLE tc, DWORD e) { return ex_Tcpip4_WSHNotify(h,s,ta,tc,e); }
INT WSAAPI ex_Tcpip6_WSHOpenSocket(PINT af,PINT st,PINT p,PUNICODE_STRING t,PVOID* c,PDWORD n) { return ex_Tcpip4_WSHOpenSocket(af,st,p,t,c,n); }
INT WSAAPI ex_Tcpip6_WSHOpenSocket2(PINT af,PINT st,PINT p,GROUP g,DWORD f,PUNICODE_STRING t,PVOID* c,PDWORD n) { return ex_Tcpip4_WSHOpenSocket2(af,st,p,g,f,t,c,n); }
INT WSAAPI ex_Tcpip6_WSHSetSocketInformation(PVOID h,SOCKET s,HANDLE ta,HANDLE tc,INT l,INT o,PCHAR ov,INT ol) { return ex_Tcpip4_WSHSetSocketInformation(h,s,ta,tc,l,o,ov,ol); }
INT WSAAPI ex_Tcpip6_WSHStringToAddress(LPWSTR as,DWORD af,LPWSAPROTOCOL_INFOW pi,LPSOCKADDR a,LPDWORD al) { return ex_Tcpip4_WSHStringToAddress(as,af,pi,a,al); }

// === MISC FUNCTIONS (ЗАГЛУШКИ) ===
INT WSAAPI ex_GetSocketErrorMessageW(INT ErrorCode, LPWSTR Buffer, INT BufferSize) { LogMessage("GetSocketErrorMessageW(%d)", ErrorCode); if (Buffer && BufferSize > 0) { swprintf_s(Buffer, BufferSize, L"Emulated Socket Error %d", ErrorCode); return (INT)wcslen(Buffer); } return 0; }
int WSAAPI ex_NPLoadNameSpaces(LPDWORD lpdwVersion, LPNS_ROUTINE lpnsrBuffer, LPDWORD lpdwBufferLength) { LogMessage("NPLoadNameSpaces"); UNREFERENCED_PARAMETER(lpdwVersion); UNREFERENCED_PARAMETER(lpnsrBuffer); if (lpdwBufferLength) *lpdwBufferLength = 0; return 0; }
INT WSAAPI ex_NSPStartup(LPGUID lpProviderId, LPNSP_ROUTINE lpnspRoutines) { LogMessage("NSPStartup"); UNREFERENCED_PARAMETER(lpProviderId); UNREFERENCED_PARAMETER(lpnspRoutines); return NO_ERROR; }
INT WSAAPI ex_WSPStartup(WORD wVersionRequested, LPWSPDATA lpWSPData, LPWSAPROTOCOL_INFOW lpProtocolInfo, WSPUPCALLTABLE UpcallTable, LPWSPPROC_TABLE lpProcTable) { LogMessage("WSPStartup"); UNREFERENCED_PARAMETER(wVersionRequested); UNREFERENCED_PARAMETER(lpProtocolInfo); UNREFERENCED_PARAMETER(UpcallTable); UNREFERENCED_PARAMETER(lpProcTable); if (lpWSPData) { lpWSPData->wVersion = MAKEWORD(2,2); lpWSPData->wHighVersion = MAKEWORD(2, 2); } return NO_ERROR; }
void WSAAPI ex_ProcessSocketNotifications(void) { LogMessage("ProcessSocketNotifications"); }
DWORD WSAAPI ex_StartWsdpService(void) { LogMessage("StartWsdpService"); return ERROR_SERVICE_DISABLED; }
BOOL WSAAPI ex_StopWsdpService(void) { LogMessage("StopWsdpService"); return TRUE; }
INT WSAAPI ex_MigrateWinsockConfiguration(DWORD dwFromVersion, DWORD dwToVersion, DWORD Reserved) { LogMessage("MigrateWinsockConfiguration"); UNREFERENCED_PARAMETER(dwFromVersion); UNREFERENCED_PARAMETER(dwToVersion); UNREFERENCED_PARAMETER(Reserved); return 0; }
INT WSAAPI ex_MigrateWinsockConfigurationEx(DWORD dwFromVersion, DWORD dwToVersion, LPWSTR lpszFromPath, LPWSTR lpszToPath, DWORD Reserved) { LogMessage("MigrateWinsockConfigurationEx"); UNREFERENCED_PARAMETER(dwFromVersion); UNREFERENCED_PARAMETER(dwToVersion); UNREFERENCED_PARAMETER(lpszFromPath); UNREFERENCED_PARAMETER(lpszToPath); UNREFERENCED_PARAMETER(Reserved); return 0; }

// === UNIX COMPATIBILITY (ЗАГЛУШКИ) ===
int WSAAPI ex_dn_expand(const unsigned char* msg, const unsigned char* eom, const unsigned char* comp, char* exp, int l) { LogMessage("dn_expand"); UNREFERENCED_PARAMETER(msg); UNREFERENCED_PARAMETER(eom); UNREFERENCED_PARAMETER(comp); if (exp && l > 0) exp[0] = '\0'; return -1; }
struct netent* WSAAPI ex_getnetbyname(const char* name) { LogMessage("getnetbyname('%s')", name ? name : "NULL"); return NULL; }
unsigned long WSAAPI ex_inet_network(const char* cp) { LogMessage("inet_network('%s')", cp ? cp : "NULL"); UNREFERENCED_PARAMETER(cp); return INADDR_NONE; }
int WSAAPI ex_rcmd(char** a, u_short r, const char* lc, const char* rm, const char* c, int* f) { LogMessage("rcmd() - BLOCKED"); UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(lc); UNREFERENCED_PARAMETER(rm); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(f); return -1; }
int WSAAPI ex_rexec(char** a, int r, const char* u, const char* p, const char* c, int* f) { LogMessage("rexec() - BLOCKED"); UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(u); UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(f); return -1; }
int WSAAPI ex_rresvport(int* port) { LogMessage("rresvport()"); UNREFERENCED_PARAMETER(port); return -1; }
void WSAAPI ex_s_perror(const char* msg) { LogMessage("s_perror('%s')", msg ? msg : "NULL"); UNREFERENCED_PARAMETER(msg); }
int WSAAPI ex_sethostname(const char* name, int namelen) { LogMessage("sethostname()"); UNREFERENCED_PARAMETER(name); UNREFERENCED_PARAMETER(namelen); return 0; }

// === DLL ENTRY POINT ===
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule); UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            if (InterlockedIncrement(&g_InitCount) == 1) {
                g_tlsError = TlsAlloc();
                #if ENABLE_DEBUG_CONSOLE
                if (AllocConsole()) { g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE); SetConsoleTitleA("EXMSW Debug Console"); }
                #endif
                #if ENABLE_FILE_LOGGING
                InitializeCriticalSection(&g_LogCS); char p[MAX_PATH]; GetTempPathA(MAX_PATH, p); strcat_s(p, MAX_PATH, "exmsw.log"); fopen_s(&g_LogFile, p, "a");
                #endif
                LogMessage("=== EXMSW Stub v1.0.1 Initialized ===");
            } break;
        case DLL_PROCESS_DETACH:
            if (InterlockedDecrement(&g_InitCount) == 0) {
                LogMessage("=== EXMSW Stub v1.0.1 Unloading ===");
                if (g_tlsError != TLS_OUT_OF_INDEXES) { TlsFree(g_tlsError); }
                #if ENABLE_FILE_LOGGING
                if (g_LogFile) { fclose(g_LogFile); } DeleteCriticalSection(&g_LogCS);
                #endif
                #if ENABLE_DEBUG_CONSOLE
                if (g_hConsole) { FreeConsole(); }
                #endif
            } break;
    } return TRUE;
}