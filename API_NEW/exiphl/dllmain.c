#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <udpmib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */
#define ENABLE_DEBUG_CONSOLE    1
#define ENABLE_FILE_LOGGING     0
#define MAX_ADAPTERS            4
#define MAX_IPS_PER_ADAPTER     4
#define CHARS_IN_GUID           39

#ifndef IF_MAX_STRING_SIZE
#define IF_MAX_STRING_SIZE      256
#endif

#ifndef NET_IF_COMPARTMENT_ID_PRIMARY
#define NET_IF_COMPARTMENT_ID_PRIMARY 1
#endif

#ifndef MIB_TCP_RTO_VANJ
#define MIB_TCP_RTO_VANJ 4
#endif

/* ============================================================================
 * STRUCTURES
 * ============================================================================ */
typedef enum { LOG_ERROR = 0, LOG_WARN, LOG_INFO, LOG_DEBUG } LogLevel;

typedef struct {
    char ipAddress[46];
    ADDRESS_FAMILY family;
    ULONG addr4;
    IN6_ADDR addr6;
    UINT8 prefixLen;
    ULONG NTEContext;
} FakeIP;

typedef struct {
    char name[MAX_ADAPTER_NAME_LENGTH + 4];
    WCHAR nameW[MAX_ADAPTER_NAME_LENGTH + 4];
    GUID guid;
    char description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
    WCHAR descriptionW[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
    WCHAR friendlyName[IF_MAX_STRING_SIZE];
    WCHAR dnsSuffix[64];
    DWORD type;
    DWORD index;
    NET_LUID luid;
    DWORD mtu;
    ULONG64 speed;
    DWORD adminStatus;
    IF_OPER_STATUS operStatus;
    NET_IF_MEDIA_CONNECT_STATE mediaState;
    NET_IF_CONNECTION_TYPE connType;
    BYTE mac[MAX_ADAPTER_ADDRESS_LENGTH];
    DWORD macLen;
    int ipCount;
    FakeIP ips[MAX_IPS_PER_ADAPTER];
    BOOL dhcpEnabled;
} FakeAdapter;

typedef struct {
    int adapterCount;
    FakeAdapter adapters[MAX_ADAPTERS];
    char hostName[MAX_HOSTNAME_LEN + 1];
    char domainName[MAX_DOMAIN_NAME_LEN + 1];
    MIB_IPSTATS ipStats;
    MIB_TCPSTATS tcpStats;
    MIB_UDPSTATS udpStats;
    MIB_ICMP icmpStats;
    ULONG nextNTEContext;
} NetworkState;

/* ============================================================================
 * GLOBALS
 * ============================================================================ */
#if ENABLE_DEBUG_CONSOLE
static HANDLE g_hConsole = NULL;
#endif
#if ENABLE_FILE_LOGGING
static FILE* g_logFile = NULL;
static CRITICAL_SECTION g_logLock;
#endif
static BOOL g_locksInit = FALSE;
static LogLevel g_logLevel = LOG_DEBUG;
static NetworkState g_Net = {0};
static volatile LONG g_initCount = 0;
static const WCHAR* DEVICE_TCPIP = L"\\DEVICE\\TCPIP_";

/* ============================================================================
 * LOGGING
 * ============================================================================ */
static void Log(LogLevel level, const char* func, const char* fmt, ...) {
    if (level > g_logLevel || g_initCount == 0) return;
    
    char buf[2048], msg[1024], ts[24];
    SYSTEMTIME st;
    va_list args;
    
    GetLocalTime(&st);
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    
    const char* lvl = (level == LOG_ERROR) ? "ERR" : (level == LOG_WARN) ? "WRN" : (level == LOG_INFO) ? "INF" : "DBG";
    snprintf(buf, sizeof(buf), "[%s][%s][%s] %s\n", ts, lvl, func, msg);
    
#if ENABLE_FILE_LOGGING
    if (g_logFile && g_locksInit) {
        EnterCriticalSection(&g_logLock);
        fputs(buf, g_logFile);
        fflush(g_logFile);
        LeaveCriticalSection(&g_logLock);
    }
#endif
#if ENABLE_DEBUG_CONSOLE
    if (g_hConsole) { DWORD w; WriteConsoleA(g_hConsole, buf, (DWORD)strlen(buf), &w, NULL); }
#endif
}

#define LogE(fmt, ...) Log(LOG_ERROR, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogW(fmt, ...) Log(LOG_WARN, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogI(fmt, ...) Log(LOG_INFO, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogD(fmt, ...) Log(LOG_DEBUG, __FUNCTION__, fmt, ##__VA_ARGS__)

/* ============================================================================
 * HELPERS
 * ============================================================================ */
static void ParseMac(const char* s, BYTE* m) {
    sscanf(s, "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
}

static void MakeLuid(NET_LUID* l, DWORD idx, DWORD type) {
    l->Value = 0;
    l->Info.IfType = type;
    l->Info.NetLuidIndex = idx;
}

static FakeAdapter* FindByIndex(DWORD i) {
    for (int j = 0; j < g_Net.adapterCount; j++)
        if (g_Net.adapters[j].index == i) return &g_Net.adapters[j];
    return NULL;
}

static FakeAdapter* FindByLuid(const NET_LUID* l) {
    for (int j = 0; j < g_Net.adapterCount; j++)
        if (g_Net.adapters[j].luid.Value == l->Value) return &g_Net.adapters[j];
    return NULL;
}

static FakeAdapter* FindByGuid(const GUID* g) {
    for (int j = 0; j < g_Net.adapterCount; j++)
        if (IsEqualGUID(&g_Net.adapters[j].guid, g)) return &g_Net.adapters[j];
    return NULL;
}

/* Local helper for mask conversion - used internally */
static DWORD LocalConvertLengthToIpv4Mask(ULONG len, PULONG mask) {
    if (len > 32) { 
        if (mask) *mask = INADDR_NONE; 
        return ERROR_INVALID_PARAMETER; 
    }
    if (mask) *mask = len ? htonl(~0u << (32 - len)) : 0;
    return NO_ERROR;
}

/* ============================================================================
 * NETWORK CONFIG - ADAPTERS EXIST BUT ALL DISCONNECTED
 * ============================================================================ */
static void InitConfig(void) {
    FakeAdapter* a;
    
    LogI("Initializing: Adapters exist but ALL DISCONNECTED");
    memset(&g_Net, 0, sizeof(g_Net));
    g_Net.nextNTEContext = 1000;
    
    strcpy(g_Net.hostName, "DESKTOP-PC");
    strcpy(g_Net.domainName, "");
    
    /* =========================================================================
     * ADAPTER 1: Ethernet - EXISTS but CABLE UNPLUGGED
     * ========================================================================= */
    a = &g_Net.adapters[g_Net.adapterCount++];
    strcpy(a->name, "{4D36E972-E325-11CE-BFC1-08002BE10318}");
    mbstowcs(a->nameW, a->name, MAX_ADAPTER_NAME_LENGTH);
    CLSIDFromString(L"{4D36E972-E325-11CE-BFC1-08002BE10318}", &a->guid);
    strcpy(a->description, "Realtek PCIe GbE Family Controller");
    mbstowcs(a->descriptionW, a->description, MAX_ADAPTER_DESCRIPTION_LENGTH);
    wcscpy(a->friendlyName, L"Ethernet");
    wcscpy(a->dnsSuffix, L"");
    a->type = IF_TYPE_ETHERNET_CSMACD;
    a->index = 3;
    MakeLuid(&a->luid, 3, IF_TYPE_ETHERNET_CSMACD);
    a->mtu = 1500;
    a->speed = 0;
    a->adminStatus = MIB_IF_ADMIN_STATUS_UP;
    a->operStatus = IfOperStatusDown;
    a->mediaState = MediaConnectStateDisconnected;
    a->connType = NET_IF_CONNECTION_DEDICATED;
    ParseMac("00-1A-2B-3C-4D-5E", a->mac);
    a->macLen = 6;
    a->dhcpEnabled = TRUE;
    a->ipCount = 0;
    
    /* =========================================================================
     * ADAPTER 2: WiFi - EXISTS but NOT CONNECTED
     * ========================================================================= */
    a = &g_Net.adapters[g_Net.adapterCount++];
    strcpy(a->name, "{6D4F81C2-A8E7-4E5B-B3C9-1234567890AB}");
    mbstowcs(a->nameW, a->name, MAX_ADAPTER_NAME_LENGTH);
    CLSIDFromString(L"{6D4F81C2-A8E7-4E5B-B3C9-1234567890AB}", &a->guid);
    strcpy(a->description, "Intel(R) Wi-Fi 6 AX200 160MHz");
    mbstowcs(a->descriptionW, a->description, MAX_ADAPTER_DESCRIPTION_LENGTH);
    wcscpy(a->friendlyName, L"Wi-Fi");
    wcscpy(a->dnsSuffix, L"");
    a->type = IF_TYPE_IEEE80211;
    a->index = 7;
    MakeLuid(&a->luid, 7, IF_TYPE_IEEE80211);
    a->mtu = 1500;
    a->speed = 0;
    a->adminStatus = MIB_IF_ADMIN_STATUS_UP;
    a->operStatus = IfOperStatusDown;
    a->mediaState = MediaConnectStateDisconnected;
    a->connType = NET_IF_CONNECTION_DEDICATED;
    ParseMac("AC-12-03-D4-E5-F6", a->mac);
    a->macLen = 6;
    a->dhcpEnabled = TRUE;
    a->ipCount = 0;
    
    /* =========================================================================
     * ADAPTER 3: Loopback - always works
     * ========================================================================= */
    a = &g_Net.adapters[g_Net.adapterCount++];
    strcpy(a->name, "{00000000-0000-0000-0000-000000000001}");
    mbstowcs(a->nameW, a->name, MAX_ADAPTER_NAME_LENGTH);
    CLSIDFromString(L"{00000000-0000-0000-0000-000000000001}", &a->guid);
    strcpy(a->description, "Software Loopback Interface 1");
    mbstowcs(a->descriptionW, a->description, MAX_ADAPTER_DESCRIPTION_LENGTH);
    wcscpy(a->friendlyName, L"Loopback Pseudo-Interface 1");
    wcscpy(a->dnsSuffix, L"");
    a->type = IF_TYPE_SOFTWARE_LOOPBACK;
    a->index = 1;
    MakeLuid(&a->luid, 1, IF_TYPE_SOFTWARE_LOOPBACK);
    a->mtu = 1500;
    a->speed = 1073741824;
    a->adminStatus = MIB_IF_ADMIN_STATUS_UP;
    a->operStatus = IfOperStatusUp;
    a->mediaState = MediaConnectStateConnected;
    a->connType = NET_IF_CONNECTION_DEDICATED;
    a->macLen = 0;
    a->dhcpEnabled = FALSE;
    
    a->ips[a->ipCount].family = AF_INET;
    strcpy(a->ips[a->ipCount].ipAddress, "127.0.0.1");
    inet_pton(AF_INET, "127.0.0.1", &a->ips[a->ipCount].addr4);
    a->ips[a->ipCount].prefixLen = 8;
    a->ips[a->ipCount].NTEContext = g_Net.nextNTEContext++;
    a->ipCount++;
    
    a->ips[a->ipCount].family = AF_INET6;
    strcpy(a->ips[a->ipCount].ipAddress, "::1");
    inet_pton(AF_INET6, "::1", &a->ips[a->ipCount].addr6);
    a->ips[a->ipCount].prefixLen = 128;
    a->ips[a->ipCount].NTEContext = g_Net.nextNTEContext++;
    a->ipCount++;
    
    g_Net.ipStats.dwForwarding = MIB_IP_NOT_FORWARDING;
    g_Net.ipStats.dwDefaultTTL = 128;
    g_Net.ipStats.dwNumIf = g_Net.adapterCount;
    g_Net.ipStats.dwNumAddr = 2;
    g_Net.ipStats.dwNumRoutes = 1;
    
    g_Net.tcpStats.dwRtoAlgorithm = MIB_TCP_RTO_VANJ;
    g_Net.tcpStats.dwRtoMin = 300;
    g_Net.tcpStats.dwRtoMax = 120000;
    g_Net.tcpStats.dwMaxConn = (DWORD)-1;
    
    LogI("Done: %d adapters (Ethernet=UNPLUGGED, WiFi=DISCONNECTED, Loopback=OK)", g_Net.adapterCount);
}

/* ============================================================================
 * INITIALIZATION
 * ============================================================================ */
static void EnsureInit(void) {
    if (InterlockedCompareExchange(&g_initCount, 1, 0) == 0) {
#if ENABLE_FILE_LOGGING
        InitializeCriticalSection(&g_logLock);
#endif
        g_locksInit = TRUE;
        
#if ENABLE_DEBUG_CONSOLE
        AllocConsole();
        g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (g_hConsole != INVALID_HANDLE_VALUE) {
            SetConsoleTitleA("IPHLPAPI - Adapters Disconnected");
            const char* msg = "\n=== IPHLPAPI EMULATOR ===\nAdapters exist but NOT CONNECTED\n\n";
            DWORD w; WriteConsoleA(g_hConsole, msg, (DWORD)strlen(msg), &w, NULL);
        }
#endif
        
#if ENABLE_FILE_LOGGING
        char path[MAX_PATH], tmp[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tmp) > 0) {
            snprintf(path, MAX_PATH, "%siphlpapi_%lu.log", tmp, GetCurrentProcessId());
            fopen_s(&g_logFile, path, "w");
        }
#endif
        
        InitConfig();
    }
}

/* ============================================================================
 * ROW FILL HELPERS
 * ============================================================================ */
static void FillIfRow(MIB_IFROW* r, const FakeAdapter* a) {
    WCHAR gs[40];
    wcscpy(r->wszName, DEVICE_TCPIP);
    StringFromGUID2(&a->guid, gs, 40);
    wcscat(r->wszName, gs);
    r->dwIndex = a->index;
    r->dwType = a->type;
    r->dwMtu = a->mtu;
    r->dwSpeed = (DWORD)min(a->speed, 0xFFFFFFFF);
    r->dwPhysAddrLen = a->macLen;
    memcpy(r->bPhysAddr, a->mac, a->macLen);
    r->dwAdminStatus = a->adminStatus;
    r->dwOperStatus = (a->operStatus == IfOperStatusUp) ? MIB_IF_OPER_STATUS_OPERATIONAL : MIB_IF_OPER_STATUS_NON_OPERATIONAL;
    r->dwDescrLen = (DWORD)strlen(a->description);
    strcpy((char*)r->bDescr, a->description);
}

static void FillIfRow2(MIB_IF_ROW2* r, const FakeAdapter* a) {
    r->InterfaceLuid = a->luid;
    r->InterfaceIndex = a->index;
    r->InterfaceGuid = a->guid;
    wcscpy(r->Alias, a->friendlyName);
    wcscpy(r->Description, a->descriptionW);
    r->PhysicalAddressLength = a->macLen;
    memcpy(r->PhysicalAddress, a->mac, a->macLen);
    memcpy(r->PermanentPhysicalAddress, a->mac, a->macLen);
    r->Mtu = a->mtu;
    r->Type = a->type;
    r->TunnelType = TUNNEL_TYPE_NONE;
    r->MediaType = NdisMedium802_3;
    r->AccessType = NET_IF_ACCESS_BROADCAST;
    r->DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
    r->InterfaceAndOperStatusFlags.HardwareInterface = (a->type != IF_TYPE_SOFTWARE_LOOPBACK);
    r->InterfaceAndOperStatusFlags.FilterInterface = FALSE;
    r->InterfaceAndOperStatusFlags.ConnectorPresent = (a->type != IF_TYPE_SOFTWARE_LOOPBACK);
    r->InterfaceAndOperStatusFlags.NotAuthenticated = FALSE;
    r->InterfaceAndOperStatusFlags.NotMediaConnected = (a->mediaState == MediaConnectStateDisconnected);
    r->OperStatus = a->operStatus;
    r->AdminStatus = (a->adminStatus == MIB_IF_ADMIN_STATUS_UP) ? NET_IF_ADMIN_STATUS_UP : NET_IF_ADMIN_STATUS_DOWN;
    r->MediaConnectState = a->mediaState;
    r->ConnectionType = a->connType;
    r->TransmitLinkSpeed = a->speed;
    r->ReceiveLinkSpeed = a->speed;
}

/* ============================================================================
 * MAIN API IMPLEMENTATIONS
 * ============================================================================ */

DWORD WINAPI ex_GetAdaptersInfo(PIP_ADAPTER_INFO pInfo, PULONG pSize) {
    EnsureInit();
    LogI("GetAdaptersInfo");
    
    if (!pSize) return ERROR_INVALID_PARAMETER;
    
    DWORD count = 0;
    for (int i = 0; i < g_Net.adapterCount; i++)
        if (g_Net.adapters[i].type != IF_TYPE_SOFTWARE_LOOPBACK) count++;
    
    if (count == 0) return ERROR_NO_DATA;
    
    DWORD needed = count * sizeof(IP_ADAPTER_INFO);
    if (!pInfo || *pSize < needed) {
        *pSize = needed;
        return ERROR_BUFFER_OVERFLOW;
    }
    
    memset(pInfo, 0, *pSize);
    PIP_ADAPTER_INFO cur = pInfo;
    DWORD idx = 0;
    
    for (int i = 0; i < g_Net.adapterCount; i++) {
        FakeAdapter* a = &g_Net.adapters[i];
        if (a->type == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        
        strncpy(cur->AdapterName, a->name, sizeof(cur->AdapterName) - 1);
        strncpy(cur->Description, a->description, sizeof(cur->Description) - 1);
        cur->AddressLength = a->macLen;
        memcpy(cur->Address, a->mac, a->macLen);
        cur->Index = a->index;
        cur->Type = a->type;
        cur->DhcpEnabled = a->dhcpEnabled;
        
        strcpy(cur->IpAddressList.IpAddress.String, "0.0.0.0");
        strcpy(cur->IpAddressList.IpMask.String, "0.0.0.0");
        cur->GatewayList.IpAddress.String[0] = '\0';
        cur->HaveWins = FALSE;
        
        idx++;
        if (idx < count) { cur->Next = cur + 1; cur++; }
        else cur->Next = NULL;
    }
    
    LogI("  -> %lu adapters (all disconnected)", count);
    return NO_ERROR;
}

DWORD WINAPI ex_GetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved,
                                      PIP_ADAPTER_ADDRESSES pAddr, PULONG pSize) {
    EnsureInit();
    LogI("GetAdaptersAddresses(family=%lu, flags=0x%lx)", Family, Flags);
    (void)Reserved;
    
    if (!pSize) return ERROR_INVALID_PARAMETER;
    if (Family != AF_INET && Family != AF_INET6 && Family != AF_UNSPEC)
        return ERROR_INVALID_PARAMETER;
    
    DWORD needed = 0;
    for (int i = 0; i < g_Net.adapterCount; i++) {
        FakeAdapter* a = &g_Net.adapters[i];
        needed += sizeof(IP_ADAPTER_ADDRESSES);
        needed += (wcslen(a->descriptionW) + 1) * sizeof(WCHAR);
        needed += (wcslen(a->friendlyName) + 1) * sizeof(WCHAR);
        needed += (wcslen(a->dnsSuffix) + 1) * sizeof(WCHAR);
        needed += (strlen(a->name) + 2) & ~1;
        
        if (!(Flags & GAA_FLAG_SKIP_UNICAST) && a->type == IF_TYPE_SOFTWARE_LOOPBACK) {
            for (int j = 0; j < a->ipCount; j++) {
                if (Family != AF_UNSPEC && a->ips[j].family != Family) continue;
                needed += sizeof(IP_ADAPTER_UNICAST_ADDRESS);
                needed += (a->ips[j].family == AF_INET) ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6);
            }
        }
    }
    needed = (needed + 7) & ~7;
    
    if (!pAddr || *pSize < needed) {
        *pSize = needed;
        return ERROR_BUFFER_OVERFLOW;
    }
    
    memset(pAddr, 0, *pSize);
    char* ptr = (char*)(pAddr + g_Net.adapterCount);
    PIP_ADAPTER_ADDRESSES cur = pAddr;
    
    for (int i = 0; i < g_Net.adapterCount; i++) {
        FakeAdapter* a = &g_Net.adapters[i];
        
        cur->Length = sizeof(IP_ADAPTER_ADDRESSES);
        cur->IfIndex = a->index;
        cur->Luid = a->luid;
        cur->IfType = a->type;
        cur->OperStatus = a->operStatus;
        cur->Mtu = a->mtu;
        cur->TransmitLinkSpeed = a->speed;
        cur->ReceiveLinkSpeed = a->speed;
        cur->PhysicalAddressLength = a->macLen;
        memcpy(cur->PhysicalAddress, a->mac, a->macLen);
        cur->Flags = a->dhcpEnabled ? IP_ADAPTER_DHCP_ENABLED : 0;
        cur->ConnectionType = a->connType;
        
        cur->AdapterName = ptr;
        strcpy(ptr, a->name);
        ptr += (strlen(a->name) + 2) & ~1;
        
        cur->Description = (WCHAR*)ptr;
        wcscpy((WCHAR*)ptr, a->descriptionW);
        ptr += (wcslen(a->descriptionW) + 1) * sizeof(WCHAR);
        
        cur->FriendlyName = (WCHAR*)ptr;
        wcscpy((WCHAR*)ptr, a->friendlyName);
        ptr += (wcslen(a->friendlyName) + 1) * sizeof(WCHAR);
        
        cur->DnsSuffix = (WCHAR*)ptr;
        wcscpy((WCHAR*)ptr, a->dnsSuffix);
        ptr += (wcslen(a->dnsSuffix) + 1) * sizeof(WCHAR);
        
        if (!(Flags & GAA_FLAG_SKIP_UNICAST) && a->type == IF_TYPE_SOFTWARE_LOOPBACK) {
            PIP_ADAPTER_UNICAST_ADDRESS pUni = NULL, pPrev = NULL;
            for (int j = 0; j < a->ipCount; j++) {
                FakeIP* ip = &a->ips[j];
                if (Family != AF_UNSPEC && ip->family != Family) continue;
                
                pUni = (PIP_ADAPTER_UNICAST_ADDRESS)ptr;
                ptr += sizeof(IP_ADAPTER_UNICAST_ADDRESS);
                pUni->Length = sizeof(IP_ADAPTER_UNICAST_ADDRESS);
                pUni->Address.lpSockaddr = (SOCKADDR*)ptr;
                
                if (ip->family == AF_INET) {
                    SOCKADDR_IN* s = (SOCKADDR_IN*)ptr;
                    s->sin_family = AF_INET;
                    s->sin_addr.s_addr = ip->addr4;
                    pUni->Address.iSockaddrLength = sizeof(SOCKADDR_IN);
                    ptr += sizeof(SOCKADDR_IN);
                    cur->Ipv4Enabled = TRUE;
                } else {
                    SOCKADDR_IN6* s = (SOCKADDR_IN6*)ptr;
                    s->sin6_family = AF_INET6;
                    s->sin6_addr = ip->addr6;
                    pUni->Address.iSockaddrLength = sizeof(SOCKADDR_IN6);
                    ptr += sizeof(SOCKADDR_IN6);
                    cur->Ipv6Enabled = TRUE;
                }
                
                pUni->OnLinkPrefixLength = ip->prefixLen;
                pUni->DadState = IpDadStatePreferred;
                
                if (pPrev) pPrev->Next = pUni;
                else cur->FirstUnicastAddress = pUni;
                pPrev = pUni;
            }
        }
        
        cur->FirstDnsServerAddress = NULL;
        cur->FirstGatewayAddress = NULL;
        cur->Ipv4Metric = 50;
        cur->Ipv6Metric = 50;
        
        if (i < g_Net.adapterCount - 1) {
            cur->Next = cur + 1;
            cur++;
        } else {
            cur->Next = NULL;
        }
    }
    
    LogI("  -> %d adapters", g_Net.adapterCount);
    return NO_ERROR;
}

static int IfRowCmp(const void* a, const void* b) {
    return ((MIB_IFROW*)a)->dwIndex - ((MIB_IFROW*)b)->dwIndex;
}

DWORD WINAPI ex_GetIfTable(PMIB_IFTABLE pTable, PULONG pSize, BOOL bOrder) {
    EnsureInit();
    LogI("GetIfTable");
    
    if (!pSize) return ERROR_INVALID_PARAMETER;
    
    DWORD needed = FIELD_OFFSET(MIB_IFTABLE, table[g_Net.adapterCount]);
    if (!pTable || *pSize < needed) { *pSize = needed; return ERROR_INSUFFICIENT_BUFFER; }
    
    memset(pTable, 0, *pSize);
    pTable->dwNumEntries = g_Net.adapterCount;
    
    for (int i = 0; i < g_Net.adapterCount; i++)
        FillIfRow(&pTable->table[i], &g_Net.adapters[i]);
    
    if (bOrder) qsort(pTable->table, pTable->dwNumEntries, sizeof(MIB_IFROW), IfRowCmp);
    return NO_ERROR;
}

DWORD WINAPI ex_GetIfEntry(PMIB_IFROW r) {
    EnsureInit();
    if (!r) return ERROR_INVALID_PARAMETER;
    FakeAdapter* a = FindByIndex(r->dwIndex);
    if (!a) return ERROR_NOT_FOUND;
    FillIfRow(r, a);
    return NO_ERROR;
}

DWORD WINAPI ex_GetIfTable2Ex(MIB_IF_TABLE_LEVEL Level, PMIB_IF_TABLE2* ppTable) {
    EnsureInit();
    LogI("GetIfTable2Ex");
    (void)Level;
    
    if (!ppTable) return ERROR_INVALID_PARAMETER;
    
    DWORD size = FIELD_OFFSET(MIB_IF_TABLE2, Table[g_Net.adapterCount]);
    *ppTable = (PMIB_IF_TABLE2)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!*ppTable) return ERROR_NOT_ENOUGH_MEMORY;
    
    (*ppTable)->NumEntries = g_Net.adapterCount;
    for (int i = 0; i < g_Net.adapterCount; i++)
        FillIfRow2(&(*ppTable)->Table[i], &g_Net.adapters[i]);
    
    return NO_ERROR;
}

DWORD WINAPI ex_GetIfTable2(PMIB_IF_TABLE2* t) { return ex_GetIfTable2Ex(MibIfTableNormal, t); }

DWORD WINAPI ex_GetIfEntry2Ex(MIB_IF_TABLE_LEVEL Level, PMIB_IF_ROW2 r) {
    EnsureInit();
    (void)Level;
    if (!r) return ERROR_INVALID_PARAMETER;
    FakeAdapter* a = r->InterfaceLuid.Value ? FindByLuid(&r->InterfaceLuid) : FindByIndex(r->InterfaceIndex);
    if (!a) return ERROR_NOT_FOUND;
    FillIfRow2(r, a);
    return NO_ERROR;
}

DWORD WINAPI ex_GetIfEntry2(PMIB_IF_ROW2 r) { return ex_GetIfEntry2Ex(MibIfTableNormal, r); }

DWORD WINAPI ex_GetIpAddrTable(PMIB_IPADDRTABLE pTable, PULONG pSize, BOOL bOrder) {
    EnsureInit();
    LogI("GetIpAddrTable");
    (void)bOrder;
    
    if (!pSize) return ERROR_INVALID_PARAMETER;
    
    DWORD count = 0;
    for (int i = 0; i < g_Net.adapterCount; i++)
        for (int j = 0; j < g_Net.adapters[i].ipCount; j++)
            if (g_Net.adapters[i].ips[j].family == AF_INET) count++;
    
    DWORD needed = FIELD_OFFSET(MIB_IPADDRTABLE, table[count]);
    if (!pTable || *pSize < needed) { *pSize = needed; return ERROR_INSUFFICIENT_BUFFER; }
    
    memset(pTable, 0, *pSize);
    pTable->dwNumEntries = count;
    
    DWORD idx = 0;
    for (int i = 0; i < g_Net.adapterCount; i++) {
        FakeAdapter* a = &g_Net.adapters[i];
        for (int j = 0; j < a->ipCount; j++) {
            FakeIP* ip = &a->ips[j];
            if (ip->family != AF_INET) continue;
            
            MIB_IPADDRROW* r = &pTable->table[idx++];
            r->dwAddr = ip->addr4;
            r->dwIndex = a->index;
            LocalConvertLengthToIpv4Mask(ip->prefixLen, &r->dwMask);
            r->dwBCastAddr = 1;
            r->dwReasmSize = 0xFFFF;
            r->wType = MIB_IPADDR_PRIMARY;
        }
    }
    
    return NO_ERROR;
}

DWORD WINAPI ex_GetIpForwardTable(PMIB_IPFORWARDTABLE pTable, PULONG pSize, BOOL bOrder) {
    EnsureInit();
    LogI("GetIpForwardTable");
    (void)bOrder;
    
    if (!pSize) return ERROR_INVALID_PARAMETER;
    
    DWORD needed = FIELD_OFFSET(MIB_IPFORWARDTABLE, table[1]);
    if (!pTable || *pSize < needed) { *pSize = needed; return ERROR_INSUFFICIENT_BUFFER; }
    
    memset(pTable, 0, *pSize);
    pTable->dwNumEntries = 1;
    
    pTable->table[0].dwForwardDest = htonl(0x7F000000);
    pTable->table[0].dwForwardMask = htonl(0xFF000000);
    pTable->table[0].dwForwardNextHop = htonl(0x7F000001);
    pTable->table[0].dwForwardIfIndex = 1;
    pTable->table[0].dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
    pTable->table[0].dwForwardProto = MIB_IPPROTO_LOCAL;
    pTable->table[0].dwForwardMetric1 = 331;
    
    return NO_ERROR;
}

DWORD WINAPI ex_GetNetworkParams(PFIXED_INFO pInfo, PULONG pSize) {
    EnsureInit();
    LogI("GetNetworkParams");
    
    if (!pSize) return ERROR_INVALID_PARAMETER;
    
    DWORD needed = sizeof(FIXED_INFO);
    if (!pInfo || *pSize < needed) { *pSize = needed; return ERROR_BUFFER_OVERFLOW; }
    
    memset(pInfo, 0, *pSize);
    strcpy(pInfo->HostName, g_Net.hostName);
    strcpy(pInfo->DomainName, g_Net.domainName);
    pInfo->NodeType = HYBRID_NODETYPE;
    pInfo->EnableRouting = FALSE;
    pInfo->EnableProxy = FALSE;
    pInfo->EnableDns = FALSE;
    pInfo->DnsServerList.IpAddress.String[0] = '\0';
    pInfo->CurrentDnsServer = &pInfo->DnsServerList;
    
    return NO_ERROR;
}

DWORD WINAPI ex_GetBestInterface(IPAddr dwDestAddr, PDWORD pdwBestIfIndex) {
    EnsureInit();
    LogI("GetBestInterface -> ERROR (nothing connected)");
    (void)dwDestAddr;
    
    if (!pdwBestIfIndex) return ERROR_INVALID_PARAMETER;
    
    for (int i = 0; i < g_Net.adapterCount; i++) {
        if (g_Net.adapters[i].type == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (g_Net.adapters[i].operStatus == IfOperStatusUp) {
            *pdwBestIfIndex = g_Net.adapters[i].index;
            return NO_ERROR;
        }
    }
    
    return ERROR_NETWORK_UNREACHABLE;
}

DWORD WINAPI ex_GetBestInterfaceEx(struct sockaddr* pDestAddr, PDWORD pdwBestIfIndex) {
    (void)pDestAddr;
    return ex_GetBestInterface(0, pdwBestIfIndex);
}

DWORD WINAPI ex_GetBestRoute(DWORD dwDestAddr, DWORD dwSourceAddr, PMIB_IPFORWARDROW pBestRoute) {
    EnsureInit();
    LogI("GetBestRoute -> ERROR_NETWORK_UNREACHABLE");
    (void)dwSourceAddr;
    
    if (!pBestRoute) return ERROR_INVALID_PARAMETER;
    
    if ((ntohl(dwDestAddr) & 0xFF000000) == 0x7F000000) {
        pBestRoute->dwForwardDest = htonl(0x7F000000);
        pBestRoute->dwForwardMask = htonl(0xFF000000);
        pBestRoute->dwForwardNextHop = htonl(0x7F000001);
        pBestRoute->dwForwardIfIndex = 1;
        pBestRoute->dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
        pBestRoute->dwForwardProto = MIB_IPPROTO_LOCAL;
        pBestRoute->dwForwardMetric1 = 331;
        return NO_ERROR;
    }
    
    return ERROR_NETWORK_UNREACHABLE;
}

/* Statistics */
DWORD WINAPI ex_GetIpStatistics(PMIB_IPSTATS s) { EnsureInit(); if(!s)return ERROR_INVALID_PARAMETER; memcpy(s,&g_Net.ipStats,sizeof(*s)); return NO_ERROR; }
DWORD WINAPI ex_GetIpStatisticsEx(PMIB_IPSTATS s, DWORD f) { (void)f; return ex_GetIpStatistics(s); }
DWORD WINAPI ex_GetTcpStatistics(PMIB_TCPSTATS s) { EnsureInit(); if(!s)return ERROR_INVALID_PARAMETER; memcpy(s,&g_Net.tcpStats,sizeof(*s)); return NO_ERROR; }
DWORD WINAPI ex_GetTcpStatisticsEx(PMIB_TCPSTATS s, DWORD f) { (void)f; return ex_GetTcpStatistics(s); }
DWORD WINAPI ex_GetUdpStatistics(PMIB_UDPSTATS s) { EnsureInit(); if(!s)return ERROR_INVALID_PARAMETER; memcpy(s,&g_Net.udpStats,sizeof(*s)); return NO_ERROR; }
DWORD WINAPI ex_GetUdpStatisticsEx(PMIB_UDPSTATS s, DWORD f) { (void)f; return ex_GetUdpStatistics(s); }
DWORD WINAPI ex_GetIcmpStatistics(PMIB_ICMP s) { EnsureInit(); if(!s)return ERROR_INVALID_PARAMETER; memcpy(s,&g_Net.icmpStats,sizeof(*s)); return NO_ERROR; }

/* Empty Tables */
DWORD WINAPI ex_GetTcpTable(PMIB_TCPTABLE t, PDWORD s, BOOL o) { EnsureInit(); (void)o; if(!s)return ERROR_INVALID_PARAMETER; DWORD n=FIELD_OFFSET(MIB_TCPTABLE,table[0]); if(!t||*s<n){*s=n;return ERROR_INSUFFICIENT_BUFFER;} t->dwNumEntries=0; return NO_ERROR; }
DWORD WINAPI ex_GetTcp6Table(PMIB_TCP6TABLE t, PDWORD s, BOOL o) { EnsureInit(); (void)o; if(!s)return ERROR_INVALID_PARAMETER; DWORD n=FIELD_OFFSET(MIB_TCP6TABLE,table[0]); if(!t||*s<n){*s=n;return ERROR_INSUFFICIENT_BUFFER;} t->dwNumEntries=0; return NO_ERROR; }
DWORD WINAPI ex_GetUdpTable(PMIB_UDPTABLE t, PDWORD s, BOOL o) { EnsureInit(); (void)o; if(!s)return ERROR_INVALID_PARAMETER; DWORD n=FIELD_OFFSET(MIB_UDPTABLE,table[0]); if(!t||*s<n){*s=n;return ERROR_INSUFFICIENT_BUFFER;} t->dwNumEntries=0; return NO_ERROR; }
DWORD WINAPI ex_GetUdp6Table(PMIB_UDP6TABLE t, PDWORD s, BOOL o) { EnsureInit(); (void)o; if(!s)return ERROR_INVALID_PARAMETER; DWORD n=FIELD_OFFSET(MIB_UDP6TABLE,table[0]); if(!t||*s<n){*s=n;return ERROR_INSUFFICIENT_BUFFER;} t->dwNumEntries=0; return NO_ERROR; }
DWORD WINAPI ex_GetExtendedTcpTable(PVOID t, PDWORD s, BOOL o, ULONG f, TCP_TABLE_CLASS c, ULONG r) { EnsureInit(); (void)o;(void)f;(void)c;(void)r; if(!s)return ERROR_INVALID_PARAMETER; if(!t||*s<sizeof(DWORD)){*s=sizeof(DWORD);return ERROR_INSUFFICIENT_BUFFER;} *(DWORD*)t=0; return NO_ERROR; }
DWORD WINAPI ex_GetExtendedUdpTable(PVOID t, PDWORD s, BOOL o, ULONG f, UDP_TABLE_CLASS c, ULONG r) { EnsureInit(); (void)o;(void)f;(void)c;(void)r; if(!s)return ERROR_INVALID_PARAMETER; if(!t||*s<sizeof(DWORD)){*s=sizeof(DWORD);return ERROR_INSUFFICIENT_BUFFER;} *(DWORD*)t=0; return NO_ERROR; }
DWORD WINAPI ex_GetIpNetTable(PMIB_IPNETTABLE t, PULONG s, BOOL o) { EnsureInit(); (void)o; if(!s)return ERROR_INVALID_PARAMETER; DWORD n=FIELD_OFFSET(MIB_IPNETTABLE,table[0]); if(!t||*s<n){*s=n;return ERROR_INSUFFICIENT_BUFFER;} t->dwNumEntries=0; return ERROR_NO_DATA; }

/* Convert functions */
DWORD WINAPI ex_ConvertInterfaceIndexToLuid(NET_IFINDEX i, PNET_LUID l) { EnsureInit(); if(!l)return ERROR_INVALID_PARAMETER; FakeAdapter*a=FindByIndex(i); if(!a){l->Value=0;return ERROR_FILE_NOT_FOUND;} *l=a->luid; return NO_ERROR; }
DWORD WINAPI ex_ConvertInterfaceLuidToIndex(const NET_LUID* l, PNET_IFINDEX i) { EnsureInit(); if(!l||!i)return ERROR_INVALID_PARAMETER; FakeAdapter*a=FindByLuid(l); if(!a){*i=0;return ERROR_FILE_NOT_FOUND;} *i=a->index; return NO_ERROR; }
DWORD WINAPI ex_ConvertInterfaceLuidToGuid(const NET_LUID* l, GUID* g) { EnsureInit(); if(!l||!g)return ERROR_INVALID_PARAMETER; FakeAdapter*a=FindByLuid(l); if(!a){memset(g,0,sizeof(GUID));return ERROR_FILE_NOT_FOUND;} *g=a->guid; return NO_ERROR; }
DWORD WINAPI ex_ConvertInterfaceGuidToLuid(const GUID* g, PNET_LUID l) { EnsureInit(); if(!g||!l)return ERROR_INVALID_PARAMETER; FakeAdapter*a=FindByGuid(g); if(!a){l->Value=0;return ERROR_FILE_NOT_FOUND;} *l=a->luid; return NO_ERROR; }
DWORD WINAPI ex_ConvertInterfaceLuidToAlias(const NET_LUID* l, PWSTR a, SIZE_T n) { EnsureInit(); if(!l||!a)return ERROR_INVALID_PARAMETER; FakeAdapter*f=FindByLuid(l); if(!f)return ERROR_FILE_NOT_FOUND; if(wcslen(f->friendlyName)>=n)return ERROR_NOT_ENOUGH_MEMORY; wcscpy(a,f->friendlyName); return NO_ERROR; }
DWORD WINAPI ex_ConvertInterfaceLuidToNameW(const NET_LUID* l, PWSTR n, SIZE_T z) { EnsureInit(); if(!l||!n)return ERROR_INVALID_PARAMETER; const WCHAR*p=(l->Info.IfType==IF_TYPE_ETHERNET_CSMACD)?L"ethernet":(l->Info.IfType==IF_TYPE_IEEE80211)?L"wifi":(l->Info.IfType==IF_TYPE_SOFTWARE_LOOPBACK)?L"loopback":L"other"; WCHAR b[64]; swprintf(b,64,L"%s_%lu",p,l->Info.NetLuidIndex); if(wcslen(b)>=z)return ERROR_NOT_ENOUGH_MEMORY; wcscpy(n,b); return NO_ERROR; }
DWORD WINAPI ex_ConvertInterfaceLuidToNameA(const NET_LUID* l, PSTR n, SIZE_T z) { WCHAR b[64]; DWORD e=ex_ConvertInterfaceLuidToNameW(l,b,64); if(e)return e; if(!WideCharToMultiByte(CP_ACP,0,b,-1,n,(int)z,NULL,NULL))return ERROR_NOT_ENOUGH_MEMORY; return NO_ERROR; }
DWORD WINAPI ex_ConvertLengthToIpv4Mask(ULONG l, PULONG m) { if(l>32){if(m)*m=INADDR_NONE;return ERROR_INVALID_PARAMETER;} if(m)*m=l?htonl(~0u<<(32-l)):0; return NO_ERROR; }
DWORD WINAPI ex_ConvertIpv4MaskToLength(ULONG m, PUINT8 l) { if(!l)return ERROR_INVALID_PARAMETER; DWORD x=ntohl(m),n=0; while(x&0x80000000){n++;x<<=1;} *l=(UINT8)n; return NO_ERROR; }
DWORD WINAPI ex_ConvertGuidToStringA(const GUID* g, PSTR s, DWORD l) { if(!g||!s||l<CHARS_IN_GUID)return ERROR_INVALID_PARAMETER; sprintf(s,"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",g->Data1,g->Data2,g->Data3,g->Data4[0],g->Data4[1],g->Data4[2],g->Data4[3],g->Data4[4],g->Data4[5],g->Data4[6],g->Data4[7]); return NO_ERROR; }
DWORD WINAPI ex_ConvertGuidToStringW(const GUID* g, PWSTR s, DWORD l) { if(!g||!s||l<CHARS_IN_GUID)return ERROR_INVALID_PARAMETER; swprintf(s,l,L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",g->Data1,g->Data2,g->Data3,g->Data4[0],g->Data4[1],g->Data4[2],g->Data4[3],g->Data4[4],g->Data4[5],g->Data4[6],g->Data4[7]); return NO_ERROR; }
DWORD WINAPI ex_ConvertStringToGuidW(const WCHAR* s, GUID* g) { if(!s||!g)return ERROR_INVALID_PARAMETER; return CLSIDFromString(s,g)==S_OK?NO_ERROR:ERROR_INVALID_PARAMETER; }

/* Other */
DWORD WINAPI ex_GetNumberOfInterfaces(PDWORD p) { EnsureInit(); if(!p)return ERROR_INVALID_PARAMETER; *p=g_Net.adapterCount; return NO_ERROR; }
DWORD WINAPI ex_GetFriendlyIfIndex(DWORD i) { return i&0x00FFFFFF; }
void WINAPI ex_FreeMibTable(PVOID m) { if(m)HeapFree(GetProcessHeap(),0,m); }

DWORD WINAPI ex_GetInterfaceInfo(PIP_INTERFACE_INFO t, PULONG s) {
    EnsureInit();
    if(!s)return ERROR_INVALID_PARAMETER;
    DWORD c=0; for(int i=0;i<g_Net.adapterCount;i++)if(g_Net.adapters[i].type!=IF_TYPE_SOFTWARE_LOOPBACK)c++;
    DWORD n=FIELD_OFFSET(IP_INTERFACE_INFO,Adapter[c]);
    if(!t||*s<n){*s=n;return ERROR_INSUFFICIENT_BUFFER;}
    t->NumAdapters=c;
    int x=0; for(int i=0;i<g_Net.adapterCount;i++){
        FakeAdapter*a=&g_Net.adapters[i]; if(a->type==IF_TYPE_SOFTWARE_LOOPBACK)continue;
        t->Adapter[x].Index=a->index;
        wcscpy(t->Adapter[x].Name,DEVICE_TCPIP);
        WCHAR gs[40]; StringFromGUID2(&a->guid,gs,40);
        wcscat(t->Adapter[x].Name,gs);
        x++;
    }
    return NO_ERROR;
}

DWORD WINAPI ex_GetPerAdapterInfo(ULONG i, PIP_PER_ADAPTER_INFO p, PULONG s) {
    EnsureInit();
    if(!s)return ERROR_INVALID_PARAMETER;
    FakeAdapter*a=FindByIndex(i); if(!a)return ERROR_NO_DATA;
    DWORD n=sizeof(IP_PER_ADAPTER_INFO);
    if(!p||*s<n){*s=n;return ERROR_BUFFER_OVERFLOW;}
    memset(p,0,*s);
    p->AutoconfigEnabled=TRUE;
    p->AutoconfigActive=FALSE;
    return NO_ERROR;
}

/* ICMP */
HANDLE WINAPI ex_IcmpCreateFile(void) { EnsureInit(); SetLastError(ERROR_NETWORK_UNREACHABLE); return INVALID_HANDLE_VALUE; }
HANDLE WINAPI ex_Icmp6CreateFile(void) { EnsureInit(); SetLastError(ERROR_NETWORK_UNREACHABLE); return INVALID_HANDLE_VALUE; }
BOOL WINAPI ex_IcmpCloseHandle(HANDLE h) { (void)h; return TRUE; }
DWORD WINAPI ex_IcmpSendEcho(HANDLE h,IPAddr d,LPVOID r,WORD rs,PIP_OPTION_INFORMATION o,LPVOID rb,DWORD rbs,DWORD t) { (void)h;(void)d;(void)r;(void)rs;(void)o;(void)rb;(void)rbs;(void)t; EnsureInit(); SetLastError(ERROR_NETWORK_UNREACHABLE); return 0; }
DWORD WINAPI ex_IcmpSendEcho2(HANDLE h,HANDLE e,PVOID a,PVOID c,IPAddr d,LPVOID r,WORD rs,PIP_OPTION_INFORMATION o,LPVOID rb,DWORD rbs,DWORD t) { (void)h;(void)e;(void)a;(void)c;(void)d;(void)r;(void)rs;(void)o;(void)rb;(void)rbs;(void)t; EnsureInit(); SetLastError(ERROR_NETWORK_UNREACHABLE); return 0; }
DWORD WINAPI ex_IcmpSendEcho2Ex(HANDLE h,HANDLE e,PVOID a,PVOID c,IPAddr ss,IPAddr d,LPVOID r,WORD rs,PIP_OPTION_INFORMATION o,LPVOID rb,DWORD rbs,DWORD t) { (void)h;(void)e;(void)a;(void)c;(void)ss;(void)d;(void)r;(void)rs;(void)o;(void)rb;(void)rbs;(void)t; EnsureInit(); SetLastError(ERROR_NETWORK_UNREACHABLE); return 0; }
DWORD WINAPI ex_IcmpParseReplies(LPVOID r,DWORD s) { (void)r;(void)s; return 0; }
DWORD WINAPI ex_Icmp6SendEcho2(HANDLE h,HANDLE e,PVOID a,PVOID c,struct sockaddr_in6*ss,struct sockaddr_in6*d,LPVOID r,WORD rs,PIP_OPTION_INFORMATION o,LPVOID rb,DWORD rbs,DWORD t) { (void)h;(void)e;(void)a;(void)c;(void)ss;(void)d;(void)r;(void)rs;(void)o;(void)rb;(void)rbs;(void)t; EnsureInit(); SetLastError(ERROR_NETWORK_UNREACHABLE); return 0; }
DWORD WINAPI ex_Icmp6ParseReplies(LPVOID r,DWORD s) { (void)r;(void)s; return 0; }

/* Notifications */
DWORD WINAPI ex_NotifyAddrChange(PHANDLE h,LPOVERLAPPED o) { (void)h;(void)o; return ERROR_IO_PENDING; }
DWORD WINAPI ex_NotifyRouteChange(PHANDLE h,LPOVERLAPPED o) { (void)h;(void)o; return ERROR_IO_PENDING; }
DWORD WINAPI ex_NotifyIpInterfaceChange(ADDRESS_FAMILY f,PVOID cb,PVOID x,BOOLEAN i,PHANDLE h) { (void)f;(void)cb;(void)x;(void)i; if(h)*h=(HANDLE)0xDEAD; return NO_ERROR; }
DWORD WINAPI ex_NotifyUnicastIpAddressChange(ADDRESS_FAMILY f,PVOID cb,PVOID x,BOOLEAN i,PHANDLE h) { (void)f;(void)cb;(void)x;(void)i; if(h)*h=(HANDLE)0xBEEF; return NO_ERROR; }
DWORD WINAPI ex_NotifyRouteChange2(ADDRESS_FAMILY f,PVOID cb,PVOID x,BOOLEAN i,PHANDLE h) { (void)f;(void)cb;(void)x;(void)i; if(h)*h=(HANDLE)0xCAFE; return NO_ERROR; }
DWORD WINAPI ex_CancelMibChangeNotify2(HANDLE h) { (void)h; return NO_ERROR; }
BOOL WINAPI ex_CancelIPChangeNotify(LPOVERLAPPED o) { (void)o; return TRUE; }

/* Stubs */
DWORD WINAPI ex_SendARP(IPAddr d,IPAddr ss,PVOID m,PULONG l) { (void)d;(void)ss;(void)m;(void)l; return ERROR_NETWORK_UNREACHABLE; }
DWORD WINAPI ex_AddIPAddress(IPAddr a,IPMask m,DWORD i,PULONG c,PULONG n) { (void)a;(void)m;(void)i;(void)c;(void)n; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DeleteIPAddress(ULONG c) { (void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetIfEntry(PMIB_IFROW r) { (void)r; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_CreateIpForwardEntry(PMIB_IPFORWARDROW r) { (void)r; return NO_ERROR; }
DWORD WINAPI ex_DeleteIpForwardEntry(PMIB_IPFORWARDROW r) { (void)r; return NO_ERROR; }
DWORD WINAPI ex_SetIpForwardEntry(PMIB_IPFORWARDROW r) { (void)r; return NO_ERROR; }
DWORD WINAPI ex_CreateIpNetEntry(PMIB_IPNETROW r) { (void)r; return NO_ERROR; }
DWORD WINAPI ex_DeleteIpNetEntry(PMIB_IPNETROW r) { (void)r; return NO_ERROR; }
DWORD WINAPI ex_SetIpNetEntry(PMIB_IPNETROW r) { (void)r; return NO_ERROR; }
DWORD WINAPI ex_FlushIpNetTable(DWORD i) { (void)i; return NO_ERROR; }
DWORD WINAPI ex_SetIpStatistics(PMIB_IPSTATS ss) { (void)ss; return NO_ERROR; }
DWORD WINAPI ex_SetIpTTL(UINT t) { (void)t; return NO_ERROR; }
DWORD WINAPI ex_SetTcpEntry(PMIB_TCPROW r) { (void)r; return NO_ERROR; }
DWORD WINAPI ex_IpReleaseAddress(PIP_ADAPTER_INDEX_MAP a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_IpRenewAddress(PIP_ADAPTER_INDEX_MAP a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_EnableRouter(PHANDLE h,LPOVERLAPPED o) { (void)h;(void)o; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_UnenableRouter(LPOVERLAPPED o,LPDWORD c) { (void)o;(void)c; return ERROR_NOT_SUPPORTED; }
BOOL WINAPI ex_GetRTTAndHopCount(IPAddr d,PULONG h,ULONG m,PULONG r) { (void)d;(void)m; if(h)*h=0; if(r)*r=0; return FALSE; }
NET_IF_COMPARTMENT_ID WINAPI ex_GetCurrentThreadCompartmentId(void) { return (NET_IF_COMPARTMENT_ID)NET_IF_COMPARTMENT_ID_PRIMARY; }
DWORD WINAPI ex_SetCurrentThreadCompartmentId(NET_IF_COMPARTMENT_ID i) { (void)i; return NO_ERROR; }
DWORD WINAPI ex_GetAdapterIndex(LPWSTR n,PULONG i) { (void)n;(void)i; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_CreateProxyArpEntry(DWORD a,DWORD m,DWORD i) { (void)a;(void)m;(void)i; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DeleteProxyArpEntry(DWORD a,DWORD m,DWORD i) { (void)a;(void)m;(void)i; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetUniDirectionalAdapterInfo(PIP_UNIDIRECTIONAL_ADAPTER_ADDRESS i,PULONG ss) { (void)i;(void)ss; return ERROR_NOT_SUPPORTED; }

/* Allocate functions */
DWORD WINAPI ex_AllocateAndGetIfTableFromStack(PMIB_IFTABLE*t,BOOL o,HANDLE h,DWORD f) { if(!t)return ERROR_INVALID_PARAMETER; DWORD ss=0;ex_GetIfTable(NULL,&ss,o); *t=(PMIB_IFTABLE)HeapAlloc(h,f,ss); if(!*t)return ERROR_NOT_ENOUGH_MEMORY; return ex_GetIfTable(*t,&ss,o); }
DWORD WINAPI ex_AllocateAndGetIpAddrTableFromStack(PMIB_IPADDRTABLE*t,BOOL o,HANDLE h,DWORD f) { if(!t)return ERROR_INVALID_PARAMETER; DWORD ss=0;ex_GetIpAddrTable(NULL,&ss,o); *t=(PMIB_IPADDRTABLE)HeapAlloc(h,f,ss); if(!*t)return ERROR_NOT_ENOUGH_MEMORY; return ex_GetIpAddrTable(*t,&ss,o); }
DWORD WINAPI ex_AllocateAndGetIpForwardTableFromStack(PMIB_IPFORWARDTABLE*t,BOOL o,HANDLE h,DWORD f) { if(!t)return ERROR_INVALID_PARAMETER; DWORD ss=0;ex_GetIpForwardTable(NULL,&ss,o); *t=(PMIB_IPFORWARDTABLE)HeapAlloc(h,f,ss); if(!*t)return ERROR_NOT_ENOUGH_MEMORY; return ex_GetIpForwardTable(*t,&ss,o); }
DWORD WINAPI ex_AllocateAndGetTcpTableFromStack(PMIB_TCPTABLE*t,BOOL o,HANDLE h,DWORD f) { if(!t)return ERROR_INVALID_PARAMETER; DWORD ss=0;ex_GetTcpTable(NULL,&ss,o); *t=(PMIB_TCPTABLE)HeapAlloc(h,f,ss); if(!*t)return ERROR_NOT_ENOUGH_MEMORY; return ex_GetTcpTable(*t,&ss,o); }
DWORD WINAPI ex_AllocateAndGetUdpTableFromStack(PMIB_UDPTABLE*t,BOOL o,HANDLE h,DWORD f) { if(!t)return ERROR_INVALID_PARAMETER; DWORD ss=0;ex_GetUdpTable(NULL,&ss,o); *t=(PMIB_UDPTABLE)HeapAlloc(h,f,ss); if(!*t)return ERROR_NOT_ENOUGH_MEMORY; return ex_GetUdpTable(*t,&ss,o); }
DWORD WINAPI ex_AllocateAndGetIpNetTableFromStack(PMIB_IPNETTABLE*t,BOOL o,HANDLE h,DWORD f) { if(!t)return ERROR_INVALID_PARAMETER; DWORD ss=0;ex_GetIpNetTable(NULL,&ss,o); *t=(PMIB_IPNETTABLE)HeapAlloc(h,f,ss); if(!*t)return ERROR_NOT_ENOUGH_MEMORY; return ex_GetIpNetTable(*t,&ss,o); }

/* ============================================================================
 * ALL REMAINING STUBS
 * ============================================================================ */

DWORD WINAPI ex_AllocateAndGetInterfaceInfoFromStack(PVOID a
,PDWORD b,BOOL c,HANDLE d,DWORD e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_AllocateAndGetTcpExTableFromStack(PVOID a,BOOL b,HANDLE c,DWORD d,DWORD e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_AllocateAndGetUdpExTableFromStack(PVOID a,BOOL b,HANDLE c,DWORD d,DWORD e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }

void WINAPI ex_CancelIfTimestampConfigChange(HANDLE h) { (void)h; }
void WINAPI ex_CloseCompartment(HANDLE h) { (void)h; }
void WINAPI ex_CloseGetIPPhysicalInterfaceForDestination(HANDLE h) { (void)h; }
DWORD WINAPI ex_CaptureInterfaceHardwareCrossTimestamp(PVOID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertCompartmentGuidToId(PVOID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertCompartmentIdToGuid(DWORD a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_CreateCompartment(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
void WINAPI ex_DeleteCompartment(HANDLE h) { (void)h; }
DWORD WINAPI ex_GetCompartmentId(void) { return 1; }
DWORD WINAPI ex_OpenCompartment(DWORD a,PHANDLE b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
void WINAPI ex_GetCurrentThreadCompartmentScope(PVOID a,PVOID b) { (void)a;(void)b; }
void WINAPI ex_SetCurrentThreadCompartmentScope(DWORD a,DWORD b) { (void)a;(void)b; }
DWORD WINAPI ex_GetDefaultCompartmentId(void) { return 1; }
DWORD WINAPI ex_GetSessionCompartmentId(DWORD a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetSessionCompartmentId(DWORD a,DWORD b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetJobCompartmentId(HANDLE a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetJobCompartmentId(HANDLE a,DWORD b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
void WINAPI ex_InitializeCompartmentEntry(PVOID a) { (void)a; }
DWORD WINAPI ex_NotifyCompartmentChange(PVOID a,PVOID b,PVOID c,BOOL d,PHANDLE e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertInterfaceAliasToLuid(PCWSTR a,PNET_LUID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertInterfaceNameToLuidA(PCSTR a,PNET_LUID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertInterfaceNameToLuidW(PCWSTR a,PNET_LUID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertInterfacePhysicalAddressToLuid(PVOID a,DWORD b,PNET_LUID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertStringToGuidA(PCSTR a,GUID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertStringToInterfacePhysicalAddress(PCWSTR a,PVOID b,PVOID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertRemoteInterfaceAliasToLuid(PCWSTR a,PCWSTR b,PNET_LUID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertRemoteInterfaceGuidToLuid(PCWSTR a,GUID* b,PNET_LUID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertRemoteInterfaceIndexToLuid(PCWSTR a,DWORD b,PNET_LUID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertRemoteInterfaceLuidToAlias(PCWSTR a,PNET_LUID b,PWSTR c,DWORD d) { (void)a;(void)b;(void)c;(void)d; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertRemoteInterfaceLuidToGuid(PCWSTR a,PNET_LUID b,GUID* c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ConvertRemoteInterfaceLuidToIndex(PCWSTR a,PNET_LUID b,PDWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_CreateAnycastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DeleteAnycastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetAnycastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetAnycastIpAddressTable(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_CreateUnicastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DeleteUnicastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetUnicastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetUnicastIpAddressTable(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetUnicastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
void WINAPI ex_InitializeUnicastIpAddressEntry(PVOID a) { (void)a; }
DWORD WINAPI ex_NotifyStableUnicastIpAddressTable(DWORD a,PVOID* b,PVOID c,PVOID d,PHANDLE e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetMulticastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetMulticastIpAddressTable(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_CreateIpForwardEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DeleteIpForwardEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetIpForwardEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetIpForwardTable2(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetIpForwardEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
void WINAPI ex_InitializeIpForwardEntry(PVOID a) { (void)a; }
DWORD WINAPI ex_CreateIpNetEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DeleteIpNetEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetIpNetEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetIpNetTable2(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetIpNetEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_FlushIpNetTable2(DWORD a,DWORD b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ResolveIpNetEntry2(PVOID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetIpInterfaceEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetIpInterfaceTable(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetIpInterfaceEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
void WINAPI ex_InitializeIpInterfaceEntry(PVOID a) { (void)a; }
DWORD WINAPI ex_FlushIpPathTable(DWORD a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetIpPathEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetIpPathTable(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetIfStackTable(PVOID* a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetInvertedIfStackTable(PVOID* a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetTcpTable2(PVOID* a,BOOL b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetTcp6Table2(PVOID* a,BOOL b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetTcpStatisticsEx2(PVOID a,DWORD b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetUdpStatisticsEx2(PVOID a,DWORD b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetIcmpStatisticsEx(PVOID a,DWORD b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_CreatePersistentTcpPortReservation(WORD a,WORD b,PVOID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_CreatePersistentUdpPortReservation(WORD a,WORD b,PVOID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DeletePersistentTcpPortReservation(WORD a,WORD b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DeletePersistentUdpPortReservation(WORD a,WORD b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_LookupPersistentTcpPortReservation(WORD a,WORD b,PVOID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_LookupPersistentUdpPortReservation(WORD a,WORD b,PVOID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
void WINAPI ex_InitializeFlVirtualInterfaceEntry(PVOID a) { (void)a; }
DWORD WINAPI ex_CreateFlVirtualInterface(PVOID a,PVOID b,PNET_LUID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
void WINAPI ex_DeleteFlVirtualInterface(PNET_LUID a) { (void)a; }
DWORD WINAPI ex_GetFlVirtualInterface(PNET_LUID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetFlVirtualInterfaceTable(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetFlVirtualInterface(PNET_LUID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
void WINAPI ex_FreeDnsSettings(PVOID a) { (void)a; }
void WINAPI ex_FreeInterfaceDnsSettings(PVOID a) { (void)a; }
DWORD WINAPI ex_GetDnsSettings(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetDnsSettings(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetInterfaceDnsSettings(GUID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetInterfaceDnsSettings(GUID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetInterfaceActiveTimestampCapabilities(PNET_LUID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetInterfaceCurrentTimestampCapabilities(PNET_LUID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetInterfaceHardwareTimestampCapabilities(PNET_LUID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetInterfaceSupportedTimestampCapabilities(PNET_LUID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NotifyIfTimestampConfigChange(PVOID a,PVOID b,PHANDLE c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_RegisterInterfaceTimestampConfigChange(PVOID a,PVOID b,PHANDLE c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
void WINAPI ex_UnregisterInterfaceTimestampConfigChange(HANDLE h) { (void)h; }
DWORD WINAPI ex_GetNetworkConnectivityHint(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetNetworkConnectivityHintForInterface(DWORD a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NotifyNetworkConnectivityHintChange(PVOID a,PVOID b,BOOL c,PHANDLE d) { (void)a;(void)b;(void)c;(void)d; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetNetworkInformation(GUID* a,PVOID b,PVOID c,PVOID d,PVOID e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetNetworkInformation(GUID* a,DWORD b,PVOID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetIpNetworkConnectionBandwidthEstimates(DWORD a,DWORD b,PVOID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetTeredoPort(PUSHORT a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NotifyTeredoPortChange(PVOID a,PVOID b,BOOL c,PHANDLE d) { (void)a;(void)b;(void)c;(void)d; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_CreateSortedAddressPairs(PVOID a,DWORD b,PVOID c,DWORD d,DWORD e,PVOID* f,PDWORD g) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetOwnerModuleFromPidAndInfo(DWORD a,PVOID b,DWORD c,PVOID d,PDWORD e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetOwnerModuleFromTcpEntry(PVOID a,DWORD b,PVOID c,PDWORD d) { (void)a;(void)b;(void)c;(void)d; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetOwnerModuleFromTcp6Entry(PVOID a,DWORD b,PVOID c,PDWORD d) { (void)a;(void)b;(void)c;(void)d; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetOwnerModuleFromUdpEntry(PVOID a,DWORD b,PVOID c,PDWORD d) { (void)a;(void)b;(void)c;(void)d; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetOwnerModuleFromUdp6Entry(PVOID a,DWORD b,PVOID c,PDWORD d) { (void)a;(void)b;(void)c;(void)d; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetPerTcpConnectionEStats(PVOID a,DWORD b,PVOID c,DWORD d,DWORD e,PVOID f,DWORD g,DWORD h,PVOID i,DWORD j,DWORD k) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetPerTcp6ConnectionEStats(PVOID a,DWORD b,PVOID c,DWORD d,DWORD e,PVOID f,DWORD g,DWORD h,PVOID i,DWORD j,DWORD k) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetPerTcpConnectionEStats(PVOID a,DWORD b,PVOID c,DWORD d,DWORD e,DWORD f) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetPerTcp6ConnectionEStats(PVOID a,DWORD b,PVOID c,DWORD d,DWORD e,DWORD f) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetPerTcpConnectionStats(PVOID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetPerTcp6ConnectionStats(PVOID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetPerTcpConnectionStats(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetPerTcp6ConnectionStats(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetIpErrorString(DWORD a,PWSTR b,PDWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
PVOID WINAPI ex_GetAdapterOrderMap(void) { return NULL; }
DWORD WINAPI ex_ResolveNeighbor(PVOID a,PVOID b,PDWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DisableMediaSense(PHANDLE a,LPOVERLAPPED b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_RestoreMediaSense(PHANDLE a,LPOVERLAPPED b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetInterfaceCompartmentId(PNET_LUID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetWPAOACSupportLevel(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_SetAdapterIpAddress(PVOID a,BOOL b,DWORD c,DWORD d,DWORD e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
void WINAPI ex_NTPTimeToNTFileTime(DWORD a,PVOID b) { (void)a;(void)b; }
void WINAPI ex_NTTimeToNTPTime(PVOID a,PDWORD b) { (void)a;(void)b; }
DWORD WINAPI ex_NhGetGuidFromInterfaceName(PCWSTR a,GUID* b,PVOID c,PVOID d) { (void)a;(void)b;(void)c;(void)d; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NhGetInterfaceDescriptionFromGuid(GUID* a,PWSTR b,PDWORD c,PVOID d,PVOID e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NhGetInterfaceNameFromDeviceGuid(GUID* a,PWSTR b,PDWORD c,BOOL d,BOOL e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NhGetInterfaceNameFromGuid(GUID* a,PWSTR b,PDWORD c,BOOL d,BOOL e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NhpAllocateAndGetInterfaceInfoFromStack(PVOID* a,PDWORD b,BOOL c,HANDLE d,DWORD e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_ParseNetworkString(PCWSTR a,DWORD b,PVOID c,PVOID d,PVOID e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_GetBestRoute2(PNET_LUID a,DWORD b,PVOID c,PVOID d,DWORD e,PVOID f,PVOID g) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g; return ERROR_NETWORK_UNREACHABLE; }
DWORD WINAPI ex_PfAddFiltersToInterface(HANDLE a,DWORD b,PVOID c,DWORD d,PVOID e,PVOID f) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfAddGlobalFilterToInterface(HANDLE a,DWORD b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfBindInterfaceToIPAddress(HANDLE a,DWORD b,PVOID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfBindInterfaceToIndex(HANDLE a,DWORD b,DWORD c,DWORD d) { (void)a;(void)b;(void)c;(void)d; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfCreateInterface(DWORD a,DWORD b,DWORD c,BOOL d,BOOL e,PHANDLE f) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfDeleteInterface(HANDLE a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfDeleteLog(void) { return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfGetInterfaceStatistics(HANDLE a,PVOID b,PDWORD c,BOOL d) { (void)a;(void)b;(void)c;(void)d; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfMakeLog(HANDLE a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfRebindFilters(HANDLE a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfRemoveFilterHandles(HANDLE a,DWORD b,PVOID c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfRemoveFiltersFromInterface(HANDLE a,DWORD b,PVOID c,DWORD d,PVOID e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfRemoveGlobalFilterFromInterface(HANDLE a,DWORD b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfSetLogBuffer(PVOID a,DWORD b,DWORD c,DWORD d,DWORD e,PDWORD f,PHANDLE g) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfTestPacket(HANDLE a,HANDLE b,DWORD c,PVOID d,PVOID e) { (void)a;(void)b;(void)c;(void)d;(void)e; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_PfUnBindInterface(HANDLE a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalCleanupPersistentStore(void) { return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalCreateAnycastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalCreateIpForwardEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalCreateIpForwardEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalCreateIpNetEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalCreateIpNetEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalCreateOrRefIpForwardEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalCreateUnicastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalDeleteAnycastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalDeleteIpForwardEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalDeleteIpForwardEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalDeleteIpNetEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalDeleteIpNetEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalDeleteUnicastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalFindInterfaceByAddress(PVOID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetAnycastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetAnycastIpAddressTable(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetBoundTcpEndpointTable(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetBoundTcp6EndpointTable(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetForwardIpTable2(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetIfEntry2(PVOID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetIfTable(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetIfTable2(PVOID* a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetIpAddrTable(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetIpForwardEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetIpForwardTable(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetIpInterfaceEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetIpInterfaceTable(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetIpNetEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetIpNetTable(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetIpNetTable2(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetIPPhysicalInterfaceForDestination(PVOID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetMulticastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetMulticastIpAddressTable(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetRtcSlotInformation(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetTcpDynamicPortRange(PVOID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetTcpTable(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetTcpTable2(PVOID* a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetTcpTableEx(PVOID* a,HANDLE b,DWORD c,DWORD d) { (void)a;(void)b;(void)c;(void)d; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetTcpTableWithOwnerModule(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetTcpTableWithOwnerPid(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetTcp6Table2(PVOID* a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetTcp6TableWithOwnerModule(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetTcp6TableWithOwnerPid(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetTunnelPhysicalAdapter(PVOID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetUdpDynamicPortRange(PVOID a,PVOID b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetUdpTable(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetUdpTable2(PVOID* a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetUdpTableEx(PVOID* a,HANDLE b,DWORD c,DWORD d) { (void)a;(void)b;(void)c;(void)d; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetUdpTableWithOwnerModule(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetUdpTableWithOwnerPid(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetUdp6Table2(PVOID* a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetUdp6TableWithOwnerModule(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetUdp6TableWithOwnerPid(PVOID* a,HANDLE b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetUnicastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalGetUnicastIpAddressTable(DWORD a,PVOID* b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalIcmpCreateFileEx(PVOID a,DWORD b,DWORD c) { (void)a;(void)b;(void)c; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalSetIfEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalSetIpForwardEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalSetIpForwardEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalSetIpInterfaceEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalSetIpNetEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalSetIpNetEntry2(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalSetIpStats(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalSetTcpDynamicPortRange(DWORD a,DWORD b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalSetTcpEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalSetTeredoPort(DWORD a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalSetUdpDynamicPortRange(DWORD a,DWORD b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_InternalSetUnicastIpAddressEntry(PVOID a) { (void)a; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_do_echo_rep(PVOID a,PVOID b,PVOID c,PVOID d) { (void)a;(void)b;(void)c;(void)d; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_do_echo_req(PVOID a,PVOID b,PVOID c,PVOID d,PVOID e,PVOID f,PVOID g) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g; return ERROR_NOT_SUPPORTED; }
PSTR WINAPI ex_if_indextoname(DWORD a,PSTR b) { (void)a;(void)b; return NULL; }
DWORD WINAPI ex_if_nametoindex(PCSTR a) { (void)a; return 0; }
HANDLE WINAPI ex_register_icmp(void) { return INVALID_HANDLE_VALUE; }
BOOL WINAPI ex_InternetSetSecureLegacyServersAppCompat(void) { return FALSE; }
DWORD WINAPI ex_SetIpStatisticsEx(PVOID a,DWORD b) { (void)a;(void)b; return ERROR_NOT_SUPPORTED; }

DWORD WINAPI ex_StubNotSupported(void) { return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_StubNoData(void) { return ERROR_NO_DATA; }
DWORD WINAPI ex_StubSuccess(void) { return NO_ERROR; }

/* ============================================================================
 * DLL MAIN
 * ============================================================================ */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    (void)hModule; (void)lpReserved;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        if (g_initCount > 0 && g_locksInit) {
#if ENABLE_FILE_LOGGING
            if (g_logFile) { fclose(g_logFile); g_logFile = NULL; }
            DeleteCriticalSection(&g_logLock);
#endif
        }
        break;
    }
    return TRUE;
}

#ifdef __cplusplus
}
#endif