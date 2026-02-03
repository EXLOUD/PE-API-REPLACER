/*
 * Fake iphlpapi.dll - Full Implementation
 * Simulates: Ethernet adapter present, link up, NO internet connectivity
 */

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <fltdefs.h>
#include <icmpapi.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NL_NETWORK_CONNECTIVITY_LEVEL_HINT
typedef enum _NL_NETWORK_CONNECTIVITY_LEVEL_HINT {
    NetworkConnectivityLevelHintUnknown = 0,
    NetworkConnectivityLevelHintNone = 1,
    NetworkConnectivityLevelHintLocalAccess = 2,
    NetworkConnectivityLevelHintInternetAccess = 3,
    NetworkConnectivityLevelHintConstrainedInternetAccess = 4,
    NetworkConnectivityLevelHintHidden = 5
} NL_NETWORK_CONNECTIVITY_LEVEL_HINT;

typedef enum _NL_NETWORK_CONNECTIVITY_COST_HINT {
    NetworkConnectivityCostHintUnknown = 0,
    NetworkConnectivityCostHintUnrestricted = 1,
    NetworkConnectivityCostHintFixed = 2,
    NetworkConnectivityCostHintVariable = 3
} NL_NETWORK_CONNECTIVITY_COST_HINT;

typedef struct _NL_NETWORK_CONNECTIVITY_HINT {
    NL_NETWORK_CONNECTIVITY_LEVEL_HINT ConnectivityLevel;
    NL_NETWORK_CONNECTIVITY_COST_HINT ConnectivityCost;
    BOOLEAN ApproachingDataLimit;
    BOOLEAN OverDataLimit;
    BOOLEAN Roaming;
} NL_NETWORK_CONNECTIVITY_HINT, *PNL_NETWORK_CONNECTIVITY_HINT;
#endif

#ifndef NET_IF_COMPARTMENT_SCOPE
typedef ULONG NET_IF_COMPARTMENT_SCOPE, *PNET_IF_COMPARTMENT_SCOPE;
#endif

#ifndef NETIO_STATUS
#define NETIO_STATUS DWORD
#endif

#ifndef NETIOAPI_API
#define NETIOAPI_API NETIO_STATUS WINAPI
#endif

/* ============================================================================
 * LOGGING CONFIGURATION
 * ============================================================================
 * Set to 1 for Debug build (with console logging)
 * Set to 0 for Production build (no logging, no console)
 * ============================================================================ */

#define IPHLPAPI_DEBUG  1   /* <-- CHANGE HERE: 1 = Debug, 0 = Production */

/* ============================================================================ */

#if IPHLPAPI_DEBUG

    static BOOL g_ConsoleInitialized = FALSE;
    static CRITICAL_SECTION g_LogLock;
    static BOOL g_LockInitialized = FALSE;
    
    static void InitConsole(void)
    {
        if (!g_ConsoleInitialized) {
            if (!g_LockInitialized) {
                InitializeCriticalSection(&g_LogLock);
                g_LockInitialized = TRUE;
            }
            
            AllocConsole();
            
            FILE* fp;
            freopen_s(&fp, "CONOUT$", "w", stdout);
            freopen_s(&fp, "CONOUT$", "w", stderr);
            
            SetConsoleTitleA("iphlpapi.dll - Debug Log");
            
            printf("==========================================================\n");
            printf("  IPHLPAPI.DLL - DEBUG MODE ENABLED\n");
            printf("  PID: %lu\n", GetCurrentProcessId());
            printf("==========================================================\n");
            
            g_ConsoleInitialized = TRUE;
        }
    }
    
    static void LogFunction(const char* func, const char* fmt, ...)
    {
        InitConsole();
        
        EnterCriticalSection(&g_LogLock);
        
        SYSTEMTIME st;
        GetLocalTime(&st);
        printf("[%02d:%02d:%02d.%03d] [IPHLPAPI] %s()", 
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, func);
        
        if (fmt && fmt[0] != '\0') {
            printf(" - ");
            va_list args;
            va_start(args, fmt);
            vprintf(fmt, args);
            va_end(args);
        }
        
        printf("\n");
        fflush(stdout);
        
        LeaveCriticalSection(&g_LogLock);
    }
    
    static void LogMessage(const char* fmt, ...)
    {
        InitConsole();
        
        EnterCriticalSection(&g_LogLock);
        
        SYSTEMTIME st;
        GetLocalTime(&st);
        printf("[%02d:%02d:%02d.%03d] [IPHLPAPI] ", 
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
        
        printf("\n");
        fflush(stdout);
        
        LeaveCriticalSection(&g_LogLock);
    }
    
    #define LOG_CALL()              LogFunction(__FUNCTION__, "")
    #define LOG_CALL_FMT(fmt, ...)  LogFunction(__FUNCTION__, fmt, ##__VA_ARGS__)
    #define LOG_MSG(fmt, ...)       LogMessage(fmt, ##__VA_ARGS__)
    
    static void CleanupLogging(void)
    {
        if (g_LockInitialized) {
            DeleteCriticalSection(&g_LogLock);
            g_LockInitialized = FALSE;
        }
        if (g_ConsoleInitialized) {
            FreeConsole();
            g_ConsoleInitialized = FALSE;
        }
    }

#else

    #define LOG_CALL()              ((void)0)
    #define LOG_CALL_FMT(fmt, ...)  ((void)0)
    #define LOG_MSG(fmt, ...)       ((void)0)
    
    static void CleanupLogging(void) { }

#endif

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

static const WCHAR DEVICE_TCPIP[] = L"\\DEVICE\\TCPIP_";
#define CHARS_IN_GUID 39

static const WCHAR ADAPTER_FRIENDLY_NAME[] = L"Ethernet";
static const WCHAR ADAPTER_DESCRIPTION[] = L"Intel(R) Ethernet Connection I219-V";
static const char  ADAPTER_NAME[] = "{12345678-1234-1234-1234-123456789ABC}";

/* GUID адаптера - має відповідати ADAPTER_NAME */
static const GUID ADAPTER_GUID = { 
    0x12345678, 0x1234, 0x1234, 
    { 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC } 
};

#define ADAPTER_IF_INDEX        1UL
#define ADAPTER_IF_TYPE         IF_TYPE_ETHERNET_CSMACD  /* = 6 */
#define ADAPTER_NET_LUID_INDEX  0UL
#define ADAPTER_MTU             1500
#define ADAPTER_SPEED           1000000000ULL

static const BYTE ADAPTER_MAC[6] = { 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E };

#define IPV4_ADDRESS        0x6401A8C0  /* 192.168.1.100 */
#define IPV4_NETMASK        0x00FFFFFF  /* 255.255.255.0 */
#define IPV4_PREFIX_LENGTH  24

static const BYTE IPV6_LINKLOCAL[16] = {
    0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x12, 0x34, 0x56, 0x78, 0xAB, 0xCD, 0xEF, 0x01
};
#define IPV6_PREFIX_LENGTH 64

#define MAKE_NET_LUID(iftype, index) \
    (((ULONG64)(iftype) << 48) | ((ULONG64)(index) << 24))

static const NET_LUID ADAPTER_LUID = { 
    .Value = MAKE_NET_LUID(ADAPTER_IF_TYPE, ADAPTER_NET_LUID_INDEX)
};

#define FAKE_ICMP_HANDLE   ((HANDLE)(ULONG_PTR)0x1CEC0001)
#define FAKE_ICMP6_HANDLE  ((HANDLE)(ULONG_PTR)0x1CEC0006)

/* ============================================================================
 * INTERFACE NAME PREFIXES (based on Wine implementation)
 * ============================================================================ */

struct name_prefix
{
    const WCHAR *prefix_w;
    const char  *prefix_a;
    DWORD        type;
};

static const struct name_prefix g_name_prefixes[] =
{
    { L"other",     "other",     IF_TYPE_OTHER },
    { L"ethernet",  "ethernet",  IF_TYPE_ETHERNET_CSMACD },
    { L"tokenring", "tokenring", IF_TYPE_ISO88025_TOKENRING },
    { L"ppp",       "ppp",       IF_TYPE_PPP },
    { L"loopback",  "loopback",  IF_TYPE_SOFTWARE_LOOPBACK },
    { L"atm",       "atm",       IF_TYPE_ATM },
    { L"wireless",  "wireless",  IF_TYPE_IEEE80211 },
    { L"tunnel",    "tunnel",    IF_TYPE_TUNNEL },
    { L"ieee1394",  "ieee1394",  IF_TYPE_IEEE1394 }
};

#define NAME_PREFIXES_COUNT (sizeof(g_name_prefixes) / sizeof(g_name_prefixes[0]))

/* ============================================================================
 * HELPERS
 * ============================================================================ */

static const char* Ipv4ToString(DWORD ip)
{
    static char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
        (unsigned int)(ip & 0xFF),
        (unsigned int)((ip >> 8) & 0xFF),
        (unsigned int)((ip >> 16) & 0xFF),
        (unsigned int)((ip >> 24) & 0xFF));
    return buf;
}

static BOOL IsLocalIPv4(DWORD ip)
{
    return ((ip & IPV4_NETMASK) == (IPV4_ADDRESS & IPV4_NETMASK)) ||
           ((ip & 0x000000FF) == 0x0000007F);
}

/* ============================================================================
 * DYNAMIC LOADING OF EXWS2.DLL (for ntohl/htonl)
 * ============================================================================ */

/* Типи функцій */
typedef ULONG (WSAAPI *PFN_NTOHL)(ULONG netlong);
typedef ULONG (WSAAPI *PFN_HTONL)(ULONG hostlong);

/* Глобальні змінні */
static HMODULE g_hExWs2 = NULL;
static PFN_NTOHL g_pfnNtohl = NULL;
static PFN_HTONL g_pfnHtonl = NULL;
static BOOL g_ExWs2Initialized = FALSE;

/* Власна реалізація як fallback */
static __inline ULONG ByteSwap32(ULONG val)
{
    return ((val & 0x000000FF) << 24) |
           ((val & 0x0000FF00) << 8)  |
           ((val & 0x00FF0000) >> 8)  |
           ((val & 0xFF000000) >> 24);
}

static BOOL InitExWs2(void)
{
    if (g_ExWs2Initialized) {
        return (g_hExWs2 != NULL);
    }
    
    g_ExWs2Initialized = TRUE;
    
    /* Спробуємо завантажити exws2.dll */
    g_hExWs2 = LoadLibraryA("exws2.dll");
    if (!g_hExWs2) {
        /* Спробуємо з поточної директорії */
        g_hExWs2 = LoadLibraryA(".\\exws2.dll");
    }
    
    if (g_hExWs2) {
        g_pfnNtohl = (PFN_NTOHL)GetProcAddress(g_hExWs2, "ntohl");
        g_pfnHtonl = (PFN_HTONL)GetProcAddress(g_hExWs2, "htonl");
        
        if (g_pfnNtohl && g_pfnHtonl) {
            LOG_MSG("[EXWS2] Loaded exws2.dll successfully");
            LOG_MSG("[EXWS2]   ntohl = %p", g_pfnNtohl);
            LOG_MSG("[EXWS2]   htonl = %p", g_pfnHtonl);
            return TRUE;
        } else {
            LOG_MSG("[EXWS2] WARNING: exws2.dll loaded but functions not found, using fallback");
            FreeLibrary(g_hExWs2);
            g_hExWs2 = NULL;
            g_pfnNtohl = NULL;
            g_pfnHtonl = NULL;
        }
    } else {
        LOG_MSG("[EXWS2] WARNING: exws2.dll not found, using built-in byte swap");
    }
    
    return FALSE;
}

static void CleanupExWs2(void)
{
    if (g_hExWs2) {
        FreeLibrary(g_hExWs2);
        g_hExWs2 = NULL;
        g_pfnNtohl = NULL;
        g_pfnHtonl = NULL;
        LOG_MSG("[EXWS2] Unloaded exws2.dll");
    }
    g_ExWs2Initialized = FALSE;
}

/* Wrapper функції - використовують exws2.dll або fallback */
static __inline ULONG FAKE_ntohl(ULONG netlong)
{
    if (!g_ExWs2Initialized) InitExWs2();
    
    if (g_pfnNtohl) {
        return g_pfnNtohl(netlong);
    }
    return ByteSwap32(netlong);
}

static __inline ULONG FAKE_htonl(ULONG hostlong)
{
    if (!g_ExWs2Initialized) InitExWs2();
    
    if (g_pfnHtonl) {
        return g_pfnHtonl(hostlong);
    }
    return ByteSwap32(hostlong);
}

/* ============================================================================
 * DLL ENTRY
 * ============================================================================ */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    (void)hModule; 
    (void)lpReserved;
    
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            LOG_MSG("DLL_PROCESS_ATTACH - PID: %lu", GetCurrentProcessId());
            DisableThreadLibraryCalls(hModule);
            /* Можна ініціалізувати тут, або лениво при першому виклику */
            /* InitExWs2(); */
            break;
            
        case DLL_PROCESS_DETACH:
            LOG_MSG("DLL_PROCESS_DETACH");
            CleanupExWs2();  /* ← Додано! */
            CleanupLogging();
            break;
    }
    
    return TRUE;
}

/* ============================================================================
 * EXPORTS
 * ============================================================================ */


VOID WINAPI FreeMibTable(PVOID Memory)
{
    LOG_CALL_FMT("Memory=%p", Memory);
    if (Memory) HeapFree(GetProcessHeap(), 0, Memory);
}


DWORD WINAPI GetNumberOfInterfaces(PDWORD pdwNumIf)
{
    LOG_CALL();
    if (!pdwNumIf) return ERROR_INVALID_PARAMETER;
    *pdwNumIf = 1;
    LOG_MSG("  -> NumInterfaces = 1");
    return NO_ERROR;
}


DWORD WINAPI GetIfEntry(PMIB_IFROW pIfRow)
{
    LOG_CALL_FMT("Index=%lu", pIfRow ? pIfRow->dwIndex : 0);
    if (!pIfRow) return ERROR_INVALID_PARAMETER;
    if (pIfRow->dwIndex != ADAPTER_IF_INDEX) {
        LOG_MSG("  -> ERROR_NOT_FOUND");
        return ERROR_NOT_FOUND;
    }

    ZeroMemory(pIfRow, sizeof(MIB_IFROW));
    pIfRow->dwIndex = ADAPTER_IF_INDEX;
    pIfRow->dwType = ADAPTER_IF_TYPE;
    pIfRow->dwMtu = ADAPTER_MTU;
    pIfRow->dwSpeed = (DWORD)(ADAPTER_SPEED);
    pIfRow->dwPhysAddrLen = 6;
    CopyMemory(pIfRow->bPhysAddr, ADAPTER_MAC, 6);
    pIfRow->dwAdminStatus = MIB_IF_ADMIN_STATUS_UP;
    pIfRow->dwOperStatus = MIB_IF_OPER_STATUS_OPERATIONAL;
    pIfRow->dwInOctets = 1000000;
    pIfRow->dwOutOctets = 500000;
    
    WideCharToMultiByte(CP_ACP, 0, ADAPTER_DESCRIPTION, -1,
        (char*)pIfRow->bDescr, sizeof(pIfRow->bDescr), NULL, NULL);
    pIfRow->dwDescrLen = (DWORD)lstrlenA((char*)pIfRow->bDescr);

    LOG_MSG("  -> OK, Status=UP");
    return NO_ERROR;
}


DWORD WINAPI GetIfEntry2(PMIB_IF_ROW2 Row)
{
    LOG_CALL_FMT("Index=%lu, LUID=0x%llX", 
        Row ? Row->InterfaceIndex : 0,
        Row ? Row->InterfaceLuid.Value : 0);
    
    if (!Row) return ERROR_INVALID_PARAMETER;
    
    if (Row->InterfaceIndex != ADAPTER_IF_INDEX &&
        Row->InterfaceLuid.Value != ADAPTER_LUID.Value) {
        LOG_MSG("  -> ERROR_NOT_FOUND");
        return ERROR_NOT_FOUND;
    }

    ZeroMemory(Row, sizeof(MIB_IF_ROW2));
    Row->InterfaceLuid = ADAPTER_LUID;
    Row->InterfaceIndex = ADAPTER_IF_INDEX;
    
    lstrcpyW(Row->Alias, ADAPTER_FRIENDLY_NAME);
    lstrcpyW(Row->Description, ADAPTER_DESCRIPTION);
    
    Row->PhysicalAddressLength = 6;
    CopyMemory(Row->PhysicalAddress, ADAPTER_MAC, 6);
    CopyMemory(Row->PermanentPhysicalAddress, ADAPTER_MAC, 6);
    
    Row->Mtu = ADAPTER_MTU;
    Row->Type = ADAPTER_IF_TYPE;
    Row->MediaType = 0;
    Row->AccessType = NET_IF_ACCESS_BROADCAST;
    Row->InterfaceAndOperStatusFlags.HardwareInterface = TRUE;
    Row->InterfaceAndOperStatusFlags.ConnectorPresent = TRUE;
    Row->OperStatus = IfOperStatusUp;
    Row->AdminStatus = NET_IF_ADMIN_STATUS_UP;
    Row->MediaConnectState = MediaConnectStateConnected;
    Row->ConnectionType = NET_IF_CONNECTION_DEDICATED;
    Row->TransmitLinkSpeed = ADAPTER_SPEED;
    Row->ReceiveLinkSpeed = ADAPTER_SPEED;
    Row->InOctets = 1000000;
    Row->OutOctets = 500000;

    LOG_MSG("  -> OK, OperStatus=Up, MediaConnectState=Connected");
    return NO_ERROR;
}


DWORD WINAPI GetIfTable(PMIB_IFTABLE pIfTable, PULONG pdwSize, BOOL bOrder)
{
    LOG_CALL_FMT("Size=%lu, bOrder=%d", pdwSize ? *pdwSize : 0, bOrder);
    (void)bOrder;
    if (!pdwSize) return ERROR_INVALID_PARAMETER;

    ULONG size = sizeof(MIB_IFTABLE);
    if (!pIfTable || *pdwSize < size) {
        *pdwSize = size;
        LOG_MSG("  -> ERROR_INSUFFICIENT_BUFFER, need %lu", size);
        return ERROR_INSUFFICIENT_BUFFER;
    }

    ZeroMemory(pIfTable, size);
    pIfTable->dwNumEntries = 1;
    pIfTable->table[0].dwIndex = ADAPTER_IF_INDEX;
    GetIfEntry(&pIfTable->table[0]);
    
    *pdwSize = size;
    LOG_MSG("  -> OK, NumEntries=1");
    return NO_ERROR;
}


DWORD WINAPI GetIfTable2(PMIB_IF_TABLE2 *Table)
{
    LOG_CALL();
    if (!Table) return ERROR_INVALID_PARAMETER;

    SIZE_T size = sizeof(MIB_IF_TABLE2);
    PMIB_IF_TABLE2 table = (PMIB_IF_TABLE2)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!table) {
        LOG_MSG("  -> ERROR_NOT_ENOUGH_MEMORY");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    table->NumEntries = 1;
    table->Table[0].InterfaceIndex = ADAPTER_IF_INDEX;
    GetIfEntry2(&table->Table[0]);

    *Table = table;
    LOG_MSG("  -> OK, NumEntries=1, Table=%p", table);
    return NO_ERROR;
}


DWORD WINAPI GetIpAddrTable(PMIB_IPADDRTABLE pIpAddrTable, PULONG pdwSize, BOOL bOrder)
{
    LOG_CALL_FMT("Size=%lu", pdwSize ? *pdwSize : 0);
    (void)bOrder;
    if (!pdwSize) return ERROR_INVALID_PARAMETER;

    ULONG size = sizeof(MIB_IPADDRTABLE);
    if (!pIpAddrTable || *pdwSize < size) {
        *pdwSize = size;
        LOG_MSG("  -> ERROR_INSUFFICIENT_BUFFER");
        return ERROR_INSUFFICIENT_BUFFER;
    }

    ZeroMemory(pIpAddrTable, size);
    pIpAddrTable->dwNumEntries = 1;
    pIpAddrTable->table[0].dwAddr = IPV4_ADDRESS;
    pIpAddrTable->table[0].dwIndex = ADAPTER_IF_INDEX;
    pIpAddrTable->table[0].dwMask = IPV4_NETMASK;
    pIpAddrTable->table[0].dwBCastAddr = (IPV4_ADDRESS & IPV4_NETMASK) | ~IPV4_NETMASK;
    pIpAddrTable->table[0].dwReasmSize = 65535;
    pIpAddrTable->table[0].wType = MIB_IPADDR_PRIMARY;

    *pdwSize = size;
    LOG_MSG("  -> OK, IP=%s", Ipv4ToString(IPV4_ADDRESS));
    return NO_ERROR;
}


DWORD WINAPI GetUnicastIpAddressTable(ADDRESS_FAMILY Family, PMIB_UNICASTIPADDRESS_TABLE *Table)
{
    LOG_CALL_FMT("Family=%d (%s)", Family,
        Family == AF_INET ? "IPv4" : Family == AF_INET6 ? "IPv6" : "UNSPEC");
    
    if (!Table) return ERROR_INVALID_PARAMETER;

    DWORD count = 0;
    if (Family == AF_UNSPEC || Family == AF_INET) count++;
    if (Family == AF_UNSPEC || Family == AF_INET6) count++;

    SIZE_T size = sizeof(MIB_UNICASTIPADDRESS_TABLE) + 
                  (count > 0 ? count - 1 : 0) * sizeof(MIB_UNICASTIPADDRESS_ROW);
    PMIB_UNICASTIPADDRESS_TABLE table = (PMIB_UNICASTIPADDRESS_TABLE)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!table) return ERROR_NOT_ENOUGH_MEMORY;

    table->NumEntries = count;
    DWORD idx = 0;

    if (Family == AF_UNSPEC || Family == AF_INET) {
        table->Table[idx].Address.Ipv4.sin_family = AF_INET;
        table->Table[idx].Address.Ipv4.sin_addr.s_addr = IPV4_ADDRESS;
        table->Table[idx].InterfaceLuid = ADAPTER_LUID;
        table->Table[idx].InterfaceIndex = ADAPTER_IF_INDEX;
        table->Table[idx].PrefixOrigin = IpPrefixOriginManual;
        table->Table[idx].SuffixOrigin = IpSuffixOriginManual;
        table->Table[idx].ValidLifetime = 0xFFFFFFFF;
        table->Table[idx].PreferredLifetime = 0xFFFFFFFF;
        table->Table[idx].OnLinkPrefixLength = IPV4_PREFIX_LENGTH;
        table->Table[idx].DadState = IpDadStatePreferred;
        idx++;
    }

    if (Family == AF_UNSPEC || Family == AF_INET6) {
        table->Table[idx].Address.Ipv6.sin6_family = AF_INET6;
        CopyMemory(&table->Table[idx].Address.Ipv6.sin6_addr, IPV6_LINKLOCAL, 16);
        table->Table[idx].Address.Ipv6.sin6_scope_id = ADAPTER_IF_INDEX;
        table->Table[idx].InterfaceLuid = ADAPTER_LUID;
        table->Table[idx].InterfaceIndex = ADAPTER_IF_INDEX;
        table->Table[idx].PrefixOrigin = IpPrefixOriginWellKnown;
        table->Table[idx].SuffixOrigin = IpSuffixOriginLinkLayerAddress;
        table->Table[idx].ValidLifetime = 0xFFFFFFFF;
        table->Table[idx].PreferredLifetime = 0xFFFFFFFF;
        table->Table[idx].OnLinkPrefixLength = IPV6_PREFIX_LENGTH;
        table->Table[idx].DadState = IpDadStatePreferred;
    }

    *Table = table;
    LOG_MSG("  -> OK, NumEntries=%lu", count);
    return NO_ERROR;
}


DWORD WINAPI GetIpInterfaceTable(ADDRESS_FAMILY Family, PMIB_IPINTERFACE_TABLE *Table)
{
    LOG_CALL_FMT("Family=%d", Family);
    if (!Table) return ERROR_INVALID_PARAMETER;

    DWORD count = 0;
    if (Family == AF_UNSPEC || Family == AF_INET) count++;
    if (Family == AF_UNSPEC || Family == AF_INET6) count++;

    SIZE_T size = sizeof(MIB_IPINTERFACE_TABLE) + 
                  (count > 0 ? count - 1 : 0) * sizeof(MIB_IPINTERFACE_ROW);
    PMIB_IPINTERFACE_TABLE table = (PMIB_IPINTERFACE_TABLE)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!table) return ERROR_NOT_ENOUGH_MEMORY;

    table->NumEntries = count;
    DWORD idx = 0;

    if (Family == AF_UNSPEC || Family == AF_INET) {
        table->Table[idx].Family = AF_INET;
        table->Table[idx].InterfaceLuid = ADAPTER_LUID;
        table->Table[idx].InterfaceIndex = ADAPTER_IF_INDEX;
        table->Table[idx].NlMtu = ADAPTER_MTU;
        table->Table[idx].Metric = 25;
        table->Table[idx].Connected = TRUE;
        table->Table[idx].UseAutomaticMetric = TRUE;
        idx++;
    }

    if (Family == AF_UNSPEC || Family == AF_INET6) {
        table->Table[idx].Family = AF_INET6;
        table->Table[idx].InterfaceLuid = ADAPTER_LUID;
        table->Table[idx].InterfaceIndex = ADAPTER_IF_INDEX;
        table->Table[idx].NlMtu = ADAPTER_MTU;
        table->Table[idx].Metric = 25;
        table->Table[idx].Connected = TRUE;
        table->Table[idx].UseAutomaticMetric = TRUE;
    }

    *Table = table;
    LOG_MSG("  -> OK, NumEntries=%lu", count);
    return NO_ERROR;
}


ULONG WINAPI GetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer)
{
    LOG_CALL_FMT("Size=%lu", SizePointer ? *SizePointer : 0);
    if (!SizePointer) return ERROR_INVALID_PARAMETER;

    ULONG size = sizeof(IP_ADAPTER_INFO);
    if (!AdapterInfo || *SizePointer < size) {
        *SizePointer = size;
        LOG_MSG("  -> ERROR_BUFFER_OVERFLOW, need %lu", size);
        return ERROR_BUFFER_OVERFLOW;
    }

    ZeroMemory(AdapterInfo, size);
    AdapterInfo->Next = NULL;
    lstrcpyA(AdapterInfo->AdapterName, ADAPTER_NAME);
    WideCharToMultiByte(CP_ACP, 0, ADAPTER_DESCRIPTION, -1,
        AdapterInfo->Description, sizeof(AdapterInfo->Description), NULL, NULL);
    AdapterInfo->AddressLength = 6;
    CopyMemory(AdapterInfo->Address, ADAPTER_MAC, 6);
    AdapterInfo->Index = ADAPTER_IF_INDEX;
    AdapterInfo->Type = MIB_IF_TYPE_ETHERNET;
    AdapterInfo->DhcpEnabled = FALSE;

    lstrcpyA(AdapterInfo->IpAddressList.IpAddress.String, "192.168.1.100");
    lstrcpyA(AdapterInfo->IpAddressList.IpMask.String, "255.255.255.0");
    lstrcpyA(AdapterInfo->GatewayList.IpAddress.String, "192.168.1.1");
    lstrcpyA(AdapterInfo->GatewayList.IpMask.String, "255.255.255.255");

    *SizePointer = size;
    LOG_MSG("  -> OK, IP=192.168.1.100, GW=192.168.1.1");
    return NO_ERROR;
}


ULONG WINAPI GetAdaptersAddresses(
    ULONG Family, ULONG Flags, PVOID Reserved,
    PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer)
{
    LOG_CALL_FMT("Family=%lu, Flags=0x%lX, Size=%lu", 
        Family, Flags, SizePointer ? *SizePointer : 0);
    (void)Reserved; (void)Flags;
    if (!SizePointer) return ERROR_INVALID_PARAMETER;

    ULONG size = sizeof(IP_ADAPTER_ADDRESSES) + 512;
    if (!AdapterAddresses || *SizePointer < size) {
        *SizePointer = size;
        LOG_MSG("  -> ERROR_BUFFER_OVERFLOW, need %lu", size);
        return ERROR_BUFFER_OVERFLOW;
    }

    ZeroMemory(AdapterAddresses, size);
    BYTE *ptr = (BYTE*)AdapterAddresses + sizeof(IP_ADAPTER_ADDRESSES);

    AdapterAddresses->Length = sizeof(IP_ADAPTER_ADDRESSES);
    AdapterAddresses->IfIndex = ADAPTER_IF_INDEX;
    AdapterAddresses->Next = NULL;

    AdapterAddresses->AdapterName = (char*)ptr;
    lstrcpyA((char*)ptr, ADAPTER_NAME);
    ptr += MAX_ADAPTER_NAME_LENGTH;

    AdapterAddresses->FriendlyName = (WCHAR*)ptr;
    lstrcpyW((WCHAR*)ptr, ADAPTER_FRIENDLY_NAME);
    ptr += 128;

    AdapterAddresses->Description = (WCHAR*)ptr;
    lstrcpyW((WCHAR*)ptr, ADAPTER_DESCRIPTION);
    ptr += 256;

    AdapterAddresses->PhysicalAddressLength = 6;
    CopyMemory(AdapterAddresses->PhysicalAddress, ADAPTER_MAC, 6);
    
    AdapterAddresses->Mtu = ADAPTER_MTU;
    AdapterAddresses->IfType = ADAPTER_IF_TYPE;
    AdapterAddresses->OperStatus = IfOperStatusUp;
    AdapterAddresses->Ipv4Enabled = (Family == AF_UNSPEC || Family == AF_INET);
    AdapterAddresses->Ipv6Enabled = (Family == AF_UNSPEC || Family == AF_INET6);
    AdapterAddresses->Luid = ADAPTER_LUID;
    AdapterAddresses->TransmitLinkSpeed = ADAPTER_SPEED;
    AdapterAddresses->ReceiveLinkSpeed = ADAPTER_SPEED;
    AdapterAddresses->ConnectionType = NET_IF_CONNECTION_DEDICATED;
    AdapterAddresses->FirstDnsServerAddress = NULL;
    
    AdapterAddresses->DnsSuffix = (WCHAR*)ptr;
    lstrcpyW((WCHAR*)ptr, L"");

    *SizePointer = size;
    LOG_MSG("  -> OK, OperStatus=Up, DNS=NULL (no internet)");
    return NO_ERROR;
}


DWORD WINAPI GetIpForwardTable(PMIB_IPFORWARDTABLE pIpForwardTable, PULONG pdwSize, BOOL bOrder)
{
    LOG_CALL_FMT("Size=%lu", pdwSize ? *pdwSize : 0);
    (void)bOrder;
    if (!pdwSize) return ERROR_INVALID_PARAMETER;

    ULONG size = sizeof(MIB_IPFORWARDTABLE);
    if (!pIpForwardTable || *pdwSize < size) {
        *pdwSize = size;
        LOG_MSG("  -> ERROR_INSUFFICIENT_BUFFER");
        return ERROR_INSUFFICIENT_BUFFER;
    }

    ZeroMemory(pIpForwardTable, size);
    pIpForwardTable->dwNumEntries = 1;
    
    pIpForwardTable->table[0].dwForwardDest = IPV4_ADDRESS & IPV4_NETMASK;
    pIpForwardTable->table[0].dwForwardMask = IPV4_NETMASK;
    pIpForwardTable->table[0].dwForwardNextHop = 0;
    pIpForwardTable->table[0].dwForwardIfIndex = ADAPTER_IF_INDEX;
    pIpForwardTable->table[0].dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
    pIpForwardTable->table[0].dwForwardProto = MIB_IPPROTO_LOCAL;
    pIpForwardTable->table[0].dwForwardMetric1 = 25;

    *pdwSize = size;
    LOG_MSG("  -> OK, NumEntries=1 (local subnet only, NO default route)");
    return NO_ERROR;
}


DWORD WINAPI GetBestRoute(DWORD dwDestAddr, DWORD dwSourceAddr, PMIB_IPFORWARDROW pBestRoute)
{
    LOG_CALL_FMT("Dest=%s, Src=%s", Ipv4ToString(dwDestAddr), Ipv4ToString(dwSourceAddr));
    (void)dwSourceAddr;
    if (!pBestRoute) return ERROR_INVALID_PARAMETER;

    if (IsLocalIPv4(dwDestAddr)) {
        ZeroMemory(pBestRoute, sizeof(MIB_IPFORWARDROW));
        pBestRoute->dwForwardDest = dwDestAddr;
        pBestRoute->dwForwardMask = 0xFFFFFFFF;
        pBestRoute->dwForwardIfIndex = ADAPTER_IF_INDEX;
        pBestRoute->dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
        pBestRoute->dwForwardProto = MIB_IPPROTO_LOCAL;
        pBestRoute->dwForwardMetric1 = 1;
        LOG_MSG("  -> OK, local route");
        return NO_ERROR;
    }

    LOG_MSG("  -> ERROR_HOST_UNREACHABLE (no internet)");
    return ERROR_HOST_UNREACHABLE;
}


DWORD WINAPI GetBestRoute2(
    NET_LUID *InterfaceLuid, NET_IFINDEX InterfaceIndex,
    CONST SOCKADDR_INET *SourceAddress, CONST SOCKADDR_INET *DestinationAddress,
    ULONG AddressSortOptions, PMIB_IPFORWARD_ROW2 BestRoute, SOCKADDR_INET *BestSourceAddress)
{
    LOG_CALL();
    (void)InterfaceLuid; (void)InterfaceIndex;
    (void)SourceAddress; (void)AddressSortOptions;
    
    if (!DestinationAddress || !BestRoute || !BestSourceAddress)
        return ERROR_INVALID_PARAMETER;

    if (DestinationAddress->si_family == AF_INET) {
        DWORD destIp = DestinationAddress->Ipv4.sin_addr.s_addr;
        LOG_MSG("  Dest=%s", Ipv4ToString(destIp));
        
        if (IsLocalIPv4(destIp)) {
            ZeroMemory(BestRoute, sizeof(MIB_IPFORWARD_ROW2));
            BestRoute->InterfaceLuid = ADAPTER_LUID;
            BestRoute->InterfaceIndex = ADAPTER_IF_INDEX;
            BestRoute->DestinationPrefix.Prefix.si_family = AF_INET;
            BestRoute->DestinationPrefix.PrefixLength = IPV4_PREFIX_LENGTH;
            BestRoute->Protocol = MIB_IPPROTO_LOCAL;
            BestRoute->Metric = 25;

            ZeroMemory(BestSourceAddress, sizeof(SOCKADDR_INET));
            BestSourceAddress->si_family = AF_INET;
            BestSourceAddress->Ipv4.sin_addr.s_addr = IPV4_ADDRESS;
            LOG_MSG("  -> OK, local route");
            return NO_ERROR;
        }
    }

    LOG_MSG("  -> ERROR_NETWORK_UNREACHABLE");
    return ERROR_NETWORK_UNREACHABLE;
}


DWORD WINAPI GetNetworkConnectivityHint(NL_NETWORK_CONNECTIVITY_HINT *ConnectivityHint)
{
    LOG_CALL();
    if (!ConnectivityHint) return ERROR_INVALID_PARAMETER;

    ZeroMemory(ConnectivityHint, sizeof(NL_NETWORK_CONNECTIVITY_HINT));
    ConnectivityHint->ConnectivityLevel = NetworkConnectivityLevelHintLocalAccess;
    ConnectivityHint->ConnectivityCost = NetworkConnectivityCostHintUnknown;
    LOG_MSG("  -> LocalAccess (no internet)");
    return NO_ERROR;
}


DWORD WINAPI GetNetworkConnectivityHintForInterface(
    NET_IFINDEX InterfaceIndex, NL_NETWORK_CONNECTIVITY_HINT *ConnectivityHint)
{
    LOG_CALL_FMT("Index=%lu", InterfaceIndex);
    if (InterfaceIndex != ADAPTER_IF_INDEX) {
        LOG_MSG("  -> ERROR_NOT_FOUND");
        return ERROR_NOT_FOUND;
    }
    return GetNetworkConnectivityHint(ConnectivityHint);
}


HANDLE WINAPI IcmpCreateFile(VOID)
{
    LOG_CALL();
    LOG_MSG("  -> Handle=0x%p", FAKE_ICMP_HANDLE);
    return FAKE_ICMP_HANDLE;
}


BOOL WINAPI IcmpCloseHandle(HANDLE IcmpHandle)
{
    LOG_CALL_FMT("Handle=%p", IcmpHandle);
    if (IcmpHandle == FAKE_ICMP_HANDLE || IcmpHandle == FAKE_ICMP6_HANDLE) {
        LOG_MSG("  -> TRUE");
        return TRUE;
    }
    LOG_MSG("  -> FALSE (invalid handle)");
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
}


DWORD WINAPI IcmpSendEcho(
    HANDLE IcmpHandle, IPAddr DestinationAddress,
    LPVOID RequestData, WORD RequestSize,
    PIP_OPTION_INFORMATION RequestOptions,
    LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout)
{
    LOG_CALL_FMT("Dest=%s, Size=%u, Timeout=%lu", 
        Ipv4ToString(DestinationAddress), RequestSize, Timeout);
    (void)IcmpHandle; (void)RequestData;
    (void)RequestOptions; (void)Timeout;

    if (!ReplyBuffer || ReplySize < sizeof(ICMP_ECHO_REPLY) + RequestSize + 8) {
        LOG_MSG("  -> ERROR_INSUFFICIENT_BUFFER");
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)ReplyBuffer;
    ZeroMemory(reply, sizeof(ICMP_ECHO_REPLY));
    reply->Address = DestinationAddress;

    if (IsLocalIPv4(DestinationAddress)) {
        reply->Status = IP_SUCCESS;
        reply->RoundTripTime = 1;
        reply->DataSize = RequestSize;
        reply->Options.Ttl = 64;
        LOG_MSG("  -> SUCCESS (local), RTT=1ms");
        return 1;
    }

    reply->Status = IP_REQ_TIMED_OUT;
    LOG_MSG("  -> TIMED_OUT (no internet)");
    SetLastError(IP_REQ_TIMED_OUT);
    return 0;
}


DWORD WINAPI IcmpSendEcho2(
    HANDLE IcmpHandle, HANDLE Event,
    FARPROC ApcRoutine, PVOID ApcContext,
    IPAddr DestinationAddress,
    LPVOID RequestData, WORD RequestSize,
    PIP_OPTION_INFORMATION RequestOptions,
    LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout)
{
    LOG_CALL_FMT("Dest=%s, Event=%p", Ipv4ToString(DestinationAddress), Event);
    (void)IcmpHandle; (void)ApcRoutine; (void)ApcContext;
    (void)RequestData; (void)RequestOptions; (void)Timeout;

    if (!ReplyBuffer || ReplySize < sizeof(ICMP_ECHO_REPLY) + RequestSize + 8) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)ReplyBuffer;
    ZeroMemory(reply, sizeof(ICMP_ECHO_REPLY));
    reply->Address = DestinationAddress;

    if (IsLocalIPv4(DestinationAddress)) {
        reply->Status = IP_SUCCESS;
        reply->RoundTripTime = 1;
        reply->DataSize = RequestSize;
        reply->Options.Ttl = 64;
        if (Event) SetEvent(Event);
        LOG_MSG("  -> SUCCESS (local)");
        return 1;
    }

    reply->Status = IP_REQ_TIMED_OUT;
    SetLastError(IP_REQ_TIMED_OUT);
    if (Event) SetEvent(Event);
    LOG_MSG("  -> TIMED_OUT");
    return 0;
}


DWORD WINAPI IcmpSendEcho2Ex(
    HANDLE IcmpHandle, HANDLE Event,
    FARPROC ApcRoutine, PVOID ApcContext,
    IPAddr SourceAddress, IPAddr DestinationAddress,
    LPVOID RequestData, WORD RequestSize,
    PIP_OPTION_INFORMATION RequestOptions,
    LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout)
{
    LOG_CALL_FMT("Src=%s, Dest=%s", 
        Ipv4ToString(SourceAddress), Ipv4ToString(DestinationAddress));
    (void)SourceAddress;
    return IcmpSendEcho2(IcmpHandle, Event, ApcRoutine, ApcContext,
                         DestinationAddress, RequestData, RequestSize,
                         RequestOptions, ReplyBuffer, ReplySize, Timeout);
}


DWORD WINAPI IcmpParseReplies(LPVOID ReplyBuffer, DWORD ReplySize)
{
    LOG_CALL_FMT("Buffer=%p, Size=%lu", ReplyBuffer, ReplySize);
    if (!ReplyBuffer || ReplySize < sizeof(ICMP_ECHO_REPLY) + 8) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)ReplyBuffer;
    DWORD result = (reply->Status == IP_SUCCESS) ? 1 : 0;
    LOG_MSG("  -> %lu replies", result);
    return result;
}


HANDLE WINAPI Icmp6CreateFile(VOID)
{
    LOG_CALL();
    LOG_MSG("  -> Handle=0x%p", FAKE_ICMP6_HANDLE);
    return FAKE_ICMP6_HANDLE;
}


DWORD WINAPI Icmp6SendEcho2(
    HANDLE IcmpHandle, HANDLE Event,
    FARPROC ApcRoutine, PVOID ApcContext,
    struct sockaddr_in6 *SourceAddress, struct sockaddr_in6 *DestinationAddress,
    LPVOID RequestData, WORD RequestSize,
    PIP_OPTION_INFORMATION RequestOptions,
    LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout)
{
    LOG_CALL();
    (void)IcmpHandle; (void)ApcRoutine; (void)ApcContext;
    (void)SourceAddress; (void)RequestData; (void)RequestSize;
    (void)RequestOptions; (void)Timeout;

    if (!DestinationAddress || !ReplyBuffer || ReplySize < sizeof(ICMPV6_ECHO_REPLY) + RequestSize + 8) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    PICMPV6_ECHO_REPLY reply = (PICMPV6_ECHO_REPLY)ReplyBuffer;
    ZeroMemory(reply, sizeof(ICMPV6_ECHO_REPLY));

    BYTE *dest = DestinationAddress->sin6_addr.s6_addr;
    if (dest[0] == 0xFE && (dest[1] & 0xC0) == 0x80) {
        reply->Status = IP_SUCCESS;
        reply->RoundTripTime = 1;
        if (Event) SetEvent(Event);
        LOG_MSG("  -> SUCCESS (link-local)");
        return 1;
    }

    reply->Status = IP_REQ_TIMED_OUT;
    SetLastError(IP_REQ_TIMED_OUT);
    if (Event) SetEvent(Event);
    LOG_MSG("  -> TIMED_OUT");
    return 0;
}


DWORD WINAPI Icmp6ParseReplies(LPVOID ReplyBuffer, DWORD ReplySize)
{
    LOG_CALL_FMT("Buffer=%p, Size=%lu", ReplyBuffer, ReplySize);
    if (!ReplyBuffer || ReplySize < sizeof(ICMPV6_ECHO_REPLY) + 8) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    PICMPV6_ECHO_REPLY reply = (PICMPV6_ECHO_REPLY)ReplyBuffer;
    DWORD result = (reply->Status == IP_SUCCESS) ? 1 : 0;
    LOG_MSG("  -> %lu replies", result);
    return result;
}

/* ============================================================================
 * IP ADDRESS MANAGEMENT FUNCTIONS
 * ============================================================================ */


DWORD WINAPI AddIPAddress(
    IPAddr Address, IPMask IpMask, DWORD IfIndex,
    PULONG NTEContext, PULONG NTEInstance)
{
	LOG_CALL_FMT("Address=%s, Mask=0x%08lX, IfIndex=%lu",
		Ipv4ToString(Address), IpMask, IfIndex);
    if (!NTEContext || !NTEInstance) return ERROR_INVALID_PARAMETER;
    *NTEContext = 1;
    *NTEInstance = 1;
    LOG_MSG("  -> ERROR_ACCESS_DENIED (read-only fake)");
    return ERROR_ACCESS_DENIED;
}


DWORD WINAPI DeleteIPAddress(ULONG NTEContext)
{
    LOG_CALL_FMT("NTEContext=%lu", NTEContext);
    LOG_MSG("  -> ERROR_ACCESS_DENIED (read-only fake)");
    return ERROR_ACCESS_DENIED;
}

/* ============================================================================
 * ARP TABLE FUNCTIONS
 * ============================================================================ */


ULONG WINAPI GetIpNetTable(
    PMIB_IPNETTABLE IpNetTable, PULONG SizePointer, BOOL Order)
{
    LOG_CALL_FMT("Size=%lu", SizePointer ? *SizePointer : 0);
    (void)Order;
    if (!SizePointer) return ERROR_INVALID_PARAMETER;
    
    ULONG size = sizeof(MIB_IPNETTABLE);
    if (!IpNetTable || *SizePointer < size) {
        *SizePointer = size;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    ZeroMemory(IpNetTable, size);
    IpNetTable->dwNumEntries = 0;
    *SizePointer = size;
    LOG_MSG("  -> OK, NumEntries=0");
    return NO_ERROR;
}


DWORD WINAPI CreateIpNetEntry(PMIB_IPNETROW pArpEntry)
{
    LOG_CALL();
    (void)pArpEntry;
    return ERROR_ACCESS_DENIED;
}


DWORD WINAPI SetIpNetEntry(PMIB_IPNETROW pArpEntry)
{
    LOG_CALL();
    (void)pArpEntry;
    return ERROR_ACCESS_DENIED;
}


DWORD WINAPI DeleteIpNetEntry(PMIB_IPNETROW pArpEntry)
{
    LOG_CALL();
    (void)pArpEntry;
    return ERROR_ACCESS_DENIED;
}


DWORD WINAPI FlushIpNetTable(DWORD dwIfIndex)
{
    LOG_CALL_FMT("IfIndex=%lu", dwIfIndex);
    return ERROR_ACCESS_DENIED;
}


DWORD WINAPI CreateProxyArpEntry(DWORD dwAddress, DWORD dwMask, DWORD dwIfIndex)
{
    LOG_CALL_FMT("Address=%s", Ipv4ToString(dwAddress));
    (void)dwMask; (void)dwIfIndex;
    return ERROR_ACCESS_DENIED;
}


DWORD WINAPI DeleteProxyArpEntry(DWORD dwAddress, DWORD dwMask, DWORD dwIfIndex)
{
    LOG_CALL_FMT("Address=%s", Ipv4ToString(dwAddress));
    (void)dwMask; (void)dwIfIndex;
    return ERROR_ACCESS_DENIED;
}


DWORD WINAPI SendARP(IPAddr DestIP, IPAddr SrcIP, PVOID pMacAddr, PULONG PhyAddrLen)
{
    LOG_CALL_FMT("Dest=%s, Src=%s", Ipv4ToString(DestIP), Ipv4ToString(SrcIP));
    if (!pMacAddr || !PhyAddrLen || *PhyAddrLen < 6) {
        if (PhyAddrLen) *PhyAddrLen = 6;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    if (IsLocalIPv4(DestIP)) {
        CopyMemory(pMacAddr, ADAPTER_MAC, 6);
        *PhyAddrLen = 6;
        LOG_MSG("  -> OK (local)");
        return NO_ERROR;
    }
    
    LOG_MSG("  -> ERROR_BAD_NET_NAME (unreachable)");
    return ERROR_BAD_NET_NAME;
}

/* ============================================================================
 * ROUTING TABLE FUNCTIONS
 * ============================================================================ */


DWORD WINAPI CreateIpForwardEntry(PMIB_IPFORWARDROW pRoute)
{
    LOG_CALL();
    (void)pRoute;
    return ERROR_ACCESS_DENIED;
}


DWORD WINAPI SetIpForwardEntry(PMIB_IPFORWARDROW pRoute)
{
    LOG_CALL();
    (void)pRoute;
    return ERROR_ACCESS_DENIED;
}


DWORD WINAPI DeleteIpForwardEntry(PMIB_IPFORWARDROW pRoute)
{
    LOG_CALL();
    (void)pRoute;
    return ERROR_ACCESS_DENIED;
}

/* ============================================================================
 * TCP/UDP TABLE FUNCTIONS
 * ============================================================================ */


ULONG WINAPI GetTcpTable(PMIB_TCPTABLE TcpTable, PULONG SizePointer, BOOL Order)
{
    LOG_CALL_FMT("Size=%lu", SizePointer ? *SizePointer : 0);
    (void)Order;
    if (!SizePointer) return ERROR_INVALID_PARAMETER;
    
    ULONG size = sizeof(MIB_TCPTABLE);
    if (!TcpTable || *SizePointer < size) {
        *SizePointer = size;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    ZeroMemory(TcpTable, size);
    TcpTable->dwNumEntries = 0;
    *SizePointer = size;
    LOG_MSG("  -> OK, NumEntries=0");
    return NO_ERROR;
}


ULONG WINAPI GetTcpTable2(PMIB_TCPTABLE2 TcpTable, PULONG SizePointer, BOOL Order)
{
    LOG_CALL_FMT("Size=%lu", SizePointer ? *SizePointer : 0);
    (void)Order;
    if (!SizePointer) return ERROR_INVALID_PARAMETER;
    
    ULONG size = sizeof(MIB_TCPTABLE2);
    if (!TcpTable || *SizePointer < size) {
        *SizePointer = size;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    ZeroMemory(TcpTable, size);
    TcpTable->dwNumEntries = 0;
    *SizePointer = size;
    LOG_MSG("  -> OK, NumEntries=0");
    return NO_ERROR;
}


ULONG WINAPI GetTcp6Table(PMIB_TCP6TABLE TcpTable, PULONG SizePointer, BOOL Order)
{
    LOG_CALL_FMT("Size=%lu", SizePointer ? *SizePointer : 0);
    (void)Order;
    if (!SizePointer) return ERROR_INVALID_PARAMETER;
    
    ULONG size = sizeof(MIB_TCP6TABLE);
    if (!TcpTable || *SizePointer < size) {
        *SizePointer = size;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    ZeroMemory(TcpTable, size);
    TcpTable->dwNumEntries = 0;
    *SizePointer = size;
    return NO_ERROR;
}


ULONG WINAPI GetTcp6Table2(PMIB_TCP6TABLE2 TcpTable, PULONG SizePointer, BOOL Order)
{
    LOG_CALL_FMT("Size=%lu", SizePointer ? *SizePointer : 0);
    (void)Order;
    if (!SizePointer) return ERROR_INVALID_PARAMETER;
    
    ULONG size = sizeof(MIB_TCP6TABLE2);
    if (!TcpTable || *SizePointer < size) {
        *SizePointer = size;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    ZeroMemory(TcpTable, size);
    TcpTable->dwNumEntries = 0;
    *SizePointer = size;
    return NO_ERROR;
}


ULONG WINAPI GetUdpTable(PMIB_UDPTABLE UdpTable, PULONG SizePointer, BOOL Order)
{
    LOG_CALL_FMT("Size=%lu", SizePointer ? *SizePointer : 0);
    (void)Order;
    if (!SizePointer) return ERROR_INVALID_PARAMETER;
    
    ULONG size = sizeof(MIB_UDPTABLE);
    if (!UdpTable || *SizePointer < size) {
        *SizePointer = size;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    ZeroMemory(UdpTable, size);
    UdpTable->dwNumEntries = 0;
    *SizePointer = size;
    LOG_MSG("  -> OK, NumEntries=0");
    return NO_ERROR;
}


ULONG WINAPI GetUdp6Table(PMIB_UDP6TABLE Udp6Table, PULONG SizePointer, BOOL Order)
{
    LOG_CALL_FMT("Size=%lu", SizePointer ? *SizePointer : 0);
    (void)Order;
    if (!SizePointer) return ERROR_INVALID_PARAMETER;
    
    ULONG size = sizeof(MIB_UDP6TABLE);
    if (!Udp6Table || *SizePointer < size) {
        *SizePointer = size;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    ZeroMemory(Udp6Table, size);
    Udp6Table->dwNumEntries = 0;
    *SizePointer = size;
    return NO_ERROR;
}


DWORD WINAPI GetExtendedTcpTable(
    PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder,
    ULONG ulAf, TCP_TABLE_CLASS TableClass, ULONG Reserved)
{
    LOG_CALL_FMT("Family=%lu, Class=%d", ulAf, TableClass);
    (void)bOrder; (void)Reserved;
    if (!pdwSize) return ERROR_INVALID_PARAMETER;
    
    DWORD size = 64;
    if (!pTcpTable || *pdwSize < size) {
        *pdwSize = size;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    ZeroMemory(pTcpTable, size);
    *pdwSize = size;
    LOG_MSG("  -> OK, NumEntries=0");
    return NO_ERROR;
}


DWORD WINAPI GetExtendedUdpTable(
    PVOID pUdpTable, PDWORD pdwSize, BOOL bOrder,
    ULONG ulAf, UDP_TABLE_CLASS TableClass, ULONG Reserved)
{
    LOG_CALL_FMT("Family=%lu, Class=%d", ulAf, TableClass);
    (void)bOrder; (void)Reserved;
    if (!pdwSize) return ERROR_INVALID_PARAMETER;
    
    DWORD size = 64;
    if (!pUdpTable || *pdwSize < size) {
        *pdwSize = size;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    ZeroMemory(pUdpTable, size);
    *pdwSize = size;
    LOG_MSG("  -> OK, NumEntries=0");
    return NO_ERROR;
}


DWORD WINAPI SetTcpEntry(PMIB_TCPROW pTcpRow)
{
    LOG_CALL();
    (void)pTcpRow;
    return ERROR_ACCESS_DENIED;
}

/* ============================================================================
 * STATISTICS FUNCTIONS
 * ============================================================================ */


ULONG WINAPI GetIpStatistics(PMIB_IPSTATS Statistics)
{
    LOG_CALL();
    if (!Statistics) return ERROR_INVALID_PARAMETER;
    
    ZeroMemory(Statistics, sizeof(MIB_IPSTATS));
    Statistics->dwForwarding = 1;
    Statistics->dwDefaultTTL = 64;
    Statistics->dwNumIf = 1;
    Statistics->dwNumAddr = 1;
    Statistics->dwNumRoutes = 1;
    LOG_MSG("  -> OK");
    return NO_ERROR;
}


ULONG WINAPI GetIpStatisticsEx(PMIB_IPSTATS Statistics, ULONG Family)
{
    LOG_CALL_FMT("Family=%lu", Family);
    return GetIpStatistics(Statistics);
}


ULONG WINAPI SetIpStatistics(PMIB_IPSTATS pIpStats)
{
    LOG_CALL();
    (void)pIpStats;
    return ERROR_ACCESS_DENIED;
}


ULONG WINAPI SetIpStatisticsEx(PMIB_IPSTATS Statistics, ULONG Family)
{
    LOG_CALL_FMT("Family=%lu", Family);
    (void)Statistics;
    return ERROR_ACCESS_DENIED;
}


DWORD WINAPI SetIpTTL(UINT nTTL)
{
    LOG_CALL_FMT("TTL=%u", nTTL);
    return ERROR_ACCESS_DENIED;
}


ULONG WINAPI GetIcmpStatistics(PMIB_ICMP Statistics)
{
    LOG_CALL();
    if (!Statistics) return ERROR_INVALID_PARAMETER;
    ZeroMemory(Statistics, sizeof(MIB_ICMP));
    LOG_MSG("  -> OK");
    return NO_ERROR;
}


ULONG WINAPI GetIcmpStatisticsEx(PMIB_ICMP_EX Statistics, ULONG Family)
{
    LOG_CALL_FMT("Family=%lu", Family);
    if (!Statistics) return ERROR_INVALID_PARAMETER;
    ZeroMemory(Statistics, sizeof(MIB_ICMP_EX));
    return NO_ERROR;
}


ULONG WINAPI GetTcpStatistics(PMIB_TCPSTATS Statistics)
{
    LOG_CALL();
    if (!Statistics) return ERROR_INVALID_PARAMETER;
    
    ZeroMemory(Statistics, sizeof(MIB_TCPSTATS));
    Statistics->dwRtoAlgorithm = 4;
    Statistics->dwRtoMin = 300;
    Statistics->dwRtoMax = 120000;
    Statistics->dwMaxConn = 0xFFFFFFFF;
    LOG_MSG("  -> OK");
    return NO_ERROR;
}


ULONG WINAPI GetTcpStatisticsEx(PMIB_TCPSTATS Statistics, ULONG Family)
{
    LOG_CALL_FMT("Family=%lu", Family);
    return GetTcpStatistics(Statistics);
}


ULONG WINAPI GetTcpStatisticsEx2(PMIB_TCPSTATS Statistics, ULONG Family)
{
    LOG_CALL_FMT("Family=%lu", Family);
    if (!Statistics) return ERROR_INVALID_PARAMETER;
    ZeroMemory(Statistics, sizeof(MIB_TCPSTATS));
    Statistics->dwRtoAlgorithm = 4;  // НЕ RtoAlgorithm!
    Statistics->dwRtoMin = 300;
    Statistics->dwRtoMax = 120000;
    Statistics->dwMaxConn = 0xFFFFFFFF;
    return NO_ERROR;
}

ULONG WINAPI GetUdpStatistics(PMIB_UDPSTATS Stats)
{
    LOG_CALL();
    if (!Stats) return ERROR_INVALID_PARAMETER;
    ZeroMemory(Stats, sizeof(MIB_UDPSTATS));
    LOG_MSG("  -> OK");
    return NO_ERROR;
}


ULONG WINAPI GetUdpStatisticsEx(PMIB_UDPSTATS Statistics, ULONG Family)
{
    LOG_CALL_FMT("Family=%lu", Family);
    return GetUdpStatistics(Statistics);
}


ULONG WINAPI GetUdpStatisticsEx2(PMIB_UDPSTATS Statistics, ULONG Family)
{
    LOG_CALL_FMT("Family=%lu", Family);
    if (!Statistics) return ERROR_INVALID_PARAMETER;
    ZeroMemory(Statistics, sizeof(MIB_UDPSTATS));
    return NO_ERROR;
}

/* ============================================================================
 * INTERFACE INFORMATION FUNCTIONS
 * ============================================================================ */

DWORD WINAPI ConvertStringToGuidW(const WCHAR *str, GUID *guid)
{
    int res, i;  /* Декларація на початку функції для C89 */
    unsigned int d1, d2, d3, d4[8];
    
    LOG_CALL_FMT("str=\"%S\"", str ? str : L"(null)");
    
    if (!str || !guid) {
        return ERROR_INVALID_PARAMETER;
    }
    
    /* Формат: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} */
    res = swscanf(str, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                  &d1, &d2, &d3, 
                  &d4[0], &d4[1], &d4[2], &d4[3], 
                  &d4[4], &d4[5], &d4[6], &d4[7]);
    
    if (res != 11) {
        ZeroMemory(guid, sizeof(GUID));
        LOG_MSG("  -> ERROR_INVALID_PARAMETER (parse failed)");
        return ERROR_INVALID_PARAMETER;
    }
    
    guid->Data1 = d1;
    guid->Data2 = (WORD)d2;
    guid->Data3 = (WORD)d3;
    for (i = 0; i < 8; i++) {
        guid->Data4[i] = (BYTE)d4[i];
    }
    
    LOG_MSG("  -> OK");
    return NO_ERROR;
}

DWORD WINAPI ConvertInterfaceLuidToIndex(const NET_LUID *InterfaceLuid, PNET_IFINDEX InterfaceIndex)
{
    LOG_CALL();
    if (!InterfaceLuid || !InterfaceIndex) return ERROR_INVALID_PARAMETER;
    
    if (InterfaceLuid->Value == ADAPTER_LUID.Value) {
        *InterfaceIndex = ADAPTER_IF_INDEX;
        return NO_ERROR;
    }
    return ERROR_FILE_NOT_FOUND;
}

DWORD WINAPI ConvertInterfaceGuidToLuid(const GUID *InterfaceGuid, PNET_LUID InterfaceLuid)
{
    LOG_CALL();
    
    if (!InterfaceGuid || !InterfaceLuid) {
        return ERROR_INVALID_PARAMETER;
    }
    
    /* Перевіряємо чи GUID відповідає нашому адаптеру */
    if (IsEqualGUID(InterfaceGuid, &ADAPTER_GUID)) {
        *InterfaceLuid = ADAPTER_LUID;
        LOG_MSG("  -> OK, LUID=0x%llX", ADAPTER_LUID.Value);
        return NO_ERROR;
    }
    
    InterfaceLuid->Value = 0;
    LOG_MSG("  -> ERROR_FILE_NOT_FOUND");
    return ERROR_FILE_NOT_FOUND;
}

DWORD WINAPI GetInterfaceInfo(PIP_INTERFACE_INFO pIfTable, PULONG dwOutBufLen)
{
    LOG_CALL_FMT("Size=%lu", dwOutBufLen ? *dwOutBufLen : 0);
    if (!dwOutBufLen) return ERROR_INVALID_PARAMETER;
    
    ULONG size = sizeof(IP_INTERFACE_INFO);
    if (!pIfTable || *dwOutBufLen < size) {
        *dwOutBufLen = size;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    ZeroMemory(pIfTable, size);
    pIfTable->NumAdapters = 1;
    pIfTable->Adapter[0].Index = ADAPTER_IF_INDEX;
    wsprintfW(pIfTable->Adapter[0].Name, L"\\DEVICE\\TCPIP_%S", ADAPTER_NAME);
    
    *dwOutBufLen = size;
    LOG_MSG("  -> OK, NumAdapters=1");
    return NO_ERROR;
}

DWORD WINAPI GetAdapterIndex(LPWSTR AdapterName, PULONG IfIndex)
{
    NET_LUID luid;
    GUID guid;
    DWORD err;
    SIZE_T prefix_len;
    
    LOG_CALL_FMT("AdapterName=\"%S\"", AdapterName ? AdapterName : L"(null)");
    
    if (!AdapterName || !IfIndex) {
        return ERROR_INVALID_PARAMETER;
    }
    
    prefix_len = wcslen(DEVICE_TCPIP);
    if (wcslen(AdapterName) < prefix_len) {
        LOG_MSG("  -> ERROR_INVALID_PARAMETER (name too short)");
        return ERROR_INVALID_PARAMETER;
    }
    
    /* Парсимо GUID після префікса \DEVICE\TCPIP_ */
    err = ConvertStringToGuidW(AdapterName + prefix_len, &guid);
    if (err) {
        LOG_MSG("  -> ConvertStringToGuidW failed: %lu", err);
        return err;
    }
    
    err = ConvertInterfaceGuidToLuid(&guid, &luid);
    if (err) {
        LOG_MSG("  -> ConvertInterfaceGuidToLuid failed: %lu", err);
        return err;
    }
    
    err = ConvertInterfaceLuidToIndex(&luid, IfIndex);
    if (err) {
        LOG_MSG("  -> ConvertInterfaceLuidToIndex failed: %lu", err);
        return err;
    }
    
    LOG_MSG("  -> OK, Index=%lu", *IfIndex);
    return NO_ERROR;
}


PIP_ADAPTER_ORDER_MAP WINAPI GetAdapterOrderMap(VOID)
{
    LOG_CALL();
    static IP_ADAPTER_ORDER_MAP map;
    map.NumAdapters = 1;
    map.AdapterOrder[0] = ADAPTER_IF_INDEX;
    LOG_MSG("  -> OK");
    return &map;
}


DWORD WINAPI GetBestInterface(IPAddr dwDestAddr, PDWORD pdwBestIfIndex)
{
    LOG_CALL_FMT("Dest=%s", Ipv4ToString(dwDestAddr));
    if (!pdwBestIfIndex) return ERROR_INVALID_PARAMETER;
    
    if (IsLocalIPv4(dwDestAddr)) {
        *pdwBestIfIndex = ADAPTER_IF_INDEX;
        LOG_MSG("  -> OK, Index=%lu", ADAPTER_IF_INDEX);
        return NO_ERROR;
    }
    
    LOG_MSG("  -> ERROR_NETWORK_UNREACHABLE");
    return ERROR_NETWORK_UNREACHABLE;
}


DWORD WINAPI GetBestInterfaceEx(struct sockaddr *pDestAddr, PDWORD pdwBestIfIndex)
{
    LOG_CALL();
    if (!pDestAddr || !pdwBestIfIndex) return ERROR_INVALID_PARAMETER;
    
    if (pDestAddr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)pDestAddr;
        return GetBestInterface(sin->sin_addr.s_addr, pdwBestIfIndex);
    }
    
    *pdwBestIfIndex = ADAPTER_IF_INDEX;
    return NO_ERROR;
}


DWORD WINAPI GetFriendlyIfIndex(DWORD IfIndex)
{
    LOG_CALL_FMT("Index=%lu", IfIndex);
    return IfIndex;
}


DWORD WINAPI GetUniDirectionalAdapterInfo(
    PIP_UNIDIRECTIONAL_ADAPTER_ADDRESS pIPIfInfo, PULONG dwOutBufLen)
{
    LOG_CALL();
    if (!dwOutBufLen) return ERROR_INVALID_PARAMETER;
    
    ULONG size = sizeof(IP_UNIDIRECTIONAL_ADAPTER_ADDRESS);
    if (!pIPIfInfo || *dwOutBufLen < size) {
        *dwOutBufLen = size;
        return ERROR_BUFFER_OVERFLOW;
    }
    
    ZeroMemory(pIPIfInfo, size);
    pIPIfInfo->NumAdapters = 0;
    *dwOutBufLen = size;
    return NO_ERROR;
}

/* ============================================================================
 * NETWORK PARAMS FUNCTIONS
 * ============================================================================ */


DWORD WINAPI GetNetworkParams(PFIXED_INFO pFixedInfo, PULONG pOutBufLen)
{
    LOG_CALL_FMT("Size=%lu", pOutBufLen ? *pOutBufLen : 0);
    if (!pOutBufLen) return ERROR_INVALID_PARAMETER;
    
    ULONG size = sizeof(FIXED_INFO);
    if (!pFixedInfo || *pOutBufLen < size) {
        *pOutBufLen = size;
        return ERROR_BUFFER_OVERFLOW;
    }
    
    ZeroMemory(pFixedInfo, size);
    lstrcpyA(pFixedInfo->HostName, "DESKTOP");
    lstrcpyA(pFixedInfo->DomainName, "local");
    pFixedInfo->NodeType = 1;
    pFixedInfo->EnableRouting = 0;
    pFixedInfo->EnableProxy = 0;
    pFixedInfo->EnableDns = 1;
    
    *pOutBufLen = size;
    LOG_MSG("  -> OK, Host=DESKTOP");
    return NO_ERROR;
}


DWORD WINAPI GetPerAdapterInfo(ULONG IfIndex, PIP_PER_ADAPTER_INFO pPerAdapterInfo, PULONG pOutBufLen)
{
    LOG_CALL_FMT("IfIndex=%lu", IfIndex);
    if (!pOutBufLen) return ERROR_INVALID_PARAMETER;
    
    ULONG size = sizeof(IP_PER_ADAPTER_INFO);
    if (!pPerAdapterInfo || *pOutBufLen < size) {
        *pOutBufLen = size;
        return ERROR_BUFFER_OVERFLOW;
    }
    
    ZeroMemory(pPerAdapterInfo, size);
    pPerAdapterInfo->AutoconfigEnabled = 0;
    pPerAdapterInfo->AutoconfigActive = 0;
    
    *pOutBufLen = size;
    return NO_ERROR;
}

/* ============================================================================
 * DHCP FUNCTIONS
 * ============================================================================ */


DWORD WINAPI IpReleaseAddress(PIP_ADAPTER_INDEX_MAP AdapterInfo)
{
    LOG_CALL();
    (void)AdapterInfo;
    LOG_MSG("  -> ERROR_NOT_SUPPORTED (no DHCP)");
    return ERROR_NOT_SUPPORTED;
}


DWORD WINAPI IpRenewAddress(PIP_ADAPTER_INDEX_MAP AdapterInfo)
{
    LOG_CALL();
    (void)AdapterInfo;
    LOG_MSG("  -> ERROR_NOT_SUPPORTED (no DHCP)");
    return ERROR_NOT_SUPPORTED;
}

/* ============================================================================
 * NOTIFICATION FUNCTIONS
 * ============================================================================ */


DWORD WINAPI NotifyAddrChange(PHANDLE Handle, LPOVERLAPPED overlapped)
{
    LOG_CALL();
    if (!overlapped) return ERROR_IO_PENDING;
    if (Handle) *Handle = INVALID_HANDLE_VALUE;
    return ERROR_IO_PENDING;
}


DWORD WINAPI NotifyRouteChange(PHANDLE Handle, LPOVERLAPPED overlapped)
{
    LOG_CALL();
    if (!overlapped) return ERROR_IO_PENDING;
    if (Handle) *Handle = INVALID_HANDLE_VALUE;
    return ERROR_IO_PENDING;
}


BOOL WINAPI CancelIPChangeNotify(LPOVERLAPPED notifyOverlapped)
{
    LOG_CALL();
    (void)notifyOverlapped;
    return TRUE;
}


DWORD WINAPI CancelMibChangeNotify2(HANDLE NotificationHandle)
{
    LOG_CALL();
    (void)NotificationHandle;
    return NO_ERROR;
}

/* ============================================================================
 * ROUTER FUNCTIONS
 * ============================================================================ */


DWORD WINAPI EnableRouter(HANDLE* pHandle, OVERLAPPED* pOverlapped)
{
    LOG_CALL();
    if (pHandle) *pHandle = NULL;
    (void)pOverlapped;
    return ERROR_NOT_SUPPORTED;
}


DWORD WINAPI UnenableRouter(OVERLAPPED* pOverlapped, LPDWORD lpdwEnableCount)
{
    LOG_CALL();
    (void)pOverlapped;
    if (lpdwEnableCount) *lpdwEnableCount = 0;
    return ERROR_NOT_SUPPORTED;
}


DWORD WINAPI DisableMediaSense(HANDLE *pHandle, OVERLAPPED *pOverLapped)
{
    LOG_CALL();
    if (pHandle) *pHandle = NULL;
    (void)pOverLapped;
    return NO_ERROR;
}


DWORD WINAPI RestoreMediaSense(OVERLAPPED* pOverlapped, LPDWORD lpdwEnableCount)
{
    LOG_CALL();
    (void)pOverlapped;
    if (lpdwEnableCount) *lpdwEnableCount = 0;
    return NO_ERROR;
}

/* ============================================================================
 * INTERFACE CONVERSION FUNCTIONS
 * ============================================================================ */


DWORD WINAPI ConvertInterfaceIndexToLuid(NET_IFINDEX InterfaceIndex, PNET_LUID InterfaceLuid)
{
    LOG_CALL_FMT("Index=%lu", InterfaceIndex);
    if (!InterfaceLuid) return ERROR_INVALID_PARAMETER;
    
    if (InterfaceIndex == ADAPTER_IF_INDEX) {
        *InterfaceLuid = ADAPTER_LUID;
        return NO_ERROR;
    }
    return ERROR_FILE_NOT_FOUND;
}


DWORD WINAPI ConvertInterfaceLuidToNameA(const NET_LUID *InterfaceLuid, PSTR InterfaceName, SIZE_T Length)
{
    WCHAR nameW[IF_MAX_STRING_SIZE + 1];
    DWORD err;
    
    LOG_CALL_FMT("LUID=0x%llX, Length=%zu", 
        InterfaceLuid ? InterfaceLuid->Value : 0, (size_t)Length);
    
    if (!InterfaceLuid) {
        return ERROR_INVALID_PARAMETER;
    }
    if (!InterfaceName || !Length) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    
    err = ConvertInterfaceLuidToNameW(InterfaceLuid, nameW, ARRAYSIZE(nameW));
    if (err) return err;
    
    if (!WideCharToMultiByte(CP_ACP, 0, nameW, -1, InterfaceName, (int)Length, NULL, NULL)) {
        err = GetLastError();
        LOG_MSG("  -> WideCharToMultiByte failed: %lu", err);
        return err;
    }
    
    LOG_MSG("  -> OK, Name=\"%s\"", InterfaceName);
    return NO_ERROR;
}


DWORD WINAPI ConvertInterfaceLuidToNameW(const NET_LUID *InterfaceLuid, PWSTR InterfaceName, SIZE_T Length)
{
    DWORD i;
    const WCHAR *prefix = NULL;
    WCHAR buf[IF_MAX_STRING_SIZE + 1];
    int needed;
    
    LOG_CALL_FMT("LUID=0x%llX, Length=%zu", 
        InterfaceLuid ? InterfaceLuid->Value : 0, (size_t)Length);
    
    if (!InterfaceLuid || !InterfaceName) {
        return ERROR_INVALID_PARAMETER;
    }
    
    /* Перевіряємо чи це наш адаптер */
    if (InterfaceLuid->Value != ADAPTER_LUID.Value) {
        LOG_MSG("  -> ERROR_FILE_NOT_FOUND (unknown LUID)");
        return ERROR_FILE_NOT_FOUND;
    }
    
    /* Шукаємо префікс за типом інтерфейсу */
    for (i = 0; i < NAME_PREFIXES_COUNT; i++) {
        if (InterfaceLuid->Info.IfType == g_name_prefixes[i].type) {
            prefix = g_name_prefixes[i].prefix_w;
            break;
        }
    }
    
    /* Формуємо ім'я: prefix_NetLuidIndex або iftypeN_NetLuidIndex */
    if (prefix) {
        needed = swprintf(buf, ARRAYSIZE(buf), L"%s_%lu", prefix, 
            (ULONG)InterfaceLuid->Info.NetLuidIndex);
    } else {
        needed = swprintf(buf, ARRAYSIZE(buf), L"iftype%lu_%lu", 
            (ULONG)InterfaceLuid->Info.IfType, 
            (ULONG)InterfaceLuid->Info.NetLuidIndex);
    }
    
    if (needed < 0 || (SIZE_T)needed >= Length) {
        LOG_MSG("  -> ERROR_NOT_ENOUGH_MEMORY (need %d, have %zu)", needed + 1, (size_t)Length);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    
    memcpy(InterfaceName, buf, (needed + 1) * sizeof(WCHAR));
    LOG_MSG("  -> OK, Name=\"%S\"", InterfaceName);
    return NO_ERROR;
}


DWORD WINAPI ConvertInterfaceNameToLuidA(const CHAR *InterfaceName, PNET_LUID InterfaceLuid)
{
    WCHAR nameW[IF_MAX_STRING_SIZE + 1];
    
    LOG_CALL_FMT("Name=\"%s\"", InterfaceName ? InterfaceName : "(null)");
    
    if (!InterfaceName) {
        return ERROR_INVALID_NAME;
    }
    
    if (!MultiByteToWideChar(CP_ACP, 0, InterfaceName, -1, nameW, ARRAYSIZE(nameW))) {
        return GetLastError();
    }
    
    return ConvertInterfaceNameToLuidW(nameW, InterfaceLuid);
}


DWORD WINAPI ConvertInterfaceNameToLuidW(const WCHAR *InterfaceName, PNET_LUID InterfaceLuid)
{
    const WCHAR *sep;
    DWORD type = ~0u, i;
    WCHAR buf[IF_MAX_STRING_SIZE + 1];
    SIZE_T prefix_len;
    
    LOG_CALL_FMT("Name=\"%S\"", InterfaceName ? InterfaceName : L"(null)");
    
    if (!InterfaceLuid) {
        return ERROR_INVALID_PARAMETER;
    }
    
    memset(InterfaceLuid, 0, sizeof(*InterfaceLuid));
    
    if (!InterfaceName) {
        return ERROR_INVALID_NAME;
    }
    
    /* Шукаємо роздільник '_' */
    sep = wcschr(InterfaceName, L'_');
    if (!sep || sep == InterfaceName) {
        LOG_MSG("  -> ERROR_INVALID_NAME (no separator)");
        return ERROR_INVALID_NAME;
    }
    
    prefix_len = sep - InterfaceName;
    if (prefix_len >= ARRAYSIZE(buf)) {
        LOG_MSG("  -> ERROR_INVALID_NAME (prefix too long)");
        return ERROR_INVALID_NAME;
    }
    
    /* Копіюємо префікс */
    memcpy(buf, InterfaceName, prefix_len * sizeof(WCHAR));
    buf[prefix_len] = L'\0';
    
    /* Перевіряємо чи це "iftypeN" формат */
    if (prefix_len > 6 && !wcsncmp(buf, L"iftype", 6)) {
        type = wcstoul(buf + 6, NULL, 10);
    } else {
        /* Шукаємо у таблиці префіксів */
        for (i = 0; i < NAME_PREFIXES_COUNT; i++) {
            if (!_wcsicmp(buf, g_name_prefixes[i].prefix_w)) {
                type = g_name_prefixes[i].type;
                break;
            }
        }
    }
    
    if (type == ~0u) {
        LOG_MSG("  -> ERROR_INVALID_NAME (unknown prefix: %S)", buf);
        return ERROR_INVALID_NAME;
    }
    
    /* Парсимо NetLuidIndex після '_' */
    InterfaceLuid->Info.IfType = (ULONG64)type;
    InterfaceLuid->Info.NetLuidIndex = wcstoul(sep + 1, NULL, 10);
    
    /* Перевіряємо чи результат відповідає нашому адаптеру */
    if (InterfaceLuid->Value != ADAPTER_LUID.Value) {
        LOG_MSG("  -> ERROR_FILE_NOT_FOUND (LUID 0x%llX not found)", InterfaceLuid->Value);
        memset(InterfaceLuid, 0, sizeof(*InterfaceLuid));
        return ERROR_FILE_NOT_FOUND;
    }
    
    LOG_MSG("  -> OK, LUID=0x%llX", InterfaceLuid->Value);
    return NO_ERROR;
}


DWORD WINAPI ConvertInterfaceLuidToAlias(const NET_LUID *InterfaceLuid, PWSTR InterfaceAlias, SIZE_T Length)
{
    SIZE_T needed;
    
    LOG_CALL_FMT("LUID=0x%llX, Length=%zu", 
        InterfaceLuid ? InterfaceLuid->Value : 0, (size_t)Length);
    
    if (!InterfaceLuid || !InterfaceAlias) {
        return ERROR_INVALID_PARAMETER;
    }
    
    if (InterfaceLuid->Value != ADAPTER_LUID.Value) {
        LOG_MSG("  -> ERROR_FILE_NOT_FOUND");
        return ERROR_FILE_NOT_FOUND;
    }
    
    needed = wcslen(ADAPTER_FRIENDLY_NAME) + 1;
    if (Length < needed) {
        LOG_MSG("  -> ERROR_NOT_ENOUGH_MEMORY (need %zu, have %zu)", needed, (size_t)Length);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    
    wcscpy(InterfaceAlias, ADAPTER_FRIENDLY_NAME);
    LOG_MSG("  -> OK, Alias=\"%S\"", InterfaceAlias);
    return NO_ERROR;
}

DWORD WINAPI ConvertGuidToStringA(const GUID *guid, char *str, DWORD len)
{
    LOG_CALL();
    
    if (!guid || !str) return ERROR_INVALID_PARAMETER;
    if (len < CHARS_IN_GUID) return ERROR_INSUFFICIENT_BUFFER;
    
    sprintf(str, "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            guid->Data1, guid->Data2, guid->Data3,
            guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
            guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
    
    return NO_ERROR;
}

DWORD WINAPI ConvertGuidToStringW(const GUID *guid, WCHAR *str, DWORD len)
{
    LOG_CALL();
    
    if (!guid || !str) return ERROR_INVALID_PARAMETER;
    if (len < CHARS_IN_GUID) return ERROR_INSUFFICIENT_BUFFER;
    
    swprintf(str, len, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             guid->Data1, guid->Data2, guid->Data3,
             guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
             guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
    
    return NO_ERROR;
}

DWORD WINAPI ConvertInterfaceAliasToLuid(const WCHAR *InterfaceAlias, PNET_LUID InterfaceLuid)
{
    LOG_CALL_FMT("Alias=\"%S\"", InterfaceAlias ? InterfaceAlias : L"(null)");
    
    if (!InterfaceAlias || !*InterfaceAlias || !InterfaceLuid) {
        return ERROR_INVALID_PARAMETER;
    }
    
    InterfaceLuid->Value = 0;
    
    /* Порівнюємо з нашим friendly name (alias) */
    if (_wcsicmp(InterfaceAlias, ADAPTER_FRIENDLY_NAME) == 0) {
        *InterfaceLuid = ADAPTER_LUID;
        LOG_MSG("  -> OK, LUID=0x%llX", ADAPTER_LUID.Value);
        return NO_ERROR;
    }
    
    LOG_MSG("  -> ERROR_INVALID_PARAMETER (alias not found)");
    return ERROR_INVALID_PARAMETER;
}


DWORD WINAPI ConvertInterfaceLuidToGuid(const NET_LUID *InterfaceLuid, GUID *InterfaceGuid)
{
    LOG_CALL_FMT("LUID=0x%llX", InterfaceLuid ? InterfaceLuid->Value : 0);
    
    if (!InterfaceLuid || !InterfaceGuid) {
        return ERROR_INVALID_PARAMETER;
    }
    
    if (InterfaceLuid->Value == ADAPTER_LUID.Value) {
        *InterfaceGuid = ADAPTER_GUID;
        LOG_MSG("  -> OK");
        return NO_ERROR;
    }
    
    ZeroMemory(InterfaceGuid, sizeof(GUID));
    LOG_MSG("  -> ERROR_FILE_NOT_FOUND");
    return ERROR_FILE_NOT_FOUND;
}

/* ============================================================================
 * IP MASK CONVERSION
 * ============================================================================ */

DWORD WINAPI ConvertIpv4MaskToLength(ULONG Mask, PUINT8 MaskLength)
{
    ULONG host_mask;
    UINT8 len = 0;
    
    LOG_CALL_FMT("Mask=0x%08lX", Mask);
    
    if (!MaskLength) {
        return ERROR_INVALID_PARAMETER;
    }
    
    /* Конвертуємо з network byte order в host byte order */
    host_mask = FAKE_ntohl(Mask);
    
    /* Рахуємо ведучі одиничні біти */
    while (host_mask & 0x80000000) {
        len++;
        host_mask <<= 1;
    }
    
    *MaskLength = len;
    LOG_MSG("  -> Length=%u", len);
    return NO_ERROR;
}


DWORD WINAPI ConvertLengthToIpv4Mask(ULONG MaskLength, PULONG Mask)
{
    LOG_CALL_FMT("Length=%lu", MaskLength);
    
    if (!Mask) {
        return ERROR_INVALID_PARAMETER;
    }
    
    if (MaskLength > 32) {
        *Mask = INADDR_NONE;  /* 0xFFFFFFFF */
        return ERROR_INVALID_PARAMETER;
    }
    
    if (MaskLength == 0) {
        *Mask = 0;
    } else {
        *Mask = FAKE_htonl(~0u << (32 - MaskLength));
    }
    
    LOG_MSG("  -> Mask=0x%08lX", *Mask);
    return NO_ERROR;
}

/* ============================================================================
 * RTT AND HOP COUNT
 * ============================================================================ */


BOOL WINAPI GetRTTAndHopCount(IPAddr DestIpAddress, PULONG HopCount, ULONG MaxHops, PULONG RTT)
{
    LOG_CALL_FMT("Dest=%s, MaxHops=%lu", Ipv4ToString(DestIpAddress), MaxHops);
    if (!HopCount || !RTT) return FALSE;
    
    if (IsLocalIPv4(DestIpAddress)) {
        *HopCount = 1;
        *RTT = 1;
        return TRUE;
    }
    
    *HopCount = 0;
    *RTT = 0;
    return FALSE;
}

/* ============================================================================
 * ERROR STRING FUNCTION
 * ============================================================================ */


DWORD WINAPI GetIpErrorString(IP_STATUS ErrorCode, PWSTR Buffer, PDWORD Size)
{
    LOG_CALL_FMT("ErrorCode=%lu", ErrorCode);
    if (!Size) return ERROR_INVALID_PARAMETER;
    
    const WCHAR *msg = L"Unknown error";
    
    switch (ErrorCode) {
        case 0: msg = L"Success"; break;
        case 11010: msg = L"Request timed out"; break;
        case 11002: msg = L"Destination net unreachable"; break;
        case 11003: msg = L"Destination host unreachable"; break;
    }
    
    DWORD len = (DWORD)(lstrlenW(msg) + 1);
    if (!Buffer || *Size < len) {
        *Size = len;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    lstrcpyW(Buffer, msg);
    *Size = len;
    return NO_ERROR;
}

/* ============================================================================
 * OWNER MODULE FUNCTIONS
 * ============================================================================ */


DWORD WINAPI GetOwnerModuleFromTcpEntry(
    PMIB_TCPROW_OWNER_MODULE pTcpEntry,
    TCPIP_OWNER_MODULE_INFO_CLASS Class,
    PVOID pBuffer,
    PDWORD pdwSize)
{
    LOG_CALL();
    (void)pTcpEntry; (void)Class; (void)pBuffer;
    if (pdwSize) *pdwSize = 0;
    return ERROR_NOT_FOUND;
}

DWORD WINAPI GetOwnerModuleFromTcp6Entry(
    PMIB_TCP6ROW_OWNER_MODULE pTcpEntry,
    TCPIP_OWNER_MODULE_INFO_CLASS Class,
    PVOID pBuffer,
    PDWORD pdwSize)
{
    LOG_CALL();
    (void)pTcpEntry; (void)Class; (void)pBuffer;
    if (pdwSize) *pdwSize = 0;
    return ERROR_NOT_FOUND;
}

DWORD WINAPI GetOwnerModuleFromUdpEntry(
    PMIB_UDPROW_OWNER_MODULE pUdpEntry,
    TCPIP_OWNER_MODULE_INFO_CLASS Class,
    PVOID pBuffer,
    PDWORD pdwSize)
{
    LOG_CALL();
    (void)pUdpEntry; (void)Class; (void)pBuffer;
    if (pdwSize) *pdwSize = 0;
    return ERROR_NOT_FOUND;
}

DWORD WINAPI GetOwnerModuleFromUdp6Entry(
    PMIB_UDP6ROW_OWNER_MODULE pUdpEntry,
    TCPIP_OWNER_MODULE_INFO_CLASS Class,
    PVOID pBuffer,
    PDWORD pdwSize)
{
    LOG_CALL();
    (void)pUdpEntry; (void)Class; (void)pBuffer;
    if (pdwSize) *pdwSize = 0;
    return ERROR_NOT_FOUND;
}


DWORD GetOwnerModuleFromPidAndInfo(ULONG ulPid, ULONGLONG *pInfo, TCPIP_OWNER_MODULE_INFO_CLASS Class, PVOID pBuffer, PDWORD pdwSize)
{
    LOG_CALL_FMT("PID=%lu", ulPid);
    (void)pInfo; (void)Class; (void)pBuffer;
    if (pdwSize) *pdwSize = 0;
    return ERROR_NOT_FOUND;
}

/* ============================================================================
 * if_indextoname / if_nametoindex (POSIX-style, RFC 2553)
 * 
 * Згідно MSDN, ці функції еквівалентні:
 *   if_indextoname = ConvertInterfaceIndexToLuid + ConvertInterfaceLuidToNameA
 *   if_nametoindex = ConvertInterfaceNameToLuidA + ConvertInterfaceLuidToIndex
 * ============================================================================ */

PCHAR WINAPI if_indextoname(NET_IFINDEX InterfaceIndex, PCHAR InterfaceName)
{
    NET_LUID luid;
    DWORD err;
    
    LOG_CALL_FMT("Index=%lu", InterfaceIndex);
    
    if (!InterfaceName) {
        LOG_MSG("  -> NULL (InterfaceName is NULL)");
        return NULL;
    }
    
    /* Крок 1: Index -> LUID */
    err = ConvertInterfaceIndexToLuid(InterfaceIndex, &luid);
    if (err) {
        LOG_MSG("  -> NULL (ConvertInterfaceIndexToLuid failed: %lu)", err);
        return NULL;
    }
    
    /* Крок 2: LUID -> Name (буфер має бути >= IF_MAX_STRING_SIZE) */
    err = ConvertInterfaceLuidToNameA(&luid, InterfaceName, IF_MAX_STRING_SIZE);
    if (err) {
        LOG_MSG("  -> NULL (ConvertInterfaceLuidToNameA failed: %lu)", err);
        return NULL;
    }
    
    LOG_MSG("  -> \"%s\"", InterfaceName);
    return InterfaceName;
}


NET_IFINDEX WINAPI if_nametoindex(PCSTR InterfaceName)
{
    NET_LUID luid;
    NET_IFINDEX index;
    DWORD err;
    
    LOG_CALL_FMT("Name=\"%s\"", InterfaceName ? InterfaceName : "(null)");
    
    if (!InterfaceName) {
        LOG_MSG("  -> 0 (InterfaceName is NULL)");
        return 0;
    }
    
    /* Крок 1: Name -> LUID */
    err = ConvertInterfaceNameToLuidA(InterfaceName, &luid);
    if (err) {
        LOG_MSG("  -> 0 (ConvertInterfaceNameToLuidA failed: %lu)", err);
        return 0;
    }
    
    /* Крок 2: LUID -> Index */
    err = ConvertInterfaceLuidToIndex(&luid, &index);
    if (err) {
        LOG_MSG("  -> 0 (ConvertInterfaceLuidToIndex failed: %lu)", err);
        return 0;
    }
    
    LOG_MSG("  -> Index=%lu", index);
    return index;
}

/* ============================================================================
 * TEREDO FUNCTIONS
 * ============================================================================ */


DWORD WINAPI GetTeredoPort(PUSHORT Port)
{
    LOG_CALL();
    if (!Port) return ERROR_INVALID_PARAMETER;
    *Port = 0;
    return ERROR_NOT_READY;
}

/* ============================================================================
 * STUB FUNCTIONS FOR REMAINING EXPORTS
 * ============================================================================ */


DWORD WINAPI AllocateAndGetInterfaceInfoFromStack(PVOID *ppTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
{
    LOG_CALL();
    (void)bOrder; (void)hHeap; (void)dwFlags;
    if (ppTable) *ppTable = NULL;
    return ERROR_NOT_SUPPORTED;
}


DWORD WINAPI AllocateAndGetIpAddrTableFromStack(PVOID *ppTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags)
{
    LOG_CALL();
    (void)bOrder; (void)hHeap; (void)dwFlags;
    if (ppTable) *ppTable = NULL;
    return ERROR_NOT_SUPPORTED;
}


DWORD WINAPI NhpAllocateAndGetInterfaceInfoFromStack(
    IP_INTERFACE_NAME_INFO **ppTable,
    PDWORD pdwCount,
    BOOL bOrder,
    HANDLE hHeap,
    DWORD dwFlags)
{
    LOG_CALL();
    (void)bOrder; (void)hHeap; (void)dwFlags;
    if (ppTable) *ppTable = NULL;
    if (pdwCount) *pdwCount = 0;
    return ERROR_NOT_SUPPORTED;
}


DWORD WINAPI SetIfEntry(PMIB_IFROW pIfRow)
{
    LOG_CALL();
    (void)pIfRow;
    return ERROR_ACCESS_DENIED;
}


DWORD WINAPI GetIfEntry2Ex(DWORD Level, PMIB_IF_ROW2 Row)
{
    LOG_CALL_FMT("Level=%lu", Level);
    (void)Level;
    return GetIfEntry2(Row);
}


DWORD WINAPI GetIfTable2Ex(MIB_IF_TABLE_LEVEL Level, PMIB_IF_TABLE2 *Table)
{
    LOG_CALL_FMT("Level=%d", Level);
    (void)Level;
    return GetIfTable2(Table);
}

/* ============================================================================
 * COMPARTMENT FUNCTIONS
 * ============================================================================ */


NET_IF_COMPARTMENT_ID WINAPI GetCurrentThreadCompartmentId(VOID)
{
    LOG_CALL();
    return 1; /* Default compartment */
}


VOID WINAPI GetCurrentThreadCompartmentScope(
    PNET_IF_COMPARTMENT_SCOPE CompartmentScope,
    PNET_IF_COMPARTMENT_ID CompartmentId)
{
    LOG_CALL();
    if (CompartmentScope) *CompartmentScope = 0;
    if (CompartmentId) *CompartmentId = 1;
}


DWORD WINAPI SetCurrentThreadCompartmentId(NET_IF_COMPARTMENT_ID CompartmentId)
{
    LOG_CALL_FMT("CompartmentId=%u", (unsigned)CompartmentId);
    return NO_ERROR;
}


DWORD WINAPI SetCurrentThreadCompartmentScope(NET_IF_COMPARTMENT_SCOPE CompartmentScope)
{
    LOG_CALL_FMT("Scope=%u", (unsigned)CompartmentScope);
    return NO_ERROR;
}


DWORD WINAPI SetSessionCompartmentId(ULONG SessionId, NET_IF_COMPARTMENT_ID CompartmentId)
{
    LOG_CALL_FMT("SessionId=%lu, CompartmentId=%u", SessionId, (unsigned)CompartmentId);
    return NO_ERROR;
}

NET_IF_COMPARTMENT_ID WINAPI GetSessionCompartmentId(ULONG SessionId)
{
    LOG_CALL_FMT("SessionId=%lu", SessionId);
    return 1; /* Default compartment */
}

NET_IF_COMPARTMENT_ID WINAPI GetDefaultCompartmentId(VOID)
{
    LOG_CALL();
    return 1; /* Default compartment */
}

DWORD WINAPI GetJobCompartmentId(HANDLE JobHandle)
{
    LOG_CALL();
    (void)JobHandle;
    return 1;
}


DWORD WINAPI SetJobCompartmentId(HANDLE JobHandle, NET_IF_COMPARTMENT_ID CompartmentId)
{
    LOG_CALL();
    (void)JobHandle; (void)CompartmentId;
    return NO_ERROR;
}


DWORD WINAPI ConvertCompartmentGuidToId(CONST GUID *CompartmentGuid, PNET_IF_COMPARTMENT_ID CompartmentId)
{
    LOG_CALL();
    if (!CompartmentGuid || !CompartmentId) return ERROR_INVALID_PARAMETER;
    *CompartmentId = 1;
    return NO_ERROR;
}


DWORD WINAPI ConvertCompartmentIdToGuid(NET_IF_COMPARTMENT_ID CompartmentId, GUID *CompartmentGuid)
{
    LOG_CALL();
    if (!CompartmentGuid) return ERROR_INVALID_PARAMETER;
    ZeroMemory(CompartmentGuid, sizeof(GUID));
    return NO_ERROR;
}

/* ============================================================================
 * NETWORK INFORMATION FUNCTIONS
 * ============================================================================ */


DWORD WINAPI GetNetworkInformation(
    CONST NET_IF_NETWORK_GUID *NetworkGuid,
    PNET_IF_COMPARTMENT_ID CompartmentId,
    PULONG SiteId,
    PWCHAR NetworkName,
    ULONG Length)
{
    LOG_CALL();
    if (!NetworkGuid) return ERROR_INVALID_PARAMETER;
    if (CompartmentId) *CompartmentId = 1;
    if (SiteId) *SiteId = 0;
    if (NetworkName && Length > 0) {
        lstrcpynW(NetworkName, L"Network", (int)Length);
    }
    return NO_ERROR;
}


DWORD WINAPI SetNetworkInformation(
    CONST NET_IF_NETWORK_GUID *NetworkGuid,
    NET_IF_COMPARTMENT_ID CompartmentId,
    CONST WCHAR *NetworkName)
{
    LOG_CALL();
    (void)NetworkGuid; (void)CompartmentId; (void)NetworkName;
    return ERROR_ACCESS_DENIED;
}

/* ============================================================================
 * RESOLVE NEIGHBOR
 * ============================================================================ */


ULONG WINAPI ResolveNeighbor(
    struct sockaddr *NetworkAddress,
    PVOID PhysicalAddress,
    PULONG PhysicalAddressLength)
{
    LOG_CALL();
    if (!NetworkAddress || !PhysicalAddress || !PhysicalAddressLength)
        return ERROR_INVALID_PARAMETER;
    
    if (*PhysicalAddressLength < 6) {
        *PhysicalAddressLength = 6;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    CopyMemory(PhysicalAddress, ADAPTER_MAC, 6);
    *PhysicalAddressLength = 6;
    return NO_ERROR;
}

/* ============================================================================
 * PARSE NETWORK STRING
 * ============================================================================ */


DWORD WINAPI ParseNetworkString(
    CONST WCHAR* NetworkString,
    DWORD Types,
    PVOID AddressInfo,
    PUSHORT PortNumber,
    PBYTE PrefixLength)
{
    LOG_CALL();
    (void)NetworkString; (void)Types; (void)AddressInfo;
    (void)PortNumber; (void)PrefixLength;
    return ERROR_NOT_SUPPORTED;
}

/* ============================================================================
 * PERSISTENT PORT RESERVATION
 * ============================================================================ */


ULONG WINAPI CreatePersistentTcpPortReservation(
    USHORT StartPort, USHORT NumberOfPorts, PULONG64 Token)
{
    LOG_CALL_FMT("StartPort=%u, Count=%u", StartPort, NumberOfPorts);
    if (!Token) return ERROR_INVALID_PARAMETER;
    *Token = 0x1234567890ABCDEFULL;
    return NO_ERROR;
}


ULONG WINAPI CreatePersistentUdpPortReservation(
    USHORT StartPort, USHORT NumberOfPorts, PULONG64 Token)
{
    LOG_CALL_FMT("StartPort=%u, Count=%u", StartPort, NumberOfPorts);
    if (!Token) return ERROR_INVALID_PARAMETER;
    *Token = 0x1234567890ABCDEFULL;
    return NO_ERROR;
}


ULONG WINAPI DeletePersistentTcpPortReservation(
    USHORT StartPort, USHORT NumberOfPorts)
{
    LOG_CALL_FMT("StartPort=%u, Count=%u", StartPort, NumberOfPorts);
    return NO_ERROR;
}


ULONG WINAPI DeletePersistentUdpPortReservation(
    USHORT StartPort, USHORT NumberOfPorts)
{
    LOG_CALL_FMT("StartPort=%u, Count=%u", StartPort, NumberOfPorts);
    return NO_ERROR;
}


ULONG WINAPI LookupPersistentTcpPortReservation(
    USHORT StartPort, USHORT NumberOfPorts, PULONG64 Token)
{
    LOG_CALL();
    if (!Token) return ERROR_INVALID_PARAMETER;
    *Token = 0;
    return ERROR_NOT_FOUND;
}


ULONG WINAPI LookupPersistentUdpPortReservation(
    USHORT StartPort, USHORT NumberOfPorts, PULONG64 Token)
{
    LOG_CALL();
    if (!Token) return ERROR_INVALID_PARAMETER;
    *Token = 0;
    return ERROR_NOT_FOUND;
}

/* ============================================================================
 * PACKET FILTER (PF*) FUNCTIONS - @262-277
 * Based on fltdefs.h
 * ============================================================================ */


DWORD WINAPI PfCreateInterface(
    DWORD dwName,
    PFFORWARD_ACTION inAction,
    PFFORWARD_ACTION outAction,
    BOOL bUseLog,
    BOOL bMustBeUnique,
    INTERFACE_HANDLE *ppInterface)
{
    LOG_CALL_FMT("dwName=%lu, inAction=%d, outAction=%d", dwName, inAction, outAction);
    (void)bUseLog; (void)bMustBeUnique;
    if (ppInterface) *ppInterface = NULL;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfDeleteInterface(INTERFACE_HANDLE pInterface)
{
    LOG_CALL_FMT("pInterface=%p", pInterface);
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfAddFiltersToInterface(
    INTERFACE_HANDLE ih,
    DWORD cInFilters,
    PPF_FILTER_DESCRIPTOR pfiltIn,
    DWORD cOutFilters,
    PPF_FILTER_DESCRIPTOR pfiltOut,
    PFILTER_HANDLE pfHandle)
{
    LOG_CALL_FMT("ih=%p, cInFilters=%lu, cOutFilters=%lu", ih, cInFilters, cOutFilters);
    (void)pfiltIn; (void)pfiltOut;
    if (pfHandle) *pfHandle = NULL;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfRemoveFiltersFromInterface(
    INTERFACE_HANDLE ih,
    DWORD cInFilters,
    PPF_FILTER_DESCRIPTOR pfiltIn,
    DWORD cOutFilters,
    PPF_FILTER_DESCRIPTOR pfiltOut)
{
    LOG_CALL_FMT("ih=%p, cInFilters=%lu, cOutFilters=%lu", ih, cInFilters, cOutFilters);
    (void)pfiltIn; (void)pfiltOut;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfRemoveFilterHandles(
    INTERFACE_HANDLE pInterface,
    DWORD cFilters,
    PFILTER_HANDLE pvHandles)
{
    LOG_CALL_FMT("pInterface=%p, cFilters=%lu", pInterface, cFilters);
    (void)pvHandles;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfUnBindInterface(INTERFACE_HANDLE pInterface)
{
    LOG_CALL_FMT("pInterface=%p", pInterface);
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfBindInterfaceToIndex(
    INTERFACE_HANDLE pInterface,
    DWORD dwIndex,
    PFADDRESSTYPE pfatLinkType,
    PBYTE LinkIPAddress)
{
    LOG_CALL_FMT("pInterface=%p, dwIndex=%lu, pfatLinkType=%d", pInterface, dwIndex, pfatLinkType);
    (void)LinkIPAddress;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfBindInterfaceToIPAddress(
    INTERFACE_HANDLE pInterface,
    PFADDRESSTYPE pfatType,
    PBYTE IPAddress)
{
    LOG_CALL_FMT("pInterface=%p, pfatType=%d", pInterface, pfatType);
    (void)IPAddress;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfRebindFilters(
    INTERFACE_HANDLE pInterface,
    PPF_LATEBIND_INFO pLateBindInfo)
{
    LOG_CALL_FMT("pInterface=%p", pInterface);
    (void)pLateBindInfo;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfAddGlobalFilterToInterface(
    INTERFACE_HANDLE pInterface,
    GLOBAL_FILTER gfFilter)
{
    LOG_CALL_FMT("pInterface=%p, gfFilter=%d", pInterface, gfFilter);
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfRemoveGlobalFilterFromInterface(
    INTERFACE_HANDLE pInterface,
    GLOBAL_FILTER gfFilter)
{
    LOG_CALL_FMT("pInterface=%p, gfFilter=%d", pInterface, gfFilter);
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfMakeLog(HANDLE hEvent)
{
    LOG_CALL_FMT("hEvent=%p", hEvent);
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfSetLogBuffer(
    PBYTE pbBuffer,
    DWORD dwSize,
    DWORD dwThreshold,
    DWORD dwEntries,
    PDWORD pdwLoggedEntries,
    PDWORD pdwLostEntries,
    PDWORD pdwSizeUsed)
{
    LOG_CALL_FMT("pbBuffer=%p, dwSize=%lu, dwThreshold=%lu, dwEntries=%lu", 
                 pbBuffer, dwSize, dwThreshold, dwEntries);
    if (pdwLoggedEntries) *pdwLoggedEntries = 0;
    if (pdwLostEntries) *pdwLostEntries = 0;
    if (pdwSizeUsed) *pdwSizeUsed = 0;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfDeleteLog(VOID)
{
    LOG_CALL();
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfGetInterfaceStatistics(
    INTERFACE_HANDLE pInterface,
    PPF_INTERFACE_STATS ppfStats,
    PDWORD pdwBufferSize,
    BOOL fResetCounters)
{
    LOG_CALL_FMT("pInterface=%p, fResetCounters=%d", pInterface, fResetCounters);
    (void)ppfStats;
    if (pdwBufferSize) *pdwBufferSize = 0;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


DWORD WINAPI PfTestPacket(
    INTERFACE_HANDLE pInInterface,
    INTERFACE_HANDLE pOutInterface,
    DWORD cBytes,
    PBYTE pbPacket,
    PPFFORWARD_ACTION ppAction)
{
    LOG_CALL_FMT("pInInterface=%p, pOutInterface=%p, cBytes=%lu", 
                 pInInterface, pOutInterface, cBytes);
    (void)pbPacket;
    if (ppAction) *ppAction = PF_ACTION_FORWARD;
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/* ============================================================================
 * ВИПРАВЛЕНІ ФУНКЦІЇ НА ОСНОВІ netioapi.h
 * ============================================================================ */

/* @92 */

DWORD WINAPI GetIfStackTable(PMIB_IFSTACK_TABLE *Table)
{
    LOG_CALL();
    if (!Table) return ERROR_INVALID_PARAMETER;
    
    SIZE_T size = sizeof(MIB_IFSTACK_TABLE);
    PMIB_IFSTACK_TABLE table = (PMIB_IFSTACK_TABLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!table) return ERROR_NOT_ENOUGH_MEMORY;
    
    table->NumEntries = 0;
    *Table = table;
    return NO_ERROR;
}

/* @103 */

DWORD WINAPI GetInvertedIfStackTable(PMIB_INVERTEDIFSTACK_TABLE *Table)
{
    LOG_CALL();
    if (!Table) return ERROR_INVALID_PARAMETER;
    
    SIZE_T size = sizeof(MIB_INVERTEDIFSTACK_TABLE);
    PMIB_INVERTEDIFSTACK_TABLE table = (PMIB_INVERTEDIFSTACK_TABLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!table) return ERROR_NOT_ENOUGH_MEMORY;
    
    table->NumEntries = 0;
    *Table = table;
    return NO_ERROR;
}

/* @72 */

DWORD WINAPI GetAnycastIpAddressEntry(PMIB_ANYCASTIPADDRESS_ROW Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_NOT_FOUND;
}

/* @73 */

DWORD WINAPI GetAnycastIpAddressTable(ADDRESS_FAMILY Family, PMIB_ANYCASTIPADDRESS_TABLE *Table)
{
    LOG_CALL_FMT("Family=%d", Family);
    if (!Table) return ERROR_INVALID_PARAMETER;
    
    SIZE_T size = sizeof(MIB_ANYCASTIPADDRESS_TABLE);
    PMIB_ANYCASTIPADDRESS_TABLE table = (PMIB_ANYCASTIPADDRESS_TABLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!table) return ERROR_NOT_ENOUGH_MEMORY;
    
    table->NumEntries = 0;
    *Table = table;
    return NO_ERROR;
}

/* @36 */

DWORD WINAPI CreateAnycastIpAddressEntry(CONST MIB_ANYCASTIPADDRESS_ROW *Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_ACCESS_DENIED;
}

/* @48 */

DWORD WINAPI DeleteAnycastIpAddressEntry(CONST MIB_ANYCASTIPADDRESS_ROW *Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_ACCESS_DENIED;
}

/* @120 */

DWORD WINAPI GetMulticastIpAddressEntry(PMIB_MULTICASTIPADDRESS_ROW Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_NOT_FOUND;
}

/* @121 */

DWORD WINAPI GetMulticastIpAddressTable(ADDRESS_FAMILY Family, PMIB_MULTICASTIPADDRESS_TABLE *Table)
{
    LOG_CALL_FMT("Family=%d", Family);
    if (!Table) return ERROR_INVALID_PARAMETER;
    
    SIZE_T size = sizeof(MIB_MULTICASTIPADDRESS_TABLE);
    PMIB_MULTICASTIPADDRESS_TABLE table = (PMIB_MULTICASTIPADDRESS_TABLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!table) return ERROR_NOT_ENOUGH_MEMORY;
    
    table->NumEntries = 0;
    *Table = table;
    return NO_ERROR;
}

/* @153 */

DWORD WINAPI GetUnicastIpAddressEntry(PMIB_UNICASTIPADDRESS_ROW Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_NOT_FOUND;
}

/* @47 */

DWORD WINAPI CreateUnicastIpAddressEntry(CONST MIB_UNICASTIPADDRESS_ROW *Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_ACCESS_DENIED;
}

/* @59 */

DWORD WINAPI DeleteUnicastIpAddressEntry(CONST MIB_UNICASTIPADDRESS_ROW *Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_ACCESS_DENIED;
}

/* @306 */

DWORD WINAPI SetUnicastIpAddressEntry(CONST MIB_UNICASTIPADDRESS_ROW *Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_ACCESS_DENIED;
}

/* @169 */

VOID WINAPI InitializeUnicastIpAddressEntry(PMIB_UNICASTIPADDRESS_ROW Row)
{
    LOG_CALL();
    if (Row) ZeroMemory(Row, sizeof(MIB_UNICASTIPADDRESS_ROW));
}

/* @109 */

DWORD WINAPI GetIpInterfaceEntry(PMIB_IPINTERFACE_ROW Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    
    if (Row->InterfaceLuid.Value == 0 && Row->InterfaceIndex == 0) 
        return ERROR_INVALID_PARAMETER;
    
    if (Row->InterfaceIndex != ADAPTER_IF_INDEX && 
        Row->InterfaceLuid.Value != ADAPTER_LUID.Value)
        return ERROR_NOT_FOUND;
    
    Row->InterfaceLuid = ADAPTER_LUID;
    Row->InterfaceIndex = ADAPTER_IF_INDEX;
    Row->NlMtu = ADAPTER_MTU;
    Row->Metric = 25;
    Row->Connected = TRUE;
    Row->SupportsWakeUpPatterns = FALSE;
    Row->SupportsNeighborDiscovery = TRUE;
    Row->SupportsRouterDiscovery = TRUE;
    
    return NO_ERROR;
}

/* @292 */

DWORD WINAPI SetIpInterfaceEntry(PMIB_IPINTERFACE_ROW Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_ACCESS_DENIED;
}

/* @168 */

VOID WINAPI InitializeIpInterfaceEntry(PMIB_IPINTERFACE_ROW Row)
{
    LOG_CALL();
    if (Row) ZeroMemory(Row, sizeof(MIB_IPINTERFACE_ROW));
}

/* @106 */

DWORD WINAPI GetIpForwardEntry2(PMIB_IPFORWARD_ROW2 Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_NOT_FOUND;
}

/* @108 */

DWORD WINAPI GetIpForwardTable2(ADDRESS_FAMILY Family, PMIB_IPFORWARD_TABLE2 *Table)
{
    LOG_CALL_FMT("Family=%d", Family);
    if (!Table) return ERROR_INVALID_PARAMETER;
    
    SIZE_T size = sizeof(MIB_IPFORWARD_TABLE2);
    PMIB_IPFORWARD_TABLE2 table = (PMIB_IPFORWARD_TABLE2)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!table) return ERROR_NOT_ENOUGH_MEMORY;
    
    table->NumEntries = 0;
    *Table = table;
    return NO_ERROR;
}

/* @40 */

DWORD WINAPI CreateIpForwardEntry2(CONST MIB_IPFORWARD_ROW2 *Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_ACCESS_DENIED;
}

/* @53 */

DWORD WINAPI DeleteIpForwardEntry2(CONST MIB_IPFORWARD_ROW2 *Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_ACCESS_DENIED;
}

/* @291 */

DWORD WINAPI SetIpForwardEntry2(CONST MIB_IPFORWARD_ROW2 *Route)
{
    LOG_CALL();
    if (!Route) return ERROR_INVALID_PARAMETER;
    return ERROR_ACCESS_DENIED;
}

/* @167 */

VOID WINAPI InitializeIpForwardEntry(PMIB_IPFORWARD_ROW2 Row)
{
    LOG_CALL();
    if (Row) ZeroMemory(Row, sizeof(MIB_IPFORWARD_ROW2));
}

/* @111 */

DWORD WINAPI GetIpNetEntry2(PMIB_IPNET_ROW2 Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_NOT_FOUND;
}

/* @113 */

DWORD WINAPI GetIpNetTable2(ADDRESS_FAMILY Family, PMIB_IPNET_TABLE2 *Table)
{
    LOG_CALL_FMT("Family=%d", Family);
    if (!Table) return ERROR_INVALID_PARAMETER;
    
    SIZE_T size = sizeof(MIB_IPNET_TABLE2);
    PMIB_IPNET_TABLE2 table = (PMIB_IPNET_TABLE2)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!table) return ERROR_NOT_ENOUGH_MEMORY;
    
    table->NumEntries = 0;
    *Table = table;
    return NO_ERROR;
}

/* @42 */

DWORD WINAPI CreateIpNetEntry2(CONST MIB_IPNET_ROW2 *Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_ACCESS_DENIED;
}

/* @55 */

DWORD WINAPI DeleteIpNetEntry2(CONST MIB_IPNET_ROW2 *Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_ACCESS_DENIED;
}

/* @294 */

DWORD WINAPI SetIpNetEntry2(PMIB_IPNET_ROW2 Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_ACCESS_DENIED;
}

/* @63 */

DWORD WINAPI FlushIpNetTable2(ADDRESS_FAMILY Family, NET_IFINDEX InterfaceIndex)
{
    LOG_CALL_FMT("Family=%d, Index=%lu", Family, InterfaceIndex);
    return ERROR_ACCESS_DENIED;
}

/* @279 */

DWORD WINAPI ResolveIpNetEntry2(PMIB_IPNET_ROW2 Row, CONST SOCKADDR_INET *SourceAddress)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    (void)SourceAddress;
    return ERROR_NOT_FOUND;
}

/* @115 */

DWORD WINAPI GetIpPathEntry(PMIB_IPPATH_ROW Row)
{
    LOG_CALL();
    if (!Row) return ERROR_INVALID_PARAMETER;
    return ERROR_NOT_FOUND;
}

/* @116 */

DWORD WINAPI GetIpPathTable(ADDRESS_FAMILY Family, PMIB_IPPATH_TABLE *Table)
{
    LOG_CALL_FMT("Family=%d", Family);
    if (!Table) return ERROR_INVALID_PARAMETER;
    
    SIZE_T size = sizeof(MIB_IPPATH_TABLE);
    PMIB_IPPATH_TABLE table = (PMIB_IPPATH_TABLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!table) return ERROR_NOT_ENOUGH_MEMORY;
    
    table->NumEntries = 0;
    *Table = table;
    return NO_ERROR;
}

/* @64 */

DWORD WINAPI FlushIpPathTable(ADDRESS_FAMILY Family)
{
    LOG_CALL_FMT("Family=%d", Family);
    return ERROR_ACCESS_DENIED;
}

/* @114 */

DWORD WINAPI GetIpNetworkConnectionBandwidthEstimates(
    NET_IFINDEX InterfaceIndex,
    ADDRESS_FAMILY AddressFamily,
    PMIB_IP_NETWORK_CONNECTION_BANDWIDTH_ESTIMATES BandwidthEstimates)
{
    LOG_CALL_FMT("Index=%lu, Family=%d", InterfaceIndex, AddressFamily);
    if (!BandwidthEstimates) return ERROR_INVALID_PARAMETER;
    ZeroMemory(BandwidthEstimates, sizeof(MIB_IP_NETWORK_CONNECTION_BANDWIDTH_ESTIMATES));
    return NO_ERROR;
}

/* @46 */

NETIO_STATUS WINAPI CreateSortedAddressPairs(
    const PSOCKADDR_IN6 SourceAddressList,
    ULONG SourceAddressCount,
    const PSOCKADDR_IN6 DestinationAddressList,
    ULONG DestinationAddressCount,
    ULONG AddressSortOptions,
    PSOCKADDR_IN6_PAIR *SortedAddressPairList,
    ULONG *SortedAddressPairCount)
{
    LOG_CALL_FMT("SrcCount=%lu, DstCount=%lu", SourceAddressCount, DestinationAddressCount);
    (void)SourceAddressList; (void)DestinationAddressList; (void)AddressSortOptions;
    
    if (SortedAddressPairList) *SortedAddressPairList = NULL;
    if (SortedAddressPairCount) *SortedAddressPairCount = 0;
    return ERROR_NOT_SUPPORTED;
}

/* @253 */

DWORD WINAPI NotifyIpInterfaceChange(
    ADDRESS_FAMILY Family,
    PIPINTERFACE_CHANGE_CALLBACK Callback,
    PVOID CallerContext,
    BOOLEAN InitialNotification,
    HANDLE *NotificationHandle)
{
    LOG_CALL_FMT("Family=%d", Family);
    (void)Callback; (void)CallerContext; (void)InitialNotification;
    
    if (NotificationHandle) *NotificationHandle = (HANDLE)(ULONG_PTR)0x11111111;
    return NO_ERROR;
}

/* @259 */

DWORD WINAPI NotifyUnicastIpAddressChange(
    ADDRESS_FAMILY Family,
    PUNICAST_IPADDRESS_CHANGE_CALLBACK Callback,
    PVOID CallerContext,
    BOOLEAN InitialNotification,
    HANDLE *NotificationHandle)
{
    LOG_CALL_FMT("Family=%d", Family);
    (void)Callback; (void)CallerContext; (void)InitialNotification;
    
    if (NotificationHandle) *NotificationHandle = (HANDLE)(ULONG_PTR)0x22222222;
    return NO_ERROR;
}

/* @257 */

DWORD WINAPI NotifyStableUnicastIpAddressTable(
    ADDRESS_FAMILY Family,
    PMIB_UNICASTIPADDRESS_TABLE *Table,
    PSTABLE_UNICAST_IPADDRESS_TABLE_CALLBACK CallerCallback,
    PVOID CallerContext,
    HANDLE *NotificationHandle)
{
    LOG_CALL_FMT("Family=%d", Family);
    (void)CallerCallback; (void)CallerContext;
    
    if (Table) *Table = NULL;
    if (NotificationHandle) *NotificationHandle = (HANDLE)(ULONG_PTR)0x33333333;
    return ERROR_IO_PENDING;
}

/* @256 */

DWORD WINAPI NotifyRouteChange2(
    ADDRESS_FAMILY AddressFamily,
    PIPFORWARD_CHANGE_CALLBACK Callback,
    PVOID CallerContext,
    BOOLEAN InitialNotification,
    HANDLE *NotificationHandle)
{
    LOG_CALL_FMT("Family=%d", AddressFamily);
    (void)Callback; (void)CallerContext; (void)InitialNotification;
    
    if (NotificationHandle) *NotificationHandle = (HANDLE)(ULONG_PTR)0x44444444;
    return NO_ERROR;
}

/* @258 */

DWORD WINAPI NotifyTeredoPortChange(
    PTEREDO_PORT_CHANGE_CALLBACK Callback,
    PVOID CallerContext,
    BOOLEAN InitialNotification,
    HANDLE *NotificationHandle)
{
    LOG_CALL();
    (void)Callback; (void)CallerContext; (void)InitialNotification;
    
    if (NotificationHandle) *NotificationHandle = (HANDLE)(ULONG_PTR)0x55555555;
    return NO_ERROR;
}

/* ============================================================================
 * STUB FOR do_echo_req, do_echo_rep, register_icmp
 * ============================================================================ */


DWORD WINAPI do_echo_req(PVOID p1, PVOID p2, PVOID p3, PVOID p4)
{
    LOG_CALL();
    (void)p1; (void)p2; (void)p3; (void)p4;
    return ERROR_NOT_SUPPORTED;
}


DWORD WINAPI do_echo_rep(PVOID p1, PVOID p2, PVOID p3, PVOID p4)
{
    LOG_CALL();
    (void)p1; (void)p2; (void)p3; (void)p4;
    return ERROR_NOT_SUPPORTED;
}


DWORD WINAPI register_icmp(VOID)
{
    LOG_CALL();
    return ERROR_NOT_SUPPORTED;
}

#ifdef __cplusplus
}
#endif