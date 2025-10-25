#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "exws2.lib")

// Виправлені визначення для сумісності
#ifndef _NETIOAPI_H_
typedef enum _MIB_IF_TABLE_LEVEL {
    MibIfTableNormal,
    MibIfTableRaw
} MIB_IF_TABLE_LEVEL, *PMIB_IF_TABLE_LEVEL;
#endif

// "Пустишки" для типів даних з нових SDK
typedef PVOID PINTERFACE_HARDWARE_CROSSTIMESTAMP;
typedef PVOID PDNS_SETTINGS;
typedef PVOID PDNS_INTERFACE_SETTINGS;
typedef PVOID PMIB_FL_VIRTUAL_INTERFACE;
typedef PVOID PMIB_FL_VIRTUAL_INTERFACE_TABLE;
typedef PVOID PINTERFACE_TIMESTAMP_CAPABILITIES;
typedef PVOID PNET_IF_CONNECTION_BANDWIDTH_ESTIMATES;
typedef PVOID PNL_NETWORK_CONNECTIVITY_HINT;
typedef PVOID PINTERFACE_TIMESTAMP_CONFIG_CHANGE_CALLBACK;
typedef PVOID PNL_NETWORK_CONNECTIVITY_HINT_CHANGE_CALLBACK;
typedef PVOID PFILTER_DESCRIPTOR;
typedef PVOID PFHANDLE;
typedef PVOID GLOBAL_FILTER;
typedef PVOID PFFORWARD_ACTION;
typedef PVOID PFP_INTERFACE_STATS;
typedef PVOID PNET_ADDRESS_INFO;
typedef PVOID PRTC_SLOT_INFORMATION_TABLE;
typedef PVOID PMIB_TUNNEL_PHYSICAL_ADAPTER;
typedef PVOID PMIB_IP_PHYSICAL_INTERFACE_ROW;
typedef PVOID PMIB_TCPSTATS2;
typedef PVOID PMIB_UDPSTATS2;

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// === НАЛАГОДЖУВАЛЬНІ КОНСТАНТИ ===
// ============================================================================
#define ENABLE_DEBUG_CONSOLE    0
#define ENABLE_FILE_LOGGING     0
#define ENABLE_MEMORY_TRACKING  0

// ============================================================================
// === СТРУКТУРИ ТА КОНСТАНТИ ДЛЯ ВІДСТЕЖЕННЯ ===
// ============================================================================
#define MAX_ADAPTERS 8
#define MAX_IPS_PER_ADAPTER 4
#define MAX_DNS_PER_ADAPTER 4
#define MAX_ARP_ENTRIES 16

typedef enum { LOG_LEVEL_ERROR = 0, LOG_LEVEL_WARNING, LOG_LEVEL_INFO, LOG_LEVEL_DEBUG } LogLevel;
#if ENABLE_MEMORY_TRACKING
typedef struct _MEMORY_BLOCK { void* ptr; size_t size; char function[64]; DWORD thread_id; struct _MEMORY_BLOCK* next; } MEMORY_BLOCK;
#endif

typedef struct { char ipAddress[40]; char ipMask[40]; DWORD dwAddr; DWORD dwMask; ULONG NTEContext; int family; } FakeIpAddress;

typedef struct {
    char name[16];
    char name_num;
    char name_flags;
    BYTE mac_address[6];
} NetBIOSName;

typedef struct {
    // Старі поля
    char name[MAX_ADAPTER_NAME_LENGTH + 4];
    char description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
    char dnsSuffix[128];
    DWORD type;
    DWORD index;
    DWORD dwAdminStatus;
    IF_OPER_STATUS operStatus;
    BYTE macAddress[MAX_ADAPTER_ADDRESS_LENGTH];
    int ipCount;
    FakeIpAddress ipAddresses[MAX_IPS_PER_ADAPTER];
    char gateway[40];
    int dnsCount;
    char dnsAddresses[MAX_DNS_PER_ADAPTER][40];
    
    // ← НОВІ ПОЛЯ ДЛЯ NETBIOS
    BOOL netbiosEnabled;                    // Чи включено NetBIOS
    char computerName[16];                  // NetBIOS ім'я комп'ютера
    char workgroupName[16];                 // NetBIOS імя робочої групи
    int netbiosNameCount;                   // Кількість NetBIOS імен
    NetBIOSName netbiosNames[8];            // Список NetBIOS імен
} FakeAdapter;

typedef struct { DWORD dwAddr; BYTE macAddress[6]; } FakeArpEntry;
typedef struct { int adapterCount; FakeAdapter adapters[MAX_ADAPTERS]; int arpCacheCount; FakeArpEntry arpCache[MAX_ARP_ENTRIES]; ULONG nextNTEContext; } NetworkState;

// ============================================================================
// === ГЛОБАЛЬНІ ЗМІННІ ===
// ============================================================================
#if ENABLE_DEBUG_CONSOLE
static HANDLE g_hConsole = NULL;
#elif ENABLE_FILE_LOGGING
static FILE* g_log_file = NULL; static CRITICAL_SECTION g_log_lock;
#endif
#if ENABLE_MEMORY_TRACKING
static MEMORY_BLOCK* g_memory_list = NULL; static CRITICAL_SECTION g_memory_lock; static size_t g_total_allocated = 0; static size_t g_total_freed = 0; static size_t g_allocation_count = 0;
#endif
static BOOL g_locks_initialized = FALSE; static LogLevel g_current_log_level = LOG_LEVEL_DEBUG;
static NetworkState g_NetworkState = {0};

// ============================================================================
// === ФУНКЦІЇ ЛОГУВАННЯ ТА УПРАВЛІННЯ ПАМ'ЯТТЮ ===
// ============================================================================
void GetTimestamp(char* buffer, size_t bufferSize) { if (!buffer || bufferSize < 20) return; SYSTEMTIME st; GetLocalTime(&st); snprintf(buffer, bufferSize, "[%02d:%02d:%02d.%03d]", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds); }
const char* GetLogLevelString(LogLevel level) { switch (level) { case LOG_LEVEL_ERROR: return "ERROR"; case LOG_LEVEL_WARNING: return "WARN "; case LOG_LEVEL_INFO: return "INFO "; case LOG_LEVEL_DEBUG: return "DEBUG"; default: return "?????"; } }
void LogMessageEx(LogLevel level, const char* function, const char* format, ...) {
    if (level > g_current_log_level) return;
    char timestamp[20] = { 0 }; GetTimestamp(timestamp, sizeof(timestamp)); va_list args; va_start(args, format);
    char user_buffer[1024]; vsnprintf(user_buffer, sizeof(user_buffer), format, args);
    char final_buffer[2048]; snprintf(final_buffer, sizeof(final_buffer), "[IPHLPAPI] %s [%s] [%s] %s\n", timestamp, GetLogLevelString(level), function, user_buffer);
#if ENABLE_FILE_LOGGING
    if (g_log_file && g_locks_initialized) { EnterCriticalSection(&g_log_lock); fputs(final_buffer, g_log_file); fflush(g_log_file); LeaveCriticalSection(&g_log_lock); }
#elif ENABLE_DEBUG_CONSOLE
    if(g_hConsole) { DWORD written; WriteConsoleA(g_hConsole, final_buffer, (DWORD)strlen(final_buffer), &written, NULL); }
#endif
    va_end(args); }
#define LogError(fmt, ...)   LogMessageEx(LOG_LEVEL_ERROR, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogWarning(fmt, ...) LogMessageEx(LOG_LEVEL_WARNING, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogInfo(fmt, ...)    LogMessageEx(LOG_LEVEL_INFO, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogDebug(fmt, ...)   LogMessageEx(LOG_LEVEL_DEBUG, __FUNCTION__, fmt, ##__VA_ARGS__)
#if ENABLE_MEMORY_TRACKING
void* TrackedAlloc(size_t size, const char* function) { if (size == 0) { return NULL; } void* ptr = malloc(size); if (!ptr) { LogError("Failed to allocate %zu bytes", size); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; } memset(ptr, 0, size); if (g_locks_initialized) { EnterCriticalSection(&g_memory_lock); MEMORY_BLOCK* block = (MEMORY_BLOCK*)malloc(sizeof(MEMORY_BLOCK)); if (block) { block->ptr = ptr; block->size = size; strncpy_s(block->function, sizeof(block->function), function, _TRUNCATE); block->thread_id = GetCurrentThreadId(); block->next = g_memory_list; g_memory_list = block; g_total_allocated += size; g_allocation_count++; } LeaveCriticalSection(&g_memory_lock); } LogDebug("Allocated %zu bytes at %p", size, ptr); return ptr; }
BOOL TrackedFree(void* ptr, const char* function) { if (!ptr) return TRUE; BOOL found = FALSE; if (g_locks_initialized) { EnterCriticalSection(&g_memory_lock); MEMORY_BLOCK** current = &g_memory_list; while (*current) { if ((*current)->ptr == ptr) { MEMORY_BLOCK* block = *current; *current = block->next; g_total_freed += block->size; g_allocation_count--; LogDebug("Freed %zu bytes from %p (allocated in %s)", block->size, ptr, block->function); free(block->ptr); free(block); found = TRUE; break; } current = &(*current)->next; } LeaveCriticalSection(&g_memory_lock); } if (!found) { LogWarning("Attempt to free untracked/already freed memory: %p from func %s", ptr, function); free(ptr); } return found; }
void ReportMemoryLeaks() { if (!g_locks_initialized) return; EnterCriticalSection(&g_memory_lock); if (g_memory_list) { LogError("=== MEMORY LEAKS DETECTED ==="); LogError("Total leaked: %zu bytes in %zu allocations", g_total_allocated - g_total_freed, g_allocation_count); MEMORY_BLOCK* current = g_memory_list; while (current) { LogError("  Leak: %zu bytes from %s (thread %lu): %p", current->size, current->function, current->ptr); current = current->next; } } else { LogInfo("No memory leaks detected."); } LeaveCriticalSection(&g_memory_lock); }
#define SAFE_ALLOC(size) TrackedAlloc(size, __FUNCTION__)
#define SAFE_FREE(ptr) TrackedFree(ptr, __FUNCTION__)
#else
#define SAFE_ALLOC(size) calloc(1, size)
#define SAFE_FREE(ptr) free(ptr)
#define ReportMemoryLeaks()
#endif
#undef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)

// --- Допоміжні функції для емуляції ---
void ParseMacAddress(const char* macStr, BYTE* target) { sscanf_s(macStr, "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx", &target[0], &target[1], &target[2], &target[3], &target[4], &target[5]); }
FakeAdapter* FindAdapterByIndex(DWORD index) { for (int i = 0; i < g_NetworkState.adapterCount; ++i) { if (g_NetworkState.adapters[i].index == index) return &g_NetworkState.adapters[i]; } return NULL; }

void InitializeHardcodedConfig() {
    LogInfo("Initializing hardcoded network configuration with NetBIOS...");
    memset(&g_NetworkState, 0, sizeof(g_NetworkState));
    g_NetworkState.nextNTEContext = 1000;

    // --- Адаптер 1: Realtek Gaming GbE (Увімкнено) ---
    FakeAdapter* adapter1 = &g_NetworkState.adapters[g_NetworkState.adapterCount++];
    strcpy_s(adapter1->name, sizeof(adapter1->name), "{A1B2C3D4-E5F6-1234-5678-ABCDEF123456}");
    strcpy_s(adapter1->description, sizeof(adapter1->description), "Realtek Gaming GbE Family Controller");
    adapter1->type = IF_TYPE_ETHERNET_CSMACD;
    adapter1->index = 1;
    adapter1->dwAdminStatus = MIB_IF_ADMIN_STATUS_UP;
    adapter1->operStatus = IfOperStatusUp;
    ParseMacAddress("00-1A-2B-3C-4D-5E", adapter1->macAddress);
    strcpy_s(adapter1->dnsSuffix, sizeof(adapter1->dnsSuffix), "WORKGROUP");

    // ← NETBIOS КОНФІГУРАЦІЯ
    adapter1->netbiosEnabled = FALSE;                   // ← NetBIOS ВИМКНЕНО (для офлайну)
    strcpy_s(adapter1->computerName, sizeof(adapter1->computerName), "COMPUTER");
    strcpy_s(adapter1->workgroupName, sizeof(adapter1->workgroupName), "WORKGROUP");
    adapter1->netbiosNameCount = 0;                     // ← Нема зареєстрованих імен

    // IPv4 адреса
    FakeIpAddress* ip1 = &adapter1->ipAddresses[adapter1->ipCount++];
    strcpy_s(ip1->ipAddress, sizeof(ip1->ipAddress), "192.168.1.100");
    strcpy_s(ip1->ipMask, sizeof(ip1->ipMask), "255.255.255.0");
    ip1->dwAddr = inet_addr(ip1->ipAddress);
    ip1->dwMask = inet_addr(ip1->ipMask);
    ip1->family = AF_INET;
    ip1->NTEContext = g_NetworkState.nextNTEContext++;

    // Gateway та DNS
    strcpy_s(adapter1->gateway, sizeof(adapter1->gateway), "192.168.1.1");
    strcpy_s(adapter1->dnsAddresses[adapter1->dnsCount++], sizeof(adapter1->dnsAddresses[0]), "192.168.1.1");
    strcpy_s(adapter1->dnsAddresses[adapter1->dnsCount++], sizeof(adapter1->dnsAddresses[0]), "8.8.8.8");

    // --- Адаптер 2: Емуляція Wi-Fi (Вимкнено) ---
    FakeAdapter* adapter2 = &g_NetworkState.adapters[g_NetworkState.adapterCount++];
    strcpy_s(adapter2->name, sizeof(adapter2->name), "{B2C3D4E5-F6A7-4321-8765-FEDCBA654321}");
    strcpy_s(adapter2->description, sizeof(adapter2->description), "Intel(R) Wi-Fi 6 AX200 160MHz");
    adapter2->type = IF_TYPE_IEEE80211;
    adapter2->index = 2;
    adapter2->dwAdminStatus = MIB_IF_ADMIN_STATUS_DOWN;
    adapter2->operStatus = IfOperStatusDown;
    ParseMacAddress("F0-E1-D2-C3-B4-A5", adapter2->macAddress);
    adapter2->ipCount = 0;
    adapter2->dnsCount = 0;
    
    // ← NetBIOS вимкнено для Wi-Fi
    adapter2->netbiosEnabled = FALSE;
    adapter2->netbiosNameCount = 0;

    // --- ARP Таблиця ---
    FakeArpEntry* arp1 = &g_NetworkState.arpCache[g_NetworkState.arpCacheCount++];
    arp1->dwAddr = inet_addr("192.168.1.1");
    ParseMacAddress("A0-B1-C2-D3-E4-F5", arp1->macAddress);

    FakeArpEntry* arp2 = &g_NetworkState.arpCache[g_NetworkState.arpCacheCount++];
    arp2->dwAddr = inet_addr("192.168.1.254");
    ParseMacAddress("01-02-03-04-05-06", arp2->macAddress);

    LogInfo("Hardcoded config initialized (NetBIOS disabled for offline mode):");
    LogInfo("  Adapter 1: Realtek Gaming GbE (192.168.1.100)");
    LogInfo("    NetBIOS: DISABLED (offline mode)");
    LogInfo("    Computer Name: COMPUTER");
    LogInfo("    Workgroup: WORKGROUP");
    LogInfo("  Adapter 2: Intel Wi-Fi 6 AX200 - DOWN");
    LogInfo("    NetBIOS: DISABLED");
    LogInfo("  ARP entries: %d", g_NetworkState.arpCacheCount);
}

#define STUB_LOG LogDebug("STUB: %s called", __FUNCTION__)
#define STUB_SUCCESS_DWORD(val) do { STUB_LOG; SetLastError(NO_ERROR); return (val); } while (0)
#define STUB_FAIL_DWORD(val, err) do { STUB_LOG; SetLastError(err); return (val); } while (0)
#define STUB_FAIL_BOOL(err) do { STUB_LOG; SetLastError(err); return FALSE; } while(0)

// --- Універсальні заглушки для .def файлу ---
DWORD WINAPI ex_StubNotSupported() { STUB_FAIL_DWORD(ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_StubNoData() { STUB_FAIL_DWORD(ERROR_NO_DATA, ERROR_NO_DATA); }
DWORD WINAPI ex_StubSuccess() { STUB_SUCCESS_DWORD(NO_ERROR); }

// --- "Розумні" реалізації ---
DWORD WINAPI ex_SetIfEntry(PMIB_IFROW pIfRow) { LogInfo("SetIfEntry(IfIndex: %lu, AdminStatus: %lu)", pIfRow->dwIndex, pIfRow->dwAdminStatus); FakeAdapter* adapter = FindAdapterByIndex(pIfRow->dwIndex); if (!adapter) { LogWarning(" -> Adapter with index %lu not found.", pIfRow->dwIndex); return ERROR_NOT_FOUND; } adapter->dwAdminStatus = pIfRow->dwAdminStatus; LogInfo(" -> Success. Adapter %lu AdminStatus set to %lu.", pIfRow->dwIndex, pIfRow->dwAdminStatus); return NO_ERROR; }
DWORD WINAPI ex_DeleteIPAddress(ULONG NTEContext) { LogInfo("DeleteIPAddress(NTEContext: %lu)", NTEContext); for (int i = 0; i < g_NetworkState.adapterCount; ++i) { FakeAdapter* adapter = &g_NetworkState.adapters[i]; for (int j = 0; j < adapter->ipCount; ++j) { if (adapter->ipAddresses[j].NTEContext == NTEContext) { for (int k = j; k < adapter->ipCount - 1; ++k) adapter->ipAddresses[k] = adapter->ipAddresses[k + 1]; adapter->ipCount--; LogInfo(" -> Success. IP Address with NTEContext %lu deleted.", NTEContext); return NO_ERROR; } } } LogWarning(" -> IP Address with NTEContext %lu not found.", NTEContext); return ERROR_NOT_FOUND; }
DWORD WINAPI ex_SendARP(IPAddr DestIP, IPAddr SrcIP, PVOID pMacAddr, PULONG PhyAddrLen) { UNREFERENCED_PARAMETER(SrcIP); IN_ADDR dest_addr = { .S_un.S_addr = DestIP }; LogInfo("SendARP(DestIP: %s)", inet_ntoa(dest_addr)); if (!pMacAddr || !PhyAddrLen || *PhyAddrLen < 6) return ERROR_BAD_ARGUMENTS; for (int i = 0; i < g_NetworkState.arpCacheCount; ++i) { if (g_NetworkState.arpCache[i].dwAddr == DestIP) { memcpy(pMacAddr, g_NetworkState.arpCache[i].macAddress, 6); *PhyAddrLen = 6; LogInfo(" -> Found in static ARP cache."); return NO_ERROR; } } for (int i = 0; i < g_NetworkState.adapterCount; ++i) { FakeAdapter* adapter = &g_NetworkState.adapters[i]; if (adapter->dwAdminStatus != MIB_IF_ADMIN_STATUS_UP || adapter->ipCount == 0) continue; for (int j = 0; j < adapter->ipCount; ++j) { FakeIpAddress* ip = &adapter->ipAddresses[j]; if ((ip->dwAddr & ip->dwMask) == (DestIP & ip->dwMask)) { BYTE simulatedMac[6] = {0x0A, 0x51, 0xDE, 0xAD, 0xBE, 0xEF}; simulatedMac[4] = (BYTE)((DestIP >> 16) & 0xFF); simulatedMac[5] = (BYTE)(DestIP >> 24); memcpy(pMacAddr, simulatedMac, 6); *PhyAddrLen = 6; LogInfo(" -> Simulated successful ARP reply on subnet of adapter %lu.", adapter->index); return NO_ERROR; } } } LogWarning(" -> Host unreachable."); return ERROR_HOST_UNREACHABLE; }
ULONG WINAPI ex_GetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen) { LogInfo("GetAdaptersInfo called."); if (!pOutBufLen) return ERROR_INVALID_PARAMETER; ULONG requiredSize = 0; for(int i=0; i<g_NetworkState.adapterCount; ++i) { requiredSize += sizeof(IP_ADAPTER_INFO); } if (g_NetworkState.adapterCount > 0 && requiredSize == 0) requiredSize = sizeof(IP_ADAPTER_INFO); if (*pOutBufLen < requiredSize) { *pOutBufLen = requiredSize; LogWarning(" -> Buffer too small. Required: %lu, Provided: %lu", requiredSize, *pOutBufLen); return ERROR_BUFFER_OVERFLOW; } if (g_NetworkState.adapterCount == 0) { *pOutBufLen = 0; LogInfo(" -> No adapters found."); return ERROR_NO_DATA; } memset(pAdapterInfo, 0, *pOutBufLen); PIP_ADAPTER_INFO pCurrent = pAdapterInfo; for (int i = 0; i < g_NetworkState.adapterCount; ++i) { const FakeAdapter* fake = &g_NetworkState.adapters[i]; strcpy_s(pCurrent->AdapterName, sizeof(pCurrent->AdapterName), fake->name); strcpy_s(pCurrent->Description, sizeof(pCurrent->Description), fake->description); pCurrent->AddressLength = 6; memcpy(pCurrent->Address, fake->macAddress, 6); pCurrent->Index = fake->index; pCurrent->Type = fake->type; pCurrent->DhcpEnabled = TRUE; IP_ADDR_STRING* pIpAddr = &pCurrent->IpAddressList; if (fake->ipCount > 0) { strcpy_s(pIpAddr->IpAddress.String, sizeof(pIpAddr->IpAddress.String), fake->ipAddresses[0].ipAddress); strcpy_s(pIpAddr->IpMask.String, sizeof(pIpAddr->IpMask.String), fake->ipAddresses[0].ipMask); pIpAddr->Context = fake->ipAddresses[0].NTEContext; } strcpy_s(pCurrent->GatewayList.IpAddress.String, sizeof(pCurrent->GatewayList.IpAddress.String), fake->gateway); if (i < g_NetworkState.adapterCount - 1) { pCurrent->Next = (IP_ADAPTER_INFO*)((BYTE*)pCurrent + sizeof(IP_ADAPTER_INFO)); pCurrent = pCurrent->Next; } else { pCurrent->Next = NULL; } } LogInfo(" -> Success. Returned info for %d adapters.", g_NetworkState.adapterCount); return NO_ERROR; }
DWORD WINAPI ex_GetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES pAdapterAddresses, PULONG pOutBufLen) {
    LogInfo("GetAdaptersAddresses(Family: %lu, Flags: %lu)", Family, Flags); UNREFERENCED_PARAMETER(Reserved); UNREFERENCED_PARAMETER(Flags);
    if (!pOutBufLen) return ERROR_INVALID_PARAMETER;

    ULONG requiredSize = 0;
    for (int i = 0; i < g_NetworkState.adapterCount; i++) {
        const FakeAdapter* fake = &g_NetworkState.adapters[i];
        requiredSize += sizeof(IP_ADAPTER_ADDRESSES);
        requiredSize += (strlen(fake->dnsSuffix) + 1) * sizeof(WCHAR);
        requiredSize += (strlen(fake->description) + 1) * sizeof(WCHAR);
        for(int j=0; j<fake->dnsCount; ++j) requiredSize += sizeof(IP_ADAPTER_DNS_SERVER_ADDRESS_XP) + sizeof(struct sockaddr_in);
        for(int j=0; j<fake->ipCount; ++j) if(fake->ipAddresses[j].family == Family || Family == AF_UNSPEC) requiredSize += sizeof(IP_ADAPTER_UNICAST_ADDRESS_LH) + sizeof(struct sockaddr_in);
        if(strlen(fake->gateway) > 0) requiredSize += sizeof(IP_ADAPTER_GATEWAY_ADDRESS_LH) + sizeof(struct sockaddr_in);
    }
    
    if (*pOutBufLen < requiredSize) {
        *pOutBufLen = requiredSize;
        LogWarning(" -> Buffer too small. Required: %lu, Provided: %lu", requiredSize, *pOutBufLen);
        return ERROR_BUFFER_OVERFLOW;
    }
    if (g_NetworkState.adapterCount == 0) { *pOutBufLen = 0; return NO_ERROR; }

    memset(pAdapterAddresses, 0, *pOutBufLen);
    char* pCurrentData = (char*)pAdapterAddresses;
    for (int i = 0; i < g_NetworkState.adapterCount; i++) pCurrentData += sizeof(IP_ADAPTER_ADDRESSES);

    for (int i = 0; i < g_NetworkState.adapterCount; i++) {
        const FakeAdapter* fake = &g_NetworkState.adapters[i];
        
        PIP_ADAPTER_ADDRESSES pCurrent = &pAdapterAddresses[i];
        if (i < g_NetworkState.adapterCount - 1) pCurrent->Next = &pAdapterAddresses[i+1];
        
        pCurrent->Length = sizeof(IP_ADAPTER_ADDRESSES);
        pCurrent->IfIndex = fake->index;
        pCurrent->PhysicalAddressLength = 6;
        memcpy(pCurrent->PhysicalAddress, fake->macAddress, 6);
        pCurrent->IfType = fake->type;
        pCurrent->OperStatus = fake->operStatus;
        
        pCurrent->DnsSuffix = (PWCHAR)pCurrentData;
        mbstowcs(pCurrent->DnsSuffix, fake->dnsSuffix, strlen(fake->dnsSuffix) + 1);
        pCurrentData += (strlen(fake->dnsSuffix) + 1) * sizeof(WCHAR);

        pCurrent->FriendlyName = (PWCHAR)pCurrentData;
        mbstowcs(pCurrent->FriendlyName, fake->description, strlen(fake->description) + 1);
        pCurrentData += (strlen(fake->description) + 1) * sizeof(WCHAR);
        
        PIP_ADAPTER_UNICAST_ADDRESS_LH pUnicast = NULL;
        for (int j = 0; j < fake->ipCount; j++) {
            if(fake->ipAddresses[j].family != Family && Family != AF_UNSPEC) continue;
            
            PIP_ADAPTER_UNICAST_ADDRESS_LH pNewUnicast = (PIP_ADAPTER_UNICAST_ADDRESS_LH)pCurrentData; pCurrentData += sizeof(IP_ADAPTER_UNICAST_ADDRESS_LH);
            if(pUnicast) pUnicast->Next = pNewUnicast; else pCurrent->FirstUnicastAddress = pNewUnicast;
            pUnicast = pNewUnicast;

            pUnicast->Address.lpSockaddr = (LPSOCKADDR)pCurrentData; pUnicast->Address.iSockaddrLength = sizeof(struct sockaddr_in);
            struct sockaddr_in* sa = (struct sockaddr_in*)pUnicast->Address.lpSockaddr; sa->sin_family = AF_INET; sa->sin_addr.s_addr = fake->ipAddresses[j].dwAddr;
            pCurrentData += sizeof(struct sockaddr_in);
        }
        
        PIP_ADAPTER_DNS_SERVER_ADDRESS_XP pDns = NULL;
        for(int j=0; j<fake->dnsCount; ++j) {
             PIP_ADAPTER_DNS_SERVER_ADDRESS_XP pNewDns = (PIP_ADAPTER_DNS_SERVER_ADDRESS_XP)pCurrentData; pCurrentData += sizeof(IP_ADAPTER_DNS_SERVER_ADDRESS_XP);
             if(pDns) pDns->Next = pNewDns; else pCurrent->FirstDnsServerAddress = pNewDns;
             pDns = pNewDns;

             pDns->Address.lpSockaddr = (LPSOCKADDR)pCurrentData; pDns->Address.iSockaddrLength = sizeof(struct sockaddr_in);
             struct sockaddr_in* sa = (struct sockaddr_in*)pDns->Address.lpSockaddr; sa->sin_family = AF_INET; sa->sin_addr.s_addr = inet_addr(fake->dnsAddresses[j]);
             pCurrentData += sizeof(struct sockaddr_in);
        }

        if(strlen(fake->gateway) > 0) {
            pCurrent->FirstGatewayAddress = (PIP_ADAPTER_GATEWAY_ADDRESS_LH)pCurrentData; pCurrentData += sizeof(IP_ADAPTER_GATEWAY_ADDRESS_LH);
            pCurrent->FirstGatewayAddress->Address.lpSockaddr = (LPSOCKADDR)pCurrentData; pCurrent->FirstGatewayAddress->Address.iSockaddrLength = sizeof(struct sockaddr_in);
            struct sockaddr_in* sa = (struct sockaddr_in*)pCurrent->FirstGatewayAddress->Address.lpSockaddr; sa->sin_family = AF_INET; sa->sin_addr.s_addr = inet_addr(fake->gateway);
            pCurrentData += sizeof(struct sockaddr_in);
        }
    }
    
    LogInfo(" -> Success. Returned info for %d adapters.", g_NetworkState.adapterCount);
    return NO_ERROR;
}
DWORD WINAPI ex_GetIfTable(PMIB_IFTABLE pIfTable, PULONG pdwSize, WINBOOL bOrder) { UNREFERENCED_PARAMETER(bOrder); LogInfo("GetIfTable called."); if (!pdwSize) return ERROR_INVALID_PARAMETER; DWORD requiredSize = sizeof(DWORD) + g_NetworkState.adapterCount * sizeof(MIB_IFROW); if (*pdwSize < requiredSize) { *pdwSize = requiredSize; LogWarning(" -> Buffer too small. Required: %lu, Provided: %lu", requiredSize, *pdwSize); return ERROR_INSUFFICIENT_BUFFER; } if (g_NetworkState.adapterCount == 0) { if(pIfTable) pIfTable->dwNumEntries = 0; *pdwSize = sizeof(DWORD); LogInfo(" -> No interfaces found."); return NO_ERROR; } pIfTable->dwNumEntries = g_NetworkState.adapterCount; for (int i = 0; i < g_NetworkState.adapterCount; ++i) { const FakeAdapter* fake = &g_NetworkState.adapters[i]; PMIB_IFROW row = &pIfTable->table[i]; memset(row, 0, sizeof(MIB_IFROW)); row->dwIndex = fake->index; row->dwType = fake->type; row->dwPhysAddrLen = 6; memcpy(row->bPhysAddr, fake->macAddress, 6); MultiByteToWideChar(CP_ACP, 0, fake->description, -1, row->wszName, MAX_INTERFACE_NAME_LEN); row->dwMtu = 1500; row->dwSpeed = 100000000; row->dwAdminStatus = fake->dwAdminStatus; row->dwOperStatus = (fake->dwAdminStatus == MIB_IF_ADMIN_STATUS_UP) ? IF_OPER_STATUS_OPERATIONAL : IF_OPER_STATUS_NON_OPERATIONAL; } *pdwSize = requiredSize; LogInfo(" -> Success. Returned %d interface entries.", g_NetworkState.adapterCount); return NO_ERROR; }
DWORD WINAPI ex_GetIpAddrTable(PMIB_IPADDRTABLE pIpAddrTable, PULONG pdwSize, WINBOOL bOrder) { UNREFERENCED_PARAMETER(bOrder); LogInfo("GetIpAddrTable called."); if (!pdwSize) return ERROR_INVALID_PARAMETER; int totalIps = 0; for (int i = 0; i < g_NetworkState.adapterCount; ++i) totalIps += g_NetworkState.adapters[i].ipCount; DWORD requiredSize = sizeof(DWORD) + totalIps * sizeof(MIB_IPADDRROW); if (*pdwSize < requiredSize) { *pdwSize = requiredSize; LogWarning(" -> Buffer too small. Required: %lu, Provided: %lu", requiredSize, *pdwSize); return ERROR_INSUFFICIENT_BUFFER; } if (totalIps == 0) { if(pIpAddrTable) pIpAddrTable->dwNumEntries = 0; *pdwSize = sizeof(DWORD); LogInfo(" -> No IP addresses found."); return NO_ERROR; } pIpAddrTable->dwNumEntries = totalIps; int currentRow = 0; for (int i = 0; i < g_NetworkState.adapterCount; ++i) { const FakeAdapter* fake = &g_NetworkState.adapters[i]; for (int j = 0; j < fake->ipCount; ++j) { const FakeIpAddress* ip = &fake->ipAddresses[j]; PMIB_IPADDRROW row = &pIpAddrTable->table[currentRow++]; row->dwAddr = ip->dwAddr; row->dwIndex = fake->index; row->dwMask = ip->dwMask; row->dwBCastAddr = ip->dwAddr | (~ip->dwMask); row->dwReasmSize = 0; row->wType = MIB_IPADDR_PRIMARY; } } *pdwSize = requiredSize; LogInfo(" -> Success. Returned %d IP address entries.", totalIps); return NO_ERROR; }
DWORD WINAPI ex_GetNumberOfInterfaces(PDWORD pdwNumIf) { LogInfo("GetNumberOfInterfaces called."); if (!pdwNumIf) return ERROR_INVALID_PARAMETER; *pdwNumIf = g_NetworkState.adapterCount; LogInfo(" -> Returning %d interfaces.", *pdwNumIf); return NO_ERROR; }
void WINAPI ex_FreeMibTable(PVOID Memory) { LogDebug("FreeMibTable called for memory %p", Memory); SAFE_FREE(Memory); }
DWORD WINAPI ex_GetNetworkParams(PFIXED_INFO pFixedInfo, PULONG pOutBufLen) { STUB_FAIL_DWORD(ERROR_BUFFER_OVERFLOW, ERROR_BUFFER_OVERFLOW); UNREFERENCED_PARAMETER(pFixedInfo); UNREFERENCED_PARAMETER(pOutBufLen); }
DWORD WINAPI ex_GetIpForwardTable(PMIB_IPFORWARDTABLE pIpForwardTable, PULONG pdwSize, BOOL bOrder) { STUB_FAIL_DWORD(ERROR_INSUFFICIENT_BUFFER, ERROR_INSUFFICIENT_BUFFER); UNREFERENCED_PARAMETER(pIpForwardTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); }
DWORD WINAPI ex_GetBestInterface(IPAddr dwDestAddr, PDWORD pdwBestIfIndex) { if (pdwBestIfIndex) *pdwBestIfIndex = 1; STUB_SUCCESS_DWORD(NO_ERROR); UNREFERENCED_PARAMETER(dwDestAddr); }
DWORD WINAPI ex_GetPerAdapterInfo(ULONG IfIndex, PIP_PER_ADAPTER_INFO pPerAdapterInfo, PULONG pOutBufLen) { STUB_FAIL_DWORD(ERROR_BUFFER_OVERFLOW, ERROR_BUFFER_OVERFLOW); UNREFERENCED_PARAMETER(IfIndex); UNREFERENCED_PARAMETER(pPerAdapterInfo); UNREFERENCED_PARAMETER(pOutBufLen); }

// ============================================================================
// === УСІ ІНШІ ЗАГЛУШКИ ===
// ============================================================================
DWORD WINAPI ex_AddIPAddress(IPAddr Address, IPMask IpMask, DWORD IfIndex, PULONG NTEContext, PULONG NTEInstance) { UNREFERENCED_PARAMETER(Address); UNREFERENCED_PARAMETER(IpMask); UNREFERENCED_PARAMETER(IfIndex); UNREFERENCED_PARAMETER(NTEContext); UNREFERENCED_PARAMETER(NTEInstance); return ex_StubNotSupported(); }
DWORD WINAPI ex_AllocateAndGetInterfaceInfoFromStack(PIP_INTERFACE_INFO* ppIfTable, PDWORD pdwSize, BOOL bOrder, HANDLE hHeap, DWORD dwFlags) { UNREFERENCED_PARAMETER(ppIfTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); UNREFERENCED_PARAMETER(hHeap); UNREFERENCED_PARAMETER(dwFlags); return ex_StubNotSupported(); }
DWORD WINAPI ex_AllocateAndGetIpAddrTableFromStack(PMIB_IPADDRTABLE* ppIpAddrTable, BOOL bOrder, HANDLE hHeap, DWORD dwFlags) { UNREFERENCED_PARAMETER(ppIpAddrTable); UNREFERENCED_PARAMETER(bOrder); UNREFERENCED_PARAMETER(hHeap); UNREFERENCED_PARAMETER(dwFlags); return ex_StubNotSupported(); }
DWORD WINAPI ex_AllocateAndGetTcpExTableFromStack(PVOID* p, PBOOL v, PBOOL o, HANDLE a, DWORD f) { UNREFERENCED_PARAMETER(p);UNREFERENCED_PARAMETER(v);UNREFERENCED_PARAMETER(o);UNREFERENCED_PARAMETER(a);UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_CancelIPChangeNotify(LPOVERLAPPED lpOverlapped) { UNREFERENCED_PARAMETER(lpOverlapped); return ex_StubNotSupported(); }
DWORD WINAPI ex_CancelIfTimestampConfigChange(LPOVERLAPPED hOverlapped) { UNREFERENCED_PARAMETER(hOverlapped); return ex_StubNotSupported(); }
DWORD WINAPI ex_CancelMibChangeNotify2(HANDLE NotificationHandle) { UNREFERENCED_PARAMETER(NotificationHandle); return ex_StubNotSupported(); }
DWORD WINAPI ex_CaptureInterfaceHardwareCrossTimestamp(const NET_LUID* InterfaceLuid, PINTERFACE_HARDWARE_CROSSTIMESTAMP CrossTimestamp) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(CrossTimestamp); return ex_StubNotSupported(); }
VOID WINAPI ex_CloseCompartment(HANDLE CompartmentHandle) { UNREFERENCED_PARAMETER(CompartmentHandle); STUB_LOG; }
VOID WINAPI ex_CloseGetIPPhysicalInterfaceForDestination(HANDLE GetIPPhysicalInterfaceForDestinationHandle) { UNREFERENCED_PARAMETER(GetIPPhysicalInterfaceForDestinationHandle); STUB_LOG; }
DWORD WINAPI ex_ConvertCompartmentGuidToId(const GUID* CompartmentGuid, PNET_IFINDEX CompartmentId) { UNREFERENCED_PARAMETER(CompartmentGuid); UNREFERENCED_PARAMETER(CompartmentId); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertCompartmentIdToGuid(NET_IFINDEX CompartmentId, GUID* CompartmentGuid) { UNREFERENCED_PARAMETER(CompartmentId); UNREFERENCED_PARAMETER(CompartmentGuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertGuidToStringA(const GUID* Guid, PSTR String, ULONG StringLength) { UNREFERENCED_PARAMETER(Guid); UNREFERENCED_PARAMETER(String); UNREFERENCED_PARAMETER(StringLength); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertGuidToStringW(const GUID* Guid, PWSTR String, ULONG StringLength) { UNREFERENCED_PARAMETER(Guid); UNREFERENCED_PARAMETER(String); UNREFERENCED_PARAMETER(StringLength); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceAliasToLuid(const WCHAR* InterfaceAlias, PNET_LUID InterfaceLuid) { UNREFERENCED_PARAMETER(InterfaceAlias); UNREFERENCED_PARAMETER(InterfaceLuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceGuidToLuid(const GUID* InterfaceGuid, PNET_LUID InterfaceLuid) { UNREFERENCED_PARAMETER(InterfaceGuid); UNREFERENCED_PARAMETER(InterfaceLuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceIndexToLuid(NET_IFINDEX InterfaceIndex, PNET_LUID InterfaceLuid) { UNREFERENCED_PARAMETER(InterfaceIndex); UNREFERENCED_PARAMETER(InterfaceLuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToAlias(const NET_LUID* InterfaceLuid, PWSTR InterfaceAlias, SIZE_T Length) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(InterfaceAlias); UNREFERENCED_PARAMETER(Length); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToGuid(const NET_LUID* InterfaceLuid, GUID* InterfaceGuid) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(InterfaceGuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToIndex(const NET_LUID* InterfaceLuid, PNET_IFINDEX InterfaceIndex) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(InterfaceIndex); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToNameA(const NET_LUID* InterfaceLuid, PSTR InterfaceName, SIZE_T Length) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(InterfaceName); UNREFERENCED_PARAMETER(Length); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToNameW(const NET_LUID* InterfaceLuid, PWSTR InterfaceName, SIZE_T Length) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(InterfaceName); UNREFERENCED_PARAMETER(Length); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceNameToLuidA(const CHAR* InterfaceName, PNET_LUID InterfaceLuid) { UNREFERENCED_PARAMETER(InterfaceName); UNREFERENCED_PARAMETER(InterfaceLuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceNameToLuidW(const WCHAR* InterfaceName, PNET_LUID InterfaceLuid) { UNREFERENCED_PARAMETER(InterfaceName); UNREFERENCED_PARAMETER(InterfaceLuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfacePhysicalAddressToLuid(const BYTE* PhysicalAddress, ULONG Length, PNET_LUID InterfaceLuid) { UNREFERENCED_PARAMETER(PhysicalAddress); UNREFERENCED_PARAMETER(Length); UNREFERENCED_PARAMETER(InterfaceLuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertIpv4MaskToLength(ULONG Mask, PUINT8 MaskLength) { UNREFERENCED_PARAMETER(Mask); UNREFERENCED_PARAMETER(MaskLength); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertLengthToIpv4Mask(ULONG MaskLength, PULONG Mask) { UNREFERENCED_PARAMETER(MaskLength); UNREFERENCED_PARAMETER(Mask); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceAliasToLuid(PCWSTR RemoteMachineName, const WCHAR* InterfaceAlias, PNET_LUID InterfaceLuid) { UNREFERENCED_PARAMETER(RemoteMachineName); UNREFERENCED_PARAMETER(InterfaceAlias); UNREFERENCED_PARAMETER(InterfaceLuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceGuidToLuid(PCWSTR RemoteMachineName, const GUID* InterfaceGuid, PNET_LUID InterfaceLuid) { UNREFERENCED_PARAMETER(RemoteMachineName); UNREFERENCED_PARAMETER(InterfaceGuid); UNREFERENCED_PARAMETER(InterfaceLuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceIndexToLuid(PCWSTR RemoteMachineName, NET_IFINDEX InterfaceIndex, PNET_LUID InterfaceLuid) { UNREFERENCED_PARAMETER(RemoteMachineName); UNREFERENCED_PARAMETER(InterfaceIndex); UNREFERENCED_PARAMETER(InterfaceLuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceLuidToAlias(PCWSTR RemoteMachineName, const NET_LUID* InterfaceLuid, PWSTR InterfaceAlias, SIZE_T Length) { UNREFERENCED_PARAMETER(RemoteMachineName); UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(InterfaceAlias); UNREFERENCED_PARAMETER(Length); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceLuidToGuid(PCWSTR RemoteMachineName, const NET_LUID* InterfaceLuid, GUID* InterfaceGuid) { UNREFERENCED_PARAMETER(RemoteMachineName); UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(InterfaceGuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceLuidToIndex(PCWSTR RemoteMachineName, const NET_LUID* InterfaceLuid, PNET_IFINDEX InterfaceIndex) { UNREFERENCED_PARAMETER(RemoteMachineName); UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(InterfaceIndex); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertStringToGuidA(const CHAR* String, GUID* Guid) { UNREFERENCED_PARAMETER(String); UNREFERENCED_PARAMETER(Guid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertStringToGuidW(const WCHAR* String, GUID* Guid) { UNREFERENCED_PARAMETER(String); UNREFERENCED_PARAMETER(Guid); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertStringToInterfacePhysicalAddress(PCWSTR String, ULONG64* PhysicalAddress, PULONG Length) { UNREFERENCED_PARAMETER(String); UNREFERENCED_PARAMETER(PhysicalAddress); UNREFERENCED_PARAMETER(Length); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateAnycastIpAddressEntry(const MIB_ANYCASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateCompartment(PCOMPARTMENT_ID CompartmentId) { UNREFERENCED_PARAMETER(CompartmentId); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateFlVirtualInterface(const WCHAR* FriendlyName, GUID* InterfaceGuid, PNET_LUID InterfaceLuid) { UNREFERENCED_PARAMETER(FriendlyName); UNREFERENCED_PARAMETER(InterfaceGuid); UNREFERENCED_PARAMETER(InterfaceLuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateIpForwardEntry(PMIB_IPFORWARDROW pRoute) { UNREFERENCED_PARAMETER(pRoute); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateIpForwardEntry2(const MIB_IPFORWARD_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateIpNetEntry(PMIB_IPNETROW pArpEntry) { UNREFERENCED_PARAMETER(pArpEntry); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateIpNetEntry2(const MIB_IPNET_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreatePersistentTcpPortReservation(USHORT StartPort, USHORT NumberOfPorts, PULONG64 Token) { UNREFERENCED_PARAMETER(StartPort); UNREFERENCED_PARAMETER(NumberOfPorts); UNREFERENCED_PARAMETER(Token); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreatePersistentUdpPortReservation(USHORT StartPort, USHORT NumberOfPorts, PULONG64 Token) { UNREFERENCED_PARAMETER(StartPort); UNREFERENCED_PARAMETER(NumberOfPorts); UNREFERENCED_PARAMETER(Token); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateProxyArpEntry(DWORD dwAddress, DWORD dwMask, DWORD dwIfIndex) { UNREFERENCED_PARAMETER(dwAddress); UNREFERENCED_PARAMETER(dwMask); UNREFERENCED_PARAMETER(dwIfIndex); return ex_StubNotSupported(); }
VOID WINAPI ex_CreateSortedAddressPairs(const PSOCKADDR_IN6 SourceAddressList, ULONG SourceAddressCount, const PSOCKADDR_IN6 DestinationAddressList, ULONG DestinationAddressCount, ULONG AddressSortOptions, PSOCKADDR_IN6_PAIR* SortedAddressPairList, PULONG SortedAddressPairCount) { UNREFERENCED_PARAMETER(SourceAddressList); UNREFERENCED_PARAMETER(SourceAddressCount); UNREFERENCED_PARAMETER(DestinationAddressList); UNREFERENCED_PARAMETER(DestinationAddressCount); UNREFERENCED_PARAMETER(AddressSortOptions); UNREFERENCED_PARAMETER(SortedAddressPairList); UNREFERENCED_PARAMETER(SortedAddressPairCount); STUB_LOG; }
DWORD WINAPI ex_CreateUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteAnycastIpAddressEntry(const MIB_ANYCASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
VOID WINAPI ex_DeleteCompartment(HANDLE CompartmentHandle) { UNREFERENCED_PARAMETER(CompartmentHandle); STUB_LOG; }
VOID WINAPI ex_DeleteFlVirtualInterface(const NET_LUID* InterfaceLuid) { UNREFERENCED_PARAMETER(InterfaceLuid); STUB_LOG; }
DWORD WINAPI ex_DeleteIpForwardEntry(PMIB_IPFORWARDROW pRoute) { UNREFERENCED_PARAMETER(pRoute); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteIpForwardEntry2(const MIB_IPFORWARD_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteIpNetEntry(PMIB_IPNETROW pArpEntry) { UNREFERENCED_PARAMETER(pArpEntry); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteIpNetEntry2(const MIB_IPNET_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeletePersistentTcpPortReservation(USHORT StartPort, USHORT NumberOfPorts) { UNREFERENCED_PARAMETER(StartPort); UNREFERENCED_PARAMETER(NumberOfPorts); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeletePersistentUdpPortReservation(USHORT StartPort, USHORT NumberOfPorts) { UNREFERENCED_PARAMETER(StartPort); UNREFERENCED_PARAMETER(NumberOfPorts); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteProxyArpEntry(DWORD dwAddress, DWORD dwMask, DWORD dwIfIndex) { UNREFERENCED_PARAMETER(dwAddress); UNREFERENCED_PARAMETER(dwMask); UNREFERENCED_PARAMETER(dwIfIndex); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_DisableMediaSense(HANDLE* pHandle, LPOVERLAPPED pOverlapped) { UNREFERENCED_PARAMETER(pHandle); UNREFERENCED_PARAMETER(pOverlapped); return ex_StubNotSupported(); }
DWORD WINAPI ex_EnableRouter(HANDLE* pHandle, LPOVERLAPPED pOverlapped) { UNREFERENCED_PARAMETER(pHandle); UNREFERENCED_PARAMETER(pOverlapped); return ex_StubNotSupported(); }
DWORD WINAPI ex_FlushIpNetTable(DWORD dwIfIndex) { UNREFERENCED_PARAMETER(dwIfIndex); return ex_StubNotSupported(); }
DWORD WINAPI ex_FlushIpNetTable2(ADDRESS_FAMILY Family, NET_IFINDEX InterfaceIndex) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(InterfaceIndex); return ex_StubNotSupported(); }
DWORD WINAPI ex_FlushIpPathTable(ADDRESS_FAMILY Family) { UNREFERENCED_PARAMETER(Family); return ex_StubNotSupported(); }
VOID WINAPI ex_FreeDnsSettings(PDNS_SETTINGS Settings) { UNREFERENCED_PARAMETER(Settings); STUB_LOG; }
VOID WINAPI ex_FreeInterfaceDnsSettings(PDNS_INTERFACE_SETTINGS Settings) { UNREFERENCED_PARAMETER(Settings); STUB_LOG; }
DWORD WINAPI ex_GetAdapterIndex(LPWSTR AdapterName, PULONG IfIndex) { UNREFERENCED_PARAMETER(AdapterName); UNREFERENCED_PARAMETER(IfIndex); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetAdapterOrderMap() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetAnycastIpAddressEntry(MIB_ANYCASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetAnycastIpAddressTable(ADDRESS_FAMILY Family, PMIB_ANYCASTIPADDRESS_TABLE* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetBestInterfaceEx(PSOCKADDR pDestAddr, PDWORD pdwBestIfIndex) { UNREFERENCED_PARAMETER(pDestAddr); UNREFERENCED_PARAMETER(pdwBestIfIndex); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetBestRoute(DWORD dwDestAddr, DWORD dwSourceAddr, PMIB_IPFORWARDROW pBestRoute) { UNREFERENCED_PARAMETER(dwDestAddr); UNREFERENCED_PARAMETER(dwSourceAddr); UNREFERENCED_PARAMETER(pBestRoute); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetBestRoute2(NET_LUID* InterfaceLuid, NET_IFINDEX InterfaceIndex, const SOCKADDR_INET* SourceAddress, const SOCKADDR_INET* DestinationAddress, ULONG AddressSortOptions, MIB_IPFORWARD_ROW2* BestRoute, SOCKADDR_INET* BestSourceAddress) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(InterfaceIndex); UNREFERENCED_PARAMETER(SourceAddress); UNREFERENCED_PARAMETER(DestinationAddress); UNREFERENCED_PARAMETER(AddressSortOptions); UNREFERENCED_PARAMETER(BestRoute); UNREFERENCED_PARAMETER(BestSourceAddress); return ex_StubNotSupported(); }
COMPARTMENT_ID WINAPI ex_GetCurrentThreadCompartmentId() { STUB_LOG; return 0; }
VOID WINAPI ex_GetCurrentThreadCompartmentScope(PCOMPARTMENT_ID CompartmentId, PCOMPARTMENT_ID CompartmentScope) { UNREFERENCED_PARAMETER(CompartmentId); UNREFERENCED_PARAMETER(CompartmentScope); STUB_LOG; }
COMPARTMENT_ID WINAPI ex_GetDefaultCompartmentId() { STUB_LOG; return 0; }
DWORD WINAPI ex_GetDnsSettings(PDNS_SETTINGS Settings) { UNREFERENCED_PARAMETER(Settings); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetFlVirtualInterface(const NET_LUID* InterfaceLuid, PMIB_FL_VIRTUAL_INTERFACE VirtualInterface) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(VirtualInterface); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetFlVirtualInterfaceTable(ADDRESS_FAMILY Family, PMIB_FL_VIRTUAL_INTERFACE_TABLE* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetFriendlyIfIndex(DWORD IfIndex) { UNREFERENCED_PARAMETER(IfIndex); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIcmpStatistics(PMIB_ICMP pStats) { UNREFERENCED_PARAMETER(pStats); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIcmpStatisticsEx(PMIB_ICMP_EX pStats, DWORD dwFamily) { UNREFERENCED_PARAMETER(pStats); UNREFERENCED_PARAMETER(dwFamily); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfEntry(PMIB_IFROW pIfRow) { UNREFERENCED_PARAMETER(pIfRow); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfEntry2(MIB_IF_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfEntry2Ex(MIB_IF_TABLE_LEVEL Level, const MIB_IF_ROW2* Row) { UNREFERENCED_PARAMETER(Level); UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfStackTable(PMIB_IFSTACK_TABLE* Table) { UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfTable2(PMIB_IF_TABLE2* Table) { UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfTable2Ex(MIB_IF_TABLE_LEVEL Level, PMIB_IF_TABLE2* Table) { UNREFERENCED_PARAMETER(Level); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceActiveTimestampCapabilities(const NET_LUID* InterfaceLuid, PINTERFACE_TIMESTAMP_CAPABILITIES TimestampCapabilities) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(TimestampCapabilities); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceCompartmentId(const NET_LUID* InterfaceLuid, PCOMPARTMENT_ID CompartmentId) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(CompartmentId); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceCurrentTimestampCapabilities(const NET_LUID* InterfaceLuid, PINTERFACE_TIMESTAMP_CAPABILITIES TimestampCapabilities) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(TimestampCapabilities); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceDnsSettings(GUID Interface, PDNS_INTERFACE_SETTINGS Settings) { UNREFERENCED_PARAMETER(Interface); UNREFERENCED_PARAMETER(Settings); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceHardwareTimestampCapabilities(const NET_LUID* InterfaceLuid, PINTERFACE_TIMESTAMP_CAPABILITIES TimestampCapabilities) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(TimestampCapabilities); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceInfo(PIP_INTERFACE_INFO pIfTable, PULONG dwOutBufLen) { UNREFERENCED_PARAMETER(pIfTable); UNREFERENCED_PARAMETER(dwOutBufLen); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceSupportedTimestampCapabilities(const NET_LUID* InterfaceLuid, PINTERFACE_TIMESTAMP_CAPABILITIES TimestampCapabilities) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(TimestampCapabilities); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInvertedIfStackTable(PMIB_INVERTEDIFSTACK_TABLE* Table) { UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpErrorString(IP_STATUS ErrorCode, PWSTR Buffer, PDWORD Size) { UNREFERENCED_PARAMETER(ErrorCode); UNREFERENCED_PARAMETER(Buffer); UNREFERENCED_PARAMETER(Size); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpForwardEntry2(MIB_IPFORWARD_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpForwardTable2(ADDRESS_FAMILY Family, PMIB_IPFORWARD_TABLE2* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpInterfaceEntry(MIB_IPINTERFACE_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpInterfaceTable(ADDRESS_FAMILY Family, PMIB_IPINTERFACE_TABLE* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpNetEntry2(MIB_IPNET_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpNetTable2(ADDRESS_FAMILY Family, PMIB_IPNET_TABLE2* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpNetworkConnectionBandwidthEstimates(NET_IFINDEX InterfaceIndex, ADDRESS_FAMILY AddressFamily, PNET_IF_CONNECTION_BANDWIDTH_ESTIMATES BandwidthEstimates) { UNREFERENCED_PARAMETER(InterfaceIndex); UNREFERENCED_PARAMETER(AddressFamily); UNREFERENCED_PARAMETER(BandwidthEstimates); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpPathEntry(const MIB_IPPATH_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpPathTable(ADDRESS_FAMILY Family, PMIB_IPPATH_TABLE* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpStatistics(PMIB_IPSTATS pStats) { UNREFERENCED_PARAMETER(pStats); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpStatisticsEx(PMIB_IPSTATS pStats, DWORD dwFamily) { UNREFERENCED_PARAMETER(pStats); UNREFERENCED_PARAMETER(dwFamily); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetJobCompartmentId(HANDLE JobHandle, PCOMPARTMENT_ID CompartmentId) { UNREFERENCED_PARAMETER(JobHandle); UNREFERENCED_PARAMETER(CompartmentId); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetMulticastIpAddressEntry(MIB_MULTICASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetMulticastIpAddressTable(ADDRESS_FAMILY Family, PMIB_MULTICASTIPADDRESS_TABLE* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetNetworkConnectivityHint(PNL_NETWORK_CONNECTIVITY_HINT ConnectivityHint) { UNREFERENCED_PARAMETER(ConnectivityHint); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetNetworkConnectivityHintForInterface(NET_IFINDEX InterfaceIndex, PNL_NETWORK_CONNECTIVITY_HINT ConnectivityHint) { UNREFERENCED_PARAMETER(InterfaceIndex); UNREFERENCED_PARAMETER(ConnectivityHint); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetNetworkInformation(const GUID* NetworkGuid, PBOOL IsNetworkMetered) { UNREFERENCED_PARAMETER(NetworkGuid); UNREFERENCED_PARAMETER(IsNetworkMetered); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromPidAndInfo(DWORD dwPid, TCPIP_OWNER_MODULE_INFO_CLASS* pInfo, PVOID pBuffer, PDWORD pdwSize) { UNREFERENCED_PARAMETER(dwPid); UNREFERENCED_PARAMETER(pInfo); UNREFERENCED_PARAMETER(pBuffer); UNREFERENCED_PARAMETER(pdwSize); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromTcp6Entry(const MIB_TCP6ROW_OWNER_MODULE* pTcpEntry, TCPIP_OWNER_MODULE_INFO_CLASS Class, PVOID pBuffer, PDWORD pdwSize) { UNREFERENCED_PARAMETER(pTcpEntry); UNREFERENCED_PARAMETER(Class); UNREFERENCED_PARAMETER(pBuffer); UNREFERENCED_PARAMETER(pdwSize); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromTcpEntry(const MIB_TCPROW_OWNER_MODULE* pTcpEntry, TCPIP_OWNER_MODULE_INFO_CLASS Class, PVOID pBuffer, PDWORD pdwSize) { UNREFERENCED_PARAMETER(pTcpEntry); UNREFERENCED_PARAMETER(Class); UNREFERENCED_PARAMETER(pBuffer); UNREFERENCED_PARAMETER(pdwSize); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromUdp6Entry(const MIB_UDP6ROW_OWNER_MODULE* pUdpEntry, TCPIP_OWNER_MODULE_INFO_CLASS Class, PVOID pBuffer, PDWORD pdwSize) { UNREFERENCED_PARAMETER(pUdpEntry); UNREFERENCED_PARAMETER(Class); UNREFERENCED_PARAMETER(pBuffer); UNREFERENCED_PARAMETER(pdwSize); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromUdpEntry(const MIB_UDPROW_OWNER_MODULE* pUdpEntry, TCPIP_OWNER_MODULE_INFO_CLASS Class, PVOID pBuffer, PDWORD pdwSize) { UNREFERENCED_PARAMETER(pUdpEntry); UNREFERENCED_PARAMETER(Class); UNREFERENCED_PARAMETER(pBuffer); UNREFERENCED_PARAMETER(pdwSize); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetPerTcp6ConnectionEStats(const MIB_TCP6ROW* Row, TCP_ESTATS_TYPE EstatsType, PUCHAR Rw, ULONG RwVersion, ULONG RwSize, PUCHAR Ros, ULONG RosVersion, ULONG RosSize, PUCHAR Rod, ULONG RodVersion, ULONG RodSize) { UNREFERENCED_PARAMETER(Row); UNREFERENCED_PARAMETER(EstatsType); UNREFERENCED_PARAMETER(Rw); UNREFERENCED_PARAMETER(RwVersion); UNREFERENCED_PARAMETER(RwSize); UNREFERENCED_PARAMETER(Ros); UNREFERENCED_PARAMETER(RosVersion); UNREFERENCED_PARAMETER(RosSize); UNREFERENCED_PARAMETER(Rod); UNREFERENCED_PARAMETER(RodVersion); UNREFERENCED_PARAMETER(RodSize); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetPerTcp6ConnectionStats(const MIB_TCP6ROW* Row, PMIB_TCPSTATS pStats) { UNREFERENCED_PARAMETER(Row); UNREFERENCED_PARAMETER(pStats); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetPerTcpConnectionEStats(PMIB_TCPROW pRow, TCP_ESTATS_TYPE EstatsType, PUCHAR Rw, ULONG RwVersion, ULONG RwSize, ULONG Offset) { UNREFERENCED_PARAMETER(pRow); UNREFERENCED_PARAMETER(EstatsType); UNREFERENCED_PARAMETER(Rw); UNREFERENCED_PARAMETER(RwVersion); UNREFERENCED_PARAMETER(RwSize); UNREFERENCED_PARAMETER(Offset); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetPerTcpConnectionStats(PMIB_TCPROW pRow, PMIB_TCPSTATS pStats) { UNREFERENCED_PARAMETER(pRow); UNREFERENCED_PARAMETER(pStats); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetRTTAndHopCount(IPAddr DestIpAddress, PULONG HopCount, ULONG MaxHops, PULONG RTT) { UNREFERENCED_PARAMETER(DestIpAddress); UNREFERENCED_PARAMETER(HopCount); UNREFERENCED_PARAMETER(MaxHops); UNREFERENCED_PARAMETER(RTT); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetSessionCompartmentId(ULONG SessionId, PCOMPARTMENT_ID CompartmentId) { UNREFERENCED_PARAMETER(SessionId); UNREFERENCED_PARAMETER(CompartmentId); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcp6Table2(PMIB_TCP6TABLE2* TcpTable, BOOL Order) { UNREFERENCED_PARAMETER(TcpTable); UNREFERENCED_PARAMETER(Order); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcpStatisticsEx2(PMIB_TCPSTATS2 Statistics, ULONG Family) { UNREFERENCED_PARAMETER(Statistics); UNREFERENCED_PARAMETER(Family); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcpTable2(PMIB_TCPTABLE2* TcpTable, BOOL Order) { UNREFERENCED_PARAMETER(TcpTable); UNREFERENCED_PARAMETER(Order); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTeredoPort(PUSHORT Port) { UNREFERENCED_PARAMETER(Port); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUdpStatisticsEx2(PMIB_UDPSTATS2 Statistics, ULONG Family) { UNREFERENCED_PARAMETER(Statistics); UNREFERENCED_PARAMETER(Family); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUniDirectionalAdapterInfo(PIP_UNIDIRECTIONAL_ADAPTER_ADDRESS pIPIfInfo, PULONG dwOutBufLen) { UNREFERENCED_PARAMETER(pIPIfInfo); UNREFERENCED_PARAMETER(dwOutBufLen); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUnicastIpAddressEntry(MIB_UNICASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUnicastIpAddressTable(ADDRESS_FAMILY Family, PMIB_UNICASTIPADDRESS_TABLE* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetWPAOACSupportLevel(PBOOL IsSupported) { UNREFERENCED_PARAMETER(IsSupported); return ex_StubNotSupported(); }
HANDLE WINAPI ex_Icmp6CreateFile() { STUB_LOG; return INVALID_HANDLE_VALUE; }
DWORD WINAPI ex_Icmp6ParseReplies(LPVOID ReplyBuffer, DWORD ReplySize) { UNREFERENCED_PARAMETER(ReplyBuffer); UNREFERENCED_PARAMETER(ReplySize); return ex_StubNotSupported(); }
DWORD WINAPI ex_Icmp6SendEcho2(HANDLE IcmpHandle, HANDLE Event, PTIMERAPCROUTINE ApcRoutine, PVOID ApcContext, const struct sockaddr_in6* SourceAddress, const struct sockaddr_in6* DestinationAddress, LPVOID RequestData, WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout) { UNREFERENCED_PARAMETER(IcmpHandle); UNREFERENCED_PARAMETER(Event); UNREFERENCED_PARAMETER(ApcRoutine); UNREFERENCED_PARAMETER(ApcContext); UNREFERENCED_PARAMETER(SourceAddress); UNREFERENCED_PARAMETER(DestinationAddress); UNREFERENCED_PARAMETER(RequestData); UNREFERENCED_PARAMETER(RequestSize); UNREFERENCED_PARAMETER(RequestOptions); UNREFERENCED_PARAMETER(ReplyBuffer); UNREFERENCED_PARAMETER(ReplySize); UNREFERENCED_PARAMETER(Timeout); return ex_StubNotSupported(); }
BOOL WINAPI ex_IcmpCloseHandle(HANDLE IcmpHandle) { UNREFERENCED_PARAMETER(IcmpHandle); STUB_FAIL_BOOL(ERROR_INVALID_HANDLE); }
HANDLE WINAPI ex_IcmpCreateFile() { STUB_LOG; return INVALID_HANDLE_VALUE; }
DWORD WINAPI ex_IcmpParseReplies(LPVOID ReplyBuffer, DWORD ReplySize) { UNREFERENCED_PARAMETER(ReplyBuffer); UNREFERENCED_PARAMETER(ReplySize); return ex_StubNotSupported(); }
DWORD WINAPI ex_IcmpSendEcho(HANDLE IcmpHandle, IPAddr DestinationAddress, LPVOID RequestData, WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout) { UNREFERENCED_PARAMETER(IcmpHandle); UNREFERENCED_PARAMETER(DestinationAddress); UNREFERENCED_PARAMETER(RequestData); UNREFERENCED_PARAMETER(RequestSize); UNREFERENCED_PARAMETER(RequestOptions); UNREFERENCED_PARAMETER(ReplyBuffer); UNREFERENCED_PARAMETER(ReplySize); UNREFERENCED_PARAMETER(Timeout); return ex_StubNotSupported(); }
DWORD WINAPI ex_IcmpSendEcho2(HANDLE IcmpHandle, HANDLE Event, PTIMERAPCROUTINE ApcRoutine, PVOID ApcContext, IPAddr DestinationAddress, LPVOID RequestData, WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout) { UNREFERENCED_PARAMETER(IcmpHandle); UNREFERENCED_PARAMETER(Event); UNREFERENCED_PARAMETER(ApcRoutine); UNREFERENCED_PARAMETER(ApcContext); UNREFERENCED_PARAMETER(DestinationAddress); UNREFERENCED_PARAMETER(RequestData); UNREFERENCED_PARAMETER(RequestSize); UNREFERENCED_PARAMETER(RequestOptions); UNREFERENCED_PARAMETER(ReplyBuffer); UNREFERENCED_PARAMETER(ReplySize); UNREFERENCED_PARAMETER(Timeout); return ex_StubNotSupported(); }
DWORD WINAPI ex_IcmpSendEcho2Ex(HANDLE IcmpHandle, HANDLE Event, PTIMERAPCROUTINE ApcRoutine, PVOID ApcContext, IPAddr SourceAddress, IPAddr DestinationAddress, LPVOID RequestData, WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout) { UNREFERENCED_PARAMETER(IcmpHandle); UNREFERENCED_PARAMETER(Event); UNREFERENCED_PARAMETER(ApcRoutine); UNREFERENCED_PARAMETER(ApcContext); UNREFERENCED_PARAMETER(SourceAddress); UNREFERENCED_PARAMETER(DestinationAddress); UNREFERENCED_PARAMETER(RequestData); UNREFERENCED_PARAMETER(RequestSize); UNREFERENCED_PARAMETER(RequestOptions); UNREFERENCED_PARAMETER(ReplyBuffer); UNREFERENCED_PARAMETER(ReplySize); UNREFERENCED_PARAMETER(Timeout); return ex_StubNotSupported(); }
VOID WINAPI ex_InitializeCompartmentEntry(PCOMPARTMENT_ID CompartmentId) { UNREFERENCED_PARAMETER(CompartmentId); STUB_LOG; }
VOID WINAPI ex_InitializeFlVirtualInterfaceEntry(PMIB_FL_VIRTUAL_INTERFACE VirtualInterface) { UNREFERENCED_PARAMETER(VirtualInterface); STUB_LOG; }
VOID WINAPI ex_InitializeIpForwardEntry(PMIB_IPFORWARDROW pRoute) { UNREFERENCED_PARAMETER(pRoute); STUB_LOG; }
VOID WINAPI ex_InitializeIpInterfaceEntry(MIB_IPINTERFACE_ROW* Row) { UNREFERENCED_PARAMETER(Row); STUB_LOG; }
VOID WINAPI ex_InitializeUnicastIpAddressEntry(MIB_UNICASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); STUB_LOG; }
DWORD WINAPI ex_InternalCleanupPersistentStore() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateAnycastIpAddressEntry(const MIB_ANYCASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateIpForwardEntry(PMIB_IPFORWARDROW pRoute) { UNREFERENCED_PARAMETER(pRoute); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateIpForwardEntry2(const MIB_IPFORWARD_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateIpNetEntry(PMIB_IPNETROW pArpEntry) { UNREFERENCED_PARAMETER(pArpEntry); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateIpNetEntry2(const MIB_IPNET_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateOrRefIpForwardEntry2(const MIB_IPFORWARD_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteAnycastIpAddressEntry(const MIB_ANYCASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteIpForwardEntry(PMIB_IPFORWARDROW pRoute) { UNREFERENCED_PARAMETER(pRoute); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteIpForwardEntry2(const MIB_IPFORWARD_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteIpNetEntry(PMIB_IPNETROW pArpEntry) { UNREFERENCED_PARAMETER(pArpEntry); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteIpNetEntry2(const MIB_IPNET_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalFindInterfaceByAddress(const SOCKADDR_INET* Address) { UNREFERENCED_PARAMETER(Address); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetAnycastIpAddressEntry(MIB_ANYCASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetAnycastIpAddressTable(ADDRESS_FAMILY Family, PMIB_ANYCASTIPADDRESS_TABLE* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetBoundTcp6EndpointTable(ULONG Unknown, PMIB_TCP6TABLE_OWNER_MODULE* TcpTable, PULONG Size) { UNREFERENCED_PARAMETER(Unknown); UNREFERENCED_PARAMETER(TcpTable); UNREFERENCED_PARAMETER(Size); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetBoundTcpEndpointTable(ULONG Unknown, PMIB_TCPTABLE_OWNER_MODULE* TcpTable, PULONG Size) { UNREFERENCED_PARAMETER(Unknown); UNREFERENCED_PARAMETER(TcpTable); UNREFERENCED_PARAMETER(Size); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetForwardIpTable2(ADDRESS_FAMILY Family, PMIB_IPFORWARD_TABLE2* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIPPhysicalInterfaceForDestination(const SOCKADDR* Destination, PMIB_IP_PHYSICAL_INTERFACE_ROW Row) { UNREFERENCED_PARAMETER(Destination); UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIfEntry2(MIB_IF_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIfTable(PMIB_IFTABLE pIfTable, PULONG pdwSize, BOOL bOrder) { UNREFERENCED_PARAMETER(pIfTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIfTable2(PMIB_IF_TABLE2* Table) { UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpAddrTable(PMIB_IPADDRTABLE pIpAddrTable, PULONG pdwSize, BOOL bOrder) { UNREFERENCED_PARAMETER(pIpAddrTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpForwardEntry2(MIB_IPFORWARD_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpForwardTable(PMIB_IPFORWARDTABLE pIpForwardTable, PULONG pdwSize, BOOL bOrder) { UNREFERENCED_PARAMETER(pIpForwardTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpInterfaceEntry(MIB_IPINTERFACE_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpInterfaceTable(ADDRESS_FAMILY Family, PMIB_IPINTERFACE_TABLE* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpNetEntry2(MIB_IPNET_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpNetTable(PMIB_IPNETTABLE pIpNetTable, PULONG pdwSize, BOOL bOrder) { UNREFERENCED_PARAMETER(pIpNetTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpNetTable2(ADDRESS_FAMILY Family, PMIB_IPNET_TABLE2* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetMulticastIpAddressEntry(MIB_MULTICASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetMulticastIpAddressTable(ADDRESS_FAMILY Family, PMIB_MULTICASTIPADDRESS_TABLE* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetRtcSlotInformation(PRTC_SLOT_INFORMATION_TABLE RtcSlotInformationTable) { UNREFERENCED_PARAMETER(RtcSlotInformationTable); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcp6Table2(PMIB_TCP6TABLE2* TcpTable, BOOL Order) { UNREFERENCED_PARAMETER(TcpTable); UNREFERENCED_PARAMETER(Order); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcp6TableWithOwnerModule(PMIB_TCP6TABLE_OWNER_MODULE* TcpTable, BOOL Order, HANDLE hHeap, DWORD dwFlags) { UNREFERENCED_PARAMETER(TcpTable); UNREFERENCED_PARAMETER(Order); UNREFERENCED_PARAMETER(hHeap); UNREFERENCED_PARAMETER(dwFlags); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcp6TableWithOwnerPid(PMIB_TCP6TABLE_OWNER_PID* TcpTable, BOOL Order) { UNREFERENCED_PARAMETER(TcpTable); UNREFERENCED_PARAMETER(Order); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpDynamicPortRange(USHORT* StartPort, USHORT* TotalNumberOfPorts) { UNREFERENCED_PARAMETER(StartPort); UNREFERENCED_PARAMETER(TotalNumberOfPorts); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTable(PMIB_TCPTABLE pTcpTable, PULONG pdwSize, BOOL bOrder) { UNREFERENCED_PARAMETER(pTcpTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTable2(PMIB_TCPTABLE2* TcpTable, BOOL Order) { UNREFERENCED_PARAMETER(TcpTable); UNREFERENCED_PARAMETER(Order); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTableEx(PVOID pTcpTable, PULONG pdwSize, BOOL bOrder, ULONG ulAf) { UNREFERENCED_PARAMETER(pTcpTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); UNREFERENCED_PARAMETER(ulAf); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTableWithOwnerModule(PMIB_TCPTABLE_OWNER_MODULE* TcpTable, BOOL Order, HANDLE hHeap, DWORD dwFlags) { UNREFERENCED_PARAMETER(TcpTable); UNREFERENCED_PARAMETER(Order); UNREFERENCED_PARAMETER(hHeap); UNREFERENCED_PARAMETER(dwFlags); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTableWithOwnerPid(PMIB_TCPTABLE_OWNER_PID* TcpTable, BOOL Order) { UNREFERENCED_PARAMETER(TcpTable); UNREFERENCED_PARAMETER(Order); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTunnelPhysicalAdapter(NET_LUID InterfaceLuid, PMIB_TUNNEL_PHYSICAL_ADAPTER TunnelPhysicalAdapter) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(TunnelPhysicalAdapter); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdp6Table2(PMIB_UDP6TABLE* UdpTable, BOOL Order) { UNREFERENCED_PARAMETER(UdpTable); UNREFERENCED_PARAMETER(Order); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdp6TableWithOwnerModule(PMIB_UDP6TABLE_OWNER_MODULE* UdpTable, BOOL Order, HANDLE hHeap, DWORD dwFlags) { UNREFERENCED_PARAMETER(UdpTable); UNREFERENCED_PARAMETER(Order); UNREFERENCED_PARAMETER(hHeap); UNREFERENCED_PARAMETER(dwFlags); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdp6TableWithOwnerPid(PMIB_UDP6TABLE_OWNER_PID* UdpTable, BOOL Order) { UNREFERENCED_PARAMETER(UdpTable); UNREFERENCED_PARAMETER(Order); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpDynamicPortRange(USHORT* StartPort, USHORT* TotalNumberOfPorts) { UNREFERENCED_PARAMETER(StartPort); UNREFERENCED_PARAMETER(TotalNumberOfPorts); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTable(PMIB_UDPTABLE pUdpTable, PULONG pdwSize, BOOL bOrder) { UNREFERENCED_PARAMETER(pUdpTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTable2(PMIB_UDPTABLE* UdpTable, BOOL Order) { UNREFERENCED_PARAMETER(UdpTable); UNREFERENCED_PARAMETER(Order); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTableEx(PVOID pUdpTable, PULONG pdwSize, BOOL bOrder, ULONG ulAf) { UNREFERENCED_PARAMETER(pUdpTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); UNREFERENCED_PARAMETER(ulAf); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTableWithOwnerModule(PMIB_UDPTABLE_OWNER_MODULE* UdpTable, BOOL Order, HANDLE hHeap, DWORD dwFlags) { UNREFERENCED_PARAMETER(UdpTable); UNREFERENCED_PARAMETER(Order); UNREFERENCED_PARAMETER(hHeap); UNREFERENCED_PARAMETER(dwFlags); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTableWithOwnerPid(PMIB_UDPTABLE_OWNER_PID* UdpTable, BOOL Order) { UNREFERENCED_PARAMETER(UdpTable); UNREFERENCED_PARAMETER(Order); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUnicastIpAddressEntry(MIB_UNICASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUnicastIpAddressTable(ADDRESS_FAMILY Family, PMIB_UNICASTIPADDRESS_TABLE* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalIcmpCreateFileEx(PHANDLE IcmpHandle, PVOID ApcContext, PTIMERAPCROUTINE ApcRoutine) { UNREFERENCED_PARAMETER(IcmpHandle); UNREFERENCED_PARAMETER(ApcContext); UNREFERENCED_PARAMETER(ApcRoutine); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIfEntry(PMIB_IFROW pIfRow) { UNREFERENCED_PARAMETER(pIfRow); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpForwardEntry(PMIB_IPFORWARDROW pRoute) { UNREFERENCED_PARAMETER(pRoute); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpForwardEntry2(const MIB_IPFORWARD_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpInterfaceEntry(MIB_IPINTERFACE_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpNetEntry(PMIB_IPNETROW pArpEntry) { UNREFERENCED_PARAMETER(pArpEntry); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpNetEntry2(const MIB_IPNET_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpStats(PMIB_IPSTATS pIpStats) { UNREFERENCED_PARAMETER(pIpStats); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetTcpDynamicPortRange(USHORT StartPort, USHORT NumberOfPorts) { UNREFERENCED_PARAMETER(StartPort); UNREFERENCED_PARAMETER(NumberOfPorts); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetTcpEntry(PMIB_TCPROW pTcpRow) { UNREFERENCED_PARAMETER(pTcpRow); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetTeredoPort(USHORT Port) { UNREFERENCED_PARAMETER(Port); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetUdpDynamicPortRange(USHORT StartPort, USHORT NumberOfPorts) { UNREFERENCED_PARAMETER(StartPort); UNREFERENCED_PARAMETER(NumberOfPorts); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_IpReleaseAddress(PIP_ADAPTER_INDEX_MAP AdapterInfo) { UNREFERENCED_PARAMETER(AdapterInfo); return ex_StubNotSupported(); }
DWORD WINAPI ex_IpRenewAddress(PIP_ADAPTER_INDEX_MAP AdapterInfo) { UNREFERENCED_PARAMETER(AdapterInfo); return ex_StubNotSupported(); }
DWORD WINAPI ex_LookupPersistentTcpPortReservation(USHORT StartPort, USHORT NumberOfPorts, PULONG64 Token) { UNREFERENCED_PARAMETER(StartPort); UNREFERENCED_PARAMETER(NumberOfPorts); UNREFERENCED_PARAMETER(Token); return ex_StubNotSupported(); }
DWORD WINAPI ex_LookupPersistentUdpPortReservation(USHORT StartPort, USHORT NumberOfPorts, PULONG64 Token) { UNREFERENCED_PARAMETER(StartPort); UNREFERENCED_PARAMETER(NumberOfPorts); UNREFERENCED_PARAMETER(Token); return ex_StubNotSupported(); }
VOID WINAPI ex_NTPTimeToNTFileTime(ULONG NtpTime, LPFILETIME NtFileTime) { UNREFERENCED_PARAMETER(NtpTime); UNREFERENCED_PARAMETER(NtFileTime); STUB_LOG; }
VOID WINAPI ex_NTTimeToNTPTime(const FILETIME* NtFileTime, PULONG NtpTime) { UNREFERENCED_PARAMETER(NtFileTime); UNREFERENCED_PARAMETER(NtpTime); STUB_LOG; }
DWORD WINAPI ex_NhGetGuidFromInterfaceName(PCWSTR ifName, GUID* pGuid) { UNREFERENCED_PARAMETER(ifName); UNREFERENCED_PARAMETER(pGuid); return ex_StubNotSupported(); }
DWORD WINAPI ex_NhGetInterfaceDescriptionFromGuid(GUID* pGuid, PWCHAR pifDescr, LPDWORD pdwSize) { UNREFERENCED_PARAMETER(pGuid); UNREFERENCED_PARAMETER(pifDescr); UNREFERENCED_PARAMETER(pdwSize); return ex_StubNotSupported(); }
DWORD WINAPI ex_NhGetInterfaceNameFromDeviceGuid(GUID* pDeviceGuid, PWCHAR pifName, LPDWORD pdwSize, BOOL bFlag) { UNREFERENCED_PARAMETER(pDeviceGuid); UNREFERENCED_PARAMETER(pifName); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bFlag); return ex_StubNotSupported(); }
DWORD WINAPI ex_NhGetInterfaceNameFromGuid(GUID* pGuid, PWCHAR pifName, LPDWORD pdwSize, BOOL bFlag) { UNREFERENCED_PARAMETER(pGuid); UNREFERENCED_PARAMETER(pifName); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bFlag); return ex_StubNotSupported(); }
DWORD WINAPI ex_NhpAllocateAndGetInterfaceInfoFromStack(PIP_INTERFACE_INFO* ppTable, PDWORD pdwCount, BOOL bOrder, HANDLE hHeap, DWORD dwFlags) { UNREFERENCED_PARAMETER(ppTable); UNREFERENCED_PARAMETER(pdwCount); UNREFERENCED_PARAMETER(bOrder); UNREFERENCED_PARAMETER(hHeap); UNREFERENCED_PARAMETER(dwFlags); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyAddrChange(PHANDLE Handle, LPOVERLAPPED overlapped) { UNREFERENCED_PARAMETER(Handle); UNREFERENCED_PARAMETER(overlapped); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyCompartmentChange(HANDLE CompartmentHandle, PTIMERAPCROUTINE ApcRoutine, PVOID ApcContext, BOOL Persistent, PHANDLE NotificationHandle) { UNREFERENCED_PARAMETER(CompartmentHandle); UNREFERENCED_PARAMETER(ApcRoutine); UNREFERENCED_PARAMETER(ApcContext); UNREFERENCED_PARAMETER(Persistent); UNREFERENCED_PARAMETER(NotificationHandle); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyIfTimestampConfigChange(PVOID CallerContext, PINTERFACE_TIMESTAMP_CONFIG_CHANGE_CALLBACK Callback, PHANDLE NotificationHandle) { UNREFERENCED_PARAMETER(CallerContext); UNREFERENCED_PARAMETER(Callback); UNREFERENCED_PARAMETER(NotificationHandle); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyIpInterfaceChange(ADDRESS_FAMILY Family, PIPINTERFACE_CHANGE_CALLBACK Callback, PVOID CallerContext, BOOL InitialNotification, PHANDLE NotificationHandle) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Callback); UNREFERENCED_PARAMETER(CallerContext); UNREFERENCED_PARAMETER(InitialNotification); UNREFERENCED_PARAMETER(NotificationHandle); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyNetworkConnectivityHintChange(PNL_NETWORK_CONNECTIVITY_HINT_CHANGE_CALLBACK Callback, PVOID CallerContext, BOOL InitialNotification, PHANDLE NotificationHandle) { UNREFERENCED_PARAMETER(Callback); UNREFERENCED_PARAMETER(CallerContext); UNREFERENCED_PARAMETER(InitialNotification); UNREFERENCED_PARAMETER(NotificationHandle); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyRouteChange(PHANDLE Handle, LPOVERLAPPED overlapped) { UNREFERENCED_PARAMETER(Handle); UNREFERENCED_PARAMETER(overlapped); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyRouteChange2(ADDRESS_FAMILY AddressFamily, PIPFORWARD_CHANGE_CALLBACK Callback, PVOID CallerContext, BOOL InitialNotification, PHANDLE NotificationHandle) { UNREFERENCED_PARAMETER(AddressFamily); UNREFERENCED_PARAMETER(Callback); UNREFERENCED_PARAMETER(CallerContext); UNREFERENCED_PARAMETER(InitialNotification); UNREFERENCED_PARAMETER(NotificationHandle); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyStableUnicastIpAddressTable(ADDRESS_FAMILY Family, PULONG NumberOfAddresses, PMIB_UNICASTIPADDRESS_TABLE* Table) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(NumberOfAddresses); UNREFERENCED_PARAMETER(Table); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyTeredoPortChange(PTEREDO_PORT_CHANGE_CALLBACK Callback, PVOID CallerContext, BOOL InitialNotification, PHANDLE NotificationHandle) { UNREFERENCED_PARAMETER(Callback); UNREFERENCED_PARAMETER(CallerContext); UNREFERENCED_PARAMETER(InitialNotification); UNREFERENCED_PARAMETER(NotificationHandle); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyUnicastIpAddressChange(ADDRESS_FAMILY Family, PUNICAST_IPADDRESS_CHANGE_CALLBACK Callback, PVOID CallerContext, BOOL InitialNotification, PHANDLE NotificationHandle) { UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Callback); UNREFERENCED_PARAMETER(CallerContext); UNREFERENCED_PARAMETER(InitialNotification); UNREFERENCED_PARAMETER(NotificationHandle); return ex_StubNotSupported(); }
DWORD WINAPI ex_OpenCompartment(COMPARTMENT_ID CompartmentId, PHANDLE CompartmentHandle) { UNREFERENCED_PARAMETER(CompartmentId); UNREFERENCED_PARAMETER(CompartmentHandle); return ex_StubNotSupported(); }
DWORD WINAPI ex_ParseNetworkString(const WCHAR* NetworkString, DWORD Types, PNET_ADDRESS_INFO AddressInfo, USHORT* PortNumber, ULONG* PrefixLength) { UNREFERENCED_PARAMETER(NetworkString); UNREFERENCED_PARAMETER(Types); UNREFERENCED_PARAMETER(AddressInfo); UNREFERENCED_PARAMETER(PortNumber); UNREFERENCED_PARAMETER(PrefixLength); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfAddFiltersToInterface(HANDLE hInterface, ULONG cInFilters, PFILTER_DESCRIPTOR pfiltIn, ULONG cOutFilters, PFILTER_DESCRIPTOR pfiltOut, PFHANDLE pfih) { UNREFERENCED_PARAMETER(hInterface); UNREFERENCED_PARAMETER(cInFilters); UNREFERENCED_PARAMETER(pfiltIn); UNREFERENCED_PARAMETER(cOutFilters); UNREFERENCED_PARAMETER(pfiltOut); UNREFERENCED_PARAMETER(pfih); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfAddGlobalFilterToInterface(HANDLE pInterface, GLOBAL_FILTER gf) { UNREFERENCED_PARAMETER(pInterface); UNREFERENCED_PARAMETER(gf); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfBindInterfaceToIPAddress(HANDLE hInterface, PFFORWARD_ACTION pfatAction, ULONG pIPAddr) { UNREFERENCED_PARAMETER(hInterface); UNREFERENCED_PARAMETER(pfatAction); UNREFERENCED_PARAMETER(pIPAddr); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfBindInterfaceToIndex(HANDLE hInterface, DWORD dwIndex, PFFORWARD_ACTION pfatLink, PFFORWARD_ACTION pfatUnLink) { UNREFERENCED_PARAMETER(hInterface); UNREFERENCED_PARAMETER(dwIndex); UNREFERENCED_PARAMETER(pfatLink); UNREFERENCED_PARAMETER(pfatUnLink); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfCreateInterface(DWORD dwName, PFFORWARD_ACTION pfatAction, PVOID pfHandle) { UNREFERENCED_PARAMETER(dwName); UNREFERENCED_PARAMETER(pfatAction); UNREFERENCED_PARAMETER(pfHandle); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfDeleteInterface(HANDLE hInterface) { UNREFERENCED_PARAMETER(hInterface); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfDeleteLog() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfGetInterfaceStatistics(HANDLE hInterface, PFP_INTERFACE_STATS pIfStats, PBOOL pfHandle) { UNREFERENCED_PARAMETER(hInterface); UNREFERENCED_PARAMETER(pIfStats); UNREFERENCED_PARAMETER(pfHandle); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfMakeLog(HANDLE hEvent) { UNREFERENCED_PARAMETER(hEvent); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfRebindFilters(HANDLE hInterface, ULONG cInFilters, PFILTER_DESCRIPTOR pfiltIn, ULONG cOutFilters, PFILTER_DESCRIPTOR pfiltOut) { UNREFERENCED_PARAMETER(hInterface); UNREFERENCED_PARAMETER(cInFilters); UNREFERENCED_PARAMETER(pfiltIn); UNREFERENCED_PARAMETER(cOutFilters); UNREFERENCED_PARAMETER(pfiltOut); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfRemoveFilterHandles(HANDLE hInterface, ULONG cFilters, PFHANDLE pfh) { UNREFERENCED_PARAMETER(hInterface); UNREFERENCED_PARAMETER(cFilters); UNREFERENCED_PARAMETER(pfh); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfRemoveFiltersFromInterface(HANDLE hInterface, ULONG cInFilters, PFILTER_DESCRIPTOR pfiltIn, ULONG cOutFilters, PFILTER_DESCRIPTOR pfiltOut) { UNREFERENCED_PARAMETER(hInterface); UNREFERENCED_PARAMETER(cInFilters); UNREFERENCED_PARAMETER(pfiltIn); UNREFERENCED_PARAMETER(cOutFilters); UNREFERENCED_PARAMETER(pfiltOut); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfRemoveGlobalFilterFromInterface(HANDLE pInterface, GLOBAL_FILTER gf) { UNREFERENCED_PARAMETER(pInterface); UNREFERENCED_PARAMETER(gf); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfSetLogBuffer(PCHAR pbBuffer, DWORD dwSize, ULONG ulNumEntries, ULONG ulFlags, HANDLE* phLog) { UNREFERENCED_PARAMETER(pbBuffer); UNREFERENCED_PARAMETER(dwSize); UNREFERENCED_PARAMETER(ulNumEntries); UNREFERENCED_PARAMETER(ulFlags); UNREFERENCED_PARAMETER(phLog); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfTestPacket(HANDLE hInInterface, HANDLE hOutInterface, ULONG cBytes, PBYTE pbPacket) { UNREFERENCED_PARAMETER(hInInterface); UNREFERENCED_PARAMETER(hOutInterface); UNREFERENCED_PARAMETER(cBytes); UNREFERENCED_PARAMETER(pbPacket); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfUnBindInterface(HANDLE hInterface) { UNREFERENCED_PARAMETER(hInterface); return ex_StubNotSupported(); }
DWORD WINAPI ex_RegisterInterfaceTimestampConfigChange(PVOID CallerContext, PINTERFACE_TIMESTAMP_CONFIG_CHANGE_CALLBACK Callback, PHANDLE NotificationHandle) { UNREFERENCED_PARAMETER(CallerContext); UNREFERENCED_PARAMETER(Callback); UNREFERENCED_PARAMETER(NotificationHandle); return ex_StubNotSupported(); }
DWORD WINAPI ex_ResolveIpNetEntry2(MIB_IPNET_ROW2* Row, const SOCKADDR_INET* SourceAddress) { UNREFERENCED_PARAMETER(Row); UNREFERENCED_PARAMETER(SourceAddress); return ex_StubNotSupported(); }
DWORD WINAPI ex_ResolveNeighbor(const SOCKADDR* NetworkAddress, PVOID PhysicalAddress, PULONG PhysicalAddressLength) { UNREFERENCED_PARAMETER(NetworkAddress); UNREFERENCED_PARAMETER(PhysicalAddress); UNREFERENCED_PARAMETER(PhysicalAddressLength); return ex_StubNotSupported(); }
DWORD WINAPI ex_RestoreMediaSense(HANDLE* pHandle, LPOVERLAPPED pOverlapped) { UNREFERENCED_PARAMETER(pHandle); UNREFERENCED_PARAMETER(pOverlapped); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetAdapterIpAddress(const CHAR* AdapterName, BOOL EnableDHCP, ULONG IpAddress, ULONG SubnetMask, ULONG Gateway) { UNREFERENCED_PARAMETER(AdapterName); UNREFERENCED_PARAMETER(EnableDHCP); UNREFERENCED_PARAMETER(IpAddress); UNREFERENCED_PARAMETER(SubnetMask); UNREFERENCED_PARAMETER(Gateway); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetCurrentThreadCompartmentId(COMPARTMENT_ID CompartmentId) { UNREFERENCED_PARAMETER(CompartmentId); return ex_StubNotSupported(); }
VOID WINAPI ex_SetCurrentThreadCompartmentScope(COMPARTMENT_ID CompartmentId, COMPARTMENT_ID CompartmentScope) { UNREFERENCED_PARAMETER(CompartmentId); UNREFERENCED_PARAMETER(CompartmentScope); STUB_LOG; }
DWORD WINAPI ex_SetDnsSettings(const PDNS_SETTINGS Settings) { UNREFERENCED_PARAMETER(Settings); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetFlVirtualInterface(const NET_LUID* InterfaceLuid, const PMIB_FL_VIRTUAL_INTERFACE VirtualInterface) { UNREFERENCED_PARAMETER(InterfaceLuid); UNREFERENCED_PARAMETER(VirtualInterface); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetInterfaceDnsSettings(GUID Interface, const PDNS_INTERFACE_SETTINGS Settings) { UNREFERENCED_PARAMETER(Interface); UNREFERENCED_PARAMETER(Settings); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpForwardEntry(PMIB_IPFORWARDROW pRoute) { UNREFERENCED_PARAMETER(pRoute); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpForwardEntry2(const MIB_IPFORWARD_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpInterfaceEntry(MIB_IPINTERFACE_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpNetEntry(PMIB_IPNETROW pArpEntry) { UNREFERENCED_PARAMETER(pArpEntry); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpNetEntry2(const MIB_IPNET_ROW2* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpStatistics(PMIB_IPSTATS pIpStats) { UNREFERENCED_PARAMETER(pIpStats); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpStatisticsEx(PMIB_IPSTATS pIpStats, DWORD dwFamily) { UNREFERENCED_PARAMETER(pIpStats); UNREFERENCED_PARAMETER(dwFamily); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpTTL(UINT nTtl) { UNREFERENCED_PARAMETER(nTtl); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetJobCompartmentId(HANDLE JobHandle, COMPARTMENT_ID CompartmentId) { UNREFERENCED_PARAMETER(JobHandle); UNREFERENCED_PARAMETER(CompartmentId); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetNetworkInformation(const GUID* NetworkGuid, BOOL IsNetworkMetered) { UNREFERENCED_PARAMETER(NetworkGuid); UNREFERENCED_PARAMETER(IsNetworkMetered); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetPerTcp6ConnectionEStats(const MIB_TCP6ROW* Row, TCP_ESTATS_TYPE EstatsType, PUCHAR Rw, ULONG RwVersion, ULONG RwSize, ULONG Offset) { UNREFERENCED_PARAMETER(Row); UNREFERENCED_PARAMETER(EstatsType); UNREFERENCED_PARAMETER(Rw); UNREFERENCED_PARAMETER(RwVersion); UNREFERENCED_PARAMETER(RwSize); UNREFERENCED_PARAMETER(Offset); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetPerTcp6ConnectionStats(const MIB_TCP6ROW* Row, PMIB_TCPSTATS pStats) { UNREFERENCED_PARAMETER(Row); UNREFERENCED_PARAMETER(pStats); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetPerTcpConnectionEStats(PMIB_TCPROW pRow, TCP_ESTATS_TYPE EstatsType, PUCHAR Rw, ULONG RwVersion, ULONG RwSize, ULONG Offset) { UNREFERENCED_PARAMETER(pRow); UNREFERENCED_PARAMETER(EstatsType); UNREFERENCED_PARAMETER(Rw); UNREFERENCED_PARAMETER(RwVersion); UNREFERENCED_PARAMETER(RwSize); UNREFERENCED_PARAMETER(Offset); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetPerTcpConnectionStats(PMIB_TCPROW pRow, PMIB_TCPSTATS pStats) { UNREFERENCED_PARAMETER(pRow); UNREFERENCED_PARAMETER(pStats); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetSessionCompartmentId(ULONG SessionId, COMPARTMENT_ID CompartmentId) { UNREFERENCED_PARAMETER(SessionId); UNREFERENCED_PARAMETER(CompartmentId); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetTcpEntry(PMIB_TCPROW pTcpRow) { UNREFERENCED_PARAMETER(pTcpRow); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW* Row) { UNREFERENCED_PARAMETER(Row); return ex_StubNotSupported(); }
DWORD WINAPI ex_UnenableRouter(LPOVERLAPPED pOverlapped, LPDWORD lpdwEnableCount) { UNREFERENCED_PARAMETER(pOverlapped); UNREFERENCED_PARAMETER(lpdwEnableCount); return ex_StubNotSupported(); }
VOID WINAPI ex_UnregisterInterfaceTimestampConfigChange(HANDLE NotificationHandle) { UNREFERENCED_PARAMETER(NotificationHandle); STUB_LOG; }
DWORD WINAPI ex_do_echo_rep() { return ex_StubNotSupported(); }
DWORD WINAPI ex_do_echo_req() { return ex_StubNotSupported(); }
PWCHAR WINAPI ex_if_indextoname(NET_IFINDEX InterfaceIndex, PWCHAR InterfaceName) { UNREFERENCED_PARAMETER(InterfaceIndex); UNREFERENCED_PARAMETER(InterfaceName); STUB_LOG; return NULL; }
NET_IFINDEX WINAPI ex_if_nametoindex(PCWSTR InterfaceName) { UNREFERENCED_PARAMETER(InterfaceName); STUB_LOG; return 0; }
HANDLE WINAPI ex_register_icmp(FARPROC pIcmpCallback, PVOID pCallbackContext) { UNREFERENCED_PARAMETER(pIcmpCallback); UNREFERENCED_PARAMETER(pCallbackContext); STUB_LOG; return INVALID_HANDLE_VALUE; }
DWORD WINAPI ex_GetExtendedTcpTable(PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, TCP_TABLE_CLASS TableClass, ULONG Reserved) { UNREFERENCED_PARAMETER(pTcpTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); UNREFERENCED_PARAMETER(ulAf); UNREFERENCED_PARAMETER(TableClass); UNREFERENCED_PARAMETER(Reserved); return ex_StubNoData(); }
DWORD WINAPI ex_GetExtendedUdpTable(PVOID pUdpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, UDP_TABLE_CLASS TableClass, ULONG Reserved) { UNREFERENCED_PARAMETER(pUdpTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); UNREFERENCED_PARAMETER(ulAf); UNREFERENCED_PARAMETER(TableClass); UNREFERENCED_PARAMETER(Reserved); return ex_StubNoData(); }
DWORD WINAPI ex_GetIpNetTable(PMIB_IPNETTABLE pIpNetTable, PULONG pdwSize, BOOL bOrder) { UNREFERENCED_PARAMETER(pIpNetTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); return ex_StubNoData(); }
DWORD WINAPI ex_GetTcp6Table(PMIB_TCP6TABLE pTcpTable, PULONG pdwSize, BOOL bOrder) { UNREFERENCED_PARAMETER(pTcpTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); return ex_StubNoData(); }
DWORD WINAPI ex_GetTcpStatistics(PMIB_TCPSTATS pStats) { UNREFERENCED_PARAMETER(pStats); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcpStatisticsEx(PMIB_TCPSTATS pStats, DWORD dwFamily) { UNREFERENCED_PARAMETER(pStats); UNREFERENCED_PARAMETER(dwFamily); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcpTable(PMIB_TCPTABLE pTcpTable, PULONG pdwSize, BOOL bOrder) { UNREFERENCED_PARAMETER(pTcpTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); return ex_StubNoData(); }
DWORD WINAPI ex_GetUdpStatistics(PMIB_UDPSTATS pStats) { UNREFERENCED_PARAMETER(pStats); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUdpStatisticsEx(PMIB_UDPSTATS pStats, DWORD dwFamily) { UNREFERENCED_PARAMETER(pStats); UNREFERENCED_PARAMETER(dwFamily); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUdp6Table(PMIB_UDP6TABLE pUdp6Table, PULONG pdwSize, BOOL bOrder) { UNREFERENCED_PARAMETER(pUdp6Table); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); return ex_StubNoData(); }
DWORD WINAPI ex_GetUdpTable(PMIB_UDPTABLE pUdpTable, PULONG pdwSize, BOOL bOrder) { UNREFERENCED_PARAMETER(pUdpTable); UNREFERENCED_PARAMETER(pdwSize); UNREFERENCED_PARAMETER(bOrder); return ex_StubNoData(); }
BOOL WINAPI ex_InternetSetSecureLegacyServersAppCompat() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }

// ============================================================================
// === DLLMAIN ===
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule); UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
#if ENABLE_FILE_LOGGING
        InitializeCriticalSection(&g_log_lock);
#endif
#if ENABLE_MEMORY_TRACKING
        InitializeCriticalSection(&g_memory_lock);
#endif
        g_locks_initialized = TRUE;
#if ENABLE_DEBUG_CONSOLE
        if (AllocConsole()) {
            g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTitleA("IPHLPAPI Emulator Debug Console v1.0.2");
        }
#endif
#if ENABLE_FILE_LOGGING
        {
            char log_path[MAX_PATH]; char exe_path[MAX_PATH]; GetModuleFileNameA(NULL, exe_path, MAX_PATH);
            char* last_slash = strrchr(exe_path, '\\'); if (last_slash) *(last_slash + 1) = '\0';
            snprintf(log_path, MAX_PATH, "%siphlpapi.log", exe_path);
            fopen_s(&g_log_file, log_path, "a");
        }
#endif
        InitializeHardcodedConfig();
        LogInfo("=== IPHLPAPI EMULATOR v1.0.2 LOADED ==="); LogInfo("Build: %s %s", __DATE__, __TIME__);
        break;
    case DLL_PROCESS_DETACH:
        LogInfo("=== IPHLPAPI EMULATOR v1.0.2 UNLOADING ===");
        if (g_locks_initialized) {
#if ENABLE_MEMORY_TRACKING
            ReportMemoryLeaks();
#endif
#if ENABLE_FILE_LOGGING
            if (g_log_file) { LogInfo("Closing log file."); fclose(g_log_file); g_log_file = NULL; }
            DeleteCriticalSection(&g_log_lock);
#endif
#if ENABLE_MEMORY_TRACKING
            DeleteCriticalSection(&g_memory_lock);
#endif
            g_locks_initialized = FALSE;
        }
#if ENABLE_DEBUG_CONSOLE
        if(g_hConsole) { LogInfo("Unloading complete."); FreeConsole(); }
#endif
        break;
    }
    return TRUE;
}

#ifdef __cplusplus
}
#endif