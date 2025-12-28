#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <combaseapi.h>

#pragma comment(lib, "exws2.lib")
#pragma comment(lib, "ole32.lib")

#ifndef _NETIOAPI_H_
typedef enum _MIB_IF_TABLE_LEVEL { MibIfTableNormal, MibIfTableRaw } MIB_IF_TABLE_LEVEL, *PMIB_IF_TABLE_LEVEL;
#endif

typedef PVOID PINTERFACE_HARDWARE_CROSSTIMESTAMP, PDNS_SETTINGS, PDNS_INTERFACE_SETTINGS, PMIB_FL_VIRTUAL_INTERFACE;
typedef PVOID PMIB_FL_VIRTUAL_INTERFACE_TABLE, PINTERFACE_TIMESTAMP_CAPABILITIES, PNET_IF_CONNECTION_BANDWIDTH_ESTIMATES;
typedef PVOID PNL_NETWORK_CONNECTIVITY_HINT, PINTERFACE_TIMESTAMP_CONFIG_CHANGE_CALLBACK, PNL_NETWORK_CONNECTIVITY_HINT_CHANGE_CALLBACK;
typedef PVOID PFILTER_DESCRIPTOR, PFHANDLE, GLOBAL_FILTER, PFFORWARD_ACTION, PFP_INTERFACE_STATS, PNET_ADDRESS_INFO;
typedef PVOID PRTC_SLOT_INFORMATION_TABLE, PMIB_TUNNEL_PHYSICAL_ADAPTER, PMIB_IP_PHYSICAL_INTERFACE_ROW, PMIB_TCPSTATS2, PMIB_UDPSTATS2;

#ifdef __cplusplus
extern "C" {
#endif

#define ENABLE_DEBUG_CONSOLE 1
#define ENABLE_FILE_LOGGING  1

#define MAX_ADAPTERS 8
#define MAX_IPS_PER_ADAPTER 4
#define MAX_DNS_PER_ADAPTER 4
#define MAX_ARP_ENTRIES 16

typedef enum { LOG_LEVEL_ERROR = 0, LOG_LEVEL_WARNING, LOG_LEVEL_INFO, LOG_LEVEL_DEBUG } LogLevel;
typedef struct { char ipAddress[46]; ADDRESS_FAMILY family; union { struct { ULONG dwAddr; ULONG dwMask; } v4; struct { IN6_ADDR dwAddr; ULONG prefixLength; } v6; } addr; ULONG NTEContext; } FakeIpAddress;
typedef struct { char name[MAX_ADAPTER_NAME_LENGTH + 4]; GUID guid; char description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4]; DWORD type; DWORD index; DWORD dwAdminStatus; IF_OPER_STATUS operStatus; BYTE macAddress[MAX_ADAPTER_ADDRESS_LENGTH]; int ipCount; FakeIpAddress ipAddresses[MAX_IPS_PER_ADAPTER]; char gateway[40]; int dnsCount; char dnsAddresses[MAX_DNS_PER_ADAPTER][40]; char dnsSuffix[128]; } FakeAdapter;
typedef struct { ULONG dwAddr; BYTE macAddress[6]; } FakeArpEntry;
typedef struct { int adapterCount; FakeAdapter adapters[MAX_ADAPTERS]; int arpCacheCount; FakeArpEntry arpCache[MAX_ARP_ENTRIES]; ULONG nextNTEContext; } NetworkState;

#if ENABLE_DEBUG_CONSOLE
static HANDLE g_hConsole = NULL;
#endif
#if ENABLE_FILE_LOGGING
static FILE* g_log_file = NULL; 
static CRITICAL_SECTION g_log_lock;
#endif
static BOOL g_locks_initialized = FALSE;
static LogLevel g_current_log_level = LOG_LEVEL_DEBUG;
static NetworkState g_NetworkState = {0};
static volatile LONG g_init_count = 0;

void EnsureInitialized(void);
void InitializeHardcodedConfig(void);
DWORD WINAPI ex_StubNotSupported(void);
DWORD WINAPI ex_StubNoData(void);
DWORD WINAPI ex_StubSuccess(void); 

void GetTimestamp(char* buffer, size_t bufferSize) {
    if (!buffer || bufferSize < 20) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buffer, bufferSize, "[%02d:%02d:%02d.%03d]", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

const char* GetLogLevelString(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_WARNING: return "WARN ";
        case LOG_LEVEL_INFO: return "INFO ";
        case LOG_LEVEL_DEBUG: return "DEBUG";
        default: return "?????";
    }
}

void LogMessageEx(LogLevel level, const char* function, const char* format, ...) {
    if (level > g_current_log_level || g_init_count == 0) return;

    char final_buffer[2048];
    va_list args;
    va_start(args, format);
    char user_buffer[1024];
    vsnprintf(user_buffer, sizeof(user_buffer), format, args);
    va_end(args);

    char timestamp[20] = { 0 };
    GetTimestamp(timestamp, sizeof(timestamp));

    char process_path[MAX_PATH] = { 0 };
    char* process_name = "UNKNOWN";
    if (GetModuleFileNameA(NULL, process_path, MAX_PATH) > 0) {
        char* last_slash = strrchr(process_path, '\\');
        process_name = last_slash ? last_slash + 1 : process_path;
    }

    snprintf(final_buffer, sizeof(final_buffer), "[IPHLPAPI] %s [%s] [%s] [%s] %s\n", timestamp, GetLogLevelString(level), process_name, function, user_buffer);

    #if ENABLE_FILE_LOGGING
    if (g_log_file && g_locks_initialized) {
        EnterCriticalSection(&g_log_lock);
        fputs(final_buffer, g_log_file);
        fflush(g_log_file);
        LeaveCriticalSection(&g_log_lock);
    }
    #endif

    #if ENABLE_DEBUG_CONSOLE
    if(g_hConsole) {
        DWORD written;
        WriteConsoleA(g_hConsole, final_buffer, (DWORD)strlen(final_buffer), &written, NULL);
    }
    #endif
}

#define LogError(fmt, ...)   LogMessageEx(LOG_LEVEL_ERROR, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogWarning(fmt, ...) LogMessageEx(LOG_LEVEL_WARNING, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogInfo(fmt, ...)    LogMessageEx(LOG_LEVEL_INFO, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogDebug(fmt, ...)   LogMessageEx(LOG_LEVEL_DEBUG, __FUNCTION__, fmt, ##__VA_ARGS__)
#undef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)

void EnsureInitialized() {
    if (InterlockedCompareExchange(&g_init_count, 1, 0) == 0) {
        #if ENABLE_FILE_LOGGING
        InitializeCriticalSection(&g_log_lock);
        #endif
        g_locks_initialized = TRUE;

        char process_path[MAX_PATH] = { 0 };
        char* process_name = "unknown.exe";
        if (GetModuleFileNameA(NULL, process_path, MAX_PATH) > 0) {
            char* last_slash = strrchr(process_path, '\\');
            process_name = last_slash ? last_slash + 1 : process_path;
        }

        #if ENABLE_DEBUG_CONSOLE
        AllocConsole();
        g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (g_hConsole != INVALID_HANDLE_VALUE) {
            SetConsoleTitleA("IPHLPAPI Emulator - DEBUG");
            const char* msg = "\n>> IPHLPAPI EMULATOR: INITIALIZED ON FIRST CALL <<\n\n";
            DWORD w;
            WriteConsoleA(g_hConsole, msg, (DWORD)strlen(msg), &w, NULL);
        }
        #endif

        #if ENABLE_FILE_LOGGING
        {
            char log_path[MAX_PATH] = {0};
            char temp_path[MAX_PATH] = {0};
            if (GetTempPathA(MAX_PATH, temp_path) > 0) {
                snprintf(log_path, MAX_PATH, "%siphlpapi-%s-%lu.log", temp_path, process_name, GetCurrentProcessId());
                errno_t err = fopen_s(&g_log_file, log_path, "w");
                if (err == 0 && g_log_file) {
                    fprintf(g_log_file, "\n========== IPHLPAPI EMULATOR INITIALIZED ==========\n");
                    fprintf(g_log_file, "Process: %s (PID: %lu)\nLog Path: %s\nBuild: %s %s\n", process_name, GetCurrentProcessId(), log_path, __DATE__, __TIME__);
                    fprintf(g_log_file, "===================================================\n\n");
                    fflush(g_log_file);
                }
            }
        }
        #endif
        
        InitializeHardcodedConfig();
        LogInfo("=== IPHLPAPI EMULATOR INITIALIZED (LAZY) ==="); 
    }
}

void ParseMacAddress(const char* macStr, BYTE* target) { sscanf_s(macStr, "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx", &target[0], &target[1], &target[2], &target[3], &target[4], &target[5]); }
FakeAdapter* FindAdapterByIndex(DWORD index) { for (int i = 0; i < g_NetworkState.adapterCount; ++i) { if (g_NetworkState.adapters[i].index == index) return &g_NetworkState.adapters[i]; } return NULL; }
void InitializeHardcodedConfig() { LogInfo("Initializing hardcoded network configuration..."); memset(&g_NetworkState, 0, sizeof(g_NetworkState)); g_NetworkState.nextNTEContext = 1000; LogInfo("  Creating Adapter 1: Realtek Gaming GbE"); FakeAdapter* adapter1 = &g_NetworkState.adapters[g_NetworkState.adapterCount++]; strcpy_s(adapter1->name, sizeof(adapter1->name), "{A1B2C3D4-E5F6-1234-5678-ABCDEF123456}"); CLSIDFromString(L"{A1B2C3D4-E5F6-1234-5678-ABCDEF123456}", &adapter1->guid); strcpy_s(adapter1->description, sizeof(adapter1->description), "Realtek Gaming GbE Family Controller"); adapter1->type = IF_TYPE_ETHERNET_CSMACD; adapter1->index = 1; adapter1->dwAdminStatus = MIB_IF_ADMIN_STATUS_UP; adapter1->operStatus = IfOperStatusUp; ParseMacAddress("00-1A-2B-3C-4D-5E", adapter1->macAddress); strcpy_s(adapter1->dnsSuffix, sizeof(adapter1->dnsSuffix), "workgroup"); LogInfo("    - Index: %lu, Type: %lu, Status: UP", adapter1->index, adapter1->type); LogInfo("    - MAC: %02X-%02X-%02X-%02X-%02X-%02X", adapter1->macAddress[0], adapter1->macAddress[1], adapter1->macAddress[2], adapter1->macAddress[3], adapter1->macAddress[4], adapter1->macAddress[5]); FakeIpAddress* ip4 = &adapter1->ipAddresses[adapter1->ipCount++]; ip4->family = AF_INET; strcpy_s(ip4->ipAddress, sizeof(ip4->ipAddress), "192.168.1.100"); inet_pton(AF_INET, ip4->ipAddress, &ip4->addr.v4.dwAddr); ip4->NTEContext = g_NetworkState.nextNTEContext++; LogInfo("    - Added IPv4: %s", ip4->ipAddress); FakeIpAddress* ip6 = &adapter1->ipAddresses[adapter1->ipCount++]; ip6->family = AF_INET6; sprintf_s(ip6->ipAddress, sizeof(ip6->ipAddress), "fe80::%02x%02x:%02xff:fe%02x:%02x%02x", adapter1->macAddress[0] ^ 0x02, adapter1->macAddress[1], adapter1->macAddress[2], adapter1->macAddress[3], adapter1->macAddress[4], adapter1->macAddress[5]); inet_pton(AF_INET6, ip6->ipAddress, &ip6->addr.v6.dwAddr); ip6->NTEContext = g_NetworkState.nextNTEContext++; LogInfo("    - Added IPv6 (Link-Local): %s", ip6->ipAddress); strcpy_s(adapter1->gateway, sizeof(adapter1->gateway), "192.168.1.1"); strcpy_s(adapter1->dnsAddresses[adapter1->dnsCount++], sizeof(adapter1->dnsAddresses[0]), "192.168.1.1"); strcpy_s(adapter1->dnsAddresses[adapter1->dnsCount++], sizeof(adapter1->dnsAddresses[0]), "8.8.8.8"); LogInfo("    - Gateway: %s", adapter1->gateway); LogInfo("    - DNS: %s, %s", adapter1->dnsAddresses[0], adapter1->dnsAddresses[1]); LogInfo("Hardcoded configuration initialized successfully."); }

#define STUB_SUCCESS_DWORD(val)       { EnsureInitialized(); LogInfo("CALLED (STUB): %s", __FUNCTION__); SetLastError(NO_ERROR); return (val); }
#define STUB_FAIL_DWORD(val, err)     { EnsureInitialized(); LogInfo("CALLED (STUB): %s", __FUNCTION__); SetLastError(err); return (val); }
#define STUB_FAIL_BOOL(err)           { EnsureInitialized(); LogInfo("CALLED (STUB): %s", __FUNCTION__); SetLastError(err); return FALSE; }
#define STUB_VOID()                   { EnsureInitialized(); LogInfo("CALLED (STUB): %s", __FUNCTION__); return; }
#define STUB_RETURN_NULL()            { EnsureInitialized(); LogInfo("CALLED (STUB): %s", __FUNCTION__); SetLastError(ERROR_NOT_SUPPORTED); return NULL; }
#define STUB_RETURN_ZERO()            { EnsureInitialized(); LogInfo("CALLED (STUB): %s", __FUNCTION__); return 0; }
#define STUB_RETURN_INVALID_HANDLE()  { EnsureInitialized(); LogInfo("CALLED (STUB): %s", __FUNCTION__); return INVALID_HANDLE_VALUE; }

DWORD WINAPI ex_StubNotSupported() { STUB_FAIL_DWORD(ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_StubNoData() { STUB_FAIL_DWORD(ERROR_NO_DATA, ERROR_NO_DATA); }
DWORD WINAPI ex_StubSuccess() { STUB_SUCCESS_DWORD(NO_ERROR); }

ULONG WINAPI ex_GetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen) { EnsureInitialized(); LogInfo(">> GetAdaptersInfo called"); if (!pOutBufLen) { LogError("   -> pOutBufLen is NULL, returning ERROR_INVALID_PARAMETER"); return ERROR_INVALID_PARAMETER; } ULONG requiredSize = 0; if (g_NetworkState.adapterCount > 0) { requiredSize = sizeof(IP_ADAPTER_INFO) * g_NetworkState.adapterCount; } else { requiredSize = sizeof(IP_ADAPTER_INFO); } LogInfo("   Buffer Info: Required=%lu, Provided=%lu", requiredSize, pAdapterInfo ? *pOutBufLen : 0); if (!pAdapterInfo || *pOutBufLen < requiredSize) { *pOutBufLen = requiredSize; LogWarning("   -> Buffer too small or NULL. Required: %lu. Returning ERROR_BUFFER_OVERFLOW.", requiredSize); return ERROR_BUFFER_OVERFLOW; } LogInfo("   -> Buffer is sufficient. Filling data for %d adapters.", g_NetworkState.adapterCount); memset(pAdapterInfo, 0, *pOutBufLen); if (g_NetworkState.adapterCount == 0) { LogInfo("   -> No adapters to report. Buffer is cleared. Returning NO_ERROR."); return NO_ERROR; } PIP_ADAPTER_INFO pCurrent = pAdapterInfo; for (int i = 0; i < g_NetworkState.adapterCount; ++i) { const FakeAdapter* fake = &g_NetworkState.adapters[i]; LogInfo("   [Adapter %d] Populating '%s'", i, fake->description); strcpy_s(pCurrent->AdapterName, sizeof(pCurrent->AdapterName), fake->name); strcpy_s(pCurrent->Description, sizeof(pCurrent->Description), fake->description); pCurrent->AddressLength = 6; memcpy(pCurrent->Address, fake->macAddress, 6); pCurrent->Index = fake->index; pCurrent->Type = fake->type; pCurrent->DhcpEnabled = TRUE; pCurrent->HaveWins = FALSE; for (int j = 0; j < fake->ipCount; j++) { if (fake->ipAddresses[j].family == AF_INET) { LogInfo("     - IP: %s", fake->ipAddresses[j].ipAddress); strcpy_s(pCurrent->IpAddressList.IpAddress.String, sizeof(pCurrent->IpAddressList.IpAddress.String), fake->ipAddresses[j].ipAddress); strcpy_s(pCurrent->IpAddressList.IpMask.String, sizeof(pCurrent->IpAddressList.IpMask.String), "255.255.255.0"); pCurrent->IpAddressList.Context = fake->ipAddresses[j].NTEContext; break; } } if (strlen(fake->gateway) > 0) { LogInfo("     - Gateway: %s", fake->gateway); strcpy_s(pCurrent->GatewayList.IpAddress.String, sizeof(pCurrent->GatewayList.IpAddress.String), fake->gateway); } if (i < g_NetworkState.adapterCount - 1) { pCurrent->Next = (IP_ADAPTER_INFO*)((BYTE*)pCurrent + sizeof(IP_ADAPTER_INFO)); pCurrent = pCurrent->Next; } else { pCurrent->Next = NULL; } } LogInfo("   -> SUCCESS. Data written to buffer. Returning NO_ERROR."); return NO_ERROR; }
DWORD WINAPI ex_GetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES pAdapterAddresses, PULONG pOutBufLen) { EnsureInitialized(); LogInfo(">> GetAdaptersAddresses(Family: %lu, Flags: %lu)", Family, Flags); UNREFERENCED_PARAMETER(Reserved); UNREFERENCED_PARAMETER(Flags); if (!pOutBufLen) { LogError("   -> pOutBufLen is NULL"); return ERROR_INVALID_PARAMETER; } ULONG requiredSize = 0; for (int i = 0; i < g_NetworkState.adapterCount; i++) { const FakeAdapter* fake = &g_NetworkState.adapters[i]; requiredSize += sizeof(IP_ADAPTER_ADDRESSES); requiredSize += (strlen(fake->description) + 1) * sizeof(WCHAR); requiredSize += (strlen(fake->dnsSuffix) + 1) * sizeof(WCHAR); for(int j = 0; j < fake->ipCount; ++j) { if(fake->ipAddresses[j].family == Family || Family == AF_UNSPEC) { requiredSize += sizeof(IP_ADAPTER_UNICAST_ADDRESS_LH); if(fake->ipAddresses[j].family == AF_INET) requiredSize += sizeof(struct sockaddr_in); else requiredSize += sizeof(struct sockaddr_in6); } } for (int j = 0; j < fake->dnsCount; ++j) { requiredSize += sizeof(IP_ADAPTER_DNS_SERVER_ADDRESS_XP) + sizeof(struct sockaddr_in); } if (strlen(fake->gateway) > 0) { requiredSize += sizeof(IP_ADAPTER_GATEWAY_ADDRESS_LH) + sizeof(struct sockaddr_in); } } LogInfo("   Buffer Info: Required (dynamic)=%lu, Provided=%lu", requiredSize, pAdapterAddresses ? *pOutBufLen : 0); if (g_NetworkState.adapterCount == 0) { *pOutBufLen = 0; LogInfo("   -> No adapters to report, returning NO_ERROR."); return NO_ERROR; } if (!pAdapterAddresses || *pOutBufLen < requiredSize) { *pOutBufLen = requiredSize; LogWarning("   -> Buffer too small or NULL. Required: %lu. Returning ERROR_BUFFER_OVERFLOW.", requiredSize); return ERROR_BUFFER_OVERFLOW; } LogInfo("   -> Buffer is sufficient. Filling data for %d adapters.", g_NetworkState.adapterCount); memset(pAdapterAddresses, 0, *pOutBufLen); char* pCurrentData = (char*)pAdapterAddresses + (g_NetworkState.adapterCount * sizeof(IP_ADAPTER_ADDRESSES)); for (int i = 0; i < g_NetworkState.adapterCount; i++) { const FakeAdapter* fake = &g_NetworkState.adapters[i]; PIP_ADAPTER_ADDRESSES pCurrent = &pAdapterAddresses[i]; LogInfo("   [Adapter %d] Populating '%s'", i, fake->description); if (i < g_NetworkState.adapterCount - 1) pCurrent->Next = &pAdapterAddresses[i+1]; pCurrent->Length = sizeof(IP_ADAPTER_ADDRESSES); pCurrent->IfIndex = fake->index; pCurrent->PhysicalAddressLength = 6; memcpy(pCurrent->PhysicalAddress, fake->macAddress, 6); pCurrent->IfType = fake->type; pCurrent->OperStatus = fake->operStatus; pCurrent->FriendlyName = (PWCHAR)pCurrentData; mbstowcs(pCurrent->FriendlyName, fake->description, strlen(fake->description) + 1); pCurrentData += (strlen(fake->description) + 1) * sizeof(WCHAR); pCurrent->DnsSuffix = (PWCHAR)pCurrentData; mbstowcs(pCurrent->DnsSuffix, fake->dnsSuffix, strlen(fake->dnsSuffix) + 1); pCurrentData += (strlen(fake->dnsSuffix) + 1) * sizeof(WCHAR); PIP_ADAPTER_UNICAST_ADDRESS_LH pUnicast = NULL; for (int j = 0; j < fake->ipCount; j++) { const FakeIpAddress* ip = &fake->ipAddresses[j]; if (ip->family != Family && Family != AF_UNSPEC) continue; PIP_ADAPTER_UNICAST_ADDRESS_LH pNewUnicast = (PIP_ADAPTER_UNICAST_ADDRESS_LH)pCurrentData; pCurrentData += sizeof(IP_ADAPTER_UNICAST_ADDRESS_LH); if (pUnicast) pUnicast->Next = pNewUnicast; else pCurrent->FirstUnicastAddress = pNewUnicast; pUnicast = pNewUnicast; pUnicast->Address.lpSockaddr = (LPSOCKADDR)pCurrentData; if (ip->family == AF_INET) { LogInfo("     - Populating IPv4 Unicast Address: %s", ip->ipAddress); pUnicast->Address.iSockaddrLength = sizeof(struct sockaddr_in); struct sockaddr_in* sa = (struct sockaddr_in*)pUnicast->Address.lpSockaddr; sa->sin_family = AF_INET; sa->sin_addr.s_addr = ip->addr.v4.dwAddr; pCurrentData += sizeof(struct sockaddr_in); } else if (ip->family == AF_INET6) { LogInfo("     - Populating IPv6 Unicast Address: %s", ip->ipAddress); pUnicast->Address.iSockaddrLength = sizeof(struct sockaddr_in6); struct sockaddr_in6* sa6 = (struct sockaddr_in6*)pUnicast->Address.lpSockaddr; sa6->sin6_family = AF_INET6; sa6->sin6_addr = ip->addr.v6.dwAddr; sa6->sin6_scope_id = fake->index; pCurrentData += sizeof(struct sockaddr_in6); } } PIP_ADAPTER_DNS_SERVER_ADDRESS_XP pDns = NULL; for (int j = 0; j < fake->dnsCount; ++j) { LogInfo("     - Populating DNS Server: %s", fake->dnsAddresses[j]); PIP_ADAPTER_DNS_SERVER_ADDRESS_XP pNewDns = (PIP_ADAPTER_DNS_SERVER_ADDRESS_XP)pCurrentData; pCurrentData += sizeof(IP_ADAPTER_DNS_SERVER_ADDRESS_XP); if (pDns) pDns->Next = pNewDns; else pCurrent->FirstDnsServerAddress = pNewDns; pDns = pNewDns; pDns->Address.lpSockaddr = (LPSOCKADDR)pCurrentData; pDns->Address.iSockaddrLength = sizeof(struct sockaddr_in); struct sockaddr_in* sa = (struct sockaddr_in*)pDns->Address.lpSockaddr; sa->sin_family = AF_INET; inet_pton(AF_INET, fake->dnsAddresses[j], &sa->sin_addr); pCurrentData += sizeof(struct sockaddr_in); } if (strlen(fake->gateway) > 0) { LogInfo("     - Populating Gateway: %s", fake->gateway); PIP_ADAPTER_GATEWAY_ADDRESS_LH pGateway = (PIP_ADAPTER_GATEWAY_ADDRESS_LH)pCurrentData; pCurrent->FirstGatewayAddress = pGateway; pCurrentData += sizeof(IP_ADAPTER_GATEWAY_ADDRESS_LH); pGateway->Address.lpSockaddr = (LPSOCKADDR)pCurrentData; pGateway->Address.iSockaddrLength = sizeof(struct sockaddr_in); struct sockaddr_in* sa = (struct sockaddr_in*)pGateway->Address.lpSockaddr; sa->sin_family = AF_INET; inet_pton(AF_INET, fake->gateway, &sa->sin_addr); pCurrentData += sizeof(struct sockaddr_in); } } LogInfo("   -> SUCCESS. Data written to buffer."); return NO_ERROR; }
DWORD WINAPI ex_GetBestInterfaceEx(PSOCKADDR pDestAddr, PDWORD pdwBestIfIndex) { EnsureInitialized(); if (!pdwBestIfIndex || !pDestAddr) { LogError("GetBestInterfaceEx: Invalid parameters"); return ERROR_INVALID_PARAMETER; } char ip_str[INET6_ADDRSTRLEN] = {0}; if (pDestAddr->sa_family == AF_INET) { inet_ntop(AF_INET, &((struct sockaddr_in*)pDestAddr)->sin_addr, ip_str, sizeof(ip_str)); } LogInfo(">> GetBestInterfaceEx called for destination: %s", ip_str); for (int i = 0; i < g_NetworkState.adapterCount; ++i) { if (g_NetworkState.adapters[i].operStatus == IfOperStatusUp) { *pdwBestIfIndex = g_NetworkState.adapters[i].index; LogInfo("   -> Found best interface. Returning index: %lu", *pdwBestIfIndex); return NO_ERROR; } } LogWarning("   -> No active interfaces found. Returning ERROR_NOT_FOUND."); return ERROR_NOT_FOUND; }
DWORD WINAPI ex_CancelMibChangeNotify2(HANDLE NotificationHandle) { EnsureInitialized(); LogInfo(">> CancelMibChangeNotify2 called with Handle: %p", NotificationHandle); UNREFERENCED_PARAMETER(NotificationHandle); LogInfo("   -> Success (emulated)."); return NO_ERROR; }
DWORD WINAPI ex_NotifyIpInterfaceChange(ADDRESS_FAMILY Family, PIPINTERFACE_CHANGE_CALLBACK Callback, PVOID CallerContext, BOOL InitialNotification, PHANDLE NotificationHandle) { EnsureInitialized(); LogInfo(">> NotifyIpInterfaceChange called (Family: %d, InitialNotification: %s)", Family, InitialNotification ? "TRUE" : "FALSE"); UNREFERENCED_PARAMETER(Family); UNREFERENCED_PARAMETER(Callback); UNREFERENCED_PARAMETER(CallerContext); UNREFERENCED_PARAMETER(InitialNotification); if (!NotificationHandle) { LogError("   -> NotificationHandle is NULL. Returning ERROR_INVALID_PARAMETER."); return ERROR_INVALID_PARAMETER; } *NotificationHandle = (HANDLE)0xDEADBEEF; LogInfo("   -> Subscription emulated. Returning fake handle: %p", *NotificationHandle); return NO_ERROR; }
DWORD WINAPI ex_ConvertInterfaceLuidToGuid(const NET_LUID* InterfaceLuid, GUID* InterfaceGuid) { EnsureInitialized(); if (!InterfaceLuid || !InterfaceGuid) { LogError("ConvertInterfaceLuidToGuid: Invalid parameters."); return ERROR_INVALID_PARAMETER; } NET_IFINDEX ifIndex = (NET_IFINDEX)(InterfaceLuid->Value & 0xFFFFFF); LogInfo(">> ConvertInterfaceLuidToGuid called for LUID value, assuming IfIndex: %lu", ifIndex); for (int i = 0; i < g_NetworkState.adapterCount; ++i) { if (g_NetworkState.adapters[i].index == ifIndex) { *InterfaceGuid = g_NetworkState.adapters[i].guid; LogInfo("   -> Found matching adapter by index. Returning GUID for '%s'", g_NetworkState.adapters[i].description); return NO_ERROR; } } LogWarning("   -> No adapter found for LUID/Index %lu. Returning ERROR_NOT_FOUND.", ifIndex); return ERROR_NOT_FOUND; }
DWORD WINAPI ex_SetIfEntry(PMIB_IFROW pIfRow) { EnsureInitialized(); if (!pIfRow) { LogError("SetIfEntry: pIfRow is NULL!"); return ERROR_INVALID_PARAMETER; } LogInfo(">> SetIfEntry called: IfIndex=%lu, AdminStatus=%lu", pIfRow->dwIndex, pIfRow->dwAdminStatus); FakeAdapter* a = FindAdapterByIndex(pIfRow->dwIndex); if (!a) { LogWarning("   -> Adapter NOT FOUND"); return ERROR_NOT_FOUND; } a->dwAdminStatus = pIfRow->dwAdminStatus; LogInfo("   -> SUCCESS"); return NO_ERROR; }
DWORD WINAPI ex_DeleteIPAddress(ULONG NTEContext) { EnsureInitialized(); LogInfo(">> DeleteIPAddress called: NTEContext=%lu", NTEContext); for (int i = 0; i < g_NetworkState.adapterCount; ++i) { FakeAdapter* a = &g_NetworkState.adapters[i]; for (int j = 0; j < a->ipCount; ++j) { if (a->ipAddresses[j].NTEContext == NTEContext) { for (int k = j; k < a->ipCount - 1; ++k) a->ipAddresses[k] = a->ipAddresses[k + 1]; a->ipCount--; LogInfo("   -> SUCCESS. IP deleted"); return NO_ERROR; } } } LogWarning("   -> NOT FOUND"); return ERROR_NOT_FOUND; }
DWORD WINAPI ex_SendARP(IPAddr DestIP, IPAddr SrcIP, PVOID pMacAddr, PULONG PhyAddrLen) { EnsureInitialized(); UNREFERENCED_PARAMETER(SrcIP); char ip_str[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &DestIP, ip_str, INET_ADDRSTRLEN); LogInfo(">> SendARP called: DestIP=%s", ip_str); if (!pMacAddr || !PhyAddrLen || *PhyAddrLen < 6) { LogError("   -> Invalid parameters"); return ERROR_BAD_ARGUMENTS; } return ERROR_HOST_UNREACHABLE; }

DWORD WINAPI ex_GetIfTable(PMIB_IFTABLE pIfTable, PULONG pOutBufLen, WINBOOL bOrder) {
    EnsureInitialized();
    LogInfo(">> GetIfTable called (bOrder=%d)", bOrder);
    
    if (!pOutBufLen) {
        LogError("   -> pOutBufLen is NULL");
        return ERROR_INVALID_PARAMETER;
    }
    
    // Calculate required buffer size
    // MIB_IFTABLE = dwNumEntries (DWORD) + array of MIB_IFROW entries
    ULONG requiredSize = sizeof(DWORD); // for dwNumEntries field
    
    if (g_NetworkState.adapterCount > 0) {
        requiredSize += (sizeof(MIB_IFROW) * g_NetworkState.adapterCount);
    }
    
    LogInfo("   Buffer Info: Required=%lu, Provided=%lu", requiredSize, pIfTable ? *pOutBufLen : 0);
    
    // Check if buffer is sufficient
    if (!pIfTable || *pOutBufLen < requiredSize) {
        *pOutBufLen = requiredSize;
        LogWarning("   -> Buffer too small or NULL. Required: %lu. Returning ERROR_INSUFFICIENT_BUFFER.", requiredSize);
        return ERROR_INSUFFICIENT_BUFFER;
    }
    
    // Buffer is sufficient - fill in the interface table
    LogInfo("   -> Buffer is sufficient. Filling data for %d adapters.", g_NetworkState.adapterCount);
    
    memset(pIfTable, 0, *pOutBufLen);
    pIfTable->dwNumEntries = g_NetworkState.adapterCount;
    
    // Fill each interface row
    for (int i = 0; i < g_NetworkState.adapterCount; ++i) {
        const FakeAdapter* fake = &g_NetworkState.adapters[i];
        PMIB_IFROW pRow = &pIfTable->table[i];
        
        LogInfo("   [Adapter %d] Populating '%s'", i, fake->description);
        
        // Basic interface information
        pRow->dwIndex = fake->index;
        pRow->dwType = fake->type;
        pRow->dwMtu = 1500;
        pRow->dwSpeed = 1000000000; // 1 Gbps
        pRow->dwPhysAddrLen = 6;
        memcpy(pRow->bPhysAddr, fake->macAddress, 6);
        
        // Status information
        pRow->dwAdminStatus = fake->dwAdminStatus;
        pRow->dwOperStatus = fake->operStatus;
        
        // Interface description
        if (strlen(fake->description) > 0) {
            DWORD descLen = (DWORD)strlen(fake->description);
            if (descLen > MAXLEN_IFDESCR - 1) descLen = MAXLEN_IFDESCR - 1;
            strcpy_s((char*)pRow->bDescr, MAXLEN_IFDESCR, fake->description);
            pRow->dwDescrLen = descLen;
        }
        
        // Statistics (fake but reasonable values)
        pRow->dwInOctets = 1024000;       // 1MB in
        pRow->dwInUcastPkts = 1000;       // 1000 packets in
        pRow->dwInNonUcastPkts = 50;      // 50 broadcast/multicast
        pRow->dwInDiscards = 0;
        pRow->dwInErrors = 0;
        pRow->dwInUnknownProtos = 0;
        
        pRow->dwOutOctets = 512000;       // 512KB out
        pRow->dwOutUcastPkts = 800;       // 800 packets out
        pRow->dwOutNonUcastPkts = 10;     // 10 broadcast/multicast
        pRow->dwOutDiscards = 0;
        pRow->dwOutErrors = 0;
        pRow->dwOutQLen = 0;
        
        LogInfo("     - Index: %lu, Type: %lu, Status: %lu, Speed: 1Gbps", 
                pRow->dwIndex, pRow->dwType, pRow->dwOperStatus);
        LogInfo("     - MAC: %02X-%02X-%02X-%02X-%02X-%02X", 
                pRow->bPhysAddr[0], pRow->bPhysAddr[1], pRow->bPhysAddr[2], 
                pRow->bPhysAddr[3], pRow->bPhysAddr[4], pRow->bPhysAddr[5]);
    }
    
    LogInfo("   -> SUCCESS. Data written to buffer. Returning NO_ERROR.");
    return NO_ERROR;
}

DWORD WINAPI ex_GetIpAddrTable(PMIB_IPADDRTABLE p, PULONG s, WINBOOL b) { EnsureInitialized(); LogInfo(">> GetIpAddrTable called"); UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); return ERROR_INSUFFICIENT_BUFFER; }
DWORD WINAPI ex_GetNumberOfInterfaces(PDWORD p) { EnsureInitialized(); LogInfo(">> GetNumberOfInterfaces called"); if (!p) return ERROR_INVALID_PARAMETER; *p = g_NetworkState.adapterCount; return NO_ERROR; }
void WINAPI ex_FreeMibTable(PVOID M) { EnsureInitialized(); LogDebug("FreeMibTable called for memory %p", M); free(M); }
DWORD WINAPI ex_GetBestInterface(IPAddr d, PDWORD p) { EnsureInitialized(); LogInfo(">> GetBestInterface called"); if (p) *p = 1; UNREFERENCED_PARAMETER(d); return NO_ERROR; }
DWORD WINAPI ex_GetNetworkParams(PFIXED_INFO p, PULONG l) { UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(l); STUB_FAIL_DWORD(ERROR_BUFFER_OVERFLOW, ERROR_BUFFER_OVERFLOW); }
DWORD WINAPI ex_GetIpForwardTable(PMIB_IPFORWARDTABLE p, PULONG s, BOOL b) { UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); STUB_FAIL_DWORD(ERROR_INSUFFICIENT_BUFFER, ERROR_INSUFFICIENT_BUFFER); }
DWORD WINAPI ex_GetPerAdapterInfo(ULONG i, PIP_PER_ADAPTER_INFO p, PULONG l) { UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(l); STUB_FAIL_DWORD(ERROR_BUFFER_OVERFLOW, ERROR_BUFFER_OVERFLOW); }

// --- ПОВНИЙ СПИСОК ЗАГЛУШОК ---
DWORD WINAPI ex_AddIPAddress(IPAddr A, IPMask M, DWORD I, PULONG C, PULONG N) { UNREFERENCED_PARAMETER(A);UNREFERENCED_PARAMETER(M);UNREFERENCED_PARAMETER(I);UNREFERENCED_PARAMETER(C);UNREFERENCED_PARAMETER(N); STUB_FAIL_DWORD(ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_AllocateAndGetInterfaceInfoFromStack(PIP_INTERFACE_INFO* p, PDWORD s, BOOL b, HANDLE h, DWORD f) { UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(f); STUB_FAIL_DWORD(ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_AllocateAndGetIpAddrTableFromStack(PMIB_IPADDRTABLE* p, BOOL b, HANDLE h, DWORD f) { UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(f); STUB_FAIL_DWORD(ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_CancelIPChangeNotify(LPOVERLAPPED o) { UNREFERENCED_PARAMETER(o); STUB_FAIL_DWORD(ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED); }
VOID WINAPI ex_CancelIfTimestampConfigChange(HANDLE h) { UNREFERENCED_PARAMETER(h); STUB_VOID(); }
DWORD WINAPI ex_CaptureInterfaceHardwareCrossTimestamp(const NET_LUID* l, PINTERFACE_HARDWARE_CROSSTIMESTAMP c) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(c); return ex_StubNotSupported(); }
VOID WINAPI ex_CloseCompartment(HANDLE h) { UNREFERENCED_PARAMETER(h); STUB_VOID(); }
VOID WINAPI ex_CloseGetIPPhysicalInterfaceForDestination(HANDLE h) { UNREFERENCED_PARAMETER(h); STUB_VOID(); }
DWORD WINAPI ex_ConvertCompartmentGuidToId(const GUID* g, PNET_IFINDEX i) { UNREFERENCED_PARAMETER(g); UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertCompartmentIdToGuid(NET_IFINDEX i, GUID* g) { UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(g); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertGuidToStringA(const GUID* g, PSTR s, ULONG l) { UNREFERENCED_PARAMETER(g); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertGuidToStringW(const GUID* g, PWSTR s, ULONG l) { UNREFERENCED_PARAMETER(g); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceAliasToLuid(const WCHAR* a, PNET_LUID l) { UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceGuidToLuid(const GUID* g, PNET_LUID l) { UNREFERENCED_PARAMETER(g); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceIndexToLuid(NET_IFINDEX i, PNET_LUID l) { UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToAlias(const NET_LUID* l, PWSTR a, SIZE_T s) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToIndex(const NET_LUID* l, PNET_IFINDEX i) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToNameA(const NET_LUID* l, PSTR n, SIZE_T s) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToNameW(const WCHAR* l, PWSTR n, SIZE_T s) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceNameToLuidA(const CHAR* n, PNET_LUID l) { UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceNameToLuidW(const WCHAR* n, PNET_LUID l) { UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfacePhysicalAddressToLuid(const BYTE* a, ULONG l, PNET_LUID n) { UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(n); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertIpv4MaskToLength(ULONG m, PUINT8 l) { UNREFERENCED_PARAMETER(m); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertLengthToIpv4Mask(ULONG l, PULONG m) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(m); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceAliasToLuid(PCWSTR r, const WCHAR* a, PNET_LUID l) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceGuidToLuid(PCWSTR r, const GUID* g, PNET_LUID l) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(g); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceIndexToLuid(PCWSTR r, NET_IFINDEX i, PNET_LUID l) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceLuidToAlias(PCWSTR r, const NET_LUID* l, PWSTR a, SIZE_T s) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceLuidToGuid(PCWSTR r, const NET_LUID* l, GUID* g) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(g); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceLuidToIndex(PCWSTR r, const NET_LUID* l, PNET_IFINDEX i) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertStringToGuidA(const CHAR* s, GUID* g) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(g); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertStringToGuidW(const WCHAR* s, GUID* g) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(g); return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertStringToInterfacePhysicalAddress(PCWSTR s, ULONG64* a, PULONG l) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateAnycastIpAddressEntry(const MIB_ANYCASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateCompartment(PCOMPARTMENT_ID i) { UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateFlVirtualInterface(const WCHAR* n, GUID* g, PNET_LUID l) { UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(g); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateIpForwardEntry(PMIB_IPFORWARDROW r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateIpForwardEntry2(const MIB_IPFORWARD_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateIpNetEntry(PMIB_IPNETROW e) { UNREFERENCED_PARAMETER(e); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateIpNetEntry2(const MIB_IPNET_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreatePersistentTcpPortReservation(USHORT s, USHORT n, PULONG64 t) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreatePersistentUdpPortReservation(USHORT s, USHORT n, PULONG64 t) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateProxyArpEntry(DWORD a, DWORD m, DWORD i) { UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(m); UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
VOID WINAPI ex_CreateSortedAddressPairs(const PSOCKADDR_IN6 a, ULONG c, const PSOCKADDR_IN6 d, ULONG e, ULONG o, PSOCKADDR_IN6_PAIR* p, PULONG t) { UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(e); UNREFERENCED_PARAMETER(o); UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(t); STUB_VOID(); }
DWORD WINAPI ex_CreateUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteAnycastIpAddressEntry(const MIB_ANYCASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
VOID WINAPI ex_DeleteCompartment(HANDLE h) { UNREFERENCED_PARAMETER(h); STUB_VOID(); }
VOID WINAPI ex_DeleteFlVirtualInterface(const NET_LUID* l) { UNREFERENCED_PARAMETER(l); STUB_VOID(); }
DWORD WINAPI ex_DeleteIpForwardEntry(PMIB_IPFORWARDROW r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteIpForwardEntry2(const MIB_IPFORWARD_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteIpNetEntry(PMIB_IPNETROW e) { UNREFERENCED_PARAMETER(e); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteIpNetEntry2(const MIB_IPNET_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeletePersistentTcpPortReservation(USHORT s, USHORT n) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(n); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeletePersistentUdpPortReservation(USHORT s, USHORT n) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(n); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteProxyArpEntry(DWORD a, DWORD m, DWORD i) { UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(m); UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_DisableMediaSense(HANDLE* p, LPOVERLAPPED o) { UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(o); return ex_StubNotSupported(); }
DWORD WINAPI ex_EnableRouter(HANDLE* p, LPOVERLAPPED o) { UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(o); return ex_StubNotSupported(); }
DWORD WINAPI ex_FlushIpNetTable(DWORD i) { UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_FlushIpNetTable2(ADDRESS_FAMILY f, NET_IFINDEX i) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_FlushIpPathTable(ADDRESS_FAMILY f) { UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
VOID WINAPI ex_FreeDnsSettings(PDNS_SETTINGS s) { UNREFERENCED_PARAMETER(s); STUB_VOID(); }
VOID WINAPI ex_FreeInterfaceDnsSettings(PDNS_INTERFACE_SETTINGS s) { UNREFERENCED_PARAMETER(s); STUB_VOID(); }
DWORD WINAPI ex_GetAdapterIndex(LPWSTR n, PULONG i) { UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetAdapterOrderMap() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetAnycastIpAddressEntry(MIB_ANYCASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetAnycastIpAddressTable(ADDRESS_FAMILY f, PMIB_ANYCASTIPADDRESS_TABLE* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetBestRoute(DWORD d, DWORD s, PMIB_IPFORWARDROW r) { UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetBestRoute2(NET_LUID* l, NET_IFINDEX i, const SOCKADDR_INET* s, const SOCKADDR_INET* d, ULONG o, MIB_IPFORWARD_ROW2* b, SOCKADDR_INET* bs) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(o); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(bs); return ex_StubNotSupported(); }
COMPARTMENT_ID WINAPI ex_GetCurrentThreadCompartmentId() { STUB_RETURN_ZERO(); }
VOID WINAPI ex_GetCurrentThreadCompartmentScope(PCOMPARTMENT_ID i, PCOMPARTMENT_ID s) { UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(s); STUB_VOID(); }
COMPARTMENT_ID WINAPI ex_GetDefaultCompartmentId() { STUB_RETURN_ZERO(); }
DWORD WINAPI ex_GetDnsSettings(PDNS_SETTINGS s) { UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetExtendedTcpTable(PVOID t, PDWORD s, BOOL b, ULONG a, TCP_TABLE_CLASS c, ULONG r) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(r); return ex_StubNoData(); }
DWORD WINAPI ex_GetExtendedUdpTable(PVOID t, PDWORD s, BOOL b, ULONG a, UDP_TABLE_CLASS c, ULONG r) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(r); return ex_StubNoData(); }
DWORD WINAPI ex_GetFlVirtualInterface(const NET_LUID* l, PMIB_FL_VIRTUAL_INTERFACE v) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(v); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetFlVirtualInterfaceTable(ADDRESS_FAMILY f, PMIB_FL_VIRTUAL_INTERFACE_TABLE* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetFriendlyIfIndex(DWORD i) { UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIcmpStatistics(PMIB_ICMP s) { UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIcmpStatisticsEx(PMIB_ICMP_EX s, DWORD f) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfEntry(PMIB_IFROW r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfEntry2(MIB_IF_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfEntry2Ex(MIB_IF_TABLE_LEVEL l, const MIB_IF_ROW2* r) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfStackTable(PMIB_IFSTACK_TABLE* t) { UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfTable2(PMIB_IF_TABLE2* t) { UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfTable2Ex(MIB_IF_TABLE_LEVEL l, PMIB_IF_TABLE2* t) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceActiveTimestampCapabilities(const NET_LUID* l, PINTERFACE_TIMESTAMP_CAPABILITIES c) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(c); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceCompartmentId(const NET_LUID* l, PCOMPARTMENT_ID i) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceCurrentTimestampCapabilities(const NET_LUID* l, PINTERFACE_TIMESTAMP_CAPABILITIES c) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(c); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceDnsSettings(GUID i, PDNS_INTERFACE_SETTINGS s) { UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceHardwareTimestampCapabilities(const NET_LUID* l, PINTERFACE_TIMESTAMP_CAPABILITIES c) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(c); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceInfo(PIP_INTERFACE_INFO t, PULONG s) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceSupportedTimestampCapabilities(const NET_LUID* l, PINTERFACE_TIMESTAMP_CAPABILITIES c) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(c); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInvertedIfStackTable(PMIB_INVERTEDIFSTACK_TABLE* t) { UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpErrorString(IP_STATUS e, PWSTR b, PDWORD s) { UNREFERENCED_PARAMETER(e); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpForwardEntry2(MIB_IPFORWARD_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpForwardTable2(ADDRESS_FAMILY f, PMIB_IPFORWARD_TABLE2* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpInterfaceEntry(MIB_IPINTERFACE_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpInterfaceTable(ADDRESS_FAMILY f, PMIB_IPINTERFACE_TABLE* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpNetEntry2(MIB_IPNET_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpNetTable(PMIB_IPNETTABLE t, PULONG s, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); return ex_StubNoData(); }
DWORD WINAPI ex_GetIpNetTable2(ADDRESS_FAMILY f, PMIB_IPNET_TABLE2* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpNetworkConnectionBandwidthEstimates(NET_IFINDEX i, ADDRESS_FAMILY f, PNET_IF_CONNECTION_BANDWIDTH_ESTIMATES e) { UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(e); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpPathEntry(const MIB_IPPATH_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpPathTable(ADDRESS_FAMILY f, PMIB_IPPATH_TABLE* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpStatistics(PMIB_IPSTATS s) { UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpStatisticsEx(PMIB_IPSTATS s, DWORD f) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetJobCompartmentId(HANDLE h, PCOMPARTMENT_ID i) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetMulticastIpAddressEntry(MIB_MULTICASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetMulticastIpAddressTable(ADDRESS_FAMILY f, PMIB_MULTICASTIPADDRESS_TABLE* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetNetworkConnectivityHint(PNL_NETWORK_CONNECTIVITY_HINT h) { UNREFERENCED_PARAMETER(h); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetNetworkConnectivityHintForInterface(NET_IFINDEX i, PNL_NETWORK_CONNECTIVITY_HINT h) { UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(h); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetNetworkInformation(const GUID* g, PBOOL m) { UNREFERENCED_PARAMETER(g); UNREFERENCED_PARAMETER(m); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromPidAndInfo(DWORD p, TCPIP_OWNER_MODULE_INFO_CLASS* i, PVOID b, PDWORD s) { UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromTcp6Entry(const MIB_TCP6ROW_OWNER_MODULE* e, TCPIP_OWNER_MODULE_INFO_CLASS c, PVOID b, PDWORD s) { UNREFERENCED_PARAMETER(e); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromTcpEntry(const MIB_TCPROW_OWNER_MODULE* e, TCPIP_OWNER_MODULE_INFO_CLASS c, PVOID b, PDWORD s) { UNREFERENCED_PARAMETER(e); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromUdp6Entry(const MIB_UDP6ROW_OWNER_MODULE* e, TCPIP_OWNER_MODULE_INFO_CLASS c, PVOID b, PDWORD s) { UNREFERENCED_PARAMETER(e); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromUdpEntry(const MIB_UDPROW_OWNER_MODULE* e, TCPIP_OWNER_MODULE_INFO_CLASS c, PVOID b, PDWORD s) { UNREFERENCED_PARAMETER(e); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetPerTcp6ConnectionEStats(const MIB_TCP6ROW* r, TCP_ESTATS_TYPE t, PUCHAR w, ULONG wv, ULONG ws, PUCHAR o, ULONG ov, ULONG os, PUCHAR d, ULONG dv, ULONG ds) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(w); UNREFERENCED_PARAMETER(wv); UNREFERENCED_PARAMETER(ws); UNREFERENCED_PARAMETER(o); UNREFERENCED_PARAMETER(ov); UNREFERENCED_PARAMETER(os); UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(dv); UNREFERENCED_PARAMETER(ds); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetPerTcp6ConnectionStats(const MIB_TCP6ROW* r, PMIB_TCPSTATS s) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetPerTcpConnectionEStats(PMIB_TCPROW r, TCP_ESTATS_TYPE t, PUCHAR w, ULONG wv, ULONG ws, ULONG o) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(w); UNREFERENCED_PARAMETER(wv); UNREFERENCED_PARAMETER(ws); UNREFERENCED_PARAMETER(o); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetPerTcpConnectionStats(PMIB_TCPROW r, PMIB_TCPSTATS s) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetRTTAndHopCount(IPAddr d, PULONG h, ULONG m, PULONG r) { UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(m); UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetSessionCompartmentId(ULONG s, PCOMPARTMENT_ID i) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcp6Table(PMIB_TCP6TABLE t, PULONG s, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); return ex_StubNoData(); }
DWORD WINAPI ex_GetTcp6Table2(PMIB_TCP6TABLE2* t, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcpStatistics(PMIB_TCPSTATS s) { UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcpStatisticsEx(PMIB_TCPSTATS s, DWORD f) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcpStatisticsEx2(PMIB_TCPSTATS2 s, ULONG f) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcpTable(PMIB_TCPTABLE t, PULONG s, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); return ex_StubNoData(); }
DWORD WINAPI ex_GetTcpTable2(PMIB_TCPTABLE2* t, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTeredoPort(PUSHORT p) { UNREFERENCED_PARAMETER(p); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUdp6Table(PMIB_UDP6TABLE t, PULONG s, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); return ex_StubNoData(); }
DWORD WINAPI ex_GetUdpStatistics(PMIB_UDPSTATS s) { UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUdpStatisticsEx(PMIB_UDPSTATS s, DWORD f) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUdpStatisticsEx2(PMIB_UDPSTATS2 s, ULONG f) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUdpTable(PMIB_UDPTABLE t, PULONG s, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); return ex_StubNoData(); }
DWORD WINAPI ex_GetUniDirectionalAdapterInfo(PIP_UNIDIRECTIONAL_ADAPTER_ADDRESS i, PULONG s) { UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUnicastIpAddressEntry(MIB_UNICASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUnicastIpAddressTable(ADDRESS_FAMILY f, PMIB_UNICASTIPADDRESS_TABLE* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_GetWPAOACSupportLevel(PBOOL s) { UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
HANDLE WINAPI ex_Icmp6CreateFile() { STUB_RETURN_INVALID_HANDLE(); }
DWORD WINAPI ex_Icmp6ParseReplies(LPVOID b, DWORD s) { UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_Icmp6SendEcho2(HANDLE h, HANDLE e, PTIMERAPCROUTINE r, PVOID c, const struct sockaddr_in6* s, const struct sockaddr_in6* d, LPVOID qd, WORD qs, PIP_OPTION_INFORMATION qo, LPVOID rb, DWORD rs, DWORD t) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(e); UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(qd); UNREFERENCED_PARAMETER(qs); UNREFERENCED_PARAMETER(qo); UNREFERENCED_PARAMETER(rb); UNREFERENCED_PARAMETER(rs); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
BOOL WINAPI ex_IcmpCloseHandle(HANDLE h) { UNREFERENCED_PARAMETER(h); STUB_FAIL_BOOL(ERROR_INVALID_HANDLE); }
HANDLE WINAPI ex_IcmpCreateFile() { STUB_RETURN_INVALID_HANDLE(); }
DWORD WINAPI ex_IcmpParseReplies(LPVOID b, DWORD s) { UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_IcmpSendEcho(HANDLE h, IPAddr d, LPVOID qd, WORD qs, PIP_OPTION_INFORMATION qo, LPVOID rb, DWORD rs, DWORD t) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(qd); UNREFERENCED_PARAMETER(qs); UNREFERENCED_PARAMETER(qo); UNREFERENCED_PARAMETER(rb); UNREFERENCED_PARAMETER(rs); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_IcmpSendEcho2(HANDLE h, HANDLE e, PTIMERAPCROUTINE r, PVOID c, IPAddr d, LPVOID qd, WORD qs, PIP_OPTION_INFORMATION qo, LPVOID rb, DWORD rs, DWORD t) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(e); UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(qd); UNREFERENCED_PARAMETER(qs); UNREFERENCED_PARAMETER(qo); UNREFERENCED_PARAMETER(rb); UNREFERENCED_PARAMETER(rs); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_IcmpSendEcho2Ex(HANDLE h, HANDLE e, PTIMERAPCROUTINE r, PVOID c, IPAddr s, IPAddr d, LPVOID qd, WORD qs, PIP_OPTION_INFORMATION qo, LPVOID rb, DWORD rs, DWORD t) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(e); UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(qd); UNREFERENCED_PARAMETER(qs); UNREFERENCED_PARAMETER(qo); UNREFERENCED_PARAMETER(rb); UNREFERENCED_PARAMETER(rs); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
VOID WINAPI ex_InitializeCompartmentEntry(PCOMPARTMENT_ID i) { UNREFERENCED_PARAMETER(i); STUB_VOID(); }
VOID WINAPI ex_InitializeFlVirtualInterfaceEntry(PMIB_FL_VIRTUAL_INTERFACE i) { UNREFERENCED_PARAMETER(i); STUB_VOID(); }
VOID WINAPI ex_InitializeIpForwardEntry(PMIB_IPFORWARDROW r) { UNREFERENCED_PARAMETER(r); STUB_VOID(); }
VOID WINAPI ex_InitializeIpInterfaceEntry(MIB_IPINTERFACE_ROW* r) { UNREFERENCED_PARAMETER(r); STUB_VOID(); }
VOID WINAPI ex_InitializeUnicastIpAddressEntry(MIB_UNICASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); STUB_VOID(); }
DWORD WINAPI ex_InternalCleanupPersistentStore() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateAnycastIpAddressEntry(const MIB_ANYCASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateIpForwardEntry(PMIB_IPFORWARDROW r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateIpForwardEntry2(const MIB_IPFORWARD_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateIpNetEntry(PMIB_IPNETROW e) { UNREFERENCED_PARAMETER(e); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateIpNetEntry2(const MIB_IPNET_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateOrRefIpForwardEntry2(const MIB_IPFORWARD_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteAnycastIpAddressEntry(const MIB_ANYCASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteIpForwardEntry(PMIB_IPFORWARDROW r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteIpForwardEntry2(const MIB_IPFORWARD_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteIpNetEntry(PMIB_IPNETROW e) { UNREFERENCED_PARAMETER(e); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteIpNetEntry2(const MIB_IPNET_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalFindInterfaceByAddress(const SOCKADDR_INET* a) { UNREFERENCED_PARAMETER(a); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetAnycastIpAddressEntry(MIB_ANYCASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetAnycastIpAddressTable(ADDRESS_FAMILY f, PMIB_ANYCASTIPADDRESS_TABLE* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetBoundTcp6EndpointTable(ULONG u, PMIB_TCP6TABLE_OWNER_MODULE* t, PULONG s) { UNREFERENCED_PARAMETER(u); UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetBoundTcpEndpointTable(ULONG u, PMIB_TCPTABLE_OWNER_MODULE* t, PULONG s) { UNREFERENCED_PARAMETER(u); UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetForwardIpTable2(ADDRESS_FAMILY f, PMIB_IPFORWARD_TABLE2* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIPPhysicalInterfaceForDestination(const SOCKADDR* d, PMIB_IP_PHYSICAL_INTERFACE_ROW r) { UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIfEntry2(MIB_IF_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIfTable(PMIB_IFTABLE t, PULONG s, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIfTable2(PMIB_IF_TABLE2* t) { UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpAddrTable(PMIB_IPADDRTABLE t, PULONG s, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpForwardEntry2(MIB_IPFORWARD_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpForwardTable(PMIB_IPFORWARDTABLE t, PULONG s, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpInterfaceEntry(MIB_IPINTERFACE_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpInterfaceTable(ADDRESS_FAMILY f, PMIB_IPINTERFACE_TABLE* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpNetEntry2(MIB_IPNET_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpNetTable(PMIB_IPNETTABLE t, PULONG s, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpNetTable2(ADDRESS_FAMILY f, PMIB_IPNET_TABLE2* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetMulticastIpAddressEntry(MIB_MULTICASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetMulticastIpAddressTable(ADDRESS_FAMILY f, PMIB_MULTICASTIPADDRESS_TABLE* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetRtcSlotInformation(PRTC_SLOT_INFORMATION_TABLE t) { UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcp6Table2(PMIB_TCP6TABLE2* t, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcp6TableWithOwnerModule(PMIB_TCP6TABLE_OWNER_MODULE* t, BOOL b, HANDLE h, DWORD f) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcp6TableWithOwnerPid(PMIB_TCP6TABLE_OWNER_PID* t, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpDynamicPortRange(USHORT* s, USHORT* n) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(n); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTable(PMIB_TCPTABLE t, PULONG s, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTable2(PMIB_TCPTABLE2* t, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTableEx(PVOID t, PULONG s, BOOL b, ULONG a) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(a); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTableWithOwnerModule(PMIB_TCPTABLE_OWNER_MODULE* t, BOOL b, HANDLE h, DWORD f) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTableWithOwnerPid(PMIB_TCPTABLE_OWNER_PID* t, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTunnelPhysicalAdapter(NET_LUID l, PMIB_TUNNEL_PHYSICAL_ADAPTER t) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdp6Table2(PMIB_UDP6TABLE* u, BOOL b) { UNREFERENCED_PARAMETER(u); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdp6TableWithOwnerModule(PMIB_UDP6TABLE_OWNER_MODULE* u, BOOL b, HANDLE h, DWORD f) { UNREFERENCED_PARAMETER(u); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdp6TableWithOwnerPid(PMIB_UDP6TABLE_OWNER_PID* u, BOOL b) { UNREFERENCED_PARAMETER(u); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpDynamicPortRange(USHORT* s, USHORT* n) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(n); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTable(PMIB_UDPTABLE t, PULONG s, BOOL b) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTable2(PMIB_UDPTABLE* u, BOOL b) { UNREFERENCED_PARAMETER(u); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTableEx(PVOID t, PULONG s, BOOL b, ULONG a) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(a); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTableWithOwnerModule(PMIB_UDPTABLE_OWNER_MODULE* u, BOOL b, HANDLE h, DWORD f) { UNREFERENCED_PARAMETER(u); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTableWithOwnerPid(PMIB_UDPTABLE_OWNER_PID* u, BOOL b) { UNREFERENCED_PARAMETER(u); UNREFERENCED_PARAMETER(b); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUnicastIpAddressEntry(MIB_UNICASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUnicastIpAddressTable(ADDRESS_FAMILY f, PMIB_UNICASTIPADDRESS_TABLE* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalIcmpCreateFileEx(PHANDLE h, PVOID c, PTIMERAPCROUTINE r) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIfEntry(PMIB_IFROW r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpForwardEntry(PMIB_IPFORWARDROW r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpForwardEntry2(const MIB_IPFORWARD_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpInterfaceEntry(MIB_IPINTERFACE_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpNetEntry(PMIB_IPNETROW e) { UNREFERENCED_PARAMETER(e); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpNetEntry2(const MIB_IPNET_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpStats(PMIB_IPSTATS s) { UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetTcpDynamicPortRange(USHORT s, USHORT n) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(n); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetTcpEntry(PMIB_TCPROW r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetTeredoPort(USHORT p) { UNREFERENCED_PARAMETER(p); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetUdpDynamicPortRange(USHORT s, USHORT n) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(n); return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_IpReleaseAddress(PIP_ADAPTER_INDEX_MAP a) { UNREFERENCED_PARAMETER(a); return ex_StubNotSupported(); }
DWORD WINAPI ex_IpRenewAddress(PIP_ADAPTER_INDEX_MAP a) { UNREFERENCED_PARAMETER(a); return ex_StubNotSupported(); }
DWORD WINAPI ex_LookupPersistentTcpPortReservation(USHORT s, USHORT n, PULONG64 t) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_LookupPersistentUdpPortReservation(USHORT s, USHORT n, PULONG64 t) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
VOID WINAPI ex_NTPTimeToNTFileTime(ULONG n, LPFILETIME f) { UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(f); STUB_VOID(); }
VOID WINAPI ex_NTTimeToNTPTime(const FILETIME* f, PULONG n) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(n); STUB_VOID(); }
DWORD WINAPI ex_NhGetGuidFromInterfaceName(PCWSTR n, GUID* g) { UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(g); return ex_StubNotSupported(); }
DWORD WINAPI ex_NhGetInterfaceDescriptionFromGuid(GUID* g, PWCHAR d, LPDWORD s) { UNREFERENCED_PARAMETER(g); UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_NhGetInterfaceNameFromDeviceGuid(GUID* g, PWCHAR n, LPDWORD s, BOOL f) { UNREFERENCED_PARAMETER(g); UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_NhGetInterfaceNameFromGuid(GUID* g, PWCHAR n, LPDWORD s, BOOL f) { UNREFERENCED_PARAMETER(g); UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_NhpAllocateAndGetInterfaceInfoFromStack(PIP_INTERFACE_INFO* t, PDWORD c, BOOL b, HANDLE h, DWORD f) { UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyAddrChange(PHANDLE h, LPOVERLAPPED o) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(o); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyCompartmentChange(HANDLE h, PTIMERAPCROUTINE r, PVOID c, BOOL p, PHANDLE n) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(n); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyIfTimestampConfigChange(PVOID c, PINTERFACE_TIMESTAMP_CONFIG_CHANGE_CALLBACK cb, PHANDLE n) { UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(cb); UNREFERENCED_PARAMETER(n); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyNetworkConnectivityHintChange(PNL_NETWORK_CONNECTIVITY_HINT_CHANGE_CALLBACK cb, PVOID c, BOOL i, PHANDLE n) { UNREFERENCED_PARAMETER(cb); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(n); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyRouteChange(PHANDLE h, LPOVERLAPPED o) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(o); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyRouteChange2(ADDRESS_FAMILY f, PIPFORWARD_CHANGE_CALLBACK c, PVOID x, BOOL i, PHANDLE h) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(x); UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(h); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyStableUnicastIpAddressTable(ADDRESS_FAMILY f, PULONG n, PMIB_UNICASTIPADDRESS_TABLE* t) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyTeredoPortChange(PTEREDO_PORT_CHANGE_CALLBACK c, PVOID x, BOOL i, PHANDLE h) { UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(x); UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(h); return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyUnicastIpAddressChange(ADDRESS_FAMILY f, PUNICAST_IPADDRESS_CHANGE_CALLBACK c, PVOID x, BOOL i, PHANDLE h) { UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(x); UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(h); return ex_StubNotSupported(); }
DWORD WINAPI ex_OpenCompartment(COMPARTMENT_ID i, PHANDLE h) { UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(h); return ex_StubNotSupported(); }
DWORD WINAPI ex_ParseNetworkString(const WCHAR* s, DWORD t, PNET_ADDRESS_INFO a, USHORT* p, ULONG* l) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfAddFiltersToInterface(HANDLE h, ULONG ci, PFILTER_DESCRIPTOR pi, ULONG co, PFILTER_DESCRIPTOR po, PFHANDLE pf) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(ci); UNREFERENCED_PARAMETER(pi); UNREFERENCED_PARAMETER(co); UNREFERENCED_PARAMETER(po); UNREFERENCED_PARAMETER(pf); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfAddGlobalFilterToInterface(HANDLE p, GLOBAL_FILTER g) { UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(g); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfBindInterfaceToIPAddress(HANDLE h, PFFORWARD_ACTION a, ULONG i) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfBindInterfaceToIndex(HANDLE h, DWORD i, PFFORWARD_ACTION l, PFFORWARD_ACTION u) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(u); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfCreateInterface(DWORD n, PFFORWARD_ACTION a, PVOID h) { UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(h); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfDeleteInterface(HANDLE h) { UNREFERENCED_PARAMETER(h); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfDeleteLog() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfGetInterfaceStatistics(HANDLE h, PFP_INTERFACE_STATS s, PBOOL f) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfMakeLog(HANDLE h) { UNREFERENCED_PARAMETER(h); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfRebindFilters(HANDLE h, ULONG ci, PFILTER_DESCRIPTOR pi, ULONG co, PFILTER_DESCRIPTOR po) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(ci); UNREFERENCED_PARAMETER(pi); UNREFERENCED_PARAMETER(co); UNREFERENCED_PARAMETER(po); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfRemoveFilterHandles(HANDLE h, ULONG c, PFHANDLE f) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfRemoveFiltersFromInterface(HANDLE h, ULONG ci, PFILTER_DESCRIPTOR pi, ULONG co, PFILTER_DESCRIPTOR po) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(ci); UNREFERENCED_PARAMETER(pi); UNREFERENCED_PARAMETER(co); UNREFERENCED_PARAMETER(po); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfRemoveGlobalFilterFromInterface(HANDLE p, GLOBAL_FILTER g) { UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(g); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfSetLogBuffer(PCHAR b, DWORD s, ULONG u, ULONG f, HANDLE* h) { UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(u); UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(h); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfTestPacket(HANDLE hi, HANDLE ho, ULONG c, PBYTE p) { UNREFERENCED_PARAMETER(hi); UNREFERENCED_PARAMETER(ho); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(p); return ex_StubNotSupported(); }
DWORD WINAPI ex_PfUnBindInterface(HANDLE h) { UNREFERENCED_PARAMETER(h); return ex_StubNotSupported(); }
DWORD WINAPI ex_RegisterInterfaceTimestampConfigChange(PVOID c, PINTERFACE_TIMESTAMP_CONFIG_CHANGE_CALLBACK cb, PHANDLE n) { UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(cb); UNREFERENCED_PARAMETER(n); return ex_StubNotSupported(); }
DWORD WINAPI ex_ResolveIpNetEntry2(MIB_IPNET_ROW2* r, const SOCKADDR_INET* s) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_ResolveNeighbor(const SOCKADDR* a, PVOID p, PULONG l) { UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(l); return ex_StubNotSupported(); }
DWORD WINAPI ex_RestoreMediaSense(HANDLE* p, LPOVERLAPPED o) { UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(o); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetAdapterIpAddress(const CHAR* n, BOOL d, ULONG i, ULONG s, ULONG g) { UNREFERENCED_PARAMETER(n); UNREFERENCED_PARAMETER(d); UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(g); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetCurrentThreadCompartmentId(COMPARTMENT_ID i) { UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
VOID WINAPI ex_SetCurrentThreadCompartmentScope(COMPARTMENT_ID i, COMPARTMENT_ID s) { UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(s); STUB_VOID(); }
DWORD WINAPI ex_SetDnsSettings(const PDNS_SETTINGS s) { UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetFlVirtualInterface(const NET_LUID* l, const PMIB_FL_VIRTUAL_INTERFACE v) { UNREFERENCED_PARAMETER(l); UNREFERENCED_PARAMETER(v); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetInterfaceDnsSettings(GUID i, const PDNS_INTERFACE_SETTINGS s) { UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpForwardEntry(PMIB_IPFORWARDROW r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpForwardEntry2(const MIB_IPFORWARD_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpInterfaceEntry(MIB_IPINTERFACE_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpNetEntry(PMIB_IPNETROW e) { UNREFERENCED_PARAMETER(e); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpNetEntry2(const MIB_IPNET_ROW2* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpStatistics(PMIB_IPSTATS s) { UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpStatisticsEx(PMIB_IPSTATS s, DWORD f) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpTTL(UINT t) { UNREFERENCED_PARAMETER(t); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetJobCompartmentId(HANDLE h, COMPARTMENT_ID i) { UNREFERENCED_PARAMETER(h); UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetNetworkInformation(const GUID* g, BOOL m) { UNREFERENCED_PARAMETER(g); UNREFERENCED_PARAMETER(m); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetPerTcp6ConnectionEStats(const MIB_TCP6ROW* r, TCP_ESTATS_TYPE t, PUCHAR w, ULONG wv, ULONG ws, ULONG o) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(w); UNREFERENCED_PARAMETER(wv); UNREFERENCED_PARAMETER(ws); UNREFERENCED_PARAMETER(o); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetPerTcp6ConnectionStats(const MIB_TCP6ROW* r, PMIB_TCPSTATS s) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetPerTcpConnectionEStats(PMIB_TCPROW r, TCP_ESTATS_TYPE t, PUCHAR w, ULONG wv, ULONG ws, ULONG o) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(w); UNREFERENCED_PARAMETER(wv); UNREFERENCED_PARAMETER(ws); UNREFERENCED_PARAMETER(o); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetPerTcpConnectionStats(PMIB_TCPROW r, PMIB_TCPSTATS s) { UNREFERENCED_PARAMETER(r); UNREFERENCED_PARAMETER(s); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetSessionCompartmentId(ULONG s, COMPARTMENT_ID i) { UNREFERENCED_PARAMETER(s); UNREFERENCED_PARAMETER(i); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetTcpEntry(PMIB_TCPROW r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_SetUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW* r) { UNREFERENCED_PARAMETER(r); return ex_StubNotSupported(); }
DWORD WINAPI ex_UnenableRouter(LPOVERLAPPED o, LPDWORD c) { UNREFERENCED_PARAMETER(o); UNREFERENCED_PARAMETER(c); return ex_StubNotSupported(); }
VOID WINAPI ex_UnregisterInterfaceTimestampConfigChange(HANDLE h) { UNREFERENCED_PARAMETER(h); STUB_VOID(); }
DWORD WINAPI ex_do_echo_rep() { return ex_StubNotSupported(); }
DWORD WINAPI ex_do_echo_req() { return ex_StubNotSupported(); }
PWCHAR WINAPI ex_if_indextoname(NET_IFINDEX i, PWCHAR n) { UNREFERENCED_PARAMETER(i); UNREFERENCED_PARAMETER(n); STUB_RETURN_NULL(); }
NET_IFINDEX WINAPI ex_if_nametoindex(PCWSTR n) { UNREFERENCED_PARAMETER(n); STUB_RETURN_ZERO(); }
HANDLE WINAPI ex_register_icmp(FARPROC p, PVOID c) { UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(c); STUB_RETURN_INVALID_HANDLE(); }
BOOL WINAPI ex_InternetSetSecureLegacyServersAppCompat() { STUB_FAIL_BOOL(ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_AllocateAndGetTcpExTableFromStack(PVOID* p, PBOOL v, PBOOL o, HANDLE a, DWORD f) { UNREFERENCED_PARAMETER(p); UNREFERENCED_PARAMETER(v); UNREFERENCED_PARAMETER(o); UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(f); return ex_StubNotSupported(); }

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule); 
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        if (g_init_count > 0) {
             if (g_locks_initialized) {
                 #if ENABLE_FILE_LOGGING
                 if (g_log_file) {
                     LogInfo("=== IPHLPAPI EMULATOR UNLOADING ===");
                     fclose(g_log_file); 
                     g_log_file = NULL; 
                 }
                 DeleteCriticalSection(&g_log_lock);
                 #endif
                 g_locks_initialized = FALSE;
             }
        }
        break;
    }
    return TRUE;
}

#ifdef __cplusplus
}
#endif
