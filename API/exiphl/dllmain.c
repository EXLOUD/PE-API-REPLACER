#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "exws2.lib")

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// === НАЛАГОДЖУВАЛЬНІ КОНСТАНТИ ===
// ============================================================================
#define ENABLE_DEBUG_CONSOLE    0
#define ENABLE_FILE_LOGGING     0 
#define ENABLE_MEMORY_TRACKING  1 

// ============================================================================
// === СТРУКТУРИ ТА КОНСТАНТИ ДЛЯ ВІДСТЕЖЕННЯ ===
// ============================================================================
#define MAX_ADAPTERS 8
#define MAX_IPS_PER_ADAPTER 4
#define MAX_ARP_ENTRIES 16

typedef enum { LOG_LEVEL_ERROR = 0, LOG_LEVEL_WARNING, LOG_LEVEL_INFO, LOG_LEVEL_DEBUG } LogLevel;
typedef struct _MEMORY_BLOCK { void* ptr; size_t size; char function[64]; DWORD thread_id; struct _MEMORY_BLOCK* next; } MEMORY_BLOCK;
typedef struct { char ipAddress[16]; char ipMask[16]; DWORD dwAddr; DWORD dwMask; ULONG NTEContext; } FakeIpAddress;
typedef struct { char name[MAX_ADAPTER_NAME_LENGTH + 4]; char description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4]; DWORD type; DWORD index; DWORD dwAdminStatus; BYTE macAddress[MAX_ADAPTER_ADDRESS_LENGTH]; int ipCount; FakeIpAddress ipAddresses[MAX_IPS_PER_ADAPTER]; } FakeAdapter;
typedef struct { DWORD dwAddr; BYTE macAddress[6]; } FakeArpEntry;
typedef struct { int adapterCount; FakeAdapter adapters[MAX_ADAPTERS]; int arpCacheCount; FakeArpEntry arpCache[MAX_ARP_ENTRIES]; ULONG nextNTEContext; } NetworkState;

// ============================================================================
// === ГЛОБАЛЬНІ ЗМІННІ ===
// ============================================================================
#if ENABLE_FILE_LOGGING
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
void LogMessageEx(LogLevel level, const char* function, const char* format, ...) { if (level > g_current_log_level) return; char timestamp[20] = { 0 }; GetTimestamp(timestamp, sizeof(timestamp)); va_list args; va_start(args, format);
#if ENABLE_FILE_LOGGING
if (g_log_file && g_locks_initialized) { EnterCriticalSection(&g_log_lock); fprintf(g_log_file, "%s [%s] [%s] ", timestamp, GetLogLevelString(level), function); vfprintf(g_log_file, format, args); fprintf(g_log_file, "\n"); fflush(g_log_file); LeaveCriticalSection(&g_log_lock); }
#endif
#if ENABLE_DEBUG_CONSOLE
printf("[IPHLPAPI] %s [%s] [%s] ", timestamp, GetLogLevelString(level), function); vprintf(format, args); printf("\n");
#endif
va_end(args); }
#define LogError(fmt, ...)   LogMessageEx(LOG_LEVEL_ERROR, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogWarning(fmt, ...) LogMessageEx(LOG_LEVEL_WARNING, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogInfo(fmt, ...)    LogMessageEx(LOG_LEVEL_INFO, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LogDebug(fmt, ...)   LogMessageEx(LOG_LEVEL_DEBUG, __FUNCTION__, fmt, ##__VA_ARGS__)
#if ENABLE_MEMORY_TRACKING
void* TrackedAlloc(size_t size, const char* function) { if (size == 0) { return NULL; } void* ptr = malloc(size); if (!ptr) { LogError("Failed to allocate %zu bytes", size); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; } memset(ptr, 0, size); if (g_locks_initialized) { EnterCriticalSection(&g_memory_lock); MEMORY_BLOCK* block = (MEMORY_BLOCK*)malloc(sizeof(MEMORY_BLOCK)); if (block) { block->ptr = ptr; block->size = size; strncpy_s(block->function, sizeof(block->function), function, _TRUNCATE); block->thread_id = GetCurrentThreadId(); block->next = g_memory_list; g_memory_list = block; g_total_allocated += size; g_allocation_count++; } LeaveCriticalSection(&g_memory_lock); } LogDebug("Allocated %zu bytes at %p", size, ptr); return ptr; }
BOOL TrackedFree(void* ptr, const char* function) { if (!ptr) return TRUE; BOOL found = FALSE; if (g_locks_initialized) { EnterCriticalSection(&g_memory_lock); MEMORY_BLOCK** current = &g_memory_list; while (*current) { if ((*current)->ptr == ptr) { MEMORY_BLOCK* block = *current; *current = block->next; g_total_freed += block->size; g_allocation_count--; LogDebug("Freed %zu bytes from %p (allocated in %s)", block->size, ptr, block->function); free(block->ptr); free(block); found = TRUE; break; } current = &(*current)->next; } LeaveCriticalSection(&g_memory_lock); } if (!found) { LogWarning("Attempt to free untracked/already freed memory: %p", ptr); free(ptr); } return found; }
void ReportMemoryLeaks() { if (!g_locks_initialized) return; EnterCriticalSection(&g_memory_lock); if (g_memory_list) { LogError("=== MEMORY LEAKS DETECTED ==="); LogError("Total leaked: %zu bytes in %zu allocations", g_total_allocated - g_total_freed, g_allocation_count); MEMORY_BLOCK* current = g_memory_list; while (current) { LogError("  Leak: %zu bytes from %s (thread %lu): %p", current->size, current->function, current->thread_id, current->ptr); current = current->next; } } else { LogInfo("No memory leaks detected."); } LeaveCriticalSection(&g_memory_lock); }
#define SAFE_ALLOC(size) TrackedAlloc(size, __FUNCTION__)
#define SAFE_FREE(ptr) TrackedFree(ptr, __FUNCTION__)
#else
#define SAFE_ALLOC(size) calloc(1, size)
#define SAFE_FREE(ptr) free(ptr)
#define ReportMemoryLeaks()
#endif

// --- Допоміжні функції для емуляції ---
void ParseMacAddress(const char* macStr, BYTE* target) { sscanf_s(macStr, "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx", &target[0], &target[1], &target[2], &target[3], &target[4], &target[5]); }
FakeAdapter* FindAdapterByIndex(DWORD index) { for (int i = 0; i < g_NetworkState.adapterCount; ++i) { if (g_NetworkState.adapters[i].index == index) return &g_NetworkState.adapters[i]; } return NULL; }
void InitializeHardcodedConfig() { LogInfo("Initializing hardcoded network configuration..."); g_NetworkState.nextNTEContext = 1000; g_NetworkState.adapterCount = 0; g_NetworkState.arpCacheCount = 0; FakeAdapter* adapter1 = &g_NetworkState.adapters[g_NetworkState.adapterCount++]; strcpy_s(adapter1->name, sizeof(adapter1->name), "{A1B2C3D4-E5F6-1234-5678-ABCDEF123456}"); strcpy_s(adapter1->description, sizeof(adapter1->description), "Virtual Ethernet (Enabled)"); adapter1->type = IF_TYPE_ETHERNET_CSMACD; adapter1->index = 1; adapter1->dwAdminStatus = MIB_IF_ADMIN_STATUS_UP; ParseMacAddress("00-1A-2B-3C-4D-5E", adapter1->macAddress); FakeIpAddress* ip1 = &adapter1->ipAddresses[adapter1->ipCount++]; strcpy_s(ip1->ipAddress, sizeof(ip1->ipAddress), "192.168.1.100"); strcpy_s(ip1->ipMask, sizeof(ip1->ipMask), "255.255.255.0"); ip1->dwAddr = inet_addr(ip1->ipAddress); ip1->dwMask = inet_addr(ip1->ipMask); ip1->NTEContext = g_NetworkState.nextNTEContext++; FakeAdapter* adapter2 = &g_NetworkState.adapters[g_NetworkState.adapterCount++]; strcpy_s(adapter2->name, sizeof(adapter2->name), "{B2C3D4E5-F6A7-4321-8765-FEDCBA654321}"); strcpy_s(adapter2->description, sizeof(adapter2->description), "Emulated Wi-Fi (Disabled)"); adapter2->type = IF_TYPE_IEEE80211; adapter2->index = 2; adapter2->dwAdminStatus = MIB_IF_ADMIN_STATUS_DOWN; ParseMacAddress("F0-E1-D2-C3-B4-A5", adapter2->macAddress); adapter2->ipCount = 0; FakeArpEntry* arp1 = &g_NetworkState.arpCache[g_NetworkState.arpCacheCount++]; arp1->dwAddr = inet_addr("192.168.1.1"); ParseMacAddress("A0-B1-C2-D3-E4-F5", arp1->macAddress); FakeArpEntry* arp2 = &g_NetworkState.arpCache[g_NetworkState.arpCacheCount++]; arp2->dwAddr = inet_addr("192.168.1.254"); ParseMacAddress("01-02-03-04-05-06", arp2->macAddress); LogInfo("Hardcoded config initialized. Adapters: %d, ARP entries: %d", g_NetworkState.adapterCount, g_NetworkState.arpCacheCount); }

#define STUB_LOG LogDebug("STUB: %s called", __FUNCTION__)
#define STUB_SUCCESS_DWORD(val) do { STUB_LOG; SetLastError(NO_ERROR); return (val); } while (0)
#define STUB_FAIL_DWORD(val, err) do { STUB_LOG; SetLastError(err); return (val); } while (0)

// --- Універсальні заглушки для .def файлу ---
DWORD WINAPI ex_StubNotSupported() { STUB_FAIL_DWORD(ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED); }
DWORD WINAPI ex_StubNoData() { STUB_FAIL_DWORD(ERROR_NO_DATA, ERROR_NO_DATA); }
DWORD WINAPI ex_StubSuccess() { STUB_SUCCESS_DWORD(NO_ERROR); }

// --- "Розумні" реалізації ---
DWORD WINAPI ex_SetIfEntry(PMIB_IFROW pIfRow) { LogInfo("SetIfEntry(IfIndex: %lu, AdminStatus: %lu)", pIfRow->dwIndex, pIfRow->dwAdminStatus); FakeAdapter* adapter = FindAdapterByIndex(pIfRow->dwIndex); if (!adapter) { LogWarning(" -> Adapter with index %lu not found.", pIfRow->dwIndex); return ERROR_NOT_FOUND; } adapter->dwAdminStatus = pIfRow->dwAdminStatus; LogInfo(" -> Success. Adapter %lu AdminStatus set to %lu.", pIfRow->dwIndex, pIfRow->dwAdminStatus); return NO_ERROR; }
DWORD WINAPI ex_DeleteIPAddress(ULONG NTEContext) { LogInfo("DeleteIPAddress(NTEContext: %lu)", NTEContext); for (int i = 0; i < g_NetworkState.adapterCount; ++i) { FakeAdapter* adapter = &g_NetworkState.adapters[i]; for (int j = 0; j < adapter->ipCount; ++j) { if (adapter->ipAddresses[j].NTEContext == NTEContext) { for (int k = j; k < adapter->ipCount - 1; ++k) adapter->ipAddresses[k] = adapter->ipAddresses[k + 1]; adapter->ipCount--; LogInfo(" -> Success. IP Address with NTEContext %lu deleted.", NTEContext); return NO_ERROR; } } } LogWarning(" -> IP Address with NTEContext %lu not found.", NTEContext); return ERROR_NOT_FOUND; }
DWORD WINAPI ex_SendARP(IPAddr DestIP, IPAddr SrcIP, PVOID pMacAddr, PULONG PhyAddrLen) { IN_ADDR dest_addr = { .S_un.S_addr = DestIP }; LogInfo("SendARP(DestIP: %s)", inet_ntoa(dest_addr)); if (!pMacAddr || !PhyAddrLen || *PhyAddrLen < 6) return ERROR_BAD_ARGUMENTS; for (int i = 0; i < g_NetworkState.arpCacheCount; ++i) { if (g_NetworkState.arpCache[i].dwAddr == DestIP) { memcpy(pMacAddr, g_NetworkState.arpCache[i].macAddress, 6); *PhyAddrLen = 6; LogInfo(" -> Found in static ARP cache."); return NO_ERROR; } } for (int i = 0; i < g_NetworkState.adapterCount; ++i) { FakeAdapter* adapter = &g_NetworkState.adapters[i]; if (adapter->dwAdminStatus != MIB_IF_ADMIN_STATUS_UP || adapter->ipCount == 0) continue; for (int j = 0; j < adapter->ipCount; ++j) { FakeIpAddress* ip = &adapter->ipAddresses[j]; if ((ip->dwAddr & ip->dwMask) == (DestIP & ip->dwMask)) { BYTE simulatedMac[6] = {0x0A, 0x51, 0xDE, 0xAD, 0xBE, 0xEF}; simulatedMac[4] = (BYTE)((DestIP >> 16) & 0xFF); simulatedMac[5] = (BYTE)(DestIP >> 24); memcpy(pMacAddr, simulatedMac, 6); *PhyAddrLen = 6; LogInfo(" -> Simulated successful ARP reply on subnet of adapter %lu.", adapter->index); return NO_ERROR; } } } LogWarning(" -> Host unreachable."); return ERROR_HOST_UNREACHABLE; }
ULONG WINAPI ex_GetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen) { LogInfo("GetAdaptersInfo called."); if (!pOutBufLen) return ERROR_INVALID_PARAMETER; ULONG requiredSize = 0; for(int i=0; i<g_NetworkState.adapterCount; ++i) { requiredSize += sizeof(IP_ADAPTER_INFO); } if (*pOutBufLen < requiredSize) { *pOutBufLen = requiredSize; LogWarning(" -> Buffer too small. Required: %lu, Provided: %lu", requiredSize, *pOutBufLen); return ERROR_BUFFER_OVERFLOW; } if (g_NetworkState.adapterCount == 0) { *pOutBufLen = 0; LogInfo(" -> No adapters found."); return ERROR_NO_DATA; } memset(pAdapterInfo, 0, *pOutBufLen); PIP_ADAPTER_INFO pCurrent = pAdapterInfo; for (int i = 0; i < g_NetworkState.adapterCount; ++i) { const FakeAdapter* fake = &g_NetworkState.adapters[i]; strcpy_s(pCurrent->AdapterName, sizeof(pCurrent->AdapterName), fake->name); strcpy_s(pCurrent->Description, sizeof(pCurrent->Description), fake->description); pCurrent->AddressLength = 6; memcpy(pCurrent->Address, fake->macAddress, 6); pCurrent->Index = fake->index; pCurrent->Type = fake->type; pCurrent->DhcpEnabled = TRUE; IP_ADDR_STRING* pIpAddr = &pCurrent->IpAddressList; for(int j = 0; j < fake->ipCount; ++j) { const FakeIpAddress* ip = &fake->ipAddresses[j]; strcpy_s(pIpAddr->IpAddress.String, sizeof(pIpAddr->IpAddress.String), ip->ipAddress); strcpy_s(pIpAddr->IpMask.String, sizeof(pIpAddr->IpMask.String), ip->ipMask); pIpAddr->Context = ip->NTEContext; } if (i < g_NetworkState.adapterCount - 1) { pCurrent->Next = (IP_ADAPTER_INFO*)((BYTE*)pCurrent + sizeof(IP_ADAPTER_INFO)); pCurrent = pCurrent->Next; } else { pCurrent->Next = NULL; } } LogInfo(" -> Success. Returned info for %d adapters.", g_NetworkState.adapterCount); return NO_ERROR; }
DWORD WINAPI ex_GetIfTable(PMIB_IFTABLE pIfTable, PULONG pdwSize, WINBOOL bOrder) { LogInfo("GetIfTable called."); if (!pdwSize) return ERROR_INVALID_PARAMETER; DWORD requiredSize = sizeof(DWORD) + g_NetworkState.adapterCount * sizeof(MIB_IFROW); if (*pdwSize < requiredSize) { *pdwSize = requiredSize; LogWarning(" -> Buffer too small. Required: %lu, Provided: %lu", requiredSize, *pdwSize); return ERROR_INSUFFICIENT_BUFFER; } if (g_NetworkState.adapterCount == 0) { if(pIfTable) pIfTable->dwNumEntries = 0; *pdwSize = sizeof(DWORD); LogInfo(" -> No interfaces found."); return NO_ERROR; } pIfTable->dwNumEntries = g_NetworkState.adapterCount; for (int i = 0; i < g_NetworkState.adapterCount; ++i) { const FakeAdapter* fake = &g_NetworkState.adapters[i]; PMIB_IFROW row = &pIfTable->table[i]; memset(row, 0, sizeof(MIB_IFROW)); row->dwIndex = fake->index; row->dwType = fake->type; row->dwPhysAddrLen = 6; memcpy(row->bPhysAddr, fake->macAddress, 6); MultiByteToWideChar(CP_ACP, 0, fake->description, -1, row->wszName, MAX_INTERFACE_NAME_LEN); row->dwMtu = 1500; row->dwSpeed = 100000000; row->dwAdminStatus = fake->dwAdminStatus; row->dwOperStatus = (fake->dwAdminStatus == MIB_IF_ADMIN_STATUS_UP) ? MIB_IF_OPER_STATUS_OPERATIONAL : MIB_IF_OPER_STATUS_NON_OPERATIONAL; } *pdwSize = requiredSize; LogInfo(" -> Success. Returned %d interface entries.", g_NetworkState.adapterCount); return NO_ERROR; }
DWORD WINAPI ex_GetIpAddrTable(PMIB_IPADDRTABLE pIpAddrTable, PULONG pdwSize, WINBOOL bOrder) { LogInfo("GetIpAddrTable called."); if (!pdwSize) return ERROR_INVALID_PARAMETER; int totalIps = 0; for (int i = 0; i < g_NetworkState.adapterCount; ++i) totalIps += g_NetworkState.adapters[i].ipCount; DWORD requiredSize = sizeof(DWORD) + totalIps * sizeof(MIB_IPADDRROW); if (*pdwSize < requiredSize) { *pdwSize = requiredSize; LogWarning(" -> Buffer too small. Required: %lu, Provided: %lu", requiredSize, *pdwSize); return ERROR_INSUFFICIENT_BUFFER; } if (totalIps == 0) { if(pIpAddrTable) pIpAddrTable->dwNumEntries = 0; *pdwSize = sizeof(DWORD); LogInfo(" -> No IP addresses found."); return NO_ERROR; } pIpAddrTable->dwNumEntries = totalIps; int currentRow = 0; for (int i = 0; i < g_NetworkState.adapterCount; ++i) { const FakeAdapter* fake = &g_NetworkState.adapters[i]; for (int j = 0; j < fake->ipCount; ++j) { const FakeIpAddress* ip = &fake->ipAddresses[j]; PMIB_IPADDRROW row = &pIpAddrTable->table[currentRow++]; row->dwAddr = ip->dwAddr; row->dwIndex = fake->index; row->dwMask = ip->dwMask; row->dwBCastAddr = ip->dwAddr | (~ip->dwMask); row->dwReasmSize = 0; row->wType = MIB_IPADDR_PRIMARY; } } *pdwSize = requiredSize; LogInfo(" -> Success. Returned %d IP address entries.", totalIps); return NO_ERROR; }
DWORD WINAPI ex_GetNumberOfInterfaces(PDWORD pdwNumIf) { LogInfo("GetNumberOfInterfaces called."); if (!pdwNumIf) return ERROR_INVALID_PARAMETER; *pdwNumIf = g_NetworkState.adapterCount; LogInfo(" -> Returning %d interfaces.", *pdwNumIf); return NO_ERROR; }
void WINAPI ex_FreeMibTable(PVOID Memory) { LogDebug("STUB: FreeMibTable called for memory %p", Memory); SAFE_FREE(Memory); }
DWORD WINAPI ex_GetNetworkParams(PFIXED_INFO pFixedInfo, PULONG pOutBufLen) { STUB_FAIL_DWORD(ERROR_BUFFER_OVERFLOW, ERROR_BUFFER_OVERFLOW); }
DWORD WINAPI ex_GetIpForwardTable(PMIB_IPFORWARDTABLE pIpForwardTable, PULONG pdwSize, BOOL bOrder) { STUB_FAIL_DWORD(ERROR_INSUFFICIENT_BUFFER, ERROR_INSUFFICIENT_BUFFER); }
DWORD WINAPI ex_GetBestInterface(IPAddr dwDestAddr, PDWORD pdwBestIfIndex) { if (pdwBestIfIndex) *pdwBestIfIndex = 1; STUB_SUCCESS_DWORD(NO_ERROR); }
DWORD WINAPI ex_GetPerAdapterInfo(ULONG IfIndex, PIP_PER_ADAPTER_INFO pPerAdapterInfo, PULONG pOutBufLen) { STUB_FAIL_DWORD(ERROR_BUFFER_OVERFLOW, ERROR_BUFFER_OVERFLOW); }

// --- Усі інші функції, згенеровані для .def файлу ---
DWORD WINAPI ex_AllocateAndGetTcpExTableFromStack(void* p, void* v, void* o, void* a, void* f) { return ex_StubNotSupported(); }
DWORD WINAPI ex_AddIPAddress() { return ex_StubNotSupported(); }
DWORD WINAPI ex_AllocateAndGetInterfaceInfoFromStack() { return ex_StubNotSupported(); }
DWORD WINAPI ex_AllocateAndGetIpAddrTableFromStack() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CancelIPChangeNotify() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CancelIfTimestampConfigChange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CancelMibChangeNotify2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CaptureInterfaceHardwareCrossTimestamp() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CloseCompartment() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CloseGetIPPhysicalInterfaceForDestination() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertCompartmentGuidToId() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertCompartmentIdToGuid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertGuidToStringA() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertGuidToStringW() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceAliasToLuid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceGuidToLuid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceIndexToLuid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToAlias() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToGuid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToIndex() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToNameA() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceLuidToNameW() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceNameToLuidA() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfaceNameToLuidW() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertInterfacePhysicalAddressToLuid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertIpv4MaskToLength() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertLengthToIpv4Mask() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceAliasToLuid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceGuidToLuid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceIndexToLuid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceLuidToAlias() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceLuidToGuid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertRemoteInterfaceLuidToIndex() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertStringToGuidA() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertStringToGuidW() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ConvertStringToInterfacePhysicalAddress() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateAnycastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateCompartment() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateFlVirtualInterface() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateIpForwardEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateIpForwardEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateIpNetEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateIpNetEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CreatePersistentTcpPortReservation() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CreatePersistentUdpPortReservation() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateProxyArpEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateSortedAddressPairs() { return ex_StubNotSupported(); }
DWORD WINAPI ex_CreateUnicastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteAnycastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteCompartment() { return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteFlVirtualInterface() { return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteIpForwardEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteIpForwardEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteIpNetEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteIpNetEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_DeletePersistentTcpPortReservation() { return ex_StubNotSupported(); }
DWORD WINAPI ex_DeletePersistentUdpPortReservation() { return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteProxyArpEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_DeleteUnicastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_DisableMediaSense() { return ex_StubNotSupported(); }
DWORD WINAPI ex_EnableRouter() { return ex_StubNotSupported(); }
DWORD WINAPI ex_FlushIpNetTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_FlushIpNetTable2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_FlushIpPathTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_FreeDnsSettings() { return ex_StubNotSupported(); }
DWORD WINAPI ex_FreeInterfaceDnsSettings() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetAdapterIndex() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetAdapterOrderMap() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetAdaptersAddresses() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetAnycastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetAnycastIpAddressTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetBestInterfaceEx() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetBestRoute() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetBestRoute2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetCurrentThreadCompartmentId() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetCurrentThreadCompartmentScope() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetDefaultCompartmentId() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetDnsSettings() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetFlVirtualInterface() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetFlVirtualInterfaceTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetFriendlyIfIndex() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIcmpStatistics() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIcmpStatisticsEx() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfEntry2Ex() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfStackTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfTable2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIfTable2Ex() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceActiveTimestampCapabilities() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceCompartmentId() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceCurrentTimestampCapabilities() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceDnsSettings() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceHardwareTimestampCapabilities() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceInfo() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInterfaceSupportedTimestampCapabilities() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetInvertedIfStackTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpErrorString() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpForwardEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpForwardTable2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpInterfaceEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpInterfaceTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpNetEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpNetTable2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpNetworkConnectionBandwidthEstimates() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpPathEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpPathTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpStatistics() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetIpStatisticsEx() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetJobCompartmentId() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetMulticastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetMulticastIpAddressTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetNetworkConnectivityHint() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetNetworkConnectivityHintForInterface() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetNetworkInformation() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromPidAndInfo() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromTcp6Entry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromTcpEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromUdp6Entry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetOwnerModuleFromUdpEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetPerTcp6ConnectionEStats() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetPerTcp6ConnectionStats() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetPerTcpConnectionEStats() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetPerTcpConnectionStats() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetRTTAndHopCount() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetSessionCompartmentId() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcp6Table2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcpStatisticsEx2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcpTable2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTeredoPort() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUdpStatisticsEx2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUniDirectionalAdapterInfo() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUnicastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUnicastIpAddressTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetWPAOACSupportLevel() { return ex_StubNotSupported(); }
DWORD WINAPI ex_Icmp6CreateFile() { return ex_StubNotSupported(); }
DWORD WINAPI ex_Icmp6ParseReplies() { return ex_StubNotSupported(); }
DWORD WINAPI ex_Icmp6SendEcho2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_IcmpCloseHandle() { return ex_StubNotSupported(); }
DWORD WINAPI ex_IcmpCreateFile() { return ex_StubNotSupported(); }
DWORD WINAPI ex_IcmpParseReplies() { return ex_StubNotSupported(); }
DWORD WINAPI ex_IcmpSendEcho() { return ex_StubNotSupported(); }
DWORD WINAPI ex_IcmpSendEcho2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_IcmpSendEcho2Ex() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InitializeCompartmentEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InitializeFlVirtualInterfaceEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InitializeIpForwardEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InitializeIpInterfaceEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InitializeUnicastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCleanupPersistentStore() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateAnycastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateIpForwardEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateIpForwardEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateIpNetEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateIpNetEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateOrRefIpForwardEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalCreateUnicastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteAnycastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteIpForwardEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteIpForwardEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteIpNetEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteIpNetEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalDeleteUnicastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalFindInterfaceByAddress() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetAnycastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetAnycastIpAddressTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetBoundTcp6EndpointTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetBoundTcpEndpointTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetForwardIpTable2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIPPhysicalInterfaceForDestination() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIfEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIfTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIfTable2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpAddrTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpForwardEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpForwardTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpInterfaceEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpInterfaceTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpNetEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpNetTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetIpNetTable2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetMulticastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetMulticastIpAddressTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetRtcSlotInformation() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcp6Table2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcp6TableWithOwnerModule() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcp6TableWithOwnerPid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpDynamicPortRange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTable2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTableEx() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTableWithOwnerModule() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTcpTableWithOwnerPid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetTunnelPhysicalAdapter() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdp6Table2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdp6TableWithOwnerModule() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdp6TableWithOwnerPid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpDynamicPortRange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTable2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTableEx() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTableWithOwnerModule() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUdpTableWithOwnerPid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUnicastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalGetUnicastIpAddressTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalIcmpCreateFileEx() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIfEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpForwardEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpForwardEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpInterfaceEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpNetEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpNetEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetIpStats() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetTcpDynamicPortRange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetTcpEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetTeredoPort() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetUdpDynamicPortRange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_InternalSetUnicastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_IpReleaseAddress() { return ex_StubNotSupported(); }
DWORD WINAPI ex_IpRenewAddress() { return ex_StubNotSupported(); }
DWORD WINAPI ex_LookupPersistentTcpPortReservation() { return ex_StubNotSupported(); }
DWORD WINAPI ex_LookupPersistentUdpPortReservation() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NTPTimeToNTFileTime() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NTTimeToNTPTime() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NhGetGuidFromInterfaceName() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NhGetInterfaceDescriptionFromGuid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NhGetInterfaceNameFromDeviceGuid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NhGetInterfaceNameFromGuid() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NhpAllocateAndGetInterfaceInfoFromStack() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyAddrChange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyCompartmentChange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyIfTimestampConfigChange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyIpInterfaceChange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyNetworkConnectivityHintChange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyRouteChange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyRouteChange2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyStableUnicastIpAddressTable() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyTeredoPortChange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_NotifyUnicastIpAddressChange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_OpenCompartment() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ParseNetworkString() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfAddFiltersToInterface() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfAddGlobalFilterToInterface() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfBindInterfaceToIPAddress() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfBindInterfaceToIndex() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfCreateInterface() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfDeleteInterface() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfDeleteLog() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfGetInterfaceStatistics() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfMakeLog() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfRebindFilters() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfRemoveFilterHandles() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfRemoveFiltersFromInterface() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfRemoveGlobalFilterFromInterface() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfSetLogBuffer() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfTestPacket() { return ex_StubNotSupported(); }
DWORD WINAPI ex_PfUnBindInterface() { return ex_StubNotSupported(); }
DWORD WINAPI ex_RegisterInterfaceTimestampConfigChange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ResolveIpNetEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_ResolveNeighbor() { return ex_StubNotSupported(); }
DWORD WINAPI ex_RestoreMediaSense() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetAdapterIpAddress() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetCurrentThreadCompartmentId() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetCurrentThreadCompartmentScope() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetDnsSettings() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetFlVirtualInterface() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetInterfaceDnsSettings() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpForwardEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpForwardEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpInterfaceEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpNetEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpNetEntry2() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpStatistics() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpStatisticsEx() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetIpTTL() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetJobCompartmentId() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetNetworkInformation() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetPerTcp6ConnectionEStats() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetPerTcp6ConnectionStats() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetPerTcpConnectionEStats() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetPerTcpConnectionStats() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetSessionCompartmentId() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetTcpEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_SetUnicastIpAddressEntry() { return ex_StubNotSupported(); }
DWORD WINAPI ex_UnenableRouter() { return ex_StubNotSupported(); }
DWORD WINAPI ex_UnregisterInterfaceTimestampConfigChange() { return ex_StubNotSupported(); }
DWORD WINAPI ex_do_echo_rep() { return ex_StubNotSupported(); }
DWORD WINAPI ex_do_echo_req() { return ex_StubNotSupported(); }
DWORD WINAPI ex_if_indextoname() { return ex_StubNotSupported(); }
DWORD WINAPI ex_if_nametoindex() { return ex_StubNotSupported(); }
DWORD WINAPI ex_register_icmp() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetExtendedTcpTable() { return ex_StubNoData(); }
DWORD WINAPI ex_GetExtendedUdpTable() { return ex_StubNoData(); }
DWORD WINAPI ex_GetIpNetTable() { return ex_StubNoData(); }
DWORD WINAPI ex_GetTcp6Table() { return ex_StubNoData(); }
DWORD WINAPI ex_GetTcpStatistics() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcpStatisticsEx() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetTcpTable() { return ex_StubNoData(); }
DWORD WINAPI ex_GetUdpStatistics() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUdpStatisticsEx() { return ex_StubNotSupported(); }
DWORD WINAPI ex_GetUdp6Table() { return ex_StubNoData(); }
DWORD WINAPI ex_GetUdpTable() { return ex_StubNoData(); }
BOOL WINAPI ex_InternetSetSecureLegacyServersAppCompat() { STUB_FAIL_DWORD(ERROR_NOT_SUPPORTED, ERROR_NOT_SUPPORTED); return FALSE; }

// ============================================================================
// === DLLMAIN ===
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
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
            FILE* fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
            SetConsoleTitleA("IPHLPAPI Stub Debug Console v1.0");
        }
#endif
#if ENABLE_FILE_LOGGING
        {
            char log_path[MAX_PATH]; char exe_path[MAX_PATH]; GetModuleFileNameA(NULL, exe_path, MAX_PATH);
            char* last_slash = strrchr(exe_path, '\\'); if (last_slash) *(last_slash + 1) = '\0';
            snprintf(log_path, MAX_PATH, "%siphlpapi_mock.log", exe_path);
            fopen_s(&g_log_file, log_path, "a");
        }
#endif
        LogInfo("=== IPHLPAPI STUB v1.0 LOADED ==="); LogInfo("Build: %s %s", __DATE__, __TIME__);
        InitializeHardcodedConfig();
        break;
    case DLL_PROCESS_DETACH:
        LogInfo("=== IPHLPAPI STUB v1.0 UNLOADING ===");
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
        printf("\nIPHLPAPI Stub Unloading complete...\n"); FreeConsole();
#endif
        break;
    }
    return TRUE;
}

#ifdef __cplusplus
}
#endif