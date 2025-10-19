// ============================================================================
// iphlpapi_stub.c
//
// Версія: 1.0

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Включаємо необхідні заголовки для визначення структур
#include <iprtrmib.h>
#include <ipexport.h>
#include <iptypes.h>

// --- Макроси та константи ---
#define MAX_ADAPTERS 8
#define MAX_IPS_PER_ADAPTER 4
#define MAX_ARP_ENTRIES 16

// Константи для налагодження (1 = увімкнено, 0 = вимкнено)
#define ENABLE_DEBUG_CONSOLE 0
#define ENABLE_FILE_LOGGING 0

// --- Розширені структури для динамічного стану ---
typedef struct {
    char ipAddress[16];
    char ipMask[16];
    DWORD dwAddr;
    DWORD dwMask;
    ULONG NTEContext; // Унікальний ідентифікатор для DeleteIPAddress
} FakeIpAddress;

typedef struct {
    char name[MAX_ADAPTER_NAME_LENGTH + 4];
    char description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
    DWORD type;
    DWORD index;
    DWORD dwAdminStatus; // MIB_IF_ADMIN_STATUS_UP (1) or DOWN (2)
    BYTE macAddress[MAX_ADAPTER_ADDRESS_LENGTH];
    int ipCount;
    FakeIpAddress ipAddresses[MAX_IPS_PER_ADAPTER];
} FakeAdapter;

typedef struct {
    DWORD dwAddr;
    BYTE macAddress[6];
} FakeArpEntry;

typedef struct {
    int adapterCount;
    FakeAdapter adapters[MAX_ADAPTERS];
    int arpCacheCount;
    FakeArpEntry arpCache[MAX_ARP_ENTRIES];
    ULONG nextNTEContext;
} NetworkState;

// --- Глобальний стан емулятора ---
static NetworkState g_NetworkState = {0};

#if ENABLE_FILE_LOGGING
static FILE* hLogFile = NULL;
static CRITICAL_SECTION csLog;
#endif

// --- Допоміжні функції ---
void LogMessage(const char* format, ...) {
    #if ENABLE_FILE_LOGGING || ENABLE_DEBUG_CONSOLE
    char buffer[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    buffer[sizeof(buffer) - 1] = '\0';
    
    #if ENABLE_FILE_LOGGING
    EnterCriticalSection(&csLog);
    if (hLogFile) {
        fprintf(hLogFile, "%s\n", buffer);
        fflush(hLogFile);
    }
    LeaveCriticalSection(&csLog);
    #endif
    
    #if ENABLE_DEBUG_CONSOLE
    printf("[STUB] %s\n", buffer);
    #endif
    #endif
}

// Власна реалізація inet_addr
unsigned long ex_inet_addr(const char* cp) {
    if (!cp) return INADDR_NONE;
    unsigned long val = 0, part = 0;
    int dots = 0;
    char ch;
    while ((ch = *cp++)) {
        if (ch >= '0' && ch <= '9') {
            part = part * 10 + (ch - '0');
            if (part > 255) return INADDR_NONE;
        } else if (ch == '.') {
            if (++dots > 3) return INADDR_NONE;
            val = (val << 8) | part;
            part = 0;
        } else return INADDR_NONE;
    }
    if (dots != 3) return INADDR_NONE;
    val = (val << 8) | part;
    return ((val & 0xff000000) >> 24) | ((val & 0x00ff0000) >> 8) |
           ((val & 0x0000ff00) << 8)  | ((val & 0x000000ff) << 24);
}

// Власна реалізація inet_ntoa
char* ex_inet_ntoa(DWORD addr) {
    static char buffer[16];
    unsigned char* bytes = (unsigned char*)&addr;
    sprintf_s(buffer, sizeof(buffer), "%u.%u.%u.%u", 
              bytes[0], bytes[1], bytes[2], bytes[3]);
    return buffer;
}

void ParseMacAddress(const char* macStr, BYTE* target) {
    sscanf_s(macStr, "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx",
           &target[0], &target[1], &target[2], &target[3], &target[4], &target[5]);
}

FakeAdapter* FindAdapterByIndex(DWORD index) {
    for (int i = 0; i < g_NetworkState.adapterCount; ++i) {
        if (g_NetworkState.adapters[i].index == index) {
            return &g_NetworkState.adapters[i];
        }
    }
    return NULL;
}

// --- Ініціалізація конфігурації (замість INI-файлу) ---
void InitializeHardcodedConfig() {
    LogMessage("Initializing hardcoded network configuration...");
    
    g_NetworkState.nextNTEContext = 1000;
    g_NetworkState.adapterCount = 0;
    g_NetworkState.arpCacheCount = 0;

    // ==================== Адаптер 1 ====================
    FakeAdapter* adapter1 = &g_NetworkState.adapters[g_NetworkState.adapterCount++];
    strcpy_s(adapter1->name, sizeof(adapter1->name), "{A1B2C3D4-E5F6-1234-5678-ABCDEF123456}");
    strcpy_s(adapter1->description, sizeof(adapter1->description), "Virtual Ethernet (Enabled)");
    adapter1->type = 6; // IF_TYPE_ETHERNET_CSMACD
    adapter1->index = 1;
    adapter1->dwAdminStatus = MIB_IF_ADMIN_STATUS_UP;
    ParseMacAddress("00-1A-2B-3C-4D-5E", adapter1->macAddress);
    
    // IP адреса для адаптера 1
    FakeIpAddress* ip1 = &adapter1->ipAddresses[adapter1->ipCount++];
    strcpy_s(ip1->ipAddress, sizeof(ip1->ipAddress), "192.168.1.100");
    strcpy_s(ip1->ipMask, sizeof(ip1->ipMask), "255.255.255.0");
    ip1->dwAddr = ex_inet_addr(ip1->ipAddress);
    ip1->dwMask = ex_inet_addr(ip1->ipMask);
    ip1->NTEContext = g_NetworkState.nextNTEContext++;

    // ==================== Адаптер 2 ====================
    FakeAdapter* adapter2 = &g_NetworkState.adapters[g_NetworkState.adapterCount++];
    strcpy_s(adapter2->name, sizeof(adapter2->name), "{B2C3D4E5-F6A7-4321-8765-FEDCBA654321}");
    strcpy_s(adapter2->description, sizeof(adapter2->description), "Emulated Wi-Fi (Disabled by default)");
    adapter2->type = 71; // IF_TYPE_IEEE80211
    adapter2->index = 2;
    adapter2->dwAdminStatus = MIB_IF_ADMIN_STATUS_DOWN;
    ParseMacAddress("F0-E1-D2-C3-B4-A5", adapter2->macAddress);
    adapter2->ipCount = 0;

    // ==================== ARP кеш ====================
    FakeArpEntry* arp1 = &g_NetworkState.arpCache[g_NetworkState.arpCacheCount++];
    arp1->dwAddr = ex_inet_addr("192.168.1.1");
    ParseMacAddress("A0-B1-C2-D3-E4-F5", arp1->macAddress);

    FakeArpEntry* arp2 = &g_NetworkState.arpCache[g_NetworkState.arpCacheCount++];
    arp2->dwAddr = ex_inet_addr("192.168.1.254");
    ParseMacAddress("01-02-03-04-05-06", arp2->macAddress);
    
    LogMessage("Hardcoded config initialized. Adapters: %d, ARP entries: %d", 
               g_NetworkState.adapterCount, g_NetworkState.arpCacheCount);
}

// --- Універсальні заглушки ---
DWORD WINAPI ex_StubSuccess() { SetLastError(NO_ERROR); return NO_ERROR; }
DWORD WINAPI ex_StubNotSupported() { SetLastError(ERROR_NOT_SUPPORTED); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_StubNoData() { SetLastError(ERROR_NO_DATA); return ERROR_NO_DATA; }

// --- "Розумні" реалізації ---

// DWORD WINAPI SetIfEntry(PMIB_IFROW pIfRow);
DWORD WINAPI ex_SetIfEntry(PMIB_IFROW pIfRow) {
    LogMessage("SetIfEntry called for IfIndex: %lu, AdminStatus: %lu", pIfRow->dwIndex, pIfRow->dwAdminStatus);
    FakeAdapter* adapter = FindAdapterByIndex(pIfRow->dwIndex);
    if (!adapter) {
        LogMessage(" -> Adapter with index %lu not found.", pIfRow->dwIndex);
        return ERROR_NOT_FOUND;
    }
    adapter->dwAdminStatus = pIfRow->dwAdminStatus;
    LogMessage(" -> Success. Adapter %lu AdminStatus set to %lu.", pIfRow->dwIndex, pIfRow->dwAdminStatus);
    return NO_ERROR;
}

// DWORD WINAPI DeleteIPAddress(ULONG NTEContext);
DWORD WINAPI ex_DeleteIPAddress(ULONG NTEContext) {
    LogMessage("DeleteIPAddress called for NTEContext: %lu", NTEContext);
    for (int i = 0; i < g_NetworkState.adapterCount; ++i) {
        FakeAdapter* adapter = &g_NetworkState.adapters[i];
        for (int j = 0; j < adapter->ipCount; ++j) {
            if (adapter->ipAddresses[j].NTEContext == NTEContext) {
                for (int k = j; k < adapter->ipCount - 1; ++k) {
                    adapter->ipAddresses[k] = adapter->ipAddresses[k + 1];
                }
                adapter->ipCount--;
                LogMessage(" -> Success. IP Address with NTEContext %lu deleted.", NTEContext);
                return NO_ERROR;
            }
        }
    }
    LogMessage(" -> IP Address with NTEContext %lu not found.", NTEContext);
    return ERROR_NOT_FOUND;
}

// DWORD WINAPI SendARP(IPAddr DestIP, IPAddr SrcIP, PVOID pMacAddr, PULONG PhyAddrLen);
DWORD WINAPI ex_SendARP(IPAddr DestIP, IPAddr SrcIP, PVOID pMacAddr, PULONG PhyAddrLen) {
    char* ip_buf = ex_inet_ntoa(DestIP);
    LogMessage("SendARP called for DestIP: %s", ip_buf);
    
    if (!pMacAddr || !PhyAddrLen || *PhyAddrLen < 6) return ERROR_BAD_ARGUMENTS;

    for (int i = 0; i < g_NetworkState.arpCacheCount; ++i) {
        if (g_NetworkState.arpCache[i].dwAddr == DestIP) {
            memcpy(pMacAddr, g_NetworkState.arpCache[i].macAddress, 6);
            *PhyAddrLen = 6;
            LogMessage(" -> Found in static ARP cache.");
            return NO_ERROR;
        }
    }
    
    for (int i = 0; i < g_NetworkState.adapterCount; ++i) {
        FakeAdapter* adapter = &g_NetworkState.adapters[i];
        if (adapter->dwAdminStatus != MIB_IF_ADMIN_STATUS_UP || adapter->ipCount == 0) continue;
        for (int j = 0; j < adapter->ipCount; ++j) {
            FakeIpAddress* ip = &adapter->ipAddresses[j];
            if ((ip->dwAddr & ip->dwMask) == (DestIP & ip->dwMask)) {
                BYTE simulatedMac[6] = {0x0A, 0x51, 0xDE, 0xAD, 0xBE, 0xEF};
                simulatedMac[4] = (BYTE)((DestIP >> 8) & 0xFF);
                simulatedMac[5] = (BYTE)(DestIP & 0xFF);
                memcpy(pMacAddr, simulatedMac, 6);
                *PhyAddrLen = 6;
                LogMessage(" -> Simulated successful ARP reply on subnet of adapter %lu.", adapter->index);
                return NO_ERROR;
            }
        }
    }
    LogMessage(" -> Host unreachable.");
    return ERROR_HOST_UNREACHABLE;
}

// ULONG WINAPI GetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);
ULONG WINAPI ex_GetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen) {
    LogMessage("GetAdaptersInfo called.");
    if (!pOutBufLen) return ERROR_INVALID_PARAMETER;
    DWORD requiredSize = g_NetworkState.adapterCount * sizeof(IP_ADAPTER_INFO);
    if (*pOutBufLen < requiredSize) {
        *pOutBufLen = requiredSize;
        return ERROR_BUFFER_OVERFLOW;
    }
    if (g_NetworkState.adapterCount == 0) {
        *pOutBufLen = 0;
        return ERROR_NO_DATA;
    }
    PIP_ADAPTER_INFO pCurrent = pAdapterInfo;
    memset(pAdapterInfo, 0, requiredSize);
    for (int i = 0; i < g_NetworkState.adapterCount; ++i) {
        const FakeAdapter* fake = &g_NetworkState.adapters[i];
        strcpy_s(pCurrent->AdapterName, sizeof(pCurrent->AdapterName), fake->name);
        strcpy_s(pCurrent->Description, sizeof(pCurrent->Description), fake->description);
        pCurrent->AddressLength = 6;
        memcpy(pCurrent->Address, fake->macAddress, 6);
        pCurrent->Index = fake->index;
        pCurrent->Type = fake->type;
        if (fake->ipCount > 0) {
            strcpy_s(pCurrent->IpAddressList.IpAddress.String, sizeof(pCurrent->IpAddressList.IpAddress.String), fake->ipAddresses[0].ipAddress);
            strcpy_s(pCurrent->IpAddressList.IpMask.String, sizeof(pCurrent->IpAddressList.IpMask.String), fake->ipAddresses[0].ipMask);
        }
        pCurrent->Next = (i < g_NetworkState.adapterCount - 1) ? (PIP_ADAPTER_INFO)((BYTE*)pCurrent + sizeof(IP_ADAPTER_INFO)) : NULL;
        pCurrent = pCurrent->Next;
    }
    return NO_ERROR;
}

// DWORD WINAPI GetIfTable(PMIB_IFTABLE pIfTable, PULONG pdwSize, WINBOOL bOrder);
DWORD WINAPI ex_GetIfTable(PMIB_IFTABLE pIfTable, PULONG pdwSize, WINBOOL bOrder) {
    LogMessage("GetIfTable called.");
    if (!pdwSize) return ERROR_INVALID_PARAMETER;
    DWORD requiredSize = sizeof(DWORD) + g_NetworkState.adapterCount * sizeof(MIB_IFROW);
    if (*pdwSize < requiredSize) {
        *pdwSize = requiredSize;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    if (g_NetworkState.adapterCount == 0) {
        if(pIfTable) pIfTable->dwNumEntries = 0;
        *pdwSize = sizeof(DWORD);
        return NO_ERROR;
    }
    pIfTable->dwNumEntries = g_NetworkState.adapterCount;
    for (int i = 0; i < g_NetworkState.adapterCount; ++i) {
        const FakeAdapter* fake = &g_NetworkState.adapters[i];
        PMIB_IFROW row = &pIfTable->table[i];
        memset(row, 0, sizeof(MIB_IFROW));
        row->dwIndex = fake->index;
        row->dwType = fake->type;
        row->dwPhysAddrLen = 6;
        memcpy(row->bPhysAddr, fake->macAddress, 6);
        MultiByteToWideChar(CP_ACP, 0, fake->description, -1, row->wszName, MAX_INTERFACE_NAME_LEN);
        row->dwMtu = 1500;
        row->dwSpeed = 100000000;
        row->dwAdminStatus = fake->dwAdminStatus;
        row->dwOperStatus = (fake->dwAdminStatus == MIB_IF_ADMIN_STATUS_UP) ? MIB_IF_OPER_STATUS_OPERATIONAL : MIB_IF_OPER_STATUS_NON_OPERATIONAL;
    }
    *pdwSize = requiredSize;
    return NO_ERROR;
}

// DWORD WINAPI GetIpAddrTable(PMIB_IPADDRTABLE pIpAddrTable, PULONG pdwSize, WINBOOL bOrder);
DWORD WINAPI ex_GetIpAddrTable(PMIB_IPADDRTABLE pIpAddrTable, PULONG pdwSize, WINBOOL bOrder) {
    LogMessage("GetIpAddrTable called.");
    if (!pdwSize) return ERROR_INVALID_PARAMETER;
    int totalIps = 0;
    for (int i = 0; i < g_NetworkState.adapterCount; ++i) totalIps += g_NetworkState.adapters[i].ipCount;
    DWORD requiredSize = sizeof(DWORD) + totalIps * sizeof(MIB_IPADDRROW);
    if (*pdwSize < requiredSize) {
        *pdwSize = requiredSize;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    if (totalIps == 0) {
        if(pIpAddrTable) pIpAddrTable->dwNumEntries = 0;
        *pdwSize = sizeof(DWORD);
        return NO_ERROR;
    }
    pIpAddrTable->dwNumEntries = totalIps;
    int currentRow = 0;
    for (int i = 0; i < g_NetworkState.adapterCount; ++i) {
        const FakeAdapter* fake = &g_NetworkState.adapters[i];
        for (int j = 0; j < fake->ipCount; ++j) {
            const FakeIpAddress* ip = &fake->ipAddresses[j];
            PMIB_IPADDRROW row = &pIpAddrTable->table[currentRow++];
            row->dwAddr = ip->dwAddr;
            row->dwIndex = fake->index;
            row->dwMask = ip->dwMask;
            row->dwBCastAddr = ip->dwAddr | (~ip->dwMask);
            row->dwReasmSize = 0;
            row->wType = MIB_IPADDR_PRIMARY;
        }
    }
    *pdwSize = requiredSize;
    return NO_ERROR;
}

// DWORD WINAPI GetNumberOfInterfaces(PDWORD pdwNumIf);
DWORD WINAPI ex_GetNumberOfInterfaces(PDWORD pdwNumIf) {
    LogMessage("GetNumberOfInterfaces called.");
    if (!pdwNumIf) return ERROR_INVALID_PARAMETER;
    *pdwNumIf = g_NetworkState.adapterCount;
    return NO_ERROR;
}

// --- Точка входу в DLL ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            DisableThreadLibraryCalls(hModule);
            
            #if ENABLE_DEBUG_CONSOLE
            if (AllocConsole()) {
                FILE* fDummy;
                freopen_s(&fDummy, "CONOUT$", "w", stdout);
                freopen_s(&fDummy, "CONOUT$", "w", stderr);
                freopen_s(&fDummy, "CONIN$", "r", stdin);
                SetConsoleTitleA("IPHLPAPI Stub Debug Console");
                printf("=== IPHLPAPI Stub Debug Console ===\n");
                printf("Close this window to terminate the host process!\n\n");
            }
            #endif
            
            #if ENABLE_FILE_LOGGING
            InitializeCriticalSection(&csLog);
            char temp_path[MAX_PATH], log_path[MAX_PATH];
            if (GetTempPathA(MAX_PATH, temp_path) > 0) {
                sprintf_s(log_path, MAX_PATH, "%sEXiphlpapi_stub_log.txt", temp_path);
                fopen_s(&hLogFile, log_path, "a");
                #if ENABLE_DEBUG_CONSOLE
                printf("Log file: %s\n", log_path);
                #endif
            }
            #endif
            
            LogMessage("--- Smart IPHLPAPI Stub Loaded (v4.2) ---");
            InitializeHardcodedConfig();
            break;
        }
        case DLL_PROCESS_DETACH: {
            LogMessage("--- Smart IPHLPAPI Stub Unloading ---");
            
            #if ENABLE_FILE_LOGGING
            if (hLogFile) fclose(hLogFile);
            DeleteCriticalSection(&csLog);
            #endif
            
            #if ENABLE_DEBUG_CONSOLE
            printf("\n=== Stub Unloading ===\n");
            FreeConsole();
            #endif
            break;
        }
    }
    return TRUE;
}