/*
 * NETAPI32 Emulator - Complete Implementation
 * Version: 2.0.0 - Registry-Based Configuration
 * 
 * All configuration stored in: HKEY_CURRENT_USER\Software\EXLOUD\Config
 * Run setup.bat to configure before using!
 */

#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <windows.h>
#include <lm.h>
#include <lmerr.h>
#include <dsgetdc.h>
#include <dsrole.h>
#include <lmjoin.h>
#include <nb30.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * REGISTRY CONFIGURATION
 * ============================================================================
 * All configuration stored in: HKEY_CURRENT_USER\Software\EXLOUD\Config
 * 
 * Registry values:
 *   - ComputerName (REG_SZ)     - Computer name
 *   - UserName (REG_SZ)         - User name
 *   - Workgroup (REG_SZ)        - Workgroup/domain name
 *   - MACAddress (REG_BINARY)   - 6 bytes MAC address
 * 
 * Run setup.bat to configure registry before using!
 * ============================================================================ */

#define REGISTRY_ROOT_W             L"Software\\EXLOUD\\Config"
#define REG_COMPUTER_NAME_W         L"ComputerName"
#define REG_USER_NAME_W             L"UserName"
#define REG_WORKGROUP_W             L"Workgroup"
#define REG_MAC_ADDRESS_W           L"MACAddress"

#define MAX_COMPUTER_NAME_LEN       256
#define MAX_USER_NAME_LEN           256
#define MAX_WORKGROUP_LEN           256
#define MAC_ADDRESS_SIZE            6

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */
#define ENABLE_DEBUG_CONSOLE    1
#define ENABLE_FILE_LOGGING     0

#define MAX_SESS                254

/* ============================================================================
 * GLOBALS
 * ============================================================================ */
typedef enum { LOG_ERROR = 0, LOG_WARN, LOG_INFO, LOG_DEBUG } LogLevel;

#if ENABLE_DEBUG_CONSOLE
static HANDLE g_hConsole = NULL;
#endif

#if ENABLE_FILE_LOGGING
static FILE* g_logFile = NULL;
static CRITICAL_SECTION g_logLock;
static BOOL g_logLockInit = FALSE;
#endif

static volatile LONG g_initCount = 0;
static LogLevel g_logLevel = LOG_DEBUG;

/*
 * REGISTRY-BASED CONFIGURATION (v2.0)
 * All values are loaded from HKEY_CURRENT_USER\Software\EXIPHL\Config
 * 
 * NO FALLBACKS! If registry is not configured, functions return error.
 * Run setup.bat to create registry configuration.
 * 
 * SYNCHRONIZED with iphlpapi.dll - both read from same registry location.
 */
static WCHAR g_computerName[MAX_COMPUTER_NAME_LEN] = {0};
static WCHAR g_userName[MAX_USER_NAME_LEN] = {0};
static WCHAR g_workgroupName[MAX_WORKGROUP_LEN] = {0};
static BYTE g_macAddress[MAC_ADDRESS_SIZE] = {0};

static BOOL g_nbInitialized = FALSE;
static CRITICAL_SECTION g_nbLock;
static UCHAR g_numLanas = 1;

/* ============================================================================
 * LOGGING
 * ============================================================================ */
static void LogMsg(LogLevel level, const char* func, const wchar_t* fmt, ...) {
    if (level > g_logLevel) return;
    WCHAR buf[2048], msg[1024];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf(msg, 1024, fmt, args);
    msg[1023] = 0;
    va_end(args);
    WCHAR funcW[128] = {0};
    MultiByteToWideChar(CP_ACP, 0, func, -1, funcW, 127);
    _snwprintf(buf, 2048, L"[%s] %s\n", funcW, msg);
    buf[2047] = 0;
#if ENABLE_FILE_LOGGING
    if (g_logFile && g_logLockInit) {
        EnterCriticalSection(&g_logLock);
        fwprintf(g_logFile, L"%s", buf);
        fflush(g_logFile);
        LeaveCriticalSection(&g_logLock);
    }
#endif
#if ENABLE_DEBUG_CONSOLE
    if (g_hConsole && g_hConsole != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteConsoleW(g_hConsole, buf, (DWORD)wcslen(buf), &w, NULL);
    }
#endif
}

#define LogI(fmt, ...) LogMsg(LOG_INFO, __FUNCTION__, fmt, ##__VA_ARGS__)

/* ============================================================================
 * REGISTRY HELPERS
 * ============================================================================ */

/**
 * Read wide string value from registry
 * Returns TRUE on success, FALSE on failure
 */
static BOOL ReadRegistryStringW(const WCHAR* valueName, WCHAR* buffer, DWORD bufferSize)
{
    HKEY hKey;
    DWORD dwType = REG_SZ;
    DWORD dwSize = bufferSize * sizeof(WCHAR);
    LONG result;
    
    result = RegOpenKeyExW(HKEY_CURRENT_USER, REGISTRY_ROOT_W, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        LogI(L"Registry key not found: %s", REGISTRY_ROOT_W);
        return FALSE;
    }
    
    result = RegQueryValueExW(hKey, valueName, NULL, &dwType, (LPBYTE)buffer, &dwSize);
    RegCloseKey(hKey);
    
    if (result != ERROR_SUCCESS || dwType != REG_SZ) {
        LogI(L"Registry value not found: %s", valueName);
        return FALSE;
    }
    
    return TRUE;
}

/**
 * Read binary value from registry (for MAC address)
 * Returns TRUE on success, FALSE on failure
 */
static BOOL ReadRegistryBinary(const WCHAR* valueName, BYTE* buffer, DWORD bufferSize)
{
    HKEY hKey;
    DWORD dwType = REG_BINARY;
    DWORD dwSize = bufferSize;
    LONG result;
    
    result = RegOpenKeyExW(HKEY_CURRENT_USER, REGISTRY_ROOT_W, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        LogI(L"Registry key not found: %s", REGISTRY_ROOT_W);
        return FALSE;
    }
    
    result = RegQueryValueExW(hKey, valueName, NULL, &dwType, buffer, &dwSize);
    RegCloseKey(hKey);
    
    if (result != ERROR_SUCCESS || dwType != REG_BINARY) {
        LogI(L"Registry value not found or wrong type: %s", valueName);
        return FALSE;
    }
    
    return TRUE;
}

/* ============================================================================
 * INITIALIZATION
 * ============================================================================ */
static void EnsureInit(void) {
    if (InterlockedCompareExchange(&g_initCount, 1, 0) == 0) {
#if ENABLE_FILE_LOGGING
        InitializeCriticalSection(&g_logLock);
        g_logLockInit = TRUE;
        WCHAR path[MAX_PATH];
        GetTempPathW(MAX_PATH, path);
        wcscat(path, L"netapi32.log");
        g_logFile = _wfopen(path, L"w");
#endif
#if ENABLE_DEBUG_CONSOLE
        AllocConsole();
        g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTitleW(L"NETAPI32 Emulator - Registry Config v2.0");
#endif
        InitializeCriticalSection(&g_nbLock);
        g_nbInitialized = TRUE;
        
        /* 
         * REGISTRY-BASED CONFIGURATION (v2.0)
         * 
         * Load all settings from HKEY_CURRENT_USER\Software\EXIPHL\Config
         * NO FALLBACKS! If registry not configured, leave values empty.
         * Functions will check and return errors if config missing.
         * 
         * SYNCHRONIZED with iphlpapi.dll - both read from same registry.
         */
        
        LogI(L"Loading configuration from registry: %s", REGISTRY_ROOT_W);
        
        /* Load computer name from registry */
        if (!ReadRegistryStringW(REG_COMPUTER_NAME_W, g_computerName, ARRAYSIZE(g_computerName))) {
            LogI(L"ERROR: ComputerName not found in registry!");
            LogI(L"Run setup.bat to configure registry");
            wcscpy(g_computerName, L"<NOT CONFIGURED>");
        }
        
        /* Load user name from registry */
        if (!ReadRegistryStringW(REG_USER_NAME_W, g_userName, ARRAYSIZE(g_userName))) {
            LogI(L"ERROR: UserName not found in registry!");
            LogI(L"Run setup.bat to configure registry");
            wcscpy(g_userName, L"<NOT CONFIGURED>");
        }
        
        /* Load workgroup from registry */
        if (!ReadRegistryStringW(REG_WORKGROUP_W, g_workgroupName, ARRAYSIZE(g_workgroupName))) {
            LogI(L"ERROR: Workgroup not found in registry!");
            LogI(L"Run setup.bat to configure registry");
            wcscpy(g_workgroupName, L"<NOT CONFIGURED>");
        }
        
        /* Load MAC address from registry */
        if (!ReadRegistryBinary(REG_MAC_ADDRESS_W, g_macAddress, MAC_ADDRESS_SIZE)) {
            LogI(L"ERROR: MAC address not found in registry!");
            LogI(L"Run setup.bat to configure registry");
            ZeroMemory(g_macAddress, MAC_ADDRESS_SIZE);
        }
        
        LogI(L"Configuration loaded:");
        LogI(L"  Computer: %s", g_computerName);
        LogI(L"  User:     %s", g_userName);
        LogI(L"  Workgroup: %s", g_workgroupName);
        LogI(L"  MAC:      %02X:%02X:%02X:%02X:%02X:%02X",
             g_macAddress[0], g_macAddress[1], g_macAddress[2],
             g_macAddress[3], g_macAddress[4], g_macAddress[5]);
    }
}

static BOOL IsLocalComputer(LPCWSTR server) {
    if (!server || !*server) return TRUE;
    if (wcsncmp(server, L"\\\\", 2) == 0) server += 2;
    if (!*server) return TRUE;
    if (_wcsicmp(server, L"localhost") == 0) return TRUE;
    if (_wcsicmp(server, g_computerName) == 0) return TRUE;
    return FALSE;
}

/* ============================================================================
 * BUFFER FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetApiBufferAllocate(DWORD ByteCount, LPVOID* Buffer) {
    EnsureInit();
    if (!Buffer) return ERROR_INVALID_PARAMETER;
    *Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ByteCount ? ByteCount : 1);
    return (*Buffer) ? NERR_Success : ERROR_NOT_ENOUGH_MEMORY;
}

NET_API_STATUS WINAPI ex_NetapipBufferAllocate(DWORD ByteCount, LPVOID* Buffer) {
    return ex_NetApiBufferAllocate(ByteCount, Buffer);
}

NET_API_STATUS WINAPI ex_NetApiBufferFree(LPVOID Buffer) {
    if (Buffer) HeapFree(GetProcessHeap(), 0, Buffer);
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetApiBufferReallocate(LPVOID OldBuffer, DWORD NewByteCount, LPVOID* NewBuffer) {
    EnsureInit();
    if (!NewBuffer) return ERROR_INVALID_PARAMETER;
    *NewBuffer = OldBuffer ? 
        HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, OldBuffer, NewByteCount ? NewByteCount : 1) :
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NewByteCount ? NewByteCount : 1);
    return (*NewBuffer) ? NERR_Success : ERROR_NOT_ENOUGH_MEMORY;
}

NET_API_STATUS WINAPI ex_NetApiBufferSize(LPVOID Buffer, LPDWORD ByteCount) {
    EnsureInit();
    if (!Buffer || !ByteCount) return ERROR_INVALID_PARAMETER;
    SIZE_T size = HeapSize(GetProcessHeap(), 0, Buffer);
    *ByteCount = (size == (SIZE_T)-1) ? 0 : (DWORD)size;
    return NERR_Success;
}

/* ============================================================================
 * NETBIOS
 * ============================================================================ */
UCHAR WINAPI ex_Netbios(PNCB ncb) {
    EnsureInit();
    if (!ncb) return NRC_INVADDRESS;
    
    UCHAR cmd = ncb->ncb_command & 0x7F;
    UCHAR ret = NRC_GOODRET;
    
    LogI(L"Netbios cmd=0x%02X lana=%d", cmd, ncb->ncb_lana_num);
    
    EnterCriticalSection(&g_nbLock);
    
    switch (cmd) {
        case NCBENUM: {
            if (!ncb->ncb_buffer || ncb->ncb_length < sizeof(LANA_ENUM)) {
                ret = NRC_BUFLEN;
            } else {
                PLANA_ENUM lanas = (PLANA_ENUM)ncb->ncb_buffer;
                lanas->length = g_numLanas;
                lanas->lana[0] = 0;
            }
            break;
        }
        case NCBRESET:
            ret = (ncb->ncb_lana_num >= g_numLanas) ? NRC_BRIDGE : NRC_GOODRET;
            break;
        case NCBASTAT: {
            if (!ncb->ncb_buffer || ncb->ncb_length < sizeof(ADAPTER_STATUS)) {
                ret = NRC_BUFLEN;
            } else if (ncb->ncb_lana_num >= g_numLanas) {
                ret = NRC_BRIDGE;
            } else {
                /* Check if MAC address was loaded from registry */
                if (g_macAddress[0] == 0 && g_macAddress[1] == 0 && g_macAddress[2] == 0 &&
                    g_macAddress[3] == 0 && g_macAddress[4] == 0 && g_macAddress[5] == 0) {
                    LogI(L"ERROR: MAC address not configured! Run setup.bat");
                    ret = NRC_ENVNOTDEF;
                } else {
                    PADAPTER_STATUS as = (PADAPTER_STATUS)ncb->ncb_buffer;
                    memset(as, 0, sizeof(ADAPTER_STATUS));
                    
                    /* 
                     * SYNCHRONIZED: MAC address must match iphlpapi ADAPTER_MAC
                     * Both loaded from registry: HKCU\Software\EXIPHL\Config\MACAddress
                     */
                    memcpy(as->adapter_address, g_macAddress, 6);
                    
                    as->rev_major = 3;
                    as->adapter_type = 0xFE;
                    as->max_cfg_sess = as->max_sess = MAX_SESS;
                    as->name_count = 1;
                    if (ncb->ncb_length >= sizeof(ADAPTER_STATUS) + sizeof(NAME_BUFFER)) {
                        PNAME_BUFFER nb = (PNAME_BUFFER)(as + 1);
                        memset(nb->name, ' ', NCBNAMSZ);
                        WideCharToMultiByte(CP_ACP, 0, g_computerName, -1, (char*)nb->name, NCBNAMSZ-1, NULL, NULL);
                        nb->name_num = 1;
                        nb->name_flags = REGISTERED | UNIQUE_NAME;
                    }
                }
            }
            break;
        }
        case NCBADDNAME:
        case NCBADDGRNAME:
            ret = (ncb->ncb_lana_num >= g_numLanas) ? NRC_BRIDGE : NRC_GOODRET;
            ncb->ncb_num = 1;
            break;
        case NCBDELNAME:
            ret = (ncb->ncb_lana_num >= g_numLanas) ? NRC_BRIDGE : NRC_GOODRET;
            break;
        case NCBCALL:
        case NCBLISTEN:
            ret = NRC_NOCALL;
            break;
        case NCBSEND:
        case NCBCHAINSEND:
        case NCBSENDNA:
        case NCBCHAINSENDNA:
        case NCBRECV:
        case NCBRECVANY:
        case NCBHANGUP:
            ret = NRC_SNUMOUT;
            break;
        case NCBCANCEL:
            ret = NRC_CANOCCR;
            break;
        case NCBSSTAT:
            if (!ncb->ncb_buffer || ncb->ncb_length < sizeof(SESSION_HEADER)) ret = NRC_BUFLEN;
            else memset(ncb->ncb_buffer, 0, sizeof(SESSION_HEADER));
            break;
        case NCBFINDNAME:
            if (!ncb->ncb_buffer || ncb->ncb_length < sizeof(FIND_NAME_HEADER)) ret = NRC_BUFLEN;
            else { memset(ncb->ncb_buffer, 0, sizeof(FIND_NAME_HEADER)); ret = NRC_ENVNOTDEF; }
            break;
        default:
            ret = NRC_ILLCMD;
            break;
    }
    
    LeaveCriticalSection(&g_nbLock);
    
    ncb->ncb_retcode = ncb->ncb_cmd_cplt = ret;
    if ((ncb->ncb_command & ASYNCH) && ret != NRC_PENDING) {
        if (ncb->ncb_event) SetEvent(ncb->ncb_event);
        if (ncb->ncb_post) ncb->ncb_post(ncb);
    }
    return ret;
}

/* ============================================================================
 * WORKSTATION FUNCTIONS
 * ============================================================================ */

/*
 * NetWkstaGetInfo - SYNCHRONIZED with iphlpapi.dll GetNetworkParams()
 * 
 * Returns:
 *   - wki102_computername: g_computerName (from GetComputerNameW)
 *   - wki102_langroup: g_workgroupName = "WORKGROUP" (registry)
 * 
 * CRITICAL: These values MUST match iphlpapi GetNetworkParams():
 *   - HostName should equal wki102_computername
 *   - DomainName should equal wki102_langroup
 */
NET_API_STATUS WINAPI ex_NetWkstaGetInfo(LMSTR servername, DWORD level, LPBYTE* bufptr) {
    EnsureInit();
    LogI(L"NetWkstaGetInfo(level=%lu)", level);
    
    /* Check if configuration was loaded from registry */
    if (wcscmp(g_computerName, L"<NOT CONFIGURED>") == 0) {
        LogI(L"ERROR: Configuration not found in registry! Run setup.bat");
        return ERROR_FILE_NOT_FOUND;
    }
    
    if (!IsLocalComputer(servername)) return NERR_InvalidComputer;
    if (!bufptr) return ERROR_INVALID_PARAMETER;
    if (level != 100 && level != 101 && level != 102) return ERROR_INVALID_LEVEL;
    
    DWORD size = sizeof(WKSTA_INFO_102) + 512;
    NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)bufptr);
    if (err != NERR_Success) return err;
    
    PWKSTA_INFO_102 info = (PWKSTA_INFO_102)*bufptr;
    LPWSTR str = (LPWSTR)(info + 1);
    
    info->wki102_platform_id = PLATFORM_ID_NT;
    
    /* Computer name - synchronized with iphlpapi GetNetworkParams() HostName */
    info->wki102_computername = str;
    wcscpy(str, g_computerName); str += wcslen(g_computerName) + 1;
    
    /* Workgroup - synchronized with iphlpapi GetNetworkParams() DomainName */
    info->wki102_langroup = str;
    wcscpy(str, g_workgroupName); str += wcslen(g_workgroupName) + 1;
    info->wki102_ver_major = 10;
    info->wki102_ver_minor = 0;
    info->wki102_lanroot = str;
    wcscpy(str, L"C:\\Windows");
    info->wki102_logged_on_users = 1;
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetWkstaSetInfo(LMSTR s, DWORD l, LPBYTE b, LPDWORD e) {
    EnsureInit(); return ERROR_ACCESS_DENIED;
}

NET_API_STATUS WINAPI ex_NetWkstaUserGetInfo(LMSTR reserved, DWORD level, LPBYTE* bufptr) {
    EnsureInit();
    LogI(L"NetWkstaUserGetInfo(level=%lu)", level);
    
    /* Check if configuration was loaded from registry */
    if (wcscmp(g_userName, L"<NOT CONFIGURED>") == 0 || 
        wcscmp(g_computerName, L"<NOT CONFIGURED>") == 0) {
        LogI(L"ERROR: Configuration not found in registry! Run setup.bat");
        return ERROR_FILE_NOT_FOUND;
    }
    
    if (!bufptr) return ERROR_INVALID_PARAMETER;
    if (level != 0 && level != 1 && level != 1101) return ERROR_INVALID_LEVEL;
    
    DWORD size = sizeof(WKSTA_USER_INFO_1) + 512;
    NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)bufptr);
    if (err != NERR_Success) return err;
    
    PWKSTA_USER_INFO_1 info = (PWKSTA_USER_INFO_1)*bufptr;
    LPWSTR str = (LPWSTR)(info + 1);
    
    info->wkui1_username = str;
    wcscpy(str, g_userName); str += wcslen(g_userName) + 1;
    info->wkui1_logon_domain = str;
    wcscpy(str, g_computerName); str += wcslen(g_computerName) + 1;
    info->wkui1_oth_domains = str; *str++ = L'\0';
    info->wkui1_logon_server = str;
    wcscpy(str, g_computerName);
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetWkstaUserSetInfo(LMSTR r, DWORD l, LPBYTE b, LPDWORD e) {
    EnsureInit(); return ERROR_ACCESS_DENIED;
}

NET_API_STATUS WINAPI ex_NetWkstaUserEnum(LMSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) {
    EnsureInit();
    
    /* Check if configuration was loaded from registry */
    if (wcscmp(g_userName, L"<NOT CONFIGURED>") == 0) {
        LogI(L"ERROR: Configuration not found in registry! Run setup.bat");
        return ERROR_FILE_NOT_FOUND;
    }
    
    if (!IsLocalComputer(s)) return NERR_InvalidComputer;
    if (!b || !er || !te) return ERROR_INVALID_PARAMETER;
    
    DWORD size = sizeof(WKSTA_USER_INFO_0) + 128;
    NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)b);
    if (err != NERR_Success) return err;
    
    PWKSTA_USER_INFO_0 info = (PWKSTA_USER_INFO_0)*b;
    info->wkui0_username = (LPWSTR)(info + 1);
    wcscpy(info->wkui0_username, g_userName);
    *er = *te = 1;
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetWkstaTransportAdd(LMSTR s, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetWkstaTransportDel(LMSTR s, LMSTR t, DWORD u) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetWkstaTransportEnum(LMSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) {
    EnsureInit();
    if (!b || !er || !te) return ERROR_INVALID_PARAMETER;
    *er = *te = 0; *b = NULL;
    return NERR_Success;
}

/* ============================================================================
 * SERVER FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetServerEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, DWORD st, LPCWSTR d, LPDWORD rh) {
    EnsureInit();
    if (!b || !er || !te) return ERROR_INVALID_PARAMETER;
    
    DWORD size = sizeof(SERVER_INFO_101) + 256;
    NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)b);
    if (err != NERR_Success) return err;
    
    PSERVER_INFO_101 info = (PSERVER_INFO_101)*b;
    LPWSTR str = (LPWSTR)(info + 1);
    
    info->sv101_platform_id = PLATFORM_ID_NT;
    info->sv101_name = str;
    wcscpy(str, g_computerName); str += wcslen(g_computerName) + 1;
    info->sv101_version_major = 10;
    info->sv101_version_minor = 0;
    info->sv101_type = SV_TYPE_WORKSTATION | SV_TYPE_NT;
    info->sv101_comment = str;
    wcscpy(str, L"Workstation");
    *er = *te = 1;
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetServerEnumEx(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, DWORD st, LPCWSTR d, LPCWSTR f) {
    return ex_NetServerEnum(s, l, b, p, er, te, st, d, NULL);
}

/*
 * NetServerGetInfo - SYNCHRONIZED with iphlpapi.dll GetNetworkParams()
 * 
 * Returns:
 *   - sv101_name: g_computerName (from GetComputerNameW)
 * 
 * CRITICAL: sv101_name MUST match iphlpapi GetNetworkParams() HostName
 */
NET_API_STATUS WINAPI ex_NetServerGetInfo(LMSTR servername, DWORD level, LPBYTE* bufptr) {
    EnsureInit();
    LogI(L"NetServerGetInfo(level=%lu)", level);
    
    /* Check if configuration was loaded from registry */
    if (wcscmp(g_computerName, L"<NOT CONFIGURED>") == 0) {
        LogI(L"ERROR: Configuration not found in registry! Run setup.bat");
        return ERROR_FILE_NOT_FOUND;
    }
    
    if (!IsLocalComputer(servername)) return NERR_InvalidComputer;
    if (!bufptr) return ERROR_INVALID_PARAMETER;
    if (level != 100 && level != 101 && level != 102) return ERROR_INVALID_LEVEL;
    
    DWORD size = sizeof(SERVER_INFO_101) + 256;
    NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)bufptr);
    if (err != NERR_Success) return err;
    
    PSERVER_INFO_101 info = (PSERVER_INFO_101)*bufptr;
    LPWSTR str = (LPWSTR)(info + 1);
    
    info->sv101_platform_id = PLATFORM_ID_NT;
    
    /* Computer name - synchronized with iphlpapi GetNetworkParams() HostName */
    info->sv101_name = str;
    wcscpy(str, g_computerName); str += wcslen(g_computerName) + 1;
    info->sv101_version_major = 10;
    info->sv101_version_minor = 0;
    info->sv101_type = SV_TYPE_WORKSTATION | SV_TYPE_NT;
    info->sv101_comment = str;
    wcscpy(str, L"Workstation");
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetServerSetInfo(LMSTR s, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetServerDiskEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) {
    EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetServerComputerNameAdd(LPCWSTR s, LPCWSTR ed, LPCWSTR dn) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerComputerNameDel(LPCWSTR s, LPCWSTR dn) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerTransportAdd(LPCWSTR s, DWORD l, LPBYTE b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerTransportAddEx(LPCWSTR s, DWORD l, LPBYTE b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerTransportDel(LPCWSTR s, DWORD l, LPBYTE b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerTransportEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) {
    EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetServerAliasAdd(LPCWSTR s, DWORD l, LPBYTE b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerAliasDel(LPCWSTR s, DWORD l, LPBYTE b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerAliasEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) {
    EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success;
}

/* ============================================================================
 * JOIN INFORMATION
 * ============================================================================ */
DWORD WINAPI ex_NetGetJoinInformation(LPCWSTR server, LPWSTR* name, PNETSETUP_JOIN_STATUS joinStatus) {
    EnsureInit();
    LogI(L"NetGetJoinInformation");
    if (!IsLocalComputer(server)) return NERR_InvalidComputer;
    if (!name || !joinStatus) return ERROR_INVALID_PARAMETER;
    
    NET_API_STATUS err = ex_NetApiBufferAllocate((wcslen(g_workgroupName)+1)*sizeof(WCHAR), (LPVOID*)name);
    if (err != NERR_Success) return err;
    wcscpy(*name, g_workgroupName);
    *joinStatus = NetSetupWorkgroupName;
    return NERR_Success;
}

/* ============================================================================
 * SHARE FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetShareAdd(LMSTR s, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetShareCheck(LMSTR s, LMSTR d, LPDWORD t) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetShareDel(LMSTR s, LMSTR n, DWORD r) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetShareDelEx(LPCWSTR s, DWORD l, LPBYTE b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetShareDelSticky(LMSTR s, LMSTR n, DWORD r) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetShareEnum(LMSTR servername, DWORD level, LPBYTE* bufptr, DWORD prefmaxlen, LPDWORD entriesread, LPDWORD totalentries, LPDWORD resumehandle) {
    EnsureInit();
    if(!bufptr||!entriesread||!totalentries) return ERROR_INVALID_PARAMETER;
    *bufptr=NULL; *entriesread=*totalentries=0;
    return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetShareEnumSticky(LMSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) {
    EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetShareGetInfo(LMSTR s, LMSTR n, DWORD l, LPBYTE* b) { EnsureInit(); return NERR_NetNameNotFound; }
NET_API_STATUS WINAPI ex_NetShareSetInfo(LMSTR s, LMSTR n, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return NERR_NetNameNotFound; }

/* ============================================================================
 * USER FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetUserAdd(LPCWSTR s, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return NERR_UserExists; }
NET_API_STATUS WINAPI ex_NetUserDel(LPCWSTR s, LPCWSTR u) { EnsureInit(); return NERR_UserNotFound; }

NET_API_STATUS WINAPI ex_NetUserEnum(LPCWSTR servername, DWORD level, DWORD filter, LPBYTE* bufptr, DWORD prefmaxlen, LPDWORD entriesread, LPDWORD totalentries, LPDWORD resumehandle) {
    EnsureInit();
    LogI(L"NetUserEnum(level=%lu)", level);
    if (!IsLocalComputer(servername)) return NERR_InvalidComputer;
    if (!bufptr || !entriesread || !totalentries) return ERROR_INVALID_PARAMETER;
    
    if (level == 0) {
        DWORD size = sizeof(USER_INFO_0) + 128;
        NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)bufptr);
        if (err != NERR_Success) return err;
        PUSER_INFO_0 info = (PUSER_INFO_0)*bufptr;
        info->usri0_name = (LPWSTR)(info + 1);
        wcscpy(info->usri0_name, g_userName);
        *entriesread = *totalentries = 1;
    } else if (level == 20) {
        DWORD size = sizeof(USER_INFO_20) + 128;
        NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)bufptr);
        if (err != NERR_Success) return err;
        PUSER_INFO_20 info = (PUSER_INFO_20)*bufptr;
        info->usri20_name = (LPWSTR)(info + 1);
        wcscpy(info->usri20_name, g_userName);
        info->usri20_flags = UF_NORMAL_ACCOUNT;
        info->usri20_user_id = 1000;
        *entriesread = *totalentries = 1;
    } else {
        *bufptr = NULL;
        *entriesread = *totalentries = 0;
    }
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetUserGetInfo(LPCWSTR s, LPCWSTR u, DWORD l, LPBYTE* b) {
    EnsureInit();
    LogI(L"NetUserGetInfo(user=%s, level=%lu)", u?u:L"null", l);
    if (!IsLocalComputer(s)) return NERR_InvalidComputer;
    if (!b) return ERROR_INVALID_PARAMETER;
    if (!u || _wcsicmp(u, g_userName) != 0) return NERR_UserNotFound;
    
    if (l == 0) {
        DWORD size = sizeof(USER_INFO_0) + 128;
        NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)b);
        if (err != NERR_Success) return err;
        PUSER_INFO_0 info = (PUSER_INFO_0)*b;
        info->usri0_name = (LPWSTR)(info + 1);
        wcscpy(info->usri0_name, g_userName);
        return NERR_Success;
    }
    return ERROR_INVALID_LEVEL;
}

NET_API_STATUS WINAPI ex_NetUserSetInfo(LPCWSTR s, LPCWSTR u, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetUserGetGroups(LPCWSTR s, LPCWSTR u, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te) {
    EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetUserSetGroups(LPCWSTR s, LPCWSTR u, DWORD l, LPBYTE b, DWORD ne) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetUserGetLocalGroups(LPCWSTR s, LPCWSTR u, DWORD l, DWORD f, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te) {
    EnsureInit();
    if(!b||!er||!te) return ERROR_INVALID_PARAMETER;
    if (l == 0) {
        DWORD size = sizeof(LOCALGROUP_USERS_INFO_0) + 64;
        NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)b);
        if (err != NERR_Success) return err;
        PLOCALGROUP_USERS_INFO_0 info = (PLOCALGROUP_USERS_INFO_0)*b;
        info->lgrui0_name = (LPWSTR)(info + 1);
        wcscpy(info->lgrui0_name, L"Administrators");
        *er = *te = 1;
        return NERR_Success;
    }
    *er = *te = 0; *b = NULL;
    return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetUserModalsGet(LPCWSTR s, DWORD l, LPBYTE* b) {
    EnsureInit();
    if(!b) return ERROR_INVALID_PARAMETER;
    if(l>3) return ERROR_INVALID_LEVEL;
    DWORD size = 256;
    NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)b);
    if(err==NERR_Success) ZeroMemory(*b, size);
    return err;
}
NET_API_STATUS WINAPI ex_NetUserModalsSet(LPCWSTR s, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetUserChangePassword(LPCWSTR d, LPCWSTR u, LPCWSTR o, LPCWSTR n) { EnsureInit(); return NERR_UserNotFound; }

/* ============================================================================
 * GROUP FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetGroupAdd(LPCWSTR s, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetGroupAddUser(LPCWSTR s, LPCWSTR gn, LPCWSTR un) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetGroupDel(LPCWSTR s, LPCWSTR gn) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetGroupDelUser(LPCWSTR s, LPCWSTR gn, LPCWSTR un) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetGroupEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, PDWORD_PTR rh) {
    EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetGroupGetInfo(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE* b) { EnsureInit(); return NERR_GroupNotFound; }
NET_API_STATUS WINAPI ex_NetGroupGetUsers(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, PDWORD_PTR rh) {
    EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetGroupSetInfo(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return NERR_GroupNotFound; }
NET_API_STATUS WINAPI ex_NetGroupSetUsers(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE b, DWORD te) { EnsureInit(); return NERR_GroupNotFound; }

/* ============================================================================
 * LOCAL GROUP FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetLocalGroupAdd(LPCWSTR s, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return NERR_GroupExists; }
NET_API_STATUS WINAPI ex_NetLocalGroupAddMember(LPCWSTR s, LPCWSTR gn, PSID m) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetLocalGroupAddMembers(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE b, DWORD te) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetLocalGroupDel(LPCWSTR s, LPCWSTR gn) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetLocalGroupDelMember(LPCWSTR s, LPCWSTR gn, PSID m) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetLocalGroupDelMembers(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE b, DWORD te) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetLocalGroupEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, PDWORD_PTR rh) {
    EnsureInit();
    if(!b||!er||!te) return ERROR_INVALID_PARAMETER;
    DWORD size = sizeof(LOCALGROUP_INFO_1) + 128;
    NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)b);
    if (err != NERR_Success) return err;
    PLOCALGROUP_INFO_1 info = (PLOCALGROUP_INFO_1)*b;
    LPWSTR str = (LPWSTR)(info + 1);
    info->lgrpi1_name = str;
    wcscpy(str, L"Administrators"); str += 15;
    info->lgrpi1_comment = str;
    wcscpy(str, L"Local Admins");
    *er = *te = 1;
    return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetLocalGroupGetInfo(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE* b) {
    EnsureInit();
    if(!b) return ERROR_INVALID_PARAMETER;
    if(gn && _wcsicmp(gn, L"Administrators")==0) {
        DWORD size = sizeof(LOCALGROUP_INFO_1) + 128;
        NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)b);
        if (err != NERR_Success) return err;
        PLOCALGROUP_INFO_1 info = (PLOCALGROUP_INFO_1)*b;
        LPWSTR str = (LPWSTR)(info + 1);
        info->lgrpi1_name = str;
        wcscpy(str, L"Administrators"); str += 15;
        info->lgrpi1_comment = str;
        wcscpy(str, L"Local Admins");
        return NERR_Success;
    }
    return NERR_GroupNotFound;
}
NET_API_STATUS WINAPI ex_NetLocalGroupGetMembers(LPCWSTR s, LPCWSTR lgn, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, PDWORD_PTR rh) {
    EnsureInit();
    if(!b||!er||!te) return ERROR_INVALID_PARAMETER;
    if(lgn && _wcsicmp(lgn, L"Administrators")==0 && l==3) {
        DWORD size = sizeof(LOCALGROUP_MEMBERS_INFO_3) + 128;
        NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)b);
        if (err != NERR_Success) return err;
        PLOCALGROUP_MEMBERS_INFO_3 info = (PLOCALGROUP_MEMBERS_INFO_3)*b;
        info->lgrmi3_domainandname = (LPWSTR)(info + 1);
        wcscpy(info->lgrmi3_domainandname, g_userName);
        *er = *te = 1;
        return NERR_Success;
    }
    *er = *te = 0; *b = NULL;
    return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetLocalGroupSetInfo(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return NERR_GroupNotFound; }
NET_API_STATUS WINAPI ex_NetLocalGroupSetMembers(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE b, DWORD te) { EnsureInit(); return ERROR_ACCESS_DENIED; }

/* ============================================================================
 * USE / STATISTICS / DC / MESSAGE / DISPLAY FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetUseAdd(LMSTR s, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_BAD_NETPATH; }
NET_API_STATUS WINAPI ex_NetUseDel(LMSTR s, LMSTR u, DWORD f) { EnsureInit(); return ERROR_NOT_CONNECTED; }
NET_API_STATUS WINAPI ex_NetUseEnum(LMSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) {
    EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetUseGetInfo(LMSTR s, LMSTR u, DWORD l, LPBYTE* b) { EnsureInit(); return ERROR_NOT_CONNECTED; }

NET_API_STATUS WINAPI ex_NetStatisticsGet(LMSTR s, LMSTR sv, DWORD l, DWORD o, LPBYTE* b) {
    EnsureInit();
    if(!b) return ERROR_INVALID_PARAMETER;
    NET_API_STATUS err = ex_NetApiBufferAllocate(256, (LPVOID*)b);
    if(err==NERR_Success) ZeroMemory(*b, 256);
    return err;
}

NET_API_STATUS WINAPI ex_NetGetDCName(LPCWSTR s, LPCWSTR d, LPBYTE* b) { EnsureInit(); return ERROR_NO_LOGON_SERVERS; }
NET_API_STATUS WINAPI ex_NetGetAnyDCName(LPCWSTR s, LPCWSTR d, LPBYTE* b) { EnsureInit(); return ERROR_NO_LOGON_SERVERS; }

NET_API_STATUS WINAPI ex_NetMessageBufferSend(LPCWSTR s, LPCWSTR m, LPCWSTR f, LPBYTE b, DWORD bl) { EnsureInit(); return NERR_Success; }
NET_API_STATUS WINAPI ex_NetMessageNameAdd(LPCWSTR s, LPCWSTR n) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetMessageNameDel(LPCWSTR s, LPCWSTR n) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetMessageNameEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) {
    EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return ERROR_NOT_SUPPORTED;
}
NET_API_STATUS WINAPI ex_NetMessageNameGetInfo(LPCWSTR s, LPCWSTR n, DWORD l, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_NetQueryDisplayInformation(LPCWSTR s, DWORD l, DWORD i, DWORD er, DWORD p, LPDWORD rec, PVOID* sb) {
    EnsureInit(); if(rec)*rec=0; if(sb)*sb=NULL; return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetGetDisplayInformationIndex(LPCWSTR s, DWORD l, LPCWSTR p, LPDWORD i) {
    EnsureInit(); if(i)*i=0; return NERR_Success;
}

/* ============================================================================
 * DS FUNCTIONS
 * ============================================================================ */
DWORD WINAPI ex_DsGetDcNameA(LPCSTR cn, LPCSTR dn, GUID* dg, LPCSTR sn, ULONG f, PDOMAIN_CONTROLLER_INFOA* dci) { EnsureInit(); return ERROR_NO_SUCH_DOMAIN; }
DWORD WINAPI ex_DsGetDcNameW(LPCWSTR cn, LPCWSTR dn, GUID* dg, LPCWSTR sn, ULONG f, PDOMAIN_CONTROLLER_INFOW* dci) { EnsureInit(); return ERROR_NO_SUCH_DOMAIN; }
DWORD WINAPI ex_DsGetDcNameWithAccountA(LPCSTR cn, LPCSTR an, ULONG af, LPCSTR dn, GUID* dg, LPCSTR sn, ULONG f, PDOMAIN_CONTROLLER_INFOA* dci) { EnsureInit(); return ERROR_NO_SUCH_DOMAIN; }
DWORD WINAPI ex_DsGetDcNameWithAccountW(LPCWSTR cn, LPCWSTR an, ULONG af, LPCWSTR dn, GUID* dg, LPCWSTR sn, ULONG f, PDOMAIN_CONTROLLER_INFOW* dci) { EnsureInit(); return ERROR_NO_SUCH_DOMAIN; }
DWORD WINAPI ex_DsGetSiteNameA(LPCSTR cn, LPSTR* sn) { EnsureInit(); if(sn)*sn=NULL; return ERROR_NO_SITENAME; }
DWORD WINAPI ex_DsGetSiteNameW(LPCWSTR cn, LPWSTR* sn) { EnsureInit(); if(sn)*sn=NULL; return ERROR_NO_SITENAME; }
DWORD WINAPI ex_DsGetDcOpenA(LPCSTR dn, ULONG on, LPCSTR sn, GUID* dg, LPCSTR dfn, ULONG f, PHANDLE rgh) { EnsureInit(); if(rgh)*rgh=NULL; return ERROR_NO_SUCH_DOMAIN; }
DWORD WINAPI ex_DsGetDcOpenW(LPCWSTR dn, ULONG on, LPCWSTR sn, GUID* dg, LPCWSTR dfn, ULONG f, PHANDLE rgh) { EnsureInit(); if(rgh)*rgh=NULL; return ERROR_NO_SUCH_DOMAIN; }
DWORD WINAPI ex_DsGetDcNextA(HANDLE gh, PULONG saf, LPSTR* dcn, LPSTR* dca) { EnsureInit(); return ERROR_NO_MORE_ITEMS; }
DWORD WINAPI ex_DsGetDcNextW(HANDLE gh, PULONG saf, LPWSTR* dcn, LPWSTR* dca) { EnsureInit(); return ERROR_NO_MORE_ITEMS; }
void WINAPI ex_DsGetDcCloseW(HANDLE gh) { EnsureInit(); }
DWORD WINAPI ex_DsValidateSubnetNameA(LPCSTR sn) { EnsureInit(); return ERROR_INVALID_PARAMETER; }
DWORD WINAPI ex_DsValidateSubnetNameW(LPCWSTR sn) { EnsureInit(); return ERROR_INVALID_PARAMETER; }
DWORD WINAPI ex_DsAddressToSiteNamesA(LPCSTR cn, DWORD ec, void* sa, LPSTR** sn) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsAddressToSiteNamesW(LPCWSTR cn, DWORD ec, void* sa, LPWSTR** sn) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsAddressToSiteNamesExA(LPCSTR cn, DWORD ec, void* sa, LPSTR** sn, LPSTR** ssn) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsAddressToSiteNamesExW(LPCWSTR cn, DWORD ec, void* sa, LPWSTR** sn, LPWSTR** ssn) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsDeregisterDnsHostRecordsA(LPSTR sn, LPSTR dn, GUID* dg, GUID* dsg, LPSTR dhn) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsDeregisterDnsHostRecordsW(LPWSTR sn, LPWSTR dn, GUID* dg, GUID* dsg, LPWSTR dhn) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsEnumerateDomainTrustsA(LPSTR sn, ULONG f, PDS_DOMAIN_TRUSTSA* d, PULONG dc) { EnsureInit(); if(d)*d=NULL; if(dc)*dc=0; return ERROR_NO_LOGON_SERVERS; }
DWORD WINAPI ex_DsEnumerateDomainTrustsW(LPWSTR sn, ULONG f, PDS_DOMAIN_TRUSTSW* d, PULONG dc) { EnsureInit(); if(d)*d=NULL; if(dc)*dc=0; return ERROR_NO_LOGON_SERVERS; }
DWORD WINAPI ex_DsGetDcSiteCoverageA(LPCSTR sn, PULONG ec, LPSTR** sna) { EnsureInit(); if(ec)*ec=0; if(sna)*sna=NULL; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetDcSiteCoverageW(LPCWSTR sn, PULONG ec, LPWSTR** sna) { EnsureInit(); if(ec)*ec=0; if(sna)*sna=NULL; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetForestTrustInformationW(LPCWSTR sn, LPCWSTR tdn, DWORD f, PVOID* fti) { EnsureInit(); if(fti)*fti=NULL; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsMergeForestTrustInformationW(LPCWSTR dn, PVOID nfti, PVOID ofti, PVOID* mfti) { EnsureInit(); if(mfti)*mfti=NULL; return ERROR_NOT_SUPPORTED; }

/* ============================================================================
 * DS ROLE / AAD FUNCTIONS
 * ============================================================================ */
DWORD WINAPI ex_DsRoleGetPrimaryDomainInformation(LPCWSTR s, DSROLE_PRIMARY_DOMAIN_INFO_LEVEL il, PBYTE* b) {
    EnsureInit();
    if(!b) return ERROR_INVALID_PARAMETER;
    if(il == DsRolePrimaryDomainInfoBasic) {
        DWORD size = sizeof(DSROLE_PRIMARY_DOMAIN_INFO_BASIC) + 256;
        NET_API_STATUS err = ex_NetApiBufferAllocate(size, (LPVOID*)b);
        if (err != NERR_Success) return err;
        PDSROLE_PRIMARY_DOMAIN_INFO_BASIC info = (PDSROLE_PRIMARY_DOMAIN_INFO_BASIC)*b;
        ZeroMemory(info, size);
        info->MachineRole = DsRole_RoleStandaloneWorkstation;
        info->DomainNameFlat = (LPWSTR)((BYTE*)info + sizeof(DSROLE_PRIMARY_DOMAIN_INFO_BASIC));
        wcscpy(info->DomainNameFlat, g_computerName);
        return ERROR_SUCCESS;
    }
    return ERROR_INVALID_LEVEL;
}
void WINAPI ex_DsRoleFreeMemory(PVOID b) { if(b) HeapFree(GetProcessHeap(), 0, b); }

HRESULT WINAPI ex_NetGetAadJoinInformation(LPCWSTR ti, PDSREG_JOIN_INFO* ji) { EnsureInit(); if(ji)*ji=NULL; return 0x80070032L; }
void WINAPI ex_NetFreeAadJoinInformation(PDSREG_JOIN_INFO ji) { EnsureInit(); if(ji) ex_NetApiBufferFree(ji); }

/* ============================================================================
 * DAV FUNCTIONS
 * ============================================================================ */
DWORD WINAPI ex_DavAddConnection(HANDLE* ch, LPCWSTR rn, LPCWSTR un, LPCWSTR pw, PBYTE ct, DWORD cts) { EnsureInit(); if(ch)*ch=INVALID_HANDLE_VALUE; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DavDeleteConnection(HANDLE ch) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DavFlushFile(HANDLE fh) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DavGetExtendedError(HANDLE ch, DWORD* es, LPWSTR eb, DWORD* ebs) { EnsureInit(); if(es)*es=0; if(ebs)*ebs=0; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DavGetTheLockOwnerOfTheFile(LPCWSTR fn, LPWSTR lo, DWORD* los) { EnsureInit(); if(los)*los=0; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DavInvalidateCache(LPCWSTR up) { EnsureInit(); return ERROR_SUCCESS; }
DWORD WINAPI ex_DavRegisterAuthCallback(PVOID cb, ULONG v) { EnsureInit(); return ERROR_SUCCESS; }
void WINAPI ex_DavUnregisterAuthCallback(DWORD ci) { EnsureInit(); }

DWORD WINAPI ex_DavGetHTTPFromUNCPath(LPCWSTR up, LPWSTR hp, LPDWORD hps) {
    EnsureInit();
    if(!up||!hps) return ERROR_INVALID_PARAMETER;
    if(!hp) { *hps=512; return ERROR_INSUFFICIENT_BUFFER; }
    if(wcsncmp(up, L"\\\\", 2)!=0) return ERROR_INVALID_PARAMETER;
    WCHAR res[512]; _snwprintf(res, 512, L"http://%s", up+2);
    for(WCHAR* p=res; *p; p++) if(*p==L'\\') *p=L'/';
    DWORD len = (DWORD)wcslen(res) + 1;
    if(*hps < len) { *hps=len; return ERROR_INSUFFICIENT_BUFFER; }
    wcscpy(hp, res); *hps = len;
    return ERROR_SUCCESS;
}

DWORD WINAPI ex_DavGetUNCFromHTTPPath(LPCWSTR hp, LPWSTR up, LPDWORD ups) {
    EnsureInit();
    if(!hp||!ups) return ERROR_INVALID_PARAMETER;
    if(!up) { *ups=512; return ERROR_INSUFFICIENT_BUFFER; }
    LPCWSTR srv = (wcsncmp(hp, L"http://", 7)==0) ? hp+7 : (wcsncmp(hp, L"https://", 8)==0) ? hp+8 : NULL;
    if(!srv) return ERROR_INVALID_PARAMETER;
    WCHAR res[512]; _snwprintf(res, 512, L"\\\\%s", srv);
    for(WCHAR* p=res; *p; p++) if(*p==L'/') *p=L'\\';
    DWORD len = (DWORD)wcslen(res) + 1;
    if(*ups < len) { *ups=len; return ERROR_INSUFFICIENT_BUFFER; }
    wcscpy(up, res); *ups = len;
    return ERROR_SUCCESS;
}

/* ============================================================================
 * ALERT / AUDIT / ACCESS / PASSWORD FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetAlertRaise(LPCWSTR an, LPVOID b, DWORD bs) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetAlertRaiseEx(LPCWSTR an, LPVOID vd, DWORD vds, LPCWSTR sn) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NetAuditClear(LPCWSTR s, LPCWSTR bf, LPCWSTR sv) { EnsureInit(); return ERROR_ACCESS_DENIED; }
DWORD WINAPI ex_NetAuditRead(LPCWSTR s, LPCWSTR sv, void* ah, DWORD o, LPDWORD r1, DWORD r2, DWORD of, LPBYTE* b, DWORD p, LPDWORD br, LPDWORD ta) { EnsureInit(); if(b)*b=NULL; return ERROR_ACCESS_DENIED; }
DWORD WINAPI ex_NetAuditWrite(DWORD t, LPBYTE b, DWORD nb, LPCWSTR sv, LPBYTE r) { EnsureInit(); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetAccessAdd(LPCWSTR s, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetAccessCheck(LPWSTR r, LPWSTR u, LPWSTR rs, DWORD o, LPDWORD re) { EnsureInit(); if(re)*re=0; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetAccessDel(LPCWSTR s, LPCWSTR r) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetAccessEnum(LPCWSTR s, LPCWSTR bp, DWORD r, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetAccessGetInfo(LPCWSTR s, LPCWSTR r, DWORD l, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetAccessGetUserPerms(LPCWSTR s, LPCWSTR ugn, LPCWSTR r, LPDWORD p) { EnsureInit(); if(p)*p=0; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetAccessSetInfo(LPCWSTR s, LPCWSTR r, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_NetValidatePasswordPolicy(LPCWSTR s, LPVOID q, NET_VALIDATE_PASSWORD_TYPE vt, LPVOID ia, LPVOID* oa) {
    EnsureInit();
    if(!oa) return ERROR_INVALID_PARAMETER;
    NET_API_STATUS err = ex_NetApiBufferAllocate(sizeof(NET_VALIDATE_OUTPUT_ARG), oa);
    if(err==NERR_Success) {
        ZeroMemory(*oa, sizeof(NET_VALIDATE_OUTPUT_ARG));
        ((PNET_VALIDATE_OUTPUT_ARG)*oa)->ValidationStatus = NERR_Success;
    }
    return err;
}
NET_API_STATUS WINAPI ex_NetValidatePasswordPolicyFree(LPVOID* oa) {
    EnsureInit();
    if(oa && *oa) { ex_NetApiBufferFree(*oa); *oa=NULL; }
    return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetValidateName(LPCWSTR s, LPCWSTR n, LPCWSTR a, LPCWSTR p, DWORD nt) { EnsureInit(); return NERR_Success; }

/* ============================================================================
 * SERVICE ACCOUNT / SERVICE / SCHEDULE FUNCTIONS
 * ============================================================================ */
NTSTATUS WINAPI ex_NetAddServiceAccount(LPWSTR s, LPWSTR an, LPWSTR p, DWORD f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NTSTATUS WINAPI ex_NetRemoveServiceAccount(LPWSTR s, LPWSTR an, DWORD f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NTSTATUS WINAPI ex_NetIsServiceAccount(LPWSTR s, LPWSTR an, BOOL* is) { EnsureInit(); if(is)*is=FALSE; return ERROR_NOT_SUPPORTED; }
NTSTATUS WINAPI ex_NetIsServiceAccount2(LPWSTR s, LPWSTR an, DWORD f, BOOL* is) { EnsureInit(); if(is)*is=FALSE; return ERROR_NOT_SUPPORTED; }
NTSTATUS WINAPI ex_NetEnumerateServiceAccounts(LPWSTR s, DWORD f, DWORD* ac, void** a) { EnsureInit(); if(ac)*ac=0; if(a)*a=NULL; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetQueryServiceAccount(LPCWSTR s, LPCWSTR an, DWORD il, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_NetServiceControl(LPCWSTR s, LPCWSTR sv, DWORD op, DWORD a, LPBYTE* b) { EnsureInit(); return NERR_ServiceNotInstalled; }
NET_API_STATUS WINAPI ex_NetServiceEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetServiceGetInfo(LPCWSTR s, LPCWSTR sv, DWORD l, LPBYTE* b) { EnsureInit(); return NERR_ServiceNotInstalled; }
NET_API_STATUS WINAPI ex_NetServiceInstall(LPCWSTR s, LPCWSTR sv, DWORD ac, LPCWSTR* av, LPBYTE* b) { EnsureInit(); return ERROR_ACCESS_DENIED; }

NET_API_STATUS WINAPI ex_NetScheduleJobAdd(LPCWSTR s, LPBYTE b, LPDWORD j) { EnsureInit(); if(j)*j=0; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetScheduleJobDel(LPCWSTR s, DWORD mn, DWORD mx) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetScheduleJobEnum(LPCWSTR s, LPBYTE* pb, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { EnsureInit(); if(pb)*pb=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetScheduleJobGetInfo(LPCWSTR s, DWORD j, LPBYTE* pb) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

/* ============================================================================
 * REPLICATION FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetReplExportDirAdd(LPCWSTR s, DWORD l, const LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplExportDirDel(LPCWSTR s, LPCWSTR d) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplExportDirEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetReplExportDirGetInfo(LPCWSTR s, LPCWSTR d, DWORD l, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplExportDirLock(LPCWSTR s, LPCWSTR d) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplExportDirSetInfo(LPCWSTR s, LPCWSTR d, DWORD l, const LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplExportDirUnlock(LPCWSTR s, LPCWSTR d, DWORD u) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplGetInfo(LPCWSTR s, DWORD l, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplImportDirAdd(LPCWSTR s, DWORD l, const LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplImportDirDel(LPCWSTR s, LPCWSTR d) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplImportDirEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplImportDirGetInfo(LPCWSTR s, LPCWSTR d, DWORD l, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplImportDirLock(LPCWSTR s, LPCWSTR d) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplImportDirUnlock(LPCWSTR s, LPCWSTR d, DWORD u) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplSetInfo(LPCWSTR s, DWORD l, const LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

/* ============================================================================
 * CONFIG / CONNECTION / FILE / SESSION / REMOTE / ERROR FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetConfigGet(LPCWSTR s, LPCWSTR c, LPCWSTR p, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetConfigGetAll(LPCWSTR s, LPCWSTR c, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetConfigSet(LPCWSTR s, LPCWSTR r, LPCWSTR c, DWORD l, DWORD r2, LPBYTE b, DWORD pr) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetConnectionEnum(LPCWSTR s, LPCWSTR q, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetFileClose(LPCWSTR s, DWORD fi) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetFileEnum(LPCWSTR s, LPCWSTR bp, LPCWSTR un, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, PDWORD_PTR rh) { EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetFileGetInfo(LPCWSTR s, DWORD fi, DWORD l, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetSessionDel(LPCWSTR s, LPCWSTR cn, LPCWSTR un) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetSessionEnum(LPCWSTR s, LPCWSTR cn, LPCWSTR un, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetSessionGetInfo(LPCWSTR s, LPCWSTR cn, LPCWSTR un, DWORD l, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetRemoteTOD(LPCWSTR un, LPBYTE* bi) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetRemoteComputerSupports(LPCWSTR un, DWORD ow, LPDWORD os) { EnsureInit(); if(os)*os=0; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetErrorLogClear(LPCWSTR un, LPCWSTR bf, LPBYTE r) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetErrorLogRead(LPCWSTR un, LPWSTR r1, void* eh, DWORD o, LPDWORD r2, DWORD r3, DWORD of, LPBYTE* b, DWORD p, LPDWORD br, LPDWORD ta) { EnsureInit(); if(b)*b=NULL; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetErrorLogWrite(LPBYTE r1, DWORD c, LPCWSTR cp, LPBYTE rd, DWORD nrd, LPBYTE d, DWORD nd, LPBYTE r2) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

/* ============================================================================
 * JOIN / PROVISIONING FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetJoinDomain(LPCWSTR s, LPCWSTR dn, LPCWSTR mao, LPCWSTR a, LPCWSTR pw, DWORD jo) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetUnjoinDomain(LPCWSTR s, LPCWSTR a, LPCWSTR pw, DWORD uo) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetRenameMachineInDomain(LPCWSTR s, LPCWSTR nmn, LPCWSTR a, LPCWSTR pw, DWORD ro) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetGetJoinableOUs(LPCWSTR s, LPCWSTR d, LPCWSTR a, LPCWSTR pw, DWORD* oc, LPWSTR** ou) { EnsureInit(); if(oc)*oc=0; if(ou)*ou=NULL; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetAddAlternateComputerName(LPCWSTR s, LPCWSTR an, LPCWSTR da, LPCWSTR dp, ULONG r) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetRemoveAlternateComputerName(LPCWSTR s, LPCWSTR an, LPCWSTR da, LPCWSTR dp, ULONG r) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetSetPrimaryComputerName(LPCWSTR s, LPCWSTR pn, LPCWSTR da, LPCWSTR dp, ULONG r) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetEnumerateComputerNames(LPCWSTR s, DWORD nt, ULONG r, PDWORD ec, LPWSTR** cn) {
    EnsureInit();
    if(!ec||!cn) return ERROR_INVALID_PARAMETER;
    if(nt==0) {
        DWORD len = (DWORD)wcslen(g_computerName) + 1;
        LPWSTR* names = NULL;
        NET_API_STATUS err = ex_NetApiBufferAllocate(sizeof(LPWSTR) + len*sizeof(WCHAR), (LPVOID*)&names);
        if(err!=NERR_Success) return err;
        names[0] = (LPWSTR)((BYTE*)names + sizeof(LPWSTR));
        wcscpy(names[0], g_computerName);
        *cn = names; *ec = 1;
        return NERR_Success;
    }
    *ec = 0; *cn = NULL;
    return NERR_Success;
}

DWORD WINAPI ex_NetCreateProvisioningPackage(void* p, PBYTE* pb, DWORD* pbs, LPWSTR* pt) { EnsureInit(); if(pb)*pb=NULL; if(pbs)*pbs=0; if(pt)*pt=NULL; return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NetRequestOfflineDomainJoin(PBYTE pb, DWORD pbs, DWORD o, LPCWSTR wn) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NetRequestProvisioningPackageInstall(PBYTE pb, DWORD pbs, DWORD o, LPCWSTR wn, PVOID r) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NetProvisionComputerAccount(LPCWSTR d, LPCWSTR mn, LPCWSTR mao, LPCWSTR dc, DWORD o, LPWSTR* pd, PBYTE* pb, DWORD* pbs) { EnsureInit(); if(pd)*pd=NULL; if(pb)*pb=NULL; if(pbs)*pbs=0; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetRegisterDomainNameChangeNotification(PHANDLE h) { EnsureInit(); if(h)*h=NULL; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetUnregisterDomainNameChangeNotification(HANDLE h) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

/* ============================================================================
 * DFS FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetDfsAdd(LPWSTR dp, LPWSTR sp, LPWSTR c, DWORD f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsAddFtRoot(LPWSTR s, LPWSTR rsh, LPWSTR frs, LPWSTR c, DWORD f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsAddRootTarget(LPWSTR pn, LPWSTR ts, ULONG mv, LPWSTR c, ULONG f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsAddStdRoot(LPWSTR s, LPWSTR rsh, LPWSTR c, DWORD f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsAddStdRootForced(LPWSTR s, LPWSTR rsh, LPWSTR c, LPWSTR st) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsEnum(LPWSTR dp, DWORD l, DWORD p, LPBYTE* b, LPDWORD er, LPDWORD rh) { EnsureInit(); if(b)*b=NULL; if(er)*er=0; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetDfsGetClientInfo(LPWSTR ep, LPWSTR sn, LPWSTR sh, DWORD l, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsGetDcAddress(LPWSTR s, LPWSTR* dc, BOOL* il, ULONG* t) { EnsureInit(); if(dc)*dc=NULL; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsGetFtContainerSecurity(LPWSTR dn, PSECURITY_INFORMATION si, PSECURITY_DESCRIPTOR* sd, LPDWORD csd) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsGetInfo(LPWSTR dp, LPWSTR sn, LPWSTR sh, DWORD l, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsGetSecurity(LPWSTR ep, PSECURITY_INFORMATION si, PSECURITY_DESCRIPTOR* sd, LPDWORD csd) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsGetStdContainerSecurity(LPWSTR mn, PSECURITY_INFORMATION si, PSECURITY_DESCRIPTOR* sd, LPDWORD csd) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsGetSupportedNamespaceVersion(DWORD o, LPWSTR pn, void* vi) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsManagerGetConfigInfo(LPCWSTR s, LPCWSTR r, GUID* g, void* ci) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsManagerInitialize(LPWSTR s, DWORD f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsManagerSendSiteInfo(LPWSTR s, LPWSTR r, void* si) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsMove(LPWSTR op, LPWSTR np, ULONG f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsRemove(LPWSTR dp, LPWSTR sn, LPWSTR sh) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsRemoveFtRoot(LPWSTR s, LPWSTR rsh, LPWSTR frs, DWORD f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsRemoveFtRootForced(LPWSTR dn, LPWSTR s, LPWSTR rsh, LPWSTR frs, DWORD f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsRemoveRootTarget(LPWSTR pn, LPWSTR ts, ULONG f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsRemoveStdRoot(LPWSTR s, LPWSTR rsh, DWORD f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsRename(LPWSTR p, LPWSTR np) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsSetClientInfo(LPWSTR ep, LPWSTR sn, LPWSTR sh, DWORD l, LPBYTE b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsSetFtContainerSecurity(LPWSTR dn, PSECURITY_INFORMATION si, PSECURITY_DESCRIPTOR sd) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsSetInfo(LPWSTR ep, LPWSTR sn, LPWSTR sh, DWORD l, LPBYTE b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsSetSecurity(LPWSTR ep, PSECURITY_INFORMATION si, PSECURITY_DESCRIPTOR sd) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetDfsSetStdContainerSecurity(LPWSTR mn, PSECURITY_INFORMATION si, PSECURITY_DESCRIPTOR sd) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

/* ============================================================================
 * I_NET / I_BROWSER / I_NETLOGON INTERNAL FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_I_BrowserSetNetlogonState(LPCWSTR s, LPCWSTR d, LPCWSTR e, DWORD r) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_BrowserQueryEmulatedDomains(LPCWSTR s, void** ed, LPDWORD er) { EnsureInit(); if(ed)*ed=NULL; if(er)*er=0; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_BrowserQueryOtherDomains(LPCWSTR s, LPBYTE* b, LPDWORD er, LPDWORD te) { EnsureInit(); if(b)*b=NULL; if(er)*er=0; if(te)*te=0; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_BrowserQueryStatistics(LPCWSTR s, void** s2) { EnsureInit(); if(s2)*s2=NULL; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_BrowserResetNetlogonState(LPCWSTR s) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_BrowserResetStatistics(LPCWSTR s) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

DWORD WINAPI ex_I_DsUpdateReadOnlyServerDnsRecords(LPWSTR s, LPWSTR d, void* r, DWORD f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_I_NetAccountDeltas(LPCWSTR s, LPCWSTR c, void* a, DWORD l, DWORD d, LPBYTE b, DWORD bs, LPDWORD er, LPDWORD te, void* rs) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetAccountSync(LPCWSTR s, LPCWSTR c, void* a, DWORD r, DWORD d, LPBYTE b, DWORD bs, LPDWORD er, LPDWORD te, LPDWORD ns, void* rs) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_I_NetChainSetClientAttributes(LPWSTR s, LPWSTR d, void* a, DWORD l, void* i, void* o) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetChainSetClientAttributes2(LPWSTR s, LPWSTR d, void* a, DWORD l, void* i, void* o, void* p) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_I_NetDatabaseDeltas(LPCWSTR s, LPCWSTR c, void* a, void* d, DWORD l, LPBYTE b, DWORD bs, LPDWORD er) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetDatabaseRedo(LPCWSTR s, LPCWSTR c, void* a, LPBYTE cb, DWORD cbs, LPBYTE b, DWORD bs, LPDWORD er) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetDatabaseSync(LPCWSTR s, LPCWSTR c, void* a, DWORD d, DWORD i, LPBYTE b, DWORD bs, LPDWORD er) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetDatabaseSync2(LPCWSTR s, LPCWSTR c, void* a, DWORD d, DWORD r, DWORD i, LPBYTE b, DWORD bs, LPDWORD er) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_I_NetDfsGetVersion(LPCWSTR s, LPDWORD v) { EnsureInit(); if(v)*v=0; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetDfsIsThisADomainName(LPCWSTR n) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

DWORD WINAPI ex_I_NetGetDCList(LPCWSTR s, LPCWSTR d, PULONG dc, void** b) { EnsureInit(); if(dc)*dc=0; if(b)*b=NULL; return ERROR_NO_LOGON_SERVERS; }
NET_API_STATUS WINAPI ex_I_NetGetForestTrustInformation(LPCWSTR s, LPCWSTR t, DWORD f, void** fti) { EnsureInit(); if(fti)*fti=NULL; return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_I_NetLogonControl(LPCWSTR s, DWORD fc, DWORD ql, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetLogonControl2(LPCWSTR s, DWORD fc, DWORD ql, LPBYTE d, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetLogonGetDomainInfo(LPCWSTR s, LPCWSTR t, void* a, DWORD l, void* w, void** d) { EnsureInit(); if(d)*d=NULL; return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_I_NetLogonSamLogoff(LPCWSTR s, LPCWSTR c, void* a, DWORD ll, DWORD li, void* ld) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetLogonSamLogon(LPCWSTR s, LPCWSTR c, void* a, DWORD ll, DWORD li, void* ld, DWORD vl, void** vd, LPBYTE* af) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetLogonSamLogonEx(HANDLE h, LPCWSTR c, DWORD ll, DWORD li, void* ld, DWORD vl, void** vd, LPBYTE* af) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetLogonSamLogonWithFlags(LPCWSTR s, LPCWSTR c, void* a, DWORD ll, DWORD li, void* ld, DWORD vl, void** vd, LPBYTE* af, DWORD* f) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetLogonSendToSam(LPCWSTR s, LPCWSTR c, void* a, LPBYTE ob, DWORD obs) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_I_NetLogonUasLogoff(LPCWSTR s, LPCWSTR u, LPCWSTR w, void* lo) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetLogonUasLogon(LPCWSTR s, LPCWSTR u, LPCWSTR w, void** vi) { EnsureInit(); if(vi)*vi=NULL; return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_I_NetServerAuthenticate(LPCWSTR s, LPCWSTR a, DWORD st, LPCWSTR c, void* cc, void* sc) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetServerAuthenticate2(LPCWSTR s, LPCWSTR a, DWORD st, LPCWSTR c, void* cc, void* sc, DWORD* nf) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetServerAuthenticate3(LPCWSTR s, LPCWSTR a, DWORD st, LPCWSTR c, void* cc, void* sc, DWORD* nf, DWORD* ar) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetServerAuthenticateKerberos(LPCWSTR s, LPCWSTR a, DWORD st, void* t, DWORD ts, void* o, DWORD os) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_I_NetServerGetTrustInfo(LPCWSTR s, LPCWSTR a, DWORD st, LPCWSTR c, void* ai, void** np, void** op, void** ti) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetServerPasswordGet(LPCWSTR s, LPCWSTR a, DWORD st, LPCWSTR c, void* ai, void** p) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetServerPasswordSet(LPCWSTR s, LPCWSTR a, DWORD st, LPCWSTR c, void* ai, void* hp) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetServerPasswordSet2(LPCWSTR s, LPCWSTR a, DWORD st, LPCWSTR c, void* ai, void* cpb) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetServerReqChallenge(LPCWSTR s, LPCWSTR c, void* cc, void* sc) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_I_NetServerSetServiceBits(LPCWSTR s, LPCWSTR t, DWORD sb, DWORD ub) { EnsureInit(); return NERR_Success; }
NET_API_STATUS WINAPI ex_I_NetServerSetServiceBitsEx(LPCWSTR s, LPCWSTR e, LPCWSTR t, DWORD sb, DWORD ub) { EnsureInit(); return NERR_Success; }

NET_API_STATUS WINAPI ex_I_NetServerTrustPasswordsGet(LPCWSTR s, LPCWSTR a, DWORD st, LPCWSTR c, void* ai, void** np, void** op) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_I_NetlogonComputeClientDigest(LPCWSTR s, LPCWSTR d, void* m, DWORD ms, void* nd, void* od) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetlogonComputeServerDigest(LPCWSTR s, DWORD r, void* m, DWORD ms, void* nd, void* od) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

/* ============================================================================
 * NETLOGON SERVICE BITS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetLogonGetTimeServiceParentDomain(LPCWSTR s, LPWSTR* pd, BOOL* pt) { EnsureInit(); if(pd)*pd=NULL; if(pt)*pt=FALSE; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetLogonSetServiceBits(LPCWSTR s, DWORD sb, DWORD sc) { EnsureInit(); return NERR_Success; }
NTSTATUS WINAPI ex_NetEnumerateTrustedDomains(LPWSTR s, LPWSTR* dn) { EnsureInit(); if(dn)*dn=NULL; return ERROR_NO_TRUST_LSA_SECRET; }

/* ============================================================================
 * NETP* INTERNAL FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetpAddTlnFtinfoEntry(void* c, void* t) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetpAllocFtinfoEntry(void* c, void* s, DWORD f, void* t, DWORD ti, void** e) { EnsureInit(); if(e)*e=NULL; return ERROR_NOT_SUPPORTED; }
void WINAPI ex_NetpAssertFailed(LPCSTR f, DWORD l, LPCSTR m) { EnsureInit(); }
NET_API_STATUS WINAPI ex_NetpCleanFtinfoContext(void* c) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetpCloseConfigData(HANDLE h) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetpCopyFtinfoContext(void* s, void* d) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
void CDECL ex_NetpDbgPrint(LPCSTR fmt, ...) { EnsureInit(); }
NET_API_STATUS WINAPI ex_NetpGetConfigBool(HANDLE h, LPCWSTR k, DWORD d, BOOL* v) { EnsureInit(); if(v)*v=(BOOL)d; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetpGetConfigDword(HANDLE h, LPCWSTR k, DWORD d, DWORD* v) { EnsureInit(); if(v)*v=d; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetpGetConfigTStrArray(HANDLE h, LPCWSTR k, LPWSTR* v) { EnsureInit(); if(v)*v=NULL; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetpGetConfigValue(HANDLE h, LPCWSTR k, LPWSTR* v) { EnsureInit(); if(v)*v=NULL; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetpGetFileSecurity(LPCWSTR f, DWORD ri, PSECURITY_DESCRIPTOR* sd, DWORD* sdl) { EnsureInit(); if(sd)*sd=NULL; return ERROR_NOT_SUPPORTED; }
void WINAPI ex_NetpHexDump(LPBYTE b, DWORD bs) { EnsureInit(); }
NET_API_STATUS WINAPI ex_NetpInitFtinfoContext(void* c) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_NetpIsRemote(LPWSTR cn, LPDWORD lr) { 
    EnsureInit(); 
    if(!lr) return ERROR_INVALID_PARAMETER; 
    *lr = (!cn || !*cn || IsLocalComputer(cn)) ? 0 : 1; 
    return NERR_Success; 
}

NET_API_STATUS WINAPI ex_NetpIsUncComputerNameValid(LPCWSTR cn) {
    EnsureInit();
    if(!cn || !*cn) return ERROR_INVALID_PARAMETER;
    if(wcsncmp(cn, L"\\\\", 2) != 0) return ERROR_INVALID_PARAMETER;
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetpMergeFtinfo(void* s, void* d, void** o) { EnsureInit(); if(o)*o=NULL; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetpNetBiosReset(UCHAR ln) { EnsureInit(); return NERR_Success; }

DWORD WINAPI ex_NetpNetBiosStatusToApiStatus(DWORD ns) { 
    EnsureInit(); 
    switch(ns) {
        case 0x00: return NERR_Success;
        case 0x05: return ERROR_REM_NOT_LIST;
        case 0x14: return ERROR_REM_NOT_LIST;
        case 0x35: return ERROR_NOT_ENOUGH_MEMORY;
        default: return ERROR_UNEXP_NET_ERR;
    }
}

NET_API_STATUS WINAPI ex_NetpOpenConfigData(PHANDLE h, LPCWSTR s, LPCWSTR k, BOOL w) { EnsureInit(); if(h)*h=NULL; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetpSetFileSecurity(LPCWSTR f, DWORD si, PSECURITY_DESCRIPTOR sd) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

/* ============================================================================
 * NETPw* NAME/PATH FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NetpwNameCanonicalize(LPCWSTR s, LPCWSTR n, LPWSTR ob, DWORD obs, DWORD nt, DWORD f) {
    EnsureInit();
    if(!n || !ob || obs == 0) return ERROR_INVALID_PARAMETER;
    wcsncpy(ob, n, obs / sizeof(WCHAR));
    ob[obs / sizeof(WCHAR) - 1] = L'\0';
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetpwNameCompare(LPCWSTR s, LPCWSTR n1, LPCWSTR n2, DWORD nt, DWORD f) { 
    EnsureInit(); 
    if(!n1 || !n2) return ERROR_INVALID_PARAMETER; 
    return (_wcsicmp(n1, n2) == 0) ? 0 : 1; 
}

NET_API_STATUS WINAPI ex_NetpwNameValidate(LPCWSTR s, LPCWSTR n, DWORD nt, DWORD f) { 
    EnsureInit(); 
    if(!n || !*n) return ERROR_INVALID_PARAMETER; 
    return NERR_Success; 
}

NET_API_STATUS WINAPI ex_NetpwPathCanonicalize(LPCWSTR s, LPCWSTR p, LPWSTR op, DWORD ops, LPCWSTR pr, LPDWORD pt, DWORD f) {
    EnsureInit();
    if(!p || !op || ops == 0) return ERROR_INVALID_PARAMETER;
    wcsncpy(op, p, ops / sizeof(WCHAR));
    op[ops / sizeof(WCHAR) - 1] = L'\0';
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetpwPathCompare(LPCWSTR s, LPCWSTR p1, LPCWSTR p2, DWORD pt, DWORD f) { 
    EnsureInit(); 
    if(!p1 || !p2) return ERROR_INVALID_PARAMETER; 
    return (_wcsicmp(p1, p2) == 0) ? 0 : 1; 
}

NET_API_STATUS WINAPI ex_NetpwPathType(LPCWSTR s, LPCWSTR p, LPDWORD pt, DWORD f) { 
    EnsureInit(); 
    if(!p || !pt) return ERROR_INVALID_PARAMETER; 
    *pt = 0; 
    return NERR_Success; 
}

/* ============================================================================
 * NLBINDING FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_NlBindingAddServerToCache(LPCWSTR s, void* b, DWORD f) { EnsureInit(); return NERR_Success; }
NET_API_STATUS WINAPI ex_NlBindingRemoveServerFromCache(LPCWSTR s, DWORD f) { EnsureInit(); return NERR_Success; }
NET_API_STATUS WINAPI ex_NlBindingSetAuthInfo(LPCWSTR s, DWORD al, void* ac, DWORD f) { EnsureInit(); return NERR_Success; }

/* ============================================================================
 * RXNET* REMOTE API FUNCTIONS
 * ============================================================================ */
NET_API_STATUS WINAPI ex_RxNetAccessAdd(LPCWSTR s, DWORD l, LPBYTE b, LPDWORD e) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_RxNetAccessDel(LPCWSTR s, LPCWSTR r) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_RxNetAccessEnum(LPCWSTR s, LPCWSTR bp, DWORD r, DWORD l, LPBYTE* b, DWORD* bs, LPDWORD er, LPDWORD te, LPDWORD rh) { 
    EnsureInit(); 
    if(b)*b=NULL; if(er)*er=0; if(te)*te=0; 
    return ERROR_NOT_SUPPORTED; 
}
NET_API_STATUS WINAPI ex_RxNetAccessGetInfo(LPCWSTR s, LPCWSTR r, DWORD l, LPBYTE* b) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_RxNetAccessGetUserPerms(LPCWSTR s, LPCWSTR ugn, LPCWSTR r, LPDWORD p) { EnsureInit(); if(p)*p=0; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_RxNetAccessSetInfo(LPCWSTR s, LPCWSTR r, DWORD l, LPBYTE b, LPDWORD pe) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_RxNetServerEnum(LPCWSTR s, LPCWSTR d, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, DWORD st, LPCWSTR fn) { 
    EnsureInit(); 
    if(b)*b=NULL; if(er)*er=0; if(te)*te=0; 
    return ERROR_NOT_SUPPORTED; 
}
NET_API_STATUS WINAPI ex_RxNetUserPasswordSet(LPCWSTR s, LPCWSTR u, LPCWSTR op, LPCWSTR np) { EnsureInit(); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_RxRemoteApi(DWORD a, LPCWSTR s, LPBYTE d, LPBYTE p, LPBYTE pa, LPBYTE pa2, DWORD f, DWORD al, DWORD sl, void* r) { EnsureInit(); return ERROR_NOT_SUPPORTED; }

/* ============================================================================
 * DLL ENTRY POINT
 * ============================================================================ */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            if (g_initCount > 0) {
                if (g_nbInitialized) DeleteCriticalSection(&g_nbLock);
#if ENABLE_FILE_LOGGING
                if (g_logLockInit) {
                    if (g_logFile) fclose(g_logFile);
                    DeleteCriticalSection(&g_logLock);
                }
#endif
#if ENABLE_DEBUG_CONSOLE
                FreeConsole();
#endif
            }
            break;
    }
    return TRUE;
}

#ifdef __cplusplus
}
#endif