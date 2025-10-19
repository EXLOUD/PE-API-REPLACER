#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>
#include <lm.h> 

// --- Коди помилок з lmerr.h ---
#define NERR_NotConn 2250
#define NERR_ReplecDirNotFound 2185
#define NERR_NotLocalMachine 2368

// --- З nb30.h (NetBIOS) ---
typedef struct _NCB {
    UCHAR ncb_command; UCHAR ncb_retcode; UCHAR ncb_lsn; UCHAR ncb_num; LPVOID ncb_buffer; WORD ncb_length;
    UCHAR ncb_callname[16]; UCHAR ncb_name[16]; UCHAR ncb_rto; UCHAR ncb_sto; void (*ncb_post)(struct _NCB*);
    UCHAR ncb_lana_num; UCHAR ncb_cmd_cplt; UCHAR ncb_reserve[10]; HANDLE ncb_event;
} NCB, *PNCB;
#define NRC_ILLCMD 0x03 // Illegal command

// --- З iphlpapi.h ---
typedef DWORD* PIP4_ADDRESS;

// --- З ntdsapi.h, dsgetdc.h, dsrole.h (Active Directory) ---
typedef struct _DS_SITE_NAME_A { CHAR *pSiteName; } DS_SITE_NAME_A, *PDS_SITE_NAME_A;
typedef struct _DS_SITE_NAME_W { WCHAR *pSiteName; } DS_SITE_NAME_W, *PDS_SITE_NAME_W;
typedef struct _DS_DOMAIN_TRUSTSA { LPSTR NetbiosDomainName; } DS_DOMAIN_TRUSTSA, *PDS_DOMAIN_TRUSTSA;
typedef struct _DS_DOMAIN_TRUSTSW { LPWSTR NetbiosDomainName; } DS_DOMAIN_TRUSTSW, *PDS_DOMAIN_TRUSTSW;
typedef struct _DOMAIN_CONTROLLER_INFOA { LPSTR DomainControllerName; } DOMAIN_CONTROLLER_INFOA, *PDOMAIN_CONTROLLER_INFOA;
typedef struct _DOMAIN_CONTROLLER_INFOW { LPWSTR DomainControllerName; } DOMAIN_CONTROLLER_INFOW, *PDOMAIN_CONTROLLER_INFOW;
typedef enum _DSROLE_PRIMARY_DOMAIN_INFO_LEVEL { DsRolePrimaryDomainInfoBasic } DSROLE_PRIMARY_DOMAIN_INFO_LEVEL;

// --- З ntsecapi.h (LSA) ---
typedef struct _LSA_UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
typedef LSA_UNICODE_STRING* LPLSA_UNICODE_STRING;
typedef struct _LSA_FOREST_TRUST_INFORMATION *PLSA_FOREST_TRUST_INFORMATION;

// --- З lmlogon.h (NetLogon) ---
typedef struct _NETLOGON_AUTHENTICATOR { BYTE data[16]; } NETLOGON_AUTHENTICATOR, *PNETLOGON_AUTHENTICATOR;
typedef struct _NETLOGON_CREDENTIAL { BYTE data[8]; } NETLOGON_CREDENTIAL, *PNETLOGON_CREDENTIAL;
typedef enum _NETLOGON_LOGON_INFO_CLASS { NetlogonInteractiveInformation = 1 } NETLOGON_LOGON_INFO_CLASS;
typedef enum _NETLOGON_VALIDATION_INFO_CLASS { NetlogonValidationSamInfo = 1, NetlogonValidationSamInfo2 = 2 } NETLOGON_VALIDATION_INFO_CLASS;
typedef struct _NETLOGON_CLIENT_ATTRIBUTES *PNETLOGON_CLIENT_ATTRIBUTES;
typedef struct _NETLOGON_VALIDATION_SAM_INFO *PNETLOGON_VALIDATION_SAM_INFO;
typedef struct _NETLOGON_INTERACTIVE_INFO *PNETLOGON_INTERACTIVE_INFO;
typedef struct _NETLOGON_AUTONOMOUS_SECRET *PNETLOGON_AUTONOMOUS_SECRET;
typedef struct _NL_TRUST_INFORMATION *PNL_TRUST_INFORMATION;
typedef struct _NL_TRUST_PASSWORD *PNL_TRUST_PASSWORD;

// --- З dfsfsctl.h ---
typedef enum _DFS_NAMESPACE_VERSION_ORIGIN { DFS_NAMESPACE_VERSION_ORIGIN_DOMAIN, DFS_NAMESPACE_VERSION_ORIGIN_SERVER } DFS_NAMESPACE_VERSION_ORIGIN;
typedef struct _DFS_SUPPORTED_NAMESPACE_VERSION_INFO {
    ULONG DomainDfsMajorVersion; ULONG DomainDfsMinorVersion; ULONGLONG DomainDfsCapabilities;
    ULONG StandaloneDfsMajorVersion; ULONG StandaloneDfsMinorVersion; ULONGLONG StandaloneDfsCapabilities;
} DFS_SUPPORTED_NAMESPACE_VERSION_INFO, *PDFS_SUPPORTED_NAMESPACE_VERSION_INFO;

// --- З lmjoin.h ---
typedef struct _NETSETUP_PROVISIONING_PARAMS *PNETSETUP_PROVISIONING_PARAMS;
typedef struct _DSREG_JOIN_INFO *PDSREG_JOIN_INFO;


// === Механізм логування ===
static CRITICAL_SECTION g_csLog;
static WCHAR g_wszLogFilePath[MAX_PATH];
static BOOL g_bLoggingInitialized = FALSE;

void LogMessage(const wchar_t* format, ...) {
    if (!g_bLoggingInitialized) return;

    EnterCriticalSection(&g_csLog);

    FILE* pFile = NULL;
    if (_wfopen_s(&pFile, g_wszLogFilePath, L"a+, ccs=UTF-8") == 0 && pFile != NULL) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fwprintf(pFile, L"[%04d-%02d-%02d %02d:%02d:%02d.%03d] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

        va_list args;
        va_start(args, format);
        vfwprintf(pFile, format, args);
        va_end(args);

        fwprintf(pFile, L"\n");
        fclose(pFile);
    }

    LeaveCriticalSection(&g_csLog);
}

// === DLL Entry Point ===
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            InitializeCriticalSection(&g_csLog);
            if (GetTempPathW(MAX_PATH, g_wszLogFilePath) > 0) {
                wcscat_s(g_wszLogFilePath, MAX_PATH, L"exnetapi.log");
                g_bLoggingInitialized = TRUE;
                LogMessage(L"===== DLL Loaded =====");
            }
            break;
        case DLL_PROCESS_DETACH:
            if(g_bLoggingInitialized) {
                 LogMessage(L"===== DLL Unloaded =====");
                 g_bLoggingInitialized = FALSE;
            }
            DeleteCriticalSection(&g_csLog);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

// --- Службові функції ---
static BOOL IsLocalComputer(LPCWSTR server) {
    if (!server || !wcslen(server)) return TRUE;
    if (wcsncmp(server, L"\\\\", 2) != 0) return FALSE;
    LPCWSTR name = server + 2;
    if (wcslen(name) == 0) return TRUE;
    if (wcsicmp(name, L"localhost") == 0) return TRUE;
    if (wcsicmp(name, L"127.0.0.1") == 0) return TRUE;
    if (wcsicmp(name, L"::1") == 0) return TRUE;
    WCHAR local[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = ARRAYSIZE(local);
    if (GetComputerNameW(local, &size)) { return (wcsicmp(name, local) == 0); }
    return FALSE;
}

static DWORD AllocAndCopyString(
    LMSTR* target, 
    LPCWSTR source, 
    LPBYTE* base, 
    DWORD* offset,
    DWORD totalSize)
{
    if (!target || !base || !offset) {
        return ERROR_INVALID_PARAMETER;
    }
    
    if (!source) { 
        *target = NULL; 
        return NERR_Success; 
    }
    
    // Обчислити розмір рядка
    DWORD len = (wcslen(source) + 1) * sizeof(WCHAR);
    
    // ✓ ПЕРЕВІРКА 1: Чи *offset перевищує totalSize?
    if (*offset >= totalSize) {
        return ERROR_BUFFER_OVERFLOW;
    }
    
    // ✓ ПЕРЕВІРКА 2: Чи вмістимо рядок у вільну пам'ять?
    if (*offset + len > totalSize) {
        return ERROR_BUFFER_OVERFLOW;
    }
    
    // Безпечне копіювання
    *target = (LMSTR)(*base + *offset);
    memcpy(*target, source, len);
    *offset += len;
    
    return NERR_Success;
}

// --- Буферні функції ---
NET_API_STATUS WINAPI ex_NetApiBufferAllocate(DWORD ByteCount, LPVOID* Buffer) {
    LogMessage(L"ex_NetApiBufferAllocate(ByteCount: %lu)", ByteCount);
    if (!Buffer) return ERROR_INVALID_PARAMETER;
    *Buffer = malloc(ByteCount);
    NET_API_STATUS status = (*Buffer) ? NERR_Success : ERROR_NOT_ENOUGH_MEMORY;
    LogMessage(L" -> ex_NetApiBufferAllocate returning %lu, Buffer: %p", status, *Buffer);
    return status;
}
NET_API_STATUS WINAPI ex_NetapipBufferAllocate(DWORD ByteCount, LPVOID* Buffer) {
    LogMessage(L"ex_NetapipBufferAllocate(ByteCount: %lu)", ByteCount);
    return ex_NetApiBufferAllocate(ByteCount, Buffer); 
}
NET_API_STATUS WINAPI ex_NetApiBufferFree(LPVOID Buffer) {
    LogMessage(L"ex_NetApiBufferFree(Buffer: %p)", Buffer);
    if (Buffer) { free(Buffer); }
    return NERR_Success;
}
NET_API_STATUS WINAPI ex_NetApiBufferReallocate(LPVOID OldBuffer, DWORD NewByteCount, LPVOID* NewBuffer) {
    LogMessage(L"ex_NetApiBufferReallocate(OldBuffer: %p, NewByteCount: %lu)", OldBuffer, NewByteCount);
    if (!NewBuffer) return ERROR_INVALID_PARAMETER;
    *NewBuffer = realloc(OldBuffer, NewByteCount);
    NET_API_STATUS status = (*NewBuffer) ? NERR_Success : ERROR_NOT_ENOUGH_MEMORY;
    LogMessage(L" -> ex_NetApiBufferReallocate returning %lu, NewBuffer: %p", status, *NewBuffer);
    return status;
}
NET_API_STATUS WINAPI ex_NetApiBufferSize(LPVOID Buffer, LPDWORD ByteCount) {
    LogMessage(L"ex_NetApiBufferSize(Buffer: %p)", Buffer);
    if (!Buffer || !ByteCount) return ERROR_INVALID_PARAMETER;
    #ifdef _WIN32
    *ByteCount = (DWORD)_msize(Buffer);
    #else
    *ByteCount = 0;
    #endif
    LogMessage(L" -> ex_NetApiBufferSize returning size: %lu", *ByteCount);
    return NERR_Success;
}

// === lmwksta.h - Workstation Functions ===
NET_API_STATUS WINAPI ex_NetWkstaGetInfo(LMSTR servername, DWORD level, LPBYTE* bufptr) {
    LogMessage(L"ex_NetWkstaGetInfo(servername: %s, level: %lu)", servername ? servername : L"(null)", level);
    if (!IsLocalComputer(servername)) return NERR_InvalidComputer;
    if (level != 100) return ERROR_INVALID_LEVEL;
    if (!bufptr) return ERROR_INVALID_PARAMETER;
    
    WCHAR compName[MAX_COMPUTERNAME_LENGTH + 1] = L""; 
    WCHAR langroup[DNLEN + 1] = L"WORKGROUP";
    DWORD compSize = ARRAYSIZE(compName), groupSize = ARRAYSIZE(langroup);
    GetComputerNameW(compName, &compSize); 
    GetComputerNameExW(ComputerNameNetBIOS, langroup, &groupSize);
    
    // Розрахунок розміру буфера
    DWORD totalSize = sizeof(WKSTA_INFO_100) + (wcslen(compName) + 1 + wcslen(langroup) + 1) * sizeof(WCHAR);
    PWKSTA_INFO_100 info = NULL;
    
    NET_API_STATUS err = ex_NetApiBufferAllocate(totalSize, (LPVOID*)&info);
    if (err != NERR_Success) { 
        LogMessage(L" -> ex_NetWkstaGetInfo returning %lu", err); 
        return err; 
    }
    
    LPBYTE ptr = (LPBYTE)(info + 1); 
    DWORD offset = 0;
    
    // ---> ВИПРАВЛЕНО: Додано п'ятий аргумент 'totalSize'
    AllocAndCopyString(&info->wki100_computername, compName, &ptr, &offset, totalSize);
    AllocAndCopyString(&info->wki100_langroup, langroup, &ptr, &offset, totalSize);
    
    info->wki100_platform_id = PLATFORM_ID_NT; 
    info->wki100_ver_major = 10; 
    info->wki100_ver_minor = 0;
    
    *bufptr = (LPBYTE)info;
    LogMessage(L" -> ex_NetWkstaGetInfo returning NERR_Success");
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetWkstaSetInfo(LMSTR s, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetWkstaSetInfo(servername: %s, level: %lu)", s ? s : L"(null)", l); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetWkstaUserGetInfo(LMSTR r, DWORD l, LPBYTE* b) { LogMessage(L"ex_NetWkstaUserGetInfo(level: %lu)", l); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetWkstaUserSetInfo(LMSTR r, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetWkstaUserSetInfo(level: %lu)", l); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetWkstaUserEnum(LMSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetWkstaUserEnum(servername: %s, level: %lu)", s ? s : L"(null)", l); if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (!b||!er||!te) return ERROR_INVALID_PARAMETER; *er = *te = 0; *b = NULL; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetWkstaTransportAdd(LMSTR s, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetWkstaTransportAdd(servername: %s, level: %lu)", s ? s : L"(null)", l); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetWkstaTransportDel(LMSTR s, LMSTR t, DWORD u) { LogMessage(L"ex_NetWkstaTransportDel(servername: %s, transport: %s)", s ? s : L"(null)", t ? t : L"(null)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetWkstaTransportEnum(LMSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetWkstaTransportEnum(servername: %s, level: %lu)", s ? s : L"(null)", l); if (!IsLocalComputer(s)) return ERROR_NOT_SUPPORTED; if (l != 0) return ERROR_INVALID_LEVEL; if (!b||!er||!te) return ERROR_INVALID_PARAMETER; *er = *te = 0; *b = NULL; return NERR_Success; }

// === lmserver.h - Server Functions ===
NET_API_STATUS WINAPI ex_NetServerEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, DWORD st, LPCWSTR d, LPDWORD rh) {
    LogMessage(L"ex_NetServerEnum(servername: %s, level: %lu)", s ? s : L"(null)", l);
    if (!IsLocalComputer(s)) return NERR_InvalidComputer; 
    if (l != 101) return ERROR_INVALID_LEVEL; 
    if (!b || !er || !te) return ERROR_INVALID_PARAMETER;
    
    WCHAR name[MAX_COMPUTERNAME_LENGTH + 1]; 
    DWORD size = ARRAYSIZE(name); 
    GetComputerNameW(name, &size);
    
    DWORD totalSize = sizeof(SERVER_INFO_101) + (wcslen(name) + 1 + 1) * sizeof(WCHAR); // +1 для порожнього коментаря
    PSERVER_INFO_101 info = NULL; 
    NET_API_STATUS err = ex_NetApiBufferAllocate(totalSize, (LPVOID*)&info); 
    if (err != NERR_Success) return err;
    
    LPBYTE ptr = (LPBYTE)(info + 1); 
    DWORD offset = 0;
    
    // ---> ВИПРАВЛЕНО: Додано п'ятий аргумент 'totalSize'
    AllocAndCopyString(&info->sv101_name, name, &ptr, &offset, totalSize);
    AllocAndCopyString(&info->sv101_comment, L"", &ptr, &offset, totalSize);
    
    info->sv101_platform_id = PLATFORM_ID_NT; 
    info->sv101_version_major = 10; 
    info->sv101_version_minor = 0; 
    info->sv101_type = SV_TYPE_WORKSTATION | SV_TYPE_SERVER;
    
    *b = (LPBYTE)info; 
    *er = *te = 1; 
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetServerEnumEx(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, DWORD st, LPCWSTR d, LPCWSTR f) { LogMessage(L"ex_NetServerEnumEx(...)"); return ex_NetServerEnum(s, l, b, p, er, te, st, d, NULL); }
NET_API_STATUS WINAPI ex_NetServerGetInfo(LMSTR s, DWORD l, LPBYTE *b) { LogMessage(L"ex_NetServerGetInfo(servername: %s, level: %lu)", s ? s : L"(null)", l); if (l == 101) { DWORD er, te; return ex_NetServerEnum(s, l, b, MAX_PREFERRED_LENGTH, &er, &te, 0, NULL, NULL); } return ERROR_INVALID_LEVEL; }
NET_API_STATUS WINAPI ex_NetServerSetInfo(LMSTR s, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetServerSetInfo(servername: %s, level: %lu)", s ? s : L"(null)", l); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }

// === lmshare.h - Share Functions ===
NET_API_STATUS WINAPI ex_NetShareAdd(LMSTR s, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetShareAdd(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetShareCheck(LMSTR s, LMSTR d, LPDWORD t) { LogMessage(L"ex_NetShareCheck(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetShareDel(LMSTR s, LMSTR n, DWORD r) { LogMessage(L"ex_NetShareDel(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetShareDelEx(LPCWSTR s, DWORD l, LPBYTE b) { LogMessage(L"ex_NetShareDelEx(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetShareDelSticky(LMSTR s, LMSTR n, DWORD r) { LogMessage(L"ex_NetShareDelSticky(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }

NET_API_STATUS WINAPI ex_NetShareEnum(LMSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) {
    LogMessage(L"ex_NetShareEnum(servername: %s, level: %lu)", s ? s : L"(null)", l);
    if (!IsLocalComputer(s)) return NERR_InvalidComputer; 
    if (l != 2) return ERROR_INVALID_LEVEL; 
    if (!b || !er || !te) return ERROR_INVALID_PARAMETER;
    
    SHARE_INFO_2 temp = {0}; 
    temp.shi2_netname = L"C$"; 
    temp.shi2_type = STYPE_DISKTREE; 
    temp.shi2_remark = L"Default share"; 
    temp.shi2_max_uses = (DWORD)-1; 
    temp.shi2_current_uses = 1; 
    temp.shi2_path = L"C:\\";
    
    DWORD totalSize = sizeof(SHARE_INFO_2) + (wcslen(temp.shi2_netname) + 1 + wcslen(temp.shi2_remark) + 1 + wcslen(temp.shi2_path) + 1) * sizeof(WCHAR);
    PSHARE_INFO_2 info = NULL; 
    NET_API_STATUS err = ex_NetApiBufferAllocate(totalSize, (LPVOID*)&info); 
    if (err != NERR_Success) return err;
    
    LPBYTE ptr = (LPBYTE)(info + 1); 
    DWORD offset = 0;
    
    // ---> ВИПРАВЛЕНО: Додано п'ятий аргумент 'totalSize'
    AllocAndCopyString(&info->shi2_netname, temp.shi2_netname, &ptr, &offset, totalSize);
    AllocAndCopyString(&info->shi2_remark, temp.shi2_remark, &ptr, &offset, totalSize);
    AllocAndCopyString(&info->shi2_path, temp.shi2_path, &ptr, &offset, totalSize);
    
    info->shi2_type = temp.shi2_type; 
    info->shi2_permissions = 0; 
    info->shi2_max_uses = temp.shi2_max_uses; 
    info->shi2_current_uses = temp.shi2_current_uses; 
    info->shi2_passwd = NULL;
    
    *b = (LPBYTE)info; 
    *er = *te = 1; 
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetShareEnumSticky(LMSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetShareEnumSticky(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetShareGetInfo(LMSTR s, LMSTR n, DWORD l, LPBYTE* b) { LogMessage(L"ex_NetShareGetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_NetNameNotFound; }
NET_API_STATUS WINAPI ex_NetShareSetInfo(LMSTR s, LMSTR n, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetShareSetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_NetNameNotFound; }

// === lmjoin.h - Join Functions ===
DWORD WINAPI ex_NetGetJoinInformation(LPCWSTR s, LPWSTR* n, PNETSETUP_JOIN_STATUS bt) {
    LogMessage(L"ex_NetGetJoinInformation(server: %s)", s ? s : L"(null)");
    if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (!bt) return ERROR_INVALID_PARAMETER;
    WCHAR domain[DNLEN + 1] = L"WORKGROUP"; DWORD size = ARRAYSIZE(domain);
    NETSETUP_JOIN_STATUS status = NetSetupWorkgroupName;
    if (GetComputerNameExW(ComputerNameDnsDomain, domain, &size) && size > 1) status = NetSetupDomainName;
    NET_API_STATUS err = ex_NetApiBufferAllocate((wcslen(domain) + 1) * sizeof(WCHAR), (LPVOID*)n); if (err != NERR_Success) return err;
    wcscpy_s(*n, wcslen(domain) + 1, domain); *bt = status; return NERR_Success;
}

// === lmstats.h - Statistics Functions ===
NET_API_STATUS WINAPI ex_NetStatisticsGet(LMSTR s, LMSTR sv, DWORD l, DWORD o, LPBYTE* b) { LogMessage(L"ex_NetStatisticsGet(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (l != 0) return ERROR_INVALID_LEVEL; if (!b) return ERROR_INVALID_PARAMETER; NET_API_STATUS err = ex_NetApiBufferAllocate(sizeof(STAT_WORKSTATION_0), (LPVOID*)b); if (err != NERR_Success) return err; ZeroMemory(*b, sizeof(STAT_WORKSTATION_0)); return NERR_Success; }

// === Miscellaneous Functions ===
NET_API_STATUS WINAPI ex_NetMessageBufferSend(LPCWSTR s, LPCWSTR m, LPCWSTR f, LPBYTE b, DWORD bl) { LogMessage(L"ex_NetMessageBufferSend(...)"); return NERR_Success; }
UCHAR WINAPI ex_Netbios(PNCB pncb) { LogMessage(L"ex_Netbios(...)"); if (pncb) pncb->ncb_retcode = NRC_ILLCMD; return NRC_ILLCMD; }

// === lmaudit.h - Audit Functions ===
DWORD WINAPI ex_NetAuditClear(LPCWSTR s, LPCWSTR bf, LPCWSTR sv) { LogMessage(L"ex_NetAuditClear(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
DWORD WINAPI ex_NetAuditRead(LPCWSTR s, LPCWSTR sv, LPHLOG ah, DWORD o, LPDWORD r1, DWORD r2, DWORD of, LPBYTE* b, DWORD p, LPDWORD br, LPDWORD ta) { LogMessage(L"ex_NetAuditRead(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
DWORD WINAPI ex_NetAuditWrite(DWORD t, LPBYTE b, DWORD nb, LPCWSTR sv, LPBYTE r) { LogMessage(L"ex_NetAuditWrite(...)"); return ERROR_ACCESS_DENIED; }

// === lmalert.h - Alert Functions ===
NET_API_STATUS WINAPI ex_NetAlertRaise(LPCWSTR a, LPVOID b, DWORD bs) { LogMessage(L"ex_NetAlertRaise(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetAlertRaiseEx(LPCWSTR a, LPVOID v, DWORD vs, LPCWSTR sn) { LogMessage(L"ex_NetAlertRaiseEx(...)"); return ERROR_NOT_SUPPORTED; }

// === lmaccess.h - User Functions ===
NET_API_STATUS WINAPI ex_NetUserAdd(LPCWSTR s, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetUserAdd(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_UserExists; }
NET_API_STATUS WINAPI ex_NetUserEnum(LPCWSTR s, DWORD l, DWORD f, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetUserEnum(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (l > 3 && l != 10 && l != 11 && l != 20 && l != 23) return ERROR_INVALID_LEVEL; if (!b||!er||!te) return ERROR_INVALID_PARAMETER; *er = *te = 0; *b = NULL; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetUserGetInfo(LPCWSTR s, LPCWSTR u, DWORD l, LPBYTE* b) { LogMessage(L"ex_NetUserGetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_UserNotFound; }
NET_API_STATUS WINAPI ex_NetUserSetInfo(LPCWSTR s, LPCWSTR u, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetUserSetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetUserDel(LPCWSTR s, LPCWSTR u) { LogMessage(L"ex_NetUserDel(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_UserNotFound; }
NET_API_STATUS WINAPI ex_NetUserGetGroups(LPCWSTR s, LPCWSTR u, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te) { LogMessage(L"ex_NetUserGetGroups(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; *er = 0; *te = 0; *b = NULL; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetUserSetGroups(LPCWSTR s, LPCWSTR u, DWORD l, LPBYTE b, DWORD ne) { LogMessage(L"ex_NetUserSetGroups(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetUserGetLocalGroups(LPCWSTR s, LPCWSTR u, DWORD l, DWORD f, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te) { LogMessage(L"ex_NetUserGetLocalGroups(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; *er = 0; *te = 0; *b = NULL; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetUserModalsGet(LPCWSTR s, DWORD l, LPBYTE* b) {
    LogMessage(L"ex_NetUserModalsGet(...)");
    if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (l > 3) return ERROR_INVALID_LEVEL;
    DWORD size = 0; if (l == 0) size = sizeof(USER_MODALS_INFO_0); else if (l == 1) size = sizeof(USER_MODALS_INFO_1); else if (l == 2) size = sizeof(USER_MODALS_INFO_2); else if (l == 3) size = sizeof(USER_MODALS_INFO_3); else return ERROR_INVALID_LEVEL;
    NET_API_STATUS status = ex_NetApiBufferAllocate(size, (LPVOID*)b); if(status == NERR_Success) { ZeroMemory(*b, size); } return status;
}
NET_API_STATUS WINAPI ex_NetUserModalsSet(LPCWSTR s, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetUserModalsSet(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetUserChangePassword(LPCWSTR d, LPCWSTR u, LPCWSTR o, LPCWSTR n) { LogMessage(L"ex_NetUserChangePassword(...)"); if (!IsLocalComputer(d)) return NERR_InvalidComputer; return NERR_UserNotFound; }

// === lmaccess.h - Group Functions ===
NET_API_STATUS WINAPI ex_NetGroupAdd(LPCWSTR s, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetGroupAdd(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetGroupAddUser(LPCWSTR s, LPCWSTR gn, LPCWSTR un) { LogMessage(L"ex_NetGroupAddUser(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetGroupEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, PDWORD_PTR rh) { LogMessage(L"ex_NetGroupEnum(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (!b||!er||!te) return ERROR_INVALID_PARAMETER; *er = *te = 0; *b = NULL; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetGroupGetInfo(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE* b) { LogMessage(L"ex_NetGroupGetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_GroupNotFound; }
NET_API_STATUS WINAPI ex_NetGroupSetInfo(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetGroupSetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_GroupNotFound; }
NET_API_STATUS WINAPI ex_NetGroupDel(LPCWSTR s, LPCWSTR gn) { LogMessage(L"ex_NetGroupDel(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetGroupDelUser(LPCWSTR s, LPCWSTR gn, LPCWSTR un) { LogMessage(L"ex_NetGroupDelUser(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetGroupGetUsers(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, PDWORD_PTR rh) { LogMessage(L"ex_NetGroupGetUsers(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (!b||!er||!te) return ERROR_INVALID_PARAMETER; *er = *te = 0; *b = NULL; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetGroupSetUsers(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE b, DWORD te) { LogMessage(L"ex_NetGroupSetUsers(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_GroupNotFound; }

// === lmaccess.h - LocalGroup Functions ===
NET_API_STATUS WINAPI ex_NetLocalGroupAdd(LPCWSTR s, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetLocalGroupAdd(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_GroupExists; }
NET_API_STATUS WINAPI ex_NetLocalGroupAddMember(LPCWSTR s, LPCWSTR gn, PSID m) { LogMessage(L"ex_NetLocalGroupAddMember(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetLocalGroupEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, PDWORD_PTR rh) { LogMessage(L"ex_NetLocalGroupEnum(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (!b||!er||!te) return ERROR_INVALID_PARAMETER; *er = *te = 0; *b = NULL; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetLocalGroupGetInfo(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE* b) { LogMessage(L"ex_NetLocalGroupGetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_GroupNotFound; }
NET_API_STATUS WINAPI ex_NetLocalGroupSetInfo(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetLocalGroupSetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_GroupNotFound; }
NET_API_STATUS WINAPI ex_NetLocalGroupDel(LPCWSTR s, LPCWSTR gn) { LogMessage(L"ex_NetLocalGroupDel(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetLocalGroupDelMember(LPCWSTR s, LPCWSTR gn, PSID m) { LogMessage(L"ex_NetLocalGroupDelMember(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetLocalGroupGetMembers(LPCWSTR s, LPCWSTR lgn, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, PDWORD_PTR rh) { LogMessage(L"ex_NetLocalGroupGetMembers(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (!b||!er||!te) return ERROR_INVALID_PARAMETER; *er = *te = 0; *b = NULL; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetLocalGroupSetMembers(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE b, DWORD te) { LogMessage(L"ex_NetLocalGroupSetMembers(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetLocalGroupAddMembers(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE b, DWORD te) { LogMessage(L"ex_NetLocalGroupAddMembers(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetLocalGroupDelMembers(LPCWSTR s, LPCWSTR gn, DWORD l, LPBYTE b, DWORD te) { LogMessage(L"ex_NetLocalGroupDelMembers(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }

// === lmaccess.h - Display Information Functions ===
NET_API_STATUS WINAPI ex_NetQueryDisplayInformation(LPCWSTR s, DWORD l, DWORD i, DWORD er, DWORD p, LPDWORD rec, PVOID* sb) { LogMessage(L"ex_NetQueryDisplayInformation(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (!rec||!sb) return ERROR_INVALID_PARAMETER; *rec = 0; *sb = NULL; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetGetDisplayInformationIndex(LPCWSTR s, DWORD l, LPCWSTR p, LPDWORD i) { LogMessage(L"ex_NetGetDisplayInformationIndex(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (!i) return ERROR_INVALID_PARAMETER; *i = 0; return NERR_Success; }

// === lmaccess.h - Access Functions ===
NET_API_STATUS WINAPI ex_NetAccessAdd(LPCWSTR s, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetAccessAdd(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetAccessEnum(LPCWSTR s, LPCWSTR bp, DWORD r, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetAccessEnum(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (!b||!er||!te) return ERROR_INVALID_PARAMETER; *er = *te = 0; *b = NULL; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetAccessGetInfo(LPCWSTR s, LPCWSTR r, DWORD l, LPBYTE* b) { LogMessage(L"ex_NetAccessGetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetAccessSetInfo(LPCWSTR s, LPCWSTR r, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetAccessSetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetAccessDel(LPCWSTR s, LPCWSTR r) { LogMessage(L"ex_NetAccessDel(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetAccessGetUserPerms(LPCWSTR s, LPCWSTR ugn, LPCWSTR r, LPDWORD p) { LogMessage(L"ex_NetAccessGetUserPerms(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (!p) return ERROR_INVALID_PARAMETER; *p = 0; return ERROR_NOT_SUPPORTED; }

// === lmaccess.h - Password Validation Functions ===
NET_API_STATUS WINAPI ex_NetValidatePasswordPolicy(LPCWSTR s, LPVOID q, NET_VALIDATE_PASSWORD_TYPE vt, LPVOID ia, LPVOID* oa) { LogMessage(L"ex_NetValidatePasswordPolicy(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetValidatePasswordPolicyFree(LPVOID* oa) { LogMessage(L"ex_NetValidatePasswordPolicyFree(...)"); if (oa && *oa) { free(*oa); *oa = NULL; } return NERR_Success; }

// === lmaccess.h - Domain Functions ===
NET_API_STATUS WINAPI ex_NetGetDCName(LPCWSTR s, LPCWSTR d, LPBYTE* b) { LogMessage(L"ex_NetGetDCName(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NO_LOGON_SERVERS; }
NET_API_STATUS WINAPI ex_NetGetAnyDCName(LPCWSTR s, LPCWSTR d, LPBYTE* b) { LogMessage(L"ex_NetGetAnyDCName(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NO_LOGON_SERVERS; }
NET_API_STATUS WINAPI ex_I_NetLogonControl(LPCWSTR s, DWORD fc, DWORD ql, LPBYTE* b) { LogMessage(L"ex_I_NetLogonControl(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_I_NetLogonControl2(LPCWSTR s, DWORD fc, DWORD ql, LPBYTE d, LPBYTE* b) { LogMessage(L"ex_I_NetLogonControl2(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NTSTATUS WINAPI ex_NetEnumerateTrustedDomains(LPWSTR s, LPWSTR* dn) { LogMessage(L"ex_NetEnumerateTrustedDomains(...)"); if (!IsLocalComputer(s)) return ERROR_INVALID_COMPUTERNAME; if (!dn) return ERROR_INVALID_PARAMETER; *dn = NULL; return ERROR_NO_TRUST_LSA_SECRET; }

// === Service Account Functions ===
NTSTATUS WINAPI ex_NetAddServiceAccount(LPWSTR s, LPWSTR an, LPWSTR r, DWORD f) { LogMessage(L"ex_NetAddServiceAccount(...)"); if (!IsLocalComputer(s)) return ERROR_INVALID_COMPUTERNAME; return ERROR_NOT_SUPPORTED; }
NTSTATUS WINAPI ex_NetRemoveServiceAccount(LPWSTR s, LPWSTR an, DWORD f) { LogMessage(L"ex_NetRemoveServiceAccount(...)"); if (!IsLocalComputer(s)) return ERROR_INVALID_COMPUTERNAME; return ERROR_NOT_SUPPORTED; }
NTSTATUS WINAPI ex_NetIsServiceAccount(LPWSTR s, LPWSTR an, BOOL* is) { LogMessage(L"ex_NetIsServiceAccount(...)"); if (!IsLocalComputer(s)) return ERROR_INVALID_COMPUTERNAME; if (!is) return ERROR_INVALID_PARAMETER; *is = FALSE; return ERROR_NOT_SUPPORTED; }
NTSTATUS WINAPI ex_NetEnumerateServiceAccounts(LPWSTR s, DWORD f, DWORD* ac, PZPWSTR* a) { LogMessage(L"ex_NetEnumerateServiceAccounts(...)"); if (!IsLocalComputer(s)) return ERROR_INVALID_COMPUTERNAME; if (!ac||!a) return ERROR_INVALID_PARAMETER; *ac = 0; *a = NULL; return ERROR_NOT_SUPPORTED; }

// === lmuse.h - Use Functions ===
NET_API_STATUS WINAPI ex_NetUseAdd(LMSTR s, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetUseAdd(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_BAD_NETPATH; }
NET_API_STATUS WINAPI ex_NetUseDel(LMSTR s, LMSTR u, DWORD f) { LogMessage(L"ex_NetUseDel(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_NotConn; }
NET_API_STATUS WINAPI ex_NetUseEnum(LMSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetUseEnum(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (l > 2) return ERROR_INVALID_LEVEL; if (!b||!er||!te) return ERROR_INVALID_PARAMETER; *er = *te = 0; *b = NULL; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetUseGetInfo(LMSTR s, LMSTR u, DWORD l, LPBYTE* b) { LogMessage(L"ex_NetUseGetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_NotConn; }

// === lmsvc.h - Service Functions ===
NET_API_STATUS WINAPI ex_NetServiceEnum(LPCWSTR s, DWORD l, LPBYTE *b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) {
    LogMessage(L"ex_NetServiceEnum(...)");
    if (!IsLocalComputer(s)) return NERR_InvalidComputer; 
    if (l > 2) return ERROR_INVALID_LEVEL; 
    if (!b || !er || !te) return ERROR_INVALID_PARAMETER;
    
    *er = 0; 
    *te = 0; 
    *b = NULL;
    
    if (l == 1) {
        WCHAR name[] = L"LanmanServer"; 
        DWORD totalSize = sizeof(SERVICE_INFO_1) + (wcslen(name) + 1) * sizeof(WCHAR);
        PSERVICE_INFO_1 info = NULL; 
        
        NET_API_STATUS err = ex_NetApiBufferAllocate(totalSize, (LPVOID*)&info); 
        if (err != NERR_Success) return err;
        
        LPBYTE ptr = (LPBYTE)(info + 1); 
        DWORD offset = 0;
		
        AllocAndCopyString(&info->svci1_name, name, &ptr, &offset, totalSize);
        
        info->svci1_status = SERVICE_ACTIVE; 
        info->svci1_code = 0; 
        info->svci1_pid = 1234;
        
        *b = (LPBYTE)info; 
        *er = *te = 1;
    }
    return NERR_Success;
}

NET_API_STATUS WINAPI ex_NetServiceControl(LPCWSTR s, LPCWSTR sv, DWORD op, DWORD a, LPBYTE* b) { LogMessage(L"ex_NetServiceControl(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_ServiceNotInstalled; }
NET_API_STATUS WINAPI ex_NetServiceGetInfo(LPCWSTR s, LPCWSTR sv, DWORD l, LPBYTE* b) { LogMessage(L"ex_NetServiceGetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_ServiceNotInstalled; }
NET_API_STATUS WINAPI ex_NetServiceInstall(LPCWSTR s, LPCWSTR sv, DWORD ac, LPCWSTR* av, LPBYTE* b) { LogMessage(L"ex_NetServiceInstall(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_ACCESS_DENIED; }

// === lmrepl.h - Replication Functions ===
NET_API_STATUS WINAPI ex_NetReplExportDirAdd(LPCWSTR s, DWORD l, const LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetReplExportDirAdd(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplExportDirDel(LPCWSTR s, LPCWSTR d) { LogMessage(L"ex_NetReplExportDirDel(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplExportDirEnum(LPCWSTR s, DWORD l, LPBYTE *b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetReplExportDirEnum(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; *er = *te = 0; *b = NULL; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetReplExportDirGetInfo(LPCWSTR s, LPCWSTR d, DWORD l, LPBYTE *b) { LogMessage(L"ex_NetReplExportDirGetInfo(...)"); return NERR_ReplecDirNotFound; }
NET_API_STATUS WINAPI ex_NetReplExportDirLock(LPCWSTR s, LPCWSTR d) { LogMessage(L"ex_NetReplExportDirLock(...)"); return NERR_ReplecDirNotFound; }
NET_API_STATUS WINAPI ex_NetReplExportDirSetInfo(LPCWSTR s, LPCWSTR d, DWORD l, const LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetReplExportDirSetInfo(...)"); return NERR_ReplecDirNotFound; }
NET_API_STATUS WINAPI ex_NetReplExportDirUnlock(LPCWSTR s, LPCWSTR d, DWORD u) { LogMessage(L"ex_NetReplExportDirUnlock(...)"); return NERR_ReplecDirNotFound; }
NET_API_STATUS WINAPI ex_NetReplGetInfo(LPCWSTR s, DWORD l, LPBYTE *b) { LogMessage(L"ex_NetReplGetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_NotLocalMachine; }
NET_API_STATUS WINAPI ex_NetReplImportDirAdd(LPCWSTR s, DWORD l, const LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetReplImportDirAdd(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplImportDirDel(LPCWSTR s, LPCWSTR d) { LogMessage(L"ex_NetReplImportDirDel(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplImportDirEnum(LPCWSTR s, DWORD l, LPBYTE *b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetReplImportDirEnum(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; *er = *te = 0; *b = NULL; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplImportDirGetInfo(LPCWSTR s, LPCWSTR d, DWORD l, LPBYTE *b) { LogMessage(L"ex_NetReplImportDirGetInfo(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplImportDirLock(LPCWSTR s, LPCWSTR d) { LogMessage(L"ex_NetReplImportDirLock(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplImportDirUnlock(LPCWSTR s, LPCWSTR d, DWORD u) { LogMessage(L"ex_NetReplImportDirUnlock(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetReplSetInfo(LPCWSTR s, DWORD l, const LPBYTE b, LPDWORD e) { LogMessage(L"ex_NetReplSetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return NERR_NotLocalMachine; }

// === RxNet Functions ===
NET_API_STATUS WINAPI ex_RxNetAccessAdd(LPCWSTR s, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_RxNetAccessAdd(...)"); return ex_NetAccessAdd(s, l, b, e); }
NET_API_STATUS WINAPI ex_RxNetAccessDel(LPCWSTR s, LPWSTR r) { LogMessage(L"ex_RxNetAccessDel(...)"); return ex_NetAccessDel(s, r); }
NET_API_STATUS WINAPI ex_RxNetAccessEnum(LPCWSTR s, LPCWSTR bp, DWORD rec, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_RxNetAccessEnum(...)"); return ex_NetAccessEnum(s, bp, rec, l, b, p, er, te, rh); }
NET_API_STATUS WINAPI ex_RxNetAccessGetInfo(LPCWSTR s, LPCWSTR r, DWORD l, LPBYTE* b) { LogMessage(L"ex_RxNetAccessGetInfo(...)"); return ex_NetAccessGetInfo(s, r, l, b); }
NET_API_STATUS WINAPI ex_RxNetAccessGetUserPerms(LPCWSTR s, LPCWSTR ugn, LPCWSTR r, LPDWORD ps) { LogMessage(L"ex_RxNetAccessGetUserPerms(...)"); return ex_NetAccessGetUserPerms(s, ugn, r, ps); }
NET_API_STATUS WINAPI ex_RxNetAccessSetInfo(LPCWSTR s, LPCWSTR r, DWORD l, LPBYTE b, LPDWORD e) { LogMessage(L"ex_RxNetAccessSetInfo(...)"); return ex_NetAccessSetInfo(s, r, l, b, e); }
NET_API_STATUS WINAPI ex_RxNetServerEnum(LPCWSTR s, DWORD l, LPBYTE* b, DWORD p, LPDWORD er, LPDWORD te, DWORD st, LPCWSTR d, LPDWORD rh) { LogMessage(L"ex_RxNetServerEnum(...)"); return ex_NetServerEnum(s, l, b, p, er, te, st, d, rh); }
NET_API_STATUS WINAPI ex_RxNetUserPasswordSet(LPCWSTR s, LPCWSTR u, LPCWSTR o, LPCWSTR n) { LogMessage(L"ex_RxNetUserPasswordSet(...)"); return ex_NetUserChangePassword(s, u, o, n); }
NET_API_STATUS __cdecl ex_RxRemoteApi(DWORD an, LPCWSTR usn, LPDESC pds, LPDESC d16, LPDESC d32, LPDESC dsmb, LPDESC a16, LPDESC a32, LPDESC asmb, DWORD f, ...) { LogMessage(L"ex_RxRemoteApi(...)"); return ERROR_NOT_SUPPORTED; }

// === Undocumented/Internal Netp* and Nl* Functions ===
VOID ex_NetpAddTlnFtinfoEntry() { LogMessage(L"ex_NetpAddTlnFtinfoEntry(...)"); }
VOID ex_NetpAllocFtinfoEntry() { LogMessage(L"ex_NetpAllocFtinfoEntry(...)"); }
VOID __cdecl ex_NetpAssertFailed(LPCSTR file, LPCSTR line, DWORD err) { LogMessage(L"ex_NetpAssertFailed(...)"); }
VOID ex_NetpCleanFtinfoContext() { LogMessage(L"ex_NetpCleanFtinfoContext(...)"); }
VOID ex_NetpCloseConfigData() { LogMessage(L"ex_NetpCloseConfigData(...)"); }
VOID ex_NetpCopyFtinfoContext() { LogMessage(L"ex_NetpCopyFtinfoContext(...)"); }
VOID __cdecl ex_NetpDbgPrint(LPCSTR Format, ...) { LogMessage(L"ex_NetpDbgPrint(...)"); }
BOOL ex_NetpGetConfigBool(HANDLE h, LPCWSTR p1, BOOL p2) { LogMessage(L"ex_NetpGetConfigBool(...)"); return FALSE; }
DWORD ex_NetpGetConfigDword(HANDLE h, LPCWSTR p1, DWORD p2) { LogMessage(L"ex_NetpGetConfigDword(...)"); return 0; }
VOID ex_NetpGetConfigTStrArray() { LogMessage(L"ex_NetpGetConfigTStrArray(...)"); }
LPWSTR ex_NetpGetConfigValue(HANDLE h, LPCWSTR p) { LogMessage(L"ex_NetpGetConfigValue(...)"); return NULL; }
DWORD ex_NetpGetFileSecurity(LPCWSTR p1, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR* psd, PACL* pacl) { LogMessage(L"ex_NetpGetFileSecurity(...)"); return ERROR_NOT_SUPPORTED; }
VOID ex_NetpHexDump(char* p1, unsigned char* p2, unsigned int p3) { LogMessage(L"ex_NetpHexDump(...)"); }
VOID ex_NetpInitFtinfoContext() { LogMessage(L"ex_NetpInitFtinfoContext(...)"); }
NET_API_STATUS ex_NetpIsRemote(LPCWSTR p1, LPDWORD p2, LPDWORD p3, LPDWORD p4, LPDWORD p5, DWORD p6) { LogMessage(L"ex_NetpIsRemote(...)"); return NERR_Success; }
BOOL ex_NetpIsUncComputerNameValid(LPCWSTR name) { LogMessage(L"ex_NetpIsUncComputerNameValid(...)"); return TRUE; }
VOID ex_NetpMergeFtinfo() { LogMessage(L"ex_NetpMergeFtinfo(...)"); }
DWORD ex_NetpNetBiosReset(UCHAR lana) { LogMessage(L"ex_NetpNetBiosReset(...)"); return NERR_Success; }
NET_API_STATUS ex_NetpNetBiosStatusToApiStatus(UCHAR status) { LogMessage(L"ex_NetpNetBiosStatusToApiStatus(...)"); return NERR_Success; }
NET_API_STATUS ex_NetpOpenConfigData(PHANDLE h, LPCWSTR s, LPCWSTR c, DWORD d) { LogMessage(L"ex_NetpOpenConfigData(...)"); return ERROR_NOT_SUPPORTED; }
DWORD ex_NetpSetFileSecurity(LPCWSTR p1, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR psd) { LogMessage(L"ex_NetpSetFileSecurity(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS ex_NetpwNameCanonicalize(LPCWSTR p1, LPWSTR p2, DWORD p3, DWORD p4, DWORD p5) { LogMessage(L"ex_NetpwNameCanonicalize(...)"); return NERR_Success; }
NET_API_STATUS ex_NetpwNameCompare(LPCWSTR p1, LPCWSTR p2, DWORD p3, DWORD p4) { LogMessage(L"ex_NetpwNameCompare(...)"); return NERR_Success; }
NET_API_STATUS ex_NetpwNameValidate(LPCWSTR p1, DWORD p2, DWORD p3) { LogMessage(L"ex_NetpwNameValidate(...)"); return NERR_Success; }
NET_API_STATUS ex_NetpwPathCanonicalize(LPCWSTR p1, LPWSTR p2, DWORD p3, LPCWSTR p4, PDWORD p5, DWORD p6, DWORD p7) { LogMessage(L"ex_NetpwPathCanonicalize(...)"); return NERR_Success; }
NET_API_STATUS ex_NetpwPathCompare(LPCWSTR p1, LPCWSTR p2, DWORD p3, DWORD p4) { LogMessage(L"ex_NetpwPathCompare(...)"); return NERR_Success; }
NET_API_STATUS ex_NetpwPathType(LPCWSTR p1, LPDWORD p2, DWORD p3) { LogMessage(L"ex_NetpwPathType(...)"); return NERR_Success; }
VOID ex_NlBindingAddServerToCache() { LogMessage(L"ex_NlBindingAddServerToCache(...)"); }
VOID ex_NlBindingRemoveServerFromCache() { LogMessage(L"ex_NlBindingRemoveServerFromCache(...)"); }
VOID ex_NlBindingSetAuthInfo() { LogMessage(L"ex_NlBindingSetAuthInfo(...)"); }

DWORD WINAPI ex_DavAddConnection(HWND h, LPCWSTR r, LPCWSTR u, LPCWSTR p, DWORD f) { LogMessage(L"ex_DavAddConnection(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DavDeleteConnection(HWND h, LPCWSTR r) { LogMessage(L"ex_DavDeleteConnection(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DavFlushFile(LPCWSTR f) { LogMessage(L"ex_DavFlushFile(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DavGetExtendedError(HANDLE h, DWORD* e, LPWSTR es, LPDWORD c) { LogMessage(L"ex_DavGetExtendedError(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DavGetHTTPFromUNCPath(LPCWSTR u, LPWSTR h, LPDWORD s) { LogMessage(L"ex_DavGetHTTPFromUNCPath(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DavGetUNCFromHTTPPath(LPCWSTR h, LPWSTR u, LPDWORD s) { LogMessage(L"ex_DavGetUNCFromHTTPPath(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsAddressToSiteNamesA(LPCSTR c, DWORD ec, PSOCKET_ADDRESS sa, PDS_SITE_NAME_A** sn) { LogMessage(L"ex_DsAddressToSiteNamesA(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsAddressToSiteNamesExA(LPCSTR c, DWORD ec, PSOCKET_ADDRESS sa, PDS_SITE_NAME_A** sn) { LogMessage(L"ex_DsAddressToSiteNamesExA(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsAddressToSiteNamesExW(LPCWSTR c, DWORD ec, PSOCKET_ADDRESS sa, PDS_SITE_NAME_W** sn) { LogMessage(L"ex_DsAddressToSiteNamesExW(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsAddressToSiteNamesW(LPCWSTR c, DWORD ec, PSOCKET_ADDRESS sa, PDS_SITE_NAME_W** sn) { LogMessage(L"ex_DsAddressToSiteNamesW(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsDeregisterDnsHostRecordsA(LPSTR s, LPSTR d, LPSTR da, GUID* dag, ULONG iac, PIP4_ADDRESS ia) { LogMessage(L"ex_DsDeregisterDnsHostRecordsA(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsDeregisterDnsHostRecordsW(LPWSTR s, LPWSTR d, LPWSTR da, GUID* dag, ULONG iac, PIP4_ADDRESS ia) { LogMessage(L"ex_DsDeregisterDnsHostRecordsW(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsEnumerateDomainTrustsA(LPSTR s, ULONG f, PDS_DOMAIN_TRUSTSA* d, PULONG dc) { LogMessage(L"ex_DsEnumerateDomainTrustsA(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsEnumerateDomainTrustsW(LPWSTR s, ULONG f, PDS_DOMAIN_TRUSTSW* d, PULONG dc) { LogMessage(L"ex_DsEnumerateDomainTrustsW(...)"); return ERROR_NOT_SUPPORTED; }
VOID WINAPI ex_DsGetDcCloseW(HANDLE h) { LogMessage(L"ex_DsGetDcCloseW(...)"); }
DWORD WINAPI ex_DsGetDcNameA(LPCSTR c, LPCSTR d, GUID* dg, LPCSTR s, ULONG f, PDOMAIN_CONTROLLER_INFOA* dci) { LogMessage(L"ex_DsGetDcNameA(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetDcNameW(LPCWSTR c, LPCWSTR d, GUID* dg, LPCWSTR s, ULONG f, PDOMAIN_CONTROLLER_INFOW* dci) { LogMessage(L"ex_DsGetDcNameW(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetDcNameWithAccountA(LPCSTR a, LPCSTR b, ULONG c, LPCSTR d, LPCSTR e, GUID* f, LPCSTR g, ULONG h, PDOMAIN_CONTROLLER_INFOA* i) { LogMessage(L"ex_DsGetDcNameWithAccountA(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetDcNameWithAccountW(LPCWSTR a, LPCWSTR b, ULONG c, LPCWSTR d, LPCWSTR e, GUID* f, LPCWSTR g, ULONG h, PDOMAIN_CONTROLLER_INFOW* i) { LogMessage(L"ex_DsGetDcNameWithAccountW(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetDcNextA(HANDLE h, PULONG sac, LPSOCKET_ADDRESS* sa, LPSTR* d) { LogMessage(L"ex_DsGetDcNextA(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetDcNextW(HANDLE h, PULONG sac, LPSOCKET_ADDRESS* sa, LPWSTR* d) { LogMessage(L"ex_DsGetDcNextW(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetDcOpenA(LPCSTR d, ULONG o, LPCSTR s, GUID* dg, LPCSTR df, ULONG f, PHANDLE r) { LogMessage(L"ex_DsGetDcOpenA(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetDcOpenW(LPCWSTR d, ULONG o, LPCWSTR s, GUID* dg, LPCWSTR df, ULONG f, PHANDLE r) { LogMessage(L"ex_DsGetDcOpenW(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetDcSiteCoverageA(LPCSTR s, PULONG ec, PDS_SITE_NAME_A** sn) { LogMessage(L"ex_DsGetDcSiteCoverageA(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetDcSiteCoverageW(LPCWSTR s, PULONG ec, PDS_SITE_NAME_W** sn) { LogMessage(L"ex_DsGetDcSiteCoverageW(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetForestTrustInformationW(LPCWSTR s, LPCWSTR t, DWORD f, PLSA_FOREST_TRUST_INFORMATION* fti) { LogMessage(L"ex_DsGetForestTrustInformationW(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetSiteNameA(LPCSTR c, LPSTR* s) { LogMessage(L"ex_DsGetSiteNameA(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsGetSiteNameW(LPCWSTR c, LPWSTR* s) { LogMessage(L"ex_DsGetSiteNameW(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsMergeForestTrustInformationW(LPCWSTR d, PLSA_FOREST_TRUST_INFORMATION n, PLSA_FOREST_TRUST_INFORMATION o, PLSA_FOREST_TRUST_INFORMATION* m) { LogMessage(L"ex_DsMergeForestTrustInformationW(...)"); return ERROR_NOT_SUPPORTED; }
VOID WINAPI ex_DsRoleFreeMemory(PVOID b) { LogMessage(L"ex_DsRoleFreeMemory(...)"); }
DWORD WINAPI ex_DsRoleGetPrimaryDomainInformation(LPCWSTR s, DSROLE_PRIMARY_DOMAIN_INFO_LEVEL il, PBYTE* b) { LogMessage(L"ex_DsRoleGetPrimaryDomainInformation(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsValidateSubnetNameA(LPCSTR sn) { LogMessage(L"ex_DsValidateSubnetNameA(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_DsValidateSubnetNameW(LPCWSTR sn) { LogMessage(L"ex_DsValidateSubnetNameW(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_BrowserSetNetlogonState(LPCWSTR a, LPCWSTR b, LPCWSTR c, DWORD d) { LogMessage(L"ex_I_BrowserSetNetlogonState(...)"); return NERR_Success; }
DWORD WINAPI ex_I_DsUpdateReadOnlyServerDnsRecords(LPCWSTR a, LPCWSTR b, LPCWSTR c, GUID* d, ULONG e, PIP4_ADDRESS f) { LogMessage(L"ex_I_DsUpdateReadOnlyServerDnsRecords(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetAccountDeltas(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, DWORD e, PUSER_MODALS_INFO_0 f, DWORD g, DWORD h, DWORD i, LPBYTE* j, LPDWORD k, LPDWORD l) { LogMessage(L"ex_I_NetAccountDeltas(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetAccountSync(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, DWORD e, LPBYTE* f, LPDWORD g) { LogMessage(L"ex_I_NetAccountSync(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetChainSetClientAttributes(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, DWORD e, PNETLOGON_CLIENT_ATTRIBUTES f) { LogMessage(L"ex_I_NetChainSetClientAttributes(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetChainSetClientAttributes2(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, DWORD e, PNETLOGON_CLIENT_ATTRIBUTES f, DWORD g) { LogMessage(L"ex_I_NetChainSetClientAttributes2(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetDatabaseDeltas(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, DWORD e, DWORD f, DWORD g, DWORD h, DWORD i, LPBYTE* j, LPDWORD k, LPDWORD l) { LogMessage(L"ex_I_NetDatabaseDeltas(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetDatabaseRedo(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, LPBYTE e, DWORD f, LPBYTE* g, LPDWORD h) { LogMessage(L"ex_I_NetDatabaseRedo(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetDatabaseSync(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, DWORD e, DWORD f, LPBYTE* g, LPDWORD h) { LogMessage(L"ex_I_NetDatabaseSync(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetDatabaseSync2(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, DWORD e, DWORD f, DWORD g, LPBYTE* h, LPDWORD i) { LogMessage(L"ex_I_NetDatabaseSync2(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetDfsGetVersion(LPCWSTR a, LPDWORD b) { LogMessage(L"ex_I_NetDfsGetVersion(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetDfsIsThisADomainName(LPCWSTR a) { LogMessage(L"ex_I_NetDfsIsThisADomainName(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetGetDCList(LPCWSTR a, LPCWSTR b, PDOMAIN_CONTROLLER_INFOW* c) { LogMessage(L"ex_I_NetGetDCList(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetGetForestTrustInformation(LPCWSTR a, LPCWSTR b, DWORD c, PLSA_FOREST_TRUST_INFORMATION* d) { LogMessage(L"ex_I_NetGetForestTrustInformation(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetLogonGetDomainInfo(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, DWORD e, LPBYTE* f) { LogMessage(L"ex_I_NetLogonGetDomainInfo(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetLogonSamLogoff(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, NETLOGON_LOGON_INFO_CLASS e, LPVOID f) { LogMessage(L"ex_I_NetLogonSamLogoff(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetLogonSamLogon(LPCWSTR a, LPCWSTR b, NETLOGON_LOGON_INFO_CLASS e, LPVOID f, PNETLOGON_VALIDATION_SAM_INFO* g) { LogMessage(L"ex_I_NetLogonSamLogon(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetLogonSamLogonEx(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, NETLOGON_LOGON_INFO_CLASS e, PVOID f, NETLOGON_VALIDATION_INFO_CLASS g, PVOID* h, PUCHAR i) { LogMessage(L"ex_I_NetLogonSamLogonEx(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetLogonSamLogonWithFlags(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, NETLOGON_LOGON_INFO_CLASS e, PVOID f, NETLOGON_VALIDATION_INFO_CLASS g, PVOID* h, PUCHAR i, PNETLOGON_INTERACTIVE_INFO j) { LogMessage(L"ex_I_NetLogonSamLogonWithFlags(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetLogonSendToSam(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, LPBYTE e, DWORD f) { LogMessage(L"ex_I_NetLogonSendToSam(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetLogonUasLogoff(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, LPCWSTR e, DWORD f) { LogMessage(L"ex_I_NetLogonUasLogoff(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetLogonUasLogon(LPCWSTR a, LPCWSTR b, LPCWSTR c, PNETLOGON_AUTHENTICATOR d, LPBYTE* e) { LogMessage(L"ex_I_NetLogonUasLogon(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetServerAuthenticate(LPCWSTR a, LPCWSTR b, PNETLOGON_CREDENTIAL c, PNETLOGON_CREDENTIAL d, LPBOOL e) { LogMessage(L"ex_I_NetServerAuthenticate(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetServerAuthenticate2(LPCWSTR a, LPCWSTR b, PNETLOGON_CREDENTIAL c, PNETLOGON_CREDENTIAL d, LPBOOL e, PNETLOGON_AUTONOMOUS_SECRET f) { LogMessage(L"ex_I_NetServerAuthenticate2(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetServerAuthenticate3(LPCWSTR a, LPCWSTR b, PNETLOGON_CREDENTIAL c, PNETLOGON_CREDENTIAL d, LPBOOL e, PNETLOGON_AUTONOMOUS_SECRET f, PDWORD g) { LogMessage(L"ex_I_NetServerAuthenticate3(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetServerAuthenticateKerberos(LPCWSTR a, PNETLOGON_AUTHENTICATOR b, PNETLOGON_AUTHENTICATOR c, DWORD d, LPBYTE e, DWORD f) { LogMessage(L"ex_I_NetServerAuthenticateKerberos(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetServerGetTrustInfo(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, PNL_TRUST_INFORMATION* e) { LogMessage(L"ex_I_NetServerGetTrustInfo(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetServerPasswordGet(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, LPLSA_UNICODE_STRING e) { LogMessage(L"ex_I_NetServerPasswordGet(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetServerPasswordSet(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, PLSA_UNICODE_STRING e) { LogMessage(L"ex_I_NetServerPasswordSet(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetServerPasswordSet2(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, PLSA_UNICODE_STRING e, PNL_TRUST_PASSWORD f) { LogMessage(L"ex_I_NetServerPasswordSet2(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetServerReqChallenge(LPCWSTR a, LPCWSTR b, PNETLOGON_CREDENTIAL c, PNETLOGON_CREDENTIAL d) { LogMessage(L"ex_I_NetServerReqChallenge(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetServerSetServiceBits(LPCWSTR a, LPCWSTR b, DWORD c, BOOL d) { LogMessage(L"ex_I_NetServerSetServiceBits(...)"); return NERR_Success; }
DWORD WINAPI ex_I_NetServerSetServiceBitsEx(LPCWSTR a, LPCWSTR b, DWORD c, DWORD d, BOOL e, LPDWORD f) { LogMessage(L"ex_I_NetServerSetServiceBitsEx(...)"); return NERR_Success; }
DWORD WINAPI ex_I_NetServerTrustPasswordsGet(LPCWSTR a, LPCWSTR b, PNETLOGON_AUTHENTICATOR c, PNETLOGON_AUTHENTICATOR d, PLSA_UNICODE_STRING e, PLSA_UNICODE_STRING f) { LogMessage(L"ex_I_NetServerTrustPasswordsGet(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetlogonComputeClientDigest(LPCWSTR a, LPCWSTR b, LPBYTE c, DWORD d, PBYTE e) { LogMessage(L"ex_I_NetlogonComputeClientDigest(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_I_NetlogonComputeServerDigest(LPCWSTR a, LPCWSTR b, LPBYTE c, DWORD d, PBYTE e) { LogMessage(L"ex_I_NetlogonComputeServerDigest(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetAddAlternateComputerName(LPCWSTR s, LPCWSTR an, LPCWSTR da, LPCWSTR dp, ULONG r) { LogMessage(L"ex_NetAddAlternateComputerName(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetConfigGet(LPCWSTR s, LPCWSTR c, LPCWSTR p, LPBYTE* b) { LogMessage(L"ex_NetConfigGet(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetConfigGetAll(LPCWSTR s, LPCWSTR c, LPBYTE* b) { LogMessage(L"ex_NetConfigGetAll(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetConfigSet(LPCWSTR s, LPCWSTR r1, LPCWSTR c, DWORD l, DWORD r2, LPBYTE b, DWORD r3) { LogMessage(L"ex_NetConfigSet(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetConnectionEnum(LMSTR s, LMSTR q, DWORD l, LPBYTE *b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetConnectionEnum(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NetCreateProvisioningPackage(PNETSETUP_PROVISIONING_PARAMS p, LPBYTE* ppb, LPDWORD ps) { LogMessage(L"ex_NetCreateProvisioningPackage(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsAdd(LPWSTR d, LPWSTR s, LPWSTR sh, LPWSTR c, DWORD f) { LogMessage(L"ex_NetDfsAdd(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsAddStdRoot(LPWSTR s, LPWSTR r, LPWSTR c, DWORD f) { LogMessage(L"ex_NetDfsAddStdRoot(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsRemoveStdRoot(LPWSTR s, LPWSTR r, DWORD f) { LogMessage(L"ex_NetDfsRemoveStdRoot(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsAddFtRoot(LPWSTR s, LPWSTR r, LPWSTR fdn, LPWSTR c, DWORD f) { LogMessage(L"ex_NetDfsAddFtRoot(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsRemoveFtRoot(LPWSTR s, LPWSTR r, LPWSTR fdn, DWORD f) { LogMessage(L"ex_NetDfsRemoveFtRoot(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsRemoveFtRootForced(LPWSTR d, LPWSTR s, LPWSTR r, LPWSTR fdn, DWORD f) { LogMessage(L"ex_NetDfsRemoveFtRootForced(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsManagerInitialize(LPWSTR s, DWORD f) { LogMessage(L"ex_NetDfsManagerInitialize(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsManagerGetConfigInfo(LPWSTR d, LPWSTR s, GUID* pg, LPDWORD pt, LPDWORD pf, LPWSTR *pd, LPWSTR *pc) { LogMessage(L"ex_NetDfsManagerGetConfigInfo(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsManagerSendSiteInfo(LPWSTR d, PVOID psi) { LogMessage(L"ex_NetDfsManagerSendSiteInfo(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsAddStdRootForced(LPWSTR s, LPWSTR r, LPWSTR c, LPWSTR st) { LogMessage(L"ex_NetDfsAddStdRootForced(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsGetDcAddress(LPWSTR s, LPWSTR *d, BOOLEAN *ir, ULONG *t) { LogMessage(L"ex_NetDfsGetDcAddress(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsRemove(LPWSTR d, LPWSTR s, LPWSTR sh) { LogMessage(L"ex_NetDfsRemove(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsEnum(LPWSTR d, DWORD l, DWORD p, LPBYTE *b, LPDWORD er, LPDWORD rh) { LogMessage(L"ex_NetDfsEnum(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsGetInfo(LPWSTR d, LPWSTR s, LPWSTR sh, DWORD l, LPBYTE *b) { LogMessage(L"ex_NetDfsGetInfo(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsSetInfo(LPWSTR d, LPWSTR s, LPWSTR sh, DWORD l, LPBYTE b) { LogMessage(L"ex_NetDfsSetInfo(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsGetClientInfo(LPWSTR d, LPWSTR s, LPWSTR sh, DWORD l, LPBYTE *b) { LogMessage(L"ex_NetDfsGetClientInfo(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsSetClientInfo(LPWSTR d, LPWSTR s, LPWSTR sh, DWORD l, LPBYTE b) { LogMessage(L"ex_NetDfsSetClientInfo(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsMove(LPWSTR d, LPWSTR nd, ULONG f) { LogMessage(L"ex_NetDfsMove(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsRename(LPWSTR p, LPWSTR np) { LogMessage(L"ex_NetDfsRename(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsGetSecurity(LPWSTR d, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR *psd, LPDWORD l) { LogMessage(L"ex_NetDfsGetSecurity(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsSetSecurity(LPWSTR d, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR psd) { LogMessage(L"ex_NetDfsSetSecurity(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsGetStdContainerSecurity(LPWSTR m, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR *psd, LPDWORD l) { LogMessage(L"ex_NetDfsGetStdContainerSecurity(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsSetStdContainerSecurity(LPWSTR m, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR psd) { LogMessage(L"ex_NetDfsSetStdContainerSecurity(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsGetFtContainerSecurity(LPWSTR d, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR *psd, LPDWORD l) { LogMessage(L"ex_NetDfsGetFtContainerSecurity(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsSetFtContainerSecurity(LPWSTR d, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR psd) { LogMessage(L"ex_NetDfsSetFtContainerSecurity(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsAddRootTarget(LPWSTR p, LPWSTR t, ULONG v, LPWSTR c, ULONG f) { LogMessage(L"ex_NetDfsAddRootTarget(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsGetSupportedNamespaceVersion(DFS_NAMESPACE_VERSION_ORIGIN o, PWSTR n, PDFS_SUPPORTED_NAMESPACE_VERSION_INFO *v) { LogMessage(L"ex_NetDfsGetSupportedNamespaceVersion(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS NET_API_FUNCTION ex_NetDfsRemoveRootTarget(LPWSTR p, LPWSTR t, ULONG f) { LogMessage(L"ex_NetDfsRemoveRootTarget(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetEnumerateComputerNames(LPCWSTR s, NET_COMPUTER_NAME_TYPE nt, ULONG r, PDWORD ec, LPWSTR **cn) { LogMessage(L"ex_NetEnumerateComputerNames(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetErrorLogClear(LPCWSTR s, LPCWSTR b, LPBYTE r) { LogMessage(L"ex_NetErrorLogClear(...)"); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetErrorLogRead(LPCWSTR s, LPWSTR r1, LPHLOG eh, DWORD o, LPDWORD r2, DWORD r3, DWORD of, LPBYTE *b, DWORD p, LPDWORD br, LPDWORD tb) { LogMessage(L"ex_NetErrorLogRead(...)"); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetErrorLogWrite(LPBYTE r1, DWORD c, LPCWSTR co, LPBYTE b, DWORD nb, LPBYTE mb, DWORD sc, LPBYTE r2) { LogMessage(L"ex_NetErrorLogWrite(...)"); return ERROR_ACCESS_DENIED; }
NET_API_STATUS WINAPI ex_NetValidateName(LPCWSTR s, LPCWSTR n, LPCWSTR a, LPCWSTR p, NETSETUP_NAME_TYPE nt) { LogMessage(L"ex_NetValidateName(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetFileClose(LMSTR s, DWORD f) { LogMessage(L"ex_NetFileClose(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetFileEnum(LMSTR s, LMSTR bp, LMSTR u, DWORD l, LPBYTE *b, DWORD p, LPDWORD er, LPDWORD te, PDWORD_PTR rh) { LogMessage(L"ex_NetFileEnum(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetFileGetInfo(LMSTR s, DWORD f, DWORD l, LPBYTE *b) { LogMessage(L"ex_NetFileGetInfo(...)"); return ERROR_NOT_SUPPORTED; }
VOID WINAPI ex_NetFreeAadJoinInformation(PDSREG_JOIN_INFO p) { LogMessage(L"ex_NetFreeAadJoinInformation(...)"); }
DWORD WINAPI ex_NetGetAadJoinInformation(LPCWSTR t, PDSREG_JOIN_INFO* p) { LogMessage(L"ex_NetGetAadJoinInformation(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetGetJoinableOUs(LPCWSTR s, LPCWSTR d, LPCWSTR a, LPCWSTR p, DWORD *oc, LPWSTR **o) { LogMessage(L"ex_NetGetJoinableOUs(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NetIsServiceAccount2(LPCWSTR a, LPCWSTR b, LPCWSTR c, BOOL* d) { LogMessage(L"ex_NetIsServiceAccount2(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetJoinDomain(LPCWSTR s, LPCWSTR d, LPCWSTR ou, LPCWSTR a, LPCWSTR p, DWORD f) { LogMessage(L"ex_NetJoinDomain(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetUnjoinDomain(LPCWSTR s, LPCWSTR a, LPCWSTR p, DWORD f) { LogMessage(L"ex_NetUnjoinDomain(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NetLogonGetTimeServiceParentDomain(LPCWSTR a, LPBYTE* b) { LogMessage(L"ex_NetLogonGetTimeServiceParentDomain(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NetLogonSetServiceBits(DWORD a, DWORD b) { LogMessage(L"ex_NetLogonSetServiceBits(...)"); return NERR_Success; }
NET_API_STATUS WINAPI ex_NetMessageNameAdd(LPCWSTR s, LPCWSTR n) { LogMessage(L"ex_NetMessageNameAdd(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetMessageNameDel(LPCWSTR s, LPCWSTR n) { LogMessage(L"ex_NetMessageNameDel(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetMessageNameEnum(LPCWSTR s, DWORD l, LPBYTE *b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetMessageNameEnum(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetMessageNameGetInfo(LPCWSTR s, LPCWSTR n, DWORD l, LPBYTE *b) { LogMessage(L"ex_NetMessageNameGetInfo(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NetProvisionComputerAccount(LPCWSTR d, LPCWSTR m, LPCWSTR ou, LPCWSTR dc, DWORD o, PBYTE *pb, LPDWORD pbs, LPWSTR *pt) { LogMessage(L"ex_NetProvisionComputerAccount(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NetQueryServiceAccount(LPCWSTR s, LPCWSTR a, DWORD i, LPBYTE* b) { LogMessage(L"ex_NetQueryServiceAccount(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetRegisterDomainNameChangeNotification(PHANDLE h) { LogMessage(L"ex_NetRegisterDomainNameChangeNotification(...)"); if (!h) return ERROR_INVALID_PARAMETER; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetUnregisterDomainNameChangeNotification(HANDLE h) { LogMessage(L"ex_NetUnregisterDomainNameChangeNotification(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetRemoteComputerSupports(LPCWSTR s, DWORD ow, LPDWORD os) { LogMessage(L"ex_NetRemoteComputerSupports(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetRemoteTOD(LPCWSTR s, LPBYTE *b) { LogMessage(L"ex_NetRemoteTOD(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetRemoveAlternateComputerName(LPCWSTR s, LPCWSTR an, LPCWSTR da, LPCWSTR dp, ULONG r) { LogMessage(L"ex_NetRemoveAlternateComputerName(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetRenameMachineInDomain(LPCWSTR s, LPCWSTR n, LPCWSTR a, LPCWSTR p, DWORD f) { LogMessage(L"ex_NetRenameMachineInDomain(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NetRequestOfflineDomainJoin(LPCWSTR pb, DWORD c, DWORD o, LPWSTR *d) { LogMessage(L"ex_NetRequestOfflineDomainJoin(...)"); return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_NetRequestProvisioningPackageInstall(BYTE* p, DWORD s, DWORD f, LPWSTR n, LPVOID r) { LogMessage(L"ex_NetRequestProvisioningPackageInstall(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetScheduleJobAdd(LPCWSTR s, LPBYTE b, LPDWORD j) { LogMessage(L"ex_NetScheduleJobAdd(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetScheduleJobDel(LPCWSTR s, DWORD min, DWORD max) { LogMessage(L"ex_NetScheduleJobDel(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetScheduleJobEnum(LPCWSTR s, LPBYTE* pb, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetScheduleJobEnum(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; if (!pb||!er||!te) return ERROR_INVALID_PARAMETER; *er = *te = 0; *pb = NULL; return NERR_Success; }
NET_API_STATUS WINAPI ex_NetScheduleJobGetInfo(LPCWSTR s, DWORD j, LPBYTE* pb) { LogMessage(L"ex_NetScheduleJobGetInfo(...)"); if (!IsLocalComputer(s)) return NERR_InvalidComputer; return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerAliasAdd(LPCWSTR a, DWORD b, LPBYTE c) { LogMessage(L"ex_NetServerAliasAdd(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerAliasDel(LPCWSTR a, LPCWSTR b) { LogMessage(L"ex_NetServerAliasDel(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerAliasEnum(LPCWSTR a, DWORD b, LPBYTE* c, DWORD d, LPDWORD e, LPDWORD f, LPDWORD g) { LogMessage(L"ex_NetServerAliasEnum(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerComputerNameAdd(LMSTR s, LMSTR esn) { LogMessage(L"ex_NetServerComputerNameAdd(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerComputerNameDel(LMSTR s, LMSTR esn) { LogMessage(L"ex_NetServerComputerNameDel(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerDiskEnum(LMSTR s, DWORD l, LPBYTE *b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetServerDiskEnum(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerTransportAdd(LMSTR s, DWORD l, LPBYTE b) { LogMessage(L"ex_NetServerTransportAdd(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerTransportAddEx(LMSTR s, DWORD l, LPBYTE b) { LogMessage(L"ex_NetServerTransportAddEx(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerTransportDel(LMSTR s, DWORD l, LPBYTE b) { LogMessage(L"ex_NetServerTransportDel(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetServerTransportEnum(LMSTR s, DWORD l, LPBYTE *b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetServerTransportEnum(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetSessionDel(LPCWSTR s, LPCWSTR uc, LPCWSTR u) { LogMessage(L"ex_NetSessionDel(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetSessionEnum(LMSTR s, LMSTR uc, LMSTR u, DWORD l, LPBYTE *b, DWORD p, LPDWORD er, LPDWORD te, LPDWORD rh) { LogMessage(L"ex_NetSessionEnum(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetSessionGetInfo(LMSTR s, LMSTR uc, LMSTR u, DWORD l, LPBYTE *b) { LogMessage(L"ex_NetSessionGetInfo(...)"); return ERROR_NOT_SUPPORTED; }
NET_API_STATUS WINAPI ex_NetSetPrimaryComputerName(LPCWSTR s, LPCWSTR pn, LPCWSTR da, LPCWSTR dp, ULONG r) { LogMessage(L"ex_NetSetPrimaryComputerName(...)"); return ERROR_NOT_SUPPORTED; }
WINBOOL WINAPI ex_SetServiceBits(SERVICE_STATUS_HANDLE h, DWORD b, WINBOOL s, WINBOOL u) { LogMessage(L"ex_SetServiceBits(...)"); return FALSE; }