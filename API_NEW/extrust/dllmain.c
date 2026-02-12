/*
 * WINTRUST.DLL Emulation - Trust Everything / No Signature Verification
 * 
 * This emulator bypasses all signature verification checks.
 * All files are treated as trusted.
 *
 * Copyright (c) 2025-2026 - EXLOUD
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wincrypt.h>
#include <prsht.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Include official Windows SDK headers for WinTrust structures and constants */
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */
#define ENABLE_DEBUG_CONSOLE    1
#define ENABLE_FILE_LOGGING     0
#define ENABLE_MEMORY_TRACKING  0

/* Trust mode configuration:
 * 0 = Trust everything (WinVerifyTrust returns ERROR_SUCCESS)
 * 1 = No signature (WinVerifyTrust returns TRUST_E_NOSIGNATURE)
 */
#define TRUST_MODE_TRUST_ALL    1

/* ============================================================================
 * GLOBAL VARIABLES
 * ============================================================================ */

static CRITICAL_SECTION g_lock;
static BOOL g_initialized = FALSE;

#if ENABLE_DEBUG_CONSOLE
static HANDLE g_hConsole = NULL;
#endif

#if ENABLE_FILE_LOGGING
static FILE* g_logFile = NULL;
static CRITICAL_SECTION g_logLock;
#endif

#if ENABLE_MEMORY_TRACKING
static size_t g_allocCount = 0;
static size_t g_freeCount = 0;
static size_t g_totalAllocated = 0;
#endif

/* ============================================================================
 * LOGGING UTILITIES
 * ============================================================================ */

static void SetConsoleColorEx(WORD color) {
#if ENABLE_DEBUG_CONSOLE
    if (g_hConsole && g_hConsole != INVALID_HANDLE_VALUE) {
        SetConsoleTextAttribute(g_hConsole, color);
    }
#else
    (void)color;
#endif
}

#define COLOR_INFO    (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COLOR_DEBUG   (FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COLOR_WARNING (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COLOR_ERROR   (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define COLOR_RESET   (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

static void LogMessage(const char* level, WORD color, const char* format, va_list args) {
    if (!g_initialized) return;
    
    EnterCriticalSection(&g_lock);
    
#if ENABLE_DEBUG_CONSOLE
    if (g_hConsole && g_hConsole != INVALID_HANDLE_VALUE) {
        SetConsoleColorEx(color);
        printf("[%s] ", level);
        vprintf(format, args);
        printf("\n");
        SetConsoleColorEx(COLOR_RESET);
    }
#endif
    
#if ENABLE_FILE_LOGGING
    if (g_logFile) {
        EnterCriticalSection(&g_logLock);
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_logFile, "[%02d:%02d:%02d.%03d] [%s] ", 
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, level);
        vfprintf(g_logFile, format, args);
        fprintf(g_logFile, "\n");
        fflush(g_logFile);
        LeaveCriticalSection(&g_logLock);
    }
#endif
    
    LeaveCriticalSection(&g_lock);
}

static void LogI(const char* format, ...) {
    va_list args;
    va_start(args, format);
    LogMessage("INFO", COLOR_INFO, format, args);
    va_end(args);
}

static void LogD(const char* format, ...) {
    va_list args;
    va_start(args, format);
    LogMessage("DEBUG", COLOR_DEBUG, format, args);
    va_end(args);
}

static void LogW(const char* format, ...) {
    va_list args;
    va_start(args, format);
    LogMessage("WARN", COLOR_WARNING, format, args);
    va_end(args);
}

static void LogE(const char* format, ...) {
    va_list args;
    va_start(args, format);
    LogMessage("ERROR", COLOR_ERROR, format, args);
    va_end(args);
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

static const char* GetChoiceName(DWORD choice) {
    switch (choice) {
        case WTD_CHOICE_FILE:    return "FILE";
        case WTD_CHOICE_CATALOG: return "CATALOG";
        case WTD_CHOICE_BLOB:    return "BLOB";
        case WTD_CHOICE_SIGNER:  return "SIGNER";
        case WTD_CHOICE_CERT:    return "CERT";
        default: return "UNKNOWN";
    }
}

static const char* GetUIChoiceName(DWORD choice) {
    switch (choice) {
        case WTD_UI_ALL:    return "ALL";
        case WTD_UI_NONE:   return "NONE";
        case WTD_UI_NOBAD:  return "NOBAD";
        case WTD_UI_NOGOOD: return "NOGOOD";
        default: return "UNKNOWN";
    }
}

static const char* GetStateActionName(DWORD action) {
    switch (action) {
        case WTD_STATEACTION_IGNORE:           return "IGNORE";
        case WTD_STATEACTION_VERIFY:           return "VERIFY";
        case WTD_STATEACTION_CLOSE:            return "CLOSE";
        case WTD_STATEACTION_AUTO_CACHE:       return "AUTO_CACHE";
        case WTD_STATEACTION_AUTO_CACHE_FLUSH: return "AUTO_CACHE_FLUSH";
        default: return "UNKNOWN";
    }
}

static const char* GetTrustProviderName(DWORD provider) {
    switch (provider) {
        case WTD_USE_IE4_TRUST_FLAG:            return "IE4_TRUST";
        case WTD_NO_IE4_CHAIN_FLAG:             return "NO_IE4_CHAIN";
        case WTD_NO_POLICY_USAGE_FLAG:          return "NO_POLICY_USAGE";
        case WTD_REVOCATION_CHECK_NONE:         return "REVOCATION_NONE";
        case WTD_REVOCATION_CHECK_END_CERT:     return "REVOCATION_END_CERT";
        case WTD_REVOCATION_CHECK_CHAIN:        return "REVOCATION_CHAIN";
        case WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT: return "REVOCATION_CHAIN_EXCLUDE_ROOT";
        case WTD_SAFER_FLAG:                    return "SAFER";
        case WTD_HASH_ONLY_FLAG:                return "HASH_ONLY";
        case WTD_USE_DEFAULT_OSVER_CHECK:       return "DEFAULT_OSVER_CHECK";
        case WTD_LIFETIME_SIGNING_FLAG:         return "LIFETIME_SIGNING";
        case WTD_CACHE_ONLY_URL_RETRIEVAL:      return "CACHE_ONLY_URL";
        default: return "UNKNOWN";
    }
}

/* Rename to avoid conflict with macro */
static BOOL CompareGUIDs(const GUID* guid1, const GUID* guid2) {
    if (!guid1 || !guid2) return FALSE;
    return memcmp(guid1, guid2, sizeof(GUID)) == 0;
}

static void LogGUID(const char* prefix, const GUID* guid) {
    if (!guid) {
        LogD("%sNULL", prefix);
        return;
    }
    
    LogD("%s{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", 
         prefix,
         guid->Data1, guid->Data2, guid->Data3,
         guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
         guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
}

static void LogWintrustData(const WINTRUST_DATA* pWTD) {
    if (!pWTD) {
        LogD("  WintrustData: NULL");
        return;
    }
    
    LogD("  cbStruct: %lu", pWTD->cbStruct);
    LogD("  dwUnionChoice: %s", GetChoiceName(pWTD->dwUnionChoice));
    LogD("  dwUIChoice: %s", GetUIChoiceName(pWTD->dwUIChoice));
    
    /* Detailed revocation checks */
    LogD("  fdwRevocationChecks: 0x%08lX", pWTD->fdwRevocationChecks);
    if (pWTD->fdwRevocationChecks == 0) {
        LogD("    - WTD_REVOKE_NONE");
    } else if (pWTD->fdwRevocationChecks & 0x00000001) {
        LogD("    - WTD_REVOKE_WHOLECHAIN");
    }
    
    LogD("  dwStateAction: %s", GetStateActionName(pWTD->dwStateAction));
    LogD("  hWVTStateData: 0x%p", pWTD->hWVTStateData);
    
    /* Detailed provider flags */
    LogD("  dwProvFlags: 0x%08lX", pWTD->dwProvFlags);
    if (pWTD->dwProvFlags != 0) {
        if (pWTD->dwProvFlags & 0x00000001) LogD("    - WTD_USE_IE4_TRUST_FLAG");
        if (pWTD->dwProvFlags & 0x00000002) LogD("    - WTD_NO_IE4_CHAIN_FLAG");
        if (pWTD->dwProvFlags & 0x00000004) LogD("    - WTD_NO_POLICY_USAGE_FLAG");
        if (pWTD->dwProvFlags & 0x00000008) LogD("    - WTD_USE_LOCAL_MACHINE_CERTS");
        if (pWTD->dwProvFlags & 0x00000010) LogD("    - WTD_REVOCATION_CHECK_NONE");
        if (pWTD->dwProvFlags & 0x00000020) LogD("    - WTD_REVOCATION_CHECK_END_CERT");
        if (pWTD->dwProvFlags & 0x00000040) LogD("    - WTD_REVOCATION_CHECK_CHAIN");
        if (pWTD->dwProvFlags & 0x00000080) LogD("    - WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT");
        if (pWTD->dwProvFlags & 0x00000100) LogD("    - WTD_SAFER_FLAG");
        if (pWTD->dwProvFlags & 0x00000200) LogD("    - WTD_HASH_ONLY_FLAG");
        if (pWTD->dwProvFlags & 0x00000400) LogD("    - WTD_USE_DEFAULT_OSVER_CHECK");
        if (pWTD->dwProvFlags & 0x00000800) LogD("    - WTD_LIFETIME_SIGNING_FLAG");
        if (pWTD->dwProvFlags & 0x00001000) LogD("    - WTD_CACHE_ONLY_URL_RETRIEVAL");
        if (pWTD->dwProvFlags & 0x00002000) LogD("    - WTD_DISABLE_MD2_MD4");
        if (pWTD->dwProvFlags & 0x00004000) LogD("    - WTD_MOTW (Mark-Of-The-Web)");
        if (pWTD->dwProvFlags & 0x00008000) LogD("    - WTD_CODE_INTEGRITY_DRIVER_MODE");
    } else {
        LogD("    - (no flags set)");
    }
    
    /* UI Context */
    LogD("  dwUIContext: %lu", pWTD->dwUIContext);
    if (pWTD->dwUIContext == 0) {
        LogD("    - WTD_UICONTEXT_EXECUTE");
    } else if (pWTD->dwUIContext == 1) {
        LogD("    - WTD_UICONTEXT_INSTALL");
    }
    
    /* Policy and SIP callback data */
    if (pWTD->pPolicyCallbackData) {
        LogD("  pPolicyCallbackData: 0x%p", pWTD->pPolicyCallbackData);
    }
    if (pWTD->pSIPClientData) {
        LogD("  pSIPClientData: 0x%p", pWTD->pSIPClientData);
    }
    
    /* URL Reference */
    if (pWTD->pwszURLReference) {
        LogD("  pwszURLReference: %ls", pWTD->pwszURLReference);
    }
    
    /* Union data based on choice */
    if (pWTD->dwUnionChoice == WTD_CHOICE_FILE && pWTD->pFile) {
        WINTRUST_FILE_INFO* pFile = pWTD->pFile;
        LogD("  === FILE INFO ===");
        LogD("    cbStruct: %lu", pFile->cbStruct);
        LogD("    pcwszFilePath: %ls", pFile->pcwszFilePath ? pFile->pcwszFilePath : L"(null)");
        if (pFile->hFile && pFile->hFile != INVALID_HANDLE_VALUE) {
            LogD("    hFile: 0x%p", pFile->hFile);
        }
        if (pFile->pgKnownSubject) {
            LogGUID("    pgKnownSubject: ", pFile->pgKnownSubject);
        }
    }
    else if (pWTD->dwUnionChoice == WTD_CHOICE_CATALOG && pWTD->pCatalog) {
        WINTRUST_CATALOG_INFO* pCat = pWTD->pCatalog;
        LogD("  === CATALOG INFO ===");
        LogD("    cbStruct: %lu", pCat->cbStruct);
        LogD("    pcwszCatalogFilePath: %ls", pCat->pcwszCatalogFilePath ? pCat->pcwszCatalogFilePath : L"(null)");
        LogD("    pcwszMemberFilePath: %ls", pCat->pcwszMemberFilePath ? pCat->pcwszMemberFilePath : L"(null)");
        LogD("    pcwszMemberTag: %ls", pCat->pcwszMemberTag ? pCat->pcwszMemberTag : L"(null)");
        if (pCat->hMemberFile && pCat->hMemberFile != INVALID_HANDLE_VALUE) {
            LogD("    hMemberFile: 0x%p", pCat->hMemberFile);
        }
        if (pCat->pbCalculatedFileHash && pCat->cbCalculatedFileHash > 0) {
            LogD("    cbCalculatedFileHash: %lu", pCat->cbCalculatedFileHash);
        }
    }
	else if (pWTD->dwUnionChoice == WTD_CHOICE_BLOB && pWTD->pBlob) {
		WINTRUST_BLOB_INFO* pBlob = pWTD->pBlob;
		LogD("  === BLOB INFO ===");
		LogD("    cbStruct: %lu", pBlob->cbStruct);
		LogGUID("    gSubject: ", &pBlob->gSubject);
		LogD("    pcwszDisplayName: %ls", pBlob->pcwszDisplayName ? pBlob->pcwszDisplayName : L"(null)");
		LogD("    cbMemObject: %lu", pBlob->cbMemObject);
		LogD("    pbMemObject: 0x%p", pBlob->pbMemObject);
		LogD("    cbMemSignedMsg: %lu", pBlob->cbMemSignedMsg);
		LogD("    pbMemSignedMsg: 0x%p", pBlob->pbMemSignedMsg);
	}
}

/* ============================================================================
 * MAIN VERIFICATION FUNCTION
 * ============================================================================ */

LONG WINAPI WinVerifyTrust(HWND hwnd, GUID* pgActionID, LPVOID pWVTData)
{
    LogI("=== WinVerifyTrust called ===");
    LogD("  HWND: 0x%p", hwnd);
    LogGUID("  ActionID: ", pgActionID);
    
    WINTRUST_DATA* pWTD = (WINTRUST_DATA*)pWVTData;
    LogWintrustData(pWTD);
    
#if TRUST_MODE_TRUST_ALL
    LogI("  Result: TRUSTED (ERROR_SUCCESS)");
    return ERROR_SUCCESS;
#else
    LogI("  Result: NO SIGNATURE (TRUST_E_NOSIGNATURE)");
    return TRUST_E_NOSIGNATURE;
#endif
}

/* ============================================================================
 * TRUST PROVIDER FUNCTIONS
 * ============================================================================ */

BOOL WINAPI WintrustLoadFunctionPointers(GUID* pgActionID, CRYPT_PROVIDER_FUNCTIONS* pPfns)
{
    LogI("=== WintrustLoadFunctionPointers ===");
    LogGUID("  ActionID: ", pgActionID);
    
    if (!pPfns) {
        LogE("  ERROR: pPfns is NULL");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    LogD("  pPfns->cbStruct: %lu", pPfns->cbStruct);
    
    /* Zero out the structure */
    ZeroMemory(pPfns, pPfns->cbStruct);
    pPfns->cbStruct = sizeof(CRYPT_PROVIDER_FUNCTIONS);
    
    LogI("  Result: SUCCESS (zeroed structure)");
    return TRUE;
}

BOOL WINAPI WintrustAddActionID(GUID* pgActionID, DWORD fdwFlags,
                                    CRYPT_REGISTER_ACTIONID* psProvInfo)
{
    LogD("WintrustAddActionID");
    LogGUID("  ActionID: ", pgActionID);
    return TRUE;
}

BOOL WINAPI WintrustRemoveActionID(GUID* pgActionID)
{
    LogD("WintrustRemoveActionID");
    LogGUID("  ActionID: ", pgActionID);
    return TRUE;
}

CRYPT_PROVIDER_DATA* WINAPI WTHelperProvDataFromStateData(HANDLE hStateData)
{
    LogI("=== WTHelperProvDataFromStateData ===");
    LogD("  hStateData: 0x%p", hStateData);
    LogI("  Result: NULL (not implemented)");
    return NULL;
}

CRYPT_PROVIDER_SGNR* WINAPI WTHelperGetProvSignerFromChain(
    CRYPT_PROVIDER_DATA* pProvData, DWORD idxSigner, BOOL fCounterSigner, DWORD idxCounterSigner)
{
    LogI("=== WTHelperGetProvSignerFromChain ===");
    LogD("  pProvData: 0x%p", pProvData);
    LogD("  idxSigner: %lu", idxSigner);
    LogD("  fCounterSigner: %s", fCounterSigner ? "TRUE" : "FALSE");
    LogD("  idxCounterSigner: %lu", idxCounterSigner);
    LogI("  Result: NULL (not implemented)");
    return NULL;
}

CRYPT_PROVIDER_CERT* WINAPI WTHelperGetProvCertFromChain(
    CRYPT_PROVIDER_SGNR* pSgnr, DWORD idxCert)
{
    LogD("WTHelperGetProvCertFromChain");
    return NULL;
}

void WINAPI WintrustGetRegPolicyFlags(DWORD* pdwPolicyFlags)
{
    LogI("=== WintrustGetRegPolicyFlags ===");
    
    if (pdwPolicyFlags) {
        *pdwPolicyFlags = WTPF_IGNOREREVOKATION | 
                          WTPF_TRUSTTEST |
                          WTPF_IGNOREEXPIRATION |
                          WTPF_IGNOREREVOCATIONONTS;
        
        LogD("  Returned flags: 0x%08lX", *pdwPolicyFlags);
        LogD("    - WTPF_IGNOREREVOKATION");
        LogD("    - WTPF_TRUSTTEST");
        LogD("    - WTPF_IGNOREEXPIRATION");
        LogD("    - WTPF_IGNOREREVOCATIONONTS");
    } else {
        LogW("  WARNING: pdwPolicyFlags is NULL");
    }
}

BOOL WINAPI WintrustSetRegPolicyFlags(DWORD dwPolicyFlags)
{
    LogI("=== WintrustSetRegPolicyFlags ===");
    LogD("  dwPolicyFlags: 0x%08lX", dwPolicyFlags);
    
    if (dwPolicyFlags & WTPF_IGNOREREVOKATION) LogD("    - WTPF_IGNOREREVOKATION");
    if (dwPolicyFlags & WTPF_TRUSTTEST) LogD("    - WTPF_TRUSTTEST");
    if (dwPolicyFlags & WTPF_IGNOREEXPIRATION) LogD("    - WTPF_IGNOREEXPIRATION");
    if (dwPolicyFlags & WTPF_IGNOREREVOCATIONONTS) LogD("    - WTPF_IGNOREREVOCATIONONTS");
    
    LogI("  Result: SUCCESS (flags accepted but ignored)");
    return TRUE;
}

/* ============================================================================
 * CATALOG FUNCTIONS
 * ============================================================================ */

BOOL WINAPI CryptCATAdminAcquireContext(HCATADMIN* phCatAdmin, const GUID* pgSubsystem, DWORD dwFlags)
{
    LogI("=== CryptCATAdminAcquireContext ===");
    LogGUID("  Subsystem GUID: ", pgSubsystem);
    LogD("  dwFlags: 0x%08lX", dwFlags);
    
    if (!phCatAdmin) {
        LogE("  ERROR: phCatAdmin is NULL");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    /* Return fake handle */
    *phCatAdmin = (HCATADMIN)(ULONG_PTR)0xCA7A10CULL;
    LogI("  Result: SUCCESS (handle=0x%p)", (void*)*phCatAdmin);
    return TRUE;
}

BOOL WINAPI CryptCATAdminAcquireContext2(HCATADMIN* phCatAdmin, const GUID* pgSubsystem,
                                             PCWSTR pwszHashAlgorithm, PCCERT_STRONG_SIGN_PARA pStrongHashPolicy,
                                             DWORD dwFlags)
{
    LogD("CryptCATAdminAcquireContext2");
    LogD("  HashAlgorithm: %ls", pwszHashAlgorithm ? pwszHashAlgorithm : L"(default)");
    
    if (!phCatAdmin) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    *phCatAdmin = (HCATADMIN)(ULONG_PTR)0xCA7A10C2ULL;
    return TRUE;
}

BOOL WINAPI CryptCATAdminReleaseContext(HCATADMIN hCatAdmin, DWORD dwFlags)
{
    LogI("=== CryptCATAdminReleaseContext ===");
    LogD("  hCatAdmin: 0x%p", (void*)hCatAdmin);
    LogD("  dwFlags: 0x%08lX", dwFlags);
    LogI("  Result: SUCCESS");
    return TRUE;
}

#define FAKE_HASH_SIZE 32

BOOL WINAPI CryptCATAdminCalcHashFromFileHandle(HANDLE hFile, DWORD* pcbHash,
                                                    BYTE* pbHash, DWORD dwFlags)
{
    LogI("=== CryptCATAdminCalcHashFromFileHandle ===");
    LogD("  hFile: 0x%p", hFile);
    LogD("  dwFlags: 0x%08lX", dwFlags);
    
    if (!pcbHash) {
        LogE("  ERROR: pcbHash is NULL");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    if (!pbHash) {
        *pcbHash = FAKE_HASH_SIZE;
        LogD("  Query mode: returning required size = %lu bytes", FAKE_HASH_SIZE);
        return TRUE;
    }
    
    if (*pcbHash < FAKE_HASH_SIZE) {
        LogW("  Buffer too small: provided=%lu, required=%lu", *pcbHash, FAKE_HASH_SIZE);
        *pcbHash = FAKE_HASH_SIZE;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    
    /* Generate fake hash */
    DWORD seed = (DWORD)(ULONG_PTR)hFile ^ GetTickCount();
    for (DWORD i = 0; i < FAKE_HASH_SIZE; i++) {
        seed = seed * 1103515245 + 12345;
        pbHash[i] = (BYTE)(seed >> 16);
    }
    *pcbHash = FAKE_HASH_SIZE;
    
    LogI("  Generated fake hash (%lu bytes)", FAKE_HASH_SIZE);
    LogD("  Hash: %02X%02X%02X%02X%02X%02X%02X%02X...", 
         pbHash[0], pbHash[1], pbHash[2], pbHash[3],
         pbHash[4], pbHash[5], pbHash[6], pbHash[7]);
    
    return TRUE;
}

BOOL WINAPI CryptCATAdminCalcHashFromFileHandle2(HCATADMIN hCatAdmin, HANDLE hFile,
                                                     DWORD* pcbHash, BYTE* pbHash, DWORD dwFlags)
{
    LogD("CryptCATAdminCalcHashFromFileHandle2");
    return CryptCATAdminCalcHashFromFileHandle(hFile, pcbHash, pbHash, dwFlags);
}

HCATINFO WINAPI CryptCATAdminEnumCatalogFromHash(HCATADMIN hCatAdmin, BYTE* pbHash,
                                                     DWORD cbHash, DWORD dwFlags, HCATINFO* phPrevCatInfo)
{
    LogI("=== CryptCATAdminEnumCatalogFromHash ===");
    LogD("  hCatAdmin: 0x%p", (void*)hCatAdmin);
    LogD("  cbHash: %lu", cbHash);
    LogD("  dwFlags: 0x%08lX", dwFlags);
    
    if (pbHash && cbHash > 0) {
        LogD("  Hash: %02X%02X%02X%02X%02X%02X%02X%02X...", 
             pbHash[0], pbHash[1], pbHash[2], pbHash[3],
             pbHash[4], pbHash[5], pbHash[6], pbHash[7]);
    }
    
    if (phPrevCatInfo && *phPrevCatInfo) {
        LogD("  Previous catalog info: 0x%p", (void*)*phPrevCatInfo);
    }
    
    LogI("  Result: NULL (no catalog found - signature bypass)");
    
    /* Return NULL to indicate no catalog found */
    return NULL;
}

BOOL WINAPI CryptCATAdminReleaseCatalogContext(HCATADMIN hCatAdmin, HCATINFO hCatInfo, DWORD dwFlags)
{
    LogD("CryptCATAdminReleaseCatalogContext");
    return TRUE;
}

BOOL WINAPI CryptCATCatalogInfoFromContext(HCATINFO hCatInfo, CATALOG_INFO* psCatInfo, DWORD dwFlags)
{
    LogD("CryptCATCatalogInfoFromContext");
    
    if (!psCatInfo) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    ZeroMemory(psCatInfo, sizeof(CATALOG_INFO));
    psCatInfo->cbStruct = sizeof(CATALOG_INFO);
    wcscpy_s(psCatInfo->wszCatalogFile, MAX_PATH, L"fake_catalog.cat");
    
    return TRUE;
}

HANDLE WINAPI CryptCATOpen(LPWSTR pwszFileName, DWORD fdwOpenFlags, HCRYPTPROV hProv,
                              DWORD dwPublicVersion, DWORD dwEncodingType)
{
    LogD("CryptCATOpen: %ls", pwszFileName ? pwszFileName : L"(null)");
    
    /* Return fake catalog handle */
    return (HANDLE)(ULONG_PTR)0xCA7A106;
}

BOOL WINAPI CryptCATClose(HANDLE hCatalog)
{
    LogD("CryptCATClose: 0x%p", hCatalog);
    return TRUE;
}

CRYPTCATMEMBER* WINAPI CryptCATEnumerateMember(HANDLE hCatalog, CRYPTCATMEMBER* pPrevMember)
{
    LogD("CryptCATEnumerateMember");
    
    /* Return NULL to indicate no more members */
    return NULL;
}

CRYPTCATATTRIBUTE* WINAPI CryptCATEnumerateAttr(HANDLE hCatalog, CRYPTCATMEMBER* pCatMember,
                                                    CRYPTCATATTRIBUTE* pPrevAttr)
{
    LogD("CryptCATEnumerateAttr");
    return NULL;
}

CRYPTCATATTRIBUTE* WINAPI CryptCATEnumerateCatAttr(HANDLE hCatalog, CRYPTCATATTRIBUTE* pPrevAttr)
{
    LogD("CryptCATEnumerateCatAttr");
    return NULL;
}

CRYPTCATATTRIBUTE* WINAPI CryptCATGetAttrInfo(HANDLE hCatalog, CRYPTCATMEMBER* pCatMember, LPWSTR pwszReferenceTag)
{
    LogD("CryptCATGetAttrInfo");
    return NULL;
}

CRYPTCATATTRIBUTE* WINAPI CryptCATGetCatAttrInfo(HANDLE hCatalog, LPWSTR pwszReferenceTag)
{
    LogD("CryptCATGetCatAttrInfo");
    return NULL;
}

CRYPTCATMEMBER* WINAPI CryptCATGetMemberInfo(HANDLE hCatalog, LPWSTR pwszReferenceTag)
{
    LogD("CryptCATGetMemberInfo");
    return NULL;
}

BOOL WINAPI CryptCATPersistStore(HANDLE hCatalog)
{
    LogD("CryptCATPersistStore");
    return TRUE;
}

CRYPTCATATTRIBUTE* WINAPI CryptCATPutAttrInfo(HANDLE hCatalog, CRYPTCATMEMBER* pCatMember,
                                   LPWSTR pwszReferenceTag, DWORD dwAttrTypeAndAction,
                                   DWORD cbData, BYTE* pbData)
{
    LogD("CryptCATPutAttrInfo");
    return NULL;
}

CRYPTCATATTRIBUTE* WINAPI CryptCATPutCatAttrInfo(HANDLE hCatalog, LPWSTR pwszReferenceTag,
                                      DWORD dwAttrTypeAndAction, DWORD cbData, BYTE* pbData)
{
    LogD("CryptCATPutCatAttrInfo");
    return NULL;
}

CRYPTCATMEMBER* WINAPI CryptCATPutMemberInfo(HANDLE hCatalog, LPWSTR pwszFileName,
                                                LPWSTR pwszReferenceTag, GUID* pgSubjectType,
                                                DWORD dwCertVersion, DWORD cbSIPIndirectData,
                                                BYTE* pbSIPIndirectData)
{
    LogD("CryptCATPutMemberInfo");
    return NULL;
}

HCATINFO WINAPI CryptCATAdminAddCatalog(HCATADMIN hCatAdmin, PWSTR pwszCatalogFile,
                                       PWSTR pwszSelectBaseName, DWORD dwFlags)
{
    LogD("CryptCATAdminAddCatalog: %ls", pwszCatalogFile ? pwszCatalogFile : L"(null)");
    return NULL;
}

BOOL WINAPI CryptCATAdminRemoveCatalog(HCATADMIN hCatAdmin, LPCWSTR pwszCatalogFile, DWORD dwFlags)
{
    LogD("CryptCATAdminRemoveCatalog: %ls", pwszCatalogFile ? pwszCatalogFile : L"(null)");
    return TRUE;
}

BOOL WINAPI CryptCATAdminResolveCatalogPath(HCATADMIN hCatAdmin, WCHAR* pwszCatalogFile,
                                               CATALOG_INFO* psCatInfo, DWORD dwFlags)
{
    LogD("CryptCATAdminResolveCatalogPath");
    return FALSE;
}

BOOL WINAPI CryptCATCDFClose(CRYPTCATCDF* pCDF)
{
    LogD("CryptCATCDFClose");
    return TRUE;
}

CRYPTCATATTRIBUTE* WINAPI CryptCATCDFEnumCatAttributes(CRYPTCATCDF* pCDF, CRYPTCATATTRIBUTE* pPrevAttr,
                                                          PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError)
{
    LogD("CryptCATCDFEnumCatAttributes");
    return NULL;
}

LPWSTR WINAPI CryptCATCDFEnumMembersByCDFTagEx(CRYPTCATCDF* pCDF, LPWSTR pwszPrevCDFTag,
                                                 PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError, 
                                                 CRYPTCATMEMBER** ppMember, BOOL fContinueOnError,
                                                 LPVOID pvReserved)
{
    LogD("CryptCATCDFEnumMembersByCDFTagEx");
    return NULL;
}

CRYPTCATCDF* WINAPI CryptCATCDFOpen(LPWSTR pwszFilePath, PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError)
{
    LogD("CryptCATCDFOpen: %ls", pwszFilePath ? pwszFilePath : L"(null)");
    return NULL;
}

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================ */

BOOL WINAPI WTHelperCertIsSelfSigned(DWORD dwEncoding, CERT_INFO* pCert)
{
    LogD("WTHelperCertIsSelfSigned");
    return FALSE;
}

HRESULT WINAPI WTHelperCertCheckValidSignature(CRYPT_PROVIDER_DATA* pProvData)
{
    LogD("WTHelperCertCheckValidSignature");
    return S_OK;
}

CRYPT_PROVIDER_PRIVDATA* WINAPI WTHelperGetProvPrivateDataFromChain(CRYPT_PROVIDER_DATA* pProvData,
                                                       GUID* pgProviderID)
{
    LogD("WTHelperGetProvPrivateDataFromChain");
    return NULL;
}

CRYPT_PROVIDER_CERT* WINAPI WTHelperGetProvCertFromSigner(CRYPT_PROVIDER_SGNR* pSgnr)
{
    LogD("WTHelperGetProvCertFromSigner");
    return NULL;
}

/* ============================================================================
 * POLICY PROVIDER FUNCTIONS
 * ============================================================================ */

HRESULT WINAPI SoftpubAuthenticode(CRYPT_PROVIDER_DATA* pProvData)
{
    LogI("=== SoftpubAuthenticode ===");
    LogD("  pProvData: 0x%p", pProvData);
    LogI("  Result: S_OK (trust all)");
    return S_OK;
}

HRESULT WINAPI SoftpubCheckCert(CRYPT_PROVIDER_DATA* pProvData, DWORD idxSigner,
                                   BOOL fCounterSignerChain, DWORD idxCounterSigner)
{
    LogI("=== SoftpubCheckCert ===");
    LogD("  pProvData: 0x%p", pProvData);
    LogD("  idxSigner: %lu", idxSigner);
    LogD("  fCounterSignerChain: %s", fCounterSignerChain ? "TRUE" : "FALSE");
    LogD("  idxCounterSigner: %lu", idxCounterSigner);
    LogI("  Result: S_OK (trust all)");
    return S_OK;
}

HRESULT WINAPI SoftpubCleanup(CRYPT_PROVIDER_DATA* pProvData)
{
    LogI("=== SoftpubCleanup ===");
    LogD("  pProvData: 0x%p", pProvData);
    LogI("  Result: S_OK");
    return S_OK;
}

HRESULT WINAPI SoftpubDefCertInit(CRYPT_PROVIDER_DATA* pProvData)
{
    LogI("=== SoftpubDefCertInit ===");
    LogD("  pProvData: 0x%p", pProvData);
    LogI("  Result: S_OK");
    return S_OK;
}

BOOL WINAPI SoftpubDllRegisterServer(void)
{
    LogI("=== SoftpubDllRegisterServer ===");
    LogI("  Result: TRUE");
    return TRUE;
}

BOOL WINAPI SoftpubDllUnregisterServer(void)
{
    LogI("=== SoftpubDllUnregisterServer ===");
    LogI("  Result: TRUE");
    return TRUE;
}

HRESULT WINAPI SoftpubFreeDefUsageCallData(CRYPT_PROVIDER_DATA* pProvData)
{
    LogI("=== SoftpubFreeDefUsageCallData ===");
    LogD("  pProvData: 0x%p", pProvData);
    LogI("  Result: S_OK");
    return S_OK;
}

HRESULT WINAPI SoftpubInitialize(CRYPT_PROVIDER_DATA* pProvData)
{
    LogI("=== SoftpubInitialize ===");
    LogD("  pProvData: 0x%p", pProvData);
    LogI("  Result: S_OK");
    return S_OK;
}

HRESULT WINAPI SoftpubLoadDefUsageCallData(CRYPT_PROVIDER_DATA* pProvData)
{
    LogI("=== SoftpubLoadDefUsageCallData ===");
    LogD("  pProvData: 0x%p", pProvData);
    LogI("  Result: S_OK");
    return S_OK;
}

HRESULT WINAPI SoftpubLoadMessage(CRYPT_PROVIDER_DATA* pProvData)
{
    LogI("=== SoftpubLoadMessage ===");
    LogD("  pProvData: 0x%p", pProvData);
    LogI("  Result: S_OK");
    return S_OK;
}

HRESULT WINAPI SoftpubLoadSignature(CRYPT_PROVIDER_DATA* pProvData)
{
    LogI("=== SoftpubLoadSignature ===");
    LogD("  pProvData: 0x%p", pProvData);
    LogI("  Result: S_OK");
    return S_OK;
}

/* ============================================================================
 * DRIVER VERIFICATION FUNCTIONS
 * ============================================================================ */

HRESULT WINAPI DriverCleanupPolicy(CRYPT_PROVIDER_DATA* pProvData)
{
    LogD("DriverCleanupPolicy");
    return S_OK;
}

HRESULT WINAPI DriverFinalPolicy(CRYPT_PROVIDER_DATA* pProvData)
{
    LogD("DriverFinalPolicy");
    return S_OK;
}

HRESULT WINAPI DriverInitializePolicy(CRYPT_PROVIDER_DATA* pProvData)
{
    LogD("DriverInitializePolicy");
    return S_OK;
}

/* ============================================================================
 * GENERIC POLICY FUNCTIONS
 * ============================================================================ */

HRESULT WINAPI GenericChainCertificateTrust(CRYPT_PROVIDER_DATA* pProvData)
{
    LogD("GenericChainCertificateTrust");
    return S_OK;
}

HRESULT WINAPI GenericChainFinalProv(CRYPT_PROVIDER_DATA* pProvData)
{
    LogD("GenericChainFinalProv");
    return S_OK;
}

HRESULT WINAPI HTTPSCertificateTrust(CRYPT_PROVIDER_DATA* pProvData)
{
    LogD("HTTPSCertificateTrust");
    return S_OK;
}

HRESULT WINAPI HTTPSFinalProv(CRYPT_PROVIDER_DATA* pProvData)
{
    LogD("HTTPSFinalProv");
    return S_OK;
}

HRESULT WINAPI OfficeCleanupPolicy(CRYPT_PROVIDER_DATA* pProvData)
{
    LogD("OfficeCleanupPolicy");
    return S_OK;
}

HRESULT WINAPI OfficeInitializePolicy(CRYPT_PROVIDER_DATA* pProvData)
{
    LogD("OfficeInitializePolicy");
    return S_OK;
}

/* ============================================================================
 * ASN.1 ENCODING/DECODING FUNCTIONS
 * ============================================================================ */

BOOL WINAPI WVTAsn1CatMemberInfoDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                          DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                          void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1CatMemberInfoDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1CatMemberInfoEncode(LPCSTR lpszType, DWORD dwFlags, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1CatMemberInfoEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI WVTAsn1CatNameValueDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                         DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                         void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1CatNameValueDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1CatNameValueEncode(LPCSTR lpszType, DWORD dwFlags, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1CatNameValueEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcFinancialCriteriaInfoDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                                      DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                                      void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcFinancialCriteriaInfoDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcFinancialCriteriaInfoEncode(LPCSTR lpszType, DWORD dwFlags, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcFinancialCriteriaInfoEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcIndirectDataContentDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                                    DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                                    void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcIndirectDataContentDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcIndirectDataContentEncode(LPCSTR lpszType, DWORD dwFlags, LPVOID pfnAlloc,
                                                    LPVOID pfnFree, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcIndirectDataContentEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcLinkDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                     DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                     void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcLinkDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcLinkEncode(LPCSTR lpszType, DWORD dwFlags, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcLinkEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcPeImageDataDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                           DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                           void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcPeImageDataDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcPeImageDataEncode(LPCSTR lpszType, DWORD dwFlags, LPVOID pfnAlloc,
                                           LPVOID pfnFree, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcPeImageDataEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcSigInfoDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                        DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                        void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcSigInfoDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcSigInfoEncode(LPCSTR lpszType, DWORD dwFlags, LPVOID pfnAlloc,
                                        LPVOID pfnFree, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcSigInfoEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcSpAgencyInfoDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                             DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                             void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcSpAgencyInfoDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcSpAgencyInfoEncode(LPCSTR lpszType, DWORD dwFlags, LPVOID pfnAlloc,
                                             LPVOID pfnFree, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcSpAgencyInfoEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcSpOpusInfoDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                           DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                           void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcSpOpusInfoDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcSpOpusInfoEncode(LPCSTR lpszType, DWORD dwFlags, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcSpOpusInfoEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcStatementTypeDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                              DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                              void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcStatementTypeDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcStatementTypeEncode(LPCSTR lpszType, DWORD dwFlags, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcStatementTypeEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

HRESULT WINAPI WintrustAddProviderToProcess(GUID* pgProvider, GUID* pgAction, WCHAR* pwszDll,
                                                DWORD dwMajor, LPVOID psProvFuncs) {
    LogD("WintrustAddProviderToProcess");
    return S_OK;
}

HRESULT WINAPI WintrustGetHash(HANDLE hFile, LPCWSTR pwszFilePath, GUID* pgActionID,
                                   LPVOID pvReserved, DWORD* pcbHash, BYTE* pbHash) {
    LogD("WintrustGetHash");
    
    if (!pcbHash) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return E_INVALIDARG;
    }
    
    if (!pbHash) {
        *pcbHash = FAKE_HASH_SIZE;
        return S_OK;
    }
    
    if (*pcbHash < FAKE_HASH_SIZE) {
        *pcbHash = FAKE_HASH_SIZE;
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }
    
    DWORD seed = (DWORD)(ULONG_PTR)hFile ^ GetTickCount();
    for (DWORD i = 0; i < FAKE_HASH_SIZE; i++) {
        seed = seed * 1103515245 + 12345;
        pbHash[i] = (BYTE)(seed >> 16);
    }
    *pcbHash = FAKE_HASH_SIZE;
    
    return S_OK;
}

BOOL WINAPI WintrustUserWriteabilityCheck(HWND hwnd, GUID* pgActionID) {
    LogD("WintrustUserWriteabilityCheck");
    return TRUE;
}

/* ============================================================================
 * ADDITIONAL EXPORTED FUNCTIONS (missing stubs)
 * ============================================================================ */

BOOL WINAPI AddPersonalTrustDBPages(LPVOID lParam, DWORD dwFlags, LPVOID pvReserved) {
    LogD("AddPersonalTrustDBPages");
    return FALSE;
}

BOOL WINAPI CatalogCompactHashDatabase(LPVOID pvReserved) {
    LogD("CatalogCompactHashDatabase");
    return FALSE;
}

DWORD WINAPI ComputeFirstPageHash(HANDLE hFile, BYTE* pbHash, DWORD cbHash) {
    LogD("ComputeFirstPageHash");
    return 0;
}

HRESULT WINAPI ConfigCiFinalPolicy(LPVOID pProvData) {
    LogD("ConfigCiFinalPolicy");
    return S_OK;
}

HRESULT WINAPI ConfigCiPackageFamilyNameCheck(LPVOID pProvData) {
    LogD("ConfigCiPackageFamilyNameCheck");
    return S_OK;
}

BOOL WINAPI CryptCATAdminCalcHashFromFileHandle3(HCATADMIN hCatAdmin, HANDLE hFile,
                                                     DWORD* pcbHash, BYTE* pbHash, DWORD dwFlags) {
    LogD("CryptCATAdminCalcHashFromFileHandle3");
    return CryptCATAdminCalcHashFromFileHandle(hFile, pcbHash, pbHash, dwFlags);
}

BOOL WINAPI CryptCATAdminPauseServiceForBackup(DWORD dwFlags, BOOL fResume) {
    LogD("CryptCATAdminPauseServiceForBackup");
    return TRUE;
}

CRYPTCATMEMBER* WINAPI CryptCATAllocSortedMemberInfo(HANDLE hCatalog, LPWSTR pwszReferenceName) {
    LogD("CryptCATAllocSortedMemberInfo");
    return NULL;
}

CRYPTCATATTRIBUTE* WINAPI CryptCATCDFEnumAttributes(CRYPTCATCDF* pCDF, CRYPTCATMEMBER* pMember,
                                                        CRYPTCATATTRIBUTE* pPrevAttr,
                                                        PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError) {
    LogD("CryptCATCDFEnumAttributes");
    return NULL;
}

CRYPTCATATTRIBUTE* WINAPI CryptCATCDFEnumAttributesWithCDFTag(CRYPTCATCDF* pCDF, LPWSTR pwszMemberTag,
                                                                  CRYPTCATMEMBER* pMember,
                                                                  CRYPTCATATTRIBUTE* pPrevAttr,
                                                                  PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError) {
    LogD("CryptCATCDFEnumAttributesWithCDFTag");
    return NULL;
}

CRYPTCATMEMBER* WINAPI CryptCATCDFEnumMembers(CRYPTCATCDF* pCDF, CRYPTCATMEMBER* pPrevMember,
                                                 PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError) {
    LogD("CryptCATCDFEnumMembers");
    return NULL;
}

LPWSTR WINAPI CryptCATCDFEnumMembersByCDFTag(CRYPTCATCDF* pCDF, LPWSTR pwszPrevCDFTag,
                                                PFN_CDF_PARSE_ERROR_CALLBACK pfnParseError,
                                                CRYPTCATMEMBER** ppMember) {
    LogD("CryptCATCDFEnumMembersByCDFTag");
    return NULL;
}

void WINAPI CryptCATFreeSortedMemberInfo(HANDLE hCatalog, CRYPTCATMEMBER* pCatMember) {
    LogD("CryptCATFreeSortedMemberInfo");
}

HANDLE WINAPI CryptCATHandleFromStore(CRYPTCATSTORE* pCatStore) {
    LogD("CryptCATHandleFromStore");
    return NULL;
}

CRYPTCATSTORE* WINAPI CryptCATStoreFromHandle(HANDLE hCatalog) {
    LogD("CryptCATStoreFromHandle");
    return NULL;
}

BOOL WINAPI CryptCATVerifyMember(HANDLE hCatalog, CRYPTCATMEMBER* pCatMember, DWORD dwFlags) {
    LogD("CryptCATVerifyMember");
    return TRUE;
}

BOOL WINAPI CryptSIPCreateIndirectData(SIP_SUBJECTINFO* pSubjectInfo, DWORD* pcbIndirectData,
                                          SIP_INDIRECT_DATA* pIndirectData) {
    LogD("CryptSIPCreateIndirectData");
    return FALSE;
}

BOOL WINAPI CryptSIPGetCaps(SIP_SUBJECTINFO* pSubjInfo, SIP_CAP_SET* pCaps) {
    LogD("CryptSIPGetCaps");
    return FALSE;
}

BOOL WINAPI CryptSIPGetInfo(SIP_SUBJECTINFO* pSubjectInfo) {
    LogD("CryptSIPGetInfo");
    return FALSE;
}

BOOL WINAPI CryptSIPGetRegWorkingFlags(DWORD* pdwState) {
    LogD("CryptSIPGetRegWorkingFlags");
    if (pdwState) *pdwState = 0;
    return TRUE;
}

BOOL WINAPI CryptSIPGetSealedDigest(SIP_SUBJECTINFO* pSubjectInfo, const BYTE* pbSig, DWORD cbSig,
                                       BYTE* pbDigest, DWORD* pcbDigest) {
    LogD("CryptSIPGetSealedDigest");
    return FALSE;
}

BOOL WINAPI CryptSIPGetSignedDataMsg(SIP_SUBJECTINFO* pSubjectInfo, DWORD* pdwEncodingType,
                                        DWORD dwIndex, DWORD* pcbSignedDataMsg, BYTE* pbSignedDataMsg) {
    LogD("CryptSIPGetSignedDataMsg");
    return FALSE;
}

BOOL WINAPI CryptSIPPutSignedDataMsg(SIP_SUBJECTINFO* pSubjectInfo, DWORD dwEncodingType,
                                        DWORD* pdwIndex, DWORD cbSignedDataMsg, BYTE* pbSignedDataMsg) {
    LogD("CryptSIPPutSignedDataMsg");
    return FALSE;
}

BOOL WINAPI CryptSIPRemoveSignedDataMsg(SIP_SUBJECTINFO* pSubjectInfo, DWORD dwIndex) {
    LogD("CryptSIPRemoveSignedDataMsg");
    return FALSE;
}

BOOL WINAPI CryptSIPVerifyIndirectData(SIP_SUBJECTINFO* pSubjectInfo, SIP_INDIRECT_DATA* pIndirectData) {
    LogD("CryptSIPVerifyIndirectData");
    return TRUE;
}

HRESULT WINAPI DllRegisterServer(void) {
    LogD("DllRegisterServer");
    return S_OK;
}

HRESULT WINAPI DllUnregisterServer(void) {
    LogD("DllUnregisterServer");
    return S_OK;
}

HRESULT WINAPI FindCertsByIssuer(PCERT_CHAIN pCertChains, DWORD* pcbCertChains,
                                    DWORD* pcCertChains, BYTE* pbEncodedIssuerName,
                                    DWORD cbEncodedIssuerName, LPCWSTR pwszPurpose, DWORD dwKeySpec) {
    LogD("FindCertsByIssuer");
    if (pcbCertChains) *pcbCertChains = 0;
    if (pcCertChains) *pcCertChains = 0;
    return S_OK;
}

HRESULT WINAPI GetAuthenticodeSha256Hash(HANDLE hFile, BYTE* pbHash, DWORD cbHash) {
    LogD("GetAuthenticodeSha256Hash");
    return E_NOTIMPL;
}

BOOL WINAPI IsCatalogFile(HANDLE hFile, LPWSTR pwszFileName) {
    LogD("IsCatalogFile: %ls", pwszFileName ? pwszFileName : L"(null)");
    return FALSE;
}

LPWSTR WINAPI MsCatConstructHashTag(CRYPT_ATTRIBUTE* pAttr, DWORD* pcbHashTag) {
    LogD("MsCatConstructHashTag");
    if (pcbHashTag) *pcbHashTag = 0;
    return NULL;
}

void WINAPI MsCatFreeHashTag(LPWSTR pwszHashTag) {
    LogD("MsCatFreeHashTag");
}

BOOL WINAPI OpenPersonalTrustDBDialog(HWND hwndParent) {
    LogD("OpenPersonalTrustDBDialog");
    return FALSE;
}

BOOL WINAPI OpenPersonalTrustDBDialogEx(HWND hwndParent, DWORD dwFlags, LPVOID* ppvTrustInfo) {
    LogD("OpenPersonalTrustDBDialogEx");
    return FALSE;
}

BOOL WINAPI SetMessageDigestInfo(LPVOID pDigestInfo, DWORD cbDigestInfo, LPVOID pvReserved) {
    LogD("SetMessageDigestInfo");
    return FALSE;
}

void WINAPI SoftpubDumpStructure(CRYPT_PROVIDER_DATA* pProvData) {
    LogD("SoftpubDumpStructure");
}

BOOL WINAPI SrpCheckSmartlockerEAandProcessToken(HANDLE hFile, HANDLE hToken, LPVOID pvReserved) {
    LogD("SrpCheckSmartlockerEAandProcessToken");
    return TRUE;
}

BOOL WINAPI TrustDecode(DWORD dwEncodingType, LPCSTR lpszStructType, const BYTE* pbEncoded,
                          DWORD cbEncoded, DWORD dwFlags, void** ppvStructInfo, DWORD* pcbStructInfo) {
    LogD("TrustDecode");
    return FALSE;
}

PCCERT_CONTEXT WINAPI TrustFindIssuerCertificate(PCCERT_CONTEXT pChildCertContext, DWORD dwFlags,
                                                     DWORD* pdwConfidence) {
    LogD("TrustFindIssuerCertificate");
    return NULL;
}

void WINAPI TrustFreeDecode(DWORD dwEncodingType, LPCSTR lpszStructType, void* pvStructInfo) {
    LogD("TrustFreeDecode");
}

BOOL WINAPI TrustIsCertificateSelfSigned(PCCERT_CONTEXT pCertContext, DWORD dwEncoding, DWORD dwFlags) {
    LogD("TrustIsCertificateSelfSigned");
    return FALSE;
}

BOOL WINAPI TrustOpenStores(HCERTSTORE* phRootStore, HCERTSTORE* phTrustStore, DWORD dwFlags) {
    LogD("TrustOpenStores");
    return FALSE;
}

void WINAPI WTConfigCiFreePrivateData(LPVOID pvPrivateData) {
    LogD("WTConfigCiFreePrivateData");
}

HRESULT WINAPI WTConvertCertCtxToChainInfo(PCCERT_CONTEXT pCertContext, LPVOID* ppChainInfo) {
    LogD("WTConvertCertCtxToChainInfo");
    return E_NOTIMPL;
}

HRESULT WINAPI WTGetBioSignatureInfo(HANDLE hFile, LPVOID pvReserved, LPVOID* ppBioInfo) {
    LogD("WTGetBioSignatureInfo");
    return E_NOTIMPL;
}

HRESULT WINAPI WTGetPluginSignatureInfo(HANDLE hFile, LPVOID pvReserved, LPVOID* ppPluginInfo) {
    LogD("WTGetPluginSignatureInfo");
    return E_NOTIMPL;
}

HRESULT WINAPI WTGetSignatureInfo(LPCWSTR pwszFile, HANDLE hFile, DWORD dwFlags,
                                     LPVOID* ppSigInfo, LPVOID pvReserved) {
    LogD("WTGetSignatureInfo: %ls", pwszFile ? pwszFile : L"(null)");
    return E_NOTIMPL;
}

PCCERT_CONTEXT WINAPI WTHelperCertFindIssuerCertificate(PCCERT_CONTEXT pChildContext,
                                                            DWORD chStores, HCERTSTORE* pahStores,
                                                            FILETIME* psftVerifyAsOf, DWORD dwEncoding,
                                                            DWORD* pdwConfidence, DWORD* pdwError) {
    LogD("WTHelperCertFindIssuerCertificate");
    return NULL;
}

HRESULT WINAPI WTHelperCheckCertUsage(PCCERT_CONTEXT pCertContext, LPCSTR pszOID) {
    LogD("WTHelperCheckCertUsage");
    return S_OK;
}

HRESULT WINAPI WTHelperGetAgencyInfo(PCCERT_CONTEXT pCertContext, LPVOID* ppAgencyInfo) {
    LogD("WTHelperGetAgencyInfo");
    return E_NOTIMPL;
}

HANDLE WINAPI WTHelperGetFileHandle(CRYPT_PROVIDER_DATA* pProvData) {
    LogD("WTHelperGetFileHandle");
    return INVALID_HANDLE_VALUE;
}

HRESULT WINAPI WTHelperGetFileHash(CRYPT_PROVIDER_DATA* pProvData, BYTE* pbHash,
                                      DWORD* pcbHash, ALG_ID* pAlgId) {
    LogD("WTHelperGetFileHash");
    if (pcbHash && !pbHash) {
        *pcbHash = FAKE_HASH_SIZE;
        if (pAlgId) *pAlgId = CALG_SHA1;
        return S_OK;
    }
    return E_NOTIMPL;
}

LPCWSTR WINAPI WTHelperGetFileName(CRYPT_PROVIDER_DATA* pProvData) {
    LogD("WTHelperGetFileName");
    return NULL;
}

HRESULT WINAPI WTHelperGetKnownUsages(DWORD dwAction, LPVOID* ppOIDInfo, DWORD* pcOIDInfo) {
    LogD("WTHelperGetKnownUsages");
    if (pcOIDInfo) *pcOIDInfo = 0;
    return S_OK;
}

BOOL WINAPI WTHelperIsChainedToMicrosoft(PCCERT_CONTEXT pCertContext, BOOL fCheckMicrosoftTestRoot) {
    LogD("WTHelperIsChainedToMicrosoft");
    return FALSE;
}

BOOL WINAPI WTHelperIsChainedToMicrosoftFromStateData(CRYPT_PROVIDER_DATA* pProvData) {
    LogD("WTHelperIsChainedToMicrosoftFromStateData");
    return FALSE;
}

BOOL WINAPI WTHelperIsInRootStore(CRYPT_PROVIDER_CERT* pProvCert) {
    LogD("WTHelperIsInRootStore");
    return FALSE;
}

HRESULT WINAPI WTHelperOpenKnownStores(CRYPT_PROVIDER_DATA* pProvData) {
    LogD("WTHelperOpenKnownStores");
    return S_OK;
}

BOOL WINAPI WTIsFirstConfigCiResultPreferred(LPVOID pResult1, LPVOID pResult2) {
    LogD("WTIsFirstConfigCiResultPreferred");
    return TRUE;
}

void WINAPI WTLogConfigCiScriptEvent(LPVOID pProvData, DWORD dwEventId) {
    LogD("WTLogConfigCiScriptEvent: eventId=%lu", dwEventId);
}

void WINAPI WTLogConfigCiScriptEvent2(LPVOID pProvData, DWORD dwEventId, LPVOID pvReserved) {
    LogD("WTLogConfigCiScriptEvent2: eventId=%lu", dwEventId);
}

void WINAPI WTLogConfigCiSignerEvent(LPVOID pProvData, LPVOID pSigner, DWORD dwEventId) {
    LogD("WTLogConfigCiSignerEvent: eventId=%lu", dwEventId);
}

HRESULT WINAPI WTValidateBioSignaturePolicy(LPVOID pProvData, LPVOID pBioInfo) {
    LogD("WTValidateBioSignaturePolicy");
    return S_OK;
}

BOOL WINAPI WVTAsn1CatMemberInfo2Decode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                           DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                           void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1CatMemberInfo2Decode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1CatMemberInfo2Encode(LPCSTR lpszType, DWORD dwFlags, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1CatMemberInfo2Encode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI WVTAsn1IntentToSealAttributeDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                                   DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                                   void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1IntentToSealAttributeDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1IntentToSealAttributeEncode(LPCSTR lpszType, DWORD dwFlags, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1IntentToSealAttributeEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI WVTAsn1SealingSignatureAttributeDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                                       DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                                       void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SealingSignatureAttributeDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1SealingSignatureAttributeEncode(LPCSTR lpszType, DWORD dwFlags, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SealingSignatureAttributeEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI WVTAsn1SealingTimestampAttributeDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                                       DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                                       void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SealingTimestampAttributeDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1SealingTimestampAttributeEncode(LPCSTR lpszType, DWORD dwFlags, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SealingTimestampAttributeEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcMinimalCriteriaInfoDecode(LPCSTR lpszType, const BYTE* pbEncoded, DWORD cbEncoded,
                                                    DWORD dwFlags, LPVOID pfnAlloc, LPVOID pfnFree,
                                                    void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcMinimalCriteriaInfoDecode");
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}

BOOL WINAPI WVTAsn1SpcMinimalCriteriaInfoEncode(LPCSTR lpszType, DWORD dwFlags, void* pvInfo, DWORD* pcbInfo) {
    LogD("WVTAsn1SpcMinimalCriteriaInfoEncode");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

LONG WINAPI WinVerifyTrustEx(HWND hwnd, GUID* pgActionID, WINTRUST_DATA* pWinTrustData) {
    LogD("WinVerifyTrustEx (calling WinVerifyTrust)");
    return WinVerifyTrust(hwnd, pgActionID, pWinTrustData);
}

BOOL WINAPI WintrustAddDefaultForUsage(const char* pszUsageOID, CRYPT_PROVIDER_REGDEFUSAGE* psDefUsage) {
    LogD("WintrustAddDefaultForUsage");
    return TRUE;
}

HRESULT WINAPI WintrustCertificateTrust(CRYPT_PROVIDER_DATA* pProvData) {
    LogD("WintrustCertificateTrust");
    return S_OK;
}

BOOL WINAPI WintrustGetDefaultForUsage(DWORD dwAction, const char* pszUsageOID,
                                          CRYPT_PROVIDER_DEFUSAGE* psUsage) {
    LogD("WintrustGetDefaultForUsage");
    return FALSE;
}

void WINAPI WintrustSetDefaultIncludePEPageHashes(BOOL fIncludePEPageHashes) {
    LogD("WintrustSetDefaultIncludePEPageHashes: %d", fIncludePEPageHashes);
}

HRESULT WINAPI mscat32DllRegisterServer(void) {
    LogD("mscat32DllRegisterServer");
    return S_OK;
}

HRESULT WINAPI mscat32DllUnregisterServer(void) {
    LogD("mscat32DllUnregisterServer");
    return S_OK;
}

HRESULT WINAPI mssip32DllRegisterServer(void) {
    LogD("mssip32DllRegisterServer");
    return S_OK;
}

HRESULT WINAPI mssip32DllUnregisterServer(void) {
    LogD("mssip32DllUnregisterServer");
    return S_OK;
}

/* ============================================================================
 * DLL ENTRY POINT
 * ============================================================================ */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    (void)lpReserved;
    
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        
        /* Initialize critical section */
        InitializeCriticalSection(&g_lock);
        
#if ENABLE_FILE_LOGGING
        InitializeCriticalSection(&g_logLock);
#endif
        
        g_initialized = TRUE;
        
#if ENABLE_DEBUG_CONSOLE
        /* Try to attach to existing console first (e.g., from iphlpapi) */
        if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
            /* No existing console - create new one */
            if (AllocConsole()) {
                FILE* fDummy;
                freopen_s(&fDummy, "CONOUT$", "w", stdout);
                freopen_s(&fDummy, "CONOUT$", "w", stderr);
                freopen_s(&fDummy, "CONIN$", "r", stdin);
                SetConsoleTitleA("WINTRUST Emulator - Trust All Mode");
            }
        } else {
            /* Attached to existing console - redirect stdout */
            FILE* fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
            freopen_s(&fDummy, "CONOUT$", "w", stderr);
        }
        g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        
        printf("\n");
        printf("================================================\n");
        printf("   WINTRUST EMULATOR v2.0\n");
#if TRUST_MODE_TRUST_ALL
        printf("   Mode: TRUST ALL (bypass signature checks)\n");
#else
        printf("   Mode: NO SIGNATURE (return TRUST_E_NOSIGNATURE)\n");
#endif
        printf("   Build: %s %s\n", __DATE__, __TIME__);
        printf("================================================\n\n");
#endif
        
#if ENABLE_FILE_LOGGING
        {
            char path[MAX_PATH], tmp[MAX_PATH];
            if (GetTempPathA(MAX_PATH, tmp) > 0) {
                snprintf(path, MAX_PATH, "%swintrust_%lu.log", tmp, GetCurrentProcessId());
                g_logFile = fopen(path, "w");
                if (g_logFile) {
                    fprintf(g_logFile, "=== WINTRUST Emulator Log ===\n");
                    fprintf(g_logFile, "Build: %s %s\n", __DATE__, __TIME__);
                    fprintf(g_logFile, "PID: %lu\n", GetCurrentProcessId());
#if TRUST_MODE_TRUST_ALL
                    fprintf(g_logFile, "Mode: TRUST ALL\n");
#else
                    fprintf(g_logFile, "Mode: NO SIGNATURE\n");
#endif
                    fprintf(g_logFile, "Log file: %s\n\n", path);
                    fflush(g_logFile);
                }
            }
        }
#endif
        
        LogI("=== WINTRUST.DLL EMULATOR LOADED ===");
        LogI("Process ID: %lu", GetCurrentProcessId());
#if TRUST_MODE_TRUST_ALL
        LogI("Trust Mode: TRUST ALL (WinVerifyTrust returns ERROR_SUCCESS)");
#else
        LogI("Trust Mode: NO SIGNATURE (WinVerifyTrust returns TRUST_E_NOSIGNATURE)");
#endif
        
        break;
    }
    
    case DLL_PROCESS_DETACH:
    {
        if (g_initialized) {
            LogI("=== WINTRUST.DLL EMULATOR UNLOADING ===");
            
#if ENABLE_DEBUG_CONSOLE
            if (g_hConsole && g_hConsole != INVALID_HANDLE_VALUE) {
                printf("\n================================================\n");
                printf("   WINTRUST EMULATOR UNLOADING\n");
                printf("================================================\n");
                Sleep(300);  /* Brief delay to see message */
            }
#endif
            
#if ENABLE_FILE_LOGGING
            if (g_logFile) {
                fprintf(g_logFile, "\n=== WINTRUST Emulator Unloading ===\n");
                fflush(g_logFile);
                fclose(g_logFile);
                g_logFile = NULL;
            }
            DeleteCriticalSection(&g_logLock);
#endif
            
            DeleteCriticalSection(&g_lock);
            g_initialized = FALSE;
        }
        
        break;
    }
    
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        /* Thread notifications disabled via DisableThreadLibraryCalls */
        break;
    }
    
    return TRUE;
}

#ifdef __cplusplus
}
#endif

/* ============================================================================
 * END OF WINTRUST EMULATION
 * ============================================================================ */