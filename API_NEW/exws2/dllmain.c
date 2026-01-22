// =========================================================================================
// Winsock2 Emulator v1.3.0 by EXLOUD
// Complete virtual network implementation via shared memory
// Full implementation with all security improvements, race condition fixes, and bug fixes
// =========================================================================================

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>

#pragma comment(lib, "kernel32.lib")

// =============================================================================
// CONFIGURATION - Logging & Debugging
// =============================================================================

#define ENABLE_CONSOLE            1
#define ENABLE_FILE_LOG           0
#define ENABLE_DEBUG_OUTPUT       0
#define ENABLE_DATA_DUMP          0
#define ENABLE_BEHAVIOR_ANALYSIS  0
#define ENABLE_MEMORY_TRACKING    1

// =============================================================================
// CONFIGURATION - Network Emulation
// =============================================================================

#define MAX_SHARED_SOCKETS        256
#define BUFFER_PER_SOCKET         (64 * 1024)
#define MAX_PENDING_CONN          16
#define EPHEMERAL_PORT_START      49152
#define EPHEMERAL_PORT_END        65535
#define BLOCKING_TIMEOUT_MS       30000
#define MUTEX_TIMEOUT_MS          10000
#define MAGIC_VALUE               0x45584C4F
#define VERSION_VALUE             0x01030000

static const char* SHARED_MEM_NAME = "Local\\EXLOUD_WS2_v130";
static const char* MUTEX_NAME      = "Local\\EXLOUD_WS2_MTX_v130";

// =============================================================================
// MISSING DEFINITIONS
// =============================================================================

#ifndef EAI_OVERFLOW
#define EAI_OVERFLOW 10069
#endif

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

#ifndef NI_MAXSERV
#define NI_MAXSERV 32
#endif

// =============================================================================
// MACROS
// =============================================================================

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a)/sizeof((a)[0]))
#endif

#ifdef _WIN64
typedef unsigned long long UPTR;
#define PTR_FORMAT "0x%llX"
#else
typedef unsigned int UPTR;
#define PTR_FORMAT "0x%lX"
#endif

#if defined(_MSC_VER)
#define TLS __declspec(thread)
#else
#define TLS __thread
#endif

// =============================================================================
// ATOMIC OPERATIONS
// =============================================================================

static __inline LONG AtomicLoad32(volatile LONG* ptr) {
    LONG value = *ptr;
    MemoryBarrier();
    return value;
}

static __inline LONG AtomicLoad32Const(const volatile LONG* ptr) {
    LONG value = *ptr;
    MemoryBarrier();
    return value;
}

static __inline void AtomicStore32(volatile LONG* ptr, LONG value) {
    MemoryBarrier();
    *ptr = value;
    MemoryBarrier();
}

static __inline SIZE_T AtomicLoadSize(volatile SIZE_T* ptr) {
    SIZE_T value = *ptr;
    MemoryBarrier();
    return value;
}

static __inline SIZE_T AtomicLoadSizeConst(const volatile SIZE_T* ptr) {
    SIZE_T value = *ptr;
    MemoryBarrier();
    return value;
}

static __inline void AtomicStoreSize(volatile SIZE_T* ptr, SIZE_T value) {
    MemoryBarrier();
    *ptr = value;
    MemoryBarrier();
}

// =============================================================================
// RESULT TYPES
// =============================================================================

typedef enum {
    LOCK_OK = 0,
    LOCK_FAILED,
    LOCK_ABANDONED,
    LOCK_TIMEOUT
} LOCK_RESULT;

typedef enum {
    BUF_OK = 0,
    BUF_ERROR_NULL,
    BUF_ERROR_OVERFLOW,
    BUF_ERROR_UNDERFLOW,
    BUF_ERROR_SPACE
} BUF_RESULT;

// =============================================================================
// MEMORY TRACKING TYPES
// =============================================================================

#if ENABLE_MEMORY_TRACKING

typedef struct _MEMORY_BLOCK {
    void* ptr;
    size_t size;
    char function[64];
    DWORD thread_id;
    DWORD alloc_time;
    struct _MEMORY_BLOCK* next;
} MEMORY_BLOCK;

typedef struct {
    MEMORY_BLOCK* list;
    CRITICAL_SECTION lock;
    volatile SIZE_T total_allocated;
    volatile SIZE_T peak_allocated;
    volatile LONG alloc_count;
    volatile LONG free_count;
    volatile LONG initialized;
} MEMORY_TRACKER;

static MEMORY_TRACKER g_memory_tracker = {0};

#endif

// =============================================================================
// BEHAVIOR ANALYSIS TYPES
// =============================================================================

#if ENABLE_BEHAVIOR_ANALYSIS
typedef struct {
    volatile LONG short_messages;
    volatile LONG long_messages;
    volatile LONG single_byte_count;
    volatile LONG total_bytes_sent;
    volatile LONG total_bytes_recv;
    volatile LONG send_count;
    volatile LONG recv_count;
} SOCKET_BEHAVIOR;
#endif

// =============================================================================
// SOCKET TYPES
// =============================================================================

typedef struct {
    int data_len;
    int from_len;
    struct sockaddr_storage from_addr;
    DWORD checksum;
} UDP_HDR;

typedef struct {
    volatile LONG in_use;
    volatile LONG is_bound;
    volatile LONG is_listening;
    volatile LONG is_connected;
    volatile LONG is_nonblocking;
    volatile LONG shutdown_flags;
    volatile LONG peer_index;
    volatile LONG accept_count;
    volatile LONG last_error;
    
    SOCKET id;
    DWORD owner_pid;
    DWORD create_time;
    int family;
    int type;
    int protocol;
    
    struct sockaddr_storage local_addr;
    int local_addr_len;
    
    int accept_queue[MAX_PENDING_CONN];
    
    volatile SIZE_T buf_head;
    volatile SIZE_T buf_tail;
    volatile LONG buf_version;
    
    volatile LONG opt_broadcast;
    volatile LONG opt_reuseaddr;
    volatile LONG opt_keepalive;
    volatile LONG opt_nodelay;
    volatile LONG opt_rcvbuf;
    volatile LONG opt_sndbuf;
    struct linger opt_linger;
    
#if ENABLE_BEHAVIOR_ANALYSIS
    SOCKET_BEHAVIOR behavior;
#endif
    
    DWORD reserved[4];
} VSOCK;

typedef struct {
    volatile DWORD magic;
    volatile DWORD version;
    volatile DWORD init_pid;
    volatile DWORD init_time;
    volatile LONG lock_count;
    volatile LONG socket_count;
    volatile LONG total_connections;
    volatile LONG total_bytes_transferred;
    VSOCK sockets[MAX_SHARED_SOCKETS];
    char buffers[MAX_SHARED_SOCKETS][BUFFER_PER_SOCKET];
} SHARED_STATE;

// =============================================================================
// LOGGING GLOBALS
// =============================================================================

#if ENABLE_CONSOLE
static HANDLE g_hConsole = NULL;
static volatile LONG g_consoleAllocated = 0;
#endif

#if ENABLE_FILE_LOG
static HANDLE g_hLogFile = INVALID_HANDLE_VALUE;
#endif

#if ENABLE_DATA_DUMP
static HANDLE g_hDataDumpFile = INVALID_HANDLE_VALUE;
#endif

// =============================================================================
// GLOBAL STATE
// =============================================================================

static HANDLE g_hMap = NULL;
static SHARED_STATE* g_pState = NULL;
static HANDLE g_hMtx = NULL;
static volatile LONG g_nStartup = 0;
static volatile LONG g_nNextPort = EPHEMERAL_PORT_START - 1;
static volatile LONG g_bInitialized = 0;

static TLS int g_err = 0;
static TLS int g_lockDepth = 0;

// Thread-local storage for gethostbyname etc
static TLS struct hostent g_tls_hostent;
static TLS char* g_tls_hostent_aliases[2];
static TLS char* g_tls_hostent_addr_list[3];
static TLS struct in_addr g_tls_hostent_addr;
static TLS char g_tls_hostent_name[256];

static TLS struct protoent g_tls_protoent;
static TLS char g_tls_protoent_name[32];
static TLS char* g_tls_protoent_aliases[2];

static TLS struct servent g_tls_servent;
static TLS char g_tls_servent_name[32];
static TLS char g_tls_servent_proto[16];
static TLS char* g_tls_servent_aliases[2];

// =============================================================================
// EXPORTED DATA
// =============================================================================

const struct in6_addr in6addr_any = {{0}};
const struct in6_addr in6addr_loopback = {{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}};

// =============================================================================
// FORWARD DECLARATIONS
// =============================================================================

static void LogMessage(const char* format, ...);
static void InitLogging(void);
static void CleanupLogging(void);
static BOOL EnsureInit(void);

// =============================================================================
// MEMORY TRACKING IMPLEMENTATION
// =============================================================================

#if ENABLE_MEMORY_TRACKING

static void InitMemoryTracking(void) {
    if (InterlockedCompareExchange(&g_memory_tracker.initialized, 1, 0) == 0) {
        InitializeCriticalSection(&g_memory_tracker.lock);
        g_memory_tracker.list = NULL;
        g_memory_tracker.total_allocated = 0;
        g_memory_tracker.peak_allocated = 0;
        g_memory_tracker.alloc_count = 0;
        g_memory_tracker.free_count = 0;
    }
}

static void* TrackedAlloc(size_t size, const char* function) {
    if (size == 0 || size > (SIZE_MAX / 2)) {
        return NULL;
    }
    
    void* ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!ptr) {
        return NULL;
    }
    
    if (g_memory_tracker.initialized) {
        MEMORY_BLOCK* block = (MEMORY_BLOCK*)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORY_BLOCK));
        
        if (block) {
            block->ptr = ptr;
            block->size = size;
            block->thread_id = GetCurrentThreadId();
            block->alloc_time = GetTickCount();
            
            if (function) {
                strncpy_s(block->function, sizeof(block->function), function, _TRUNCATE);
            }
            
            EnterCriticalSection(&g_memory_tracker.lock);
            
            block->next = g_memory_tracker.list;
            g_memory_tracker.list = block;
            g_memory_tracker.total_allocated += size;
            
            if (g_memory_tracker.total_allocated > g_memory_tracker.peak_allocated) {
                g_memory_tracker.peak_allocated = g_memory_tracker.total_allocated;
            }
            
            InterlockedIncrement(&g_memory_tracker.alloc_count);
            
            LeaveCriticalSection(&g_memory_tracker.lock);
        }
    }
    
    return ptr;
}

static void TrackedFree(void* ptr) {
    if (!ptr) {
        return;
    }
    
    BOOL found = FALSE;
    
    if (g_memory_tracker.initialized) {
        EnterCriticalSection(&g_memory_tracker.lock);
        
        MEMORY_BLOCK** current = &g_memory_tracker.list;
        while (*current) {
            if ((*current)->ptr == ptr) {
                MEMORY_BLOCK* block = *current;
                g_memory_tracker.total_allocated -= block->size;
                *current = block->next;
                HeapFree(GetProcessHeap(), 0, block);
                found = TRUE;
                InterlockedIncrement(&g_memory_tracker.free_count);
                break;
            }
            current = &(*current)->next;
        }
        
        LeaveCriticalSection(&g_memory_tracker.lock);
    }
    
    HeapFree(GetProcessHeap(), 0, ptr);
}

static void ReportMemoryLeaks(void) {
    if (!g_memory_tracker.initialized) {
        return;
    }
    
    EnterCriticalSection(&g_memory_tracker.lock);
    
    LogMessage("=== Memory Report ===");
    LogMessage("[MEM] Allocations: %ld, Frees: %ld", 
        g_memory_tracker.alloc_count, g_memory_tracker.free_count);
    LogMessage("[MEM] Current: %zu bytes, Peak: %zu bytes",
        g_memory_tracker.total_allocated, g_memory_tracker.peak_allocated);
    
    if (g_memory_tracker.list) {
        LogMessage("[MEM] === LEAKS DETECTED ===");
        
        int count = 0;
        for (MEMORY_BLOCK* c = g_memory_tracker.list; c && count < 50; c = c->next, count++) {
            DWORD age = GetTickCount() - c->alloc_time;
            LogMessage("[MEM]   Leak: %zu bytes from %s at %p (TID: %lu, Age: %lu ms)", 
                c->size, c->function, c->ptr, c->thread_id, age);
        }
    } else {
        LogMessage("[MEM] No memory leaks detected.");
    }
    
    LeaveCriticalSection(&g_memory_tracker.lock);
}

static void CleanupMemoryTracking(void) {
    if (InterlockedCompareExchange(&g_memory_tracker.initialized, 0, 1) == 1) {
        ReportMemoryLeaks();
        
        EnterCriticalSection(&g_memory_tracker.lock);
        
        while (g_memory_tracker.list) {
            MEMORY_BLOCK* block = g_memory_tracker.list;
            g_memory_tracker.list = block->next;
            HeapFree(GetProcessHeap(), 0, block->ptr);
            HeapFree(GetProcessHeap(), 0, block);
        }
        
        LeaveCriticalSection(&g_memory_tracker.lock);
        DeleteCriticalSection(&g_memory_tracker.lock);
    }
}

#define SAFE_ALLOC(size, func) TrackedAlloc(size, func)
#define SAFE_FREE(ptr) TrackedFree(ptr)

#else

#define SAFE_ALLOC(size, func) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define SAFE_FREE(ptr) do { if (ptr) HeapFree(GetProcessHeap(), 0, ptr); } while(0)

#endif

// =============================================================================
// LOGGING IMPLEMENTATION
// =============================================================================

static void InitLogging(void) {
#if ENABLE_CONSOLE
    if (InterlockedCompareExchange(&g_consoleAllocated, 1, 0) == 0) {
        if (AllocConsole()) {
            g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            if (g_hConsole && g_hConsole != INVALID_HANDLE_VALUE) {
                SetConsoleTitleA("EXLOUD WS2 Emulator v1.3.0 Debug Console");
            }
        }
    }
#endif

#if ENABLE_FILE_LOG
    if (g_hLogFile == INVALID_HANDLE_VALUE) {
        char path[MAX_PATH];
        if (GetTempPathA(MAX_PATH, path)) {
            strcat_s(path, MAX_PATH, "exloud_ws2_v130.log");
            g_hLogFile = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, 
                NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        }
    }
#endif

#if ENABLE_DATA_DUMP
    if (g_hDataDumpFile == INVALID_HANDLE_VALUE) {
        char path[MAX_PATH];
        if (GetTempPathA(MAX_PATH, path)) {
            strcat_s(path, MAX_PATH, "exloud_ws2_data_v130.log");
            g_hDataDumpFile = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ,
                NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        }
    }
#endif
}

static void CleanupLogging(void) {
#if ENABLE_FILE_LOG
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hLogFile);
        g_hLogFile = INVALID_HANDLE_VALUE;
    }
#endif

#if ENABLE_DATA_DUMP
    if (g_hDataDumpFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hDataDumpFile);
        g_hDataDumpFile = INVALID_HANDLE_VALUE;
    }
#endif

#if ENABLE_CONSOLE
    if (InterlockedCompareExchange(&g_consoleAllocated, 0, 1) == 1) {
        FreeConsole();
        g_hConsole = NULL;
    }
#endif
}

#if ENABLE_CONSOLE || ENABLE_FILE_LOG || ENABLE_DEBUG_OUTPUT

static void LogMessage(const char* format, ...) {
    char buffer[2048];
    char output[2300];
    va_list args;
    
    va_start(args, format);
    int len = _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    
    if (len < 0) {
        buffer[sizeof(buffer) - 1] = '\0';
    }
    
    int outLen = _snprintf_s(output, sizeof(output), _TRUNCATE, 
        "[PID:%05lu TID:%05lu] %s\r\n", 
        GetCurrentProcessId(), GetCurrentThreadId(), buffer);
    
    if (outLen < 0) {
        output[sizeof(output) - 1] = '\0';
        outLen = (int)strlen(output);
    }
    
#if ENABLE_CONSOLE
    if (g_hConsole && g_hConsole != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteConsoleA(g_hConsole, output, (DWORD)outLen, &written, NULL);
    }
#endif

#if ENABLE_FILE_LOG
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(g_hLogFile, output, (DWORD)outLen, &written, NULL);
    }
#endif

#if ENABLE_DEBUG_OUTPUT
    OutputDebugStringA(output);
#endif
}

#else
#define LogMessage(...) ((void)0)
#endif

#if ENABLE_DATA_DUMP
static void DumpDataToFile(const char* prefix, SOCKET s, const char* data, int len) {
    if (g_hDataDumpFile == INVALID_HANDLE_VALUE || len <= 0 || !data) {
        return;
    }
    
    char header[256];
    int headerLen = _snprintf_s(header, sizeof(header), _TRUNCATE, 
        "\r\n=== %s on socket " PTR_FORMAT ", %d bytes ===\r\n", 
        prefix, (UPTR)s, len);
    
    if (headerLen < 0) return;
    
    DWORD written;
    WriteFile(g_hDataDumpFile, header, (DWORD)headerLen, &written, NULL);
    
    char line[128];
    for (int i = 0; i < len && i < 1024; i += 16) {
        int pos = sprintf_s(line, sizeof(line), "%04X: ", i);
        
        for (int j = 0; j < 16; j++) {
            if (i + j < len) {
                pos += sprintf_s(line + pos, sizeof(line) - pos, "%02X ", 
                    (unsigned char)data[i + j]);
            } else {
                pos += sprintf_s(line + pos, sizeof(line) - pos, "   ");
            }
        }
        
        pos += sprintf_s(line + pos, sizeof(line) - pos, " | ");
        
        for (int j = 0; j < 16 && i + j < len; j++) {
            char c = data[i + j];
            line[pos++] = (c >= 32 && c < 127) ? c : '.';
        }
        
        line[pos++] = '\r';
        line[pos++] = '\n';
        line[pos] = '\0';
        
        WriteFile(g_hDataDumpFile, line, (DWORD)pos, &written, NULL);
    }
}
#else
#define DumpDataToFile(prefix, s, data, len) ((void)0)
#endif

// =============================================================================
// PROTOCOLS
// =============================================================================

static const WSAPROTOCOL_INFOW g_Proto[] = {
    {
        .dwServiceFlags1 = XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER | XP1_GRACEFUL_CLOSE,
        .dwProviderFlags = PFL_MATCHES_PROTOCOL_ZERO,
        .ProviderId = {0xe70f1aa0, 0xab8b, 0x11cf, {0x8c, 0xa3, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}},
        .dwCatalogEntryId = 1001,
        .ProtocolChain.ChainLen = 1,
        .iVersion = 2,
        .iAddressFamily = AF_INET,
        .iMaxSockAddr = sizeof(struct sockaddr_in),
        .iMinSockAddr = sizeof(struct sockaddr_in),
        .iSocketType = SOCK_STREAM,
        .iProtocol = IPPROTO_TCP,
        .szProtocol = L"TCP/IP"
    },
    {
        .dwServiceFlags1 = XP1_CONNECTIONLESS | XP1_MESSAGE_ORIENTED | XP1_SUPPORT_BROADCAST,
        .dwProviderFlags = PFL_MATCHES_PROTOCOL_ZERO,
        .ProviderId = {0xe70f1aa0, 0xab8b, 0x11cf, {0x8c, 0xa3, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}},
        .dwCatalogEntryId = 1002,
        .ProtocolChain.ChainLen = 1,
        .iVersion = 2,
        .iAddressFamily = AF_INET,
        .iMaxSockAddr = sizeof(struct sockaddr_in),
        .iMinSockAddr = sizeof(struct sockaddr_in),
        .iSocketType = SOCK_DGRAM,
        .iProtocol = IPPROTO_UDP,
        .dwMessageSize = 65467,
        .szProtocol = L"UDP/IP"
    },
    {
        .dwServiceFlags1 = XP1_GUARANTEED_DELIVERY | XP1_GUARANTEED_ORDER | XP1_GRACEFUL_CLOSE,
        .dwProviderFlags = PFL_MATCHES_PROTOCOL_ZERO,
        .ProviderId = {0xf9eab0c0, 0x26d4, 0x11d0, {0xbb, 0xbf, 0x00, 0xaa, 0x00, 0x6c, 0x34, 0xe4}},
        .dwCatalogEntryId = 1004,
        .ProtocolChain.ChainLen = 1,
        .iVersion = 2,
        .iAddressFamily = AF_INET6,
        .iMaxSockAddr = sizeof(struct sockaddr_in6),
        .iMinSockAddr = sizeof(struct sockaddr_in6),
        .iSocketType = SOCK_STREAM,
        .iProtocol = IPPROTO_TCP,
        .szProtocol = L"TCP/IPv6"
    },
    {
        .dwServiceFlags1 = XP1_CONNECTIONLESS | XP1_MESSAGE_ORIENTED | XP1_SUPPORT_BROADCAST,
        .dwProviderFlags = PFL_MATCHES_PROTOCOL_ZERO,
        .ProviderId = {0xf9eab0c0, 0x26d4, 0x11d0, {0xbb, 0xbf, 0x00, 0xaa, 0x00, 0x6c, 0x34, 0xe4}},
        .dwCatalogEntryId = 1005,
        .ProtocolChain.ChainLen = 1,
        .iVersion = 2,
        .iAddressFamily = AF_INET6,
        .iMaxSockAddr = sizeof(struct sockaddr_in6),
        .iMinSockAddr = sizeof(struct sockaddr_in6),
        .iSocketType = SOCK_DGRAM,
        .iProtocol = IPPROTO_UDP,
        .dwMessageSize = 65467,
        .szProtocol = L"UDP/IPv6"
    }
};

#define NUM_PROTO ARRAYSIZE(g_Proto)

// =============================================================================
// LOCKING HELPERS
// =============================================================================

static LOCK_RESULT Lk(void) {
    if (!g_hMtx) {
        return LOCK_FAILED;
    }
    
    if (g_lockDepth > 0) {
        g_lockDepth++;
        return LOCK_OK;
    }
    
    DWORD result = WaitForSingleObject(g_hMtx, MUTEX_TIMEOUT_MS);
    
    switch (result) {
        case WAIT_OBJECT_0:
            g_lockDepth = 1;
            if (g_pState) {
                InterlockedIncrement(&g_pState->lock_count);
            }
            return LOCK_OK;
            
        case WAIT_ABANDONED:
            g_lockDepth = 1;
            if (g_pState) {
                InterlockedIncrement(&g_pState->lock_count);
            }
            return LOCK_ABANDONED;
            
        case WAIT_TIMEOUT:
            return LOCK_TIMEOUT;
            
        default:
            return LOCK_FAILED;
    }
}

static void Ulk(void) {
    if (g_lockDepth > 0) {
        g_lockDepth--;
        if (g_lockDepth == 0 && g_hMtx) {
            ReleaseMutex(g_hMtx);
        }
    }
}

static void ForceUnlock(void) {
    if (g_hMtx && g_lockDepth > 0) {
        g_lockDepth = 0;
        ReleaseMutex(g_hMtx);
    }
}

#define SAFE_LOCK() do { \
    LOCK_RESULT _lr = Lk(); \
    if (_lr == LOCK_FAILED || _lr == LOCK_TIMEOUT) { \
        g_err = WSAENETDOWN; \
        return SOCKET_ERROR; \
    } \
} while(0)

#define SAFE_LOCK_SOCKET() do { \
    LOCK_RESULT _lr = Lk(); \
    if (_lr == LOCK_FAILED || _lr == LOCK_TIMEOUT) { \
        g_err = WSAENETDOWN; \
        return INVALID_SOCKET; \
    } \
} while(0)

// =============================================================================
// VALIDATION HELPERS
// =============================================================================

static __inline BOOL IsValidSocketIndex(int index) {
    return (index >= 0 && index < MAX_SHARED_SOCKETS);
}

static BOOL IsValidState(void) {
    if (!g_pState) return FALSE;
    DWORD magic = AtomicLoad32((volatile LONG*)&g_pState->magic);
    DWORD version = AtomicLoad32((volatile LONG*)&g_pState->version);
    if (magic != MAGIC_VALUE) return FALSE;
    if (version != VERSION_VALUE) return FALSE;
    return TRUE;
}

static __inline BOOL IsSocketInUse(const VSOCK* s) {
    if (!s) return FALSE;
    return (AtomicLoad32Const(&s->in_use) != 0);
}

// =============================================================================
// SOCKET HELPERS
// =============================================================================

static SOCKET GenId(void) {
    static volatile LONG counter = 1000;
    LONG newId;
    do {
        newId = InterlockedIncrement(&counter);
    } while ((SOCKET)(UPTR)newId == INVALID_SOCKET);
    return (SOCKET)(UPTR)newId;
}

static int FindSlot(void) {
    if (!IsValidState()) return -1;
    for (int i = 0; i < MAX_SHARED_SOCKETS; i++) {
        if (!IsSocketInUse(&g_pState->sockets[i])) {
            return i;
        }
    }
    return -1;
}

static VSOCK* FindSock(SOCKET s) {
    if (!IsValidState()) return NULL;
    if (s == INVALID_SOCKET) return NULL;
    
    for (int i = 0; i < MAX_SHARED_SOCKETS; i++) {
        VSOCK* sock = &g_pState->sockets[i];
        if (IsSocketInUse(sock) && sock->id == s) {
            return sock;
        }
    }
    return NULL;
}

static int SockIdx(const VSOCK* v) {
    if (!v || !IsValidState()) return -1;
    ptrdiff_t i = v - g_pState->sockets;
    if (i >= 0 && i < MAX_SHARED_SOCKETS) {
        return (int)i;
    }
    return -1;
}

static VSOCK* GetSockByIndex(int index) {
    if (!IsValidState()) return NULL;
    if (!IsValidSocketIndex(index)) return NULL;
    VSOCK* s = &g_pState->sockets[index];
    if (!IsSocketInUse(s)) return NULL;
    return s;
}

// =============================================================================
// BUFFER MANAGEMENT
// =============================================================================

static __inline char* GetBuf(int sockIdx) {
    if (!IsValidState() || !IsValidSocketIndex(sockIdx)) return NULL;
    return g_pState->buffers[sockIdx];
}

static __inline size_t BufCap(void) {
    return BUFFER_PER_SOCKET;
}

typedef struct {
    size_t head;
    size_t tail;
    size_t used;
    size_t free_space;
    LONG version;
} BUF_SNAPSHOT;

static BUF_SNAPSHOT BufSnapshot(const VSOCK* s) {
    BUF_SNAPSHOT snap = {0};
    if (!s) return snap;
    
    size_t cap = BufCap();
    snap.version = AtomicLoad32Const(&s->buf_version);
    snap.head = AtomicLoadSizeConst(&s->buf_head) % cap;
    snap.tail = AtomicLoadSizeConst(&s->buf_tail) % cap;
    snap.used = (snap.tail + cap - snap.head) % cap;
    snap.free_space = (snap.used >= cap - 1) ? 0 : (cap - snap.used - 1);
    
    return snap;
}

static BUF_RESULT BufWrite(VSOCK* s, const void* data, size_t len) {
    if (!s) return BUF_ERROR_NULL;
    if (!data || len == 0) return BUF_OK;
    
    int sockIdx = SockIdx(s);
    char* buf = GetBuf(sockIdx);
    if (!buf) return BUF_ERROR_NULL;
    
    size_t cap = BufCap();
    if (len > cap - 1) return BUF_ERROR_OVERFLOW;
    
    BUF_SNAPSHOT snap = BufSnapshot(s);
    if (len > snap.free_space) return BUF_ERROR_SPACE;
    
    size_t first_chunk = min(len, cap - snap.tail);
    memcpy(buf + snap.tail, data, first_chunk);
    
    if (len > first_chunk) {
        memcpy(buf, (const char*)data + first_chunk, len - first_chunk);
    }
    
    MemoryBarrier();
    AtomicStoreSize(&s->buf_tail, (snap.tail + len) % cap);
    InterlockedIncrement(&s->buf_version);
    
    return BUF_OK;
}

static BUF_RESULT BufRead(VSOCK* s, void* data, size_t len, BOOL consume) {
    if (!s) return BUF_ERROR_NULL;
    if (!data || len == 0) return BUF_OK;
    
    int sockIdx = SockIdx(s);
    char* buf = GetBuf(sockIdx);
    if (!buf) return BUF_ERROR_NULL;
    
    size_t cap = BufCap();
    BUF_SNAPSHOT snap = BufSnapshot(s);
    
    if (len > snap.used) return BUF_ERROR_UNDERFLOW;
    
    size_t first_chunk = min(len, cap - snap.head);
    memcpy(data, buf + snap.head, first_chunk);
    
    if (len > first_chunk) {
        memcpy((char*)data + first_chunk, buf, len - first_chunk);
    }
    
    if (consume) {
        MemoryBarrier();
        AtomicStoreSize(&s->buf_head, (snap.head + len) % cap);
    }
    
    return BUF_OK;
}

static size_t BufUsed(const VSOCK* s) {
    BUF_SNAPSHOT snap = BufSnapshot(s);
    return snap.used;
}

static size_t BufFree(const VSOCK* s) {
    BUF_SNAPSHOT snap = BufSnapshot(s);
    return snap.free_space;
}

// =============================================================================
// BYTE ORDER
// =============================================================================

static __inline u_long SwapL(u_long x) {
    return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | 
           ((x >> 8) & 0xFF00) | ((x >> 24) & 0xFF);
}

static __inline u_short SwapS(u_short x) {
    return (u_short)(((x & 0xFF) << 8) | ((x >> 8) & 0xFF));
}

u_long WSAAPI ex_htonl(u_long h) { return SwapL(h); }
u_short WSAAPI ex_htons(u_short h) { return SwapS(h); }
u_long WSAAPI ex_ntohl(u_long n) { return SwapL(n); }
u_short WSAAPI ex_ntohs(u_short n) { return SwapS(n); }

// =============================================================================
// ADDRESS HELPERS
// =============================================================================

static u_short GetPort(const struct sockaddr* sa) {
    if (!sa) return 0;
    switch (sa->sa_family) {
        case AF_INET:
            return ex_ntohs(((const struct sockaddr_in*)sa)->sin_port);
        case AF_INET6:
            return ex_ntohs(((const struct sockaddr_in6*)sa)->sin6_port);
        default:
            return 0;
    }
}

static void SetPort(struct sockaddr* sa, u_short port) {
    if (!sa) return;
    switch (sa->sa_family) {
        case AF_INET:
            ((struct sockaddr_in*)sa)->sin_port = ex_htons(port);
            break;
        case AF_INET6:
            ((struct sockaddr_in6*)sa)->sin6_port = ex_htons(port);
            break;
    }
}

static u_short NextPort(void) {
    for (int attempts = 0; attempts < 100; attempts++) {
        LONG current = g_nNextPort;
        LONG next = current + 1;
        
        if (next > EPHEMERAL_PORT_END) {
            next = EPHEMERAL_PORT_START;
        }
        
        if (InterlockedCompareExchange(&g_nNextPort, next, current) == current) {
            return (u_short)next;
        }
    }
    
    return (u_short)(EPHEMERAL_PORT_START + (GetTickCount() % 
        (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START)));
}

static BOOL PortUsed(u_short port, int family) {
    if (!IsValidState()) return FALSE;
    
    for (int i = 0; i < MAX_SHARED_SOCKETS; i++) {
        VSOCK* s = &g_pState->sockets[i];
        if (!IsSocketInUse(s)) continue;
        if (!AtomicLoad32(&s->is_bound)) continue;
        if (s->local_addr.ss_family != family) continue;
        if (GetPort((struct sockaddr*)&s->local_addr) == port) {
            return TRUE;
        }
    }
    return FALSE;
}

static void AutoBind(VSOCK* s) {
    if (!s || AtomicLoad32(&s->is_bound)) return;
    
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    addr.ss_family = (ADDRESS_FAMILY)s->family;
    
    u_short port = 0;
    
    if (s->family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)&addr;
        sin->sin_addr.s_addr = ex_htonl(INADDR_LOOPBACK);
        
        for (int i = 0; i < 1000; i++) {
            port = NextPort();
            if (!PortUsed(port, AF_INET)) {
                sin->sin_port = ex_htons(port);
                break;
            }
        }
        s->local_addr_len = sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&addr;
        sin6->sin6_addr = in6addr_loopback;
        
        for (int i = 0; i < 1000; i++) {
            port = NextPort();
            if (!PortUsed(port, AF_INET6)) {
                sin6->sin6_port = ex_htons(port);
                break;
            }
        }
        s->local_addr_len = sizeof(struct sockaddr_in6);
    }
    
    memcpy(&s->local_addr, &addr, sizeof(addr));
    AtomicStore32(&s->is_bound, TRUE);
}

// =============================================================================
// EVENT HELPERS
// =============================================================================

static BOOL EvName(char* buf, size_t bufsize, const char* prefix, SOCKET sock) {
    if (!buf || bufsize < 64 || !prefix) return FALSE;
    
    int result = _snprintf_s(buf, bufsize, _TRUNCATE, 
        "Local\\EXLOUD_%s_%llu", prefix, (unsigned long long)(UPTR)sock);
    
    return (result > 0);
}

static BOOL EvNameAccept(char* buf, size_t bufsize, int family, u_short port) {
    if (!buf || bufsize < 64) return FALSE;
    
    int result = _snprintf_s(buf, bufsize, _TRUNCATE, 
        "Local\\EXLOUD_AC_%d_%u", family, (unsigned)port);
    
    return (result > 0);
}

static void SignalEvent(const char* name) {
    if (!name || name[0] == '\0') return;
    
    HANDLE h = OpenEventA(EVENT_MODIFY_STATE, FALSE, name);
    if (h) {
        SetEvent(h);
        CloseHandle(h);
    }
}

// =============================================================================
// INET FUNCTIONS
// =============================================================================

unsigned long WSAAPI ex_inet_addr(const char* cp) {
    if (!cp) return INADDR_NONE;
    
    unsigned int a, b, c, d;
    char extra;
    
    int result = sscanf_s(cp, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra, 1);
    
    if (result != 4) return INADDR_NONE;
    if (a > 255 || b > 255 || c > 255 || d > 255) return INADDR_NONE;
    
    return (u_long)((d << 24) | (c << 16) | (b << 8) | a);
}

char* WSAAPI ex_inet_ntoa(struct in_addr in) {
    static TLS char buf[20];
    unsigned char* p = (unsigned char*)&in.s_addr;
    sprintf_s(buf, sizeof(buf), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return buf;
}

int WSAAPI ex_inet_pton(int af, const char* src, void* dst) {
    if (!src || !dst) {
        g_err = WSAEFAULT;
        return -1;
    }
    
    if (af == AF_INET) {
        u_long addr = ex_inet_addr(src);
        if (addr == INADDR_NONE && strcmp(src, "255.255.255.255") != 0) {
            return 0;
        }
        ((struct in_addr*)dst)->s_addr = addr;
        return 1;
    }
    
    if (af == AF_INET6) {
        if (strcmp(src, "::1") == 0) {
            memcpy(dst, &in6addr_loopback, 16);
            return 1;
        }
        if (strcmp(src, "::") == 0) {
            memset(dst, 0, 16);
            return 1;
        }
        return 0;
    }
    
    g_err = WSAEAFNOSUPPORT;
    return -1;
}

const char* WSAAPI ex_inet_ntop(int af, const void* src, char* dst, size_t size) {
    if (!src || !dst) {
        g_err = WSAEFAULT;
        return NULL;
    }
    
    if (af == AF_INET) {
        if (size < INET_ADDRSTRLEN) {
            g_err = WSAEINVAL;
            return NULL;
        }
        char* s = ex_inet_ntoa(*(const struct in_addr*)src);
        strcpy_s(dst, size, s);
        return dst;
    }
    
    if (af == AF_INET6) {
        if (size < INET6_ADDRSTRLEN) {
            g_err = WSAEINVAL;
            return NULL;
        }
        const unsigned char* b = (const unsigned char*)src;
        sprintf_s(dst, size, 
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
        return dst;
    }
    
    g_err = WSAEAFNOSUPPORT;
    return NULL;
}

// Wide versions
const wchar_t* WSAAPI ex_InetNtopW(INT Family, const VOID* pAddr, 
    PWSTR pStringBuf, size_t StringBufSize) {
    
    if (!pAddr || !pStringBuf || StringBufSize == 0) {
        g_err = WSAEFAULT;
        return NULL;
    }
    
    char tempBuf[INET6_ADDRSTRLEN];
    
    if (!ex_inet_ntop(Family, pAddr, tempBuf, sizeof(tempBuf))) {
        return NULL;
    }
    
    int converted = MultiByteToWideChar(CP_ACP, 0, tempBuf, -1, 
        pStringBuf, (int)StringBufSize);
    
    if (converted == 0) {
        g_err = WSAEINVAL;
        return NULL;
    }
    
    return pStringBuf;
}

INT WSAAPI ex_InetPtonW(INT Family, PCWSTR pszAddrString, PVOID pAddrBuf) {
    if (!pszAddrString || !pAddrBuf) {
        g_err = WSAEFAULT;
        return -1;
    }
    
    char tempBuf[INET6_ADDRSTRLEN];
    
    int converted = WideCharToMultiByte(CP_ACP, 0, pszAddrString, -1,
        tempBuf, sizeof(tempBuf), NULL, NULL);
    
    if (converted == 0) {
        g_err = WSAEINVAL;
        return -1;
    }
    
    return ex_inet_pton(Family, tempBuf, pAddrBuf);
}

// =============================================================================
// UDP CHECKSUM
// =============================================================================

static DWORD CalcUdpChecksum(const UDP_HDR* hdr, const char* data, int len) {
    DWORD sum = 0;
    sum += hdr->data_len;
    sum += hdr->from_len;
    sum += (DWORD)hdr->from_addr.ss_family;
    
    for (int i = 0; i < min(len, 16); i++) {
        sum += (unsigned char)data[i];
    }
    
    return sum ^ 0xDEADBEEF;
}

// =============================================================================
// CLEANUP DEAD PROCESSES
// =============================================================================

static void CleanDeadProcesses(void) {
    if (!IsValidState()) return;
    
    DWORD myPid = GetCurrentProcessId();
    
    for (int i = 0; i < MAX_SHARED_SOCKETS; i++) {
        VSOCK* s = &g_pState->sockets[i];
        if (!IsSocketInUse(s)) continue;
        if (s->owner_pid == myPid) continue;
        if (s->owner_pid == 0) continue;
        
        HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, s->owner_pid);
        
        BOOL shouldClean = FALSE;
        
        if (!hProcess) {
            DWORD err = GetLastError();
            if (err == ERROR_INVALID_PARAMETER || err == ERROR_ACCESS_DENIED) {
                shouldClean = TRUE;
            }
        } else {
            DWORD waitResult = WaitForSingleObject(hProcess, 0);
            if (waitResult == WAIT_OBJECT_0) {
                shouldClean = TRUE;
            }
            CloseHandle(hProcess);
        }
        
        if (shouldClean) {
            LogMessage("CleanDeadProcesses: Cleaning socket %d from dead process %lu", 
                i, s->owner_pid);
            
            int peerIdx = AtomicLoad32(&s->peer_index);
            if (IsValidSocketIndex(peerIdx)) {
                VSOCK* peer = &g_pState->sockets[peerIdx];
                if (IsSocketInUse(peer)) {
                    AtomicStore32(&peer->is_connected, FALSE);
                    AtomicStore32(&peer->peer_index, -1);
                    
                    char evName[64];
                    if (EvName(evName, sizeof(evName), "RD", peer->id)) {
                        SignalEvent(evName);
                    }
                }
            }
            
            memset(s, 0, sizeof(VSOCK));
            AtomicStore32(&s->peer_index, -1);
        }
    }
}

// =============================================================================
// BEHAVIOR ANALYSIS
// =============================================================================

#if ENABLE_BEHAVIOR_ANALYSIS
static void UpdateSendBehavior(VSOCK* s, int bytes) {
    if (!s || bytes <= 0) return;
    
    InterlockedAdd(&s->behavior.total_bytes_sent, bytes);
    InterlockedIncrement(&s->behavior.send_count);
    
    if (bytes == 1) {
        InterlockedIncrement(&s->behavior.single_byte_count);
    } else if (bytes < 16) {
        InterlockedIncrement(&s->behavior.short_messages);
    } else {
        InterlockedIncrement(&s->behavior.long_messages);
    }
}

static void UpdateRecvBehavior(VSOCK* s, int bytes) {
    if (!s || bytes <= 0) return;
    
    InterlockedAdd(&s->behavior.total_bytes_recv, bytes);
    InterlockedIncrement(&s->behavior.recv_count);
}
#else
#define UpdateSendBehavior(s, bytes) ((void)0)
#define UpdateRecvBehavior(s, bytes) ((void)0)
#endif

// =============================================================================
// INITIALIZATION / CLEANUP
// =============================================================================

static BOOL InitSharedMemory(void) {
    if (g_hMtx && IsValidState()) {
        return TRUE;
    }
    
    InitLogging();
    
#if ENABLE_MEMORY_TRACKING
    InitMemoryTracking();
#endif
    
    LogMessage("=== EXLOUD WS2 Emulator v1.3.0 Initializing ===");
    
    g_hMtx = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    if (!g_hMtx) {
        LogMessage("InitSharedMemory: CreateMutex failed: %lu", GetLastError());
        return FALSE;
    }
    
    LOCK_RESULT lr = Lk();
    if (lr == LOCK_FAILED || lr == LOCK_TIMEOUT) {
        CloseHandle(g_hMtx);
        g_hMtx = NULL;
        return FALSE;
    }
    
    g_hMap = CreateFileMappingA(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
        0, sizeof(SHARED_STATE), SHARED_MEM_NAME);
    
    if (!g_hMap) {
        LogMessage("InitSharedMemory: CreateFileMapping failed: %lu", GetLastError());
        Ulk();
        CloseHandle(g_hMtx);
        g_hMtx = NULL;
        return FALSE;
    }
    
    BOOL isFirst = (GetLastError() != ERROR_ALREADY_EXISTS);
    
    g_pState = (SHARED_STATE*)MapViewOfFile(
        g_hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SHARED_STATE));
    
    if (!g_pState) {
        LogMessage("InitSharedMemory: MapViewOfFile failed: %lu", GetLastError());
        Ulk();
        CloseHandle(g_hMap);
        CloseHandle(g_hMtx);
        g_hMap = NULL;
        g_hMtx = NULL;
        return FALSE;
    }
    
    if (isFirst) {
        LogMessage("First process: Initializing shared state");
        memset(g_pState, 0, sizeof(SHARED_STATE));
        
        AtomicStore32((volatile LONG*)&g_pState->magic, MAGIC_VALUE);
        AtomicStore32((volatile LONG*)&g_pState->version, VERSION_VALUE);
        AtomicStore32((volatile LONG*)&g_pState->init_pid, GetCurrentProcessId());
        AtomicStore32((volatile LONG*)&g_pState->init_time, GetTickCount());
        
        for (int i = 0; i < MAX_SHARED_SOCKETS; i++) {
            AtomicStore32(&g_pState->sockets[i].peer_index, -1);
        }
    } else {
        if (!IsValidState()) {
            LogMessage("InitSharedMemory: Invalid shared state");
            UnmapViewOfFile(g_pState);
            Ulk();
            CloseHandle(g_hMap);
            CloseHandle(g_hMtx);
            g_pState = NULL;
            g_hMap = NULL;
            g_hMtx = NULL;
            return FALSE;
        }
        LogMessage("Attached to existing shared state (init by PID: %lu)", g_pState->init_pid);
    }
    
    CleanDeadProcesses();
    Ulk();
    
    InterlockedExchange(&g_bInitialized, 1);
    LogMessage("Initialization complete");
    return TRUE;
}

static void CleanupSharedMemory(void) {
    LONG count = InterlockedDecrement(&g_nStartup);
    if (count > 0) {
        return;
    }
    
    LogMessage("=== Final Cleanup ===");
    
    if (g_pState) {
        LOCK_RESULT lr = Lk();
        if (lr == LOCK_OK || lr == LOCK_ABANDONED) {
            DWORD myPid = GetCurrentProcessId();
            
            for (int i = 0; i < MAX_SHARED_SOCKETS; i++) {
                VSOCK* s = &g_pState->sockets[i];
                if (s->owner_pid != myPid) continue;
                
                int peerIdx = AtomicLoad32(&s->peer_index);
                if (IsValidSocketIndex(peerIdx)) {
                    VSOCK* peer = &g_pState->sockets[peerIdx];
                    if (IsSocketInUse(peer)) {
                        AtomicStore32(&peer->is_connected, FALSE);
                        AtomicStore32(&peer->peer_index, -1);
                        
                        char evName[64];
                        if (EvName(evName, sizeof(evName), "RD", peer->id)) {
                            SignalEvent(evName);
                        }
                    }
                }
                
                memset(s, 0, sizeof(VSOCK));
                AtomicStore32(&s->peer_index, -1);
            }
            Ulk();
        }
        
        UnmapViewOfFile(g_pState);
        g_pState = NULL;
    }
    
    if (g_hMap) {
        CloseHandle(g_hMap);
        g_hMap = NULL;
    }
    
    ForceUnlock();
    
    if (g_hMtx) {
        CloseHandle(g_hMtx);
        g_hMtx = NULL;
    }
    
#if ENABLE_MEMORY_TRACKING
    CleanupMemoryTracking();
#endif
    
    CleanupLogging();
    
    InterlockedExchange(&g_bInitialized, 0);
}

static BOOL EnsureInit(void) {
    if (AtomicLoad32(&g_bInitialized) && IsValidState()) {
        return TRUE;
    }
    return InitSharedMemory();
}

// =============================================================================
// WSA STARTUP/CLEANUP/ERROR
// =============================================================================

int WSAAPI ex_WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData) {
    (void)wVersionRequested;
    
    if (InterlockedIncrement(&g_nStartup) == 1) {
        if (!InitSharedMemory()) {
            InterlockedDecrement(&g_nStartup);
            return WSASYSNOTREADY;
        }
    }
    
    LogMessage("WSAStartup(version=0x%04X)", wVersionRequested);
    
    if (lpWSAData) {
        memset(lpWSAData, 0, sizeof(WSADATA));
        lpWSAData->wVersion = MAKEWORD(2, 2);
        lpWSAData->wHighVersion = MAKEWORD(2, 2);
        strcpy_s(lpWSAData->szDescription, sizeof(lpWSAData->szDescription), 
            "EXLOUD WS2 Emulator 1.3");
        strcpy_s(lpWSAData->szSystemStatus, sizeof(lpWSAData->szSystemStatus), 
            "Running");
    }
    
    return 0;
}

int WSAAPI ex_WSACleanup(void) {
    LogMessage("WSACleanup");
    CleanupSharedMemory();
    return 0;
}

int WSAAPI ex_WSAGetLastError(void) {
    return g_err;
}

void WSAAPI ex_WSASetLastError(int iError) {
    g_err = iError;
    SetLastError((DWORD)iError);
}

// =============================================================================
// SOCKET
// =============================================================================

SOCKET WSAAPI ex_socket(int af, int type, int protocol) {
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return INVALID_SOCKET;
    }
    
    LogMessage("socket(af=%d, type=%d, proto=%d)", af, type, protocol);
    
    if (af != AF_INET && af != AF_INET6) {
        g_err = WSAEAFNOSUPPORT;
        return INVALID_SOCKET;
    }
    
    if (type != SOCK_STREAM && type != SOCK_DGRAM) {
        g_err = WSAESOCKTNOSUPPORT;
        return INVALID_SOCKET;
    }
    
    if (protocol == 0) {
        protocol = (type == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
    }
    
    SAFE_LOCK_SOCKET();
    
    int idx = FindSlot();
    if (idx < 0) {
        Ulk();
        g_err = WSAENOBUFS;
        return INVALID_SOCKET;
    }
    
    VSOCK* s = &g_pState->sockets[idx];
    memset(s, 0, sizeof(VSOCK));
    
    s->id = GenId();
    s->owner_pid = GetCurrentProcessId();
    s->create_time = GetTickCount();
    s->family = af;
    s->type = type;
    s->protocol = protocol;
    s->local_addr.ss_family = (ADDRESS_FAMILY)af;
    s->local_addr_len = (af == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    
    AtomicStore32(&s->peer_index, -1);
    AtomicStore32(&s->opt_rcvbuf, 65536);
    AtomicStore32(&s->opt_sndbuf, 65536);
    AtomicStore32(&s->in_use, TRUE);
    
    InterlockedIncrement(&g_pState->socket_count);
    
    SOCKET result = s->id;
    Ulk();
    
    LogMessage(" -> socket " PTR_FORMAT " (idx=%d)", (UPTR)result, idx);
    return result;
}

SOCKET WSAAPI ex_WSASocketA(int af, int type, int protocol, 
    LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags) {
    (void)lpProtocolInfo; (void)g; (void)dwFlags;
    return ex_socket(af, type, protocol);
}

SOCKET WSAAPI ex_WSASocketW(int af, int type, int protocol,
    LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags) {
    (void)lpProtocolInfo; (void)g; (void)dwFlags;
    return ex_socket(af, type, protocol);
}

// =============================================================================
// BIND
// =============================================================================

int WSAAPI ex_bind(SOCKET s, const struct sockaddr* addr, int namelen) {
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    if (!addr || namelen < (int)sizeof(struct sockaddr)) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    int family = addr->sa_family;
    if (family != AF_INET && family != AF_INET6) {
        g_err = WSAEAFNOSUPPORT;
        return SOCKET_ERROR;
    }
    
    int minLen = (family == AF_INET) ? (int)sizeof(struct sockaddr_in) : 
                                        (int)sizeof(struct sockaddr_in6);
    if (namelen < minLen) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    struct sockaddr_storage localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    memcpy(&localAddr, addr, min(namelen, (int)sizeof(localAddr)));
    
    u_short port = GetPort((struct sockaddr*)&localAddr);
    
    LogMessage("bind(" PTR_FORMAT ", port=%u)", (UPTR)s, port);
    
    SAFE_LOCK();
    
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    if (AtomicLoad32(&sock->is_bound)) {
        Ulk();
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    if (port == 0) {
        for (int i = 0; i < 1000; i++) {
            u_short testPort = NextPort();
            if (!PortUsed(testPort, family)) {
                SetPort((struct sockaddr*)&localAddr, testPort);
                port = testPort;
                break;
            }
        }
        if (port == 0) {
            Ulk();
            g_err = WSAEADDRINUSE;
            return SOCKET_ERROR;
        }
    }
    
    BOOL reuseAddr = AtomicLoad32(&sock->opt_reuseaddr);
    
    for (int i = 0; i < MAX_SHARED_SOCKETS; i++) {
        VSOCK* other = &g_pState->sockets[i];
        if (!IsSocketInUse(other) || other == sock) continue;
        if (!AtomicLoad32(&other->is_bound)) continue;
        if (other->local_addr.ss_family != family) continue;
        if (GetPort((struct sockaddr*)&other->local_addr) == port) {
            BOOL otherReuse = AtomicLoad32(&other->opt_reuseaddr);
            if (!reuseAddr || !otherReuse) {
                Ulk();
                g_err = WSAEADDRINUSE;
                return SOCKET_ERROR;
            }
        }
    }
    
    memcpy(&sock->local_addr, &localAddr, sizeof(localAddr));
    sock->local_addr_len = minLen;
    AtomicStore32(&sock->is_bound, TRUE);
    
    Ulk();
    LogMessage(" -> bound to port %u", port);
    return 0;
}

// =============================================================================
// LISTEN
// =============================================================================

int WSAAPI ex_listen(SOCKET s, int backlog) {
    (void)backlog;
    
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    LogMessage("listen(" PTR_FORMAT ", backlog=%d)", (UPTR)s, backlog);
    
    SAFE_LOCK();
    
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    if (!AtomicLoad32(&sock->is_bound)) {
        Ulk();
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    if (sock->type != SOCK_STREAM) {
        Ulk();
        g_err = WSAEOPNOTSUPP;
        return SOCKET_ERROR;
    }
    
    AtomicStore32(&sock->is_listening, TRUE);
    Ulk();
    
    LogMessage(" -> listening");
    return 0;
}

// =============================================================================
// CONNECT
// =============================================================================

int WSAAPI ex_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    if (!name || namelen < (int)sizeof(struct sockaddr)) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    int family = name->sa_family;
    u_short port = GetPort(name);
    
    LogMessage("connect(" PTR_FORMAT ", port=%u)", (UPTR)s, port);
    
    SAFE_LOCK();
    
    VSOCK* client = FindSock(s);
    if (!client) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    if (client->type == SOCK_DGRAM) {
        AtomicStore32(&client->is_connected, TRUE);
        Ulk();
        LogMessage(" -> UDP connected");
        return 0;
    }
    
    if (AtomicLoad32(&client->is_connected)) {
        Ulk();
        g_err = WSAEISCONN;
        return SOCKET_ERROR;
    }
    
    AutoBind(client);
    
    int listenerIdx = -1;
    for (int i = 0; i < MAX_SHARED_SOCKETS; i++) {
        VSOCK* listener = &g_pState->sockets[i];
        if (!IsSocketInUse(listener)) continue;
        if (!AtomicLoad32(&listener->is_listening)) continue;
        if (listener->local_addr.ss_family != family) continue;
        if (GetPort((struct sockaddr*)&listener->local_addr) == port) {
            listenerIdx = i;
            break;
        }
    }
    
    if (listenerIdx < 0) {
        Ulk();
        g_err = WSAECONNREFUSED;
        return SOCKET_ERROR;
    }
    
    VSOCK* listener = &g_pState->sockets[listenerIdx];
    
    LONG acceptCount = AtomicLoad32(&listener->accept_count);
    if (acceptCount >= MAX_PENDING_CONN) {
        Ulk();
        g_err = WSAECONNREFUSED;
        return SOCKET_ERROR;
    }
    
    int serverIdx = FindSlot();
    if (serverIdx < 0) {
        Ulk();
        g_err = WSAENOBUFS;
        return SOCKET_ERROR;
    }
    
    int clientIdx = SockIdx(client);
    if (clientIdx < 0) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    VSOCK* server = &g_pState->sockets[serverIdx];
    memset(server, 0, sizeof(VSOCK));
    
    server->id = GenId();
    server->owner_pid = listener->owner_pid;
    server->create_time = GetTickCount();
    server->family = family;
    server->type = SOCK_STREAM;
    server->protocol = IPPROTO_TCP;
    server->local_addr = listener->local_addr;
    server->local_addr_len = listener->local_addr_len;
    
    AtomicStore32(&server->is_bound, TRUE);
    AtomicStore32(&server->is_connected, TRUE);
    AtomicStore32(&server->peer_index, clientIdx);
    AtomicStore32(&server->opt_rcvbuf, 65536);
    AtomicStore32(&server->opt_sndbuf, 65536);
    AtomicStore32(&server->in_use, TRUE);
    
    AtomicStore32(&client->is_connected, TRUE);
    AtomicStore32(&client->peer_index, serverIdx);
    
    listener->accept_queue[acceptCount] = serverIdx;
    AtomicStore32(&listener->accept_count, acceptCount + 1);
    
    InterlockedIncrement(&g_pState->total_connections);
    InterlockedIncrement(&g_pState->socket_count);
    
    u_short listenerPort = GetPort((struct sockaddr*)&listener->local_addr);
    int listenerFamily = listener->local_addr.ss_family;
    
    Ulk();
    
    char evName[64];
    if (EvNameAccept(evName, sizeof(evName), listenerFamily, listenerPort)) {
        SignalEvent(evName);
    }
    
    LogMessage(" -> connected " PTR_FORMAT " <=> " PTR_FORMAT, 
        (UPTR)client->id, (UPTR)server->id);
    return 0;
}

// =============================================================================
// ACCEPT
// =============================================================================

SOCKET WSAAPI ex_accept(SOCKET s, struct sockaddr* addr, int* addrlen) {
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return INVALID_SOCKET;
    }
    
    LogMessage("accept(" PTR_FORMAT ")", (UPTR)s);
    
    SAFE_LOCK_SOCKET();
    
    VSOCK* listener = FindSock(s);
    if (!listener) {
        Ulk();
        g_err = WSAENOTSOCK;
        return INVALID_SOCKET;
    }
    
    if (!AtomicLoad32(&listener->is_listening)) {
        Ulk();
        g_err = WSAEINVAL;
        return INVALID_SOCKET;
    }
    
    u_short port = GetPort((struct sockaddr*)&listener->local_addr);
    int family = listener->local_addr.ss_family;
    
    Ulk();
    
    char evName[64];
    if (!EvNameAccept(evName, sizeof(evName), family, port)) {
        g_err = WSAENETDOWN;
        return INVALID_SOCKET;
    }
    
    HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, evName);
    if (!hEvent) {
        g_err = WSAENETDOWN;
        return INVALID_SOCKET;
    }
    
    DWORD startTime = GetTickCount();
    SOCKET result = INVALID_SOCKET;
    
    while (result == INVALID_SOCKET) {
        LOCK_RESULT lr = Lk();
        if (lr == LOCK_FAILED || lr == LOCK_TIMEOUT) {
            CloseHandle(hEvent);
            g_err = WSAENETDOWN;
            return INVALID_SOCKET;
        }
        
        listener = FindSock(s);
        if (!listener) {
            Ulk();
            CloseHandle(hEvent);
            g_err = WSAENOTSOCK;
            return INVALID_SOCKET;
        }
        
        LONG acceptCount = AtomicLoad32(&listener->accept_count);
        
        if (acceptCount > 0) {
            int serverIdx = listener->accept_queue[0];
            
            for (int i = 0; i < acceptCount - 1; i++) {
                listener->accept_queue[i] = listener->accept_queue[i + 1];
            }
            AtomicStore32(&listener->accept_count, acceptCount - 1);
            
            if (IsValidSocketIndex(serverIdx)) {
                VSOCK* server = GetSockByIndex(serverIdx);
                
                if (server) {
                    result = server->id;
                    
                    if (addr && addrlen && *addrlen > 0) {
                        int peerIdx = AtomicLoad32(&server->peer_index);
                        if (IsValidSocketIndex(peerIdx)) {
                            VSOCK* client = GetSockByIndex(peerIdx);
                            if (client) {
                                int copyLen = min(*addrlen, client->local_addr_len);
                                memcpy(addr, &client->local_addr, copyLen);
                                *addrlen = client->local_addr_len;
                            }
                        }
                    }
                }
            }
            
            Ulk();
            
            if (result != INVALID_SOCKET) {
                CloseHandle(hEvent);
                LogMessage(" -> accepted " PTR_FORMAT, (UPTR)result);
                return result;
            }
            continue;
        }
        
        BOOL nonBlocking = AtomicLoad32(&listener->is_nonblocking);
        Ulk();
        
        if (nonBlocking) {
            CloseHandle(hEvent);
            g_err = WSAEWOULDBLOCK;
            return INVALID_SOCKET;
        }
        
        DWORD elapsed = GetTickCount() - startTime;
        if (elapsed >= BLOCKING_TIMEOUT_MS) {
            CloseHandle(hEvent);
            g_err = WSAETIMEDOUT;
            return INVALID_SOCKET;
        }
        
        DWORD waitTime = min(1000UL, BLOCKING_TIMEOUT_MS - elapsed);
        WaitForSingleObject(hEvent, waitTime);
    }
    
    CloseHandle(hEvent);
    return result;
}

SOCKET WSAAPI ex_WSAAccept(SOCKET s, struct sockaddr* addr, LPINT addrlen,
    LPCONDITIONPROC lpfnCondition, DWORD_PTR dwCallbackData) {
    (void)lpfnCondition; (void)dwCallbackData;
    return ex_accept(s, addr, addrlen);
}

// =============================================================================
// SEND (TCP)
// =============================================================================

int WSAAPI ex_send(SOCKET s, const char* buf, int len, int flags) {
    (void)flags;
    
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    if (len < 0) {
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    if (len == 0) return 0;
    
    if (!buf) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    HANDLE hWaitEvent = NULL;
    DWORD startTime = GetTickCount();
    int result = SOCKET_ERROR;
    char evName[64];
    
    while (TRUE) {
        LOCK_RESULT lr = Lk();
        if (lr == LOCK_FAILED || lr == LOCK_TIMEOUT) {
            g_err = WSAENETDOWN;
            goto cleanup;
        }
        
        VSOCK* sender = FindSock(s);
        if (!sender) {
            Ulk();
            g_err = WSAENOTSOCK;
            goto cleanup;
        }
        
        if (sender->type != SOCK_STREAM) {
            Ulk();
            g_err = WSAEOPNOTSUPP;
            goto cleanup;
        }
        
        if (AtomicLoad32(&sender->shutdown_flags) & SD_SEND) {
            Ulk();
            g_err = WSAESHUTDOWN;
            goto cleanup;
        }
        
        if (!AtomicLoad32(&sender->is_connected)) {
            Ulk();
            g_err = WSAENOTCONN;
            goto cleanup;
        }
        
        int peerIdx = AtomicLoad32(&sender->peer_index);
        if (!IsValidSocketIndex(peerIdx)) {
            Ulk();
            g_err = WSAENOTCONN;
            goto cleanup;
        }
        
        VSOCK* receiver = &g_pState->sockets[peerIdx];
        if (!IsSocketInUse(receiver)) {
            Ulk();
            g_err = WSAECONNRESET;
            goto cleanup;
        }
        
        size_t freeSpace = BufFree(receiver);
        int toWrite = (int)min((size_t)len, freeSpace);
        
        if (toWrite > 0) {
            BUF_RESULT br = BufWrite(receiver, buf, toWrite);
            if (br != BUF_OK) {
                Ulk();
                g_err = WSAENOBUFS;
                goto cleanup;
            }
            
            UpdateSendBehavior(sender, toWrite);
            InterlockedAdd(&g_pState->total_bytes_transferred, toWrite);
            
            SOCKET receiverId = receiver->id;
            Ulk();
            
            DumpDataToFile("SEND", s, buf, toWrite);
            
            if (EvName(evName, sizeof(evName), "RD", receiverId)) {
                SignalEvent(evName);
            }
            
            result = toWrite;
            LogMessage("send(" PTR_FORMAT ", len=%d) -> wrote %d", (UPTR)s, len, toWrite);
            goto cleanup;
        }
        
        BOOL nonBlocking = AtomicLoad32(&sender->is_nonblocking);
        SOCKET senderId = sender->id;
        Ulk();
        
        if (nonBlocking) {
            g_err = WSAEWOULDBLOCK;
            goto cleanup;
        }
        
        DWORD elapsed = GetTickCount() - startTime;
        if (elapsed >= BLOCKING_TIMEOUT_MS) {
            g_err = WSAETIMEDOUT;
            goto cleanup;
        }
        
        if (!hWaitEvent) {
            if (EvName(evName, sizeof(evName), "WR", senderId)) {
                hWaitEvent = CreateEventA(NULL, FALSE, FALSE, evName);
                if (!hWaitEvent) {
                    g_err = WSAENETDOWN;
                    goto cleanup;
                }
            } else {
                g_err = WSAENETDOWN;
                goto cleanup;
            }
        }
        
        DWORD waitTime = min(1000UL, BLOCKING_TIMEOUT_MS - elapsed);
        WaitForSingleObject(hWaitEvent, waitTime);
    }
    
cleanup:
    if (hWaitEvent) {
        CloseHandle(hWaitEvent);
    }
    return result;
}

// =============================================================================
// RECV (TCP)
// =============================================================================

int WSAAPI ex_recv(SOCKET s, char* buf, int len, int flags) {
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    if (len < 0) {
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    if (len == 0) return 0;
    
    if (!buf) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    char evName[64];
    if (!EvName(evName, sizeof(evName), "RD", s)) {
        g_err = WSAENETDOWN;
        return SOCKET_ERROR;
    }
    
    HANDLE hWaitEvent = CreateEventA(NULL, FALSE, FALSE, evName);
    if (!hWaitEvent) {
        g_err = WSAENETDOWN;
        return SOCKET_ERROR;
    }
    
    DWORD startTime = GetTickCount();
    int result = SOCKET_ERROR;
    
    while (TRUE) {
        LOCK_RESULT lr = Lk();
        if (lr == LOCK_FAILED || lr == LOCK_TIMEOUT) {
            g_err = WSAENETDOWN;
            goto cleanup;
        }
        
        VSOCK* sock = FindSock(s);
        if (!sock) {
            Ulk();
            g_err = WSAENOTSOCK;
            goto cleanup;
        }
        
        if (sock->type != SOCK_STREAM) {
            Ulk();
            g_err = WSAEOPNOTSUPP;
            goto cleanup;
        }
        
        if (AtomicLoad32(&sock->shutdown_flags) & SD_RECEIVE) {
            Ulk();
            g_err = WSAESHUTDOWN;
            goto cleanup;
        }
        
        size_t available = BufUsed(sock);
        
        if (available > 0) {
            int toRead = (int)min((size_t)len, available);
            BOOL consume = !(flags & MSG_PEEK);
            
            BUF_RESULT br = BufRead(sock, buf, toRead, consume);
            if (br != BUF_OK) {
                Ulk();
                g_err = WSAENETDOWN;
                goto cleanup;
            }
            
            if (consume) {
                UpdateRecvBehavior(sock, toRead);
            }
            
            int peerIdx = AtomicLoad32(&sock->peer_index);
            SOCKET peerId = INVALID_SOCKET;
            
            if (consume && IsValidSocketIndex(peerIdx)) {
                VSOCK* peer = GetSockByIndex(peerIdx);
                if (peer) {
                    peerId = peer->id;
                }
            }
            
            Ulk();
            
            if (consume) {
                DumpDataToFile("RECV", s, buf, toRead);
            }
            
            if (peerId != INVALID_SOCKET) {
                char peerEvName[64];
                if (EvName(peerEvName, sizeof(peerEvName), "WR", peerId)) {
                    SignalEvent(peerEvName);
                }
            }
            
            result = toRead;
            LogMessage("recv(" PTR_FORMAT ", len=%d) -> read %d", (UPTR)s, len, toRead);
            goto cleanup;
        }
        
        // Check for connection closed
        int peerIdx = AtomicLoad32(&sock->peer_index);
        BOOL isConnected = AtomicLoad32(&sock->is_connected);
        
        if (IsValidSocketIndex(peerIdx)) {
            VSOCK* peer = GetSockByIndex(peerIdx);
            if (!peer || (AtomicLoad32(&peer->shutdown_flags) & SD_SEND)) {
                Ulk();
                result = 0;  // Graceful close
                LogMessage("recv(" PTR_FORMAT ") -> peer closed", (UPTR)s);
                goto cleanup;
            }
        } else if (isConnected) {
            Ulk();
            result = 0;
            goto cleanup;
        } else {
            Ulk();
            g_err = WSAENOTCONN;
            goto cleanup;
        }
        
        BOOL nonBlocking = AtomicLoad32(&sock->is_nonblocking);
        Ulk();
        
        if (nonBlocking) {
            g_err = WSAEWOULDBLOCK;
            goto cleanup;
        }
        
        DWORD elapsed = GetTickCount() - startTime;
        if (elapsed >= BLOCKING_TIMEOUT_MS) {
            g_err = WSAETIMEDOUT;
            goto cleanup;
        }
        
        DWORD waitTime = min(1000UL, BLOCKING_TIMEOUT_MS - elapsed);
        WaitForSingleObject(hWaitEvent, waitTime);
    }
    
cleanup:
    CloseHandle(hWaitEvent);
    return result;
}

// =============================================================================
// SENDTO (UDP)
// =============================================================================

int WSAAPI ex_sendto(SOCKET s, const char* buf, int len, int flags,
    const struct sockaddr* to, int tolen) {
    (void)flags;
    
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    if (len < 0) {
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    if (len == 0) return 0;
    
    if (!buf || !to) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    if (tolen < (int)sizeof(struct sockaddr)) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    if ((size_t)len > BUFFER_PER_SOCKET - sizeof(UDP_HDR) - 1024) {
        g_err = WSAEMSGSIZE;
        return SOCKET_ERROR;
    }
    
    u_short destPort = GetPort(to);
    int family = to->sa_family;
    
    LogMessage("sendto(" PTR_FORMAT ", len=%d, port=%u)", (UPTR)s, len, destPort);
    
    SAFE_LOCK();
    
    VSOCK* sender = FindSock(s);
    if (!sender) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    if (sender->type != SOCK_DGRAM) {
        Ulk();
        g_err = WSAEOPNOTSUPP;
        return SOCKET_ERROR;
    }
    
    AutoBind(sender);
    
    // Find receiver
    int receiverIdx = -1;
    for (int i = 0; i < MAX_SHARED_SOCKETS; i++) {
        VSOCK* r = &g_pState->sockets[i];
        if (!IsSocketInUse(r)) continue;
        if (!AtomicLoad32(&r->is_bound)) continue;
        if (r->type != SOCK_DGRAM) continue;
        if (r->local_addr.ss_family != family) continue;
        if (GetPort((struct sockaddr*)&r->local_addr) == destPort) {
            receiverIdx = i;
            break;
        }
    }
    
    if (receiverIdx < 0) {
        Ulk();
        LogMessage(" -> no receiver on port %u (data discarded)", destPort);
        return len;  // UDP: pretend success
    }
    
    VSOCK* receiver = &g_pState->sockets[receiverIdx];
    
    // Prepare UDP header with checksum
    UDP_HDR hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.data_len = len;
    hdr.from_len = sender->local_addr_len;
    memcpy(&hdr.from_addr, &sender->local_addr, sender->local_addr_len);
    hdr.checksum = CalcUdpChecksum(&hdr, buf, len);
    
    size_t packetSize = sizeof(UDP_HDR) + len;
    
    if (BufFree(receiver) < packetSize) {
        Ulk();
        LogMessage(" -> receiver buffer full");
        g_err = WSAEWOULDBLOCK;
        return SOCKET_ERROR;
    }
    
    BUF_RESULT br = BufWrite(receiver, &hdr, sizeof(hdr));
    if (br != BUF_OK) {
        Ulk();
        g_err = WSAENOBUFS;
        return SOCKET_ERROR;
    }
    
    br = BufWrite(receiver, buf, len);
    if (br != BUF_OK) {
        Ulk();
        g_err = WSAENOBUFS;
        return SOCKET_ERROR;
    }
    
    UpdateSendBehavior(sender, len);
    InterlockedAdd(&g_pState->total_bytes_transferred, len);
    
    SOCKET receiverId = receiver->id;
    Ulk();
    
    DumpDataToFile("SENDTO", s, buf, len);
    
    char evName[64];
    if (EvName(evName, sizeof(evName), "RD", receiverId)) {
        SignalEvent(evName);
    }
    
    LogMessage(" -> sent %d bytes to port %u", len, destPort);
    return len;
}

// =============================================================================
// RECVFROM (UDP)
// =============================================================================

int WSAAPI ex_recvfrom(SOCKET s, char* buf, int len, int flags,
    struct sockaddr* from, int* fromlen) {
    
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    if (len < 0) {
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    if (len == 0) return 0;
    
    if (!buf) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    LogMessage("recvfrom(" PTR_FORMAT ", len=%d)", (UPTR)s, len);
    
    char evName[64];
    if (!EvName(evName, sizeof(evName), "RD", s)) {
        g_err = WSAENETDOWN;
        return SOCKET_ERROR;
    }
    
    HANDLE hWaitEvent = CreateEventA(NULL, FALSE, FALSE, evName);
    if (!hWaitEvent) {
        g_err = WSAENETDOWN;
        return SOCKET_ERROR;
    }
    
    DWORD startTime = GetTickCount();
    int result = SOCKET_ERROR;
    
    while (TRUE) {
        LOCK_RESULT lr = Lk();
        if (lr == LOCK_FAILED || lr == LOCK_TIMEOUT) {
            g_err = WSAENETDOWN;
            goto cleanup;
        }
        
        VSOCK* sock = FindSock(s);
        if (!sock) {
            Ulk();
            g_err = WSAENOTSOCK;
            goto cleanup;
        }
        
        if (sock->type != SOCK_DGRAM) {
            Ulk();
            g_err = WSAEOPNOTSUPP;
            goto cleanup;
        }
        
        size_t available = BufUsed(sock);
        
        if (available >= sizeof(UDP_HDR)) {
            UDP_HDR hdr;
            
            BUF_RESULT br = BufRead(sock, &hdr, sizeof(hdr), FALSE);
            if (br != BUF_OK) {
                Ulk();
                g_err = WSAENETDOWN;
                goto cleanup;
            }
            
            // Validate header
            if (hdr.data_len < 0 || 
                hdr.data_len > (int)(BUFFER_PER_SOCKET - sizeof(UDP_HDR)) ||
                hdr.from_len < 0 || 
                hdr.from_len > (int)sizeof(struct sockaddr_storage)) {
                
                LogMessage(" -> corrupted UDP header, skipping");
                size_t head = AtomicLoadSize(&sock->buf_head);
                AtomicStoreSize(&sock->buf_head, (head + sizeof(UDP_HDR)) % BufCap());
                Ulk();
                continue;
            }
            
            size_t packetSize = sizeof(UDP_HDR) + hdr.data_len;
            
            if (available >= packetSize) {
                // Consume header
                size_t head = AtomicLoadSize(&sock->buf_head);
                AtomicStoreSize(&sock->buf_head, (head + sizeof(UDP_HDR)) % BufCap());
                
                int toRead = min(len, hdr.data_len);
                
                // Read data
                char* tempBuf = NULL;
                BOOL needTempBuf = (hdr.data_len > len);
                
                if (needTempBuf) {
                    tempBuf = (char*)SAFE_ALLOC(hdr.data_len, "recvfrom_temp");
                    if (!tempBuf) {
                        Ulk();
                        g_err = WSAENOBUFS;
                        goto cleanup;
                    }
                    
                    br = BufRead(sock, tempBuf, hdr.data_len, TRUE);
                    if (br != BUF_OK) {
                        SAFE_FREE(tempBuf);
                        Ulk();
                        g_err = WSAENETDOWN;
                        goto cleanup;
                    }
                    
                    // Validate checksum
                    DWORD expectedChecksum = CalcUdpChecksum(&hdr, tempBuf, hdr.data_len);
                    if (hdr.checksum != expectedChecksum) {
                        LogMessage(" -> UDP checksum mismatch, discarding");
                        SAFE_FREE(tempBuf);
                        Ulk();
                        continue;
                    }
                    
                    memcpy(buf, tempBuf, toRead);
                    SAFE_FREE(tempBuf);
                } else {
                    br = BufRead(sock, buf, toRead, TRUE);
                    if (br != BUF_OK) {
                        Ulk();
                        g_err = WSAENETDOWN;
                        goto cleanup;
                    }
                    
                    // Skip remaining data if buffer too small
                    if (hdr.data_len > toRead) {
                        head = AtomicLoadSize(&sock->buf_head);
                        AtomicStoreSize(&sock->buf_head, 
                            (head + (hdr.data_len - toRead)) % BufCap());
                    }
                }
                
                // Return sender address
                if (from && fromlen && *fromlen > 0) {
                    int copyLen = min(*fromlen, hdr.from_len);
                    memcpy(from, &hdr.from_addr, copyLen);
                    *fromlen = hdr.from_len;
                }
                
                if (!(flags & MSG_PEEK)) {
                    UpdateRecvBehavior(sock, toRead);
                }
                
                Ulk();
                
                if (!(flags & MSG_PEEK)) {
                    DumpDataToFile("RECVFROM", s, buf, toRead);
                }
                
                result = toRead;
                LogMessage(" -> received %d bytes", toRead);
                goto cleanup;
            }
        }
        
        BOOL nonBlocking = AtomicLoad32(&sock->is_nonblocking);
        Ulk();
        
        if (nonBlocking) {
            g_err = WSAEWOULDBLOCK;
            goto cleanup;
        }
        
        DWORD elapsed = GetTickCount() - startTime;
        if (elapsed >= BLOCKING_TIMEOUT_MS) {
            g_err = WSAETIMEDOUT;
            goto cleanup;
        }
        
        DWORD waitTime = min(1000UL, BLOCKING_TIMEOUT_MS - elapsed);
        WaitForSingleObject(hWaitEvent, waitTime);
    }
    
cleanup:
    CloseHandle(hWaitEvent);
    return result;
}

// =============================================================================
// WSASEND / WSARECV
// =============================================================================

int WSAAPI ex_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    
    (void)lpOverlapped; (void)lpCompletionRoutine;
    
    LogMessage("WSASend(" PTR_FORMAT ", buffers=%lu)", (UPTR)s, dwBufferCount);
    
    if (!lpBuffers || dwBufferCount == 0) {
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    if (lpNumberOfBytesSent) {
        *lpNumberOfBytesSent = 0;
    }
    
    DWORD totalSent = 0;
    
    for (DWORD i = 0; i < dwBufferCount; i++) {
        if (!lpBuffers[i].buf || lpBuffers[i].len == 0) {
            continue;
        }
        
        int sent = ex_send(s, lpBuffers[i].buf, lpBuffers[i].len, dwFlags);
        
        if (sent == SOCKET_ERROR) {
            if (totalSent == 0) {
                return SOCKET_ERROR;
            }
            break;
        }
        
        totalSent += sent;
        
        if ((DWORD)sent < lpBuffers[i].len) {
            break;
        }
    }
    
    if (lpNumberOfBytesSent) {
        *lpNumberOfBytesSent = totalSent;
    }
    
    return 0;
}

int WSAAPI ex_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    
    (void)lpOverlapped; (void)lpCompletionRoutine;
    
    LogMessage("WSARecv(" PTR_FORMAT ", buffers=%lu)", (UPTR)s, dwBufferCount);
    
    if (!lpBuffers || dwBufferCount == 0) {
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    if (lpNumberOfBytesRecvd) {
        *lpNumberOfBytesRecvd = 0;
    }
    
    int flags = lpFlags ? (int)*lpFlags : 0;
    DWORD totalRecvd = 0;
    
    for (DWORD i = 0; i < dwBufferCount; i++) {
        if (!lpBuffers[i].buf || lpBuffers[i].len == 0) {
            continue;
        }
        
        int recvd = ex_recv(s, lpBuffers[i].buf, lpBuffers[i].len, flags);
        
        if (recvd == SOCKET_ERROR) {
            if (totalRecvd == 0) {
                return SOCKET_ERROR;
            }
            break;
        }
        
        if (recvd == 0) {
            break;
        }
        
        totalRecvd += recvd;
        
        if ((DWORD)recvd < lpBuffers[i].len) {
            break;
        }
    }
    
    if (lpNumberOfBytesRecvd) {
        *lpNumberOfBytesRecvd = totalRecvd;
    }
    
    return 0;
}

int WSAAPI ex_WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* lpTo,
    int iTolen, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    
    (void)lpOverlapped; (void)lpCompletionRoutine;
    
    LogMessage("WSASendTo(" PTR_FORMAT ", buffers=%lu)", (UPTR)s, dwBufferCount);
    
    if (!lpBuffers || dwBufferCount == 0) {
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    if (lpNumberOfBytesSent) {
        *lpNumberOfBytesSent = 0;
    }
    
    // Calculate total length
    size_t totalLen = 0;
    for (DWORD i = 0; i < dwBufferCount; i++) {
        if (lpBuffers[i].buf && lpBuffers[i].len > 0) {
            totalLen += lpBuffers[i].len;
        }
    }
    
    if (totalLen == 0) {
        return 0;
    }
    
    if (totalLen > BUFFER_PER_SOCKET / 2) {
        g_err = WSAEMSGSIZE;
        return SOCKET_ERROR;
    }
    
    // Gather buffers
    char* tempBuf = (char*)SAFE_ALLOC(totalLen, "WSASendTo");
    if (!tempBuf) {
        g_err = WSAENOBUFS;
        return SOCKET_ERROR;
    }
    
    size_t offset = 0;
    for (DWORD i = 0; i < dwBufferCount; i++) {
        if (lpBuffers[i].buf && lpBuffers[i].len > 0) {
            memcpy(tempBuf + offset, lpBuffers[i].buf, lpBuffers[i].len);
            offset += lpBuffers[i].len;
        }
    }
    
    int sent = ex_sendto(s, tempBuf, (int)totalLen, dwFlags, lpTo, iTolen);
    
    SAFE_FREE(tempBuf);
    
    if (sent == SOCKET_ERROR) {
        return SOCKET_ERROR;
    }
    
    if (lpNumberOfBytesSent) {
        *lpNumberOfBytesSent = sent;
    }
    
    return 0;
}

int WSAAPI ex_WSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom,
    LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    
    (void)lpOverlapped; (void)lpCompletionRoutine;
    
    LogMessage("WSARecvFrom(" PTR_FORMAT ", buffers=%lu)", (UPTR)s, dwBufferCount);
    
    if (!lpBuffers || dwBufferCount == 0) {
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    if (lpNumberOfBytesRecvd) {
        *lpNumberOfBytesRecvd = 0;
    }
    
    // Use first buffer
    if (!lpBuffers[0].buf || lpBuffers[0].len == 0) {
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    int flags = lpFlags ? (int)*lpFlags : 0;
    
    int recvd = ex_recvfrom(s, lpBuffers[0].buf, lpBuffers[0].len, 
        flags, lpFrom, lpFromlen);
    
    if (recvd == SOCKET_ERROR) {
        return SOCKET_ERROR;
    }
    
    if (lpNumberOfBytesRecvd) {
        *lpNumberOfBytesRecvd = recvd;
    }
    
    return 0;
}

// =============================================================================
// SELECT
// =============================================================================

int WSAAPI ex_select(int nfds, fd_set* readfds, fd_set* writefds, 
    fd_set* exceptfds, const struct timeval* timeout) {
    (void)nfds;
    
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    DWORD timeoutMs = INFINITE;
    if (timeout) {
        if (timeout->tv_sec > 100000) {
            timeoutMs = 100000000;
        } else {
            timeoutMs = (DWORD)(timeout->tv_sec * 1000 + timeout->tv_usec / 1000);
        }
    }
    
    LogMessage("select(timeout=%lu ms)", timeoutMs == INFINITE ? 0xFFFFFFFF : timeoutMs);
    
    DWORD startTime = GetTickCount();
    
    do {
        int count = 0;
        fd_set readReady, writeReady, exceptReady;
        
        FD_ZERO(&readReady);
        FD_ZERO(&writeReady);
        FD_ZERO(&exceptReady);
        
        LOCK_RESULT lr = Lk();
        if (lr == LOCK_FAILED || lr == LOCK_TIMEOUT) {
            g_err = WSAENETDOWN;
            return SOCKET_ERROR;
        }
        
        // Check read sockets
        if (readfds) {
            for (u_int i = 0; i < readfds->fd_count; i++) {
                SOCKET fd = readfds->fd_array[i];
                VSOCK* s = FindSock(fd);
                if (!s) continue;
                
                BOOL readable = FALSE;
                
                if (BufUsed(s) > 0) {
                    readable = TRUE;
                }
                
                if (AtomicLoad32(&s->is_listening) && 
                    AtomicLoad32(&s->accept_count) > 0) {
                    readable = TRUE;
                }
                
                if (AtomicLoad32(&s->is_connected) && s->type == SOCK_STREAM) {
                    int peerIdx = AtomicLoad32(&s->peer_index);
                    if (IsValidSocketIndex(peerIdx)) {
                        VSOCK* peer = GetSockByIndex(peerIdx);
                        if (!peer || (AtomicLoad32(&peer->shutdown_flags) & SD_SEND)) {
                            readable = TRUE;
                        }
                    } else {
                        readable = TRUE;
                    }
                }
                
                if (readable) {
                    FD_SET(fd, &readReady);
                    count++;
                }
            }
        }
        
        // Check write sockets
        if (writefds) {
            for (u_int i = 0; i < writefds->fd_count; i++) {
                SOCKET fd = writefds->fd_array[i];
                VSOCK* s = FindSock(fd);
                if (!s) continue;
                
                BOOL writable = FALSE;
                
                if (s->type == SOCK_DGRAM) {
                    writable = TRUE;
                } else if (AtomicLoad32(&s->is_connected) && s->type == SOCK_STREAM) {
                    int peerIdx = AtomicLoad32(&s->peer_index);
                    if (IsValidSocketIndex(peerIdx)) {
                        VSOCK* peer = GetSockByIndex(peerIdx);
                        if (peer && BufFree(peer) > 0) {
                            writable = TRUE;
                        }
                    }
                }
                
                if (writable) {
                    FD_SET(fd, &writeReady);
                    count++;
                }
            }
        }
        
        if (exceptfds) {
            FD_ZERO(exceptfds);
        }
        
        Ulk();
        
        if (count > 0) {
            if (readfds) *readfds = readReady;
            if (writefds) *writefds = writeReady;
            LogMessage(" -> select returned %d", count);
            return count;
        }
        
        if (timeoutMs == 0) {
            break;
        }
        
        DWORD elapsed = GetTickCount() - startTime;
        if (elapsed >= timeoutMs) {
            break;
        }
        
        Sleep(min(10UL, timeoutMs - elapsed));
        
    } while (TRUE);
    
    if (readfds) FD_ZERO(readfds);
    if (writefds) FD_ZERO(writefds);
    if (exceptfds) FD_ZERO(exceptfds);
    
    LogMessage(" -> select timeout");
    return 0;
}

// =============================================================================
// POLL (WSAPoll)
// =============================================================================

int WSAAPI ex_WSAPoll(LPWSAPOLLFD fdArray, ULONG fds, INT timeout) {
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    if (!fdArray || fds == 0) {
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    LogMessage("WSAPoll(fds=%lu, timeout=%d)", fds, timeout);
    
    DWORD timeoutMs = (timeout < 0) ? INFINITE : (DWORD)timeout;
    DWORD startTime = GetTickCount();
    
    // Initialize revents
    for (ULONG i = 0; i < fds; i++) {
        fdArray[i].revents = 0;
    }
    
    do {
        int count = 0;
        
        LOCK_RESULT lr = Lk();
        if (lr == LOCK_FAILED || lr == LOCK_TIMEOUT) {
            g_err = WSAENETDOWN;
            return SOCKET_ERROR;
        }
        
        for (ULONG i = 0; i < fds; i++) {
            SOCKET fd = fdArray[i].fd;
            SHORT events = fdArray[i].events;
            
            if (fd == INVALID_SOCKET) {
                continue;
            }
            
            VSOCK* s = FindSock(fd);
            if (!s) {
                fdArray[i].revents = POLLNVAL;
                count++;
                continue;
            }
            
            SHORT revents = 0;
            
            // POLLIN
            if (events & POLLIN) {
                if (BufUsed(s) > 0) {
                    revents |= POLLIN;
                }
                if (AtomicLoad32(&s->is_listening) && 
                    AtomicLoad32(&s->accept_count) > 0) {
                    revents |= POLLIN;
                }
            }
            
            // POLLOUT
            if (events & POLLOUT) {
                if (s->type == SOCK_DGRAM) {
                    revents |= POLLOUT;
                } else if (AtomicLoad32(&s->is_connected)) {
                    int peerIdx = AtomicLoad32(&s->peer_index);
                    if (IsValidSocketIndex(peerIdx)) {
                        VSOCK* peer = GetSockByIndex(peerIdx);
                        if (peer && BufFree(peer) > 0) {
                            revents |= POLLOUT;
                        }
                    }
                }
            }
            
            // POLLHUP
            if (AtomicLoad32(&s->is_connected) && s->type == SOCK_STREAM) {
                int peerIdx = AtomicLoad32(&s->peer_index);
                if (IsValidSocketIndex(peerIdx)) {
                    VSOCK* peer = GetSockByIndex(peerIdx);
                    if (!peer || !IsSocketInUse(peer)) {
                        revents |= POLLHUP;
                    }
                }
            }
            
            fdArray[i].revents = revents;
            if (revents != 0) {
                count++;
            }
        }
        
        Ulk();
        
        if (count > 0) {
            return count;
        }
        
        if (timeoutMs == 0) {
            break;
        }
        
        DWORD elapsed = GetTickCount() - startTime;
        if (elapsed >= timeoutMs) {
            break;
        }
        
        Sleep(min(10UL, timeoutMs - elapsed));
        
    } while (TRUE);
    
    return 0;
}

// =============================================================================
// CLOSESOCKET
// =============================================================================

int WSAAPI ex_closesocket(SOCKET s) {
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    LogMessage("closesocket(" PTR_FORMAT ")", (UPTR)s);
    
    SAFE_LOCK();
    
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    // Notify peer
    int peerIdx = AtomicLoad32(&sock->peer_index);
    if (IsValidSocketIndex(peerIdx)) {
        VSOCK* peer = GetSockByIndex(peerIdx);
        if (peer) {
            AtomicStore32(&peer->is_connected, FALSE);
            AtomicStore32(&peer->peer_index, -1);
            
            char evName[64];
            if (EvName(evName, sizeof(evName), "RD", peer->id)) {
                SignalEvent(evName);
            }
            if (EvName(evName, sizeof(evName), "WR", peer->id)) {
                SignalEvent(evName);
            }
        }
    }
    
    memset(sock, 0, sizeof(VSOCK));
    AtomicStore32(&sock->peer_index, -1);
    
    InterlockedDecrement(&g_pState->socket_count);
    
    Ulk();
    
    LogMessage(" -> closed");
    return 0;
}

// =============================================================================
// SHUTDOWN
// =============================================================================

int WSAAPI ex_shutdown(SOCKET s, int how) {
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    LogMessage("shutdown(" PTR_FORMAT ", how=%d)", (UPTR)s, how);
    
    if (how != SD_RECEIVE && how != SD_SEND && how != SD_BOTH) {
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    SAFE_LOCK();
    
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    if (!AtomicLoad32(&sock->is_connected)) {
        Ulk();
        g_err = WSAENOTCONN;
        return SOCKET_ERROR;
    }
    
    LONG currentFlags = AtomicLoad32(&sock->shutdown_flags);
    
    if (how == SD_RECEIVE || how == SD_BOTH) {
        AtomicStore32(&sock->shutdown_flags, currentFlags | SD_RECEIVE);
    }
    
    if (how == SD_SEND || how == SD_BOTH) {
        AtomicStore32(&sock->shutdown_flags, currentFlags | SD_SEND);
        
        int peerIdx = AtomicLoad32(&sock->peer_index);
        if (IsValidSocketIndex(peerIdx)) {
            VSOCK* peer = GetSockByIndex(peerIdx);
            if (peer) {
                char evName[64];
                if (EvName(evName, sizeof(evName), "RD", peer->id)) {
                    SignalEvent(evName);
                }
            }
        }
    }
    
    Ulk();
    return 0;
}

// =============================================================================
// IOCTLSOCKET
// =============================================================================

int WSAAPI ex_ioctlsocket(SOCKET s, long cmd, u_long* argp) {
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    if (!argp) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    SAFE_LOCK();
    
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    switch (cmd) {
        case FIONBIO:
            AtomicStore32(&sock->is_nonblocking, (*argp != 0) ? TRUE : FALSE);
            LogMessage("ioctlsocket(" PTR_FORMAT ", FIONBIO=%lu)", (UPTR)s, *argp);
            break;
            
        case FIONREAD:
            *argp = (u_long)BufUsed(sock);
            LogMessage("ioctlsocket(" PTR_FORMAT ", FIONREAD) -> %lu", (UPTR)s, *argp);
            break;
            
        case SIOCATMARK:
            *argp = 1;
            break;
            
        default:
            Ulk();
            g_err = WSAEINVAL;
            return SOCKET_ERROR;
    }
    
    Ulk();
    return 0;
}

// =============================================================================
// GETSOCKNAME / GETPEERNAME
// =============================================================================

int WSAAPI ex_getsockname(SOCKET s, struct sockaddr* name, int* namelen) {
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    if (!name || !namelen || *namelen <= 0) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    SAFE_LOCK();
    
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    if (!AtomicLoad32(&sock->is_bound)) {
        memset(name, 0, *namelen);
        if (sock->family == AF_INET && *namelen >= (int)sizeof(struct sockaddr_in)) {
            ((struct sockaddr_in*)name)->sin_family = AF_INET;
            *namelen = sizeof(struct sockaddr_in);
        } else if (sock->family == AF_INET6 && *namelen >= (int)sizeof(struct sockaddr_in6)) {
            ((struct sockaddr_in6*)name)->sin6_family = AF_INET6;
            *namelen = sizeof(struct sockaddr_in6);
        }
        Ulk();
        return 0;
    }
    
    int copyLen = min(*namelen, sock->local_addr_len);
    memcpy(name, &sock->local_addr, copyLen);
    *namelen = sock->local_addr_len;
    
    Ulk();
    return 0;
}

int WSAAPI ex_getpeername(SOCKET s, struct sockaddr* name, int* namelen) {
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    if (!name || !namelen || *namelen <= 0) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    SAFE_LOCK();
    
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    if (!AtomicLoad32(&sock->is_connected)) {
        Ulk();
        g_err = WSAENOTCONN;
        return SOCKET_ERROR;
    }
    
    int peerIdx = AtomicLoad32(&sock->peer_index);
    if (!IsValidSocketIndex(peerIdx)) {
        Ulk();
        g_err = WSAENOTCONN;
        return SOCKET_ERROR;
    }
    
    VSOCK* peer = GetSockByIndex(peerIdx);
    if (!peer) {
        Ulk();
        g_err = WSAENOTCONN;
        return SOCKET_ERROR;
    }
    
    int copyLen = min(*namelen, peer->local_addr_len);
    memcpy(name, &peer->local_addr, copyLen);
    *namelen = peer->local_addr_len;
    
    Ulk();
    return 0;
}

// =============================================================================
// GETHOSTNAME / GETHOSTBYNAME / GETHOSTBYADDR
// =============================================================================

int WSAAPI ex_gethostname(char* name, int namelen) {
    LogMessage("gethostname()");
    
    if (!name || namelen <= 0) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    const char* hostname = "EXLOUD-EMU";
    size_t len = strlen(hostname);
    
    if ((size_t)namelen <= len) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    strcpy_s(name, namelen, hostname);
    return 0;
}

int WSAAPI ex_GetHostNameW(PWSTR name, int namelen) {
    LogMessage("GetHostNameW()");
    
    if (!name || namelen <= 0) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    char tempBuf[256];
    
    int ret = ex_gethostname(tempBuf, sizeof(tempBuf));
    if (ret != 0) {
        return ret;
    }
    
    int converted = MultiByteToWideChar(CP_ACP, 0, tempBuf, -1, name, namelen);
    if (converted == 0) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    return 0;
}

struct hostent* WSAAPI ex_gethostbyname(const char* name) {
    LogMessage("gethostbyname('%s')", name ? name : "(null)");
    
    if (!name) {
        g_err = WSAHOST_NOT_FOUND;
        return NULL;
    }
    
    // Initialize TLS arrays
    g_tls_hostent_aliases[0] = NULL;
    g_tls_hostent_aliases[1] = NULL;
    g_tls_hostent_addr_list[0] = NULL;
    g_tls_hostent_addr_list[1] = NULL;
    g_tls_hostent_addr_list[2] = NULL;
    
    BOOL isLocalhost = FALSE;
    if (_stricmp(name, "localhost") == 0 || 
        strcmp(name, "127.0.0.1") == 0 ||
        _stricmp(name, "EXLOUD-EMU") == 0 ||
        name[0] == '\0') {
        isLocalhost = TRUE;
    }
    
    if (!isLocalhost) {
        LogMessage(" -> BLOCKED (not localhost)");
        g_err = WSAHOST_NOT_FOUND;
        return NULL;
    }
    
    strcpy_s(g_tls_hostent_name, sizeof(g_tls_hostent_name), 
        (name[0] == '\0') ? "EXLOUD-EMU" : name);
    
    g_tls_hostent_addr.s_addr = ex_htonl(INADDR_LOOPBACK);
    g_tls_hostent_addr_list[0] = (char*)&g_tls_hostent_addr;
    g_tls_hostent_addr_list[1] = NULL;
    
    g_tls_hostent.h_name = g_tls_hostent_name;
    g_tls_hostent.h_aliases = g_tls_hostent_aliases;
    g_tls_hostent.h_addrtype = AF_INET;
    g_tls_hostent.h_length = sizeof(struct in_addr);
    g_tls_hostent.h_addr_list = g_tls_hostent_addr_list;
    
    return &g_tls_hostent;
}

struct hostent* WSAAPI ex_gethostbyaddr(const char* addr, int len, int type) {
    LogMessage("gethostbyaddr()");
    
    if (!addr) {
        g_err = WSAEFAULT;
        return NULL;
    }
    
    g_tls_hostent_aliases[0] = NULL;
    g_tls_hostent_addr_list[0] = NULL;
    g_tls_hostent_addr_list[1] = NULL;
    
    if (type == AF_INET && len == sizeof(struct in_addr)) {
        struct in_addr* inaddr = (struct in_addr*)addr;
        
        if (inaddr->s_addr == ex_htonl(INADDR_LOOPBACK)) {
            strcpy_s(g_tls_hostent_name, sizeof(g_tls_hostent_name), "localhost");
            g_tls_hostent_addr = *inaddr;
            g_tls_hostent_addr_list[0] = (char*)&g_tls_hostent_addr;
            g_tls_hostent_addr_list[1] = NULL;
            
            g_tls_hostent.h_name = g_tls_hostent_name;
            g_tls_hostent.h_aliases = g_tls_hostent_aliases;
            g_tls_hostent.h_addrtype = AF_INET;
            g_tls_hostent.h_length = sizeof(struct in_addr);
            g_tls_hostent.h_addr_list = g_tls_hostent_addr_list;
            
            return &g_tls_hostent;
        }
    }
    
    g_err = WSAHOST_NOT_FOUND;
    return NULL;
}

// =============================================================================
// GETPROTOBYNAME / GETPROTOBYNUMBER
// =============================================================================

struct protoent* WSAAPI ex_getprotobyname(const char* name) {
    LogMessage("getprotobyname('%s')", name ? name : "(null)");
    
    if (!name) {
        g_err = WSAEINVAL;
        return NULL;
    }
    
    g_tls_protoent_aliases[0] = NULL;
    g_tls_protoent_aliases[1] = NULL;
    
    int proto = 0;
    
    if (_stricmp(name, "tcp") == 0) {
        strcpy_s(g_tls_protoent_name, sizeof(g_tls_protoent_name), "tcp");
        proto = IPPROTO_TCP;
    } else if (_stricmp(name, "udp") == 0) {
        strcpy_s(g_tls_protoent_name, sizeof(g_tls_protoent_name), "udp");
        proto = IPPROTO_UDP;
    } else if (_stricmp(name, "icmp") == 0) {
        strcpy_s(g_tls_protoent_name, sizeof(g_tls_protoent_name), "icmp");
        proto = IPPROTO_ICMP;
    } else if (_stricmp(name, "ip") == 0) {
        strcpy_s(g_tls_protoent_name, sizeof(g_tls_protoent_name), "ip");
        proto = IPPROTO_IP;
    } else {
        return NULL;
    }
    
    g_tls_protoent.p_name = g_tls_protoent_name;
    g_tls_protoent.p_aliases = g_tls_protoent_aliases;
    g_tls_protoent.p_proto = proto;
    
    return &g_tls_protoent;
}

struct protoent* WSAAPI ex_getprotobynumber(int number) {
    LogMessage("getprotobynumber(%d)", number);
    
    g_tls_protoent_aliases[0] = NULL;
    g_tls_protoent_aliases[1] = NULL;
    
    switch (number) {
        case IPPROTO_TCP:
            strcpy_s(g_tls_protoent_name, sizeof(g_tls_protoent_name), "tcp");
            break;
        case IPPROTO_UDP:
            strcpy_s(g_tls_protoent_name, sizeof(g_tls_protoent_name), "udp");
            break;
        case IPPROTO_ICMP:
            strcpy_s(g_tls_protoent_name, sizeof(g_tls_protoent_name), "icmp");
            break;
        case IPPROTO_IP:
            strcpy_s(g_tls_protoent_name, sizeof(g_tls_protoent_name), "ip");
            break;
        default:
            return NULL;
    }
    
    g_tls_protoent.p_name = g_tls_protoent_name;
    g_tls_protoent.p_aliases = g_tls_protoent_aliases;
    g_tls_protoent.p_proto = number;
    
    return &g_tls_protoent;
}

// =============================================================================
// GETSERVBYNAME / GETSERVBYPORT
// =============================================================================

struct servent* WSAAPI ex_getservbyname(const char* name, const char* proto) {
    LogMessage("getservbyname('%s', '%s')", 
        name ? name : "(null)", proto ? proto : "(null)");
    
    if (!name) {
        return NULL;
    }
    
    g_tls_servent_aliases[0] = NULL;
    g_tls_servent_aliases[1] = NULL;
    
    u_short port = 0;
    
    if (_stricmp(name, "http") == 0) port = 80;
    else if (_stricmp(name, "https") == 0) port = 443;
    else if (_stricmp(name, "ftp") == 0) port = 21;
    else if (_stricmp(name, "ftp-data") == 0) port = 20;
    else if (_stricmp(name, "ssh") == 0) port = 22;
    else if (_stricmp(name, "telnet") == 0) port = 23;
    else if (_stricmp(name, "smtp") == 0) port = 25;
    else if (_stricmp(name, "dns") == 0 || _stricmp(name, "domain") == 0) port = 53;
    else if (_stricmp(name, "pop3") == 0) port = 110;
    else if (_stricmp(name, "imap") == 0) port = 143;
    else if (_stricmp(name, "snmp") == 0) port = 161;
    else if (_stricmp(name, "ldap") == 0) port = 389;
    else if (_stricmp(name, "smtps") == 0) port = 465;
    else if (_stricmp(name, "imaps") == 0) port = 993;
    else if (_stricmp(name, "pop3s") == 0) port = 995;
    else return NULL;
    
    strcpy_s(g_tls_servent_name, sizeof(g_tls_servent_name), name);
    strcpy_s(g_tls_servent_proto, sizeof(g_tls_servent_proto), proto ? proto : "tcp");
    
    g_tls_servent.s_name = g_tls_servent_name;
    g_tls_servent.s_aliases = g_tls_servent_aliases;
    g_tls_servent.s_port = ex_htons(port);
    g_tls_servent.s_proto = g_tls_servent_proto;
    
    return &g_tls_servent;
}

struct servent* WSAAPI ex_getservbyport(int port, const char* proto) {
    u_short hostPort = ex_ntohs((u_short)port);
    
    LogMessage("getservbyport(%u, '%s')", hostPort, proto ? proto : "(null)");
    
    g_tls_servent_aliases[0] = NULL;
    g_tls_servent_aliases[1] = NULL;
    
    const char* name = NULL;
    
    switch (hostPort) {
        case 20: name = "ftp-data"; break;
        case 21: name = "ftp"; break;
        case 22: name = "ssh"; break;
        case 23: name = "telnet"; break;
        case 25: name = "smtp"; break;
        case 53: name = "domain"; break;
        case 80: name = "http"; break;
        case 110: name = "pop3"; break;
        case 143: name = "imap"; break;
        case 161: name = "snmp"; break;
        case 389: name = "ldap"; break;
        case 443: name = "https"; break;
        case 465: name = "smtps"; break;
        case 993: name = "imaps"; break;
        case 995: name = "pop3s"; break;
        default: return NULL;
    }
    
    strcpy_s(g_tls_servent_name, sizeof(g_tls_servent_name), name);
    strcpy_s(g_tls_servent_proto, sizeof(g_tls_servent_proto), proto ? proto : "tcp");
    
    g_tls_servent.s_name = g_tls_servent_name;
    g_tls_servent.s_aliases = g_tls_servent_aliases;
    g_tls_servent.s_port = (short)port;
    g_tls_servent.s_proto = g_tls_servent_proto;
    
    return &g_tls_servent;
}

// =============================================================================
// GETADDRINFO / FREEADDRINFO (ANSI)
// =============================================================================

void WSAAPI ex_freeaddrinfo(struct addrinfo* ai) {
    while (ai) {
        struct addrinfo* next = ai->ai_next;
        if (ai->ai_canonname) {
            SAFE_FREE(ai->ai_canonname);
        }
        SAFE_FREE(ai);
        ai = next;
    }
}

int WSAAPI ex_getaddrinfo(const char* nodename, const char* servname,
    const struct addrinfo* hints, struct addrinfo** res) {
    
    LogMessage("getaddrinfo('%s', '%s')", 
        nodename ? nodename : "(null)", servname ? servname : "(null)");
    
    if (!res) {
        return EAI_FAIL;
    }
    
    *res = NULL;
    
    BOOL isLocalhost = FALSE;
    if (!nodename) {
        isLocalhost = TRUE;
    } else if (_stricmp(nodename, "localhost") == 0 ||
               strcmp(nodename, "127.0.0.1") == 0 ||
               strcmp(nodename, "::1") == 0 ||
               _stricmp(nodename, "EXLOUD-EMU") == 0 ||
               nodename[0] == '\0') {
        isLocalhost = TRUE;
    }
    
    if (!isLocalhost) {
        LogMessage(" -> BLOCKED (not localhost)");
        return EAI_NONAME;
    }
    
    u_short port = 0;
    if (servname && *servname) {
        char* endptr;
        long portNum = strtol(servname, &endptr, 10);
        if (*endptr == '\0' && portNum >= 0 && portNum <= 65535) {
            port = (u_short)portNum;
        } else {
            struct servent* se = ex_getservbyname(servname, NULL);
            if (se) {
                port = ex_ntohs(se->s_port);
            }
        }
    }
    
    int family = hints ? hints->ai_family : AF_UNSPEC;
    int socktype = hints ? hints->ai_socktype : 0;
    int protocol = hints ? hints->ai_protocol : 0;
    int flags = hints ? hints->ai_flags : 0;
    
    BOOL wantIPv4 = (family == AF_UNSPEC || family == AF_INET);
    BOOL wantIPv6 = (family == AF_UNSPEC || family == AF_INET6);
    
    struct addrinfo* head = NULL;
    struct addrinfo* tail = NULL;
    
    // Create IPv4 result
    if (wantIPv4) {
        size_t size = sizeof(struct addrinfo) + sizeof(struct sockaddr_in);
        struct addrinfo* ai = (struct addrinfo*)SAFE_ALLOC(size, "getaddrinfo_ipv4");
        if (!ai) {
            ex_freeaddrinfo(head);
            return EAI_MEMORY;
        }
        
        memset(ai, 0, size);
        
        struct sockaddr_in* sin = (struct sockaddr_in*)(ai + 1);
        sin->sin_family = AF_INET;
        sin->sin_port = ex_htons(port);
        
        if (flags & AI_PASSIVE) {
            sin->sin_addr.s_addr = ex_htonl(INADDR_ANY);
        } else {
            sin->sin_addr.s_addr = ex_htonl(INADDR_LOOPBACK);
        }
        
        ai->ai_flags = flags;
        ai->ai_family = AF_INET;
        ai->ai_socktype = socktype ? socktype : SOCK_STREAM;
        ai->ai_protocol = protocol ? protocol : 
            ((ai->ai_socktype == SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP);
        ai->ai_addrlen = sizeof(struct sockaddr_in);
        ai->ai_addr = (struct sockaddr*)sin;
        ai->ai_canonname = NULL;
        ai->ai_next = NULL;
        
        if (flags & AI_CANONNAME) {
            const char* srcName = nodename ? nodename : "localhost";
            size_t nameLen = strlen(srcName) + 1;
            ai->ai_canonname = (char*)SAFE_ALLOC(nameLen, "getaddrinfo_canonname");
            if (ai->ai_canonname) {
                strcpy_s(ai->ai_canonname, nameLen, srcName);
            }
        }
        
        if (!head) head = ai;
        else tail->ai_next = ai;
        tail = ai;
    }
    
    // Create IPv6 result
    if (wantIPv6) {
        size_t size = sizeof(struct addrinfo) + sizeof(struct sockaddr_in6);
        struct addrinfo* ai = (struct addrinfo*)SAFE_ALLOC(size, "getaddrinfo_ipv6");
        if (!ai) {
            ex_freeaddrinfo(head);
            return EAI_MEMORY;
        }
        
        memset(ai, 0, size);
        
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)(ai + 1);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = ex_htons(port);
        
        if (flags & AI_PASSIVE) {
            sin6->sin6_addr = in6addr_any;
        } else {
            sin6->sin6_addr = in6addr_loopback;
        }
        
        ai->ai_flags = flags;
        ai->ai_family = AF_INET6;
        ai->ai_socktype = socktype ? socktype : SOCK_STREAM;
        ai->ai_protocol = protocol ? protocol :
            ((ai->ai_socktype == SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP);
        ai->ai_addrlen = sizeof(struct sockaddr_in6);
        ai->ai_addr = (struct sockaddr*)sin6;
        ai->ai_canonname = NULL;
        ai->ai_next = NULL;
        
        if (!head) head = ai;
        else tail->ai_next = ai;
        tail = ai;
    }
    
    *res = head;
    return head ? 0 : EAI_FAIL;
}

// =============================================================================
// GETADDRINFO / FREEADDRINFO (UNICODE)
// =============================================================================

void WSAAPI ex_FreeAddrInfoW(PADDRINFOW ai) {
    while (ai) {
        PADDRINFOW next = ai->ai_next;
        if (ai->ai_canonname) {
            SAFE_FREE(ai->ai_canonname);
        }
        SAFE_FREE(ai);
        ai = next;
    }
}

int WSAAPI ex_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName,
    const ADDRINFOW* pHints, PADDRINFOW* ppResult) {
    
    if (!ppResult) {
        return EAI_FAIL;
    }
    
    *ppResult = NULL;
    
    char nodeNameA[256] = {0};
    char serviceNameA[64] = {0};
    
    if (pNodeName) {
        WideCharToMultiByte(CP_ACP, 0, pNodeName, -1, 
            nodeNameA, sizeof(nodeNameA), NULL, NULL);
    }
    
    if (pServiceName) {
        WideCharToMultiByte(CP_ACP, 0, pServiceName, -1, 
            serviceNameA, sizeof(serviceNameA), NULL, NULL);
    }
    
    LogMessage("GetAddrInfoW('%s', '%s')", 
        nodeNameA[0] ? nodeNameA : "(null)", 
        serviceNameA[0] ? serviceNameA : "(null)");
    
    BOOL isLocalhost = FALSE;
    if (!pNodeName) {
        isLocalhost = TRUE;
    } else if (_wcsicmp(pNodeName, L"localhost") == 0 ||
               wcscmp(pNodeName, L"127.0.0.1") == 0 ||
               wcscmp(pNodeName, L"::1") == 0 ||
               _wcsicmp(pNodeName, L"EXLOUD-EMU") == 0 ||
               pNodeName[0] == L'\0') {
        isLocalhost = TRUE;
    }
    
    if (!isLocalhost) {
        LogMessage(" -> BLOCKED (not localhost)");
        return EAI_NONAME;
    }
    
    u_short port = 0;
    if (pServiceName && *pServiceName) {
        wchar_t* endptr;
        long portNum = wcstol(pServiceName, &endptr, 10);
        if (*endptr == L'\0' && portNum >= 0 && portNum <= 65535) {
            port = (u_short)portNum;
        } else if (serviceNameA[0]) {
            struct servent* se = ex_getservbyname(serviceNameA, NULL);
            if (se) {
                port = ex_ntohs(se->s_port);
            }
        }
    }
    
    int family = pHints ? pHints->ai_family : AF_UNSPEC;
    int socktype = pHints ? pHints->ai_socktype : 0;
    int protocol = pHints ? pHints->ai_protocol : 0;
    int flags = pHints ? pHints->ai_flags : 0;
    
    BOOL wantIPv4 = (family == AF_UNSPEC || family == AF_INET);
    BOOL wantIPv6 = (family == AF_UNSPEC || family == AF_INET6);
    
    PADDRINFOW head = NULL;
    PADDRINFOW tail = NULL;
    
    // Create IPv4 result
    if (wantIPv4) {
        size_t size = sizeof(ADDRINFOW) + sizeof(struct sockaddr_in);
        PADDRINFOW ai = (PADDRINFOW)SAFE_ALLOC(size, "GetAddrInfoW_ipv4");
        if (!ai) {
            ex_FreeAddrInfoW(head);
            return EAI_MEMORY;
        }
        
        memset(ai, 0, size);
        
        struct sockaddr_in* sin = (struct sockaddr_in*)(ai + 1);
        sin->sin_family = AF_INET;
        sin->sin_port = ex_htons(port);
        
        if (flags & AI_PASSIVE) {
            sin->sin_addr.s_addr = ex_htonl(INADDR_ANY);
        } else {
            sin->sin_addr.s_addr = ex_htonl(INADDR_LOOPBACK);
        }
        
        ai->ai_flags = flags;
        ai->ai_family = AF_INET;
        ai->ai_socktype = socktype ? socktype : SOCK_STREAM;
        ai->ai_protocol = protocol ? protocol :
            ((ai->ai_socktype == SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP);
        ai->ai_addrlen = sizeof(struct sockaddr_in);
        ai->ai_addr = (struct sockaddr*)sin;
        ai->ai_canonname = NULL;
        ai->ai_next = NULL;
        
        if (flags & AI_CANONNAME) {
            const wchar_t* srcName = pNodeName ? pNodeName : L"localhost";
            size_t nameLen = wcslen(srcName) + 1;
            ai->ai_canonname = (PWSTR)SAFE_ALLOC(nameLen * sizeof(wchar_t), "GetAddrInfoW_canon4");
            if (ai->ai_canonname) {
                wcscpy_s(ai->ai_canonname, nameLen, srcName);
            }
        }
        
        if (!head) head = ai;
        else tail->ai_next = ai;
        tail = ai;
    }
    
    // Create IPv6 result
    if (wantIPv6) {
        size_t size = sizeof(ADDRINFOW) + sizeof(struct sockaddr_in6);
        PADDRINFOW ai = (PADDRINFOW)SAFE_ALLOC(size, "GetAddrInfoW_ipv6");
        if (!ai) {
            ex_FreeAddrInfoW(head);
            return EAI_MEMORY;
        }
        
        memset(ai, 0, size);
        
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)(ai + 1);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = ex_htons(port);
        
        if (flags & AI_PASSIVE) {
            sin6->sin6_addr = in6addr_any;
        } else {
            sin6->sin6_addr = in6addr_loopback;
        }
        
        ai->ai_flags = flags;
        ai->ai_family = AF_INET6;
        ai->ai_socktype = socktype ? socktype : SOCK_STREAM;
        ai->ai_protocol = protocol ? protocol :
            ((ai->ai_socktype == SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP);
        ai->ai_addrlen = sizeof(struct sockaddr_in6);
        ai->ai_addr = (struct sockaddr*)sin6;
        ai->ai_canonname = NULL;
        ai->ai_next = NULL;
        
        if ((flags & AI_CANONNAME) && !head) {
            const wchar_t* srcName = pNodeName ? pNodeName : L"localhost";
            size_t nameLen = wcslen(srcName) + 1;
            ai->ai_canonname = (PWSTR)SAFE_ALLOC(nameLen * sizeof(wchar_t), "GetAddrInfoW_canon6");
            if (ai->ai_canonname) {
                wcscpy_s(ai->ai_canonname, nameLen, srcName);
            }
        }
        
        if (!head) head = ai;
        else tail->ai_next = ai;
        tail = ai;
    }
    
    *ppResult = head;
    return head ? 0 : EAI_FAIL;
}

// =============================================================================
// GETADDRINFO EXTENDED (UNICODE)
// =============================================================================

void WSAAPI ex_FreeAddrInfoExW(PADDRINFOEXW pAddrInfoEx) {
    while (pAddrInfoEx) {
        PADDRINFOEXW next = pAddrInfoEx->ai_next;
        if (pAddrInfoEx->ai_canonname) {
            // Cast away const for deallocation
            SAFE_FREE((void*)pAddrInfoEx->ai_canonname);
        }
        SAFE_FREE(pAddrInfoEx);
        pAddrInfoEx = next;
    }
}

int WSAAPI ex_GetAddrInfoExW(PCWSTR pName, PCWSTR pServiceName, DWORD dwNameSpace,
    LPGUID lpNspId, const ADDRINFOEXW* hints, PADDRINFOEXW* ppResult,
    struct timeval* timeout, LPOVERLAPPED lpOverlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine, LPHANDLE lpHandle) {
    
    (void)dwNameSpace; (void)lpNspId; (void)timeout;
    (void)lpOverlapped; (void)lpCompletionRoutine; (void)lpHandle;
    
    if (!ppResult) {
        return EAI_FAIL;
    }
    
    *ppResult = NULL;
    
    ADDRINFOW hintsW = {0};
    if (hints) {
        hintsW.ai_flags = hints->ai_flags;
        hintsW.ai_family = hints->ai_family;
        hintsW.ai_socktype = hints->ai_socktype;
        hintsW.ai_protocol = hints->ai_protocol;
    }
    
    PADDRINFOW result = NULL;
    int ret = ex_GetAddrInfoW(pName, pServiceName, hints ? &hintsW : NULL, &result);
    
    if (ret != 0 || !result) {
        return ret;
    }
    
    // Convert ADDRINFOW to ADDRINFOEXW
    PADDRINFOEXW headEx = NULL;
    PADDRINFOEXW tailEx = NULL;
    
    for (PADDRINFOW ai = result; ai; ai = ai->ai_next) {
        size_t size = sizeof(ADDRINFOEXW) + ai->ai_addrlen;
        PADDRINFOEXW aiEx = (PADDRINFOEXW)SAFE_ALLOC(size, "GetAddrInfoExW");
        if (!aiEx) {
            ex_FreeAddrInfoExW(headEx);
            ex_FreeAddrInfoW(result);
            return EAI_MEMORY;
        }
        
        memset(aiEx, 0, size);
        
        aiEx->ai_flags = ai->ai_flags;
        aiEx->ai_family = ai->ai_family;
        aiEx->ai_socktype = ai->ai_socktype;
        aiEx->ai_protocol = ai->ai_protocol;
        aiEx->ai_addrlen = ai->ai_addrlen;
        aiEx->ai_addr = (struct sockaddr*)(aiEx + 1);
        memcpy(aiEx->ai_addr, ai->ai_addr, ai->ai_addrlen);
        
        if (ai->ai_canonname) {
            size_t nameLen = wcslen(ai->ai_canonname) + 1;
            PWSTR canonName = (PWSTR)SAFE_ALLOC(nameLen * sizeof(wchar_t), "GetAddrInfoExW_canon");
            if (canonName) {
                wcscpy_s(canonName, nameLen, ai->ai_canonname);
                aiEx->ai_canonname = canonName;
            }
        }
        
        aiEx->ai_blob = NULL;
        aiEx->ai_bloblen = 0;
        aiEx->ai_provider = NULL;
        aiEx->ai_next = NULL;
        
        if (!headEx) headEx = aiEx;
        else tailEx->ai_next = aiEx;
        tailEx = aiEx;
    }
    
    ex_FreeAddrInfoW(result);
    *ppResult = headEx;
    return 0;
}

// =============================================================================
// GETNAMEINFO
// =============================================================================

int WSAAPI ex_getnameinfo(const struct sockaddr* sa, socklen_t salen,
    char* host, DWORD hostlen, char* serv, DWORD servlen, int flags) {
    (void)salen;
    
    LogMessage("getnameinfo(flags=0x%X)", flags);
    
    if (!sa) {
        return EAI_FAIL;
    }
    
    // Get host name
    if (host && hostlen > 0) {
        if (sa->sa_family == AF_INET) {
            const struct sockaddr_in* sin = (const struct sockaddr_in*)sa;
            
            if (!(flags & NI_NUMERICHOST)) {
                if (sin->sin_addr.s_addr == ex_htonl(INADDR_LOOPBACK)) {
                    if (hostlen > 9) {
                        strcpy_s(host, hostlen, "localhost");
                    } else {
                        return EAI_OVERFLOW;
                    }
                } else {
                    if (!ex_inet_ntop(AF_INET, &sin->sin_addr, host, hostlen)) {
                        return EAI_FAIL;
                    }
                }
            } else {
                if (!ex_inet_ntop(AF_INET, &sin->sin_addr, host, hostlen)) {
                    return EAI_FAIL;
                }
            }
        } else if (sa->sa_family == AF_INET6) {
            const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)sa;
            
            if (!(flags & NI_NUMERICHOST)) {
                if (memcmp(&sin6->sin6_addr, &in6addr_loopback, sizeof(in6addr_loopback)) == 0) {
                    if (hostlen > 9) {
                        strcpy_s(host, hostlen, "localhost");
                    } else {
                        return EAI_OVERFLOW;
                    }
                } else {
                    if (!ex_inet_ntop(AF_INET6, &sin6->sin6_addr, host, hostlen)) {
                        return EAI_FAIL;
                    }
                }
            } else {
                if (!ex_inet_ntop(AF_INET6, &sin6->sin6_addr, host, hostlen)) {
                    return EAI_FAIL;
                }
            }
        } else {
            return EAI_FAMILY;
        }
    }
    
    // Get service name
    if (serv && servlen > 0) {
        u_short port = GetPort(sa);
        
        if (!(flags & NI_NUMERICSERV)) {
            const char* protoStr = (flags & NI_DGRAM) ? "udp" : "tcp";
            struct servent* se = ex_getservbyport(ex_htons(port), protoStr);
            if (se && se->s_name) {
                size_t nameLen = strlen(se->s_name);
                if (nameLen < servlen) {
                    strcpy_s(serv, servlen, se->s_name);
                    return 0;
                } else {
                    return EAI_OVERFLOW;
                }
            }
        }
        
        int written = sprintf_s(serv, servlen, "%u", port);
        if (written < 0) {
            return EAI_OVERFLOW;
        }
    }
    
    return 0;
}

int WSAAPI ex_GetNameInfoW(const SOCKADDR* pSockaddr, socklen_t SockaddrLength,
    PWCHAR pNodeBuffer, DWORD NodeBufferSize,
    PWCHAR pServiceBuffer, DWORD ServiceBufferSize, INT Flags) {
    
    LogMessage("GetNameInfoW(flags=0x%X)", Flags);
    
    char hostA[NI_MAXHOST] = {0};
    char servA[NI_MAXSERV] = {0};
    
    int ret = ex_getnameinfo(pSockaddr, SockaddrLength,
        pNodeBuffer ? hostA : NULL, pNodeBuffer ? sizeof(hostA) : 0,
        pServiceBuffer ? servA : NULL, pServiceBuffer ? sizeof(servA) : 0,
        Flags);
    
    if (ret != 0) {
        return ret;
    }
    
    if (pNodeBuffer && NodeBufferSize > 0) {
        int converted = MultiByteToWideChar(CP_ACP, 0, hostA, -1, 
            pNodeBuffer, NodeBufferSize);
        if (converted == 0) {
            return EAI_FAIL;
        }
    }
    
    if (pServiceBuffer && ServiceBufferSize > 0) {
        int converted = MultiByteToWideChar(CP_ACP, 0, servA, -1,
            pServiceBuffer, ServiceBufferSize);
        if (converted == 0) {
            return EAI_FAIL;
        }
    }
    
    return 0;
}

// =============================================================================
// GETSOCKOPT / SETSOCKOPT
// =============================================================================

int WSAAPI ex_getsockopt(SOCKET s, int level, int optname, char* optval, int* optlen) {
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    if (!optval || !optlen || *optlen <= 0) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    LogMessage("getsockopt(" PTR_FORMAT ", level=%d, opt=%d)", (UPTR)s, level, optname);
    
    SAFE_LOCK();
    
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    int result = 0;
    
    if (level == SOL_SOCKET) {
        switch (optname) {
            case SO_ERROR:
                if (*optlen >= (int)sizeof(int)) {
                    *(int*)optval = AtomicLoad32(&sock->last_error);
                    AtomicStore32(&sock->last_error, 0);
                    *optlen = sizeof(int);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            case SO_TYPE:
                if (*optlen >= (int)sizeof(int)) {
                    *(int*)optval = sock->type;
                    *optlen = sizeof(int);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            case SO_RCVBUF:
                if (*optlen >= (int)sizeof(int)) {
                    *(int*)optval = AtomicLoad32(&sock->opt_rcvbuf);
                    *optlen = sizeof(int);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            case SO_SNDBUF:
                if (*optlen >= (int)sizeof(int)) {
                    *(int*)optval = AtomicLoad32(&sock->opt_sndbuf);
                    *optlen = sizeof(int);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            case SO_REUSEADDR:
                if (*optlen >= (int)sizeof(int)) {
                    *(int*)optval = AtomicLoad32(&sock->opt_reuseaddr) ? 1 : 0;
                    *optlen = sizeof(int);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            case SO_BROADCAST:
                if (*optlen >= (int)sizeof(int)) {
                    *(int*)optval = AtomicLoad32(&sock->opt_broadcast) ? 1 : 0;
                    *optlen = sizeof(int);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            case SO_KEEPALIVE:
                if (*optlen >= (int)sizeof(int)) {
                    *(int*)optval = AtomicLoad32(&sock->opt_keepalive) ? 1 : 0;
                    *optlen = sizeof(int);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            case SO_LINGER:
                if (*optlen >= (int)sizeof(struct linger)) {
                    memcpy(optval, &sock->opt_linger, sizeof(struct linger));
                    *optlen = sizeof(struct linger);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            case SO_ACCEPTCONN:
                if (*optlen >= (int)sizeof(int)) {
                    *(int*)optval = AtomicLoad32(&sock->is_listening) ? 1 : 0;
                    *optlen = sizeof(int);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            case SO_OOBINLINE:
                if (*optlen >= (int)sizeof(int)) {
                    *(int*)optval = 0;
                    *optlen = sizeof(int);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            case SO_RCVTIMEO:
            case SO_SNDTIMEO:
                if (*optlen >= (int)sizeof(DWORD)) {
                    *(DWORD*)optval = BLOCKING_TIMEOUT_MS;
                    *optlen = sizeof(DWORD);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            default:
                memset(optval, 0, *optlen);
                break;
        }
    } else if (level == IPPROTO_TCP) {
        switch (optname) {
            case TCP_NODELAY:
                if (*optlen >= (int)sizeof(int)) {
                    *(int*)optval = AtomicLoad32(&sock->opt_nodelay) ? 1 : 0;
                    *optlen = sizeof(int);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            default:
                memset(optval, 0, *optlen);
                break;
        }
    } else if (level == IPPROTO_IP) {
        switch (optname) {
            case IP_TTL:
                if (*optlen >= (int)sizeof(int)) {
                    *(int*)optval = 64;
                    *optlen = sizeof(int);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            default:
                memset(optval, 0, *optlen);
                break;
        }
    } else if (level == IPPROTO_IPV6) {
        switch (optname) {
            case IPV6_V6ONLY:
                if (*optlen >= (int)sizeof(int)) {
                    *(int*)optval = 0;
                    *optlen = sizeof(int);
                } else {
                    result = SOCKET_ERROR;
                    g_err = WSAEFAULT;
                }
                break;
                
            default:
                memset(optval, 0, *optlen);
                break;
        }
    } else {
        memset(optval, 0, *optlen);
    }
    
    Ulk();
    return result;
}

int WSAAPI ex_setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen) {
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    LogMessage("setsockopt(" PTR_FORMAT ", level=%d, opt=%d, len=%d)", 
        (UPTR)s, level, optname, optlen);
    
    SAFE_LOCK();
    
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    if (level == SOL_SOCKET) {
        switch (optname) {
            case SO_RCVBUF:
                if (optval && optlen >= (int)sizeof(int)) {
                    int val = *(const int*)optval;
                    if (val < 0) val = 0;
                    if (val > (int)BUFFER_PER_SOCKET) val = BUFFER_PER_SOCKET;
                    AtomicStore32(&sock->opt_rcvbuf, val);
                }
                break;
                
            case SO_SNDBUF:
                if (optval && optlen >= (int)sizeof(int)) {
                    int val = *(const int*)optval;
                    if (val < 0) val = 0;
                    if (val > (int)BUFFER_PER_SOCKET) val = BUFFER_PER_SOCKET;
                    AtomicStore32(&sock->opt_sndbuf, val);
                }
                break;
                
            case SO_REUSEADDR:
                if (optval && optlen >= (int)sizeof(int)) {
                    AtomicStore32(&sock->opt_reuseaddr, (*(const int*)optval != 0) ? TRUE : FALSE);
                }
                break;
                
            case SO_BROADCAST:
                if (optval && optlen >= (int)sizeof(int)) {
                    AtomicStore32(&sock->opt_broadcast, (*(const int*)optval != 0) ? TRUE : FALSE);
                }
                break;
                
            case SO_KEEPALIVE:
                if (optval && optlen >= (int)sizeof(int)) {
                    AtomicStore32(&sock->opt_keepalive, (*(const int*)optval != 0) ? TRUE : FALSE);
                }
                break;
                
            case SO_LINGER:
                if (optval && optlen >= (int)sizeof(struct linger)) {
                    memcpy(&sock->opt_linger, optval, sizeof(struct linger));
                }
                break;
                
            case SO_DONTLINGER:
                sock->opt_linger.l_onoff = 0;
                sock->opt_linger.l_linger = 0;
                break;
                
            case SO_RCVTIMEO:
            case SO_SNDTIMEO:
            case SO_EXCLUSIVEADDRUSE:
                break;
                
            default:
                break;
        }
    } else if (level == IPPROTO_TCP) {
        switch (optname) {
            case TCP_NODELAY:
                if (optval && optlen >= (int)sizeof(int)) {
                    AtomicStore32(&sock->opt_nodelay, (*(const int*)optval != 0) ? TRUE : FALSE);
                }
                break;
                
            default:
                break;
        }
    }
    
    Ulk();
    return 0;
}

// =============================================================================
// WSAIOCTL
// =============================================================================

int WSAAPI ex_WSAIoctl(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer,
    DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    
    (void)cbInBuffer;
    (void)lpOverlapped;
    (void)lpCompletionRoutine;
    
    LogMessage("WSAIoctl(" PTR_FORMAT ", code=0x%08X)", (UPTR)s, dwIoControlCode);
    
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    if (lpcbBytesReturned) {
        *lpcbBytesReturned = 0;
    }
    
    switch (dwIoControlCode) {
        case FIONBIO:
            if (lpvInBuffer) {
                return ex_ioctlsocket(s, FIONBIO, (u_long*)lpvInBuffer);
            }
            g_err = WSAEINVAL;
            return SOCKET_ERROR;
            
        case FIONREAD:
            if (lpvOutBuffer && cbOutBuffer >= sizeof(u_long)) {
                int result = ex_ioctlsocket(s, FIONREAD, (u_long*)lpvOutBuffer);
                if (result == 0 && lpcbBytesReturned) {
                    *lpcbBytesReturned = sizeof(u_long);
                }
                return result;
            }
            g_err = WSAEINVAL;
            return SOCKET_ERROR;
            
        case SIO_KEEPALIVE_VALS:
            if (lpcbBytesReturned) {
                *lpcbBytesReturned = 0;
            }
            return 0;
            
        case SIO_GET_EXTENSION_FUNCTION_POINTER:
            g_err = WSAEOPNOTSUPP;
            return SOCKET_ERROR;
            
        case SIO_UDP_CONNRESET:
            return 0;
            
        default:
            g_err = WSAEOPNOTSUPP;
            return SOCKET_ERROR;
    }
}

// =============================================================================
// WSA EVENT FUNCTIONS
// =============================================================================

WSAEVENT WSAAPI ex_WSACreateEvent(void) {
    LogMessage("WSACreateEvent");
    HANDLE h = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!h) {
        g_err = WSAENOBUFS;
        return WSA_INVALID_EVENT;
    }
    return h;
}

BOOL WSAAPI ex_WSACloseEvent(WSAEVENT hEvent) {
    LogMessage("WSACloseEvent");
    if (!hEvent || hEvent == WSA_INVALID_EVENT) {
        g_err = WSA_INVALID_HANDLE;
        return FALSE;
    }
    return CloseHandle(hEvent);
}

BOOL WSAAPI ex_WSASetEvent(WSAEVENT hEvent) {
    LogMessage("WSASetEvent");
    if (!hEvent || hEvent == WSA_INVALID_EVENT) {
        g_err = WSA_INVALID_HANDLE;
        return FALSE;
    }
    return SetEvent(hEvent);
}

BOOL WSAAPI ex_WSAResetEvent(WSAEVENT hEvent) {
    LogMessage("WSAResetEvent");
    if (!hEvent || hEvent == WSA_INVALID_EVENT) {
        g_err = WSA_INVALID_HANDLE;
        return FALSE;
    }
    return ResetEvent(hEvent);
}

DWORD WSAAPI ex_WSAWaitForMultipleEvents(DWORD cEvents, const WSAEVENT* lphEvents,
    BOOL fWaitAll, DWORD dwTimeout, BOOL fAlertable) {
    
    LogMessage("WSAWaitForMultipleEvents(count=%lu, timeout=%lu)", cEvents, dwTimeout);
    
    if (cEvents == 0 || !lphEvents) {
        g_err = WSA_INVALID_PARAMETER;
        return WSA_WAIT_FAILED;
    }
    
    if (cEvents > WSA_MAXIMUM_WAIT_EVENTS) {
        g_err = WSA_INVALID_PARAMETER;
        return WSA_WAIT_FAILED;
    }
    
    DWORD result = WaitForMultipleObjectsEx(cEvents, lphEvents, fWaitAll, dwTimeout, fAlertable);
    
    if (result == WAIT_FAILED) {
        g_err = WSA_INVALID_HANDLE;
    }
    
    return result;
}

int WSAAPI ex_WSAEventSelect(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents) {
    LogMessage("WSAEventSelect(" PTR_FORMAT ", events=0x%lX)", (UPTR)s, lNetworkEvents);
    
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    SAFE_LOCK();
    
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    if (hEventObject && lNetworkEvents) {
        AtomicStore32(&sock->is_nonblocking, TRUE);
    }
    
    Ulk();
    return 0;
}

int WSAAPI ex_WSAEnumNetworkEvents(SOCKET s, WSAEVENT hEventObject,
    LPWSANETWORKEVENTS lpNetworkEvents) {
    
    LogMessage("WSAEnumNetworkEvents(" PTR_FORMAT ")", (UPTR)s);
    
    if (!lpNetworkEvents) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    memset(lpNetworkEvents, 0, sizeof(WSANETWORKEVENTS));
    
    if (!EnsureInit()) {
        g_err = WSANOTINITIALISED;
        return SOCKET_ERROR;
    }
    
    if (hEventObject && hEventObject != WSA_INVALID_EVENT) {
        ResetEvent(hEventObject);
    }
    
    SAFE_LOCK();
    
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    if (BufUsed(sock) > 0) {
        lpNetworkEvents->lNetworkEvents |= FD_READ;
    }
    
    if (AtomicLoad32(&sock->is_listening) && AtomicLoad32(&sock->accept_count) > 0) {
        lpNetworkEvents->lNetworkEvents |= FD_ACCEPT;
    }
    
    if (sock->type == SOCK_DGRAM) {
        lpNetworkEvents->lNetworkEvents |= FD_WRITE;
    } else if (AtomicLoad32(&sock->is_connected) && sock->type == SOCK_STREAM) {
        int peerIdx = AtomicLoad32(&sock->peer_index);
        if (IsValidSocketIndex(peerIdx)) {
            VSOCK* peer = GetSockByIndex(peerIdx);
            if (peer && BufFree(peer) > 0) {
                lpNetworkEvents->lNetworkEvents |= FD_WRITE;
            }
        }
    }
    
    if (AtomicLoad32(&sock->is_connected) && sock->type == SOCK_STREAM) {
        int peerIdx = AtomicLoad32(&sock->peer_index);
        if (IsValidSocketIndex(peerIdx)) {
            VSOCK* peer = GetSockByIndex(peerIdx);
            if (!peer || !IsSocketInUse(peer) || (AtomicLoad32(&peer->shutdown_flags) & SD_SEND)) {
                lpNetworkEvents->lNetworkEvents |= FD_CLOSE;
            }
        } else {
            lpNetworkEvents->lNetworkEvents |= FD_CLOSE;
        }
    }
    
    if (AtomicLoad32(&sock->is_connected)) {
        lpNetworkEvents->lNetworkEvents |= FD_CONNECT;
    }
    
    Ulk();
    return 0;
}

BOOL WSAAPI ex_WSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED lpOverlapped,
    LPDWORD lpcbTransfer, BOOL fWait, LPDWORD lpdwFlags) {
    
    (void)s; (void)lpOverlapped; (void)fWait;
    
    LogMessage("WSAGetOverlappedResult - not fully supported");
    
    if (lpcbTransfer) {
        *lpcbTransfer = 0;
    }
    if (lpdwFlags) {
        *lpdwFlags = 0;
    }
    
    g_err = WSAEOPNOTSUPP;
    return FALSE;
}

int WSAAPI ex_WSAAsyncSelect(SOCKET s, HWND hWnd, u_int wMsg, long lEvent) {
    (void)s; (void)hWnd; (void)wMsg; (void)lEvent;
    
    LogMessage("WSAAsyncSelect - not supported (use WSAEventSelect)");
    g_err = WSAEOPNOTSUPP;
    return SOCKET_ERROR;
}

// =============================================================================
// FD_SET HELPER
// =============================================================================

int WSAAPI ex___WSAFDIsSet(SOCKET fd, fd_set* set) {
    if (!set) return 0;
    
    for (u_int i = 0; i < set->fd_count; i++) {
        if (set->fd_array[i] == fd) {
            return 1;
        }
    }
    return 0;
}

// =============================================================================
// WSAENUMPROTOCOLS
// =============================================================================

int WSAAPI ex_WSAEnumProtocolsA(LPINT lpiProtocols, LPWSAPROTOCOL_INFOA lpProtocolBuffer,
    LPDWORD lpdwBufferLength) {
    
    LogMessage("WSAEnumProtocolsA");
    
    if (!lpdwBufferLength) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    DWORD count = 0;
    for (DWORD i = 0; i < NUM_PROTO; i++) {
        BOOL match = (lpiProtocols == NULL);
        
        if (!match) {
            for (LPINT p = lpiProtocols; *p != 0; p++) {
                if (*p == g_Proto[i].iProtocol) {
                    match = TRUE;
                    break;
                }
            }
        }
        
        if (match) {
            count++;
        }
    }
    
    DWORD needed = count * sizeof(WSAPROTOCOL_INFOA);
    
    if (!lpProtocolBuffer || *lpdwBufferLength < needed) {
        *lpdwBufferLength = needed;
        g_err = WSAENOBUFS;
        return SOCKET_ERROR;
    }
    
    count = 0;
    for (DWORD i = 0; i < NUM_PROTO; i++) {
        BOOL match = (lpiProtocols == NULL);
        
        if (!match) {
            for (LPINT p = lpiProtocols; *p != 0; p++) {
                if (*p == g_Proto[i].iProtocol) {
                    match = TRUE;
                    break;
                }
            }
        }
        
        if (match) {
            LPWSAPROTOCOL_INFOA pInfo = &lpProtocolBuffer[count];
            memset(pInfo, 0, sizeof(WSAPROTOCOL_INFOA));
            
            pInfo->dwServiceFlags1 = g_Proto[i].dwServiceFlags1;
            pInfo->dwServiceFlags2 = g_Proto[i].dwServiceFlags2;
            pInfo->dwServiceFlags3 = g_Proto[i].dwServiceFlags3;
            pInfo->dwServiceFlags4 = g_Proto[i].dwServiceFlags4;
            pInfo->dwProviderFlags = g_Proto[i].dwProviderFlags;
            pInfo->ProviderId = g_Proto[i].ProviderId;
            pInfo->dwCatalogEntryId = g_Proto[i].dwCatalogEntryId;
            pInfo->ProtocolChain = g_Proto[i].ProtocolChain;
            pInfo->iVersion = g_Proto[i].iVersion;
            pInfo->iAddressFamily = g_Proto[i].iAddressFamily;
            pInfo->iMaxSockAddr = g_Proto[i].iMaxSockAddr;
            pInfo->iMinSockAddr = g_Proto[i].iMinSockAddr;
            pInfo->iSocketType = g_Proto[i].iSocketType;
            pInfo->iProtocol = g_Proto[i].iProtocol;
            pInfo->iProtocolMaxOffset = g_Proto[i].iProtocolMaxOffset;
            pInfo->iNetworkByteOrder = g_Proto[i].iNetworkByteOrder;
            pInfo->iSecurityScheme = g_Proto[i].iSecurityScheme;
            pInfo->dwMessageSize = g_Proto[i].dwMessageSize;
            pInfo->dwProviderReserved = g_Proto[i].dwProviderReserved;
            
            WideCharToMultiByte(CP_ACP, 0, g_Proto[i].szProtocol, -1,
                pInfo->szProtocol, sizeof(pInfo->szProtocol), NULL, NULL);
            
            count++;
        }
    }
    
    *lpdwBufferLength = count * sizeof(WSAPROTOCOL_INFOA);
    return (int)count;
}

int WSAAPI ex_WSAEnumProtocolsW(LPINT lpiProtocols, LPWSAPROTOCOL_INFOW lpProtocolBuffer,
    LPDWORD lpdwBufferLength) {
    
    LogMessage("WSAEnumProtocolsW");
    
    if (!lpdwBufferLength) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    DWORD count = 0;
    for (DWORD i = 0; i < NUM_PROTO; i++) {
        BOOL match = (lpiProtocols == NULL);
        
        if (!match) {
            for (LPINT p = lpiProtocols; *p != 0; p++) {
                if (*p == g_Proto[i].iProtocol) {
                    match = TRUE;
                    break;
                }
            }
        }
        
        if (match) {
            count++;
        }
    }
    
    DWORD needed = count * sizeof(WSAPROTOCOL_INFOW);
    
    if (!lpProtocolBuffer || *lpdwBufferLength < needed) {
        *lpdwBufferLength = needed;
        g_err = WSAENOBUFS;
        return SOCKET_ERROR;
    }
    
    count = 0;
    for (DWORD i = 0; i < NUM_PROTO; i++) {
        BOOL match = (lpiProtocols == NULL);
        
        if (!match) {
            for (LPINT p = lpiProtocols; *p != 0; p++) {
                if (*p == g_Proto[i].iProtocol) {
                    match = TRUE;
                    break;
                }
            }
        }
        
        if (match) {
            lpProtocolBuffer[count] = g_Proto[i];
            count++;
        }
    }
    
    *lpdwBufferLength = count * sizeof(WSAPROTOCOL_INFOW);
    return (int)count;
}

// =============================================================================
// WSA STRING FUNCTIONS
// =============================================================================

INT WSAAPI ex_WSAAddressToStringA(LPSOCKADDR lpsaAddress, DWORD dwAddressLength,
    LPWSAPROTOCOL_INFOA lpProtocolInfo, LPSTR lpszAddressString,
    LPDWORD lpdwAddressStringLength) {
    
    (void)dwAddressLength;
    (void)lpProtocolInfo;
    
    if (!lpsaAddress || !lpszAddressString || !lpdwAddressStringLength) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    char tempBuf[128];
    int len = 0;
    
    if (lpsaAddress->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)lpsaAddress;
        char* ip = ex_inet_ntoa(sin->sin_addr);
        u_short port = ex_ntohs(sin->sin_port);
        
        if (port != 0) {
            len = sprintf_s(tempBuf, sizeof(tempBuf), "%s:%u", ip, port);
        } else {
            len = sprintf_s(tempBuf, sizeof(tempBuf), "%s", ip);
        }
    } else if (lpsaAddress->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)lpsaAddress;
        char ip[INET6_ADDRSTRLEN];
        
        if (!ex_inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip))) {
            g_err = WSAEINVAL;
            return SOCKET_ERROR;
        }
        
        u_short port = ex_ntohs(sin6->sin6_port);
        
        if (port != 0) {
            len = sprintf_s(tempBuf, sizeof(tempBuf), "[%s]:%u", ip, port);
        } else {
            len = sprintf_s(tempBuf, sizeof(tempBuf), "%s", ip);
        }
    } else {
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    if (len < 0) {
        g_err = WSAEINVAL;
        return SOCKET_ERROR;
    }
    
    DWORD needed = (DWORD)(len + 1);
    
    if (*lpdwAddressStringLength < needed) {
        *lpdwAddressStringLength = needed;
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    strcpy_s(lpszAddressString, *lpdwAddressStringLength, tempBuf);
    *lpdwAddressStringLength = needed;
    
    return 0;
}

INT WSAAPI ex_WSAAddressToStringW(LPSOCKADDR lpsaAddress, DWORD dwAddressLength,
    LPWSAPROTOCOL_INFOW lpProtocolInfo, LPWSTR lpszAddressString,
    LPDWORD lpdwAddressStringLength) {
    
    char tempA[128];
    DWORD tempLen = sizeof(tempA);
    
    int ret = ex_WSAAddressToStringA(lpsaAddress, dwAddressLength,
        (LPWSAPROTOCOL_INFOA)lpProtocolInfo, tempA, &tempLen);
    
    if (ret != 0) {
        return ret;
    }
    
    DWORD needed = (DWORD)(strlen(tempA) + 1);
    
    if (!lpdwAddressStringLength) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    if (*lpdwAddressStringLength < needed || !lpszAddressString) {
        *lpdwAddressStringLength = needed;
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    MultiByteToWideChar(CP_ACP, 0, tempA, -1, lpszAddressString, *lpdwAddressStringLength);
    *lpdwAddressStringLength = needed;
    
    return 0;
}

INT WSAAPI ex_WSAStringToAddressA(LPSTR AddressString, INT AddressFamily,
    LPWSAPROTOCOL_INFOA lpProtocolInfo, LPSOCKADDR lpAddress,
    LPINT lpAddressLength) {
    
    (void)lpProtocolInfo;
    
    if (!AddressString || !lpAddress || !lpAddressLength) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    if (AddressFamily == AF_INET) {
        if (*lpAddressLength < (int)sizeof(struct sockaddr_in)) {
            g_err = WSAEFAULT;
            return SOCKET_ERROR;
        }
        
        struct sockaddr_in* sin = (struct sockaddr_in*)lpAddress;
        memset(sin, 0, sizeof(*sin));
        sin->sin_family = AF_INET;
        
        char tempBuf[64];
        strncpy_s(tempBuf, sizeof(tempBuf), AddressString, _TRUNCATE);
        
        char* portStr = strchr(tempBuf, ':');
        if (portStr) {
            *portStr = '\0';
            portStr++;
            sin->sin_port = ex_htons((u_short)atoi(portStr));
        }
        
        if (ex_inet_pton(AF_INET, tempBuf, &sin->sin_addr) != 1) {
            g_err = WSAEINVAL;
            return SOCKET_ERROR;
        }
        
        *lpAddressLength = sizeof(struct sockaddr_in);
        return 0;
        
    } else if (AddressFamily == AF_INET6) {
        if (*lpAddressLength < (int)sizeof(struct sockaddr_in6)) {
            g_err = WSAEFAULT;
            return SOCKET_ERROR;
        }
        
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)lpAddress;
        memset(sin6, 0, sizeof(*sin6));
        sin6->sin6_family = AF_INET6;
        
        char tempBuf[128];
        strncpy_s(tempBuf, sizeof(tempBuf), AddressString, _TRUNCATE);
        
        char* ipStart = tempBuf;
        char* portStr = NULL;
        
        if (tempBuf[0] == '[') {
            ipStart = tempBuf + 1;
            char* bracket = strchr(ipStart, ']');
            if (bracket) {
                *bracket = '\0';
                if (bracket[1] == ':') {
                    portStr = bracket + 2;
                }
            }
        }
        
        if (portStr) {
            sin6->sin6_port = ex_htons((u_short)atoi(portStr));
        }
        
        if (ex_inet_pton(AF_INET6, ipStart, &sin6->sin6_addr) != 1) {
            g_err = WSAEINVAL;
            return SOCKET_ERROR;
        }
        
        *lpAddressLength = sizeof(struct sockaddr_in6);
        return 0;
    }
    
    g_err = WSAEINVAL;
    return SOCKET_ERROR;
}

INT WSAAPI ex_WSAStringToAddressW(LPWSTR AddressString, INT AddressFamily,
    LPWSAPROTOCOL_INFOW lpProtocolInfo, LPSOCKADDR lpAddress,
    LPINT lpAddressLength) {
    
    if (!AddressString) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    char tempA[128];
    WideCharToMultiByte(CP_ACP, 0, AddressString, -1, tempA, sizeof(tempA), NULL, NULL);
    
    return ex_WSAStringToAddressA(tempA, AddressFamily,
        (LPWSAPROTOCOL_INFOA)lpProtocolInfo, lpAddress, lpAddressLength);
}

// =============================================================================
// SOCKET DUPLICATION
// =============================================================================

int WSAAPI ex_WSADuplicateSocketA(SOCKET s, DWORD dwProcessId,
    LPWSAPROTOCOL_INFOA lpProtocolInfo) {
    
    (void)dwProcessId;
    
    LogMessage("WSADuplicateSocketA(" PTR_FORMAT ") - limited support", (UPTR)s);
    
    if (!lpProtocolInfo) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    SAFE_LOCK();
    
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    memset(lpProtocolInfo, 0, sizeof(WSAPROTOCOL_INFOA));
    lpProtocolInfo->iAddressFamily = sock->family;
    lpProtocolInfo->iSocketType = sock->type;
    lpProtocolInfo->iProtocol = sock->protocol;
    lpProtocolInfo->dwServiceFlags1 = XP1_IFS_HANDLES;
    
    Ulk();
    return 0;
}

int WSAAPI ex_WSADuplicateSocketW(SOCKET s, DWORD dwProcessId,
    LPWSAPROTOCOL_INFOW lpProtocolInfo) {
    
    (void)dwProcessId;
    
    LogMessage("WSADuplicateSocketW(" PTR_FORMAT ") - limited support", (UPTR)s);
    
    if (!lpProtocolInfo) {
        g_err = WSAEFAULT;
        return SOCKET_ERROR;
    }
    
    SAFE_LOCK();
    
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        g_err = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    
    memset(lpProtocolInfo, 0, sizeof(WSAPROTOCOL_INFOW));
    lpProtocolInfo->iAddressFamily = sock->family;
    lpProtocolInfo->iSocketType = sock->type;
    lpProtocolInfo->iProtocol = sock->protocol;
    lpProtocolInfo->dwServiceFlags1 = XP1_IFS_HANDLES;
    
    Ulk();
    return 0;
}

// =============================================================================
// DISCONNECT FUNCTIONS
// =============================================================================

int WSAAPI ex_WSARecvDisconnect(SOCKET s, LPWSABUF lpInboundDisconnectData) {
    (void)lpInboundDisconnectData;
    return ex_shutdown(s, SD_RECEIVE);
}

int WSAAPI ex_WSASendDisconnect(SOCKET s, LPWSABUF lpOutboundDisconnectData) {
    (void)lpOutboundDisconnectData;
    return ex_shutdown(s, SD_SEND);
}

// =============================================================================
// STUB FUNCTIONS
// =============================================================================

int WSAAPI ex_StubFail_NotSupp(void) {
    LogMessage("STUB: Unsupported function called -> SOCKET_ERROR");
    g_err = WSAEOPNOTSUPP;
    return SOCKET_ERROR;
}

int WSAAPI ex_StubSuccess(void) {
    LogMessage("STUB: Function called -> SUCCESS");
    return 0;
}

void WSAAPI ex_StubVoid(void) {
    LogMessage("STUB: Void function called");
}

LPVOID WSAAPI ex_StubReturnNull(void) {
    LogMessage("STUB: Function called -> NULL");
    return NULL;
}

HANDLE WSAAPI ex_WSAAsyncGetHostByAddr(HWND hWnd, u_int wMsg, const char* addr,
    int len, int type, char* buf, int buflen) {
    (void)hWnd; (void)wMsg; (void)addr; (void)len; (void)type; (void)buf; (void)buflen;
    g_err = WSAEOPNOTSUPP;
    return NULL;
}

HANDLE WSAAPI ex_WSAAsyncGetHostByName(HWND hWnd, u_int wMsg, const char* name,
    char* buf, int buflen) {
    (void)hWnd; (void)wMsg; (void)name; (void)buf; (void)buflen;
    g_err = WSAEOPNOTSUPP;
    return NULL;
}

HANDLE WSAAPI ex_WSAAsyncGetProtoByName(HWND hWnd, u_int wMsg, const char* name,
    char* buf, int buflen) {
    (void)hWnd; (void)wMsg; (void)name; (void)buf; (void)buflen;
    g_err = WSAEOPNOTSUPP;
    return NULL;
}

HANDLE WSAAPI ex_WSAAsyncGetProtoByNumber(HWND hWnd, u_int wMsg, int number,
    char* buf, int buflen) {
    (void)hWnd; (void)wMsg; (void)number; (void)buf; (void)buflen;
    g_err = WSAEOPNOTSUPP;
    return NULL;
}

HANDLE WSAAPI ex_WSAAsyncGetServByName(HWND hWnd, u_int wMsg, const char* name,
    const char* proto, char* buf, int buflen) {
    (void)hWnd; (void)wMsg; (void)name; (void)proto; (void)buf; (void)buflen;
    g_err = WSAEOPNOTSUPP;
    return NULL;
}

HANDLE WSAAPI ex_WSAAsyncGetServByPort(HWND hWnd, u_int wMsg, int port,
    const char* proto, char* buf, int buflen) {
    (void)hWnd; (void)wMsg; (void)port; (void)proto; (void)buf; (void)buflen;
    g_err = WSAEOPNOTSUPP;
    return NULL;
}

int WSAAPI ex_WSACancelAsyncRequest(HANDLE hAsyncTaskHandle) {
    (void)hAsyncTaskHandle;
    g_err = WSAEOPNOTSUPP;
    return SOCKET_ERROR;
}

int WSAAPI ex_WSACancelBlockingCall(void) {
    g_err = WSAEOPNOTSUPP;
    return SOCKET_ERROR;
}

BOOL WSAAPI ex_WSAIsBlocking(void) {
    return FALSE;
}

FARPROC WSAAPI ex_WSASetBlockingHook(FARPROC lpBlockFunc) {
    (void)lpBlockFunc;
    g_err = WSAEOPNOTSUPP;
    return NULL;
}

int WSAAPI ex_WSAUnhookBlockingHook(void) {
    return 0;
}

// =============================================================================
// DLLMAIN
// =============================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)hModule;
    
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
            
        case DLL_PROCESS_DETACH:
            if (lpReserved == NULL) {
                if (g_nStartup > 0) {
                    g_nStartup = 1;
                    CleanupSharedMemory();
                }
            }
            break;
            
        case DLL_THREAD_ATTACH:
            break;
            
        case DLL_THREAD_DETACH:
            g_lockDepth = 0;
            break;
    }
    
    return TRUE;
}