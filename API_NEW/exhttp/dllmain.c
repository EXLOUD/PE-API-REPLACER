/*
 * WinHTTP Emulator - Wine-style with exws2 integration
 * Fixed for async mode and missing options
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <wctype.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// CONFIGURATION
// ============================================================================
#define ENABLE_DEBUG_CONSOLE    1
#define ENABLE_FILE_LOGGING     0
#define ENABLE_NETWORK_ATTEMPTS 1
#define FORCE_OFFLINE_MODE      1

// ============================================================================
// WINHTTP OPTION CONSTANTS
// ============================================================================
#ifndef WINHTTP_OPTION_CALLBACK
#define WINHTTP_OPTION_CALLBACK                         1
#endif
#ifndef WINHTTP_OPTION_RESOLVE_TIMEOUT
#define WINHTTP_OPTION_RESOLVE_TIMEOUT                  2
#endif
#ifndef WINHTTP_OPTION_CONNECT_TIMEOUT
#define WINHTTP_OPTION_CONNECT_TIMEOUT                  3
#endif
#ifndef WINHTTP_OPTION_CONNECT_RETRIES
#define WINHTTP_OPTION_CONNECT_RETRIES                  4
#endif
#ifndef WINHTTP_OPTION_SEND_TIMEOUT
#define WINHTTP_OPTION_SEND_TIMEOUT                     5
#endif
#ifndef WINHTTP_OPTION_RECEIVE_TIMEOUT
#define WINHTTP_OPTION_RECEIVE_TIMEOUT                  6
#endif
#ifndef WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT
#define WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT         7
#endif

// Додати відсутні:
#ifndef WINHTTP_OPTION_NETWORK_INTERFACE_AFFINITY
#define WINHTTP_OPTION_NETWORK_INTERFACE_AFFINITY       105
#endif
#ifndef WINHTTP_OPTION_PROXY_DISABLE_SERVICE_CALLS
#define WINHTTP_OPTION_PROXY_DISABLE_SERVICE_CALLS      137
#endif
#ifndef WINHTTP_OPTION_SERVER_CERT_CHAIN_BUILD_FLAGS
#define WINHTTP_OPTION_SERVER_CERT_CHAIN_BUILD_FLAGS    148
#endif
#ifndef WINHTTP_OPTION_CONNECTION_STATS_V1
#define WINHTTP_OPTION_CONNECTION_STATS_V1              150
#endif
#ifndef WINHTTP_OPTION_SECURITY_INFO
#define WINHTTP_OPTION_SECURITY_INFO                    151
#endif
#ifndef WINHTTP_OPTION_TCP_KEEPALIVE
#define WINHTTP_OPTION_TCP_KEEPALIVE                    152
#endif
#ifndef WINHTTP_OPTION_TCP_FAST_OPEN
#define WINHTTP_OPTION_TCP_FAST_OPEN                    153
#endif
#ifndef WINHTTP_OPTION_TLS_FALSE_START
#define WINHTTP_OPTION_TLS_FALSE_START                  154
#endif
#ifndef WINHTTP_OPTION_IGNORE_CERT_REVOCATION_OFFLINE
#define WINHTTP_OPTION_IGNORE_CERT_REVOCATION_OFFLINE   155
#endif
#ifndef WINHTTP_OPTION_TLS_PROTOCOL_INSECURE_FALLBACK
#define WINHTTP_OPTION_TLS_PROTOCOL_INSECURE_FALLBACK   158
#endif
#ifndef WINHTTP_OPTION_STREAM_ERROR_CODE
#define WINHTTP_OPTION_STREAM_ERROR_CODE                159
#endif
#ifndef WINHTTP_OPTION_REQUIRE_STREAM_END
#define WINHTTP_OPTION_REQUIRE_STREAM_END               160
#endif
#ifndef WINHTTP_OPTION_FAILED_CONNECTION_RETRIES
#define WINHTTP_OPTION_FAILED_CONNECTION_RETRIES        162
#endif
#ifndef WINHTTP_OPTION_HTTP2_KEEPALIVE
#define WINHTTP_OPTION_HTTP2_KEEPALIVE                  164
#endif
#ifndef WINHTTP_OPTION_RESOLUTION_HOSTNAME
#define WINHTTP_OPTION_RESOLUTION_HOSTNAME              165
#endif
#ifndef WINHTTP_OPTION_SET_TOKEN_BINDING
#define WINHTTP_OPTION_SET_TOKEN_BINDING                166
#endif
#ifndef WINHTTP_OPTION_TOKEN_BINDING_PUBLIC_KEY
#define WINHTTP_OPTION_TOKEN_BINDING_PUBLIC_KEY         167
#endif
#ifndef WINHTTP_OPTION_REFERER_TOKEN_BINDING_HOSTNAME
#define WINHTTP_OPTION_REFERER_TOKEN_BINDING_HOSTNAME   168
#endif
#ifndef WINHTTP_OPTION_HTTP2_PLUS_TRANSFER_ENCODING
#define WINHTTP_OPTION_HTTP2_PLUS_TRANSFER_ENCODING     169
#endif
#ifndef WINHTTP_OPTION_RESOLVER_CACHE_CONFIG
#define WINHTTP_OPTION_RESOLVER_CACHE_CONFIG            170
#endif
#ifndef WINHTTP_OPTION_DISABLE_CERT_CHAIN_BUILDING
#define WINHTTP_OPTION_DISABLE_CERT_CHAIN_BUILDING      171
#endif
#ifndef WINHTTP_OPTION_BACKGROUND_CONNECTIONS
#define WINHTTP_OPTION_BACKGROUND_CONNECTIONS           172
#endif
#ifndef WINHTTP_OPTION_FIRST_AVAILABLE_CONNECTION
#define WINHTTP_OPTION_FIRST_AVAILABLE_CONNECTION       173
#endif
#ifndef WINHTTP_OPTION_TCP_PRIORITY_STATUS
#define WINHTTP_OPTION_TCP_PRIORITY_STATUS              177
#endif
#ifndef WINHTTP_OPTION_CONNECTION_GUID
#define WINHTTP_OPTION_CONNECTION_GUID                  178
#endif
#ifndef WINHTTP_OPTION_HTTP2_RECEIVE_WINDOW
#define WINHTTP_OPTION_HTTP2_RECEIVE_WINDOW             183
#endif
#ifndef WINHTTP_OPTION_FEATURE_SUPPORTED
#define WINHTTP_OPTION_FEATURE_SUPPORTED                184
#endif

// Protocol flags
#ifndef WINHTTP_PROTOCOL_FLAG_HTTP2
#define WINHTTP_PROTOCOL_FLAG_HTTP2                     0x1
#endif
#ifndef WINHTTP_PROTOCOL_FLAG_HTTP3
#define WINHTTP_PROTOCOL_FLAG_HTTP3                     0x2
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define WINHTTP_HANDLE_TYPE_SESSION                  1
#define WINHTTP_HANDLE_TYPE_CONNECT                  2
#define WINHTTP_HANDLE_TYPE_REQUEST                  3
#define WINHTTP_HANDLE_TYPE_PROXY_RESOLVER           4
#define WINHTTP_HANDLE_TYPE_WEBSOCKET                5
#define WINHTTP_HANDLE_TYPE_PROTOCOL                 6

#define DEFAULT_RESOLVE_TIMEOUT       0
#define DEFAULT_CONNECT_TIMEOUT       20000
#define DEFAULT_SEND_TIMEOUT          30000
#define DEFAULT_RECEIVE_TIMEOUT       30000
#define HANDLE_CHUNK_SIZE             0x10

// ============================================================================
// LOGGING
// ============================================================================
#if ENABLE_FILE_LOGGING
static FILE *g_log_file = NULL;
#endif

static const char* GetOptionName(DWORD option) {
    switch (option) {
        case 1: return "CALLBACK";
        case 2: return "RESOLVE_TIMEOUT";
        case 3: return "CONNECT_TIMEOUT";
        case 4: return "CONNECT_RETRIES";
        case 5: return "SEND_TIMEOUT";
        case 6: return "RECEIVE_TIMEOUT";
        case 7: return "RECEIVE_RESPONSE_TIMEOUT";
        case 9: return "HANDLE_TYPE";
        case 12: return "READ_BUFFER_SIZE";
        case 13: return "WRITE_BUFFER_SIZE";
        case 21: return "PARENT_HANDLE";
        case 24: return "EXTENDED_ERROR";
        case 31: return "SECURITY_FLAGS";
        case 32: return "SECURITY_CERTIFICATE_STRUCT";
        case 34: return "URL";
        case 36: return "SECURITY_KEY_BITNESS";
        case 38: return "PROXY";
        case 39: return "PROXY_RESULT_ENTRY";
        case 41: return "USER_AGENT";
        case 45: return "CONTEXT_VALUE";
        case 47: return "CLIENT_CERT_CONTEXT";
        case 58: return "REQUEST_PRIORITY";
        case 59: return "HTTP_VERSION";
        case 63: return "DISABLE_FEATURE";
        case 68: return "CODEPAGE";
        case 73: return "MAX_CONNS_PER_SERVER";
        case 74: return "MAX_CONNS_PER_1_0_SERVER";
        case 77: return "AUTOLOGON_POLICY";
        case 78: return "SERVER_CERT_CONTEXT";
        case 79: return "ENABLE_FEATURE";
        case 80: return "WORKER_THREAD_COUNT";
        case 81: return "PASSPORT_COBRANDING_TEXT";
        case 82: return "PASSPORT_COBRANDING_URL";
        case 83: return "CONFIGURE_PASSPORT_AUTH";
        case 84: return "SECURE_PROTOCOLS";
        case 85: return "ENABLETRACING";
        case 86: return "PASSPORT_SIGN_OUT";
        case 87: return "PASSPORT_RETURN_URL";
        case 88: return "REDIRECT_POLICY";
        case 89: return "MAX_HTTP_AUTOMATIC_REDIRECTS";
        case 90: return "MAX_HTTP_STATUS_CONTINUE";
        case 91: return "MAX_RESPONSE_HEADER_SIZE";
        case 92: return "MAX_RESPONSE_DRAIN_SIZE";
        case 93: return "CONNECTION_INFO";
        case 94: return "CLIENT_CERT_ISSUER_LIST";
        case 96: return "SPN";
        case 97: return "GLOBAL_PROXY_CREDS";
        case 98: return "GLOBAL_SERVER_CREDS";
        case 99: return "UNLOAD_NOTIFY_EVENT";
        case 100: return "REJECT_USERPWD_IN_URL";
        case 101: return "USE_GLOBAL_SERVER_CREDENTIALS";
        case 103: return "RECEIVE_PROXY_CONNECT_RESPONSE";
        case 104: return "IS_PROXY_CONNECT_RESPONSE";
        case 105: return "NETWORK_INTERFACE_AFFINITY";
        case 106: return "SERVER_SPN_USED";
        case 107: return "PROXY_SPN_USED";
        case 108: return "SERVER_CBT";
        case 110: return "UNSAFE_HEADER_PARSING";
        case 111: return "ASSURED_NON_BLOCKING_CALLBACKS";
        case 114: return "UPGRADE_TO_WEB_SOCKET";
        case 115: return "WEB_SOCKET_CLOSE_TIMEOUT";
        case 116: return "WEB_SOCKET_KEEPALIVE_INTERVAL";
        case 118: return "DECOMPRESSION";
        case 122: return "WEB_SOCKET_RECEIVE_BUFFER_SIZE";
        case 123: return "WEB_SOCKET_SEND_BUFFER_SIZE";
        case 128: return "TCP_PRIORITY_HINT";
        case 131: return "CONNECTION_FILTER";
        case 133: return "ENABLE_HTTP_PROTOCOL";
        case 134: return "HTTP_PROTOCOL_USED";
        case 136: return "KDC_PROXY_SETTINGS";
        case 137: return "PROXY_DISABLE_SERVICE_CALLS";
        case 138: return "ENCODE_EXTRA";
        case 139: return "DISABLE_STREAM_QUEUE";
        case 140: return "IPV6_FAST_FALLBACK";
        case 141: return "CONNECTION_STATS_V0";
        case 142: return "REQUEST_TIMES";
        case 143: return "EXPIRE_CONNECTION";
        case 144: return "DISABLE_SECURE_PROTOCOL_FALLBACK";
        case 145: return "HTTP_PROTOCOL_REQUIRED";
        case 146: return "REQUEST_STATS";
        case 147: return "SERVER_CERT_CHAIN_CONTEXT";
        case 148: return "SERVER_CERT_CHAIN_BUILD_FLAGS";
        case 150: return "CONNECTION_STATS_V1";
        case 151: return "SECURITY_INFO";
        case 152: return "TCP_KEEPALIVE";
        case 153: return "TCP_FAST_OPEN";
        case 154: return "TLS_FALSE_START";
        case 155: return "IGNORE_CERT_REVOCATION_OFFLINE";
        case 158: return "TLS_PROTOCOL_INSECURE_FALLBACK";
        case 159: return "STREAM_ERROR_CODE";
        case 160: return "REQUIRE_STREAM_END";
        case 161: return "ENABLE_HTTP2_PLUS_CLIENT_CERT";
        case 162: return "FAILED_CONNECTION_RETRIES";
        case 164: return "HTTP2_KEEPALIVE";
        case 165: return "RESOLUTION_HOSTNAME";
        case 166: return "SET_TOKEN_BINDING";
        case 167: return "TOKEN_BINDING_PUBLIC_KEY";
        case 168: return "REFERER_TOKEN_BINDING_HOSTNAME";
        case 169: return "HTTP2_PLUS_TRANSFER_ENCODING";
        case 170: return "RESOLVER_CACHE_CONFIG";
        case 171: return "DISABLE_CERT_CHAIN_BUILDING";
        case 172: return "BACKGROUND_CONNECTIONS";
        case 173: return "FIRST_AVAILABLE_CONNECTION";
        case 177: return "TCP_PRIORITY_STATUS";
        case 178: return "CONNECTION_GUID";
        case 179: return "MATCH_CONNECTION_GUID";
        case 183: return "HTTP2_RECEIVE_WINDOW";
        case 184: return "FEATURE_SUPPORTED";
        case 185: return "QUIC_STATS";
        case 188: return "HTTP3_KEEPALIVE";
        case 189: return "HTTP3_HANDSHAKE_TIMEOUT";
        case 190: return "HTTP3_INITIAL_RTT";
        case 191: return "HTTP3_STREAM_ERROR_CODE";
        case 192: return "REQUEST_ANNOTATION";
        case 193: return "DISABLE_PROXY_AUTH_SCHEMES";
        case 194: return "REVERT_IMPERSONATION_SERVER_CERT";
        case 195: return "DISABLE_GLOBAL_POOLING";
        case 196: return "USE_SESSION_SCH_CRED";
        case 199: return "SERVER_CERT_CHAIN_BUILD_CACHE_ONLY";
        case 200: return "QUIC_STATS_V2";
        case 202: return "QUIC_STREAM_STATS";
        case 203: return "USE_LOOKASIDE";
        case 204: return "ERROR_LOG_GUID";
        case 205: return "ENABLE_FAST_FORWARDING";
        case 206: return "FAST_FORWARDING_RESPONSE_DATA";
        case 207: return "UPGRADE_TO_PROTOCOL";
        case 208: return "CONNECTION_STATS_V2";
        case 209: return "FAST_FORWARDING_RESPONSE_STATUS";
        case 210: return "DSCP_TAG";
        case 211: return "HTTP11_DOWNGRADE_TTL";
        case 0x1000: return "USERNAME";
        case 0x1001: return "PASSWORD";
        case 0x1002: return "PROXY_USERNAME";
        case 0x1003: return "PROXY_PASSWORD";
        default: {
            static char buf[32];
            snprintf(buf, sizeof(buf), "UNKNOWN(%lu)", option);
            return buf;
        }
    }
}

static void Log(const char *fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
#if ENABLE_DEBUG_CONSOLE
    printf("[WINHTTP] %s\n", buf);
    OutputDebugStringA("[WINHTTP] ");
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
#endif
#if ENABLE_FILE_LOGGING
    if (g_log_file) { fprintf(g_log_file, "%s\n", buf); fflush(g_log_file); }
#endif
}

// ============================================================================
// EXWS2 SOCKET LAYER
// ============================================================================
static BOOL g_winsock_initialized = FALSE;
static CRITICAL_SECTION g_winsock_cs;
static BOOL g_winsock_cs_initialized = FALSE;

typedef struct _SOCKET_CONNECTION {
    SOCKET sock;
    BOOL connected;
    char host[256];
    WORD port;
    struct sockaddr_in addr;
} SOCKET_CONNECTION;

static BOOL InitWinsock(void) {
    BOOL result = FALSE;
    
    if (!g_winsock_cs_initialized) {
        InitializeCriticalSection(&g_winsock_cs);
        g_winsock_cs_initialized = TRUE;
    }
    
    EnterCriticalSection(&g_winsock_cs);
    
    if (!g_winsock_initialized) {
        WSADATA wsa;
        int err = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (err == 0) {
            Log("WSAStartup via exws2: SUCCESS (version %d.%d)",
                LOBYTE(wsa.wVersion), HIBYTE(wsa.wVersion));
            g_winsock_initialized = TRUE;
            result = TRUE;
        } else {
            Log("WSAStartup via exws2: FAILED (error %d)", err);
        }
    } else {
        result = TRUE;
    }
    
    LeaveCriticalSection(&g_winsock_cs);
    return result;
}

static void CleanupWinsock(void) {
    if (g_winsock_cs_initialized) {
        EnterCriticalSection(&g_winsock_cs);
        if (g_winsock_initialized) {
            WSACleanup();
            g_winsock_initialized = FALSE;
            Log("WSACleanup completed");
        }
        LeaveCriticalSection(&g_winsock_cs);
    }
}

static BOOL ResolveHost(const WCHAR *host, struct sockaddr_in *addr) {
    char hostA[256];
    struct addrinfo hints = {0}, *result = NULL;
    int ret;
    
    if (!g_winsock_initialized) return FALSE;
    
    WideCharToMultiByte(CP_UTF8, 0, host, -1, hostA, sizeof(hostA), NULL, NULL);
    
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    Log("  [SOCKET] getaddrinfo('%s')...", hostA);
    ret = getaddrinfo(hostA, NULL, &hints, &result);
    
    if (ret != 0) {
        Log("  [SOCKET] DNS resolution FAILED: %d", ret);
        return FALSE;
    }
    
    memcpy(addr, result->ai_addr, sizeof(struct sockaddr_in));
    freeaddrinfo(result);
    
    Log("  [SOCKET] DNS resolved: %s -> %d.%d.%d.%d",
        hostA,
        addr->sin_addr.S_un.S_un_b.s_b1,
        addr->sin_addr.S_un.S_un_b.s_b2,
        addr->sin_addr.S_un.S_un_b.s_b3,
        addr->sin_addr.S_un.S_un_b.s_b4);
    
    return TRUE;
}

static SOCKET_CONNECTION *CreateSocketConnection(const WCHAR *host, WORD port) {
    SOCKET_CONNECTION *conn;
    
    if (!g_winsock_initialized) {
        Log("  [SOCKET] Winsock not initialized");
        return NULL;
    }
    
    conn = (SOCKET_CONNECTION *)calloc(1, sizeof(SOCKET_CONNECTION));
    if (!conn) return NULL;
    
    WideCharToMultiByte(CP_UTF8, 0, host, -1, conn->host, sizeof(conn->host), NULL, NULL);
    conn->port = port;
    conn->sock = INVALID_SOCKET;
    conn->connected = FALSE;
    
    if (!ResolveHost(host, &conn->addr)) {
        free(conn);
        return NULL;
    }
    conn->addr.sin_port = htons(port);
    
    Log("  [SOCKET] Creating TCP socket...");
    conn->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (conn->sock == INVALID_SOCKET) {
        Log("  [SOCKET] socket() FAILED: %d", WSAGetLastError());
        free(conn);
        return NULL;
    }
    Log("  [SOCKET] Socket created: %lld", (long long)conn->sock);
    
    Log("  [SOCKET] Connecting to %s:%d...", conn->host, port);
    if (connect(conn->sock, (struct sockaddr *)&conn->addr, sizeof(conn->addr)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        Log("  [SOCKET] connect() FAILED: %d", err);
        closesocket(conn->sock);
        conn->sock = INVALID_SOCKET;
    } else {
        Log("  [SOCKET] Connected successfully!");
        conn->connected = TRUE;
    }
    
    return conn;
}

static void CloseSocketConnection(SOCKET_CONNECTION *conn) {
    if (!conn) return;
    if (conn->sock != INVALID_SOCKET) {
        closesocket(conn->sock);
        Log("  [SOCKET] Connection closed: %s:%d", conn->host, conn->port);
    }
    free(conn);
}

static int SocketSend(SOCKET_CONNECTION *conn, const char *data, int len) {
    if (!conn || !conn->connected) return -1;
    return send(conn->sock, data, len, 0);
}

static int SocketRecv(SOCKET_CONNECTION *conn, char *buf, int len) {
    if (!conn || !conn->connected) return -1;
    return recv(conn->sock, buf, len, 0);
}

// ============================================================================
// OBJECT STRUCTURES
// ============================================================================
struct object_header;
struct object_vtbl {
    void (*handle_closing)(struct object_header *);
    void (*destroy)(struct object_header *);
    BOOL (*query_option)(struct object_header *, DWORD, void *, DWORD *);
    BOOL (*set_option)(struct object_header *, DWORD, void *, DWORD);
};

struct object_header {
    DWORD type;
    HINTERNET handle;
    const struct object_vtbl *vtbl;
    DWORD flags;
    DWORD disable_flags;
    DWORD logon_policy;
    DWORD redirect_policy;
    DWORD_PTR context;
    LONG refs;
    WINHTTP_STATUS_CALLBACK callback;
    DWORD notify_mask;
};

struct header {
    WCHAR *field;
    WCHAR *value;
    BOOL is_request;
};

struct session {
    struct object_header hdr;
    CRITICAL_SECTION cs;
    WCHAR *agent;
    DWORD access;
    int resolve_timeout;
    int connect_timeout;
    int send_timeout;
    int receive_timeout;
    int connect_retries;                // НОВА - для CONNECT_RETRIES (4)
    WCHAR *proxy_server;
    WCHAR *proxy_bypass;
    WCHAR *proxy_username;
    WCHAR *proxy_password;
    DWORD secure_protocols;
    DWORD http_protocols;
    BOOL assured_non_blocking;
    DWORD decompression;
    BOOL tcp_fast_open;                 // НОВА - для TCP_FAST_OPEN (153)
    BOOL tls_false_start;               // НОВА - для TLS_FALSE_START (154)
    DWORD max_conns_per_server;         // НОВА
    DWORD max_conns_per_1_0_server;     // НОВА
    unsigned int websocket_receive_buffer_size;
    unsigned int websocket_send_buffer_size;
};

struct connect {
    struct object_header hdr;
    struct session *session;
    WCHAR *hostname;
    WCHAR *servername;
    WCHAR *username;
    WCHAR *password;
    INTERNET_PORT hostport;
    INTERNET_PORT serverport;
};

struct request {
    struct object_header hdr;
    struct connect *connect;
    WCHAR *verb;
    WCHAR *path;
    WCHAR *version;
    WCHAR *raw_headers;
    WCHAR *status_text;
    struct header *headers;
    DWORD num_headers;
    DWORD security_flags;
    DWORD http_protocols;
    int resolve_timeout;
    int connect_timeout;
    int send_timeout;
    int receive_timeout;
    DWORD max_redirects;
    BOOL sent;
    BOOL upgrade_to_websocket;
    SOCKET_CONNECTION *socket_conn;
    DWORD status_code;
    char *response_buffer;
    DWORD response_len;
    DWORD response_pos;
};

struct socket {
    struct object_header hdr;
    struct request *request;
    USHORT status;
    char reason[128];
    DWORD reason_len;
    SOCKET_CONNECTION *ws_conn;
};

// ============================================================================
// HANDLE TABLE
// ============================================================================
static CRITICAL_SECTION handle_cs;
static BOOL handle_cs_initialized = FALSE;
static struct object_header **handles;
static ULONG_PTR next_handle;
static ULONG_PTR max_handles;

static void ensure_handle_cs_initialized(void) {
    if (!handle_cs_initialized) {
        InitializeCriticalSection(&handle_cs);
        handle_cs_initialized = TRUE;
    }
}

static struct object_header *addref_object(struct object_header *hdr) {
    InterlockedIncrement(&hdr->refs);
    return hdr;
}

static struct object_header *grab_object(HINTERNET hinternet) {
    struct object_header *hdr = NULL;
    ULONG_PTR handle = (ULONG_PTR)hinternet;
    
    EnterCriticalSection(&handle_cs);
    if ((handle > 0) && (handle <= max_handles) && handles[handle - 1])
        hdr = addref_object(handles[handle - 1]);
    LeaveCriticalSection(&handle_cs);
    
    return hdr;
}

static void send_callback(struct object_header *hdr, DWORD status, LPVOID info, DWORD buflen) {
    if (hdr->callback && (hdr->notify_mask & status)) {
        Log("  [CALLBACK] Status: 0x%08lX, Context: 0x%llX", status, (unsigned long long)hdr->context);
        hdr->callback(hdr->handle, hdr->context, status, info, buflen);
    }
}

static void release_object(struct object_header *hdr);

static HINTERNET alloc_handle(struct object_header *hdr) {
    struct object_header **p;
    ULONG_PTR handle, num;
    
    hdr->handle = NULL;
    EnterCriticalSection(&handle_cs);
    
    if (!max_handles) {
        num = HANDLE_CHUNK_SIZE;
        if (!(p = (struct object_header **)calloc(1, sizeof(*p) * num))) goto end;
        handles = p;
        max_handles = num;
    }
    if (max_handles == next_handle) {
        size_t new_size, old_size = max_handles * sizeof(*handles);
        num = max_handles * 2;
        new_size = num * sizeof(*handles);
        if (!(p = (struct object_header **)realloc(handles, new_size))) goto end;
        memset((char *)p + old_size, 0, new_size - old_size);
        handles = p;
        max_handles = num;
    }
    handle = next_handle;
    handles[handle] = addref_object(hdr);
    hdr->handle = (HINTERNET)(handle + 1);
    while ((next_handle < max_handles) && handles[next_handle]) next_handle++;
    
end:
    LeaveCriticalSection(&handle_cs);
    return hdr->handle;
}

static BOOL free_handle(HINTERNET hinternet) {
    BOOL ret = FALSE;
    ULONG_PTR handle = (ULONG_PTR)hinternet;
    struct object_header *hdr = NULL;
    
    EnterCriticalSection(&handle_cs);
    if ((handle > 0) && (handle <= max_handles)) {
        handle--;
        if (handles[handle]) {
            hdr = handles[handle];
            handles[handle] = NULL;
            ret = TRUE;
        }
    }
    LeaveCriticalSection(&handle_cs);
    
    if (hdr) {
        if (hdr->vtbl && hdr->vtbl->handle_closing)
            hdr->vtbl->handle_closing(hdr);
        release_object(hdr);
    }
    
    EnterCriticalSection(&handle_cs);
    if (next_handle > handle && !handles[handle]) next_handle = handle;
    LeaveCriticalSection(&handle_cs);
    
    return ret;
}

static void session_destroy(struct object_header *hdr);
static void connect_destroy(struct object_header *hdr);
static void request_destroy(struct object_header *hdr);
static void socket_destroy(struct object_header *hdr);

static void release_object(struct object_header *hdr) {
    if (!hdr) return;
    if (InterlockedDecrement(&hdr->refs) == 0) {
        send_callback(hdr, WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING, &hdr->handle, sizeof(HINTERNET));
        if (hdr->vtbl && hdr->vtbl->destroy)
            hdr->vtbl->destroy(hdr);
    }
}

// ============================================================================
// UTILITY
// ============================================================================
static WCHAR *strdupW(const WCHAR *src) {
    WCHAR *dst;
    if (!src) return NULL;
    if ((dst = (WCHAR *)malloc((wcslen(src) + 1) * sizeof(WCHAR))))
        wcscpy(dst, src);
    return dst;
}

// ============================================================================
// SESSION VTBL - Extended options support
// ============================================================================
static BOOL session_query_option(struct object_header *hdr, DWORD option, void *buffer, DWORD *buflen) {
    struct session *session = (struct session *)hdr;
    
    Log("  session_query_option: %s (%lu)", GetOptionName(option), option);
    
    switch (option) {
    case WINHTTP_OPTION_REDIRECT_POLICY:
        if (!buffer || *buflen < sizeof(DWORD)) { *buflen = sizeof(DWORD); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(DWORD *)buffer = hdr->redirect_policy;
        *buflen = sizeof(DWORD);
        return TRUE;
        
    case WINHTTP_OPTION_RESOLVE_TIMEOUT:
        if (!buffer || *buflen < sizeof(DWORD)) { *buflen = sizeof(DWORD); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(DWORD *)buffer = session->resolve_timeout;
        *buflen = sizeof(DWORD);
        return TRUE;
        
    case WINHTTP_OPTION_CONNECT_TIMEOUT:
        if (!buffer || *buflen < sizeof(DWORD)) { *buflen = sizeof(DWORD); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(DWORD *)buffer = session->connect_timeout;
        *buflen = sizeof(DWORD);
        return TRUE;
        
    case WINHTTP_OPTION_SEND_TIMEOUT:
        if (!buffer || *buflen < sizeof(DWORD)) { *buflen = sizeof(DWORD); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(DWORD *)buffer = session->send_timeout;
        *buflen = sizeof(DWORD);
        return TRUE;
        
    case WINHTTP_OPTION_RECEIVE_TIMEOUT:
        if (!buffer || *buflen < sizeof(DWORD)) { *buflen = sizeof(DWORD); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(DWORD *)buffer = session->receive_timeout;
        *buflen = sizeof(DWORD);
        return TRUE;
        
    case WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL:
        if (!buffer || *buflen < sizeof(DWORD)) { *buflen = sizeof(DWORD); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(DWORD *)buffer = session->http_protocols;
        *buflen = sizeof(DWORD);
        return TRUE;
        
    case WINHTTP_OPTION_ASSURED_NON_BLOCKING_CALLBACKS:
        if (!buffer || *buflen < sizeof(BOOL)) { *buflen = sizeof(BOOL); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(BOOL *)buffer = session->assured_non_blocking;
        *buflen = sizeof(BOOL);
        return TRUE;
        
    case WINHTTP_OPTION_HANDLE_TYPE:
        if (!buffer || *buflen < sizeof(DWORD)) { *buflen = sizeof(DWORD); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(DWORD *)buffer = WINHTTP_HANDLE_TYPE_SESSION;
        *buflen = sizeof(DWORD);
        return TRUE;
        
    default:
        Log("  -> Query option %lu NOT IMPLEMENTED", option);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
}

static BOOL session_set_option(struct object_header *hdr, DWORD option, void *buffer, DWORD buflen) {
    struct session *session = (struct session *)hdr;
    
    Log("  session_set_option: %s (%lu)", GetOptionName(option), option);
    
    switch (option) {
    case WINHTTP_OPTION_RESOLVE_TIMEOUT:  // 2
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->resolve_timeout = *(DWORD *)buffer;
        Log("    -> resolve_timeout = %d", session->resolve_timeout);
        return TRUE;
        
    case WINHTTP_OPTION_CONNECT_TIMEOUT:  // 3
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->connect_timeout = *(DWORD *)buffer;
        Log("    -> connect_timeout = %d", session->connect_timeout);
        return TRUE;
        
    case WINHTTP_OPTION_CONNECT_RETRIES:  // 4 - НОВА!
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->connect_retries = *(DWORD *)buffer;
        Log("    -> connect_retries = %d", session->connect_retries);
        return TRUE;
        
    case WINHTTP_OPTION_SEND_TIMEOUT:  // 5
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->send_timeout = *(DWORD *)buffer;
        Log("    -> send_timeout = %d", session->send_timeout);
        return TRUE;
        
    case WINHTTP_OPTION_RECEIVE_TIMEOUT:  // 6
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->receive_timeout = *(DWORD *)buffer;
        Log("    -> receive_timeout = %d", session->receive_timeout);
        return TRUE;
        
    case WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT:  // 7 - НОВА!
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        // Можна зберігати окремо або використовувати receive_timeout
        session->receive_timeout = *(DWORD *)buffer;
        Log("    -> receive_response_timeout = %d", session->receive_timeout);
        return TRUE;
    
    case WINHTTP_OPTION_REDIRECT_POLICY:  // 88
        if (buflen != sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        hdr->redirect_policy = *(DWORD *)buffer;
        Log("    -> redirect_policy = %lu", hdr->redirect_policy);
        return TRUE;
        
    case WINHTTP_OPTION_SECURE_PROTOCOLS:  // 84
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->secure_protocols = *(DWORD *)buffer;
        Log("    -> secure_protocols = 0x%lX", session->secure_protocols);
        return TRUE;
        
    case WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL:  // 133
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->http_protocols = *(DWORD *)buffer;
        Log("    -> http_protocols = 0x%lX (HTTP/2: %s, HTTP/3: %s)", 
            session->http_protocols, 
            (session->http_protocols & WINHTTP_PROTOCOL_FLAG_HTTP2) ? "YES" : "NO",
            (session->http_protocols & WINHTTP_PROTOCOL_FLAG_HTTP3) ? "YES" : "NO");
        return TRUE;
        
    case WINHTTP_OPTION_ASSURED_NON_BLOCKING_CALLBACKS:  // 111
        if (buflen < sizeof(BOOL)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->assured_non_blocking = *(BOOL *)buffer;
        Log("    -> assured_non_blocking = %s", session->assured_non_blocking ? "TRUE" : "FALSE");
        return TRUE;
        
    case WINHTTP_OPTION_DECOMPRESSION:  // 118
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->decompression = *(DWORD *)buffer;
        Log("    -> decompression = 0x%lX", session->decompression);
        return TRUE;
        
    case WINHTTP_OPTION_MAX_CONNS_PER_SERVER:  // 73
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->max_conns_per_server = *(DWORD *)buffer;
        Log("    -> max_conns_per_server = %lu", session->max_conns_per_server);
        return TRUE;
        
    case WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER:  // 74
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->max_conns_per_1_0_server = *(DWORD *)buffer;
        Log("    -> max_conns_per_1_0_server = %lu", session->max_conns_per_1_0_server);
        return TRUE;
        
    case WINHTTP_OPTION_TCP_FAST_OPEN:  // 153
        if (buflen < sizeof(BOOL)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->tcp_fast_open = *(BOOL *)buffer;
        Log("    -> tcp_fast_open = %s", session->tcp_fast_open ? "TRUE" : "FALSE");
        return TRUE;
        
    case WINHTTP_OPTION_TLS_FALSE_START:  // 154
        if (buflen < sizeof(BOOL)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->tls_false_start = *(BOOL *)buffer;
        Log("    -> tls_false_start = %s", session->tls_false_start ? "TRUE" : "FALSE");
        return TRUE;
        
    case WINHTTP_OPTION_WEB_SOCKET_RECEIVE_BUFFER_SIZE:  // 122
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->websocket_receive_buffer_size = *(DWORD *)buffer;
        Log("    -> websocket_receive_buffer_size = %u", session->websocket_receive_buffer_size);
        return TRUE;
        
    case WINHTTP_OPTION_WEB_SOCKET_SEND_BUFFER_SIZE:  // 123
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        session->websocket_send_buffer_size = *(DWORD *)buffer;
        Log("    -> websocket_send_buffer_size = %u", session->websocket_send_buffer_size);
        return TRUE;
        
    // Опції які приймаємо але не зберігаємо:
    case WINHTTP_OPTION_CODEPAGE:           // 68
    case WINHTTP_OPTION_WORKER_THREAD_COUNT:// 80
    case WINHTTP_OPTION_ENABLETRACING:      // 85
    case WINHTTP_OPTION_IPV6_FAST_FALLBACK: // 140
    case WINHTTP_OPTION_DISABLE_STREAM_QUEUE: // 139
    case WINHTTP_OPTION_BACKGROUND_CONNECTIONS: // 172
    case WINHTTP_OPTION_FIRST_AVAILABLE_CONNECTION: // 173
        Log("    -> Option accepted (not stored)");
        return TRUE;
        
    default:
        Log("    -> Option %lu NOT IMPLEMENTED (accepting anyway)", option);
        return TRUE;
    }
}

static void session_destroy(struct object_header *hdr) {
    struct session *session = (struct session *)hdr;
    Log("session_destroy(%p)", session);
    DeleteCriticalSection(&session->cs);
    free(session->agent);
    free(session->proxy_server);
    free(session->proxy_bypass);
    free(session->proxy_username);
    free(session->proxy_password);
    free(session);
}

static const struct object_vtbl session_vtbl = {
    NULL, session_destroy, session_query_option, session_set_option
};

// ============================================================================
// CONNECT VTBL
// ============================================================================
static BOOL connect_query_option(struct object_header *hdr, DWORD option, void *buffer, DWORD *buflen) {
    struct connect *connect = (struct connect *)hdr;
    
    Log("  connect_query_option: %s (%lu)", GetOptionName(option), option);
    
    switch (option) {
    case WINHTTP_OPTION_PARENT_HANDLE:
        if (!buffer || *buflen < sizeof(HINTERNET)) { *buflen = sizeof(HINTERNET); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(HINTERNET *)buffer = connect->session->hdr.handle;
        *buflen = sizeof(HINTERNET);
        return TRUE;
        
    case WINHTTP_OPTION_HANDLE_TYPE:
        if (!buffer || *buflen < sizeof(DWORD)) { *buflen = sizeof(DWORD); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(DWORD *)buffer = WINHTTP_HANDLE_TYPE_CONNECT;
        *buflen = sizeof(DWORD);
        return TRUE;
        
    default:
        Log("  -> Query option %lu NOT IMPLEMENTED", option);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
}

static BOOL connect_set_option(struct object_header *hdr, DWORD option, void *buffer, DWORD buflen) {
    Log("  connect_set_option: %s (%lu)", GetOptionName(option), option);
    // Accept all options
    return TRUE;
}

static void connect_destroy(struct object_header *hdr) {
    struct connect *connect = (struct connect *)hdr;
    Log("connect_destroy(%p)", connect);
    release_object(&connect->session->hdr);
    free(connect->hostname);
    free(connect->servername);
    free(connect->username);
    free(connect->password);
    free(connect);
}

static const struct object_vtbl connect_vtbl = {
    NULL, connect_destroy, connect_query_option, connect_set_option
};

// ============================================================================
// REQUEST VTBL - Extended options support
// ============================================================================
static BOOL request_query_option(struct object_header *hdr, DWORD option, void *buffer, DWORD *buflen) {
    struct request *request = (struct request *)hdr;
    
    Log("  request_query_option: %s (%lu)", GetOptionName(option), option);
    
    switch (option) {
    case WINHTTP_OPTION_HANDLE_TYPE:  // 9
        if (!buffer || *buflen < sizeof(DWORD)) { *buflen = sizeof(DWORD); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(DWORD *)buffer = WINHTTP_HANDLE_TYPE_REQUEST;
        *buflen = sizeof(DWORD);
        return TRUE;
        
    case WINHTTP_OPTION_PARENT_HANDLE:  // 21
        if (!buffer || *buflen < sizeof(HINTERNET)) { *buflen = sizeof(HINTERNET); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(HINTERNET *)buffer = request->connect->hdr.handle;
        *buflen = sizeof(HINTERNET);
        return TRUE;
        
    case WINHTTP_OPTION_SECURITY_FLAGS:  // 31
        if (!buffer || *buflen < sizeof(DWORD)) { *buflen = sizeof(DWORD); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(DWORD *)buffer = request->security_flags;
        *buflen = sizeof(DWORD);
        return TRUE;
        
    case WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT:  // 32
        Log("    -> No certificate (not connected)");
        SetLastError(ERROR_WINHTTP_INCORRECT_HANDLE_STATE);
        return FALSE;
        
    case WINHTTP_OPTION_SERVER_CERT_CONTEXT:  // 78
        Log("    -> No server certificate context");
        SetLastError(ERROR_WINHTTP_INCORRECT_HANDLE_STATE);
        return FALSE;
        
    case WINHTTP_OPTION_HTTP_PROTOCOL_USED:  // 134
        if (!buffer || *buflen < sizeof(DWORD)) { *buflen = sizeof(DWORD); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(DWORD *)buffer = 0;  // HTTP/1.1
        *buflen = sizeof(DWORD);
        return TRUE;
        
    case WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT:  // 147
        Log("    -> No certificate chain");
        SetLastError(ERROR_WINHTTP_INCORRECT_HANDLE_STATE);
        return FALSE;
        
    case WINHTTP_OPTION_CONNECTION_STATS_V1:  // 150
        Log("    -> Connection stats V1 not available");
        SetLastError(ERROR_WINHTTP_INCORRECT_HANDLE_STATE);
        return FALSE;
        
    case WINHTTP_OPTION_SECURITY_INFO:  // 151
        Log("    -> Security info not available");
        SetLastError(ERROR_WINHTTP_INCORRECT_HANDLE_STATE);
        return FALSE;
        
    case WINHTTP_OPTION_REQUEST_TIMES:  // 142
        Log("    -> Request times not available");
        SetLastError(ERROR_WINHTTP_INCORRECT_HANDLE_STATE);
        return FALSE;
        
    case WINHTTP_OPTION_REQUEST_STATS:  // 146
        Log("    -> Request stats not available");
        SetLastError(ERROR_WINHTTP_INCORRECT_HANDLE_STATE);
        return FALSE;
        
    default:
        Log("    -> Query option %lu NOT IMPLEMENTED", option);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
}

static BOOL request_set_option(struct object_header *hdr, DWORD option, void *buffer, DWORD buflen) {
    struct request *request = (struct request *)hdr;
    
    Log("  request_set_option: %s (%lu)", GetOptionName(option), option);
    
    switch (option) {
    case WINHTTP_OPTION_SECURITY_FLAGS:  // 31
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        request->security_flags = *(DWORD *)buffer;
        Log("    -> security_flags = 0x%lX", request->security_flags);
        return TRUE;
        
    case WINHTTP_OPTION_DISABLE_FEATURE:  // 63
        if (buflen != sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        hdr->disable_flags |= *(DWORD *)buffer;
        Log("    -> disable_flags |= 0x%lX", *(DWORD *)buffer);
        return TRUE;
        
    case WINHTTP_OPTION_AUTOLOGON_POLICY:  // 77
        if (buflen != sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        hdr->logon_policy = *(DWORD *)buffer;
        Log("    -> logon_policy = %lu", hdr->logon_policy);
        return TRUE;
        
    case WINHTTP_OPTION_ENABLE_FEATURE:  // 79 - НОВА!
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        Log("    -> enable_feature = 0x%lX", *(DWORD *)buffer);
        return TRUE;
        
    case WINHTTP_OPTION_REDIRECT_POLICY:  // 88
        if (buflen != sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        hdr->redirect_policy = *(DWORD *)buffer;
        Log("    -> redirect_policy = %lu", hdr->redirect_policy);
        return TRUE;
        
    case WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS:  // 89 - НОВА!
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        request->max_redirects = *(DWORD *)buffer;
        Log("    -> max_redirects = %lu", request->max_redirects);
        return TRUE;
        
    case WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL:  // 133
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        request->http_protocols = *(DWORD *)buffer;
        Log("    -> http_protocols = 0x%lX", request->http_protocols);
        return TRUE;
        
    case WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET:  // 114
        request->upgrade_to_websocket = TRUE;
        Log("    -> upgrade_to_websocket = TRUE");
        return TRUE;
        
    case WINHTTP_OPTION_RESOLVE_TIMEOUT:  // 2
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        request->resolve_timeout = *(DWORD *)buffer;
        Log("    -> resolve_timeout = %d", request->resolve_timeout);
        return TRUE;
        
    case WINHTTP_OPTION_CONNECT_TIMEOUT:  // 3
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        request->connect_timeout = *(DWORD *)buffer;
        Log("    -> connect_timeout = %d", request->connect_timeout);
        return TRUE;
        
    case WINHTTP_OPTION_SEND_TIMEOUT:  // 4
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        request->send_timeout = *(DWORD *)buffer;
        Log("    -> send_timeout = %d", request->send_timeout);
        return TRUE;
        
    case WINHTTP_OPTION_RECEIVE_TIMEOUT:  // 5
        if (buflen < sizeof(DWORD)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        request->receive_timeout = *(DWORD *)buffer;
        Log("    -> receive_timeout = %d", request->receive_timeout);
        return TRUE;
        
    default:
        Log("    -> Option %lu NOT IMPLEMENTED (accepting anyway)", option);
        return TRUE;
    }
}

static void request_destroy(struct object_header *hdr) {
    struct request *request = (struct request *)hdr;
    DWORD i;
    Log("request_destroy(%p)", request);
    
    if (request->socket_conn) {
        CloseSocketConnection(request->socket_conn);
        request->socket_conn = NULL;
    }
    
    release_object(&request->connect->hdr);
    free(request->verb);
    free(request->path);
    free(request->version);
    free(request->raw_headers);
    free(request->status_text);
    free(request->response_buffer);
    for (i = 0; i < request->num_headers; i++) {
        free(request->headers[i].field);
        free(request->headers[i].value);
    }
    free(request->headers);
    free(request);
}

static const struct object_vtbl request_vtbl = {
    NULL, request_destroy, request_query_option, request_set_option
};

// ============================================================================
// SOCKET VTBL
// ============================================================================
static void socket_destroy(struct object_header *hdr) {
    struct socket *socket = (struct socket *)hdr;
    Log("socket_destroy(%p)", socket);
    if (socket->ws_conn) {
        CloseSocketConnection(socket->ws_conn);
        socket->ws_conn = NULL;
    }
    if (socket->request) release_object(&socket->request->hdr);
    free(socket);
}

static const struct object_vtbl socket_vtbl = {
    NULL, socket_destroy, NULL, NULL
};

// ============================================================================
// DLL MAIN
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        ensure_handle_cs_initialized();
        
#if ENABLE_DEBUG_CONSOLE
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        SetConsoleTitleA("WinHTTP + exws2 Emulator");
#endif

        Log("========================================");
        Log("WinHTTP Emulator Loaded");
        Log("Mode: %s", FORCE_OFFLINE_MODE ? "OFFLINE" : "NETWORK ENABLED");
        Log("========================================");
        
        InitWinsock();
        break;

    case DLL_PROCESS_DETACH:
        Log("=== WinHTTP Emulator Unloading ===");
        CleanupWinsock();
        
        if (g_winsock_cs_initialized) {
            DeleteCriticalSection(&g_winsock_cs);
            g_winsock_cs_initialized = FALSE;
        }
        if (handle_cs_initialized) {
            DeleteCriticalSection(&handle_cs);
            handle_cs_initialized = FALSE;
        }
        if (handles) {
            free(handles);
            handles = NULL;
            max_handles = 0;
            next_handle = 0;
        }
#if ENABLE_DEBUG_CONSOLE
        FreeConsole();
#endif
        break;
    }
    return TRUE;
}

// ============================================================================
// CORE API
// ============================================================================
HINTERNET WINAPI ex_WinHttpOpen(LPCWSTR agent, DWORD access, LPCWSTR proxy, LPCWSTR bypass, DWORD flags) {
    struct session *session;
    HINTERNET handle = NULL;

    Log("WinHttpOpen(Agent:'%S', Access:%lu, Flags:0x%lX)", agent ? agent : L"<null>", access, flags);
    
    if (flags & WINHTTP_FLAG_ASYNC) {
        Log("  -> ASYNC mode enabled");
    }

    if (!(session = (struct session *)calloc(1, sizeof(*session)))) return NULL;

    session->hdr.type = WINHTTP_HANDLE_TYPE_SESSION;
    session->hdr.vtbl = &session_vtbl;
    session->hdr.flags = flags;
    session->hdr.refs = 1;
    session->hdr.redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    session->resolve_timeout = DEFAULT_RESOLVE_TIMEOUT;
    session->connect_timeout = DEFAULT_CONNECT_TIMEOUT;
    session->send_timeout = DEFAULT_SEND_TIMEOUT;
    session->receive_timeout = DEFAULT_RECEIVE_TIMEOUT;
    session->websocket_receive_buffer_size = 32768;
    session->websocket_send_buffer_size = 32768;
    session->http_protocols = 0;
    session->assured_non_blocking = FALSE;
    InitializeCriticalSection(&session->cs);

    if (agent) session->agent = strdupW(agent);
    session->access = access;
    if (proxy) session->proxy_server = strdupW(proxy);
    if (bypass) session->proxy_bypass = strdupW(bypass);

    if ((handle = alloc_handle(&session->hdr)))
        send_callback(&session->hdr, WINHTTP_CALLBACK_STATUS_HANDLE_CREATED, &handle, sizeof(handle));

    release_object(&session->hdr);
    Log("  -> SESSION: %p", handle);
    if (handle) SetLastError(ERROR_SUCCESS);
    return handle;
}

HINTERNET WINAPI ex_WinHttpConnect(HINTERNET hsession, LPCWSTR server, INTERNET_PORT port, DWORD reserved) {
    struct session *session;
    struct connect *connect;
    HINTERNET hconnect = NULL;

    Log("WinHttpConnect(Session:%p, Server:'%S', Port:%u)", hsession, server ? server : L"<null>", port);

    if (!server) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    if (!(session = (struct session *)grab_object(hsession))) { SetLastError(ERROR_INVALID_HANDLE); return NULL; }
    if (session->hdr.type != WINHTTP_HANDLE_TYPE_SESSION) {
        release_object(&session->hdr);
        SetLastError(ERROR_WINHTTP_INCORRECT_HANDLE_TYPE);
        return NULL;
    }
    if (!(connect = (struct connect *)calloc(1, sizeof(*connect)))) { release_object(&session->hdr); return NULL; }

    connect->hdr.type = WINHTTP_HANDLE_TYPE_CONNECT;
    connect->hdr.vtbl = &connect_vtbl;
    connect->hdr.refs = 1;
    connect->hdr.flags = session->hdr.flags;
    connect->hdr.callback = session->hdr.callback;
    connect->hdr.notify_mask = session->hdr.notify_mask;
    connect->hdr.context = session->hdr.context;
    connect->hdr.redirect_policy = session->hdr.redirect_policy;

    addref_object(&session->hdr);
    connect->session = session;
    connect->hostname = strdupW(server);
    connect->servername = strdupW(server);
    connect->hostport = port ? port : INTERNET_DEFAULT_HTTP_PORT;
    connect->serverport = connect->hostport;

    if ((hconnect = alloc_handle(&connect->hdr)))
        send_callback(&session->hdr, WINHTTP_CALLBACK_STATUS_HANDLE_CREATED, &hconnect, sizeof(hconnect));

    release_object(&connect->hdr);
    release_object(&session->hdr);
    Log("  -> CONNECT: %p", hconnect);
    if (hconnect) SetLastError(ERROR_SUCCESS);
    return hconnect;
}

HINTERNET WINAPI ex_WinHttpOpenRequest(HINTERNET hconnect, LPCWSTR verb, LPCWSTR object,
                                        LPCWSTR version, LPCWSTR referrer, LPCWSTR *types, DWORD flags) {
    struct connect *connect;
    struct request *request;
    HINTERNET hrequest = NULL;

    Log("WinHttpOpenRequest(Connect:%p, Verb:'%S', Path:'%S', Flags:0x%lX)",
        hconnect, verb ? verb : L"GET", object ? object : L"/", flags);

    if (!(connect = (struct connect *)grab_object(hconnect))) { SetLastError(ERROR_INVALID_HANDLE); return NULL; }
    if (connect->hdr.type != WINHTTP_HANDLE_TYPE_CONNECT) {
        release_object(&connect->hdr);
        SetLastError(ERROR_WINHTTP_INCORRECT_HANDLE_TYPE);
        return NULL;
    }
    if (!(request = (struct request *)calloc(1, sizeof(*request)))) { release_object(&connect->hdr); return NULL; }

    request->hdr.type = WINHTTP_HANDLE_TYPE_REQUEST;
    request->hdr.vtbl = &request_vtbl;
    request->hdr.refs = 1;
    request->hdr.flags = flags | (connect->hdr.flags & WINHTTP_FLAG_ASYNC);
    request->hdr.callback = connect->hdr.callback;
    request->hdr.notify_mask = connect->hdr.notify_mask;
    request->hdr.context = connect->hdr.context;
    request->hdr.redirect_policy = connect->hdr.redirect_policy;

    addref_object(&connect->hdr);
    request->connect = connect;

    request->verb = strdupW(verb && verb[0] ? verb : L"GET");
    if (!object || object[0] != '/') {
        DWORD len = object ? (DWORD)wcslen(object) : 0;
        request->path = (WCHAR *)malloc((len + 2) * sizeof(WCHAR));
        if (request->path) { request->path[0] = '/'; if (object) wcscpy(request->path + 1, object); else request->path[1] = 0; }
    } else request->path = strdupW(object);
    request->version = strdupW(version && version[0] ? version : L"HTTP/1.1");

    request->resolve_timeout = connect->session->resolve_timeout;
    request->connect_timeout = connect->session->connect_timeout;
    request->send_timeout = connect->session->send_timeout;
    request->receive_timeout = connect->session->receive_timeout;
    request->max_redirects = 10;
    request->http_protocols = connect->session->http_protocols;

    if ((hrequest = alloc_handle(&request->hdr)))
        send_callback(&request->hdr, WINHTTP_CALLBACK_STATUS_HANDLE_CREATED, &hrequest, sizeof(hrequest));

    release_object(&request->hdr);
    release_object(&connect->hdr);
    Log("  -> REQUEST: %p", hrequest);
    if (hrequest) SetLastError(ERROR_SUCCESS);
    return hrequest;
}

BOOL WINAPI ex_WinHttpCloseHandle(HINTERNET handle) {
    Log("WinHttpCloseHandle(%p)", handle);
    if (!handle) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (!free_handle(handle)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

// ============================================================================
// OPTIONS & CALLBACKS
// ============================================================================
BOOL WINAPI ex_WinHttpQueryOption(HINTERNET handle, DWORD option, void *buffer, DWORD *buflen) {
    struct object_header *hdr;
    BOOL ret = FALSE;

    Log("WinHttpQueryOption(Handle:%p, Option:%lu [%s])", handle, option, GetOptionName(option));
    if (!buflen) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!(hdr = grab_object(handle))) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }

    if (option == WINHTTP_OPTION_CONTEXT_VALUE) {
        if (!buffer || *buflen < sizeof(DWORD_PTR)) { 
            *buflen = sizeof(DWORD_PTR); 
            SetLastError(ERROR_INSUFFICIENT_BUFFER); 
        } else { 
            *(DWORD_PTR *)buffer = hdr->context; 
            *buflen = sizeof(DWORD_PTR); 
            ret = TRUE; 
        }
    } else if (hdr->vtbl && hdr->vtbl->query_option) {
        ret = hdr->vtbl->query_option(hdr, option, buffer, buflen);
    } else {
        SetLastError(ERROR_INVALID_PARAMETER);
    }

    release_object(hdr);
    if (ret) SetLastError(ERROR_SUCCESS);
    return ret;
}

BOOL WINAPI ex_WinHttpSetOption(HINTERNET handle, DWORD option, void *buffer, DWORD buflen) {
    struct object_header *hdr;
    BOOL ret = FALSE;

    Log("WinHttpSetOption(Handle:%p, Option:%lu [%s])", handle, option, GetOptionName(option));
    
    if (!(hdr = grab_object(handle))) { 
        SetLastError(ERROR_INVALID_HANDLE); 
        return FALSE; 
    }

    if (option == WINHTTP_OPTION_CONTEXT_VALUE) {
        if (buflen != sizeof(DWORD_PTR)) SetLastError(ERROR_INSUFFICIENT_BUFFER);
        else { hdr->context = *(DWORD_PTR *)buffer; ret = TRUE; }
    } else if (hdr->vtbl && hdr->vtbl->set_option) {
        ret = hdr->vtbl->set_option(hdr, option, buffer, buflen);
    } else {
        // Accept unknown options
        Log("  -> No vtbl handler, accepting option %lu", option);
        ret = TRUE;
    }

    release_object(hdr);
    if (ret) SetLastError(ERROR_SUCCESS);
    return ret;
}

BOOL WINAPI ex_WinHttpSetTimeouts(HINTERNET handle, int resolve, int connect, int send, int receive) {
    struct object_header *hdr;
    
    Log("WinHttpSetTimeouts(%p, R:%d, C:%d, S:%d, Rcv:%d)", handle, resolve, connect, send, receive);
    
    if (!(hdr = grab_object(handle))) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    
    if (hdr->type == WINHTTP_HANDLE_TYPE_SESSION) {
        struct session *session = (struct session *)hdr;
        session->resolve_timeout = resolve;
        session->connect_timeout = connect;
        session->send_timeout = send;
        session->receive_timeout = receive;
    } else if (hdr->type == WINHTTP_HANDLE_TYPE_REQUEST) {
        struct request *request = (struct request *)hdr;
        request->resolve_timeout = resolve;
        request->connect_timeout = connect;
        request->send_timeout = send;
        request->receive_timeout = receive;
    }
    
    release_object(hdr);
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

WINHTTP_STATUS_CALLBACK WINAPI ex_WinHttpSetStatusCallback(HINTERNET handle, WINHTTP_STATUS_CALLBACK callback,
                                                            DWORD flags, DWORD_PTR reserved) {
    struct object_header *hdr;
    WINHTTP_STATUS_CALLBACK ret;

    Log("WinHttpSetStatusCallback(%p, %p, 0x%lX)", handle, callback, flags);
    if (!(hdr = grab_object(handle))) { SetLastError(ERROR_INVALID_HANDLE); return WINHTTP_INVALID_STATUS_CALLBACK; }
    ret = hdr->callback;
    hdr->callback = callback;
    hdr->notify_mask = flags;
    release_object(hdr);
    SetLastError(ERROR_SUCCESS);
    return ret;
}

// ============================================================================
// NETWORK OPERATIONS
// ============================================================================
BOOL WINAPI ex_WinHttpSendRequest(HINTERNET hrequest, LPCWSTR headers, DWORD headers_len,
                                   LPVOID optional, DWORD optional_len, DWORD total_len, DWORD_PTR context) {
    struct request *request;
    BOOL success = FALSE;
    BOOL is_async;

    Log("WinHttpSendRequest(%p)", hrequest);
    
    if (!(request = (struct request *)grab_object(hrequest))) { 
        SetLastError(ERROR_INVALID_HANDLE); 
        return FALSE; 
    }
    if (request->hdr.type != WINHTTP_HANDLE_TYPE_REQUEST) {
        release_object(&request->hdr);
        SetLastError(ERROR_WINHTTP_INCORRECT_HANDLE_TYPE);
        return FALSE;
    }
    
    if (context) request->hdr.context = context;
    is_async = (request->hdr.flags & WINHTTP_FLAG_ASYNC) != 0;
    
    Log("  -> %S %S:%u%S (async=%s)", request->verb, request->connect->hostname, 
        request->connect->hostport, request->path, is_async ? "YES" : "NO");
    
    send_callback(&request->hdr, WINHTTP_CALLBACK_STATUS_SENDING_REQUEST, NULL, 0);
    
#if ENABLE_NETWORK_ATTEMPTS
    if (!request->socket_conn) {
        WORD port = request->connect->hostport;
        
        if (request->hdr.flags & WINHTTP_FLAG_SECURE) {
            if (port == INTERNET_DEFAULT_HTTP_PORT) port = INTERNET_DEFAULT_HTTPS_PORT;
        }
        
        send_callback(&request->hdr, WINHTTP_CALLBACK_STATUS_RESOLVING_NAME, 
                      (LPVOID)request->connect->hostname, 
                      (DWORD)((wcslen(request->connect->hostname) + 1) * sizeof(WCHAR)));
        
        request->socket_conn = CreateSocketConnection(request->connect->hostname, port);
        
        if (request->socket_conn) {
            send_callback(&request->hdr, WINHTTP_CALLBACK_STATUS_NAME_RESOLVED,
                          (LPVOID)request->connect->hostname,
                          (DWORD)((wcslen(request->connect->hostname) + 1) * sizeof(WCHAR)));
            
            if (request->socket_conn->connected) {
                send_callback(&request->hdr, WINHTTP_CALLBACK_STATUS_CONNECTED_TO_SERVER, NULL, 0);
                
                char http_request[4096];
                char hostA[256], pathA[1024], verbA[32];
                
                WideCharToMultiByte(CP_UTF8, 0, request->verb, -1, verbA, sizeof(verbA), NULL, NULL);
                WideCharToMultiByte(CP_UTF8, 0, request->connect->hostname, -1, hostA, sizeof(hostA), NULL, NULL);
                WideCharToMultiByte(CP_UTF8, 0, request->path, -1, pathA, sizeof(pathA), NULL, NULL);
                
                int len = snprintf(http_request, sizeof(http_request),
                    "%s %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "Connection: close\r\n"
                    "\r\n",
                    verbA, pathA, hostA);
                
                int sent = SocketSend(request->socket_conn, http_request, len);
                
                if (sent > 0) {
                    Log("  -> Sent %d bytes", sent);
                    request->sent = TRUE;
                    send_callback(&request->hdr, WINHTTP_CALLBACK_STATUS_REQUEST_SENT, &sent, sizeof(DWORD));
#if !FORCE_OFFLINE_MODE
                    success = TRUE;
#endif
                }
            }
        }
    }
#endif

    release_object(&request->hdr);
    
    if (!success) {
        Log("  -> BLOCKED: ERROR_WINHTTP_CANNOT_CONNECT");
        
        // In async mode, send error callback
        if (is_async) {
            WINHTTP_ASYNC_RESULT result;
            result.dwResult = API_SEND_REQUEST;
            result.dwError = ERROR_WINHTTP_CANNOT_CONNECT;
            // Would need to grab object again for callback
        }
        
        SetLastError(ERROR_WINHTTP_CANNOT_CONNECT);
        return FALSE;
    }
    
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI ex_WinHttpReceiveResponse(HINTERNET hrequest, LPVOID reserved) {
    Log("WinHttpReceiveResponse(%p) -> BLOCKED", hrequest);
    SetLastError(ERROR_WINHTTP_CANNOT_CONNECT);
    return FALSE;
}

BOOL WINAPI ex_WinHttpReadData(HINTERNET hrequest, LPVOID buffer, DWORD to_read, LPDWORD read) {
    Log("WinHttpReadData(%p, %lu bytes)", hrequest, to_read);
    if (read) *read = 0;
    SetLastError(ERROR_WINHTTP_CANNOT_CONNECT);
    return FALSE;
}

BOOL WINAPI ex_WinHttpWriteData(HINTERNET hrequest, LPCVOID buffer, DWORD to_write, LPDWORD written) {
    Log("WinHttpWriteData(%p, %lu bytes)", hrequest, to_write);
    if (written) *written = 0;
    SetLastError(ERROR_WINHTTP_CANNOT_CONNECT);
    return FALSE;
}

BOOL WINAPI ex_WinHttpQueryDataAvailable(HINTERNET hrequest, LPDWORD available) {
    Log("WinHttpQueryDataAvailable(%p)", hrequest);
    if (available) *available = 0;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI ex_WinHttpAddRequestHeaders(HINTERNET hrequest, LPCWSTR headers, DWORD len, DWORD modifiers) {
    Log("WinHttpAddRequestHeaders(%p)", hrequest);
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI ex_WinHttpQueryHeaders(HINTERNET hrequest, DWORD level, LPCWSTR name, 
                                    LPVOID buffer, LPDWORD buflen, LPDWORD index) {
    Log("WinHttpQueryHeaders(%p, Level:0x%lX)", hrequest, level);
    SetLastError(ERROR_WINHTTP_HEADER_NOT_FOUND);
    return FALSE;
}

// ============================================================================
// CREDENTIALS & AUTH
// ============================================================================
BOOL WINAPI ex_WinHttpSetCredentials(HINTERNET hrequest, DWORD target, DWORD scheme,
                                      LPCWSTR username, LPCWSTR password, LPVOID params) {
    Log("WinHttpSetCredentials()");
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI ex_WinHttpQueryAuthSchemes(HINTERNET hrequest, LPDWORD supported, LPDWORD first, LPDWORD target) {
    Log("WinHttpQueryAuthSchemes()");
    if (supported) *supported = 0;
    if (first) *first = 0;
    if (target) *target = 0;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

// ============================================================================
// URL FUNCTIONS
// ============================================================================
struct url_component {
    WCHAR **str;
    DWORD *len;
};

static DWORD set_component(struct url_component *comp, WCHAR *value, DWORD len, DWORD flags, BOOL *overflow) {
    if (*comp->str && !*comp->len) return ERROR_INVALID_PARAMETER;
    if (!*comp->len) return ERROR_SUCCESS;
    if (!*comp->str) {
        if (len && *comp->len && (flags & (ICU_DECODE|ICU_ESCAPE))) return ERROR_INVALID_PARAMETER;
        *comp->str = value;
        *comp->len = len;
    } else {
        if (len >= *comp->len) {
            *comp->len = len + 1;
            *overflow = TRUE;
            return ERROR_SUCCESS;
        }
        memcpy(*comp->str, value, len * sizeof(WCHAR));
        (*comp->str)[len] = 0;
        *comp->len = len;
    }
    return ERROR_SUCCESS;
}

static DWORD parse_port(const WCHAR *str, DWORD len, INTERNET_PORT *ret) {
    const WCHAR *p = str;
    DWORD port = 0;
    while (len && '0' <= *p && *p <= '9') {
        if ((port = port * 10 + *p - '0') > 65535) return ERROR_WINHTTP_INVALID_URL;
        p++; len--;
    }
    *ret = (INTERNET_PORT)port;
    return ERROR_SUCCESS;
}

BOOL WINAPI ex_WinHttpCrackUrl(const WCHAR *url, DWORD len, DWORD flags, URL_COMPONENTSW *uc) {
    WCHAR *p, *q, *r;
    INTERNET_SCHEME scheme_number = 0;
    struct url_component scheme, username, password, hostname, path, extra;
    BOOL overflow = FALSE;
    DWORD err = ERROR_SUCCESS;

    Log("WinHttpCrackUrl(Flags:0x%lX)", flags);

    if (!url || !uc || uc->dwStructSize != sizeof(*uc)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!len) len = (DWORD)wcslen(url);

    if (!(p = (WCHAR *)wcschr(url, ':'))) {
        SetLastError(ERROR_WINHTTP_UNRECOGNIZED_SCHEME);
        return FALSE;
    }
    if (p - url == 4 && !_wcsnicmp(url, L"http", 4)) scheme_number = INTERNET_SCHEME_HTTP;
    else if (p - url == 5 && !_wcsnicmp(url, L"https", 5)) scheme_number = INTERNET_SCHEME_HTTPS;
    else { SetLastError(ERROR_WINHTTP_UNRECOGNIZED_SCHEME); return FALSE; }

    scheme.str = &uc->lpszScheme; scheme.len = &uc->dwSchemeLength;
    if ((err = set_component(&scheme, (WCHAR *)url, (DWORD)(p - url), flags, &overflow))) goto exit;

    p++;
    if (p[0] != '/' || p[1] != '/') { err = ERROR_WINHTTP_INVALID_URL; goto exit; }
    p += 2;
    if (!p[0]) { err = ERROR_WINHTTP_INVALID_URL; goto exit; }

    username.str = &uc->lpszUserName; username.len = &uc->dwUserNameLength;
    password.str = &uc->lpszPassword; password.len = &uc->dwPasswordLength;

    if ((q = wmemchr(p, '@', len - (p - url))) && !(wmemchr(p, '/', q - p))) {
        if ((r = wmemchr(p, ':', q - p))) {
            if ((err = set_component(&username, (WCHAR*)p, (DWORD)(r - p), flags, &overflow))) goto exit;
            r++;
            if ((err = set_component(&password, r, (DWORD)(q - r), flags, &overflow))) goto exit;
        } else {
            if ((err = set_component(&username, (WCHAR*)p, (DWORD)(q - p), flags, &overflow))) goto exit;
            if ((err = set_component(&password, NULL, 0, flags, &overflow))) goto exit;
        }
        p = q + 1;
    } else {
        if ((err = set_component(&username, NULL, 0, flags, &overflow))) goto exit;
        if ((err = set_component(&password, NULL, 0, flags, &overflow))) goto exit;
    }

    hostname.str = &uc->lpszHostName; hostname.len = &uc->dwHostNameLength;
    path.str = &uc->lpszUrlPath; path.len = &uc->dwUrlPathLength;
    extra.str = &uc->lpszExtraInfo; extra.len = &uc->dwExtraInfoLength;

    uc->nPort = (scheme_number == INTERNET_SCHEME_HTTPS) ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;

    if ((q = wmemchr(p, '/', len - (p - url)))) {
        if ((r = wmemchr(p, ':', q - p))) {
            if ((err = set_component(&hostname, (WCHAR*)p, (DWORD)(r - p), flags, &overflow))) goto exit;
            r++;
            if (q - r > 0 && (err = parse_port(r, (DWORD)(q - r), &uc->nPort))) goto exit;
        } else {
            if ((err = set_component(&hostname, (WCHAR*)p, (DWORD)(q - p), flags, &overflow))) goto exit;
        }
        if ((r = wmemchr(q, '?', len - (q - url)))) {
            if (*extra.len) {
                if ((err = set_component(&path, q, (DWORD)(r - q), flags, &overflow))) goto exit;
                if ((err = set_component(&extra, r, len - (DWORD)(r - url), flags, &overflow))) goto exit;
            } else if ((err = set_component(&path, q, len - (DWORD)(q - url), flags, &overflow))) goto exit;
        } else {
            if ((err = set_component(&path, q, len - (DWORD)(q - url), flags, &overflow))) goto exit;
            if ((err = set_component(&extra, (WCHAR *)url + len, 0, flags, &overflow))) goto exit;
        }
    } else {
        if ((r = wmemchr(p, ':', len - (p - url)))) {
            if ((err = set_component(&hostname, (WCHAR*)p, (DWORD)(r - p), flags, &overflow))) goto exit;
            r++;
            if (len - (r - url) > 0 && (err = parse_port(r, len - (DWORD)(r - url), &uc->nPort))) goto exit;
        } else {
            if ((err = set_component(&hostname, (WCHAR*)p, len - (DWORD)(p - url), flags, &overflow))) goto exit;
        }
        if ((err = set_component(&path, (WCHAR *)url + len, 0, flags, &overflow))) goto exit;
        if ((err = set_component(&extra, (WCHAR *)url + len, 0, flags, &overflow))) goto exit;
    }

exit:
    if (!err) {
        if (overflow) err = ERROR_INSUFFICIENT_BUFFER;
        uc->nScheme = scheme_number;
    }

    SetLastError(err);
    return !err;
}

BOOL WINAPI ex_WinHttpCreateUrl(URL_COMPONENTSW *uc, DWORD flags, WCHAR *url, DWORD *required) {
    DWORD len;
    WCHAR *p;
    INTERNET_SCHEME scheme;

    Log("WinHttpCreateUrl(Flags:0x%lX)", flags);

    if (!uc || uc->dwStructSize != sizeof(URL_COMPONENTSW) || !required) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    scheme = uc->lpszScheme ? ((uc->dwSchemeLength == 5 && !_wcsnicmp(uc->lpszScheme, L"https", 5))
            ? INTERNET_SCHEME_HTTPS : INTERNET_SCHEME_HTTP)
            : (uc->nScheme ? uc->nScheme : INTERNET_SCHEME_HTTP);

    len = (scheme == INTERNET_SCHEME_HTTPS ? 5 : 4) + 3;
    if (uc->lpszUserName && uc->dwUserNameLength) {
        len += uc->dwUserNameLength + 1;
        if (uc->lpszPassword && uc->dwPasswordLength) len += uc->dwPasswordLength + 1;
    }
    if (uc->lpszHostName && uc->dwHostNameLength) {
        len += uc->dwHostNameLength;
        if (uc->nPort && uc->nPort != INTERNET_DEFAULT_HTTP_PORT && uc->nPort != INTERNET_DEFAULT_HTTPS_PORT)
            len += 6;
    }
    if (uc->lpszUrlPath && uc->dwUrlPathLength) {
        if (uc->lpszUrlPath[0] != '/') len++;
        len += uc->dwUrlPathLength;
    }
    if (uc->lpszExtraInfo && uc->dwExtraInfoLength) len += uc->dwExtraInfoLength;

    if (*required < len + 1) {
        *required = len + 1;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (!url) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }

    p = url;
    if (scheme == INTERNET_SCHEME_HTTPS) { memcpy(p, L"https", 5 * sizeof(WCHAR)); p += 5; }
    else { memcpy(p, L"http", 4 * sizeof(WCHAR)); p += 4; }
    *p++ = ':'; *p++ = '/'; *p++ = '/';

    if (uc->lpszUserName && uc->dwUserNameLength) {
        memcpy(p, uc->lpszUserName, uc->dwUserNameLength * sizeof(WCHAR)); p += uc->dwUserNameLength;
        if (uc->lpszPassword && uc->dwPasswordLength) {
            *p++ = ':';
            memcpy(p, uc->lpszPassword, uc->dwPasswordLength * sizeof(WCHAR)); p += uc->dwPasswordLength;
        }
        *p++ = '@';
    }
    if (uc->lpszHostName && uc->dwHostNameLength) {
        memcpy(p, uc->lpszHostName, uc->dwHostNameLength * sizeof(WCHAR)); p += uc->dwHostNameLength;
        if (uc->nPort && uc->nPort != INTERNET_DEFAULT_HTTP_PORT && uc->nPort != INTERNET_DEFAULT_HTTPS_PORT)
            p += swprintf(p, 7, L":%u", uc->nPort);
    }
    if (uc->lpszUrlPath && uc->dwUrlPathLength) {
        if (uc->lpszUrlPath[0] != '/') *p++ = '/';
        memcpy(p, uc->lpszUrlPath, uc->dwUrlPathLength * sizeof(WCHAR)); p += uc->dwUrlPathLength;
    }
    if (uc->lpszExtraInfo && uc->dwExtraInfoLength) {
        memcpy(p, uc->lpszExtraInfo, uc->dwExtraInfoLength * sizeof(WCHAR)); p += uc->dwExtraInfoLength;
    }
    *p = 0;
    *required = (DWORD)(p - url);

    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

// ============================================================================
// TIME FUNCTIONS
// ============================================================================
static const WCHAR wkday[7][4] = {L"Sun", L"Mon", L"Tue", L"Wed", L"Thu", L"Fri", L"Sat"};
static const WCHAR month[12][4] = {L"Jan", L"Feb", L"Mar", L"Apr", L"May", L"Jun",
                                   L"Jul", L"Aug", L"Sep", L"Oct", L"Nov", L"Dec"};

BOOL WINAPI ex_WinHttpTimeFromSystemTime(const SYSTEMTIME *time, LPWSTR string) {
    if (!time || !string) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    swprintf(string, WINHTTP_TIME_FORMAT_BUFSIZE / sizeof(WCHAR),
             L"%s, %02d %s %4d %02d:%02d:%02d GMT",
             wkday[time->wDayOfWeek % 7], time->wDay, month[(time->wMonth - 1) % 12],
             time->wYear, time->wHour, time->wMinute, time->wSecond);
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI ex_WinHttpTimeToSystemTime(LPCWSTR string, SYSTEMTIME *time) {
    unsigned int i;
    const WCHAR *s;
    WCHAR *end;

    if (!string || !time) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    GetSystemTime(time);
    s = string;
    while (*s && !iswalpha(*s)) s++;
    if (!s[0] || !s[1] || !s[2]) { SetLastError(ERROR_SUCCESS); return TRUE; }
    
    time->wDayOfWeek = 7;
    for (i = 0; i < 7; i++) {
        if (towupper(wkday[i][0]) == towupper(s[0]) && 
            towupper(wkday[i][1]) == towupper(s[1]) && 
            towupper(wkday[i][2]) == towupper(s[2])) {
            time->wDayOfWeek = (WORD)i; break;
        }
    }
    if (time->wDayOfWeek > 6) { SetLastError(ERROR_SUCCESS); return TRUE; }
    
    while (*s && !iswdigit(*s)) s++;
    time->wDay = (WORD)wcstol(s, &end, 10); s = end;
    while (*s && !iswalpha(*s)) s++;
    if (!s[0] || !s[1] || !s[2]) { SetLastError(ERROR_SUCCESS); return TRUE; }
    
    time->wMonth = 0;
    for (i = 0; i < 12; i++) {
        if (towupper(month[i][0]) == towupper(s[0]) && 
            towupper(month[i][1]) == towupper(s[1]) && 
            towupper(month[i][2]) == towupper(s[2])) {
            time->wMonth = (WORD)(i + 1); break;
        }
    }
    if (!time->wMonth) { SetLastError(ERROR_SUCCESS); return TRUE; }
    
    while (*s && !iswdigit(*s)) s++;
    if (!*s) { SetLastError(ERROR_SUCCESS); return TRUE; }
    time->wYear = (WORD)wcstol(s, &end, 10); s = end;
    while (*s && !iswdigit(*s)) s++;
    if (!*s) { SetLastError(ERROR_SUCCESS); return TRUE; }
    time->wHour = (WORD)wcstol(s, &end, 10); s = end;
    while (*s && !iswdigit(*s)) s++;
    if (!*s) { SetLastError(ERROR_SUCCESS); return TRUE; }
    time->wMinute = (WORD)wcstol(s, &end, 10); s = end;
    while (*s && !iswdigit(*s)) s++;
    if (!*s) { SetLastError(ERROR_SUCCESS); return TRUE; }
    time->wSecond = (WORD)wcstol(s, &end, 10);
    time->wMilliseconds = 0;
    
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

// ============================================================================
// PLATFORM & PROXY
// ============================================================================
BOOL WINAPI ex_WinHttpCheckPlatform(void) { 
    Log("WinHttpCheckPlatform() -> TRUE"); 
    return TRUE; 
}

BOOL WINAPI ex_WinHttpGetDefaultProxyConfiguration(WINHTTP_PROXY_INFO *info) {
    Log("WinHttpGetDefaultProxyConfiguration()");
    if (info) { 
        info->dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY; 
        info->lpszProxy = NULL; 
        info->lpszProxyBypass = NULL; 
    }
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI ex_WinHttpSetDefaultProxyConfiguration(WINHTTP_PROXY_INFO *info) {
    Log("WinHttpSetDefaultProxyConfiguration()");
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI ex_WinHttpGetIEProxyConfigForCurrentUser(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *config) {
    Log("WinHttpGetIEProxyConfigForCurrentUser()");
    if (config) { 
        memset(config, 0, sizeof(*config)); 
        config->fAutoDetect = FALSE; 
    }
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI ex_WinHttpGetProxyForUrl(HINTERNET hsession, LPCWSTR url, 
                                      WINHTTP_AUTOPROXY_OPTIONS *options, WINHTTP_PROXY_INFO *info) {
    Log("WinHttpGetProxyForUrl()");
    if (info) { 
        info->dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY; 
        info->lpszProxy = NULL; 
        info->lpszProxyBypass = NULL; 
    }
    SetLastError(ERROR_WINHTTP_AUTODETECTION_FAILED);
    return FALSE;
}

BOOL WINAPI ex_WinHttpDetectAutoProxyConfigUrl(DWORD flags, LPWSTR *url) {
    Log("WinHttpDetectAutoProxyConfigUrl()");
    if (url) *url = NULL;
    SetLastError(ERROR_WINHTTP_AUTODETECTION_FAILED);
    return FALSE;
}

// ============================================================================
// WEBSOCKET
// ============================================================================
HINTERNET WINAPI ex_WinHttpWebSocketCompleteUpgrade(HINTERNET hrequest, DWORD_PTR ctx) {
    Log("WinHttpWebSocketCompleteUpgrade() -> NULL");
    SetLastError(ERROR_WINHTTP_CANNOT_CONNECT);
    return NULL;
}

DWORD WINAPI ex_WinHttpWebSocketSend(HINTERNET ws, DWORD type, LPVOID buf, DWORD len) { 
    return ERROR_WINHTTP_CANNOT_CONNECT; 
}

DWORD WINAPI ex_WinHttpWebSocketReceive(HINTERNET ws, LPVOID buf, DWORD len, LPDWORD read, LPDWORD type) {
    if (read) *read = 0; 
    if (type) *type = 0; 
    return ERROR_WINHTTP_CANNOT_CONNECT;
}

DWORD WINAPI ex_WinHttpWebSocketShutdown(HINTERNET ws, USHORT status, LPVOID reason, DWORD len) { 
    return ERROR_SUCCESS; 
}

DWORD WINAPI ex_WinHttpWebSocketClose(HINTERNET ws, USHORT status, LPVOID reason, DWORD len) { 
    return ERROR_SUCCESS; 
}

DWORD WINAPI ex_WinHttpWebSocketQueryCloseStatus(HINTERNET ws, USHORT *status, LPVOID reason, 
                                                  DWORD len, LPDWORD consumed) {
    if (status) *status = 1000; 
    if (consumed) *consumed = 0; 
    return ERROR_SUCCESS;
}

// ============================================================================
// ALL REMAINING STUBS
// ============================================================================
DWORD WINAPI ex_WinHttpCreateProxyResolver(HINTERNET s, HINTERNET *r) { if (r) *r = NULL; return ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR; }
DWORD WINAPI ex_WinHttpGetProxyForUrlEx(HINTERNET r, LPCWSTR u, WINHTTP_AUTOPROXY_OPTIONS *o, DWORD_PTR c) { return ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR; }
DWORD WINAPI ex_WinHttpGetProxyForUrlEx2(HINTERNET r, LPCWSTR u, WINHTTP_AUTOPROXY_OPTIONS *o, DWORD l, BYTE *s, DWORD_PTR c) { return ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR; }
DWORD WINAPI ex_WinHttpGetProxyResult(HINTERNET r, LPVOID p) { return ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR; }
DWORD WINAPI ex_WinHttpGetProxyResultEx(HINTERNET r, LPVOID p) { return ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR; }
VOID WINAPI ex_WinHttpFreeProxyResult(LPVOID p) {}
VOID WINAPI ex_WinHttpFreeProxyResultEx(LPVOID p) {}
VOID WINAPI ex_WinHttpFreeProxySettings(LPVOID p) {}
DWORD WINAPI ex_WinHttpFreeProxySettingsEx(DWORD a, LPVOID p) { return 0; }
VOID WINAPI ex_WinHttpFreeQueryConnectionGroupResult(LPVOID p) {}
DWORD WINAPI ex_WinHttpResetAutoProxy(HINTERNET s, DWORD f) { return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpGetProxySettingsVersion(HINTERNET s, DWORD *v) { if (v) *v = 1; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpReadProxySettings(HINTERNET s, LPCWSTR c, BOOL u, BOOL a, DWORD *v, BOOL *d, LPVOID p) { if (v) *v = 1; if (d) *d = TRUE; return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpWriteProxySettings(HINTERNET s, BOOL f, LPVOID p) { return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpSetProxySettingsPerUser(BOOL p) { return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpRegisterProxyChangeNotification(ULONGLONG f, LPVOID c, LPVOID x, LPVOID r) { return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpUnregisterProxyChangeNotification(LPVOID r) { return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpAddRequestHeadersEx(HINTERNET r, DWORD m, ULONGLONG f, ULONGLONG e, DWORD c, LPVOID h) { return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpQueryHeadersEx(HINTERNET r, DWORD l, ULONGLONG f, UINT c, PDWORD i, LPVOID n, LPVOID b, PDWORD bl, LPVOID h, PDWORD hc) { return ERROR_WINHTTP_HEADER_NOT_FOUND; }
DWORD WINAPI ex_WinHttpReadDataEx(HINTERNET r, LPVOID b, DWORD l, LPDWORD rd, ULONGLONG f, DWORD ps, PVOID p) { if (rd) *rd = 0; return ERROR_WINHTTP_CANNOT_CONNECT; }
HRESULT WINAPI ex_DllCanUnloadNow(void) { return S_FALSE; }
HRESULT WINAPI ex_DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) { if (ppv) *ppv = NULL; return CLASS_E_CLASSNOTAVAILABLE; }
void WINAPI ex_Private1(void) {}
void WINAPI ex_SvchostPushServiceGlobals(LPVOID p) {}
void WINAPI ex_WinHttpAutoProxySvcMain(DWORD argc, LPWSTR *argv) {}
void WINAPI ex_WinHttpPacJsWorkerMain(LPVOID p) {}
DWORD WINAPI ex_WinHttpGetProxyForUrlHvsi(LPVOID a, LPVOID b, LPVOID c, LPVOID d) { return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpGetProxySettingsEx(HINTERNET s, DWORD t, LPVOID p, DWORD_PTR c) { return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpGetProxySettingsResultEx(HINTERNET r, LPVOID p) { return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpReadProxySettingsHvsi(LPVOID a, LPVOID b, LPVOID c, LPVOID d) { return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpConnectionDeletePolicyEntries(LPVOID p) { return 0; }
DWORD WINAPI ex_WinHttpConnectionDeleteProxyInfo(LPVOID p) { return 0; }
DWORD WINAPI ex_WinHttpConnectionFreeNameList(LPVOID p) { return 0; }
DWORD WINAPI ex_WinHttpConnectionFreeProxyInfo(LPVOID p) { return 0; }
DWORD WINAPI ex_WinHttpConnectionFreeProxyList(LPVOID p) { return 0; }
DWORD WINAPI ex_WinHttpConnectionGetNameList(LPVOID p) { return 0; }
DWORD WINAPI ex_WinHttpConnectionGetProxyInfo(LPVOID p) { return 0; }
DWORD WINAPI ex_WinHttpConnectionGetProxyList(LPVOID p) { return 0; }
DWORD WINAPI ex_WinHttpConnectionOnlyConvert(LPVOID a, LPVOID b) { return 0; }
DWORD WINAPI ex_WinHttpConnectionOnlyReceive(LPVOID a, LPVOID b) { return ERROR_WINHTTP_CANNOT_CONNECT; }
DWORD WINAPI ex_WinHttpConnectionOnlySend(LPVOID a, LPVOID b) { return ERROR_WINHTTP_CANNOT_CONNECT; }
DWORD WINAPI ex_WinHttpConnectionSetPolicyEntries(LPVOID p) { return 0; }
DWORD WINAPI ex_WinHttpConnectionSetProxyInfo(LPVOID p) { return 0; }
DWORD WINAPI ex_WinHttpConnectionUpdateIfIndexTable(LPVOID p) { return 0; }
DWORD WINAPI ex_WinHttpQueryConnectionGroup(HINTERNET h, const GUID *g, ULONGLONG f, LPVOID r) { return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpGetTunnelSocket(HINTERNET r, LPVOID s) { return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpProbeConnectivity(LPVOID a, LPVOID b, LPVOID c) { return ERROR_WINHTTP_CANNOT_CONNECT; }
DWORD WINAPI ex_WinHttpSaveProxyCredentials(LPVOID a, LPVOID b, LPVOID c) { return ERROR_SUCCESS; }
HINTERNET WINAPI ex_WinHttpProtocolCompleteUpgrade(HINTERNET r, DWORD_PTR c) { return NULL; }
DWORD WINAPI ex_WinHttpProtocolReceive(HINTERNET p, ULONGLONG f, LPVOID b, DWORD l, LPDWORD r) { return ERROR_WINHTTP_CANNOT_CONNECT; }
DWORD WINAPI ex_WinHttpProtocolSend(HINTERNET p, ULONGLONG f, LPVOID b, DWORD l) { return ERROR_WINHTTP_CANNOT_CONNECT; }
DWORD WINAPI ex_WinHttpCreateProxyList(LPVOID a, LPVOID b) { return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpCreateProxyManager(LPVOID a, LPVOID b) { return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpCreateProxyResult(LPVOID a, LPVOID b) { return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpCreateUiCompatibleProxyString(LPVOID a, DWORD b, LPVOID c, LPVOID d) { return ERROR_NOT_SUPPORTED; }
DWORD WINAPI ex_WinHttpRefreshProxySettings(HINTERNET s, LPVOID p) { return ERROR_SUCCESS; }
DWORD WINAPI ex_WinHttpResolverGetProxyForUrl(HINTERNET r, LPCWSTR u, LPVOID p) { return ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR; }
DWORD WINAPI ex_WinHttpSetSecureLegacyServersAppCompat(LPVOID a) { return ERROR_SUCCESS; }

#ifdef __cplusplus
}
#endif