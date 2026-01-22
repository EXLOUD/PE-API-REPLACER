#ifndef _WININET_INTERNAL_H_
#define _WININET_INTERNAL_H_

#define _CRT_SECURE_NO_WARNINGS
#define ENABLE_DEBUG_CONSOLE 1
#define ENABLE_FILE_LOGGING  1

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#pragma comment(lib, "exws2.lib")

// ============================================================
// WinSock declarations (для exws2.lib)
// ============================================================
#ifdef __cplusplus
extern "C" {
#endif

#ifndef _WINSOCK2API_
typedef unsigned int SOCKET;
#define INVALID_SOCKET  (SOCKET)(~0)
#define SOCKET_ERROR    (-1)
#define AF_INET         2
#define SOCK_STREAM     1
#define IPPROTO_TCP     6

struct in_addr {
    union {
        struct { unsigned char s_b1,s_b2,s_b3,s_b4; } S_un_b;
        struct { unsigned short s_w1,s_w2; } S_un_w;
        unsigned long S_addr;
    } S_un;
};

struct sockaddr_in {
    short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};

struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

struct hostent {
    char* h_name;
    char** h_aliases;
    short h_addrtype;
    short h_length;
    char** h_addr_list;
};
#define h_addr h_addr_list[0]

typedef struct {
    WORD wVersion;
    WORD wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char* lpVendorInfo;
} WSADATA;
#endif

int PASCAL WSAStartup(WORD wVersionRequested, WSADATA* lpWSAData);
int PASCAL WSACleanup(void);
int PASCAL WSAGetLastError(void);
SOCKET PASCAL socket(int af, int type, int protocol);
int PASCAL connect(SOCKET s, const struct sockaddr* name, int namelen);
int PASCAL send(SOCKET s, const char* buf, int len, int flags);
int PASCAL recv(SOCKET s, char* buf, int len, int flags);
int PASCAL closesocket(SOCKET s);
struct hostent* PASCAL gethostbyname(const char* name);
unsigned short PASCAL htons(unsigned short hostshort);
unsigned short PASCAL ntohs(unsigned short netshort);
unsigned long PASCAL htonl(unsigned long hostlong);
unsigned long PASCAL inet_addr(const char* cp);
int PASCAL select(int nfds, void* readfds, void* writefds, void* exceptfds, const void* timeout);
int PASCAL setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen);

#ifdef __cplusplus
}
#endif

// ============================================================
// WinINet Basic Types
// ============================================================

typedef LPVOID HINTERNET;
typedef HINTERNET* LPHINTERNET;
typedef WORD INTERNET_PORT;
typedef LONGLONG GROUPID;

// ============================================================
// Internet Scheme Enumeration
// ============================================================

typedef enum {
    INTERNET_SCHEME_PARTIAL = -2,
    INTERNET_SCHEME_UNKNOWN = -1,
    INTERNET_SCHEME_DEFAULT = 0,
    INTERNET_SCHEME_FTP,
    INTERNET_SCHEME_GOPHER,
    INTERNET_SCHEME_HTTP,
    INTERNET_SCHEME_HTTPS,
    INTERNET_SCHEME_FILE,
    INTERNET_SCHEME_NEWS,
    INTERNET_SCHEME_MAILTO,
    INTERNET_SCHEME_SOCKS,
    INTERNET_SCHEME_JAVASCRIPT,
    INTERNET_SCHEME_VBSCRIPT,
    INTERNET_SCHEME_RES,
    INTERNET_SCHEME_FIRST = INTERNET_SCHEME_FTP,
    INTERNET_SCHEME_LAST = INTERNET_SCHEME_RES
} INTERNET_SCHEME, *LPINTERNET_SCHEME;

// ============================================================
// Port Constants
// ============================================================

#define INTERNET_INVALID_PORT_NUMBER    0
#define INTERNET_DEFAULT_FTP_PORT       21
#define INTERNET_DEFAULT_GOPHER_PORT    70
#define INTERNET_DEFAULT_HTTP_PORT      80
#define INTERNET_DEFAULT_HTTPS_PORT     443
#define INTERNET_DEFAULT_SOCKS_PORT     1080

// ============================================================
// Max Length Constants
// ============================================================

#define INTERNET_MAX_HOST_NAME_LENGTH   256
#define INTERNET_MAX_USER_NAME_LENGTH   128
#define INTERNET_MAX_PASSWORD_LENGTH    128
#define INTERNET_MAX_PORT_NUMBER_LENGTH 5
#define INTERNET_MAX_PORT_NUMBER_VALUE  65535
#define INTERNET_MAX_PATH_LENGTH        2048
#define INTERNET_MAX_SCHEME_LENGTH      32
#define INTERNET_MAX_URL_LENGTH         (INTERNET_MAX_SCHEME_LENGTH + 3 + INTERNET_MAX_PATH_LENGTH)

// ============================================================
// Access Types for InternetOpen
// ============================================================

#define INTERNET_OPEN_TYPE_PRECONFIG                    0
#define INTERNET_OPEN_TYPE_DIRECT                       1
#define INTERNET_OPEN_TYPE_PROXY                        3
#define INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY  4

// ============================================================
// Service Types for InternetConnect
// ============================================================

#define INTERNET_SERVICE_FTP    1
#define INTERNET_SERVICE_GOPHER 2
#define INTERNET_SERVICE_HTTP   3

// ============================================================
// Handle Types
// ============================================================

#define INTERNET_HANDLE_TYPE_INTERNET           1
#define INTERNET_HANDLE_TYPE_CONNECT_FTP        2
#define INTERNET_HANDLE_TYPE_CONNECT_GOPHER     3
#define INTERNET_HANDLE_TYPE_CONNECT_HTTP       4
#define INTERNET_HANDLE_TYPE_FTP_FIND           5
#define INTERNET_HANDLE_TYPE_FTP_FIND_HTML      6
#define INTERNET_HANDLE_TYPE_FTP_FILE           7
#define INTERNET_HANDLE_TYPE_FTP_FILE_HTML      8
#define INTERNET_HANDLE_TYPE_GOPHER_FIND        9
#define INTERNET_HANDLE_TYPE_GOPHER_FIND_HTML   10
#define INTERNET_HANDLE_TYPE_GOPHER_FILE        11
#define INTERNET_HANDLE_TYPE_GOPHER_FILE_HTML   12
#define INTERNET_HANDLE_TYPE_HTTP_REQUEST       13
#define INTERNET_HANDLE_TYPE_FILE_REQUEST       14

// ============================================================
// Internet Flags
// ============================================================

#define INTERNET_FLAG_RELOAD            0x80000000
#define INTERNET_FLAG_RAW_DATA          0x40000000
#define INTERNET_FLAG_EXISTING_CONNECT  0x20000000
#define INTERNET_FLAG_ASYNC             0x10000000
#define INTERNET_FLAG_PASSIVE           0x08000000
#define INTERNET_FLAG_NO_CACHE_WRITE    0x04000000
#define INTERNET_FLAG_DONT_CACHE        INTERNET_FLAG_NO_CACHE_WRITE
#define INTERNET_FLAG_MAKE_PERSISTENT   0x02000000
#define INTERNET_FLAG_FROM_CACHE        0x01000000
#define INTERNET_FLAG_OFFLINE           INTERNET_FLAG_FROM_CACHE
#define INTERNET_FLAG_SECURE            0x00800000
#define INTERNET_FLAG_KEEP_CONNECTION   0x00400000
#define INTERNET_FLAG_NO_AUTO_REDIRECT  0x00200000
#define INTERNET_FLAG_READ_PREFETCH     0x00100000
#define INTERNET_FLAG_NO_COOKIES        0x00080000
#define INTERNET_FLAG_NO_AUTH           0x00040000
#define INTERNET_FLAG_RESTRICTED_ZONE   0x00020000
#define INTERNET_FLAG_CACHE_IF_NET_FAIL 0x00010000
#define INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP   0x00008000
#define INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS  0x00004000
#define INTERNET_FLAG_IGNORE_CERT_DATE_INVALID  0x00002000
#define INTERNET_FLAG_IGNORE_CERT_CN_INVALID    0x00001000
#define INTERNET_FLAG_RESYNCHRONIZE     0x00000800
#define INTERNET_FLAG_HYPERLINK         0x00000400
#define INTERNET_FLAG_NO_UI             0x00000200
#define INTERNET_FLAG_PRAGMA_NOCACHE    0x00000100
#define INTERNET_FLAG_CACHE_ASYNC       0x00000080
#define INTERNET_FLAG_FORMS_SUBMIT      0x00000040
#define INTERNET_FLAG_FWD_BACK          0x00000020
#define INTERNET_FLAG_NEED_FILE         0x00000010
#define INTERNET_FLAG_MUST_CACHE_REQUEST INTERNET_FLAG_NEED_FILE
#define INTERNET_FLAG_BGUPDATE          0x00000008

// ============================================================
// FTP Transfer Types
// ============================================================

#define FTP_TRANSFER_TYPE_UNKNOWN   0x00000000
#define FTP_TRANSFER_TYPE_ASCII     0x00000001
#define FTP_TRANSFER_TYPE_BINARY    0x00000002
#define INTERNET_FLAG_TRANSFER_ASCII    FTP_TRANSFER_TYPE_ASCII
#define INTERNET_FLAG_TRANSFER_BINARY   FTP_TRANSFER_TYPE_BINARY

// ============================================================
// INTERNET_OPTION_* for Query/SetOption
// ============================================================

#define INTERNET_OPTION_CALLBACK                1
#define INTERNET_OPTION_CONNECT_TIMEOUT         2
#define INTERNET_OPTION_CONNECT_RETRIES         3
#define INTERNET_OPTION_CONNECT_BACKOFF         4
#define INTERNET_OPTION_SEND_TIMEOUT            5
#define INTERNET_OPTION_CONTROL_SEND_TIMEOUT    INTERNET_OPTION_SEND_TIMEOUT
#define INTERNET_OPTION_RECEIVE_TIMEOUT         6
#define INTERNET_OPTION_CONTROL_RECEIVE_TIMEOUT INTERNET_OPTION_RECEIVE_TIMEOUT
#define INTERNET_OPTION_DATA_SEND_TIMEOUT       7
#define INTERNET_OPTION_DATA_RECEIVE_TIMEOUT    8
#define INTERNET_OPTION_HANDLE_TYPE             9
#define INTERNET_OPTION_LISTEN_TIMEOUT          11
#define INTERNET_OPTION_READ_BUFFER_SIZE        12
#define INTERNET_OPTION_WRITE_BUFFER_SIZE       13
#define INTERNET_OPTION_ASYNC_ID                15
#define INTERNET_OPTION_ASYNC_PRIORITY          16
#define INTERNET_OPTION_PARENT_HANDLE           21
#define INTERNET_OPTION_KEEP_CONNECTION         22
#define INTERNET_OPTION_REQUEST_FLAGS           23
#define INTERNET_OPTION_EXTENDED_ERROR          24
#define INTERNET_OPTION_OFFLINE_MODE            26
#define INTERNET_OPTION_CACHE_STREAM_HANDLE     27
#define INTERNET_OPTION_USERNAME                28
#define INTERNET_OPTION_PASSWORD                29
#define INTERNET_OPTION_ASYNC                   30
#define INTERNET_OPTION_SECURITY_FLAGS          31
#define INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT 32
#define INTERNET_OPTION_DATAFILE_NAME           33
#define INTERNET_OPTION_URL                     34
#define INTERNET_OPTION_SECURITY_CERTIFICATE    35
#define INTERNET_OPTION_SECURITY_KEY_BITNESS    36
#define INTERNET_OPTION_REFRESH                 37
#define INTERNET_OPTION_PROXY                   38
#define INTERNET_OPTION_SETTINGS_CHANGED        39
#define INTERNET_OPTION_VERSION                 40
#define INTERNET_OPTION_USER_AGENT              41
#define INTERNET_OPTION_END_BROWSER_SESSION     42
#define INTERNET_OPTION_PROXY_USERNAME          43
#define INTERNET_OPTION_PROXY_PASSWORD          44
#define INTERNET_OPTION_CONTEXT_VALUE           45
#define INTERNET_OPTION_CONNECT_LIMIT           46
#define INTERNET_OPTION_SECURITY_SELECT_CLIENT_CERT 47
#define INTERNET_OPTION_POLICY                  48
#define INTERNET_OPTION_DISCONNECTED_TIMEOUT    49
#define INTERNET_OPTION_CONNECTED_STATE         50
#define INTERNET_OPTION_IDLE_STATE              51
#define INTERNET_OPTION_OFFLINE_SEMANTICS       52
#define INTERNET_OPTION_SECONDARY_CACHE_KEY     53
#define INTERNET_OPTION_CALLBACK_FILTER         54
#define INTERNET_OPTION_CONNECT_TIME            55
#define INTERNET_OPTION_SEND_THROUGHPUT         56
#define INTERNET_OPTION_RECEIVE_THROUGHPUT      57
#define INTERNET_OPTION_REQUEST_PRIORITY        58
#define INTERNET_OPTION_HTTP_VERSION            59
#define INTERNET_OPTION_RESET_URLCACHE_SESSION  60
#define INTERNET_OPTION_ERROR_MASK              62
#define INTERNET_OPTION_FROM_CACHE_TIMEOUT      63
#define INTERNET_OPTION_BYPASS_EDITED_ENTRY     64
#define INTERNET_OPTION_HTTP_DECODING           65
#define INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO  67
#define INTERNET_OPTION_CODEPAGE                68
#define INTERNET_OPTION_CACHE_TIMESTAMPS        69
#define INTERNET_OPTION_DISABLE_AUTODIAL        70
#define INTERNET_OPTION_MAX_CONNS_PER_SERVER    73
#define INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER 74
#define INTERNET_OPTION_PER_CONNECTION_OPTION   75
#define INTERNET_OPTION_DIGEST_AUTH_UNLOAD      76
#define INTERNET_OPTION_IGNORE_OFFLINE          77
#define INTERNET_OPTION_IDENTITY                78
#define INTERNET_OPTION_REMOVE_IDENTITY         79
#define INTERNET_OPTION_ALTER_IDENTITY          80
#define INTERNET_OPTION_SUPPRESS_BEHAVIOR       81
#define INTERNET_OPTION_AUTODIAL_MODE           82
#define INTERNET_OPTION_AUTODIAL_CONNECTION     83
#define INTERNET_OPTION_CLIENT_CERT_CONTEXT     84
#define INTERNET_OPTION_AUTH_FLAGS              85
#define INTERNET_OPTION_COOKIES_3RD_PARTY       86
#define INTERNET_OPTION_DISABLE_PASSPORT_AUTH   87
#define INTERNET_OPTION_SEND_UTF8_SERVERNAME_TO_PROXY 88
#define INTERNET_OPTION_EXEMPT_CONNECTION_LIMIT 89
#define INTERNET_OPTION_ENABLE_PASSPORT_AUTH    90
#define INTERNET_OPTION_HIBERNATE_INACTIVE_WORKER_THREADS 91
#define INTERNET_OPTION_ACTIVATE_WORKER_THREADS 92
#define INTERNET_OPTION_RESTORE_WORKER_THREAD_DEFAULTS 93
#define INTERNET_OPTION_SOCKET_SEND_BUFFER_LENGTH 94
#define INTERNET_OPTION_PROXY_SETTINGS_CHANGED  95
#define INTERNET_OPTION_DATAFILE_EXT            96
#define INTERNET_OPTION_CODEPAGE_PATH           100
#define INTERNET_OPTION_CODEPAGE_EXTRA          101
#define INTERNET_OPTION_IDN                     102
#define INTERNET_OPTION_MAX_CONNS_PER_PROXY     103
#define INTERNET_OPTION_SUPPRESS_SERVER_AUTH    104
#define INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT 105

// ============================================================
// Connection State Flags
// ============================================================

#define INTERNET_STATE_CONNECTED                0x00000001
#define INTERNET_STATE_DISCONNECTED             0x00000002
#define INTERNET_STATE_DISCONNECTED_BY_USER     0x00000010
#define INTERNET_STATE_IDLE                     0x00000100
#define INTERNET_STATE_BUSY                     0x00000200

#define INTERNET_CONNECTION_MODEM           0x01
#define INTERNET_CONNECTION_LAN             0x02
#define INTERNET_CONNECTION_PROXY           0x04
#define INTERNET_CONNECTION_MODEM_BUSY      0x08
#define INTERNET_RAS_INSTALLED              0x10
#define INTERNET_CONNECTION_OFFLINE         0x20
#define INTERNET_CONNECTION_CONFIGURED      0x40

// ============================================================
// HTTP_QUERY_* for HttpQueryInfo
// ============================================================

#define HTTP_QUERY_MIME_VERSION                 0
#define HTTP_QUERY_CONTENT_TYPE                 1
#define HTTP_QUERY_CONTENT_TRANSFER_ENCODING    2
#define HTTP_QUERY_CONTENT_ID                   3
#define HTTP_QUERY_CONTENT_DESCRIPTION          4
#define HTTP_QUERY_CONTENT_LENGTH               5
#define HTTP_QUERY_CONTENT_LANGUAGE             6
#define HTTP_QUERY_ALLOW                        7
#define HTTP_QUERY_PUBLIC                       8
#define HTTP_QUERY_DATE                         9
#define HTTP_QUERY_EXPIRES                      10
#define HTTP_QUERY_LAST_MODIFIED                11
#define HTTP_QUERY_MESSAGE_ID                   12
#define HTTP_QUERY_URI                          13
#define HTTP_QUERY_DERIVED_FROM                 14
#define HTTP_QUERY_COST                         15
#define HTTP_QUERY_LINK                         16
#define HTTP_QUERY_PRAGMA                       17
#define HTTP_QUERY_VERSION                      18
#define HTTP_QUERY_STATUS_CODE                  19
#define HTTP_QUERY_STATUS_TEXT                  20
#define HTTP_QUERY_RAW_HEADERS                  21
#define HTTP_QUERY_RAW_HEADERS_CRLF             22
#define HTTP_QUERY_CONNECTION                   23
#define HTTP_QUERY_ACCEPT                       24
#define HTTP_QUERY_ACCEPT_CHARSET               25
#define HTTP_QUERY_ACCEPT_ENCODING              26
#define HTTP_QUERY_ACCEPT_LANGUAGE              27
#define HTTP_QUERY_AUTHORIZATION                28
#define HTTP_QUERY_CONTENT_ENCODING             29
#define HTTP_QUERY_FORWARDED                    30
#define HTTP_QUERY_FROM                         31
#define HTTP_QUERY_IF_MODIFIED_SINCE            32
#define HTTP_QUERY_LOCATION                     33
#define HTTP_QUERY_ORIG_URI                     34
#define HTTP_QUERY_REFERER                      35
#define HTTP_QUERY_RETRY_AFTER                  36
#define HTTP_QUERY_SERVER                       37
#define HTTP_QUERY_TITLE                        38
#define HTTP_QUERY_USER_AGENT                   39
#define HTTP_QUERY_WWW_AUTHENTICATE             40
#define HTTP_QUERY_PROXY_AUTHENTICATE           41
#define HTTP_QUERY_ACCEPT_RANGES                42
#define HTTP_QUERY_SET_COOKIE                   43
#define HTTP_QUERY_COOKIE                       44
#define HTTP_QUERY_REQUEST_METHOD               45
#define HTTP_QUERY_REFRESH                      46
#define HTTP_QUERY_CONTENT_DISPOSITION          47
#define HTTP_QUERY_AGE                          48
#define HTTP_QUERY_CACHE_CONTROL                49
#define HTTP_QUERY_CONTENT_BASE                 50
#define HTTP_QUERY_CONTENT_LOCATION             51
#define HTTP_QUERY_CONTENT_MD5                  52
#define HTTP_QUERY_CONTENT_RANGE                53
#define HTTP_QUERY_ETAG                         54
#define HTTP_QUERY_HOST                         55
#define HTTP_QUERY_IF_MATCH                     56
#define HTTP_QUERY_IF_NONE_MATCH                57
#define HTTP_QUERY_IF_RANGE                     58
#define HTTP_QUERY_IF_UNMODIFIED_SINCE          59
#define HTTP_QUERY_MAX_FORWARDS                 60
#define HTTP_QUERY_PROXY_AUTHORIZATION          61
#define HTTP_QUERY_RANGE                        62
#define HTTP_QUERY_TRANSFER_ENCODING            63
#define HTTP_QUERY_UPGRADE                      64
#define HTTP_QUERY_VARY                         65
#define HTTP_QUERY_VIA                          66
#define HTTP_QUERY_WARNING                      67
#define HTTP_QUERY_EXPECT                       68
#define HTTP_QUERY_PROXY_CONNECTION             69
#define HTTP_QUERY_UNLESS_MODIFIED_SINCE        70
#define HTTP_QUERY_CUSTOM                       65535

// HTTP_QUERY Flags
#define HTTP_QUERY_FLAG_REQUEST_HEADERS         0x80000000
#define HTTP_QUERY_FLAG_SYSTEMTIME              0x40000000
#define HTTP_QUERY_FLAG_NUMBER                  0x20000000
#define HTTP_QUERY_FLAG_COALESCE                0x10000000
#define HTTP_QUERY_FLAG_NUMBER64                0x08000000
#define HTTP_QUERY_FLAG_COALESCE_WITH_COMMA     0x04000000
#define HTTP_QUERY_MODIFIER_FLAGS_MASK          (HTTP_QUERY_FLAG_REQUEST_HEADERS \
                                                | HTTP_QUERY_FLAG_SYSTEMTIME \
                                                | HTTP_QUERY_FLAG_NUMBER \
                                                | HTTP_QUERY_FLAG_COALESCE \
                                                | HTTP_QUERY_FLAG_NUMBER64 \
                                                | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA)
#define HTTP_QUERY_HEADER_MASK                  (~HTTP_QUERY_MODIFIER_FLAGS_MASK)

// ============================================================
// HTTP Status Codes
// ============================================================

#define HTTP_STATUS_CONTINUE            100
#define HTTP_STATUS_SWITCH_PROTOCOLS    101
#define HTTP_STATUS_OK                  200
#define HTTP_STATUS_CREATED             201
#define HTTP_STATUS_ACCEPTED            202
#define HTTP_STATUS_PARTIAL             203
#define HTTP_STATUS_NO_CONTENT          204
#define HTTP_STATUS_RESET_CONTENT       205
#define HTTP_STATUS_PARTIAL_CONTENT     206
#define HTTP_STATUS_AMBIGUOUS           300
#define HTTP_STATUS_MOVED               301
#define HTTP_STATUS_REDIRECT            302
#define HTTP_STATUS_REDIRECT_METHOD     303
#define HTTP_STATUS_NOT_MODIFIED        304
#define HTTP_STATUS_USE_PROXY           305
#define HTTP_STATUS_REDIRECT_KEEP_VERB  307
#define HTTP_STATUS_PERMANENT_REDIRECT  308
#define HTTP_STATUS_BAD_REQUEST         400
#define HTTP_STATUS_DENIED              401
#define HTTP_STATUS_PAYMENT_REQ         402
#define HTTP_STATUS_FORBIDDEN           403
#define HTTP_STATUS_NOT_FOUND           404
#define HTTP_STATUS_BAD_METHOD          405
#define HTTP_STATUS_NONE_ACCEPTABLE     406
#define HTTP_STATUS_PROXY_AUTH_REQ      407
#define HTTP_STATUS_REQUEST_TIMEOUT     408
#define HTTP_STATUS_CONFLICT            409
#define HTTP_STATUS_GONE                410
#define HTTP_STATUS_LENGTH_REQUIRED     411
#define HTTP_STATUS_PRECOND_FAILED      412
#define HTTP_STATUS_REQUEST_TOO_LARGE   413
#define HTTP_STATUS_URI_TOO_LONG        414
#define HTTP_STATUS_UNSUPPORTED_MEDIA   415
#define HTTP_STATUS_RETRY_WITH          449
#define HTTP_STATUS_SERVER_ERROR        500
#define HTTP_STATUS_NOT_SUPPORTED       501
#define HTTP_STATUS_BAD_GATEWAY         502
#define HTTP_STATUS_SERVICE_UNAVAIL     503
#define HTTP_STATUS_GATEWAY_TIMEOUT     504
#define HTTP_STATUS_VERSION_NOT_SUP     505

// ============================================================
// HTTP_ADDREQ_* for HttpAddRequestHeaders
// ============================================================

#define HTTP_ADDREQ_INDEX_MASK          0x0000FFFF
#define HTTP_ADDREQ_FLAGS_MASK          0xFFFF0000
#define HTTP_ADDREQ_FLAG_ADD_IF_NEW     0x10000000
#define HTTP_ADDREQ_FLAG_ADD            0x20000000
#define HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA       0x40000000
#define HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON   0x01000000
#define HTTP_ADDREQ_FLAG_COALESCE       HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA
#define HTTP_ADDREQ_FLAG_REPLACE        0x80000000

// ============================================================
// Cookie Flags
// ============================================================

#define INTERNET_COOKIE_IS_SECURE       0x00000001
#define INTERNET_COOKIE_IS_SESSION      0x00000002
#define INTERNET_COOKIE_THIRD_PARTY     0x00000010
#define INTERNET_COOKIE_PROMPT_REQUIRED 0x00000020
#define INTERNET_COOKIE_EVALUATE_P3P    0x00000040
#define INTERNET_COOKIE_APPLY_P3P       0x00000080
#define INTERNET_COOKIE_P3P_ENABLED     0x00000100
#define INTERNET_COOKIE_IS_RESTRICTED   0x00000200
#define INTERNET_COOKIE_IE6             0x00000400
#define INTERNET_COOKIE_IS_LEGACY       0x00000800
#define INTERNET_COOKIE_NON_SCRIPT      0x00001000
#define INTERNET_COOKIE_HTTPONLY        0x00002000

// ============================================================
// Status Callback
// ============================================================

#define INTERNET_STATUS_RESOLVING_NAME          10
#define INTERNET_STATUS_NAME_RESOLVED           11
#define INTERNET_STATUS_CONNECTING_TO_SERVER    20
#define INTERNET_STATUS_CONNECTED_TO_SERVER     21
#define INTERNET_STATUS_SENDING_REQUEST         30
#define INTERNET_STATUS_REQUEST_SENT            31
#define INTERNET_STATUS_RECEIVING_RESPONSE      40
#define INTERNET_STATUS_RESPONSE_RECEIVED       41
#define INTERNET_STATUS_CTL_RESPONSE_RECEIVED   42
#define INTERNET_STATUS_PREFETCH                43
#define INTERNET_STATUS_CLOSING_CONNECTION      50
#define INTERNET_STATUS_CONNECTION_CLOSED       51
#define INTERNET_STATUS_HANDLE_CREATED          60
#define INTERNET_STATUS_HANDLE_CLOSING          70
#define INTERNET_STATUS_DETECTING_PROXY         80
#define INTERNET_STATUS_REQUEST_COMPLETE        100
#define INTERNET_STATUS_REDIRECT                110
#define INTERNET_STATUS_INTERMEDIATE_RESPONSE   120
#define INTERNET_STATUS_USER_INPUT_REQUIRED     140
#define INTERNET_STATUS_STATE_CHANGE            200
#define INTERNET_STATUS_COOKIE_SENT             320
#define INTERNET_STATUS_COOKIE_RECEIVED         321
#define INTERNET_STATUS_PRIVACY_IMPACTED        324
#define INTERNET_STATUS_P3P_HEADER              325
#define INTERNET_STATUS_P3P_POLICYREF           326
#define INTERNET_STATUS_COOKIE_HISTORY          327

// ============================================================
// Cache Entry Types
// ============================================================

#define NORMAL_CACHE_ENTRY              0x00000001
#define STICKY_CACHE_ENTRY              0x00000004
#define EDITED_CACHE_ENTRY              0x00000008
#define TRACK_OFFLINE_CACHE_ENTRY       0x00000010
#define TRACK_ONLINE_CACHE_ENTRY        0x00000020
#define SPARSE_CACHE_ENTRY              0x00010000
#define COOKIE_CACHE_ENTRY              0x00100000
#define URLHISTORY_CACHE_ENTRY          0x00200000

// ============================================================
// Privacy Templates
// ============================================================

#define PRIVACY_TEMPLATE_NO_COOKIES     0
#define PRIVACY_TEMPLATE_HIGH           1
#define PRIVACY_TEMPLATE_MEDIUM_HIGH    2
#define PRIVACY_TEMPLATE_MEDIUM         3
#define PRIVACY_TEMPLATE_MEDIUM_LOW     4
#define PRIVACY_TEMPLATE_LOW            5
#define PRIVACY_TEMPLATE_CUSTOM         100
#define PRIVACY_TEMPLATE_ADVANCED       101
#define PRIVACY_TEMPLATE_MAX            PRIVACY_TEMPLATE_LOW

#define PRIVACY_TYPE_FIRST_PARTY        0
#define PRIVACY_TYPE_THIRD_PARTY        1

// ============================================================
// Error Codes
// ============================================================

#define INTERNET_ERROR_BASE                     12000

#define ERROR_INTERNET_OUT_OF_HANDLES           (INTERNET_ERROR_BASE + 1)
#define ERROR_INTERNET_TIMEOUT                  (INTERNET_ERROR_BASE + 2)
#define ERROR_INTERNET_EXTENDED_ERROR           (INTERNET_ERROR_BASE + 3)
#define ERROR_INTERNET_INTERNAL_ERROR           (INTERNET_ERROR_BASE + 4)
#define ERROR_INTERNET_INVALID_URL              (INTERNET_ERROR_BASE + 5)
#define ERROR_INTERNET_UNRECOGNIZED_SCHEME      (INTERNET_ERROR_BASE + 6)
#define ERROR_INTERNET_NAME_NOT_RESOLVED        (INTERNET_ERROR_BASE + 7)
#define ERROR_INTERNET_PROTOCOL_NOT_FOUND       (INTERNET_ERROR_BASE + 8)
#define ERROR_INTERNET_INVALID_OPTION           (INTERNET_ERROR_BASE + 9)
#define ERROR_INTERNET_BAD_OPTION_LENGTH        (INTERNET_ERROR_BASE + 10)
#define ERROR_INTERNET_OPTION_NOT_SETTABLE      (INTERNET_ERROR_BASE + 11)
#define ERROR_INTERNET_SHUTDOWN                 (INTERNET_ERROR_BASE + 12)
#define ERROR_INTERNET_INCORRECT_USER_NAME      (INTERNET_ERROR_BASE + 13)
#define ERROR_INTERNET_INCORRECT_PASSWORD       (INTERNET_ERROR_BASE + 14)
#define ERROR_INTERNET_LOGIN_FAILURE            (INTERNET_ERROR_BASE + 15)
#define ERROR_INTERNET_INVALID_OPERATION        (INTERNET_ERROR_BASE + 16)
#define ERROR_INTERNET_OPERATION_CANCELLED      (INTERNET_ERROR_BASE + 17)
#define ERROR_INTERNET_INCORRECT_HANDLE_TYPE    (INTERNET_ERROR_BASE + 18)
#define ERROR_INTERNET_INCORRECT_HANDLE_STATE   (INTERNET_ERROR_BASE + 19)
#define ERROR_INTERNET_NOT_PROXY_REQUEST        (INTERNET_ERROR_BASE + 20)
#define ERROR_INTERNET_REGISTRY_VALUE_NOT_FOUND (INTERNET_ERROR_BASE + 21)
#define ERROR_INTERNET_BAD_REGISTRY_PARAMETER   (INTERNET_ERROR_BASE + 22)
#define ERROR_INTERNET_NO_DIRECT_ACCESS         (INTERNET_ERROR_BASE + 23)
#define ERROR_INTERNET_NO_CONTEXT               (INTERNET_ERROR_BASE + 24)
#define ERROR_INTERNET_NO_CALLBACK              (INTERNET_ERROR_BASE + 25)
#define ERROR_INTERNET_REQUEST_PENDING          (INTERNET_ERROR_BASE + 26)
#define ERROR_INTERNET_INCORRECT_FORMAT         (INTERNET_ERROR_BASE + 27)
#define ERROR_INTERNET_ITEM_NOT_FOUND           (INTERNET_ERROR_BASE + 28)
#define ERROR_INTERNET_CANNOT_CONNECT           (INTERNET_ERROR_BASE + 29)
#define ERROR_INTERNET_CONNECTION_ABORTED       (INTERNET_ERROR_BASE + 30)
#define ERROR_INTERNET_CONNECTION_RESET         (INTERNET_ERROR_BASE + 31)
#define ERROR_INTERNET_FORCE_RETRY              (INTERNET_ERROR_BASE + 32)
#define ERROR_INTERNET_INVALID_PROXY_REQUEST    (INTERNET_ERROR_BASE + 33)
#define ERROR_INTERNET_NEED_UI                  (INTERNET_ERROR_BASE + 34)
#define ERROR_INTERNET_HANDLE_EXISTS            (INTERNET_ERROR_BASE + 36)
#define ERROR_INTERNET_SEC_CERT_DATE_INVALID    (INTERNET_ERROR_BASE + 37)
#define ERROR_INTERNET_SEC_CERT_CN_INVALID      (INTERNET_ERROR_BASE + 38)
#define ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR   (INTERNET_ERROR_BASE + 39)
#define ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR   (INTERNET_ERROR_BASE + 40)
#define ERROR_INTERNET_MIXED_SECURITY           (INTERNET_ERROR_BASE + 41)
#define ERROR_INTERNET_CHG_POST_IS_NON_SECURE   (INTERNET_ERROR_BASE + 42)
#define ERROR_INTERNET_POST_IS_NON_SECURE       (INTERNET_ERROR_BASE + 43)
#define ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED  (INTERNET_ERROR_BASE + 44)
#define ERROR_INTERNET_INVALID_CA               (INTERNET_ERROR_BASE + 45)
#define ERROR_INTERNET_CLIENT_AUTH_NOT_SETUP    (INTERNET_ERROR_BASE + 46)
#define ERROR_INTERNET_ASYNC_THREAD_FAILED      (INTERNET_ERROR_BASE + 47)
#define ERROR_INTERNET_REDIRECT_SCHEME_CHANGE   (INTERNET_ERROR_BASE + 48)
#define ERROR_INTERNET_DIALOG_PENDING           (INTERNET_ERROR_BASE + 49)
#define ERROR_INTERNET_RETRY_DIALOG             (INTERNET_ERROR_BASE + 50)
#define ERROR_INTERNET_HTTPS_HTTP_SUBMIT_REDIR  (INTERNET_ERROR_BASE + 52)
#define ERROR_INTERNET_INSERT_CDROM             (INTERNET_ERROR_BASE + 53)
#define ERROR_INTERNET_FORTEZZA_LOGIN_NEEDED    (INTERNET_ERROR_BASE + 54)
#define ERROR_INTERNET_SEC_CERT_ERRORS          (INTERNET_ERROR_BASE + 55)
#define ERROR_INTERNET_SEC_CERT_NO_REV          (INTERNET_ERROR_BASE + 56)
#define ERROR_INTERNET_SEC_CERT_REV_FAILED      (INTERNET_ERROR_BASE + 57)
#define ERROR_HTTP_HSTS_REDIRECT_REQUIRED       (INTERNET_ERROR_BASE + 60)
#define ERROR_INTERNET_SEC_CERT_WEAK_SIGNATURE  (INTERNET_ERROR_BASE + 62)

// FTP Errors
#define ERROR_FTP_TRANSFER_IN_PROGRESS          (INTERNET_ERROR_BASE + 110)
#define ERROR_FTP_DROPPED                       (INTERNET_ERROR_BASE + 111)
#define ERROR_FTP_NO_PASSIVE_MODE               (INTERNET_ERROR_BASE + 112)

// Gopher Errors
#define ERROR_GOPHER_PROTOCOL_ERROR             (INTERNET_ERROR_BASE + 130)
#define ERROR_GOPHER_NOT_FILE                   (INTERNET_ERROR_BASE + 131)
#define ERROR_GOPHER_DATA_ERROR                 (INTERNET_ERROR_BASE + 132)
#define ERROR_GOPHER_END_OF_DATA                (INTERNET_ERROR_BASE + 133)
#define ERROR_GOPHER_INVALID_LOCATOR            (INTERNET_ERROR_BASE + 134)
#define ERROR_GOPHER_INCORRECT_LOCATOR_TYPE     (INTERNET_ERROR_BASE + 135)
#define ERROR_GOPHER_NOT_GOPHER_PLUS            (INTERNET_ERROR_BASE + 136)
#define ERROR_GOPHER_ATTRIBUTE_NOT_FOUND        (INTERNET_ERROR_BASE + 137)
#define ERROR_GOPHER_UNKNOWN_LOCATOR            (INTERNET_ERROR_BASE + 138)

// HTTP Errors
#define ERROR_HTTP_HEADER_NOT_FOUND             (INTERNET_ERROR_BASE + 150)
#define ERROR_HTTP_DOWNLEVEL_SERVER             (INTERNET_ERROR_BASE + 151)
#define ERROR_HTTP_INVALID_SERVER_RESPONSE      (INTERNET_ERROR_BASE + 152)
#define ERROR_HTTP_INVALID_HEADER               (INTERNET_ERROR_BASE + 153)
#define ERROR_HTTP_INVALID_QUERY_REQUEST        (INTERNET_ERROR_BASE + 154)
#define ERROR_HTTP_HEADER_ALREADY_EXISTS        (INTERNET_ERROR_BASE + 155)
#define ERROR_HTTP_REDIRECT_FAILED              (INTERNET_ERROR_BASE + 156)
#define ERROR_INTERNET_SECURITY_CHANNEL_ERROR   (INTERNET_ERROR_BASE + 157)
#define ERROR_INTERNET_UNABLE_TO_CACHE_FILE     (INTERNET_ERROR_BASE + 158)
#define ERROR_INTERNET_TCPIP_NOT_INSTALLED      (INTERNET_ERROR_BASE + 159)
#define ERROR_HTTP_NOT_REDIRECTED               (INTERNET_ERROR_BASE + 160)
#define ERROR_HTTP_COOKIE_NEEDS_CONFIRMATION    (INTERNET_ERROR_BASE + 161)
#define ERROR_HTTP_COOKIE_DECLINED              (INTERNET_ERROR_BASE + 162)
#define ERROR_INTERNET_DISCONNECTED             (INTERNET_ERROR_BASE + 163)
#define ERROR_INTERNET_SERVER_UNREACHABLE       (INTERNET_ERROR_BASE + 164)
#define ERROR_INTERNET_PROXY_SERVER_UNREACHABLE (INTERNET_ERROR_BASE + 165)
#define ERROR_INTERNET_BAD_AUTO_PROXY_SCRIPT    (INTERNET_ERROR_BASE + 166)
#define ERROR_INTERNET_UNABLE_TO_DOWNLOAD_SCRIPT (INTERNET_ERROR_BASE + 167)
#define ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION  (INTERNET_ERROR_BASE + 168)
#define ERROR_INTERNET_SEC_INVALID_CERT         (INTERNET_ERROR_BASE + 169)
#define ERROR_INTERNET_SEC_CERT_REVOKED         (INTERNET_ERROR_BASE + 170)
#define ERROR_INTERNET_FAILED_DUETOSECURITYCHECK (INTERNET_ERROR_BASE + 171)
#define ERROR_INTERNET_NOT_INITIALIZED          (INTERNET_ERROR_BASE + 172)
#define ERROR_INTERNET_NEED_MSN_SSPI_PKG        (INTERNET_ERROR_BASE + 173)
#define ERROR_INTERNET_LOGIN_FAILURE_DISPLAY_ENTITY_BODY (INTERNET_ERROR_BASE + 174)
#define ERROR_INTERNET_DECODING_FAILED          (INTERNET_ERROR_BASE + 175)

#define INTERNET_ERROR_LAST                     ERROR_INTERNET_DECODING_FAILED

// ============================================================
// Structures
// ============================================================

// URL_COMPONENTS
typedef struct {
    DWORD   dwStructSize;
    LPSTR   lpszScheme;
    DWORD   dwSchemeLength;
    INTERNET_SCHEME nScheme;
    LPSTR   lpszHostName;
    DWORD   dwHostNameLength;
    INTERNET_PORT nPort;
    LPSTR   lpszUserName;
    DWORD   dwUserNameLength;
    LPSTR   lpszPassword;
    DWORD   dwPasswordLength;
    LPSTR   lpszUrlPath;
    DWORD   dwUrlPathLength;
    LPSTR   lpszExtraInfo;
    DWORD   dwExtraInfoLength;
} URL_COMPONENTSA, *LPURL_COMPONENTSA;

typedef struct {
    DWORD   dwStructSize;
    LPWSTR  lpszScheme;
    DWORD   dwSchemeLength;
    INTERNET_SCHEME nScheme;
    LPWSTR  lpszHostName;
    DWORD   dwHostNameLength;
    INTERNET_PORT nPort;
    LPWSTR  lpszUserName;
    DWORD   dwUserNameLength;
    LPWSTR  lpszPassword;
    DWORD   dwPasswordLength;
    LPWSTR  lpszUrlPath;
    DWORD   dwUrlPathLength;
    LPWSTR  lpszExtraInfo;
    DWORD   dwExtraInfoLength;
} URL_COMPONENTSW, *LPURL_COMPONENTSW;

// INTERNET_BUFFERS
typedef struct _INTERNET_BUFFERSA {
    DWORD dwStructSize;
    struct _INTERNET_BUFFERSA* Next;
    LPCSTR  lpcszHeader;
    DWORD dwHeadersLength;
    DWORD dwHeadersTotal;
    LPVOID lpvBuffer;
    DWORD dwBufferLength;
    DWORD dwBufferTotal;
    DWORD dwOffsetLow;
    DWORD dwOffsetHigh;
} INTERNET_BUFFERSA, *LPINTERNET_BUFFERSA;

typedef struct _INTERNET_BUFFERSW {
    DWORD dwStructSize;
    struct _INTERNET_BUFFERSW* Next;
    LPCWSTR lpcszHeader;
    DWORD dwHeadersLength;
    DWORD dwHeadersTotal;
    LPVOID lpvBuffer;
    DWORD dwBufferLength;
    DWORD dwBufferTotal;
    DWORD dwOffsetLow;
    DWORD dwOffsetHigh;
} INTERNET_BUFFERSW, *LPINTERNET_BUFFERSW;

// INTERNET_CACHE_ENTRY_INFO
typedef struct _INTERNET_CACHE_ENTRY_INFOA {
    DWORD dwStructSize;
    LPSTR   lpszSourceUrlName;
    LPSTR   lpszLocalFileName;
    DWORD CacheEntryType;
    DWORD dwUseCount;
    DWORD dwHitRate;
    DWORD dwSizeLow;
    DWORD dwSizeHigh;
    FILETIME LastModifiedTime;
    FILETIME ExpireTime;
    FILETIME LastAccessTime;
    FILETIME LastSyncTime;
    LPSTR   lpHeaderInfo;
    DWORD dwHeaderInfoSize;
    LPSTR   lpszFileExtension;
    union {
        DWORD dwReserved;
        DWORD dwExemptDelta;
    };
} INTERNET_CACHE_ENTRY_INFOA, *LPINTERNET_CACHE_ENTRY_INFOA;

typedef struct _INTERNET_CACHE_ENTRY_INFOW {
    DWORD dwStructSize;
    LPWSTR  lpszSourceUrlName;
    LPWSTR  lpszLocalFileName;
    DWORD CacheEntryType;
    DWORD dwUseCount;
    DWORD dwHitRate;
    DWORD dwSizeLow;
    DWORD dwSizeHigh;
    FILETIME LastModifiedTime;
    FILETIME ExpireTime;
    FILETIME LastAccessTime;
    FILETIME LastSyncTime;
    LPWSTR  lpHeaderInfo;
    DWORD dwHeaderInfoSize;
    LPWSTR  lpszFileExtension;
    union {
        DWORD dwReserved;
        DWORD dwExemptDelta;
    };
} INTERNET_CACHE_ENTRY_INFOW, *LPINTERNET_CACHE_ENTRY_INFOW;

// INTERNET_CACHE_GROUP_INFO
#define GROUPNAME_MAX_LENGTH       120
#define GROUP_OWNER_STORAGE_SIZE   4

typedef struct _INTERNET_CACHE_GROUP_INFOA {
    DWORD           dwGroupSize;
    DWORD           dwGroupFlags;
    DWORD           dwGroupType;
    DWORD           dwDiskUsage;
    DWORD           dwDiskQuota;
    DWORD           dwOwnerStorage[GROUP_OWNER_STORAGE_SIZE];
    CHAR            szGroupName[GROUPNAME_MAX_LENGTH];
} INTERNET_CACHE_GROUP_INFOA, *LPINTERNET_CACHE_GROUP_INFOA;

typedef struct _INTERNET_CACHE_GROUP_INFOW {
    DWORD           dwGroupSize;
    DWORD           dwGroupFlags;
    DWORD           dwGroupType;
    DWORD           dwDiskUsage;
    DWORD           dwDiskQuota;
    DWORD           dwOwnerStorage[GROUP_OWNER_STORAGE_SIZE];
    WCHAR           szGroupName[GROUPNAME_MAX_LENGTH];
} INTERNET_CACHE_GROUP_INFOW, *LPINTERNET_CACHE_GROUP_INFOW;

// Gopher
#define MAX_GOPHER_DISPLAY_TEXT     128
#define MAX_GOPHER_SELECTOR_TEXT    256
#define MAX_GOPHER_HOST_NAME        INTERNET_MAX_HOST_NAME_LENGTH
#define MAX_GOPHER_LOCATOR_LENGTH   (1 + MAX_GOPHER_DISPLAY_TEXT + 1 + MAX_GOPHER_SELECTOR_TEXT + 1 + MAX_GOPHER_HOST_NAME + 1 + INTERNET_MAX_PORT_NUMBER_LENGTH + 1 + 1 + 2)

typedef struct {
    CHAR   DisplayString[MAX_GOPHER_DISPLAY_TEXT + 1];
    DWORD GopherType;
    DWORD SizeLow;
    DWORD SizeHigh;
    FILETIME LastModificationTime;
    CHAR   Locator[MAX_GOPHER_LOCATOR_LENGTH + 1];
} GOPHER_FIND_DATAA, *LPGOPHER_FIND_DATAA;

typedef struct {
    WCHAR  DisplayString[MAX_GOPHER_DISPLAY_TEXT + 1];
    DWORD GopherType;
    DWORD SizeLow;
    DWORD SizeHigh;
    FILETIME LastModificationTime;
    WCHAR  Locator[MAX_GOPHER_LOCATOR_LENGTH + 1];
} GOPHER_FIND_DATAW, *LPGOPHER_FIND_DATAW;

// ============================================================
// Internal Structures
// ============================================================

typedef enum {
    HANDLE_ROOT = INTERNET_HANDLE_TYPE_INTERNET,
    HANDLE_HTTP_CONNECT = INTERNET_HANDLE_TYPE_CONNECT_HTTP,
    HANDLE_HTTP_REQUEST = INTERNET_HANDLE_TYPE_HTTP_REQUEST,
    HANDLE_FTP_CONNECT = INTERNET_HANDLE_TYPE_CONNECT_FTP,
    HANDLE_FTP_FILE = INTERNET_HANDLE_TYPE_FTP_FILE
} HandleType;

typedef struct _HEADER {
    HandleType type;
    HINTERNET parent;
    SOCKET sock;
    
    char host[INTERNET_MAX_HOST_NAME_LENGTH];
    WORD port;
    DWORD flags;
    DWORD_PTR context;
    
    char verb[16];
    char path[INTERNET_MAX_PATH_LENGTH];
    char* request_headers;
    DWORD request_headers_len;
    
    DWORD status_code;
    char status_text[64];
    char* response_headers;
    DWORD response_headers_len;
    BOOL headers_received;
    
    DWORD content_length;
    DWORD content_read;
    char content_type[128];
    BOOL chunked;
    
    char* overflow_buffer;
    DWORD overflow_size;
    
    void* user_data;
} HEADER;

// ============================================================
// Globals & Functions
// ============================================================
extern BOOL g_wsInitialized;
extern HINSTANCE g_hInst;

BOOL InitWinsock(void);
void CleanupWinsock(void);
void Log(const char* fmt, ...);

// ============================================================
// Stub Macros
// ============================================================
#define STUB_TRUE(name)  BOOL WINAPI ex_##name(void) { Log(#name " (stub)"); return TRUE; }
#define STUB_FALSE(name) BOOL WINAPI ex_##name(void) { Log(#name " (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
#define STUB_NULL(name)  void* WINAPI ex_##name(void) { Log(#name " (stub)"); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
#define STUB_OK(name)    DWORD WINAPI ex_##name(void) { Log(#name " (stub)"); return ERROR_SUCCESS; }

// ============================================================
// Function Declarations
// ============================================================

// Core HTTP Functions
HINTERNET WINAPI ex_InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
HINTERNET WINAPI ex_InternetOpenW(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags);
HINTERNET WINAPI ex_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI ex_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI ex_HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI ex_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI ex_HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
BOOL WINAPI ex_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
BOOL WINAPI ex_HttpQueryInfoA(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
BOOL WINAPI ex_HttpQueryInfoW(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
BOOL WINAPI ex_HttpAddRequestHeadersA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
BOOL WINAPI ex_HttpAddRequestHeadersW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
BOOL WINAPI ex_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
BOOL WINAPI ex_InternetCloseHandle(HINTERNET hInternet);
BOOL WINAPI ex_InternetQueryOptionA(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);
BOOL WINAPI ex_InternetQueryOptionW(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);
BOOL WINAPI ex_InternetSetOptionA(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
BOOL WINAPI ex_InternetSetOptionW(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
BOOL WINAPI ex_InternetQueryDataAvailable(HINTERNET hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI ex_InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI ex_InternetOpenUrlW(HINTERNET hInternet, LPCWSTR lpszUrl, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI ex_InternetGetConnectedState(LPDWORD lpdwFlags, DWORD dwReserved);
BOOL WINAPI ex_InternetGetConnectedStateExA(LPDWORD lpdwFlags, LPSTR lpszConnectionName, DWORD cchNameLen, DWORD dwReserved);
BOOL WINAPI ex_InternetGetConnectedStateExW(LPDWORD lpdwFlags, LPWSTR lpszConnectionName, DWORD cchNameLen, DWORD dwReserved);
BOOL WINAPI ex_InternetCheckConnectionA(LPCSTR lpszUrl, DWORD dwFlags, DWORD dwReserved);
BOOL WINAPI ex_InternetCheckConnectionW(LPCWSTR lpszUrl, DWORD dwFlags, DWORD dwReserved);

// URL Functions
BOOL WINAPI ex_InternetCrackUrlA(LPCSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSA lpUrlComponents);
BOOL WINAPI ex_InternetCrackUrlW(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents);
BOOL WINAPI ex_InternetCreateUrlA(LPURL_COMPONENTSA lpUrlComponents, DWORD dwFlags, LPSTR lpszUrl, LPDWORD lpdwUrlLength);
BOOL WINAPI ex_InternetCreateUrlW(LPURL_COMPONENTSW lpUrlComponents, DWORD dwFlags, LPWSTR lpszUrl, LPDWORD lpdwUrlLength);
BOOL WINAPI ex_InternetCanonicalizeUrlA(LPCSTR lpszUrl, LPSTR lpszBuffer, LPDWORD lpdwBufferLength, DWORD dwFlags);
BOOL WINAPI ex_InternetCanonicalizeUrlW(LPCWSTR lpszUrl, LPWSTR lpszBuffer, LPDWORD lpdwBufferLength, DWORD dwFlags);
BOOL WINAPI ex_InternetCombineUrlA(LPCSTR lpszBaseUrl, LPCSTR lpszRelativeUrl, LPSTR lpszBuffer, LPDWORD lpdwBufferLength, DWORD dwFlags);
BOOL WINAPI ex_InternetCombineUrlW(LPCWSTR lpszBaseUrl, LPCWSTR lpszRelativeUrl, LPWSTR lpszBuffer, LPDWORD lpdwBufferLength, DWORD dwFlags);

// FTP Functions
HINTERNET WINAPI ex_FtpOpenFileA(HINTERNET hConnect, LPCSTR lpszFileName, DWORD dwAccess, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI ex_FtpOpenFileW(HINTERNET hConnect, LPCWSTR lpszFileName, DWORD dwAccess, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI ex_FtpPutFileA(HINTERNET hConnect, LPCSTR lpszLocalFile, LPCSTR lpszNewRemoteFile, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI ex_FtpPutFileW(HINTERNET hConnect, LPCWSTR lpszLocalFile, LPCWSTR lpszNewRemoteFile, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI ex_FtpGetFileA(HINTERNET hConnect, LPCSTR lpszRemoteFile, LPCSTR lpszNewFile, BOOL fFailIfExists, DWORD dwFlagsAndAttributes, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI ex_FtpGetFileW(HINTERNET hConnect, LPCWSTR lpszRemoteFile, LPCWSTR lpszNewFile, BOOL fFailIfExists, DWORD dwFlagsAndAttributes, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI ex_FtpDeleteFileA(HINTERNET hConnect, LPCSTR lpszFileName);
BOOL WINAPI ex_FtpDeleteFileW(HINTERNET hConnect, LPCWSTR lpszFileName);
BOOL WINAPI ex_FtpRenameFileA(HINTERNET hConnect, LPCSTR lpszExisting, LPCSTR lpszNew);
BOOL WINAPI ex_FtpRenameFileW(HINTERNET hConnect, LPCWSTR lpszExisting, LPCWSTR lpszNew);
BOOL WINAPI ex_FtpCreateDirectoryA(HINTERNET hConnect, LPCSTR lpszDirectory);
BOOL WINAPI ex_FtpCreateDirectoryW(HINTERNET hConnect, LPCWSTR lpszDirectory);
BOOL WINAPI ex_FtpRemoveDirectoryA(HINTERNET hConnect, LPCSTR lpszDirectory);
BOOL WINAPI ex_FtpRemoveDirectoryW(HINTERNET hConnect, LPCWSTR lpszDirectory);
BOOL WINAPI ex_FtpSetCurrentDirectoryA(HINTERNET hConnect, LPCSTR lpszDirectory);
BOOL WINAPI ex_FtpSetCurrentDirectoryW(HINTERNET hConnect, LPCWSTR lpszDirectory);
BOOL WINAPI ex_FtpGetCurrentDirectoryA(HINTERNET hConnect, LPSTR lpszCurrentDirectory, LPDWORD lpdwCurrentDirectory);
BOOL WINAPI ex_FtpGetCurrentDirectoryW(HINTERNET hConnect, LPWSTR lpszCurrentDirectory, LPDWORD lpdwCurrentDirectory);
BOOL WINAPI ex_FtpCommandA(HINTERNET hConnect, BOOL fExpectResponse, DWORD dwFlags, LPCSTR lpszCommand, DWORD_PTR dwContext, HINTERNET* phFtpCommand);
BOOL WINAPI ex_FtpCommandW(HINTERNET hConnect, BOOL fExpectResponse, DWORD dwFlags, LPCWSTR lpszCommand, DWORD_PTR dwContext, HINTERNET* phFtpCommand);
DWORD WINAPI ex_FtpGetFileSize(HINTERNET hFile, LPDWORD lpdwFileSizeHigh);
HINTERNET WINAPI ex_FtpFindFirstFileA(HINTERNET hConnect, LPCSTR lpszSearchFile, LPWIN32_FIND_DATAA lpFindFileData, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI ex_FtpFindFirstFileW(HINTERNET hConnect, LPCWSTR lpszSearchFile, LPWIN32_FIND_DATAW lpFindFileData, DWORD dwFlags, DWORD_PTR dwContext);

// Cookie Functions
BOOL WINAPI ex_InternetGetCookieA(LPCSTR lpszUrl, LPCSTR lpszCookieName, LPSTR lpszCookieData, LPDWORD lpdwSize);
BOOL WINAPI ex_InternetGetCookieW(LPCWSTR lpszUrl, LPCWSTR lpszCookieName, LPWSTR lpszCookieData, LPDWORD lpdwSize);
BOOL WINAPI ex_InternetSetCookieA(LPCSTR lpszUrl, LPCSTR lpszCookieName, LPCSTR lpszCookieData);
BOOL WINAPI ex_InternetSetCookieW(LPCWSTR lpszUrl, LPCWSTR lpszCookieName, LPCWSTR lpszCookieData);
BOOL WINAPI ex_InternetGetCookieExA(LPCSTR url, LPCSTR name, LPSTR data, LPDWORD size, DWORD flags, LPVOID reserved);
BOOL WINAPI ex_InternetGetCookieExW(LPCWSTR url, LPCWSTR name, LPWSTR data, LPDWORD size, DWORD flags, LPVOID reserved);
DWORD WINAPI ex_InternetSetCookieExA(LPCSTR lpszUrl, LPCSTR lpszCookieName, LPCSTR lpszCookieData, DWORD dwFlags, DWORD_PTR dwReserved);
DWORD WINAPI ex_InternetSetCookieExW(LPCWSTR lpszUrl, LPCWSTR lpszCookieName, LPCWSTR lpszCookieData, DWORD dwFlags, DWORD_PTR dwReserved);

// Cache Functions
BOOL WINAPI ex_CommitUrlCacheEntryA(LPCSTR lpszUrlName, LPCSTR lpszLocalFileName, FILETIME ExpireTime, FILETIME LastModifiedTime, DWORD CacheEntryType, LPBYTE lpHeaderInfo, DWORD dwHeaderSize, LPCSTR lpszFileExtension, LPCSTR lpszOriginalUrl);
BOOL WINAPI ex_CommitUrlCacheEntryW(LPCWSTR lpszUrlName, LPCWSTR lpszLocalFileName, FILETIME ExpireTime, FILETIME LastModifiedTime, DWORD CacheEntryType, LPBYTE lpHeaderInfo, DWORD dwHeaderSize, LPCWSTR lpszFileExtension, LPCWSTR lpszOriginalUrl);
BOOL WINAPI ex_CreateUrlCacheEntryA(LPCSTR lpszUrlName, DWORD dwExpectedFileSize, LPCSTR lpszFileExtension, LPSTR lpszFileName, DWORD dwReserved);
BOOL WINAPI ex_CreateUrlCacheEntryW(LPCWSTR lpszUrlName, DWORD dwExpectedFileSize, LPCWSTR lpszFileExtension, LPWSTR lpszFileName, DWORD dwReserved);
BOOL WINAPI ex_DeleteUrlCacheEntryA(LPCSTR lpszUrlName);
BOOL WINAPI ex_DeleteUrlCacheEntryW(LPCWSTR lpszUrlName);
BOOL WINAPI ex_GetUrlCacheEntryInfoA(LPCSTR lpszUrlName, LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo, LPDWORD lpdwCacheEntryInfoBufferSize);
BOOL WINAPI ex_GetUrlCacheEntryInfoW(LPCWSTR lpszUrlName, LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo, LPDWORD lpdwCacheEntryInfoBufferSize);

// DLL Entry Points
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
HRESULT WINAPI ex_DllCanUnloadNow(void);
HRESULT WINAPI ex_DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv);
HRESULT WINAPI ex_DllInstall(BOOL bInstall, LPCWSTR pszCmdLine);
HRESULT WINAPI ex_DllRegisterServer(void);
HRESULT WINAPI ex_DllUnregisterServer(void);

#endif // _WININET_INTERNAL_H_