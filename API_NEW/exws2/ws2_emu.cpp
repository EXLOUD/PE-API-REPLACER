// =========================================================================================
// Winsock2 Emulator v2.1.1 (optimized byte swap with compiler intrinsics)
// =========================================================================================

#define ENABLE_CONSOLE_LOGGING 0

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <mswsock.h>
#include <wsipx.h>
#include <windns.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <limits.h>
#include <stddef.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")

// =============================================================================
// LOGGING SYSTEM
// =============================================================================

#if ENABLE_CONSOLE_LOGGING
    static BOOL g_bConsoleInit = FALSE;
    static void InitConsole() {
        if (g_bConsoleInit) return;
        AllocConsole();
        FILE* fp;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        SetConsoleTitleA("WS2_EMU Debug Console v2.1");
        printf("[WS2_EMU] Logging started...\n");
        g_bConsoleInit = TRUE;
    }
    #define LOG(fmt, ...) do { printf("[WS2_EMU] " fmt "\n", ##__VA_ARGS__); } while(0)
    #define LOG_MSG(msg) printf("[WS2_EMU] %s\n", msg)
#else
    #define InitConsole()
    #define LOG(fmt, ...)
    #define LOG_MSG(msg)
#endif

// =============================================================================
// COMPATIBILITY & MACROS
// =============================================================================

#if defined(__GNUC__) || defined(__clang__)
    #define TLS __thread
#else
    #define TLS __declspec(thread)
#endif

#ifndef STATUS_PENDING
#define STATUS_PENDING ((LONG)0x00000103L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((LONG)0xC000000DL)
#endif

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif

// EXLOUD Registry Configuration
#define EXLOUD_REG_KEY "Software\\EXLOUD\\Config"
#define REG_COMPUTER_NAME "ComputerName"

// Socket options
#ifndef SO_PROTOCOL_INFOA
#define SO_PROTOCOL_INFOA   0x2004
#define SO_PROTOCOL_INFOW   0x2005
#endif

#ifndef SO_EXCLUSIVEADDRUSE
#define SO_EXCLUSIVEADDRUSE ((int)(~SO_REUSEADDR))
#endif

#ifndef SO_CONNECT_TIME
#define SO_CONNECT_TIME     0x700C
#endif

#ifndef TCP_NODELAY
#define TCP_NODELAY         0x0001
#endif

// Address families
#ifndef AF_IPX
#define AF_IPX              6
#endif

#ifndef AF_INET6
#define AF_INET6            23
#endif

// IPv6 options
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY         27
#endif

#ifndef IPV6_JOIN_GROUP
#define IPV6_JOIN_GROUP     12
#define IPV6_LEAVE_GROUP    13
#endif

#ifndef IPV6_UNICAST_HOPS
#define IPV6_UNICAST_HOPS   4
#define IPV6_MULTICAST_HOPS 10
#define IPV6_MULTICAST_LOOP 11
#endif

#ifndef IP_TOS
#define IP_TOS              3
#endif
#ifndef IP_TTL
#define IP_TTL              4
#endif
#ifndef IP_DONTFRAGMENT
#define IP_DONTFRAGMENT     14
#endif
#ifndef IP_MULTICAST_TTL
#define IP_MULTICAST_TTL    10
#endif
#ifndef IP_MULTICAST_LOOP
#define IP_MULTICAST_LOOP   11
#endif
#ifndef IP_ADD_MEMBERSHIP
#define IP_ADD_MEMBERSHIP   12
#endif
#ifndef IP_DROP_MEMBERSHIP
#define IP_DROP_MEMBERSHIP  13
#endif

// IPX/SPX protocols
#ifndef NSPROTO_IPX
#define NSPROTO_IPX         1000
#define NSPROTO_SPX         1256
#define NSPROTO_SPXII       1257
#endif

// Service flags (XP1_*)
#ifndef XP1_CONNECTIONLESS
#define XP1_CONNECTIONLESS          0x00000001
#define XP1_GUARANTEED_DELIVERY     0x00000002
#define XP1_GUARANTEED_ORDER        0x00000004
#define XP1_MESSAGE_ORIENTED        0x00000008
#define XP1_PSEUDO_STREAM           0x00000010
#define XP1_GRACEFUL_CLOSE          0x00000020
#define XP1_EXPEDITED_DATA          0x00000040
#define XP1_CONNECT_DATA            0x00000080
#define XP1_DISCONNECT_DATA         0x00000100
#define XP1_SUPPORT_BROADCAST       0x00000200
#define XP1_SUPPORT_MULTIPOINT      0x00000400
#define XP1_MULTIPOINT_CONTROL_PLANE 0x00000800
#define XP1_MULTIPOINT_DATA_PLANE   0x00001000
#define XP1_QOS_SUPPORTED           0x00002000
#define XP1_INTERRUPT               0x00004000
#define XP1_UNI_SEND                0x00008000
#define XP1_UNI_RECV                0x00010000
#define XP1_IFS_HANDLES             0x00020000
#define XP1_PARTIAL_MESSAGE         0x00040000
#define XP1_SAN_SUPPORT_SDP         0x00080000
#endif

// Provider flags (PFL_*)
#ifndef PFL_MULTIPLE_PROTO_ENTRIES
#define PFL_MULTIPLE_PROTO_ENTRIES  0x00000001
#define PFL_RECOMMENDED_PROTO_ENTRY 0x00000002
#define PFL_HIDDEN                  0x00000004
#define PFL_MATCHES_PROTOCOL_ZERO   0x00000008
#define PFL_NETWORKDIRECT_PROVIDER  0x00000010
#endif

// Network byte order
#ifndef BIGENDIAN
#define BIGENDIAN           0x0000
#define LITTLEENDIAN        0x0001
#endif

// Security scheme
#ifndef SECURITY_PROTOCOL_NONE
#define SECURITY_PROTOCOL_NONE  0x0000
#endif

#ifndef SIO_IDEAL_SEND_BACKLOG_QUERY
#define SIO_IDEAL_SEND_BACKLOG_QUERY 0x4004747B
#endif

#ifndef SIO_IDEAL_SEND_BACKLOG_CHANGE
#define SIO_IDEAL_SEND_BACKLOG_CHANGE 0x08000017
#endif

#ifndef SIO_KEEPALIVE_VALS
#define SIO_KEEPALIVE_VALS _WSAIOW(IOC_VENDOR, 4)
#endif

// =============================================================================
// BYTE SWAP FUNCTIONS (using optimized compiler intrinsics for USER-MODE)
// =============================================================================
// User-mode: Використовуємо compiler intrinsics (швидкі та портативні)
// Kernel-mode альтернатива: RtlUlongByteSwap/RtlUshortByteSwap (wdm.h/ntddk.h)
//
// MSVC:       _byteswap_ulong/_byteswap_ushort (stdlib.h) → BSWAP instruction
// GCC/Clang:  __builtin_bswap32/__builtin_bswap16       → BSWAP instruction
// =============================================================================

#if defined(_MSC_VER)
    // MSVC: використовує _byteswap_ulong/_byteswap_ushort
    static inline u_long bswap_32(u_long x) {
        return _byteswap_ulong(x);
    }
    static inline u_short bswap_16(u_short x) {
        return _byteswap_ushort(x);
    }
#elif defined(__GNUC__) || defined(__clang__)
    // GCC/Clang: використовує __builtin_bswap32/__builtin_bswap16
    static inline u_long bswap_32(u_long x) {
        return __builtin_bswap32(x);
    }
    static inline u_short bswap_16(u_short x) {
        return __builtin_bswap16(x);
    }
#else
    #error "Unsupported compiler! Use MSVC, GCC, or Clang for byte swap intrinsics."
#endif

// =============================================================================
// EMBEDDED DATABASES (FULL)
// =============================================================================

static const char* DB_PROTOCOLS = 
"ip 0 IP\n"
"icmp 1 ICMP\n"
"ggp 3 GGP\n"
"tcp 6 TCP\n"
"egp 8 EGP\n"
"pup 12 PUP\n"
"udp 17 UDP\n"
"hmp 20 HMP\n"
"xns-idp 22 XNS-IDP\n"
"rdp 27 RDP\n"
"ipv6 41 IPv6\n"
"ipv6-route 43 IPv6-Route\n"
"ipv6-frag 44 IPv6-Frag\n"
"esp 50 ESP\n"
"ah 51 AH\n"
"ipv6-icmp 58 IPv6-ICMP\n"
"ipv6-nonxt 59 IPv6-NoNxt\n"
"ipv6-opts 60 IPv6-Opts\n"
"rvd 66 RVD\n";

static const char* DB_SERVICES = 
"echo 7/tcp\n"
"echo 7/udp\n"
"discard 9/tcp sink null\n"
"discard 9/udp sink null\n"
"systat 11/tcp users\n"
"daytime 13/tcp\n"
"daytime 13/udp\n"
"netstat 15/tcp\n"
"qotd 17/tcp quote\n"
"qotd 17/udp quote\n"
"chargen 19/tcp ttytst source\n"
"chargen 19/udp ttytst source\n"
"ftp-data 20/tcp\n"
"ftp 21/tcp\n"
"fsp 21/udp fspd\n"
"ssh 22/tcp\n"
"telnet 23/tcp\n"
"smtp 25/tcp mail\n"
"time 37/tcp timserver\n"
"time 37/udp timserver\n"
"rlp 39/udp resource\n"
"nameserver 42/tcp name\n"
"nameserver 42/udp name\n"
"whois 43/tcp nicname\n"
"tacacs 49/tcp\n"
"tacacs 49/udp\n"
"domain 53/tcp\n"
"domain 53/udp\n"
"bootps 67/udp dhcps\n"
"bootpc 68/udp dhcpc\n"
"tftp 69/udp\n"
"gopher 70/tcp\n"
"finger 79/tcp\n"
"http 80/tcp www\n"
"kerberos 88/tcp kerberos5 krb5\n"
"kerberos 88/udp kerberos5 krb5\n"
"pop3 110/tcp pop-3\n"
"sunrpc 111/tcp rpcbind portmap\n"
"sunrpc 111/udp rpcbind portmap\n"
"auth 113/tcp authentication tap ident\n"
"nntp 119/tcp usenet readnews\n"
"ntp 123/udp\n"
"epmap 135/tcp loc-srv\n"
"epmap 135/udp loc-srv\n"
"netbios-ns 137/tcp nbname\n"
"netbios-ns 137/udp nbname\n"
"netbios-dgm 138/udp nbdatagram\n"
"netbios-ssn 139/tcp nbsession\n"
"imap 143/tcp imap4\n"
"snmp 161/tcp\n"
"snmp 161/udp\n"
"snmp-trap 162/tcp snmptrap\n"
"snmp-trap 162/udp snmptrap\n"
"ldap 389/tcp\n"
"ldap 389/udp\n"
"https 443/tcp\n"
"https 443/udp\n"
"microsoft-ds 445/tcp\n"
"microsoft-ds 445/udp\n"
"kpasswd 464/tcp\n"
"kpasswd 464/udp\n"
"isakmp 500/udp ike\n"
"exec 512/tcp\n"
"login 513/tcp\n"
"shell 514/tcp cmd syslog\n"
"syslog 514/udp\n"
"printer 515/tcp spooler\n"
"talk 517/udp\n"
"ntalk 518/udp\n"
"nfs 2049/udp\n"
"ms-sql-s 1433/tcp\n"
"ms-sql-s 1433/udp\n"
"ms-sql-m 1434/tcp\n"
"ms-sql-m 1434/udp\n"
"wins 1512/tcp\n"
"wins 1512/udp\n"
"pptp 1723/tcp\n"
"radius 1812/udp\n"
"radacct 1813/udp\n"
"rdp 3389/tcp ms-wbt-server\n"
"rdp 3389/udp ms-wbt-server\n"
"sip 5060/tcp\n"
"sip 5060/udp\n";

// =============================================================================
// SUPPORTED PROTOCOLS TABLE (Wine-compatible)
// =============================================================================

#define SUPPORTED_PROTOCOLS_COUNT 8

static const WSAPROTOCOL_INFOW g_SupportedProtocols[SUPPORTED_PROTOCOLS_COUNT] = {
    // TCP/IP (IPv4)
    {
        /* dwServiceFlags1 */       XP1_IFS_HANDLES | XP1_EXPEDITED_DATA | XP1_GRACEFUL_CLOSE
                                    | XP1_GUARANTEED_ORDER | XP1_GUARANTEED_DELIVERY,
        /* dwServiceFlags2 */       0,
        /* dwServiceFlags3 */       0,
        /* dwServiceFlags4 */       0,
        /* dwProviderFlags */       PFL_MATCHES_PROTOCOL_ZERO,
        /* ProviderId */            {0xe70f1aa0, 0xab8b, 0x11cf, {0x8c, 0xa3, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}},
        /* dwCatalogEntryId */      1001,
        /* ProtocolChain */         {1, {0}},
        /* iVersion */              2,
        /* iAddressFamily */        AF_INET,
        /* iMaxSockAddr */          sizeof(struct sockaddr_in),
        /* iMinSockAddr */          sizeof(struct sockaddr_in),
        /* iSocketType */           SOCK_STREAM,
        /* iProtocol */             IPPROTO_TCP,
        /* iProtocolMaxOffset */    0,
        /* iNetworkByteOrder */     BIGENDIAN,
        /* iSecurityScheme */       SECURITY_PROTOCOL_NONE,
        /* dwMessageSize */         0,
        /* dwProviderReserved */    0,
        /* szProtocol */            L"TCP/IP",
    },
    // UDP/IP (IPv4)
    {
        /* dwServiceFlags1 */       XP1_IFS_HANDLES | XP1_SUPPORT_BROADCAST
                                    | XP1_SUPPORT_MULTIPOINT | XP1_MESSAGE_ORIENTED | XP1_CONNECTIONLESS,
        /* dwServiceFlags2 */       0,
        /* dwServiceFlags3 */       0,
        /* dwServiceFlags4 */       0,
        /* dwProviderFlags */       PFL_MATCHES_PROTOCOL_ZERO,
        /* ProviderId */            {0xe70f1aa0, 0xab8b, 0x11cf, {0x8c, 0xa3, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}},
        /* dwCatalogEntryId */      1002,
        /* ProtocolChain */         {1, {0}},
        /* iVersion */              2,
        /* iAddressFamily */        AF_INET,
        /* iMaxSockAddr */          sizeof(struct sockaddr_in),
        /* iMinSockAddr */          sizeof(struct sockaddr_in),
        /* iSocketType */           SOCK_DGRAM,
        /* iProtocol */             IPPROTO_UDP,
        /* iProtocolMaxOffset */    0,
        /* iNetworkByteOrder */     BIGENDIAN,
        /* iSecurityScheme */       SECURITY_PROTOCOL_NONE,
        /* dwMessageSize */         0xFFBB,
        /* dwProviderReserved */    0,
        /* szProtocol */            L"UDP/IP",
    },
    // RAW/IP (IPv4)
    {
        /* dwServiceFlags1 */       XP1_IFS_HANDLES | XP1_SUPPORT_BROADCAST
                                    | XP1_SUPPORT_MULTIPOINT | XP1_MESSAGE_ORIENTED | XP1_CONNECTIONLESS,
        /* dwServiceFlags2 */       0,
        /* dwServiceFlags3 */       0,
        /* dwServiceFlags4 */       0,
        /* dwProviderFlags */       PFL_MATCHES_PROTOCOL_ZERO | PFL_HIDDEN,
        /* ProviderId */            {0xe70f1aa0, 0xab8b, 0x11cf, {0x8c, 0xa3, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}},
        /* dwCatalogEntryId */      1003,
        /* ProtocolChain */         {1, {0}},
        /* iVersion */              2,
        /* iAddressFamily */        AF_INET,
        /* iMaxSockAddr */          sizeof(struct sockaddr_in),
        /* iMinSockAddr */          sizeof(struct sockaddr_in),
        /* iSocketType */           SOCK_RAW,
        /* iProtocol */             0,
        /* iProtocolMaxOffset */    255,
        /* iNetworkByteOrder */     BIGENDIAN,
        /* iSecurityScheme */       SECURITY_PROTOCOL_NONE,
        /* dwMessageSize */         0x8000,
        /* dwProviderReserved */    0,
        /* szProtocol */            L"MSAFD Tcpip [RAW/IP]",
    },
    // TCP/IPv6
    {
        /* dwServiceFlags1 */       XP1_IFS_HANDLES | XP1_EXPEDITED_DATA | XP1_GRACEFUL_CLOSE
                                    | XP1_GUARANTEED_ORDER | XP1_GUARANTEED_DELIVERY,
        /* dwServiceFlags2 */       0,
        /* dwServiceFlags3 */       0,
        /* dwServiceFlags4 */       0,
        /* dwProviderFlags */       PFL_MATCHES_PROTOCOL_ZERO,
        /* ProviderId */            {0xf9eab0c0, 0x26d4, 0x11d0, {0xbb, 0xbf, 0x00, 0xaa, 0x00, 0x6c, 0x34, 0xe4}},
        /* dwCatalogEntryId */      1004,
        /* ProtocolChain */         {1, {0}},
        /* iVersion */              2,
        /* iAddressFamily */        AF_INET6,
        /* iMaxSockAddr */          sizeof(struct sockaddr_in6),
        /* iMinSockAddr */          sizeof(struct sockaddr_in6),
        /* iSocketType */           SOCK_STREAM,
        /* iProtocol */             IPPROTO_TCP,
        /* iProtocolMaxOffset */    0,
        /* iNetworkByteOrder */     BIGENDIAN,
        /* iSecurityScheme */       SECURITY_PROTOCOL_NONE,
        /* dwMessageSize */         0,
        /* dwProviderReserved */    0,
        /* szProtocol */            L"TCP/IPv6",
    },
    // UDP/IPv6
    {
        /* dwServiceFlags1 */       XP1_IFS_HANDLES | XP1_SUPPORT_BROADCAST
                                    | XP1_SUPPORT_MULTIPOINT | XP1_MESSAGE_ORIENTED | XP1_CONNECTIONLESS,
        /* dwServiceFlags2 */       0,
        /* dwServiceFlags3 */       0,
        /* dwServiceFlags4 */       0,
        /* dwProviderFlags */       PFL_MATCHES_PROTOCOL_ZERO,
        /* ProviderId */            {0xf9eab0c0, 0x26d4, 0x11d0, {0xbb, 0xbf, 0x00, 0xaa, 0x00, 0x6c, 0x34, 0xe4}},
        /* dwCatalogEntryId */      1005,
        /* ProtocolChain */         {1, {0}},
        /* iVersion */              2,
        /* iAddressFamily */        AF_INET6,
        /* iMaxSockAddr */          sizeof(struct sockaddr_in6),
        /* iMinSockAddr */          sizeof(struct sockaddr_in6),
        /* iSocketType */           SOCK_DGRAM,
        /* iProtocol */             IPPROTO_UDP,
        /* iProtocolMaxOffset */    0,
        /* iNetworkByteOrder */     BIGENDIAN,
        /* iSecurityScheme */       SECURITY_PROTOCOL_NONE,
        /* dwMessageSize */         0xFFBB,
        /* dwProviderReserved */    0,
        /* szProtocol */            L"UDP/IPv6",
    },
    // IPX
    {
        /* dwServiceFlags1 */       XP1_PARTIAL_MESSAGE | XP1_SUPPORT_BROADCAST
                                    | XP1_SUPPORT_MULTIPOINT | XP1_MESSAGE_ORIENTED | XP1_CONNECTIONLESS,
        /* dwServiceFlags2 */       0,
        /* dwServiceFlags3 */       0,
        /* dwServiceFlags4 */       0,
        /* dwProviderFlags */       PFL_MATCHES_PROTOCOL_ZERO,
        /* ProviderId */            {0x11058240, 0xbe47, 0x11cf, {0x95, 0xc8, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}},
        /* dwCatalogEntryId */      1030,
        /* ProtocolChain */         {1, {0}},
        /* iVersion */              2,
        /* iAddressFamily */        AF_IPX,
        /* iMaxSockAddr */          sizeof(struct sockaddr),
        /* iMinSockAddr */          sizeof(struct sockaddr_ipx),
        /* iSocketType */           SOCK_DGRAM,
        /* iProtocol */             NSPROTO_IPX,
        /* iProtocolMaxOffset */    255,
        /* iNetworkByteOrder */     BIGENDIAN,
        /* iSecurityScheme */       SECURITY_PROTOCOL_NONE,
        /* dwMessageSize */         0x240,
        /* dwProviderReserved */    0,
        /* szProtocol */            L"IPX",
    },
    // SPX
    {
        /* dwServiceFlags1 */       XP1_IFS_HANDLES | XP1_PSEUDO_STREAM | XP1_MESSAGE_ORIENTED
                                    | XP1_GUARANTEED_ORDER | XP1_GUARANTEED_DELIVERY,
        /* dwServiceFlags2 */       0,
        /* dwServiceFlags3 */       0,
        /* dwServiceFlags4 */       0,
        /* dwProviderFlags */       PFL_MATCHES_PROTOCOL_ZERO,
        /* ProviderId */            {0x11058241, 0xbe47, 0x11cf, {0x95, 0xc8, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}},
        /* dwCatalogEntryId */      1031,
        /* ProtocolChain */         {1, {0}},
        /* iVersion */              2,
        /* iAddressFamily */        AF_IPX,
        /* iMaxSockAddr */          sizeof(struct sockaddr),
        /* iMinSockAddr */          sizeof(struct sockaddr_ipx),
        /* iSocketType */           SOCK_SEQPACKET,
        /* iProtocol */             NSPROTO_SPX,
        /* iProtocolMaxOffset */    0,
        /* iNetworkByteOrder */     BIGENDIAN,
        /* iSecurityScheme */       SECURITY_PROTOCOL_NONE,
        /* dwMessageSize */         UINT_MAX,
        /* dwProviderReserved */    0,
        /* szProtocol */            L"SPX",
    },
    // SPX II
    {
        /* dwServiceFlags1 */       XP1_IFS_HANDLES | XP1_GRACEFUL_CLOSE | XP1_PSEUDO_STREAM
                                    | XP1_MESSAGE_ORIENTED | XP1_GUARANTEED_ORDER | XP1_GUARANTEED_DELIVERY,
        /* dwServiceFlags2 */       0,
        /* dwServiceFlags3 */       0,
        /* dwServiceFlags4 */       0,
        /* dwProviderFlags */       PFL_MATCHES_PROTOCOL_ZERO,
        /* ProviderId */            {0x11058241, 0xbe47, 0x11cf, {0x95, 0xc8, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}},
        /* dwCatalogEntryId */      1033,
        /* ProtocolChain */         {1, {0}},
        /* iVersion */              2,
        /* iAddressFamily */        AF_IPX,
        /* iMaxSockAddr */          sizeof(struct sockaddr),
        /* iMinSockAddr */          sizeof(struct sockaddr_ipx),
        /* iSocketType */           SOCK_SEQPACKET,
        /* iProtocol */             NSPROTO_SPXII,
        /* iProtocolMaxOffset */    0,
        /* iNetworkByteOrder */     BIGENDIAN,
        /* iSecurityScheme */       SECURITY_PROTOCOL_NONE,
        /* dwMessageSize */         UINT_MAX,
        /* dwProviderReserved */    0,
        /* szProtocol */            L"SPX II",
    },
};

// =============================================================================
// SHARED MEMORY BACKEND
// =============================================================================

#define MAX_SHARED_SOCKETS      256
#define BUFFER_PER_SOCKET       (64 * 1024)
#define MAX_PENDING_CONN        16
#define MAX_DGRAM_QUEUE         32
#define DGRAM_SLOT_SIZE         (BUFFER_PER_SOCKET / MAX_DGRAM_QUEUE) // 2048 bytes
#define SHARED_MEM_NAME         "Local\\EXLOUD_WS2_EMU_MEM_V2"
#define MUTEX_NAME              "Local\\EXLOUD_WS2_EMU_MTX_V2"

// Mutex timeout configuration
// Use 5000 for 5 second timeout (safe, prevents deadlock)
// Use INFINITE for no timeout (faster, but risky if bugs exist)
#define MUTEX_TIMEOUT           INFINITE  // Change to INFINITE if you want no timeout

typedef struct {
    volatile LONG in_use;
    volatile LONG is_bound;
    volatile LONG is_listening;
    volatile LONG is_connected;
    volatile LONG is_nonblocking;
    volatile LONG is_shutdown_recv;
    volatile LONG is_shutdown_send;

    SOCKET id;
    DWORD owner_pid;
    int family;
    int type;
    int protocol;

    struct sockaddr_storage local_addr;
    int local_addr_len;

    struct sockaddr_storage peer_addr;
    int peer_addr_len;

    volatile LONG peer_index;
    volatile LONG accept_count;

    int accept_queue[MAX_PENDING_CONN];

    // TCP: circular buffer indices
    volatile SIZE_T buf_head;
    volatile SIZE_T buf_tail;

    // UDP: datagram queue (circular indices)
    volatile LONG dgram_head;
    volatile LONG dgram_tail;
    struct {
        struct sockaddr_storage from_addr;
        int from_addr_len;
        int data_len;
    } dgram_queue[MAX_DGRAM_QUEUE];

    // Socket options
    int so_broadcast;
    int so_keepalive;
    int so_reuseaddr;
    int so_exclusiveaddruse;
    int so_oobinline;
    int tcp_nodelay;
    int ipv6_v6only;
    DWORD so_rcvtimeo;
    DWORD so_sndtimeo;
    DWORD connect_time;
} VSOCK;

typedef struct {
    volatile DWORD magic;
    volatile DWORD init_pid;
    VSOCK sockets[MAX_SHARED_SOCKETS];
    char buffers[MAX_SHARED_SOCKETS][BUFFER_PER_SOCKET];
} SHARED_STATE;

static HANDLE g_hMap = NULL;
static SHARED_STATE* g_pState = NULL;
static HANDLE g_hMtx = NULL;
static volatile LONG g_nStartup = 0;
static volatile LONG g_nNextPort = 49152;

// Hostname Cache
static char g_szHostName[256] = "localhost";
static volatile LONG g_bHostNameInit = 0;

static BOOL Lk() {
    if (!g_hMtx) {
        LOG("Lk: ERROR - No mutex handle!");
        return FALSE;
    }
    // Налаштовуваний timeout через MUTEX_TIMEOUT константу
    DWORD result = WaitForSingleObject(g_hMtx, MUTEX_TIMEOUT);
    if (result == WAIT_TIMEOUT) {
        LOG("Lk: WARNING - Mutex timeout after %lums!", MUTEX_TIMEOUT);
        return FALSE;
    }
    if (result == WAIT_FAILED) {
        LOG("Lk: ERROR - WaitForSingleObject failed (error=%lu)", GetLastError());
        return FALSE;
    }
    // Успішно отримано lock - без логування для зменшення навантаження
    return TRUE;
}
static void Ulk() { if (g_hMtx) ReleaseMutex(g_hMtx); }

static BOOL InitBackend() {
    LOG("InitBackend: Starting...");
    if (g_pState) {
        LOG("InitBackend: Already initialized");
        return TRUE;
    }
    
    LOG("InitBackend: Creating mutex '%s'...", MUTEX_NAME);
    g_hMtx = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    if (!g_hMtx) {
        LOG("InitBackend: CreateMutex FAILED (error=%lu)", GetLastError());
        return FALSE;
    }
    LOG("InitBackend: Mutex created successfully");
    
    LOG("InitBackend: Acquiring lock...");
    if (!Lk()) {
        LOG("InitBackend: Lock FAILED (timeout or error)");
        return FALSE;
    }
    LOG("InitBackend: Lock acquired");
    
    LOG("InitBackend: Creating shared memory '%s' (size=%zu)...", SHARED_MEM_NAME, sizeof(SHARED_STATE));
    g_hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(SHARED_STATE), SHARED_MEM_NAME);
    if (g_hMap) {
        BOOL first = (GetLastError() != ERROR_ALREADY_EXISTS);
        LOG("InitBackend: Shared memory %s (first=%d)", first ? "CREATED" : "OPENED", first);
        
        LOG("InitBackend: Mapping view...");
        g_pState = (SHARED_STATE*)MapViewOfFile(g_hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SHARED_STATE));
        if (!g_pState) {
            LOG("InitBackend: MapViewOfFile FAILED (error=%lu)", GetLastError());
        } else {
            LOG("InitBackend: View mapped at %p", g_pState);
            if (first) {
                LOG("InitBackend: Initializing shared state...");
                memset(g_pState, 0, sizeof(SHARED_STATE));
                g_pState->magic = 0x57533245; // "WS2E"
                LOG("InitBackend: State initialized (magic=0x%08lX)", g_pState->magic);
            } else {
                LOG("InitBackend: Existing state (magic=0x%08lX)", g_pState->magic);
            }
        }
    } else {
        LOG("InitBackend: CreateFileMapping FAILED (error=%lu)", GetLastError());
    }
    
    Ulk();
    LOG("InitBackend: Lock released");
    
    BOOL result = (g_pState != NULL);
    LOG("InitBackend: %s", result ? "SUCCESS" : "FAILED");
    return result;
}

// =============================================================================
// InitLocalHostname - Reads hostname from EXLOUD registry (NO EXIPHL!)
// =============================================================================
static void InitLocalHostname() {
    LOG("InitLocalHostname: Starting...");
    
    if (InterlockedCompareExchange(&g_bHostNameInit, 1, 0) == 1) {
        LOG("InitLocalHostname: Already initialized");
        return;
    }

    // =========================================================================
    // Read hostname from EXLOUD registry - NO FALLBACK!
    // =========================================================================
    HKEY hKey;
    BOOL bFound = FALSE;
    
    if (RegOpenKeyExA(HKEY_CURRENT_USER, EXLOUD_REG_KEY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        LOG("InitLocalHostname: Reading from EXLOUD config...");
        
        char computerName[256] = {0};
        DWORD size = sizeof(computerName);
        DWORD type;
        
        if (RegQueryValueExA(hKey, REG_COMPUTER_NAME, NULL, &type, 
            (LPBYTE)computerName, &size) == ERROR_SUCCESS && type == REG_SZ) 
        {
            if (computerName[0] != '\0') {
                strncpy(g_szHostName, computerName, sizeof(g_szHostName) - 1);
                g_szHostName[sizeof(g_szHostName) - 1] = '\0';
                bFound = TRUE;
                LOG("InitLocalHostname: ✓ Hostname = '%s'", g_szHostName);
            }
        } else {
            LOG("InitLocalHostname: ComputerName not found in registry");
        }
        
        RegCloseKey(hKey);
    } else {
        LOG("InitLocalHostname: ⚠ EXLOUD config not found");
        LOG("InitLocalHostname: Registry key: HKCU\\%s", EXLOUD_REG_KEY);
    }
    
    // =========================================================================
    // EXLOUD config not found or empty - use default "localhost"
    // =========================================================================
    if (!bFound || g_szHostName[0] == '\0') {
        strcpy(g_szHostName, "localhost");
        LOG("InitLocalHostname: ⚠ Using default 'localhost'");
        LOG("InitLocalHostname: Run add_to_reg.bat to configure!");
    }
    
    LOG("InitLocalHostname: FINAL hostname = '%s'", g_szHostName);
}

static VSOCK* FindSock(SOCKET s) {
    if (!g_pState || s == INVALID_SOCKET) return NULL;
    for (int i = 0; i < MAX_SHARED_SOCKETS; i++)
        if (g_pState->sockets[i].in_use && g_pState->sockets[i].id == s) 
            return &g_pState->sockets[i];
    return NULL;
}

static int SockIdx(VSOCK* s) { return (int)(s - g_pState->sockets); }
static char* GetBuf(VSOCK* s) { return g_pState->buffers[SockIdx(s)]; }

static size_t BufUsed(VSOCK* s) {
    size_t cap = BUFFER_PER_SOCKET;
    size_t h = s->buf_head % cap;
    size_t t = s->buf_tail % cap;
    return (t >= h) ? (t - h) : (cap - (h - t));
}

static size_t BufFree(VSOCK* s) { return (BUFFER_PER_SOCKET - 1) - BufUsed(s); }

static void BufWrite(VSOCK* s, const void* data, size_t len) {
    char* buf = GetBuf(s);
    size_t cap = BUFFER_PER_SOCKET;
    size_t t = s->buf_tail % cap;
    size_t chunk = min(len, cap - t);
    memcpy(buf + t, data, chunk);
    if (len > chunk) memcpy(buf, (char*)data + chunk, len - chunk);
    MemoryBarrier();
    s->buf_tail = (s->buf_tail + len) % cap;
}

static void BufRead(VSOCK* s, void* data, size_t len, BOOL consume) {
    char* buf = GetBuf(s);
    size_t cap = BUFFER_PER_SOCKET;
    size_t h = s->buf_head % cap;
    size_t chunk = min(len, cap - h);
    memcpy(data, buf + h, chunk);
    if (len > chunk) memcpy((char*)data + chunk, buf, len - chunk);
    if (consume) {
        MemoryBarrier();
        s->buf_head = (s->buf_head + len) % cap;
    }
}



// ---- UDP datagram queue helpers ----

static int DgramCount(VSOCK* s) {
    return s->dgram_tail - s->dgram_head;
}

static BOOL DgramEnqueue(VSOCK* target, const struct sockaddr* from, int from_len,
                         const char* data, int data_len) {
    if (DgramCount(target) >= MAX_DGRAM_QUEUE) return FALSE;
    if (data_len > DGRAM_SLOT_SIZE) return FALSE;
    int idx = target->dgram_tail % MAX_DGRAM_QUEUE;
    char* slot = GetBuf(target) + (idx * DGRAM_SLOT_SIZE);
    memcpy(slot, data, data_len);
    if (from && from_len > 0) {
        memcpy(&target->dgram_queue[idx].from_addr, from,
               min(from_len, (int)sizeof(struct sockaddr_storage)));
        target->dgram_queue[idx].from_addr_len = from_len;
    } else {
        memset(&target->dgram_queue[idx].from_addr, 0, sizeof(struct sockaddr_storage));
        target->dgram_queue[idx].from_addr_len = 0;
    }
    target->dgram_queue[idx].data_len = data_len;
    MemoryBarrier();
    target->dgram_tail++;
    return TRUE;
}

static int DgramDequeue(VSOCK* sock, char* buf, int buf_len,
                        struct sockaddr* from, int* from_len, BOOL peek) {
    if (DgramCount(sock) <= 0) return -1;
    int idx = sock->dgram_head % MAX_DGRAM_QUEUE;
    int data_len = sock->dgram_queue[idx].data_len;
    int copy_len = min(buf_len, data_len);
    char* slot = GetBuf(sock) + (idx * DGRAM_SLOT_SIZE);
    memcpy(buf, slot, copy_len);
    if (from && from_len && *from_len > 0) {
        int addr_copy = min(*from_len, sock->dgram_queue[idx].from_addr_len);
        memcpy(from, &sock->dgram_queue[idx].from_addr, addr_copy);
        *from_len = sock->dgram_queue[idx].from_addr_len;
    }
    if (!peek) { MemoryBarrier(); sock->dgram_head++; }
    return copy_len;
}

static VSOCK* FindUDPTarget(int family, const struct sockaddr* to) {
    if (!g_pState || !to) return NULL;
    u_short dst_port = 0;
    u_long  dst_addr4 = 0;
    if (family == AF_INET) {
        dst_port  = ((const struct sockaddr_in*)to)->sin_port;
        dst_addr4 = ((const struct sockaddr_in*)to)->sin_addr.s_addr;
    } else if (family == AF_INET6) {
        dst_port = ((const struct sockaddr_in6*)to)->sin6_port;
    } else return NULL;

    for (int i = 0; i < MAX_SHARED_SOCKETS; i++) {
        VSOCK* s = &g_pState->sockets[i];
        if (!s->in_use || !s->is_bound || s->type != SOCK_DGRAM) continue;
        if (s->family != family) continue;
        if (family == AF_INET) {
            struct sockaddr_in* bound = (struct sockaddr_in*)&s->local_addr;
            if (bound->sin_port != dst_port) continue;
            if (bound->sin_addr.s_addr != 0 &&
                bound->sin_addr.s_addr != dst_addr4 &&
                dst_addr4 != 0xFFFFFFFF) continue;
        } else if (family == AF_INET6) {
            struct sockaddr_in6* bound = (struct sockaddr_in6*)&s->local_addr;
            if (bound->sin6_port != dst_port) continue;
        }
        return s;
    }
    return NULL;
}

// =============================================================================
// PROTOCOL HELPER FUNCTIONS
// =============================================================================

static BOOL protocol_matches_filter(const int* filter, unsigned int index) {
    if (g_SupportedProtocols[index].dwProviderFlags & PFL_HIDDEN)
        return FALSE;
    if (!filter)
        return TRUE;
    while (*filter) {
        if (g_SupportedProtocols[index].iProtocol == *filter)
            return TRUE;
        filter++;
    }
    return FALSE;
}

static const WSAPROTOCOL_INFOW* FindProtocolInfo(int af, int type, int protocol) {
    for (unsigned int i = 0; i < SUPPORTED_PROTOCOLS_COUNT; i++) {
        const WSAPROTOCOL_INFOW* info = &g_SupportedProtocols[i];
        
        if (af != AF_UNSPEC && af != 0 && af != info->iAddressFamily)
            continue;
        if (type != 0 && type != info->iSocketType)
            continue;
        if (protocol != 0) {
            if (protocol < info->iProtocol || 
                protocol > info->iProtocol + info->iProtocolMaxOffset)
                continue;
        } else {
            if (!(info->dwProviderFlags & PFL_MATCHES_PROTOCOL_ZERO))
                continue;
        }
        return info;
    }
    return NULL;
}

static BOOL GetSocketProtocolInfo(SOCKET s, BOOL unicode, void* buffer, int* size) {
    if (!g_pState) return FALSE;
    
    Lk();
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        SetLastError(WSAENOTSOCK);
        return FALSE;
    }
    
    int family = sock->family;
    int type = sock->type;
    int protocol = sock->protocol;
    Ulk();
    
    const WSAPROTOCOL_INFOW* info = FindProtocolInfo(family, type, protocol);
    
    if (unicode) {
        *size = sizeof(WSAPROTOCOL_INFOW);
        if (buffer) {
            WSAPROTOCOL_INFOW* dst = (WSAPROTOCOL_INFOW*)buffer;
            if (info) {
                *dst = *info;  // Копіюємо всю структуру
                dst->iProtocol = protocol;
            } else {
                memset(dst, 0, sizeof(*dst));
                dst->iAddressFamily = family;
                dst->iSocketType = type;
                dst->iProtocol = protocol;
                wcscpy(dst->szProtocol, L"Unknown");
            }
        }
    } else {
        *size = sizeof(WSAPROTOCOL_INFOA);
        if (buffer) {
            WSAPROTOCOL_INFOA* dst = (WSAPROTOCOL_INFOA*)buffer;
            if (info) {
                // Копіюємо поля вручну
                dst->dwServiceFlags1 = info->dwServiceFlags1;
                dst->dwServiceFlags2 = info->dwServiceFlags2;
                dst->dwServiceFlags3 = info->dwServiceFlags3;
                dst->dwServiceFlags4 = info->dwServiceFlags4;
                dst->dwProviderFlags = info->dwProviderFlags;
                dst->ProviderId = info->ProviderId;
                dst->dwCatalogEntryId = info->dwCatalogEntryId;
                dst->ProtocolChain = info->ProtocolChain;
                dst->iVersion = info->iVersion;
                dst->iAddressFamily = info->iAddressFamily;
                dst->iMaxSockAddr = info->iMaxSockAddr;
                dst->iMinSockAddr = info->iMinSockAddr;
                dst->iSocketType = info->iSocketType;
                dst->iProtocol = protocol;
                dst->iProtocolMaxOffset = info->iProtocolMaxOffset;
                dst->iNetworkByteOrder = info->iNetworkByteOrder;
                dst->iSecurityScheme = info->iSecurityScheme;
                dst->dwMessageSize = info->dwMessageSize;
                dst->dwProviderReserved = info->dwProviderReserved;
                WideCharToMultiByte(CP_ACP, 0, info->szProtocol, -1,
                                   dst->szProtocol, sizeof(dst->szProtocol), NULL, NULL);
            } else {
                memset(dst, 0, sizeof(*dst));
                dst->iAddressFamily = family;
                dst->iSocketType = type;
                dst->iProtocol = protocol;
                strcpy(dst->szProtocol, "Unknown");
            }
        }
    }
    return TRUE;
}

// =============================================================================
// DATABASE PARSERS
// =============================================================================

static char* next_line_from_mem(const char** cursor, const char* end) {
    const char* p = *cursor;
    while (p < end && isspace((unsigned char)*p)) p++;
    if (p >= end) return NULL;
    const char* line_end = p;
    while (line_end < end && *line_end != '\n') line_end++;
    static TLS char buf[256];
    size_t len = min(sizeof(buf)-1, (size_t)(line_end - p));
    memcpy(buf, p, len);
    buf[len] = 0;
    *cursor = line_end;
    return buf;
}

extern "C" struct protoent* WSAAPI ex_getprotobyname(const char* name) {
    if (!name) {
        SetLastError(WSANO_DATA);
        return NULL;
    }
    static TLS struct protoent pe;
    static TLS char* aliases[1] = {0};
    static TLS char name_buf[32];
    const char* cursor = DB_PROTOCOLS;
    const char* end = cursor + strlen(cursor);
    char* line;
    while ((line = next_line_from_mem(&cursor, end))) {
        char p_name[32];
        int p_num;
        if (sscanf(line, "%31s %d", p_name, &p_num) == 2) {
            if (_stricmp(p_name, name) == 0) {
                strcpy(name_buf, p_name);
                pe.p_name = name_buf;
                pe.p_proto = (short)p_num;
                pe.p_aliases = aliases;
                return &pe;
            }
        }
    }
    SetLastError(WSANO_DATA);
    return NULL;
}

extern "C" struct protoent* WSAAPI ex_getprotobynumber(int number) {
    static TLS struct protoent pe;
    static TLS char* aliases[1] = {0};
    static TLS char name_buf[32];
    const char* cursor = DB_PROTOCOLS;
    const char* end = cursor + strlen(cursor);
    char* line;
    while ((line = next_line_from_mem(&cursor, end))) {
        char p_name[32];
        int p_num;
        if (sscanf(line, "%31s %d", p_name, &p_num) == 2) {
            if (p_num == number) {
                strcpy(name_buf, p_name);
                pe.p_name = name_buf;
                pe.p_proto = (short)p_num;
                pe.p_aliases = aliases;
                return &pe;
            }
        }
    }
    SetLastError(WSANO_DATA);
    return NULL;
}

extern "C" struct servent* WSAAPI ex_getservbyname(const char* name, const char* proto) {
    if (!name) {
        SetLastError(WSANO_DATA);
        return NULL;
    }
    static TLS struct servent se;
    static TLS char* aliases[1] = {0};
    static TLS char name_buf[32];
    static TLS char proto_buf[16];
    const char* cursor = DB_SERVICES;
    const char* end = cursor + strlen(cursor);
    char* line;
    while ((line = next_line_from_mem(&cursor, end))) {
        char s_name[32], s_port_proto[32];
        if (sscanf(line, "%31s %31s", s_name, s_port_proto) == 2) {
            if (_stricmp(s_name, name) == 0) {
                int port = atoi(s_port_proto);
                char* slash = strchr(s_port_proto, '/');
                if (slash) {
                    char* p = slash + 1;
                    if (!proto || _stricmp(p, proto) == 0) {
                        strcpy(name_buf, s_name);
                        strcpy(proto_buf, p);
                        se.s_name = name_buf;
                        se.s_port = bswap_16((u_short)port);
                        se.s_proto = proto_buf;
                        se.s_aliases = aliases;
                        return &se;
                    }
                }
            }
        }
    }
    SetLastError(WSANO_DATA);
    return NULL;
}

extern "C" struct servent* WSAAPI ex_getservbyport(int port, const char* proto) {
    int host_port = bswap_16((u_short)port);
    static TLS struct servent se;
    static TLS char* aliases[1] = {0};
    static TLS char name_buf[32];
    static TLS char proto_buf[16];
    const char* cursor = DB_SERVICES;
    const char* end = cursor + strlen(cursor);
    char* line;
    while ((line = next_line_from_mem(&cursor, end))) {
        char s_name[32], s_port_proto[32];
        if (sscanf(line, "%31s %31s", s_name, s_port_proto) == 2) {
            int p_val = atoi(s_port_proto);
            if (p_val == host_port) {
                char* slash = strchr(s_port_proto, '/');
                if (slash) {
                    char* p = slash + 1;
                    if (!proto || _stricmp(p, proto) == 0) {
                        strcpy(name_buf, s_name);
                        strcpy(proto_buf, p);
                        se.s_name = name_buf;
                        se.s_port = (u_short)port;
                        se.s_proto = proto_buf;
                        se.s_aliases = aliases;
                        return &se;
                    }
                }
            }
        }
    }
    SetLastError(WSANO_DATA);
    return NULL;
}

// =============================================================================
// BYTE ORDER FUNCTIONS
// =============================================================================

// =============================================================================
// NETWORK BYTE ORDER CONVERSION
// =============================================================================
// Важливо: htonl/htons != просто byte swap!
// - htonl() = конвертація з HOST в NETWORK byte order
// - bswap() = безумовний byte swap
//
// Network byte order = big-endian (RFC 1700)
// Host byte order залежить від архітектури:
//   - x86/x64 = little-endian → потрібен swap
//   - ARM (зазвичай) = little-endian → потрібен swap
//   - PowerPC/MIPS (старі) = big-endian → swap НЕ потрібен
//
// Використовуємо умовну компіляцію для визначення endianness
// =============================================================================

// Визначаємо endianness на етапі компіляції
#if defined(_MSC_VER)
    // MSVC завжди little-endian (x86, x64, ARM)
    #define HOST_IS_LITTLE_ENDIAN 1
#elif defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && defined(__ORDER_BIG_ENDIAN__)
    // GCC/Clang мають вбудовані макроси
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        #define HOST_IS_LITTLE_ENDIAN 1
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        #define HOST_IS_LITTLE_ENDIAN 0
    #else
        #error "Unknown byte order!"
    #endif
#elif defined(__LITTLE_ENDIAN__) || defined(_LITTLE_ENDIAN)
    #define HOST_IS_LITTLE_ENDIAN 1
#elif defined(__BIG_ENDIAN__) || defined(_BIG_ENDIAN)
    #define HOST_IS_LITTLE_ENDIAN 0
#else
    // Fallback: припускаємо x86/x64 (99% випадків для Windows)
    #define HOST_IS_LITTLE_ENDIAN 1
#endif

// htonl/htons: host → network (big-endian)
#if HOST_IS_LITTLE_ENDIAN
    // Little-endian host → потрібен swap
    extern "C" u_long WSAAPI ex_htonl(u_long h) { return bswap_32(h); }
    extern "C" u_short WSAAPI ex_htons(u_short h) { return bswap_16(h); }
#else
    // Big-endian host → swap НЕ потрібен
    extern "C" u_long WSAAPI ex_htonl(u_long h) { return h; }
    extern "C" u_short WSAAPI ex_htons(u_short h) { return h; }
#endif

// ntohl/ntohs: network (big-endian) → host
#if HOST_IS_LITTLE_ENDIAN
    // Little-endian host → потрібен swap
    extern "C" u_long WSAAPI ex_ntohl(u_long n) { return bswap_32(n); }
    extern "C" u_short WSAAPI ex_ntohs(u_short n) { return bswap_16(n); }
#else
    // Big-endian host → swap НЕ потрібен
    extern "C" u_long WSAAPI ex_ntohl(u_long n) { return n; }
    extern "C" u_short WSAAPI ex_ntohs(u_short n) { return n; }
#endif

extern "C" int WSAAPI ex_WSAHtonl(SOCKET s, u_long hostlong, u_long* netlong) {
    if (!netlong) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    *netlong = ex_htonl(hostlong);
    return 0;
}

extern "C" int WSAAPI ex_WSAHtons(SOCKET s, u_short hostshort, u_short* netshort) {
    if (!netshort) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    *netshort = ex_htons(hostshort);
    return 0;
}

extern "C" int WSAAPI ex_WSANtohl(SOCKET s, u_long netlong, u_long* hostlong) {
    if (!hostlong) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    *hostlong = ex_ntohl(netlong);
    return 0;
}

extern "C" int WSAAPI ex_WSANtohs(SOCKET s, u_short netshort, u_short* hostshort) {
    if (!hostshort) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    *hostshort = ex_ntohs(netshort);
    return 0;
}

// =============================================================================
// ADDRESS CONVERSION FUNCTIONS
// =============================================================================

extern "C" char* WSAAPI ex_inet_ntoa(struct in_addr in) {
    static TLS char buf[18];
    unsigned char *p = (unsigned char *)&in;
    sprintf(buf, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return buf;
}

// Wine-compatible inet_addr with all format support
extern "C" unsigned long WSAAPI ex_inet_addr(const char* cp) {
    unsigned long a[4] = { 0 };
    const char *s = cp;
    unsigned char *d;
    unsigned int i;
    u_long addr;
    char *z;

    if (!s) {
        SetLastError(WSAEFAULT);
        return INADDR_NONE;
    }

    d = (unsigned char *)&addr;

    // Special case: single space
    if (s[0] == ' ' && !s[1]) return 0;

    for (i = 0; i < 4; ++i) {
        a[i] = strtoul(s, &z, 0);
        if (z == s || !isdigit((unsigned char)*s)) return INADDR_NONE;
        if (!*z || isspace((unsigned char)*z)) break;
        if (*z != '.') return INADDR_NONE;
        s = z + 1;
    }

    if (i == 4) return INADDR_NONE;

    // Convert different formats
    switch (i) {
        case 0:
            a[1] = a[0] & 0xffffff;
            a[0] >>= 24;
            /* fallthrough */
        case 1:
            a[2] = a[1] & 0xffff;
            a[1] >>= 16;
            /* fallthrough */
        case 2:
            a[3] = a[2] & 0xff;
            a[2] >>= 8;
    }
    
    for (i = 0; i < 4; ++i) {
        if (a[i] > 255) return INADDR_NONE;
        d[i] = (unsigned char)a[i];
    }
    return addr;
}

extern "C" const char* WSAAPI ex_inet_ntop(int family, const void* src, char* dst, size_t size) {
    if (!dst || !src) { SetLastError(WSAEFAULT); return NULL; }
    if (family == AF_INET) {
        const unsigned char* p = (const unsigned char*)src;
        char temp[18];
        sprintf(temp, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
        if (strlen(temp) >= size) { SetLastError(WSAEINVAL); return NULL; }
        strcpy(dst, temp); return dst;
    }
    if (family == AF_INET6) {
        const unsigned char* b = (const unsigned char*)src;
        unsigned short words[8];
        for (int i = 0; i < 8; i++)
            words[i] = (unsigned short)((b[i*2] << 8) | b[i*2+1]);
        int best_start = -1, best_len = 0, cur_start = -1, cur_len = 0;
        for (int i = 0; i < 8; i++) {
            if (words[i] == 0) { if (cur_start < 0) cur_start = i; cur_len++; }
            else {
                if (cur_len > best_len && cur_len >= 2) { best_start = cur_start; best_len = cur_len; }
                cur_start = -1; cur_len = 0;
            }
        }
        if (cur_len > best_len && cur_len >= 2) { best_start = cur_start; best_len = cur_len; }
        char temp[48]; char* p = temp; BOOL need_colon = FALSE;
        for (int i = 0; i < 8; ) {
            if (best_start >= 0 && i == best_start) {
                *p++ = ':'; *p++ = ':'; i += best_len; need_colon = FALSE; continue;
            }
            if (need_colon) *p++ = ':';
            p += sprintf(p, "%x", words[i]); need_colon = TRUE; i++;
        }
        *p = '\0';
        if (strlen(temp) >= size) { SetLastError(WSAEINVAL); return NULL; }
        strcpy(dst, temp); return dst;
    }
    SetLastError(WSAEAFNOSUPPORT); return NULL;
}


// Full IPv6 parser with :: support
static int parse_ipv6(const char* src, struct in6_addr* dst) {
    unsigned short words[8] = {0};
    int word_count = 0, dbl_colon_pos = -1;
    const char* p = src;
    if (!src || !dst) return 0;

    if (p[0] == ':' && p[1] == ':') {
        dbl_colon_pos = 0; p += 2;
        if (*p == '\0' || *p == '%') { memset(dst, 0, sizeof(*dst)); return 1; }
    } else if (p[0] == ':') return 0;

    while (*p != '\0' && *p != '%' && word_count < 8) {
        if (*p == ':' && *(p+1) == ':') {
            if (dbl_colon_pos >= 0) return 0;
            dbl_colon_pos = word_count; p += 2;
            if (*p == '\0' || *p == '%') break;
            continue;
        }
        char* end;
        unsigned long val = strtoul(p, &end, 16);
        if (end == p || val > 0xFFFF) return 0;
        words[word_count++] = (unsigned short)val;
        p = end;
        if (*p == ':') {
            if (*(p+1) == ':') continue;
            p++;
            if (*p == '\0' || *p == '%') return 0;
        } else if (*p != '\0' && *p != '%') return 0;
    }
    if (*p != '\0' && *p != '%') return 0;

    unsigned short result[8] = {0};
    if (dbl_colon_pos >= 0) {
        int zeros_needed = 8 - word_count;
        if (zeros_needed < 0) return 0;
        for (int i = 0; i < dbl_colon_pos; i++) result[i] = words[i];
        int after_count = word_count - dbl_colon_pos;
        for (int i = 0; i < after_count; i++)
            result[dbl_colon_pos + zeros_needed + i] = words[dbl_colon_pos + i];
    } else {
        if (word_count != 8) return 0;
        memcpy(result, words, sizeof(result));
    }

    unsigned char* out = (unsigned char*)dst;
    for (int i = 0; i < 8; i++) {
        out[i*2]   = (unsigned char)(result[i] >> 8);
        out[i*2+1] = (unsigned char)(result[i] & 0xFF);
    }
    return 1;
}

extern "C" int WSAAPI ex_inet_pton(int family, const char* src, void* dst) {
    if (!src || !dst) { SetLastError(WSAEFAULT); return -1; }
    if (family == AF_INET) {
        while (*src == ' ') src++;
        u_long a = ex_inet_addr(src);
        if (a == INADDR_NONE && strcmp(src, "255.255.255.255") != 0) return 0;
        memcpy(dst, &a, 4); return 1;
    }
    if (family == AF_INET6) return parse_ipv6(src, (struct in6_addr*)dst);
    SetLastError(WSAEAFNOSUPPORT); return -1;
}

extern "C" int WSAAPI ex_InetPtonW(int family, const WCHAR* src, void* dst) {
    if (!src) { SetLastError(WSAEFAULT); return -1; }
    char srcA[128];
    WideCharToMultiByte(CP_ACP, 0, src, -1, srcA, sizeof(srcA), NULL, NULL);
    int ret = ex_inet_pton(family, srcA, dst);
    if (ret == 0) SetLastError(WSAEINVAL);
    return ret;
}

extern "C" const WCHAR* WSAAPI ex_InetNtopW(int family, void* src, WCHAR* dst, size_t size) {
    char bufA[64];
    if (!ex_inet_ntop(family, src, bufA, sizeof(bufA)))
        return NULL;
    if (MultiByteToWideChar(CP_ACP, 0, bufA, -1, dst, (int)size) == 0) {
        SetLastError(WSAEINVAL);
        return NULL;
    }
    return dst;
}

// =============================================================================
// HOST/ADDRESS RESOLUTION
// =============================================================================

extern "C" struct hostent* WSAAPI ex_gethostbyname(const char* name) {
    LOG("gethostbyname: %s", name ? name : "NULL");
    
    if (!g_nStartup) {
        SetLastError(WSANOTINITIALISED);
        return NULL;
    }
    
    static TLS struct hostent he;
    static TLS char* aliases[1] = {0};
    static TLS char* addrs[2];
    static TLS struct in_addr addr;
    static TLS char name_buf[256];
    
    if (!name || !name[0]) {
        name = g_szHostName;
    }
    
    strncpy(name_buf, name, sizeof(name_buf) - 1);
    name_buf[sizeof(name_buf) - 1] = '\0';
    
    addr.s_addr = 0x0100007F; // 127.0.0.1
    
    he.h_name = name_buf;
    he.h_aliases = aliases;
    he.h_addrtype = AF_INET;
    he.h_length = 4;
    addrs[0] = (char*)&addr;
    addrs[1] = NULL;
    he.h_addr_list = addrs;
    
    return &he;
}

extern "C" struct hostent* WSAAPI ex_gethostbyaddr(const char* addr, int len, int type) {
    if (!g_nStartup) {
        SetLastError(WSANOTINITIALISED);
        return NULL;
    }
    return ex_gethostbyname("localhost");
}

extern "C" int WSAAPI ex_getaddrinfo(const char* node, const char* service,
                                      const struct addrinfo* hints, struct addrinfo** res) {
    LOG("getaddrinfo: node=%s, service=%s", node ? node : "NULL", service ? service : "NULL");
    if (!res) { SetLastError(WSAEINVAL); return EAI_FAIL; }
    *res = NULL;
    if (!node && !service) { SetLastError(WSAHOST_NOT_FOUND); return WSAHOST_NOT_FOUND; }

    int family   = hints ? hints->ai_family   : AF_UNSPEC;
    int socktype = hints ? hints->ai_socktype : 0;
    int protocol = hints ? hints->ai_protocol : 0;
    if (family != AF_INET && family != AF_INET6 && family != AF_UNSPEC) {
        SetLastError(WSAEAFNOSUPPORT); return EAI_FAMILY;
    }

    u_short port_n = 0;
    if (service && service[0]) {
        int p = atoi(service);
        if (p > 0 && p <= 65535) port_n = bswap_16((u_short)p);
        else {
            const char* pn = (socktype == SOCK_DGRAM) ? "udp" : "tcp";
            struct servent* se = ex_getservbyname(service, pn);
            if (se) port_n = se->s_port;
        }
    }

    u_long addr4 = 0x0100007F;
    if (node && node[0]) {
        u_long a = ex_inet_addr(node);
        if (a != INADDR_NONE) addr4 = a;
    }

    int want_v4 = (family == AF_INET  || family == AF_UNSPEC);
    int want_v6 = (family == AF_INET6 || family == AF_UNSPEC);
    struct addrinfo* head = NULL;
    struct addrinfo* tail = NULL;

    if (want_v4) {
        size_t sz = sizeof(struct addrinfo) + sizeof(struct sockaddr_in);
        struct addrinfo* ai = (struct addrinfo*)calloc(1, sz);
        if (!ai) { SetLastError(WSA_NOT_ENOUGH_MEMORY); return EAI_MEMORY; }
        ai->ai_family = AF_INET;
        ai->ai_socktype = socktype ? socktype : SOCK_STREAM;
        ai->ai_protocol = protocol ? protocol : (ai->ai_socktype == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP);
        ai->ai_addrlen = sizeof(struct sockaddr_in);
        ai->ai_addr = (struct sockaddr*)(ai + 1);
        struct sockaddr_in* sin = (struct sockaddr_in*)ai->ai_addr;
        sin->sin_family = AF_INET; sin->sin_addr.s_addr = addr4; sin->sin_port = port_n;
        if (!head) head = ai; else tail->ai_next = ai;
        tail = ai;
    }
    if (want_v6) {
        size_t sz = sizeof(struct addrinfo) + sizeof(struct sockaddr_in6);
        struct addrinfo* ai = (struct addrinfo*)calloc(1, sz);
        if (!ai) {
            while (head) { struct addrinfo* n = head->ai_next; free(head); head = n; }
            SetLastError(WSA_NOT_ENOUGH_MEMORY); return EAI_MEMORY;
        }
        ai->ai_family = AF_INET6;
        ai->ai_socktype = socktype ? socktype : SOCK_STREAM;
        ai->ai_protocol = protocol ? protocol : (ai->ai_socktype == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP);
        ai->ai_addrlen = sizeof(struct sockaddr_in6);
        ai->ai_addr = (struct sockaddr*)(ai + 1);
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)ai->ai_addr;
        sin6->sin6_family = AF_INET6; sin6->sin6_port = port_n;
        memset(&sin6->sin6_addr, 0, sizeof(sin6->sin6_addr));
        ((unsigned char*)&sin6->sin6_addr)[15] = 1;
        if (node && node[0]) ex_inet_pton(AF_INET6, node, &sin6->sin6_addr);
        if (!head) head = ai; else tail->ai_next = ai;
        tail = ai;
    }
    *res = head;
    return 0;
}

extern "C" void WSAAPI ex_freeaddrinfo(struct addrinfo* ai) {
    while (ai) {
        struct addrinfo* next = ai->ai_next;
        // ai_addr is inline (after struct), single free handles both
        free(ai);
        ai = next;
    }
}

extern "C" int WSAAPI ex_GetAddrInfoW(const WCHAR* node, const WCHAR* service,
                                       const ADDRINFOW* hints, PADDRINFOW* res) {
    char nodeA[256] = {0}, serviceA[64] = {0};
    if (node)    WideCharToMultiByte(CP_ACP, 0, node, -1, nodeA, sizeof(nodeA), NULL, NULL);
    if (service) WideCharToMultiByte(CP_ACP, 0, service, -1, serviceA, sizeof(serviceA), NULL, NULL);

    struct addrinfo* resA = NULL;
    int ret = ex_getaddrinfo(node ? nodeA : NULL, service ? serviceA : NULL,
                             (const struct addrinfo*)hints, &resA);
    if (ret != 0 || !resA) { *res = NULL; return ret; }

    PADDRINFOW headW = NULL, tailW = NULL;
    for (struct addrinfo* cur = resA; cur; cur = cur->ai_next) {
        ADDRINFOW* aiW = (ADDRINFOW*)calloc(1, sizeof(ADDRINFOW));
        if (!aiW) {
            while (headW) {
                PADDRINFOW n = headW->ai_next;
                if (headW->ai_canonname) free(headW->ai_canonname);
                if (headW->ai_addr) free(headW->ai_addr);
                free(headW); headW = n;
            }
            ex_freeaddrinfo(resA); *res = NULL; return EAI_MEMORY;
        }
        aiW->ai_flags = cur->ai_flags; aiW->ai_family = cur->ai_family;
        aiW->ai_socktype = cur->ai_socktype; aiW->ai_protocol = cur->ai_protocol;
        aiW->ai_addrlen = cur->ai_addrlen;
        if (cur->ai_addr && cur->ai_addrlen > 0) {
            aiW->ai_addr = (struct sockaddr*)malloc(cur->ai_addrlen);
            if (aiW->ai_addr) memcpy(aiW->ai_addr, cur->ai_addr, cur->ai_addrlen);
        }
        if (cur->ai_canonname) {
            int wlen = MultiByteToWideChar(CP_ACP, 0, cur->ai_canonname, -1, NULL, 0);
            aiW->ai_canonname = (WCHAR*)malloc(wlen * sizeof(WCHAR));
            if (aiW->ai_canonname)
                MultiByteToWideChar(CP_ACP, 0, cur->ai_canonname, -1, aiW->ai_canonname, wlen);
        }
        if (!headW) headW = aiW; else tailW->ai_next = aiW;
        tailW = aiW;
    }
    ex_freeaddrinfo(resA);
    *res = headW;
    return 0;
}

extern "C" void WSAAPI ex_FreeAddrInfoW(PADDRINFOW ai) {
    while (ai) {
        PADDRINFOW next = ai->ai_next;
        if (ai->ai_canonname) free(ai->ai_canonname);
        if (ai->ai_addr)      free(ai->ai_addr);
        free(ai);
        ai = next;
    }
}

extern "C" void WSAAPI ex_FreeAddrInfoExW(PADDRINFOEXW ai) {
    while (ai) {
        PADDRINFOEXW next = ai->ai_next;
        if (ai->ai_canonname) free((void*)ai->ai_canonname);
        if (ai->ai_addr) free((void*)ai->ai_addr);
        free(ai);
        ai = next;
    }
}

extern "C" void WSAAPI ex_FreeAddrInfoEx(PADDRINFOEXA ai) {
    while (ai) {
        PADDRINFOEXA next = ai->ai_next;
        if (ai->ai_canonname) free((void*)ai->ai_canonname);
        if (ai->ai_addr) free((void*)ai->ai_addr);
        free(ai);
        ai = next;
    }
}

extern "C" int WSAAPI ex_getnameinfo(const struct sockaddr* addr, int addrlen,
                                      char* host, DWORD hostlen,
                                      char* serv, DWORD servlen, int flags) {
    if (!addr) {
        SetLastError(WSAEFAULT);
        return EAI_FAIL;
    }
    
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;
        
        if (host && hostlen > 0) {
            const char* ip = ex_inet_ntoa(sin->sin_addr);
            if (strlen(ip) >= hostlen) {
                SetLastError(WSAEFAULT);
                return EAI_FAIL;
            }
            strcpy(host, ip);
        }
        
        if (serv && servlen > 0) {
            int port = ex_ntohs(sin->sin_port);
            char portstr[16];
            sprintf(portstr, "%d", port);
            if (strlen(portstr) >= servlen) {
                SetLastError(WSAEFAULT);
                return EAI_FAIL;
            }
            strcpy(serv, portstr);
        }
        
        return 0;
    }
    
    // IPv6 support
    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)addr;
        
        if (host && hostlen > 0) {
            char ipv6str[INET6_ADDRSTRLEN] = {0};
            const unsigned char* bytes = sin6->sin6_addr.s6_addr;
            
            // Convert IPv6 address to string
            sprintf(ipv6str, "%x:%x:%x:%x:%x:%x:%x:%x",
                    (bytes[0] << 8) | bytes[1],
                    (bytes[2] << 8) | bytes[3],
                    (bytes[4] << 8) | bytes[5],
                    (bytes[6] << 8) | bytes[7],
                    (bytes[8] << 8) | bytes[9],
                    (bytes[10] << 8) | bytes[11],
                    (bytes[12] << 8) | bytes[13],
                    (bytes[14] << 8) | bytes[15]);
            
            if (strlen(ipv6str) >= hostlen) {
                SetLastError(WSAEFAULT);
                return EAI_FAIL;
            }
            strcpy(host, ipv6str);
        }
        
        if (serv && servlen > 0) {
            int port = ex_ntohs(sin6->sin6_port);
            char portstr[16];
            sprintf(portstr, "%d", port);
            if (strlen(portstr) >= servlen) {
                SetLastError(WSAEFAULT);
                return EAI_FAIL;
            }
            strcpy(serv, portstr);
        }
        
        return 0;
    }
    
    SetLastError(WSAEAFNOSUPPORT);
    return EAI_FAMILY;
}

extern "C" int WSAAPI ex_GetNameInfoW(const SOCKADDR* addr, int addrlen,
                                       WCHAR* host, DWORD hostlen,
                                       WCHAR* serv, DWORD servlen, int flags) {
    char hostA[NI_MAXHOST] = {0};
    char servA[NI_MAXSERV] = {0};
    
    int ret = ex_getnameinfo(addr, addrlen, 
                             host ? hostA : NULL, host ? NI_MAXHOST : 0,
                             serv ? servA : NULL, serv ? NI_MAXSERV : 0, flags);
    
    if (ret == 0) {
        if (host) MultiByteToWideChar(CP_ACP, 0, hostA, -1, host, hostlen);
        if (serv) MultiByteToWideChar(CP_ACP, 0, servA, -1, serv, servlen);
    }
    
    return ret;
}

extern "C" int WSAAPI ex_gethostname(char* name, int namelen) {
    if (!g_nStartup) {
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    if (!name) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    InitLocalHostname();
    
    int name_len = (int)strlen(g_szHostName);
    
    if (name_len > 15) {
        LOG("Warning: hostname exceeds NetBIOS 15 char limit");
    }
    
    if (namelen <= name_len) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    strcpy(name, g_szHostName);
    return 0;
}

extern "C" int WSAAPI ex_GetHostNameW(WCHAR* name, int namelen) {
    if (!g_nStartup) {
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    if (!name) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    InitLocalHostname();
    
    int needed = MultiByteToWideChar(CP_ACP, 0, g_szHostName, -1, NULL, 0);
    if (namelen < needed) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    MultiByteToWideChar(CP_ACP, 0, g_szHostName, -1, name, namelen);
    return 0;
}

// =============================================================================
// SOCKET CORE FUNCTIONS
// =============================================================================

extern "C" {

int WSAAPI ex_WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData) {
    LOG("WSAStartup: Ver %d.%d", LOBYTE(wVersionRequested), HIBYTE(wVersionRequested));
    
    // Check version first (Wine behavior)
    if (!LOBYTE(wVersionRequested))
        return WSAVERNOTSUPPORTED;
    
    if (!lpWSAData) {
        SetLastError(WSAEFAULT);
        return WSAEFAULT;
    }
    
    // Determine version to return (Wine logic)
    if (!LOBYTE(wVersionRequested) || LOBYTE(wVersionRequested) > 2
            || (LOBYTE(wVersionRequested) == 2 && HIBYTE(wVersionRequested) > 2))
        lpWSAData->wVersion = MAKEWORD(2, 2);
    else if (LOBYTE(wVersionRequested) == 1 && HIBYTE(wVersionRequested) > 1)
        lpWSAData->wVersion = MAKEWORD(1, 1);
    else
        lpWSAData->wVersion = wVersionRequested;
    
    lpWSAData->wHighVersion = MAKEWORD(2, 2);
    strcpy(lpWSAData->szDescription, "WinSock 2.0 Emulator");
    strcpy(lpWSAData->szSystemStatus, "Running on Shared Memory");
    lpWSAData->iMaxSockets = (LOBYTE(wVersionRequested) == 1) ? 32767 : 0;
    lpWSAData->iMaxUdpDg = (LOBYTE(wVersionRequested) == 1) ? 65467 : 0;
    lpWSAData->lpVendorInfo = NULL;
    
    if (InterlockedIncrement(&g_nStartup) == 1) {
        // NOTE: InitLocalHostname() removed from here to avoid LoaderLock deadlock
        // (GetNetworkParams → exiphl → LoadLibrary(exws2.dll) → deadlock)
        // Hostname will be initialized lazily on first use (gethostname/GetHostNameW)
        if (!InitBackend()) {
            InterlockedDecrement(&g_nStartup);
            return WSASYSNOTREADY;
        }
    }
    
    return 0;
}

int WSAAPI ex_WSACleanup() {
    LOG("WSACleanup: startup count = %ld", g_nStartup);
    
    LONG prev = InterlockedDecrement(&g_nStartup);
    
    if (prev < 0) {
        InterlockedIncrement(&g_nStartup);
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    if (prev == 0) {
        // Cleanup all sockets owned by this process
        if (g_pState) {
            DWORD pid = GetCurrentProcessId();
            Lk();
            for (int i = 0; i < MAX_SHARED_SOCKETS; i++) {
                if (g_pState->sockets[i].in_use && g_pState->sockets[i].owner_pid == pid) {
                    g_pState->sockets[i].in_use = 0;
                }
            }
            Ulk();
            UnmapViewOfFile(g_pState);
            g_pState = NULL;
        }
        if (g_hMap) { CloseHandle(g_hMap); g_hMap = NULL; }
        if (g_hMtx) { CloseHandle(g_hMtx); g_hMtx = NULL; }
    }
    
    return 0;
}

int WSAAPI ex_WSAGetLastError() { return GetLastError(); }
void WSAAPI ex_WSASetLastError(int iError) { SetLastError(iError); }

SOCKET WSAAPI ex_socket(int af, int type, int protocol) {
    if (!g_nStartup || !g_pState) {
        SetLastError(WSANOTINITIALISED);
        return INVALID_SOCKET;
    }
    
    LOG("socket: af=%d, type=%d, protocol=%d", af, type, protocol);
    
    // Validate parameters (Wine behavior)
    if (!af && !protocol) {
        SetLastError(WSAEINVAL);
        return INVALID_SOCKET;
    }
    
    // Try to find matching protocol and fill in missing values
    const WSAPROTOCOL_INFOW* proto_info = FindProtocolInfo(af, type, protocol);
    
    if (!proto_info) {
        // Try auto-selection
        for (unsigned int i = 0; i < SUPPORTED_PROTOCOLS_COUNT; i++) {
            const WSAPROTOCOL_INFOW* info = &g_SupportedProtocols[i];
            
            if (af && af != info->iAddressFamily) continue;
            if (type && type != info->iSocketType) continue;
            if (protocol) {
                if (protocol < info->iProtocol || 
                    protocol > info->iProtocol + info->iProtocolMaxOffset)
                    continue;
            } else {
                if (!(info->dwProviderFlags & PFL_MATCHES_PROTOCOL_ZERO))
                    continue;
            }
            
            proto_info = info;
            if (!af) af = info->iAddressFamily;
            if (!type) type = info->iSocketType;
            if (!protocol) protocol = info->iProtocol;
            break;
        }
    }
    
    // Default if still not set
    if (!protocol) {
        if (type == SOCK_STREAM) protocol = IPPROTO_TCP;
        else if (type == SOCK_DGRAM) protocol = IPPROTO_UDP;
    }
    
    if (!Lk()) {
        SetLastError(WSAENOBUFS);
        return INVALID_SOCKET;
    }
    
    int idx = -1;
    for (int i = 0; i < MAX_SHARED_SOCKETS; i++) {
        if (!g_pState->sockets[i].in_use) {
            idx = i;
            break;
        }
    }
    
    if (idx < 0) {
        Ulk();
        SetLastError(WSAENOBUFS);
        return INVALID_SOCKET;
    }
    
    VSOCK* s = &g_pState->sockets[idx];
    memset(s, 0, sizeof(VSOCK));
    
    static volatile LONG id_gen = 1000;
    s->id = (SOCKET)(uintptr_t)InterlockedIncrement(&id_gen);
    s->owner_pid = GetCurrentProcessId();
    s->family = af;
    s->type = type;
    s->protocol = protocol;
    s->peer_index = -1;
    s->dgram_head = 0;
    s->dgram_tail = 0;
    s->in_use     = 1;
    
    SOCKET ret = s->id;
    Ulk();
    
    LOG("socket created: %d (af=%d, type=%d, proto=%d)", (int)ret, af, type, protocol);
    return ret;
}

SOCKET WSAAPI ex_WSASocketA(int af, int type, int protocol, LPWSAPROTOCOL_INFOA info, GROUP g, DWORD flags) {
    if (info && info->dwServiceFlags4 == 0xff00ff00) {
        // Duplicate socket magic
        return (SOCKET)info->dwServiceFlags3;
    }
    if (info) {
        if (af == FROM_PROTOCOL_INFO) af = info->iAddressFamily;
        if (type == FROM_PROTOCOL_INFO) type = info->iSocketType;
        if (protocol == FROM_PROTOCOL_INFO) protocol = info->iProtocol;
    }
    return ex_socket(af, type, protocol);
}

SOCKET WSAAPI ex_WSASocketW(int af, int type, int protocol, LPWSAPROTOCOL_INFOW info, GROUP g, DWORD flags) {
    if (info && info->dwServiceFlags4 == 0xff00ff00) {
        return (SOCKET)info->dwServiceFlags3;
    }
    if (info) {
        if (af == FROM_PROTOCOL_INFO) af = info->iAddressFamily;
        if (type == FROM_PROTOCOL_INFO) type = info->iSocketType;
        if (protocol == FROM_PROTOCOL_INFO) protocol = info->iProtocol;
    }
    return ex_socket(af, type, protocol);
}

int WSAAPI ex_closesocket(SOCKET s) {
    if (!g_nStartup || !g_pState) {
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    LOG("closesocket: %d", (int)s);
    
    Lk();
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        SetLastError(WSAENOTSOCK);
        return SOCKET_ERROR;
    }
    
    // Disconnect peer if connected (TCP only)
    if (sock->type == SOCK_STREAM && sock->is_connected && sock->peer_index >= 0 && sock->peer_index < MAX_SHARED_SOCKETS) {
        VSOCK* peer = &g_pState->sockets[sock->peer_index];
        if (peer->in_use) {
            peer->is_connected = 0;
            peer->peer_index = -1;
        }
    }
    
    memset(sock, 0, sizeof(VSOCK));
    sock->peer_index = -1;
    Ulk();
    
    return 0;
}

int WSAAPI ex_bind(SOCKET s, const struct sockaddr* addr, int namelen) {
    if (!g_nStartup || !g_pState) {
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    if (!addr) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    // Validate address length per family (Wine behavior)
    switch (addr->sa_family) {
        case AF_INET:
            if (namelen < (int)sizeof(struct sockaddr_in)) {
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            break;
        case AF_INET6:
            if (namelen < (int)sizeof(struct sockaddr_in6)) {
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            break;
        case AF_IPX:
            if (namelen < (int)sizeof(struct sockaddr_ipx)) {
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            break;
        default:
            SetLastError(WSAEAFNOSUPPORT);
            return SOCKET_ERROR;
    }
    
    Lk();
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        SetLastError(WSAENOTSOCK);
        return SOCKET_ERROR;
    }
    
    if (sock->is_bound) {
        Ulk();
        SetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    
    memcpy(&sock->local_addr, addr, min(namelen, (int)sizeof(sock->local_addr)));
    sock->local_addr_len = namelen;
    sock->is_bound = 1;
    
    LOG("bind: socket %d bound to port %d", (int)s, 
        (addr->sa_family == AF_INET) ? ex_ntohs(((struct sockaddr_in*)addr)->sin_port) : 0);
    
    Ulk();
    return 0;
}

int WSAAPI ex_listen(SOCKET s, int backlog) {
    if (!g_nStartup || !g_pState) {
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    Lk();
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        SetLastError(WSAENOTSOCK);
        return SOCKET_ERROR;
    }
    
    if (sock->type != SOCK_STREAM && sock->type != SOCK_SEQPACKET) {
        Ulk();
        SetLastError(WSAEOPNOTSUPP);
        return SOCKET_ERROR;
    }
    
    sock->is_listening = 1;
    LOG("listen: socket %d listening, backlog=%d", (int)s, backlog);
    Ulk();
    return 0;
}

static void AutoBind(VSOCK* s) {
    if (s->is_bound) return;
    u_short port = bswap_16((u_short)InterlockedIncrement(&g_nNextPort));
    if (s->family == AF_INET6) {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = port;
        ((unsigned char*)&sin6.sin6_addr)[15] = 1;
        memcpy(&s->local_addr, &sin6, sizeof(sin6));
        s->local_addr_len = sizeof(sin6);
    } else {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = 0x0100007F;
        sin.sin_port = port;
        memcpy(&s->local_addr, &sin, sizeof(sin));
        s->local_addr_len = sizeof(sin);
    }
    s->is_bound = 1;
}

// Forward declarations for cross-referencing
int WSAAPI ex_sendto(SOCKET s, const char* buf, int len, int flags,
                     const struct sockaddr* to, int tolen);
int WSAAPI ex_recvfrom(SOCKET s, char* buf, int len, int flags,
                       struct sockaddr* from, int* fromlen);

int WSAAPI ex_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (!g_nStartup || !g_pState) { SetLastError(WSANOTINITIALISED); return SOCKET_ERROR; }
    if (!name) { SetLastError(WSAEFAULT); return SOCKET_ERROR; }
    LOG("connect: socket %d", (int)s);

    Lk();
    VSOCK* c = FindSock(s);
    if (!c) { Ulk(); SetLastError(WSAENOTSOCK); return SOCKET_ERROR; }

    // UDP: just set default peer
    if (c->type == SOCK_DGRAM) {
        memcpy(&c->peer_addr, name, min(namelen, (int)sizeof(c->peer_addr)));
        c->peer_addr_len = namelen;
        c->is_connected = 1;
        AutoBind(c);
        LOG("connect (UDP): socket %d default peer set", (int)s);
        Ulk(); return 0;
    }

    // TCP
    if (c->is_connected) { Ulk(); SetLastError(WSAEISCONN); return SOCKET_ERROR; }
    AutoBind(c);
    memcpy(&c->peer_addr, name, min(namelen, (int)sizeof(c->peer_addr)));
    c->peer_addr_len = namelen;

    u_short port = 0;
    if (name->sa_family == AF_INET) port = ((struct sockaddr_in*)name)->sin_port;
    else if (name->sa_family == AF_INET6) port = ((struct sockaddr_in6*)name)->sin6_port;

    int lIdx = -1;
    for (int i = 0; i < MAX_SHARED_SOCKETS; i++) {
        VSOCK* t = &g_pState->sockets[i];
        if (!t->in_use || !t->is_listening || t->local_addr_len <= 0) continue;
        u_short t_port = 0;
        if (((struct sockaddr*)&t->local_addr)->sa_family == AF_INET)
            t_port = ((struct sockaddr_in*)&t->local_addr)->sin_port;
        else if (((struct sockaddr*)&t->local_addr)->sa_family == AF_INET6)
            t_port = ((struct sockaddr_in6*)&t->local_addr)->sin6_port;
        if (t_port == port) { lIdx = i; break; }
    }
    if (lIdx < 0) { Ulk(); SetLastError(WSAECONNREFUSED); return SOCKET_ERROR; }

    int sIdx = -1;
    for (int i = 0; i < MAX_SHARED_SOCKETS; i++)
        if (!g_pState->sockets[i].in_use) { sIdx = i; break; }
    if (sIdx < 0) { Ulk(); SetLastError(WSAENOBUFS); return SOCKET_ERROR; }

    VSOCK* srv = &g_pState->sockets[sIdx];
    memset(srv, 0, sizeof(VSOCK));
    static volatile LONG srv_id_gen = 100000;
    srv->id = (SOCKET)(uintptr_t)InterlockedIncrement(&srv_id_gen);
    srv->in_use = 1; srv->is_connected = 1; srv->peer_index = SockIdx(c);
    srv->family = c->family; srv->type = c->type; srv->protocol = c->protocol;
    srv->owner_pid = g_pState->sockets[lIdx].owner_pid;
    srv->connect_time = GetTickCount();
    memcpy(&srv->local_addr, &g_pState->sockets[lIdx].local_addr,
           g_pState->sockets[lIdx].local_addr_len);
    srv->local_addr_len = g_pState->sockets[lIdx].local_addr_len;
    memcpy(&srv->peer_addr, &c->local_addr, c->local_addr_len);
    srv->peer_addr_len = c->local_addr_len;

    c->is_connected = 1; c->peer_index = sIdx; c->connect_time = GetTickCount();
    VSOCK* l = &g_pState->sockets[lIdx];
    if (l->accept_count < MAX_PENDING_CONN)
        l->accept_queue[l->accept_count++] = sIdx;
    LOG("connect: socket %d -> listener %d, server socket %d", (int)s, lIdx, sIdx);
    Ulk(); return 0;
}

SOCKET WSAAPI ex_accept(SOCKET s, struct sockaddr* addr, int* addrlen) {
    if (!g_nStartup || !g_pState) {
        SetLastError(WSANOTINITIALISED);
        return INVALID_SOCKET;
    }
    
    LOG("accept: socket %d", (int)s);
    
    while (1) {
        Lk();
        VSOCK* l = FindSock(s);
        if (!l || !l->is_listening) {
            Ulk();
            SetLastError(WSAEINVAL);
            return INVALID_SOCKET;
        }
        
        if (l->accept_count > 0) {
            int idx = l->accept_queue[0];
            
            // Shift queue
            for (int i = 0; i < l->accept_count - 1; i++) {
                l->accept_queue[i] = l->accept_queue[i + 1];
            }
            l->accept_count--;
            
            VSOCK* client_sock = &g_pState->sockets[idx];
            
            if (addr && addrlen && *addrlen > 0) {
                // Return peer (client) address
                if (client_sock->peer_index >= 0 && client_sock->peer_index < MAX_SHARED_SOCKETS) {
                    VSOCK* peer = &g_pState->sockets[client_sock->peer_index];
                    int copy_len = min(*addrlen, peer->local_addr_len);
                    memcpy(addr, &peer->local_addr, copy_len);
                    *addrlen = peer->local_addr_len;
                }
            }
            
            SOCKET ret = client_sock->id;
            LOG("accept: returning socket %d", (int)ret);
            Ulk();
            return ret;
        }
        
        if (l->is_nonblocking) {
            Ulk();
            SetLastError(WSAEWOULDBLOCK);
            return INVALID_SOCKET;
        }
        
        Ulk();
        Sleep(1);
    }
}

int WSAAPI ex_send(SOCKET s, const char* buf, int len, int flags) {
    if (!g_nStartup || !g_pState) {
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    if (!buf) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    // UDP -> delegate to sendto
    Lk();
    VSOCK* chk = FindSock(s);
    if (!chk) { Ulk(); SetLastError(WSAENOTSOCK); return SOCKET_ERROR; }
    if (chk->type == SOCK_DGRAM) { Ulk(); return ex_sendto(s, buf, len, flags, NULL, 0); }
    Ulk();
    
    DWORD start = GetTickCount();
    
    while (1) {
        Lk();
        VSOCK* sock = FindSock(s);
        if (!sock) {
            Ulk();
            SetLastError(WSAENOTSOCK);
            return SOCKET_ERROR;
        }
        
        if (!sock->is_connected) {
            Ulk();
            SetLastError(WSAENOTCONN);
            return SOCKET_ERROR;
        }
        
        if (sock->is_shutdown_send) {
            Ulk();
            SetLastError(WSAESHUTDOWN);
            return SOCKET_ERROR;
        }
        
        if (sock->peer_index < 0 || sock->peer_index >= MAX_SHARED_SOCKETS) {
            Ulk();
            SetLastError(WSAENOTCONN);
            return SOCKET_ERROR;
        }
        
        VSOCK* peer = &g_pState->sockets[sock->peer_index];
        
        if (!peer->in_use) {
            sock->is_connected = 0;
            Ulk();
            SetLastError(WSAECONNRESET);
            return SOCKET_ERROR;
        }
        
        size_t free_space = BufFree(peer);
        if (free_space >= (size_t)len) {
            BufWrite(peer, buf, len);
            Ulk();
            return len;
        }
        
        if (sock->is_nonblocking) {
            Ulk();
            SetLastError(WSAEWOULDBLOCK);
            return SOCKET_ERROR;
        }
        
        // Check timeout
        if (sock->so_sndtimeo > 0) {
            if (GetTickCount() - start >= sock->so_sndtimeo) {
                Ulk();
                SetLastError(WSAETIMEDOUT);
                return SOCKET_ERROR;
            }
        }
        
        Ulk();
        Sleep(1);
    }
}

int WSAAPI ex_recv(SOCKET s, char* buf, int len, int flags) {
    if (!g_nStartup || !g_pState) {
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    if (!buf) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    // UDP -> delegate to recvfrom
    Lk();
    VSOCK* chk = FindSock(s);
    if (!chk) { Ulk(); SetLastError(WSAENOTSOCK); return SOCKET_ERROR; }
    if (chk->type == SOCK_DGRAM) { Ulk(); return ex_recvfrom(s, buf, len, flags, NULL, NULL); }
    Ulk();
    
    DWORD start = GetTickCount();
    
    while (1) {
        Lk();
        VSOCK* sock = FindSock(s);
        if (!sock) {
            Ulk();
            SetLastError(WSAENOTSOCK);
            return SOCKET_ERROR;
        }
        
        size_t avail = BufUsed(sock);
        if (avail > 0) {
            int to_read = min(len, (int)avail);
            BufRead(sock, buf, to_read, !(flags & MSG_PEEK));
            Ulk();
            return to_read;
        }
        
        // Connection closed gracefully
        if (!sock->is_connected) {
            Ulk();
            return 0;
        }
        
        // Check if peer is still alive
        if (sock->peer_index >= 0 && sock->peer_index < MAX_SHARED_SOCKETS) {
            VSOCK* peer = &g_pState->sockets[sock->peer_index];
            if (!peer->in_use) {
                sock->is_connected = 0;
                Ulk();
                return 0;
            }
        }
        
        if (sock->is_nonblocking) {
            Ulk();
            SetLastError(WSAEWOULDBLOCK);
            return SOCKET_ERROR;
        }
        
        // Check timeout
        if (sock->so_rcvtimeo > 0) {
            if (GetTickCount() - start >= sock->so_rcvtimeo) {
                Ulk();
                SetLastError(WSAETIMEDOUT);
                return SOCKET_ERROR;
            }
        }
        
        Ulk();
        Sleep(1);
    }
}

int WSAAPI ex_sendto(SOCKET s, const char* buf, int len, int flags,
                     const struct sockaddr* to, int tolen) {
    if (!g_nStartup || !g_pState) { SetLastError(WSANOTINITIALISED); return SOCKET_ERROR; }
    if (!buf) { SetLastError(WSAEFAULT); return SOCKET_ERROR; }

    Lk();
    VSOCK* sock = FindSock(s);
    if (!sock) { Ulk(); SetLastError(WSAENOTSOCK); return SOCKET_ERROR; }

    // TCP -> delegate
    if (sock->type == SOCK_STREAM) { Ulk(); return ex_send(s, buf, len, flags); }

    // UDP
    if (sock->is_shutdown_send) { Ulk(); SetLastError(WSAESHUTDOWN); return SOCKET_ERROR; }

    const struct sockaddr* dest = to;
    int dest_len = tolen;
    if (!dest || dest_len <= 0) {
        if (!sock->is_connected || sock->peer_addr_len <= 0) {
            Ulk(); SetLastError(WSAENOTCONN); return SOCKET_ERROR;
        }
        dest = (const struct sockaddr*)&sock->peer_addr;
        dest_len = sock->peer_addr_len;
    }

    AutoBind(sock);
    if (len > DGRAM_SLOT_SIZE) { Ulk(); SetLastError(WSAEMSGSIZE); return SOCKET_ERROR; }

    VSOCK* target = FindUDPTarget(sock->family, dest);
    if (!target) { Ulk(); return len; } // no receiver - silently drop

    if (!DgramEnqueue(target, (const struct sockaddr*)&sock->local_addr,
                      sock->local_addr_len, buf, len)) {
        if (sock->is_nonblocking) { Ulk(); SetLastError(WSAEWOULDBLOCK); return SOCKET_ERROR; }
        Ulk(); return len; // queue full - drop
    }
    LOG("sendto: %d bytes socket %d -> socket %d", len, (int)s, (int)target->id);
    Ulk(); return len;
}

int WSAAPI ex_recvfrom(SOCKET s, char* buf, int len, int flags,
                       struct sockaddr* from, int* fromlen) {
    if (!g_nStartup || !g_pState) { SetLastError(WSANOTINITIALISED); return SOCKET_ERROR; }
    if (!buf) { SetLastError(WSAEFAULT); return SOCKET_ERROR; }

    Lk();
    VSOCK* chk = FindSock(s);
    if (!chk) { Ulk(); SetLastError(WSAENOTSOCK); return SOCKET_ERROR; }
    BOOL is_udp = (chk->type == SOCK_DGRAM);
    Ulk();

    // TCP -> delegate
    if (!is_udp) {
        int ret = ex_recv(s, buf, len, flags);
        if (ret > 0 && from && fromlen && *fromlen > 0) {
            Lk();
            VSOCK* sock2 = FindSock(s);
            if (sock2 && sock2->peer_addr_len > 0) {
                int cl = min(*fromlen, sock2->peer_addr_len);
                memcpy(from, &sock2->peer_addr, cl);
                *fromlen = sock2->peer_addr_len;
            }
            Ulk();
        }
        return ret;
    }

    // UDP
    DWORD start = GetTickCount();
    while (1) {
        Lk();
        VSOCK* sock = FindSock(s);
        if (!sock) { Ulk(); SetLastError(WSAENOTSOCK); return SOCKET_ERROR; }
        BOOL peek = (flags & MSG_PEEK) != 0;
        int ret = DgramDequeue(sock, buf, len, from, fromlen, peek);
        if (ret >= 0) {
            LOG("recvfrom: %d bytes on socket %d", ret, (int)s);
            Ulk(); return ret;
        }
        if (sock->is_nonblocking) { Ulk(); SetLastError(WSAEWOULDBLOCK); return SOCKET_ERROR; }
        if (sock->so_rcvtimeo > 0 && GetTickCount() - start >= sock->so_rcvtimeo) {
            Ulk(); SetLastError(WSAETIMEDOUT); return SOCKET_ERROR;
        }
        Ulk(); Sleep(1);
    }
}

int WSAAPI ex___WSAFDIsSet(SOCKET s, fd_set* set) {
    if (!set) return 0;
    for (u_int i = 0; i < set->fd_count; i++) {
        if (set->fd_array[i] == s) return 1;
    }
    return 0;
}

int WSAAPI ex_ioctlsocket(SOCKET s, long cmd, u_long* argp) {
    if (!g_nStartup || !g_pState) {
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    if (!argp) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    Lk();
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        SetLastError(WSAENOTSOCK);
        return SOCKET_ERROR;
    }
    
    int ret = 0;
    switch ((u_long)cmd) {
        case FIONBIO:
            sock->is_nonblocking = (*argp != 0);
            LOG("ioctlsocket: FIONBIO = %lu", *argp);
            break;
        case FIONREAD:
            if (sock->type == SOCK_DGRAM) {
                if (DgramCount(sock) > 0) {
                    int idx = sock->dgram_head % MAX_DGRAM_QUEUE;
                    *argp = (u_long)sock->dgram_queue[idx].data_len;
                } else {
                    *argp = 0;
                }
            } else {
                *argp = (u_long)BufUsed(sock);
            }
            break;
        case SIOCATMARK:
            *argp = 0;
            break;
        default:
            ret = SOCKET_ERROR;
            SetLastError(WSAEINVAL);
            break;
    }
    
    Ulk();
    return ret;
}

int WSAAPI ex_select(int nfds, fd_set* readfds, fd_set* writefds, 
                     fd_set* exceptfds, const struct timeval* timeout) {
    if (!g_nStartup || !g_pState) {
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    // Check for empty set (Wine behavior)
    DWORD poll_count = 0;
    if (readfds) poll_count += readfds->fd_count;
    if (writefds) poll_count += writefds->fd_count;
    if (exceptfds) poll_count += exceptfds->fd_count;
    
    if (!poll_count) {
        SetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    
    DWORD timeout_ms = timeout ? (timeout->tv_sec * 1000 + timeout->tv_usec / 1000) : INFINITE;
    DWORD start = GetTickCount();
    
    fd_set in_read = {0}, in_write = {0};
    if (readfds) memcpy(&in_read, readfds, sizeof(fd_set));
    if (writefds) memcpy(&in_write, writefds, sizeof(fd_set));
    
    int total = 0;
    
    while (TRUE) {
        if (readfds) readfds->fd_count = 0;
        if (writefds) writefds->fd_count = 0;
        if (exceptfds) exceptfds->fd_count = 0;
        total = 0;
        
        Lk();
        
        // Check read sockets
        for (u_int i = 0; i < in_read.fd_count; i++) {
            SOCKET sock_id = in_read.fd_array[i];
            VSOCK* sock = FindSock(sock_id);
            if (!sock) continue;
            
            BOOL ready = FALSE;
            if (sock->is_listening) {
                if (sock->accept_count > 0) ready = TRUE;
            } else if (sock->type == SOCK_DGRAM) {
                if (DgramCount(sock) > 0) ready = TRUE;
            } else {
                if (BufUsed(sock) > 0) ready = TRUE;
                else if (!sock->is_connected) ready = TRUE;
            }
            
            if (ready && readfds && readfds->fd_count < FD_SETSIZE) {
                readfds->fd_array[readfds->fd_count++] = sock_id;
            }
        }
        
        // Check write sockets
        for (u_int i = 0; i < in_write.fd_count; i++) {
            SOCKET sock_id = in_write.fd_array[i];
            VSOCK* sock = FindSock(sock_id);
            if (!sock) continue;
            
            BOOL ready = FALSE;
            if (sock->type == SOCK_DGRAM) {
                ready = TRUE;
            } else if (sock->is_connected && sock->peer_index >= 0 && sock->peer_index < MAX_SHARED_SOCKETS) {
                VSOCK* peer = &g_pState->sockets[sock->peer_index];
                if (peer->in_use && BufFree(peer) > 0) ready = TRUE;
            }
            
            if (ready && writefds && writefds->fd_count < FD_SETSIZE) {
                writefds->fd_array[writefds->fd_count++] = sock_id;
            }
        }
        
        Ulk();
        
        total = (readfds ? readfds->fd_count : 0) + (writefds ? writefds->fd_count : 0);
        
        if (total > 0 || timeout_ms == 0) break;
        if (timeout_ms != INFINITE && (GetTickCount() - start >= timeout_ms)) break;
        
        Sleep(1);
    }
    
    return total;
}

int WSAAPI ex_WSAPoll(LPWSAPOLLFD fdArray, ULONG fds, INT timeout) {
    if (!g_nStartup || !g_pState) {
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    if (!fdArray || fds == 0) {
        SetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    
    DWORD start = GetTickCount();
    DWORD wait_ms = (timeout >= 0) ? (DWORD)timeout : INFINITE;
    int total = 0;
    
    while (TRUE) {
        total = 0;
        Lk();
        
        for (ULONG i = 0; i < fds; i++) {
            fdArray[i].revents = 0;
            VSOCK* sock = FindSock(fdArray[i].fd);
            
            if (!sock) {
                fdArray[i].revents |= POLLNVAL;
                total++;
                continue;
            }
            
            if (fdArray[i].events & POLLIN) {
                if (sock->is_listening) {
                    if (sock->accept_count > 0) fdArray[i].revents |= POLLIN;
                } else if (sock->type == SOCK_DGRAM) {
                    if (DgramCount(sock) > 0) fdArray[i].revents |= POLLIN;
                } else {
                    if (BufUsed(sock) > 0) fdArray[i].revents |= POLLIN;
                    else if (!sock->is_connected) fdArray[i].revents |= POLLHUP;
                }
            }
            
            if (fdArray[i].events & POLLOUT) {
                if (sock->type == SOCK_DGRAM) {
                    fdArray[i].revents |= POLLOUT;
                } else if (sock->is_connected && sock->peer_index >= 0
                           && sock->peer_index < MAX_SHARED_SOCKETS) {
                    VSOCK* peer = &g_pState->sockets[sock->peer_index];
                    if (peer->in_use && BufFree(peer) > 0)
                        fdArray[i].revents |= POLLOUT;
                }
            }
            
            if (fdArray[i].revents != 0) total++;
        }
        
        Ulk();
        
        if (total > 0 || wait_ms == 0) break;
        if (wait_ms != INFINITE && (GetTickCount() - start >= wait_ms)) break;
        
        Sleep(1);
    }
    
    return total;
}

int WSAAPI ex_getsockname(SOCKET s, struct sockaddr* name, int* namelen) {
    if (!g_nStartup || !g_pState) {
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    if (!name || !namelen) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    Lk();
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        SetLastError(WSAENOTSOCK);
        return SOCKET_ERROR;
    }
    
    if (sock->is_bound || sock->is_connected) {
        int copy_len = min(*namelen, sock->local_addr_len);
        memcpy(name, &sock->local_addr, copy_len);
        *namelen = sock->local_addr_len;
    } else {
        struct sockaddr_in temp = {0};
        temp.sin_family = AF_INET;
        int copy_len = min(*namelen, (int)sizeof(temp));
        memcpy(name, &temp, copy_len);
        *namelen = sizeof(temp);
    }
    
    Ulk();
    return 0;
}

int WSAAPI ex_getpeername(SOCKET s, struct sockaddr* name, int* namelen) {
    if (!g_nStartup || !g_pState) {
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    if (!name || !namelen) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    Lk();
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        SetLastError(WSAENOTSOCK);
        return SOCKET_ERROR;
    }
    
    if (!sock->is_connected) {
        Ulk();
        SetLastError(WSAENOTCONN);
        return SOCKET_ERROR;
    }
    
    // Use stored peer address
    if (sock->peer_addr_len > 0) {
        int copy_len = min(*namelen, sock->peer_addr_len);
        memcpy(name, &sock->peer_addr, copy_len);
        *namelen = sock->peer_addr_len;
    } else if (sock->peer_index >= 0 && sock->peer_index < MAX_SHARED_SOCKETS) {
        VSOCK* peer = &g_pState->sockets[sock->peer_index];
        int copy_len = min(*namelen, peer->local_addr_len);
        memcpy(name, &peer->local_addr, copy_len);
        *namelen = peer->local_addr_len;
    }
    
    Ulk();
    return 0;
}

int WSAAPI ex_shutdown(SOCKET s, int how) {
    if (!g_nStartup || !g_pState) {
        SetLastError(WSANOTINITIALISED);
        return SOCKET_ERROR;
    }
    
    Lk();
    VSOCK* sock = FindSock(s);
    if (!sock) {
        Ulk();
        SetLastError(WSAENOTSOCK);
        return SOCKET_ERROR;
    }
    
    if (how == SD_RECEIVE || how == SD_BOTH) {
        sock->is_shutdown_recv = 1;
    }
    if (how == SD_SEND || how == SD_BOTH) {
        sock->is_shutdown_send = 1;
    }
    
    Ulk();
    return 0;
}

int WSAAPI ex_setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen) {
    if (!g_nStartup || !g_pState) { SetLastError(WSANOTINITIALISED); return SOCKET_ERROR; }
    if (optlen > 0 && !optval) { SetLastError(WSAEFAULT); return SOCKET_ERROR; }

    Lk();
    VSOCK* sock = FindSock(s);
    if (!sock) { Ulk(); SetLastError(WSAENOTSOCK); return SOCKET_ERROR; }

    if (level == SOL_SOCKET) {
        switch (optname) {
            case SO_BROADCAST:   if (optlen >= (int)sizeof(int)) sock->so_broadcast = *(int*)optval; break;
            case SO_KEEPALIVE:   if (optlen >= (int)sizeof(int)) sock->so_keepalive = *(int*)optval; break;
            case SO_REUSEADDR:   if (optlen >= (int)sizeof(int)) sock->so_reuseaddr = *(int*)optval; break;
            case SO_EXCLUSIVEADDRUSE: if (optlen >= (int)sizeof(int)) sock->so_exclusiveaddruse = *(int*)optval; break;
            case SO_OOBINLINE:   if (optlen >= (int)sizeof(int)) sock->so_oobinline = *(int*)optval; break;
            case SO_RCVTIMEO:
                if (optlen >= (int)sizeof(DWORD)) sock->so_rcvtimeo = *(DWORD*)optval;
                else if (optlen >= (int)sizeof(int)) sock->so_rcvtimeo = *(int*)optval;
                break;
            case SO_SNDTIMEO:
                if (optlen >= (int)sizeof(DWORD)) sock->so_sndtimeo = *(DWORD*)optval;
                else if (optlen >= (int)sizeof(int)) sock->so_sndtimeo = *(int*)optval;
                break;
            case SO_DEBUG: case SO_DONTROUTE: case SO_LINGER: case SO_RCVBUF: case SO_SNDBUF:
                break;
        }
    } else if (level == IPPROTO_TCP) {
        if (optname == TCP_NODELAY && optlen >= (int)sizeof(int))
            sock->tcp_nodelay = *(int*)optval;
    } else if (level == IPPROTO_IPV6) {
        switch (optname) {
            case IPV6_V6ONLY: if (optlen >= (int)sizeof(int)) sock->ipv6_v6only = *(int*)optval; break;
            case IPV6_UNICAST_HOPS: case IPV6_MULTICAST_HOPS: case IPV6_MULTICAST_LOOP:
            case IPV6_JOIN_GROUP: case IPV6_LEAVE_GROUP: break;
        }
    } else if (level == IPPROTO_IP) {
        switch (optname) {
            case IP_TTL: case IP_MULTICAST_TTL: case IP_MULTICAST_LOOP:
            case IP_ADD_MEMBERSHIP: case IP_DROP_MEMBERSHIP:
            case IP_TOS: case IP_DONTFRAGMENT: break;
        }
    }
    Ulk(); return 0;
}

int WSAAPI ex_getsockopt(SOCKET s, int level, int optname, char* optval, int* optlen) {
    if (!g_nStartup || !g_pState) { SetLastError(WSANOTINITIALISED); return SOCKET_ERROR; }
    if (!optval || !optlen) { SetLastError(WSAEFAULT); return SOCKET_ERROR; }

    Lk();
    VSOCK* sock = FindSock(s);
    if (!sock) { Ulk(); SetLastError(WSAENOTSOCK); return SOCKET_ERROR; }

    if (level == SOL_SOCKET) {
        switch (optname) {
            case SO_ERROR:
                if (*optlen >= (int)sizeof(int)) { *(int*)optval = 0; *optlen = sizeof(int); } break;
            case SO_TYPE:
                if (*optlen >= (int)sizeof(int)) { *(int*)optval = sock->type; *optlen = sizeof(int); } break;
            case SO_ACCEPTCONN:
                if (*optlen >= (int)sizeof(int)) { *(int*)optval = sock->is_listening ? 1 : 0; *optlen = sizeof(int); } break;
            case SO_BROADCAST:
                if (*optlen >= (int)sizeof(int)) { *(int*)optval = sock->so_broadcast; *optlen = sizeof(int); } break;
            case SO_KEEPALIVE:
                if (*optlen >= (int)sizeof(int)) { *(int*)optval = sock->so_keepalive; *optlen = sizeof(int); } break;
            case SO_REUSEADDR:
                if (*optlen >= (int)sizeof(int)) { *(int*)optval = sock->so_reuseaddr; *optlen = sizeof(int); } break;
            case SO_RCVBUF: case SO_SNDBUF:
                if (*optlen >= (int)sizeof(int)) { *(int*)optval = BUFFER_PER_SOCKET; *optlen = sizeof(int); } break;
            case SO_RCVTIMEO:
                if (*optlen >= (int)sizeof(DWORD)) { *(DWORD*)optval = sock->so_rcvtimeo; *optlen = sizeof(DWORD); } break;
            case SO_SNDTIMEO:
                if (*optlen >= (int)sizeof(DWORD)) { *(DWORD*)optval = sock->so_sndtimeo; *optlen = sizeof(DWORD); } break;
            case SO_CONNECT_TIME:
                if (*optlen >= (int)sizeof(DWORD)) {
                    if (sock->is_connected && sock->connect_time > 0)
                        *(DWORD*)optval = (GetTickCount() - sock->connect_time) / 1000;
                    else *(DWORD*)optval = 0xFFFFFFFF;
                    *optlen = sizeof(DWORD);
                } break;
            case SO_PROTOCOL_INFOA: case SO_PROTOCOL_INFOW: {
                Ulk();
                int size; BOOL unicode = (optname == SO_PROTOCOL_INFOW);
                if (!GetSocketProtocolInfo(s, unicode, NULL, &size)) return SOCKET_ERROR;
                if (*optlen < size) { *optlen = size; SetLastError(WSAEFAULT); return SOCKET_ERROR; }
                if (!GetSocketProtocolInfo(s, unicode, optval, &size)) return SOCKET_ERROR;
                *optlen = size; return 0;
            }
            default: memset(optval, 0, *optlen); break;
        }
    } else if (level == IPPROTO_TCP) {
        if (optname == TCP_NODELAY && *optlen >= (int)sizeof(int)) {
            *(int*)optval = sock->tcp_nodelay; *optlen = sizeof(int);
        } else memset(optval, 0, *optlen);
    } else if (level == IPPROTO_IPV6) {
        if (optname == IPV6_V6ONLY && *optlen >= (int)sizeof(int)) {
            *(int*)optval = sock->ipv6_v6only; *optlen = sizeof(int);
        } else memset(optval, 0, *optlen);
    } else if (level == IPPROTO_IP) {
        memset(optval, 0, *optlen);
    } else {
        memset(optval, 0, *optlen);
    }
    Ulk(); return 0;
}

// =============================================================================
// WSA OVERLAPPED FUNCTIONS
// =============================================================================

int WSAAPI ex_WSARecv(SOCKET s, LPWSABUF bufs, DWORD bufcount, LPDWORD received,
                      LPDWORD flags, LPWSAOVERLAPPED overlapped,
                      LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    if (!bufs || bufcount == 0 || !received) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    DWORD total = 0;
    for (DWORD i = 0; i < bufcount; i++) {
        int ret = ex_recv(s, bufs[i].buf, bufs[i].len, flags ? *flags : 0);
        if (ret == SOCKET_ERROR) {
            if (total > 0) break;
            return SOCKET_ERROR;
        }
        total += ret;
        if ((DWORD)ret < bufs[i].len) break;
    }
    
    *received = total;
    return 0;
}

int WSAAPI ex_WSASend(SOCKET s, LPWSABUF bufs, DWORD bufcount, LPDWORD sent,
                      DWORD flags, LPWSAOVERLAPPED overlapped,
                      LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    if (!bufs || bufcount == 0 || !sent) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    DWORD total = 0;
    for (DWORD i = 0; i < bufcount; i++) {
        int ret = ex_send(s, bufs[i].buf, bufs[i].len, flags);
        if (ret == SOCKET_ERROR) {
            if (total > 0) break;
            return SOCKET_ERROR;
        }
        total += ret;
        if ((DWORD)ret < bufs[i].len) break;
    }
    
    *sent = total;
    return 0;
}

int WSAAPI ex_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD bufcount, LPDWORD received,
                          LPDWORD flags, struct sockaddr* from, LPINT fromlen,
                          LPWSAOVERLAPPED overlapped,
                          LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    if (!bufs || bufcount == 0 || !received) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    int ret = ex_recvfrom(s, bufs[0].buf, bufs[0].len, flags ? *flags : 0, from, fromlen);
    if (ret == SOCKET_ERROR) return SOCKET_ERROR;
    
    *received = ret;
    return 0;
}

int WSAAPI ex_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD bufcount, LPDWORD sent,
                        DWORD flags, const struct sockaddr* to, int tolen,
                        LPWSAOVERLAPPED overlapped,
                        LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    if (!bufs || bufcount == 0 || !sent) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    int ret = ex_sendto(s, bufs[0].buf, bufs[0].len, flags, to, tolen);
    if (ret == SOCKET_ERROR) return SOCKET_ERROR;
    
    *sent = ret;
    return 0;
}

int WSAAPI ex_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen,
                         LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                         LPQOS lpSQOS, LPQOS lpGQOS) {
    return ex_connect(s, name, namelen);
}

SOCKET WSAAPI ex_WSAAccept(SOCKET s, struct sockaddr* addr, int* addrlen,
                           LPCONDITIONPROC condition, DWORD_PTR callbackData) {
    return ex_accept(s, addr, addrlen);
}

// =============================================================================
// PROTOCOL ENUMERATION
// =============================================================================

int WSAAPI ex_WSAEnumProtocolsA(LPINT lpiProtocols, LPWSAPROTOCOL_INFOA lpProtocolBuffer,
                                 LPDWORD lpdwBufferLength) {
    if (!lpdwBufferLength) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    DWORD count = 0;
    for (unsigned int i = 0; i < SUPPORTED_PROTOCOLS_COUNT; i++) {
        if (protocol_matches_filter(lpiProtocols, i)) count++;
    }
    
    DWORD needed = count * sizeof(WSAPROTOCOL_INFOA);
    
    if (!lpProtocolBuffer || *lpdwBufferLength < needed) {
        *lpdwBufferLength = needed;
        SetLastError(WSAENOBUFS);
        return SOCKET_ERROR;
    }
    
    count = 0;
    for (unsigned int i = 0; i < SUPPORTED_PROTOCOLS_COUNT; i++) {
        if (protocol_matches_filter(lpiProtocols, i)) {
            const WSAPROTOCOL_INFOW* src = &g_SupportedProtocols[i];
            WSAPROTOCOL_INFOA* dst = &lpProtocolBuffer[count];
            
            // Копіюємо поля вручну замість offsetof
            dst->dwServiceFlags1 = src->dwServiceFlags1;
            dst->dwServiceFlags2 = src->dwServiceFlags2;
            dst->dwServiceFlags3 = src->dwServiceFlags3;
            dst->dwServiceFlags4 = src->dwServiceFlags4;
            dst->dwProviderFlags = src->dwProviderFlags;
            dst->ProviderId = src->ProviderId;
            dst->dwCatalogEntryId = src->dwCatalogEntryId;
            dst->ProtocolChain = src->ProtocolChain;
            dst->iVersion = src->iVersion;
            dst->iAddressFamily = src->iAddressFamily;
            dst->iMaxSockAddr = src->iMaxSockAddr;
            dst->iMinSockAddr = src->iMinSockAddr;
            dst->iSocketType = src->iSocketType;
            dst->iProtocol = src->iProtocol;
            dst->iProtocolMaxOffset = src->iProtocolMaxOffset;
            dst->iNetworkByteOrder = src->iNetworkByteOrder;
            dst->iSecurityScheme = src->iSecurityScheme;
            dst->dwMessageSize = src->dwMessageSize;
            dst->dwProviderReserved = src->dwProviderReserved;
            
            WideCharToMultiByte(CP_ACP, 0, src->szProtocol, -1,
                               dst->szProtocol, sizeof(dst->szProtocol), NULL, NULL);
            count++;
        }
    }
    
    return (int)count;
}

int WSAAPI ex_WSAEnumProtocolsW(LPINT lpiProtocols, LPWSAPROTOCOL_INFOW lpProtocolBuffer,
                                 LPDWORD lpdwBufferLength) {
    if (!lpdwBufferLength) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    DWORD count = 0;
    for (unsigned int i = 0; i < SUPPORTED_PROTOCOLS_COUNT; i++) {
        if (protocol_matches_filter(lpiProtocols, i)) count++;
    }
    
    DWORD needed = count * sizeof(WSAPROTOCOL_INFOW);
    
    if (!lpProtocolBuffer || *lpdwBufferLength < needed) {
        *lpdwBufferLength = needed;
        SetLastError(WSAENOBUFS);
        return SOCKET_ERROR;
    }
    
    count = 0;
    for (unsigned int i = 0; i < SUPPORTED_PROTOCOLS_COUNT; i++) {
        if (protocol_matches_filter(lpiProtocols, i)) {
            lpProtocolBuffer[count++] = g_SupportedProtocols[i];
        }
    }
    
    return (int)count;
}

int WSAAPI ex_WSCEnumProtocols(LPINT lpiProtocols, LPWSAPROTOCOL_INFOW lpProtocolBuffer,
                                LPDWORD lpdwBufferLength, LPINT lpErrno) {
    int ret = ex_WSAEnumProtocolsW(lpiProtocols, lpProtocolBuffer, lpdwBufferLength);
    if (ret == SOCKET_ERROR && lpErrno) {
        *lpErrno = GetLastError();
    }
    return ret;
}

// =============================================================================
// EVENT & OVERLAPPED FUNCTIONS
// =============================================================================

BOOL WSAAPI ex_WSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED overlapped,
                                       LPDWORD transferred, BOOL wait, LPDWORD flags) {
    if (!overlapped || !transferred) {
        SetLastError(WSAEINVAL);
        return FALSE;
    }
    *transferred = (DWORD)overlapped->InternalHigh;
    if (flags) *flags = 0;
    return TRUE;
}

int WSAAPI ex_WSACancelBlockingCall() { return 0; }
BOOL WSAAPI ex_WSAIsBlocking() { return FALSE; }
FARPROC WSAAPI ex_WSASetBlockingHook(FARPROC f) { return NULL; }
int WSAAPI ex_WSAUnhookBlockingHook() { return 0; }

WSAEVENT WSAAPI ex_WSACreateEvent() {
    return CreateEventW(NULL, TRUE, FALSE, NULL);
}

BOOL WSAAPI ex_WSACloseEvent(WSAEVENT hEvent) {
    return CloseHandle(hEvent);
}

BOOL WSAAPI ex_WSASetEvent(WSAEVENT hEvent) {
    return SetEvent(hEvent);
}

BOOL WSAAPI ex_WSAResetEvent(WSAEVENT hEvent) {
    return ResetEvent(hEvent);
}

DWORD WSAAPI ex_WSAWaitForMultipleEvents(DWORD cEvents, const WSAEVENT* lphEvents,
                                          BOOL fWaitAll, DWORD dwTimeout, BOOL fAlertable) {
    return WaitForMultipleObjectsEx(cEvents, lphEvents, fWaitAll, dwTimeout, fAlertable);
}

int WSAAPI ex_WSAEventSelect(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents) {
    // Store event association - simplified implementation
    return 0;
}

int WSAAPI ex_WSAEnumNetworkEvents(SOCKET s, WSAEVENT hEventObject,
                                    LPWSANETWORKEVENTS lpNetworkEvents) {
    if (!lpNetworkEvents) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    memset(lpNetworkEvents, 0, sizeof(WSANETWORKEVENTS));
    
    if (hEventObject) ResetEvent(hEventObject);
    
    Lk();
    VSOCK* sock = FindSock(s);
    if (sock) {
        if (sock->is_listening && sock->accept_count > 0)
            lpNetworkEvents->lNetworkEvents |= FD_ACCEPT;

        if (!sock->is_listening) {
            if (sock->type == SOCK_DGRAM) {
                if (DgramCount(sock) > 0)
                    lpNetworkEvents->lNetworkEvents |= FD_READ;
                lpNetworkEvents->lNetworkEvents |= FD_WRITE;
            } else {
                if (BufUsed(sock) > 0)
                    lpNetworkEvents->lNetworkEvents |= FD_READ;
                if (sock->is_connected && sock->peer_index >= 0
                    && sock->peer_index < MAX_SHARED_SOCKETS) {
                    VSOCK* peer = &g_pState->sockets[sock->peer_index];
                    if (peer->in_use && BufFree(peer) > 0)
                        lpNetworkEvents->lNetworkEvents |= FD_WRITE;
                }
            }
        }
    }
    Ulk();
    
    return 0;
}

int WSAAPI ex_WSAAsyncSelect(SOCKET s, HWND hWnd, unsigned int wMsg, long lEvent) {
    // Simplified - just return success
    return 0;
}

// =============================================================================
// IOCTL
// =============================================================================

int WSAAPI ex_WSAIoctl(SOCKET s, DWORD dwIoControlCode, void* lpvInBuffer,
                       DWORD cbInBuffer, void* lpvOutBuffer, DWORD cbOutBuffer,
                       LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped,
                       LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (!lpcbBytesReturned) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    *lpcbBytesReturned = 0;
    
    LOG("WSAIoctl: socket %d, code 0x%08lX", (int)s, (unsigned long)dwIoControlCode);
    
    // Validate socket for most operations (except some special cases)
    if (s == INVALID_SOCKET) {
        LOG("WSAIoctl: Invalid socket");
        SetLastError(WSAENOTSOCK);
        return SOCKET_ERROR;
    }
    
    // Check if socket exists in our table
    VSOCK* vs = FindSock(s);
    if (!vs) {
        LOG("WSAIoctl: Socket not found");
        SetLastError(WSAENOTSOCK);
        return SOCKET_ERROR;
    }
    
    switch (dwIoControlCode) {
        case FIONBIO: {
            if (!lpvInBuffer || cbInBuffer < sizeof(u_long)) {
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            u_long arg = *(u_long*)lpvInBuffer;
            return ex_ioctlsocket(s, FIONBIO, &arg);
        }
        
        case FIONREAD: {
            if (!lpvOutBuffer || cbOutBuffer < sizeof(u_long)) {
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            u_long val = 0;
            int ret = ex_ioctlsocket(s, FIONREAD, &val);
            if (ret == 0) {
                *(u_long*)lpvOutBuffer = val;
                *lpcbBytesReturned = sizeof(u_long);
            }
            return ret;
        }
        
        case SIOCATMARK: {
            if (!lpvOutBuffer || cbOutBuffer < sizeof(u_long)) {
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            *(u_long*)lpvOutBuffer = 0;
            *lpcbBytesReturned = sizeof(u_long);
            return 0;
        }
        
        case SIO_GET_EXTENSION_FUNCTION_POINTER: {
            if (!lpvInBuffer || cbInBuffer < sizeof(GUID) || 
                !lpvOutBuffer || cbOutBuffer < sizeof(void*)) {
                SetLastError(WSAEINVAL);
                return SOCKET_ERROR;
            }
            
            GUID* guid = (GUID*)lpvInBuffer;
            void** func = (void**)lpvOutBuffer;
            
            // WSAID_CONNECTEX
            static const GUID WSAID_CONNECTEX_GUID = 
                {0x25a207b9,0xddf3,0x4660,{0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}};
            // WSAID_DISCONNECTEX
            static const GUID WSAID_DISCONNECTEX_GUID = 
                {0x7fda2e11,0x8630,0x436f,{0xa0,0x31,0xf5,0x36,0xa6,0xee,0xc1,0x57}};
            // WSAID_ACCEPTEX
            static const GUID WSAID_ACCEPTEX_GUID = 
                {0xb5367df1,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}};
            // WSAID_GETACCEPTEXSOCKADDRS
            static const GUID WSAID_GETACCEPTEXSOCKADDRS_GUID = 
                {0xb5367df2,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}};
            // WSAID_TRANSMITFILE
            static const GUID WSAID_TRANSMITFILE_GUID = 
                {0xb5367df0,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}};
            // WSAID_WSARECVMSG
            static const GUID WSAID_WSARECVMSG_GUID = 
                {0xf689d7c8,0x6f1f,0x436b,{0x8a,0x53,0xe5,0x4f,0xe3,0x51,0xc3,0x22}};
            // WSAID_WSASENDMSG
            static const GUID WSAID_WSASENDMSG_GUID = 
                {0xa441e712,0x754f,0x43ca,{0x84,0xa7,0x0d,0xee,0x44,0xcf,0x60,0x6d}};
            
            // Forward declarations for extension functions
            extern BOOL WINAPI ex_ConnectEx(SOCKET, const struct sockaddr*, int, 
                                            PVOID, DWORD, LPDWORD, LPOVERLAPPED);
            extern BOOL WINAPI ex_DisconnectEx(SOCKET, LPOVERLAPPED, DWORD, DWORD);
            extern BOOL WINAPI ex_AcceptEx(SOCKET, SOCKET, PVOID, DWORD, DWORD, DWORD,
                                           LPDWORD, LPOVERLAPPED);
            extern void WINAPI ex_GetAcceptExSockaddrs(PVOID, DWORD, DWORD, DWORD,
                                                       struct sockaddr**, LPINT,
                                                       struct sockaddr**, LPINT);
            extern BOOL WINAPI ex_TransmitFile(SOCKET, HANDLE, DWORD, DWORD,
                                               LPOVERLAPPED, LPTRANSMIT_FILE_BUFFERS, DWORD);
            extern int WINAPI ex_WSARecvMsg(SOCKET, LPWSAMSG, LPDWORD,
                                            LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
            extern int WINAPI ex_WSASendMsg(SOCKET, LPWSAMSG, DWORD, LPDWORD,
                                            LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
            
            if (memcmp(guid, &WSAID_CONNECTEX_GUID, sizeof(GUID)) == 0) {
                *func = (void*)ex_ConnectEx;
            } else if (memcmp(guid, &WSAID_DISCONNECTEX_GUID, sizeof(GUID)) == 0) {
                *func = (void*)ex_DisconnectEx;
            } else if (memcmp(guid, &WSAID_ACCEPTEX_GUID, sizeof(GUID)) == 0) {
                *func = (void*)ex_AcceptEx;
            } else if (memcmp(guid, &WSAID_GETACCEPTEXSOCKADDRS_GUID, sizeof(GUID)) == 0) {
                *func = (void*)ex_GetAcceptExSockaddrs;
            } else if (memcmp(guid, &WSAID_TRANSMITFILE_GUID, sizeof(GUID)) == 0) {
                *func = (void*)ex_TransmitFile;
            } else if (memcmp(guid, &WSAID_WSARECVMSG_GUID, sizeof(GUID)) == 0) {
                *func = (void*)ex_WSARecvMsg;
            } else if (memcmp(guid, &WSAID_WSASENDMSG_GUID, sizeof(GUID)) == 0) {
                *func = (void*)ex_WSASendMsg;
            } else {
                LOG("WSAIoctl: Unknown extension GUID");
                SetLastError(WSAEINVAL);
                return SOCKET_ERROR;
            }
            
            *lpcbBytesReturned = sizeof(void*);
            return 0;
        }
        
        case SIO_KEEPALIVE_VALS: {
            // struct tcp_keepalive { ULONG onoff; ULONG keepalivetime; ULONG keepaliveinterval; }
            if (cbInBuffer < 12) {
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            // Accept silently
            return 0;
        }
        
        case SIO_GET_INTERFACE_LIST: {
            if (!lpvOutBuffer || cbOutBuffer < sizeof(INTERFACE_INFO)) {
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            
            // Return at least loopback interface
            INTERFACE_INFO* pInfo = (INTERFACE_INFO*)lpvOutBuffer;
            memset(pInfo, 0, sizeof(INTERFACE_INFO));
            
            pInfo->iiFlags = IFF_UP | IFF_LOOPBACK;
            ((struct sockaddr_in*)&pInfo->iiAddress)->sin_family = AF_INET;
            ((struct sockaddr_in*)&pInfo->iiAddress)->sin_addr.s_addr = 0x0100007F;
            ((struct sockaddr_in*)&pInfo->iiNetmask)->sin_family = AF_INET;
            ((struct sockaddr_in*)&pInfo->iiNetmask)->sin_addr.s_addr = 0x000000FF;
            ((struct sockaddr_in*)&pInfo->iiBroadcastAddress)->sin_family = AF_INET;
            ((struct sockaddr_in*)&pInfo->iiBroadcastAddress)->sin_addr.s_addr = 0xFFFFFFFF;
            
            *lpcbBytesReturned = sizeof(INTERFACE_INFO);
            return 0;
        }
        
        case SIO_ADDRESS_LIST_QUERY: {
            if (!lpvOutBuffer || cbOutBuffer < sizeof(SOCKET_ADDRESS_LIST)) {
                *lpcbBytesReturned = sizeof(SOCKET_ADDRESS_LIST) + sizeof(SOCKET_ADDRESS) + sizeof(struct sockaddr_in);
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            
            SOCKET_ADDRESS_LIST* list = (SOCKET_ADDRESS_LIST*)lpvOutBuffer;
            list->iAddressCount = 1;
            
            struct sockaddr_in* addr = (struct sockaddr_in*)((char*)lpvOutBuffer + sizeof(SOCKET_ADDRESS_LIST));
            addr->sin_family = AF_INET;
            addr->sin_addr.s_addr = 0x0100007F;
            addr->sin_port = 0;
            
            list->Address[0].lpSockaddr = (struct sockaddr*)addr;
            list->Address[0].iSockaddrLength = sizeof(struct sockaddr_in);
            
            *lpcbBytesReturned = sizeof(SOCKET_ADDRESS_LIST) + sizeof(struct sockaddr_in);
            return 0;
        }
        
        case SIO_ROUTING_INTERFACE_QUERY: {
            if (!lpvInBuffer || cbInBuffer < sizeof(struct sockaddr_in) ||
                !lpvOutBuffer || cbOutBuffer < sizeof(struct sockaddr_in)) {
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            
            struct sockaddr_in* out = (struct sockaddr_in*)lpvOutBuffer;
            out->sin_family = AF_INET;
            out->sin_addr.s_addr = 0x0100007F;
            out->sin_port = 0;
            
            *lpcbBytesReturned = sizeof(struct sockaddr_in);
            return 0;
        }
        
        case SIO_ADDRESS_LIST_CHANGE: {
            // Non-blocking notification - just return success
            if (lpOverlapped) {
                SetLastError(WSA_IO_PENDING);
                return SOCKET_ERROR;
            }
            return 0;
        }
        
        case SIO_UDP_CONNRESET: {
            // Silently accept
            return 0;
        }
        
        case SIO_ENABLE_CIRCULAR_QUEUEING: {
            // Silently accept
            return 0;
        }
        
        case SIO_GET_BROADCAST_ADDRESS: {
            if (!lpvOutBuffer || cbOutBuffer < sizeof(struct sockaddr_in)) {
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            struct sockaddr_in* addr = (struct sockaddr_in*)lpvOutBuffer;
            addr->sin_family = AF_INET;
            addr->sin_addr.s_addr = 0xFFFFFFFF;
            addr->sin_port = 0;
            *lpcbBytesReturned = sizeof(struct sockaddr_in);
            return 0;
        }
        
        case SIO_IDEAL_SEND_BACKLOG_QUERY: {
            if (!lpvOutBuffer || cbOutBuffer < sizeof(DWORD)) {
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            *(DWORD*)lpvOutBuffer = 0x10000; // 64KB
            *lpcbBytesReturned = sizeof(DWORD);
            return 0;
        }
        
        case SIO_BASE_HANDLE: {
            if (!lpvOutBuffer || cbOutBuffer < sizeof(SOCKET)) {
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            *(SOCKET*)lpvOutBuffer = s;
            *lpcbBytesReturned = sizeof(SOCKET);
            return 0;
        }
        
        default:
            LOG("WSAIoctl: Unsupported IOCTL 0x%08lX", (unsigned long)dwIoControlCode);
            SetLastError(WSAEOPNOTSUPP);
            return SOCKET_ERROR;
    }
}

// =============================================================================
// EXTENSION FUNCTIONS
// =============================================================================

BOOL WINAPI ex_ConnectEx(SOCKET s, const struct sockaddr* name, int namelen,
                         PVOID lpSendBuffer, DWORD dwSendDataLength,
                         LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped) {
    LOG("ConnectEx: socket %d", (int)s);
    
    if (!lpOverlapped) {
        SetLastError(WSA_INVALID_PARAMETER);
        return FALSE;
    }
    
    lpOverlapped->Internal = STATUS_PENDING;
    lpOverlapped->InternalHigh = 0;
    
    int ret = ex_connect(s, name, namelen);
    if (ret == SOCKET_ERROR) {
        return FALSE;
    }
    
    // Send initial data if provided
    if (lpSendBuffer && dwSendDataLength > 0) {
        int sent = ex_send(s, (const char*)lpSendBuffer, dwSendDataLength, 0);
        if (sent > 0 && lpdwBytesSent) {
            *lpdwBytesSent = sent;
            lpOverlapped->InternalHigh = sent;
        }
    }
    
    lpOverlapped->Internal = 0;
    return TRUE;
}

BOOL WINAPI ex_DisconnectEx(SOCKET s, LPOVERLAPPED lpOverlapped, 
                            DWORD dwFlags, DWORD dwReserved) {
    LOG("DisconnectEx: socket %d", (int)s);
    
    if (lpOverlapped) {
        lpOverlapped->Internal = STATUS_PENDING;
        lpOverlapped->InternalHigh = 0;
    }
    
    int ret = ex_shutdown(s, SD_SEND);
    
    if (lpOverlapped) {
        lpOverlapped->Internal = (ret == 0) ? 0 : GetLastError();
    }
    
    return (ret == 0);
}

BOOL WINAPI ex_AcceptEx(SOCKET sListenSocket, SOCKET sAcceptSocket,
                        PVOID lpOutputBuffer, DWORD dwReceiveDataLength,
                        DWORD dwLocalAddressLength, DWORD dwRemoteAddressLength,
                        LPDWORD lpdwBytesReceived, LPOVERLAPPED lpOverlapped) {
    LOG("AcceptEx: listen=%d, accept=%d", (int)sListenSocket, (int)sAcceptSocket);
    
    if (!lpOverlapped) {
        SetLastError(WSA_INVALID_PARAMETER);
        return FALSE;
    }
    
    if (!lpOutputBuffer || dwRemoteAddressLength == 0) {
        SetLastError(WSAEFAULT);
        return FALSE;
    }
    
    lpOverlapped->Internal = STATUS_PENDING;
    lpOverlapped->InternalHigh = 0;
    
    // Simplified: just wait for accept
    struct sockaddr_storage addr;
    int addrlen = sizeof(addr);
    
    // Use accept on listen socket and associate with accept socket
    // Note: Real AcceptEx uses pre-created accept socket differently
    SOCKET accepted = ex_accept(sListenSocket, (struct sockaddr*)&addr, &addrlen);
    
    if (accepted == INVALID_SOCKET) {
        if (GetLastError() == WSAEWOULDBLOCK) {
            SetLastError(WSA_IO_PENDING);
        }
        return FALSE;
    }
    
    // Store addresses in output buffer
    char* pLocal = (char*)lpOutputBuffer + dwReceiveDataLength;
    char* pRemote = pLocal + dwLocalAddressLength;
    
    // Set address lengths
    *(int*)pLocal = sizeof(struct sockaddr_in);
    *(int*)pRemote = addrlen;
    
    // Copy addresses
    memcpy(pLocal + sizeof(int), &addr, min((int)dwLocalAddressLength - sizeof(int), addrlen));
    memcpy(pRemote + sizeof(int), &addr, min((int)dwRemoteAddressLength - sizeof(int), addrlen));
    
    if (lpdwBytesReceived) *lpdwBytesReceived = 0;
    lpOverlapped->Internal = 0;
    
    // Close the temp socket since AcceptEx expects sAcceptSocket to be used
    ex_closesocket(accepted);
    
    return TRUE;
}

void WINAPI ex_GetAcceptExSockaddrs(PVOID lpOutputBuffer,
                                    DWORD dwReceiveDataLength,
                                    DWORD dwLocalAddressLength,
                                    DWORD dwRemoteAddressLength,
                                    struct sockaddr** LocalSockaddr,
                                    LPINT LocalSockaddrLength,
                                    struct sockaddr** RemoteSockaddr,
                                    LPINT RemoteSockaddrLength) {
    char* pLocal = (char*)lpOutputBuffer + dwReceiveDataLength;
    char* pRemote = pLocal + dwLocalAddressLength;
    
    if (LocalSockaddrLength) *LocalSockaddrLength = *(int*)pLocal;
    if (LocalSockaddr) *LocalSockaddr = (struct sockaddr*)(pLocal + sizeof(int));
    
    if (RemoteSockaddrLength) *RemoteSockaddrLength = *(int*)pRemote;
    if (RemoteSockaddr) *RemoteSockaddr = (struct sockaddr*)(pRemote + sizeof(int));
}

BOOL WINAPI ex_TransmitFile(SOCKET hSocket, HANDLE hFile, DWORD nNumberOfBytesToWrite,
                            DWORD nNumberOfBytesPerSend, LPOVERLAPPED lpOverlapped,
                            LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers, DWORD dwFlags) {
    LOG("TransmitFile: socket %d", (int)hSocket);
    
    if (lpOverlapped) {
        lpOverlapped->Internal = STATUS_PENDING;
        lpOverlapped->InternalHigh = 0;
    }
    
    DWORD totalSent = 0;
    
    // Send head buffer
    if (lpTransmitBuffers && lpTransmitBuffers->Head && lpTransmitBuffers->HeadLength > 0) {
        int sent = ex_send(hSocket, (const char*)lpTransmitBuffers->Head, 
                          lpTransmitBuffers->HeadLength, 0);
        if (sent > 0) totalSent += sent;
    }
    
    // Send file content
    if (hFile && hFile != INVALID_HANDLE_VALUE) {
        char buffer[8192];
        DWORD bytesToRead = nNumberOfBytesToWrite ? nNumberOfBytesToWrite : 0xFFFFFFFF;
        DWORD bytesRead;
        
        while (bytesToRead > 0) {
            DWORD toRead = min(bytesToRead, sizeof(buffer));
            if (!ReadFile(hFile, buffer, toRead, &bytesRead, NULL) || bytesRead == 0)
                break;
            
            int sent = ex_send(hSocket, buffer, bytesRead, 0);
            if (sent <= 0) break;
            
            totalSent += sent;
            if (nNumberOfBytesToWrite) bytesToRead -= bytesRead;
        }
    }
    
    // Send tail buffer
    if (lpTransmitBuffers && lpTransmitBuffers->Tail && lpTransmitBuffers->TailLength > 0) {
        int sent = ex_send(hSocket, (const char*)lpTransmitBuffers->Tail,
                          lpTransmitBuffers->TailLength, 0);
        if (sent > 0) totalSent += sent;
    }
    
    if (lpOverlapped) {
        lpOverlapped->Internal = 0;
        lpOverlapped->InternalHigh = totalSent;
    }
    
    // Handle disconnect/reuse flags
    if (dwFlags & TF_DISCONNECT) {
        ex_shutdown(hSocket, SD_SEND);
    }
    
    return TRUE;
}

int WINAPI ex_WSARecvMsg(SOCKET s, LPWSAMSG lpMsg, LPDWORD lpNumberOfBytesRecvd,
                         LPWSAOVERLAPPED lpOverlapped,
                         LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (!lpMsg) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    DWORD flags = lpMsg->dwFlags;
    return ex_WSARecvFrom(s, lpMsg->lpBuffers, lpMsg->dwBufferCount,
                          lpNumberOfBytesRecvd, &flags,
                          lpMsg->name, &lpMsg->namelen,
                          lpOverlapped, lpCompletionRoutine);
}

int WINAPI ex_WSASendMsg(SOCKET s, LPWSAMSG lpMsg, DWORD dwFlags,
                         LPDWORD lpNumberOfBytesSent,
                         LPWSAOVERLAPPED lpOverlapped,
                         LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (!lpMsg) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    return ex_WSASendTo(s, lpMsg->lpBuffers, lpMsg->dwBufferCount,
                        lpNumberOfBytesSent, dwFlags,
                        lpMsg->name, lpMsg->namelen,
                        lpOverlapped, lpCompletionRoutine);
}

// =============================================================================
// STRING CONVERSION FUNCTIONS
// =============================================================================

int WSAAPI ex_WSAStringToAddressA(char* AddressString, int AddressFamily,
                                   LPWSAPROTOCOL_INFOA lpProtocolInfo,
                                   struct sockaddr* lpAddress, LPINT lpAddressLength) {
    if (!AddressString || !lpAddress || !lpAddressLength) {
        SetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    
    if (AddressFamily == AF_INET) {
        if (*lpAddressLength < (int)sizeof(struct sockaddr_in)) {
            *lpAddressLength = sizeof(struct sockaddr_in);
            SetLastError(WSAEFAULT);
            return SOCKET_ERROR;
        }
        
        struct sockaddr_in* addr = (struct sockaddr_in*)lpAddress;
        memset(addr, 0, sizeof(*addr));
        addr->sin_family = AF_INET;
        
        // Parse address and optional port
        char addrCopy[256];
        strncpy(addrCopy, AddressString, sizeof(addrCopy) - 1);
        
        char* portStr = strchr(addrCopy, ':');
        if (portStr) {
            *portStr++ = '\0';
            int port = atoi(portStr);
            if (port > 0 && port <= 65535) {
                addr->sin_port = ex_htons((u_short)port);
            }
        }
        
        u_long ip = ex_inet_addr(addrCopy);
        if (ip == INADDR_NONE && strcmp(addrCopy, "255.255.255.255") != 0) {
            SetLastError(WSAEINVAL);
            return SOCKET_ERROR;
        }
        addr->sin_addr.s_addr = ip;
        *lpAddressLength = sizeof(struct sockaddr_in);
        return 0;
    }
    
    if (AddressFamily == AF_INET6) {
        if (*lpAddressLength < (int)sizeof(struct sockaddr_in6)) {
            *lpAddressLength = sizeof(struct sockaddr_in6);
            SetLastError(WSAEFAULT);
            return SOCKET_ERROR;
        }
        
        struct sockaddr_in6* addr = (struct sockaddr_in6*)lpAddress;
        memset(addr, 0, sizeof(*addr));
        addr->sin6_family = AF_INET6;
        
        // Handle [addr]:port format
        char addrCopy[256];
        strncpy(addrCopy, AddressString, sizeof(addrCopy) - 1);
        
        char* addrStart = addrCopy;
        char* portStr = NULL;
        
        if (addrCopy[0] == '[') {
            addrStart++;
            char* bracket = strchr(addrStart, ']');
            if (bracket) {
                *bracket = '\0';
                if (bracket[1] == ':') {
                    portStr = bracket + 2;
                }
            }
        }
        
        if (portStr) {
            int port = atoi(portStr);
            if (port > 0 && port <= 65535) {
                addr->sin6_port = ex_htons((u_short)port);
            }
        }
        
        if (ex_inet_pton(AF_INET6, addrStart, &addr->sin6_addr) != 1) {
            SetLastError(WSAEINVAL);
            return SOCKET_ERROR;
        }
        
        *lpAddressLength = sizeof(struct sockaddr_in6);
        return 0;
    }
    
    SetLastError(WSAEINVAL);
    return SOCKET_ERROR;
}

int WSAAPI ex_WSAStringToAddressW(WCHAR* AddressString, int AddressFamily,
                                   LPWSAPROTOCOL_INFOW lpProtocolInfo,
                                   struct sockaddr* lpAddress, LPINT lpAddressLength) {
    if (!AddressString) {
        SetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    
    char addrA[256];
    WideCharToMultiByte(CP_ACP, 0, AddressString, -1, addrA, sizeof(addrA), NULL, NULL);
    
    return ex_WSAStringToAddressA(addrA, AddressFamily, NULL, lpAddress, lpAddressLength);
}

int WSAAPI ex_WSAAddressToStringA(struct sockaddr* lpsaAddress, DWORD dwAddressLength,
                                   LPWSAPROTOCOL_INFOA lpProtocolInfo,
                                   char* lpszAddressString, LPDWORD lpdwAddressStringLength) {
    if (!lpsaAddress || !lpszAddressString || !lpdwAddressStringLength) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    char buffer[64];
    
    if (lpsaAddress->sa_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*)lpsaAddress;
        const char* ip = ex_inet_ntoa(addr->sin_addr);
        int port = ex_ntohs(addr->sin_port);
        
        if (port) {
            sprintf(buffer, "%s:%d", ip, port);
        } else {
            strcpy(buffer, ip);
        }
    } else if (lpsaAddress->sa_family == AF_INET6) {
        struct sockaddr_in6* addr = (struct sockaddr_in6*)lpsaAddress;
        char ipbuf[64];
        ex_inet_ntop(AF_INET6, &addr->sin6_addr, ipbuf, sizeof(ipbuf));
        int port = ex_ntohs(addr->sin6_port);
        
        if (port) {
            sprintf(buffer, "[%s]:%d", ipbuf, port);
        } else {
            strcpy(buffer, ipbuf);
        }
    } else {
        SetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    
    DWORD needed = (DWORD)strlen(buffer) + 1;
    if (*lpdwAddressStringLength < needed) {
        *lpdwAddressStringLength = needed;
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    strcpy(lpszAddressString, buffer);
    *lpdwAddressStringLength = needed;
    return 0;
}

int WSAAPI ex_WSAAddressToStringW(struct sockaddr* lpsaAddress, DWORD dwAddressLength,
                                   LPWSAPROTOCOL_INFOW lpProtocolInfo,
                                   WCHAR* lpszAddressString, LPDWORD lpdwAddressStringLength) {
    char bufA[64];
    DWORD lenA = sizeof(bufA);
    
    int ret = ex_WSAAddressToStringA(lpsaAddress, dwAddressLength, NULL, bufA, &lenA);
    if (ret != 0) {
        return ret;
    }
    
    int needed = MultiByteToWideChar(CP_ACP, 0, bufA, -1, NULL, 0);
    if (*lpdwAddressStringLength < (DWORD)needed) {
        *lpdwAddressStringLength = needed;
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    MultiByteToWideChar(CP_ACP, 0, bufA, -1, lpszAddressString, *lpdwAddressStringLength);
    *lpdwAddressStringLength = needed;
    return 0;
}

// =============================================================================
// DUPLICATE SOCKET
// =============================================================================

int WSAAPI ex_WSADuplicateSocketA(SOCKET s, DWORD dwProcessId, 
                                   LPWSAPROTOCOL_INFOA lpProtocolInfo) {
    if (!lpProtocolInfo) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    int size;
    if (!GetSocketProtocolInfo(s, FALSE, lpProtocolInfo, &size)) {
        return SOCKET_ERROR;
    }
    
    // Magic value to indicate duplicated socket
    lpProtocolInfo->dwServiceFlags3 = (DWORD)s;
    lpProtocolInfo->dwServiceFlags4 = 0xff00ff00;
    
    return 0;
}

int WSAAPI ex_WSADuplicateSocketW(SOCKET s, DWORD dwProcessId,
                                   LPWSAPROTOCOL_INFOW lpProtocolInfo) {
    if (!lpProtocolInfo) {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    
    int size;
    if (!GetSocketProtocolInfo(s, TRUE, lpProtocolInfo, &size)) {
        return SOCKET_ERROR;
    }
    
    lpProtocolInfo->dwServiceFlags3 = (DWORD)s;
    lpProtocolInfo->dwServiceFlags4 = 0xff00ff00;
    
    return 0;
}

// =============================================================================
// SERVICE CLASS FUNCTIONS (STUBS)
// =============================================================================

int WSAAPI ex_WSAInstallServiceClassA(LPWSASERVICECLASSINFOA lpServiceClassInfo) {
    SetLastError(WSAEACCES);
    return SOCKET_ERROR;
}

int WSAAPI ex_WSAInstallServiceClassW(LPWSASERVICECLASSINFOW lpServiceClassInfo) {
    SetLastError(WSAEACCES);
    return SOCKET_ERROR;
}

int WSAAPI ex_WSARemoveServiceClass(LPGUID lpServiceClassId) {
    SetLastError(WSATYPE_NOT_FOUND);
    return SOCKET_ERROR;
}

int WSAAPI ex_WSAGetServiceClassInfoA(LPGUID lpProviderId, LPGUID lpServiceClassId,
                                       LPDWORD lpdwBufferLength,
                                       LPWSASERVICECLASSINFOA lpServiceClassInfo) {
    SetLastError(WSA_NOT_ENOUGH_MEMORY);
    return SOCKET_ERROR;
}

int WSAAPI ex_WSAGetServiceClassInfoW(LPGUID lpProviderId, LPGUID lpServiceClassId,
                                       LPDWORD lpdwBufferLength,
                                       LPWSASERVICECLASSINFOW lpServiceClassInfo) {
    SetLastError(WSA_NOT_ENOUGH_MEMORY);
    return SOCKET_ERROR;
}

int WSAAPI ex_WSAGetServiceClassNameByClassIdA(LPGUID lpServiceClassId,
                                                LPSTR lpszServiceClassName,
                                                LPDWORD lpdwBufferLength) {
    SetLastError(WSA_NOT_ENOUGH_MEMORY);
    return SOCKET_ERROR;
}

int WSAAPI ex_WSAGetServiceClassNameByClassIdW(LPGUID lpServiceClassId,
                                                LPWSTR lpszServiceClassName,
                                                LPDWORD lpdwBufferLength) {
    SetLastError(WSA_NOT_ENOUGH_MEMORY);
    return SOCKET_ERROR;
}

// =============================================================================
// LOOKUP SERVICE FUNCTIONS (STUBS)
// =============================================================================

int WSAAPI ex_WSALookupServiceBeginA(LPWSAQUERYSETA lpqsRestrictions,
                                      DWORD dwControlFlags, LPHANDLE lphLookup) {
    SetLastError(WSASERVICE_NOT_FOUND);
    return SOCKET_ERROR;
}

int WSAAPI ex_WSALookupServiceBeginW(LPWSAQUERYSETW lpqsRestrictions,
                                      DWORD dwControlFlags, LPHANDLE lphLookup) {
    SetLastError(WSASERVICE_NOT_FOUND);
    return SOCKET_ERROR;
}

int WSAAPI ex_WSALookupServiceNextA(HANDLE hLookup, DWORD dwControlFlags,
                                     LPDWORD lpdwBufferLength,
                                     LPWSAQUERYSETA lpqsResults) {
    SetLastError(WSA_E_NO_MORE);
    return SOCKET_ERROR;
}

int WSAAPI ex_WSALookupServiceNextW(HANDLE hLookup, DWORD dwControlFlags,
                                     LPDWORD lpdwBufferLength,
                                     LPWSAQUERYSETW lpqsResults) {
    SetLastError(WSA_E_NO_MORE);
    return SOCKET_ERROR;
}

int WSAAPI ex_WSALookupServiceEnd(HANDLE hLookup) {
    return 0;
}

int WSAAPI ex_WSASetServiceA(LPWSAQUERYSETA lpqsRegInfo,
                              WSAESETSERVICEOP essOperation, DWORD dwControlFlags) {
    return 0;
}

int WSAAPI ex_WSASetServiceW(LPWSAQUERYSETW lpqsRegInfo,
                              WSAESETSERVICEOP essOperation, DWORD dwControlFlags) {
    return 0;
}

// =============================================================================
// NAMESPACE PROVIDER FUNCTIONS (STUBS)
// =============================================================================

int WSAAPI ex_WSAEnumNameSpaceProvidersA(LPDWORD lpdwBufferLength,
                                          LPWSANAMESPACE_INFOA lpnspBuffer) {
    if (lpdwBufferLength) *lpdwBufferLength = 0;
    return 0;
}

int WSAAPI ex_WSAEnumNameSpaceProvidersW(LPDWORD lpdwBufferLength,
                                          LPWSANAMESPACE_INFOW lpnspBuffer) {
    if (lpdwBufferLength) *lpdwBufferLength = 0;
    return 0;
}

int WSAAPI ex_WSANSPIoctl(HANDLE hLookup, DWORD dwControlCode, LPVOID lpvInBuffer,
                          DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer,
                          LPDWORD lpcbBytesReturned, LPWSACOMPLETION lpCompletion) {
    SetLastError(WSA_NOT_ENOUGH_MEMORY);
    return SOCKET_ERROR;
}

int WSAAPI ex_WSAProviderConfigChange(LPHANDLE lpNotificationHandle,
                                       LPWSAOVERLAPPED lpOverlapped,
                                       LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    SetLastError(WSAEOPNOTSUPP);
    return SOCKET_ERROR;
}

// =============================================================================
// WSC FUNCTIONS (STUBS)
// =============================================================================

int WSAAPI ex_WSCDeinstallProvider(LPGUID lpProviderId, LPINT lpErrno) {
    if (lpErrno) *lpErrno = 0;
    return 0;
}

int WSAAPI ex_WSCEnableNSProvider(LPGUID lpProviderId, BOOL fEnable) {
    return 0;
}

int WSAAPI ex_WSCGetApplicationCategory(LPCWSTR Path, DWORD PathLength,
                                         LPCWSTR Extra, DWORD ExtraLength,
                                         DWORD* pPermittedLspCategories,
                                         LPINT lpErrno) {
    if (lpErrno) *lpErrno = WSANO_RECOVERY;
    return SOCKET_ERROR;
}

int WSAAPI ex_WSCGetProviderInfo(LPGUID lpProviderId, WSC_PROVIDER_INFO_TYPE InfoType,
                                  PBYTE Info, size_t* InfoSize, DWORD Flags, LPINT lpErrno) {
    if (lpErrno) *lpErrno = WSANO_RECOVERY;
    return SOCKET_ERROR;
}

int WSAAPI ex_WSCGetProviderPath(LPGUID lpProviderId, WCHAR* lpszProviderDllPath,
                                  LPINT lpProviderDllPathLen, LPINT lpErrno) {
    if (lpErrno) *lpErrno = 0;
    return 0;
}

int WSAAPI ex_WSCInstallNameSpace(LPWSTR lpszIdentifier, LPWSTR lpszPathName,
                                   DWORD dwNameSpace, DWORD dwVersion, LPGUID lpProviderId) {
    return 0;
}

int WSAAPI ex_WSCInstallProvider(LPGUID lpProviderId, const WCHAR* lpszProviderDllPath,
                                  const LPWSAPROTOCOL_INFOW lpProtocolInfoList,
                                  DWORD dwNumberOfEntries, LPINT lpErrno) {
    if (lpErrno) *lpErrno = 0;
    return 0;
}

int WSAAPI ex_WSCSetApplicationCategory(LPCWSTR Path, DWORD PathLength,
                                         LPCWSTR Extra, DWORD ExtraLength,
                                         DWORD PermittedLspCategories,
                                         DWORD* pPrevPermLspCat, LPINT lpErrno) {
    if (lpErrno) *lpErrno = 0;
    return 0;
}

int WSAAPI ex_WSCUnInstallNameSpace(LPGUID lpProviderId) {
    return 0;
}

int WSAAPI ex_WSCWriteProviderOrder(LPDWORD lpwdCatalogEntryId, DWORD dwNumberOfEntries) {
    return 0;
}

// =============================================================================
// ASYNC FUNCTIONS (STUBS)
// =============================================================================

HANDLE WSAAPI ex_WSAAsyncGetHostByAddr(HWND hWnd, unsigned int wMsg, const char* addr,
                                        int len, int type, char* buf, int buflen) {
    return NULL;
}

HANDLE WSAAPI ex_WSAAsyncGetHostByName(HWND hWnd, unsigned int wMsg, const char* name,
                                        char* buf, int buflen) {
    return NULL;
}

HANDLE WSAAPI ex_WSAAsyncGetProtoByName(HWND hWnd, unsigned int wMsg, const char* name,
                                         char* buf, int buflen) {
    return NULL;
}

HANDLE WSAAPI ex_WSAAsyncGetProtoByNumber(HWND hWnd, unsigned int wMsg, int number,
                                           char* buf, int buflen) {
    return NULL;
}

HANDLE WSAAPI ex_WSAAsyncGetServByName(HWND hWnd, unsigned int wMsg, const char* name,
                                        const char* proto, char* buf, int buflen) {
    return NULL;
}

HANDLE WSAAPI ex_WSAAsyncGetServByPort(HWND hWnd, unsigned int wMsg, int port,
                                        const char* proto, char* buf, int buflen) {
    return NULL;
}

int WSAAPI ex_WSACancelAsyncRequest(HANDLE hAsyncTaskHandle) {
    return 0;
}

// =============================================================================
// MISC FUNCTIONS
// =============================================================================

int WSAAPI ex_WSARecvDisconnect(SOCKET s, LPWSABUF lpInboundDisconnectData) {
    return ex_shutdown(s, SD_RECEIVE);
}

int WSAAPI ex_WSASendDisconnect(SOCKET s, LPWSABUF lpOutboundDisconnectData) {
    return ex_shutdown(s, SD_SEND);
}

SOCKET WSAAPI ex_WSAJoinLeaf(SOCKET s, const struct sockaddr* name, int namelen,
                             LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                             LPQOS lpSQOS, LPQOS lpGQOS, DWORD dwFlags) {
    SetLastError(WSAEOPNOTSUPP);
    return INVALID_SOCKET;
}

BOOL WSAAPI ex_WSAGetQOSByName(SOCKET s, LPWSABUF lpQOSName, LPQOS lpQOS) {
    return FALSE;
}

int WSAAPI ex_WSApSetPostRoutine(void* lpPostRoutine) {
    return 0;
}

int WSAAPI ex_WPUCompleteOverlappedRequest(SOCKET s, LPWSAOVERLAPPED lpOverlapped,
                                            DWORD dwError, DWORD cbTransferred,
                                            LPINT lpErrno) {
    return 0;
}

int WSAAPI ex_WEP() {
    return 0;
}

BOOL WSAAPI ex_WSAConnectByNameA(SOCKET s, LPCSTR nodename, LPCSTR servicename,
                                  LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress,
                                  LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress,
                                  const struct timeval* timeout, LPWSAOVERLAPPED Reserved) {
    if (!nodename || !servicename) {
        SetLastError(WSAEINVAL);
        return FALSE;
    }
    
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    int ret = ex_getaddrinfo(nodename, servicename, &hints, &res);
    if (ret != 0 || !res) {
        return FALSE;
    }
    
    ret = ex_connect(s, res->ai_addr, (int)res->ai_addrlen);
    
    if (ret == 0) {
        if (LocalAddress && LocalAddressLength) {
            ex_getsockname(s, LocalAddress, (int*)LocalAddressLength);
        }
        if (RemoteAddress && RemoteAddressLength) {
            memcpy(RemoteAddress, res->ai_addr, min(*RemoteAddressLength, (DWORD)res->ai_addrlen));
            *RemoteAddressLength = (DWORD)res->ai_addrlen;
        }
    }
    
    ex_freeaddrinfo(res);
    return (ret == 0);
}

BOOL WSAAPI ex_WSAConnectByNameW(SOCKET s, LPCWSTR nodename, LPCWSTR servicename,
                                  LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress,
                                  LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress,
                                  const struct timeval* timeout, LPWSAOVERLAPPED Reserved) {
    if (!nodename || !servicename) {
        SetLastError(WSAEINVAL);
        return FALSE;
    }
    
    char nodeA[256], servA[64];
    WideCharToMultiByte(CP_ACP, 0, nodename, -1, nodeA, sizeof(nodeA), NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, servicename, -1, servA, sizeof(servA), NULL, NULL);
    
    return ex_WSAConnectByNameA(s, nodeA, servA, LocalAddressLength, LocalAddress,
                                RemoteAddressLength, RemoteAddress, timeout, Reserved);
}

int WSAAPI ex_GetAddrInfoExW(PCWSTR pName, PCWSTR pServiceName, DWORD dwNameSpace,
                              LPGUID lpNspId, const ADDRINFOEXW* hints,
                              PADDRINFOEXW* ppResult, struct timeval* timeout,
                              LPOVERLAPPED lpOverlapped,
                              LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
                              LPHANDLE lpHandle) {
    if (!ppResult) {
        SetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }

    // Convert ADDRINFOEXW hints → addrinfo
    struct addrinfo hintsA = {0};
    if (hints) {
        hintsA.ai_flags    = hints->ai_flags;
        hintsA.ai_family   = hints->ai_family;
        hintsA.ai_socktype = hints->ai_socktype;
        hintsA.ai_protocol = hints->ai_protocol;
    }

    char nameA[256] = {0}, serviceA[64] = {0};
    if (pName)        WideCharToMultiByte(CP_ACP, 0, pName, -1, nameA, sizeof(nameA), NULL, NULL);
    if (pServiceName) WideCharToMultiByte(CP_ACP, 0, pServiceName, -1, serviceA, sizeof(serviceA), NULL, NULL);

    struct addrinfo* resA = NULL;
    int ret = ex_getaddrinfo(pName ? nameA : NULL, pServiceName ? serviceA : NULL,
                             hints ? &hintsA : NULL, &resA);
    if (ret != 0 || !resA) {
        *ppResult = NULL;
        if (lpOverlapped) {
            lpOverlapped->Internal = ret ? ret : WSAHOST_NOT_FOUND;
            if (lpOverlapped->hEvent) SetEvent(lpOverlapped->hEvent);
        }
        return ret;
    }

    // Convert addrinfo chain → ADDRINFOEXW chain (proper allocation)
    PADDRINFOEXW headW = NULL, tailW = NULL;
    for (struct addrinfo* cur = resA; cur; cur = cur->ai_next) {
        ADDRINFOEXW* exW = (ADDRINFOEXW*)calloc(1, sizeof(ADDRINFOEXW));
        if (!exW) {
            ex_FreeAddrInfoExW(headW);
            ex_freeaddrinfo(resA);
            *ppResult = NULL;
            return EAI_MEMORY;
        }

        exW->ai_flags    = cur->ai_flags;
        exW->ai_family   = cur->ai_family;
        exW->ai_socktype = cur->ai_socktype;
        exW->ai_protocol = cur->ai_protocol;
        exW->ai_addrlen  = cur->ai_addrlen;
        exW->ai_blob     = NULL;
        exW->ai_bloblen  = 0;
        exW->ai_provider = NULL;
        exW->ai_next     = NULL;

        if (cur->ai_addr && cur->ai_addrlen > 0) {
            exW->ai_addr = (struct sockaddr*)malloc(cur->ai_addrlen);
            if (exW->ai_addr) memcpy(exW->ai_addr, cur->ai_addr, cur->ai_addrlen);
        }

        if (cur->ai_canonname) {
            int wlen = MultiByteToWideChar(CP_ACP, 0, cur->ai_canonname, -1, NULL, 0);
            WCHAR* canon = (WCHAR*)malloc(wlen * sizeof(WCHAR));
            if (canon) {
                MultiByteToWideChar(CP_ACP, 0, cur->ai_canonname, -1, canon, wlen);
                exW->ai_canonname = canon;
            }
        }

        if (!headW) headW = exW; else tailW->ai_next = exW;
        tailW = exW;
    }

    ex_freeaddrinfo(resA);
    *ppResult = headW;

    // Signal overlapped completion (synchronous)
    if (lpOverlapped) {
        lpOverlapped->Internal = 0;
        lpOverlapped->InternalHigh = 0;
        if (lpOverlapped->hEvent) SetEvent(lpOverlapped->hEvent);
    }

    return 0;
}

int WSAAPI ex_GetAddrInfoExOverlappedResult(LPOVERLAPPED lpOverlapped) {
    if (!lpOverlapped) return WSAEINVAL;
    return (int)lpOverlapped->Internal;
}

int WSAAPI ex_GetAddrInfoExCancel(LPHANDLE lpHandle) {
    SetLastError(WSA_INVALID_HANDLE);
    return SOCKET_ERROR;
}

} // extern "C"

// =============================================================================
// DLL ENTRY POINT
// =============================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        InitConsole();
        LOG("WS2_EMU v2.1 loaded (PID: %lu)", GetCurrentProcessId());
        break;
        
    case DLL_PROCESS_DETACH:
        LOG("WS2_EMU unloading...");
        if (g_nStartup > 0) {
            // Force cleanup
            while (g_nStartup > 0) {
                ex_WSACleanup();
            }
        }
        break;
        
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}