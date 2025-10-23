// =========================================================================================
// EXLOUD Winsock2 Emulator v1.0.2
//
// - Core Architecture: Inter-process communication via Shared Memory
// - Protocol Support: Full IPv4 and IPv6
// - Async Support:    Functional `select()` and more robust `getsockopt`/`setsockopt`
// - Advanced Debugging: Data dumping, memory leak tracking, and behavior analysis
// =========================================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#pragma comment(lib, "kernel32.lib")

// --- Configuration ---
#define ENABLE_FILE_LOG           1
#define ENABLE_DATA_DUMP          1
#define ENABLE_BEHAVIOR_ANALYSIS  1
#define ENABLE_MEMORY_TRACKING    1
#define MAX_SHARED_SOCKETS      256
#define BUFFER_PER_SOCKET       (64 * 1024)
#define MAX_PENDING_CONN        16
#define EPHEMERAL_PORT_START    49152
#define EPHEMERAL_PORT_END      65535
static const char* SHARED_MEM_NAME = "Local\\EXLOUD_VirtualNetworkState_v1_0_2";
static const char* MUTEX_NAME      = "Local\\EXLOUD_VirtualNetworkMutex_v1_0_2";

// --- Helper Macros ---
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

#ifdef _WIN64
    #define PTR_FORMAT "0x%llX"
    #define UIPTR_FMT  "%llu"
    typedef unsigned long long UIPTR_FMT_T;
#else
    #define PTR_FORMAT "0x%lX"
    #define UIPTR_FMT  "%u"
    typedef unsigned int UIPTR_FMT_T;
#endif

#if defined(_MSC_VER)
    #define THREAD_LOCAL __declspec(thread)
#else
    #define THREAD_LOCAL __thread
#endif

// --- Constants ---
const struct in6_addr in6addr_any = { { 0 } };
const struct in6_addr in6addr_loopback = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };

// --- Type Definitions ---
typedef struct { DWORD short_messages, long_messages, single_byte_count, total_bytes_sent, total_bytes_recv; } SOCKET_BEHAVIOR;
typedef struct {
    BOOL in_use, is_listening, is_connected, is_bound, is_nonblocking; SOCKET fake_socket_id; DWORD owner_pid; int shutdown_flags, bind_addr_len, peer_socket_index, accept_queue[MAX_PENDING_CONN], accept_queue_len;
    struct sockaddr_storage bind_addr; size_t recv_head, recv_tail; struct linger linger_opts; BOOL tcp_nodelay;
#if ENABLE_BEHAVIOR_ANALYSIS
    SOCKET_BEHAVIOR behavior;
#endif
} SHARED_SOCKET;
typedef struct { DWORD initializing_pid; SHARED_SOCKET sockets[MAX_SHARED_SOCKETS]; char data_buffers[MAX_SHARED_SOCKETS * BUFFER_PER_SOCKET]; } GLOBAL_NETWORK_STATE;
#if ENABLE_MEMORY_TRACKING
typedef struct _MEMORY_BLOCK { void* ptr; size_t size; char function[64]; DWORD thread_id; struct _MEMORY_BLOCK* next; } MEMORY_BLOCK;
#endif

// --- Forward Declarations ---
static void InitializeEmulator(void);
static void CleanupEmulator(void);
void WSAAPI ex_freeaddrinfo(PADDRINFOA p);
void WSAAPI ex_FreeAddrInfoW(PADDRINFOW p);
SOCKET WSAAPI ex_accept(SOCKET s, struct sockaddr* a, int* al);
static int PortInUse(unsigned short port, int family);
static void AutoBindIfNeeded(SHARED_SOCKET* s, int family);
static unsigned short GetNextEphemeralPort();

// --- Globals ---
static HANDLE g_hSharedMemory = NULL;
static GLOBAL_NETWORK_STATE* g_pGlobalState = NULL;
static HANDLE g_hGlobalMutex = NULL;
THREAD_LOCAL static int g_tlsWSAError = 0;
static HANDLE g_hLogFile = NULL;
#if ENABLE_DATA_DUMP
static HANDLE g_hDataDumpFile = NULL;
#endif
#if ENABLE_MEMORY_TRACKING
static MEMORY_BLOCK* g_memory_list = NULL;
static CRITICAL_SECTION g_memory_lock;
static size_t g_total_allocated = 0;
#endif
static volatile LONG g_init_count = 0;
static volatile LONG g_ephemeral_port = EPHEMERAL_PORT_START - 1;

// --- Memory Tracking ---
#if ENABLE_MEMORY_TRACKING
void ReportMemoryLeaks();
void* TrackedAlloc(size_t size, const char* function) { if (size == 0) return NULL; void* ptr = calloc(1, size); if (!ptr) return NULL; EnterCriticalSection(&g_memory_lock); MEMORY_BLOCK* block = (MEMORY_BLOCK*)malloc(sizeof(MEMORY_BLOCK)); if (block) { block->ptr = ptr; block->size = size; strncpy_s(block->function, 64, function, _TRUNCATE); block->thread_id = GetCurrentThreadId(); block->next = g_memory_list; g_memory_list = block; g_total_allocated += size; } LeaveCriticalSection(&g_memory_lock); return ptr; }
void TrackedFree(void* ptr) { if (!ptr) return; EnterCriticalSection(&g_memory_lock); MEMORY_BLOCK** current = &g_memory_list; while (*current) { if ((*current)->ptr == ptr) { MEMORY_BLOCK* block = *current; g_total_allocated -= block->size; *current = block->next; free(block); break; } current = &(*current)->next; } LeaveCriticalSection(&g_memory_lock); free(ptr); }
#define SAFE_ALLOC(size, func) TrackedAlloc(size, func)
#define SAFE_FREE(ptr) TrackedFree(ptr)
#else
#define SAFE_ALLOC(size, func) calloc(1, size)
#define SAFE_FREE(ptr) free(ptr)
#endif

// --- Logging & Core Helpers ---
static inline UIPTR_FMT_T to_uiptr(UINT_PTR v) { return (UIPTR_FMT_T)v; }
static void Lock()   { if (g_hGlobalMutex) WaitForSingleObject(g_hGlobalMutex, INFINITE); }
static void Unlock() { if (g_hGlobalMutex) ReleaseMutex(g_hGlobalMutex); }
static void InternalLog(HANDLE hFile, const char* s, BOOL with_newline) { if (hFile && hFile != INVALID_HANDLE_VALUE) { DWORD w = 0; WriteFile(hFile, s, (DWORD)strlen(s), &w, NULL); if(with_newline) WriteFile(hFile, "\r\n", 2, &w, NULL); } }
static void LogMessage(const char* format, ...) { if (!g_hLogFile && g_init_count == 0) return; char buffer[2048]; va_list args; va_start(args, format); _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args); va_end(args); char out[2300]; _snprintf_s(out, sizeof(out), _TRUNCATE, "[PID:%05lu TID:%05lu] %s", GetCurrentProcessId(), GetCurrentThreadId(), buffer); OutputDebugStringA(out); InternalLog(g_hLogFile, out, TRUE); }
#if ENABLE_DATA_DUMP
static void DumpDataToFile(const char* prefix, SOCKET s, const char* data, int len) { if (!g_hDataDumpFile || g_hDataDumpFile == INVALID_HANDLE_VALUE || len <= 0) return; char header[256]; _snprintf_s(header, sizeof(header), _TRUNCATE, "[%s on " PTR_FORMAT ", %d bytes]", prefix, (UINT_PTR)s, len); InternalLog(g_hDataDumpFile, header, TRUE); }
#endif
#if ENABLE_MEMORY_TRACKING
void ReportMemoryLeaks() { EnterCriticalSection(&g_memory_lock); LogMessage("--- Memory Leak Report ---"); if (g_memory_list) { char buf[256]; sprintf_s(buf, sizeof(buf), "[MEM] Leaks Detected: %zu bytes remaining", g_total_allocated); LogMessage(buf); for (MEMORY_BLOCK* c=g_memory_list; c; c=c->next) { sprintf_s(buf, sizeof(buf), "[MEM]   Leak: %zu bytes from %s at %p", c->size, c->function, c->ptr); LogMessage(buf); } } else { LogMessage("[MEM] No memory leaks detected."); } LeaveCriticalSection(&g_memory_lock); }
#endif
static SOCKET GenerateFakeSocket() { static volatile LONG last_id = 1000; return (SOCKET)(UINT_PTR)InterlockedIncrement(&last_id); }
static int FindFreeSocketSlot() { for (int i = 0; i < MAX_SHARED_SOCKETS; i++) if (!g_pGlobalState->sockets[i].in_use) return i; return -1; }
static SHARED_SOCKET* FindSharedSocketById(SOCKET s) { if (g_pGlobalState) for (int i = 0; i < MAX_SHARED_SOCKETS; i++) if (g_pGlobalState->sockets[i].in_use && g_pGlobalState->sockets[i].fake_socket_id == s) return &g_pGlobalState->sockets[i]; return NULL; }
static char* GetRecvBuffer(SHARED_SOCKET* sock) { int index = (int)(sock - g_pGlobalState->sockets); return g_pGlobalState->data_buffers + (index * BUFFER_PER_SOCKET); }
static inline size_t recv_capacity() { return BUFFER_PER_SOCKET; }
static inline size_t recv_available(SHARED_SOCKET* s) { return (s->recv_tail + recv_capacity() - s->recv_head) % recv_capacity(); }
static inline size_t recv_free_space(SHARED_SOCKET* s) { return recv_capacity() - recv_available(s) - 1; }

// --- Byte-order and address functions ---
static inline unsigned long swap_ulong(unsigned long x) { return ((x & 0x000000FF) << 24)|((x & 0x0000FF00) << 8)|((x & 0x00FF0000) >> 8)|((x & 0xFF000000) >> 24); }
static inline unsigned short swap_ushort(unsigned short x) { return ((x & 0x00FF) << 8) | ((x & 0xFF00) >> 8); }
u_long WSAAPI ex_htonl(u_long h) { return swap_ulong(h); }
u_short WSAAPI ex_htons(u_short h) { return swap_ushort(h); }
u_long WSAAPI ex_ntohl(u_long n) { return swap_ulong(n); }
u_short WSAAPI ex_ntohs(u_short n) { return swap_ushort(n); }
unsigned long WSAAPI ex_inet_addr(const char* c){ int a,b,d,e; if (!c || sscanf_s(c, "%d.%d.%d.%d",&a,&b,&d,&e) != 4) return INADDR_NONE; if ((unsigned)a>255||(unsigned)b>255||(unsigned)d>255||(unsigned)e>255) return INADDR_NONE; return (unsigned long)((e<<24)|(d<<16)|(b<<8)|a); }
char* WSAAPI ex_inet_ntoa(struct in_addr i){ static THREAD_LOCAL char b[18]; unsigned char*p=(unsigned char*)&i.s_addr; sprintf_s(b,sizeof(b),"%u.%u.%u.%u",p[0],p[1],p[2],p[3]); return b;}
int WSAAPI ex_inet_pton(int af, const char* src, void* dst) { if (!src || !dst) return 0; if (af == AF_INET) { unsigned long v = ex_inet_addr(src); if (v == INADDR_NONE && strcmp(src,"255.255.255.255") != 0) return 0; ((struct in_addr*)dst)->s_addr = v; return 1; } else if (af == AF_INET6) { unsigned short w[8]={0}; const char*x=src; int d=-1,c=0; if(*x==':'){if(*(x+1)!=':')return 0;d=0;x+=2;} while(*x&&c<8){if(*x==':'){if(d!=-1)return 0;d=c;x++;if(!*x)break;continue;} char b[5]={0}; int i=0; while(*x&&*x!=':'&&i<4){char ch=*x;int v=(ch>='0'&&ch<='9')?ch-'0':(ch>='a'&&ch<='f')?ch-'a'+10:(ch>='A'&&ch<='F')?ch-'A'+10:-1;if(v<0)return 0;b[i++]=ch;x++;} unsigned int val=0;sscanf_s(b,"%x",&val);if(val>0xFFFF)return 0;w[c++]=(unsigned short)val;if(*x==':')x++;} if(*x)return 0;int i,j;unsigned short f[8]={0};if(d==-1){if(c!=8)return 0;for(i=0;i<8;i++)f[i]=w[i];}else{for(i=0;i<d;i++)f[i]=w[i];for(i=d;i<8-(c-d);i++)f[i]=0;for(i=8-(c-d),j=d;i<8;i++,j++)f[i]=w[j];} unsigned char*p=(unsigned char*)dst;for(i=0;i<8;i++){p[2*i]=(unsigned char)(f[i]>>8);p[2*i+1]=(unsigned char)(f[i]&0xFF);} return 1;} return 0; }
const char* WSAAPI ex_inet_ntop(int af, const void* src, char* dst, size_t size) { if (!src || !dst || size==0) return NULL; if (af==AF_INET) { struct in_addr a=*(const struct in_addr*)src; char* s=ex_inet_ntoa(a); if(strlen(s)+1 > size)return NULL; strcpy_s(dst,size,s); return dst; } else if(af==AF_INET6){ const unsigned char*b=(const unsigned char*)src; unsigned short w[8]; for(int i=0;i<8;i++)w[i]=(unsigned short)((b[2*i]<<8)|b[2*i+1]); int bb=-1,bl=0,cb=-1,cl=0; for(int i=0;i<8;i++){if(w[i]==0){if(cb==-1){cb=i;cl=1;}else cl++;}else{if(cb!=-1){if(cl>bl){bb=cb;bl=cl;}cb=-1;cl=0;}}} if(cb!=-1&&cl>bl){bb=cb;bl=cl;} if(bl<2)bb=-1; char o[64]={0},*p=o;size_t r=sizeof(o);for(int i=0;i<8;i++){if(bb==i){if(r<2)return NULL;*p++=':';r--;if(i==0){*p++=':';r--;}while(i<bb+bl)i++;if(i>=8)break;}int n=_snprintf_s(p,r,_TRUNCATE,"%x",w[i]);if(n<0)return NULL;p+=n;r-=n;if(i<7){if(r<2)return NULL;*p++=':';r--;}} if(strlen(o)+1>size)return NULL;strcpy_s(dst,size,o);return dst;} return NULL; }
static inline void MakeReadEventName(char* out, size_t sz, SOCKET s) { sprintf_s(out, sz, "Local\\ReadEvent_Socket_" UIPTR_FMT, to_uiptr((UINT_PTR)s)); }
static inline void MakeWriteEventName(char* out, size_t sz, SOCKET s) { sprintf_s(out, sz, "Local\\WriteEvent_Socket_" UIPTR_FMT, to_uiptr((UINT_PTR)s)); }
static inline unsigned short GetSockaddrPort(const struct sockaddr* sa) { if(!sa)return 0; if(sa->sa_family==AF_INET)return ex_ntohs(((const struct sockaddr_in*)sa)->sin_port); if(sa->sa_family==AF_INET6)return ex_ntohs(((const struct sockaddr_in6*)sa)->sin6_port); return 0; }
static inline void SetSockaddrPort(struct sockaddr* sa, unsigned short p) { if(!sa)return; if(sa->sa_family==AF_INET)((struct sockaddr_in*)sa)->sin_port=ex_htons(p); else if(sa->sa_family==AF_INET6)((struct sockaddr_in6*)sa)->sin6_port=ex_htons(p); }
static inline void MakeAcceptEventName(char* out, size_t sz, int fam, unsigned short p) { sprintf_s(out, sz, "Local\\AcceptEvent_Fam_%d_Port_%u", (fam==AF_INET6)?6:4, (unsigned)p); }
static unsigned short GetNextEphemeralPort() { LONG n = InterlockedIncrement(&g_ephemeral_port); if(n > EPHEMERAL_PORT_END){InterlockedExchange(&g_ephemeral_port, EPHEMERAL_PORT_START); n=EPHEMERAL_PORT_START;} return(unsigned short)n; }
static int PortInUse(unsigned short port, int family) { for (int i=0; i<MAX_SHARED_SOCKETS; i++) { SHARED_SOCKET* ss=&g_pGlobalState->sockets[i]; if (!ss->in_use || !ss->is_bound || ss->bind_addr.ss_family != family) continue; if (GetSockaddrPort((struct sockaddr*)&ss->bind_addr)==port) return 1; } return 0; }
static void AutoBindIfNeeded(SHARED_SOCKET* s, int family) { if (s->is_bound) return; struct sockaddr_storage addr; memset(&addr,0,sizeof(addr)); addr.ss_family=(short)family; if (family==AF_INET) { struct sockaddr_in* a=(struct sockaddr_in*)&addr; a->sin_family=AF_INET; a->sin_addr.s_addr=ex_inet_addr("127.0.0.1"); while(1){unsigned short np=GetNextEphemeralPort();if(!PortInUse(np,AF_INET)){a->sin_port=ex_htons(np);break;}} s->bind_addr_len=sizeof(struct sockaddr_in); } else { struct sockaddr_in6*a6=(struct sockaddr_in6*)&addr; a6->sin6_family=AF_INET6;a6->sin6_addr=in6addr_loopback; while(1){unsigned short np=GetNextEphemeralPort();if(!PortInUse(np,AF_INET6)){a6->sin6_port=ex_htons(np);break;}} s->bind_addr_len=sizeof(struct sockaddr_in6);} memcpy(&s->bind_addr,&addr,sizeof(addr)); s->is_bound=TRUE; }
static void SanitizeSharedState() { if (!g_pGlobalState) return; for (int i=0; i<MAX_SHARED_SOCKETS; i++) { SHARED_SOCKET* s=&g_pGlobalState->sockets[i]; if (!s->in_use||s->owner_pid==0||s->owner_pid==GetCurrentProcessId()) continue; HANDLE hp=OpenProcess(SYNCHRONIZE,FALSE,s->owner_pid); if(!hp){LogMessage("Sanitize: freeing socket %d (owner %lu) - can't open process",i,s->owner_pid);memset(s,0,sizeof(SHARED_SOCKET));continue;} if(WaitForSingleObject(hp,0)==WAIT_OBJECT_0){LogMessage("Sanitize: freeing socket %d (owner %lu) - process exited",i,s->owner_pid);memset(s,0,sizeof(SHARED_SOCKET));} CloseHandle(hp); } }
static void InitializeEmulator() { if (g_hGlobalMutex) return;
#if ENABLE_FILE_LOG || ENABLE_DATA_DUMP
char p[MAX_PATH]; if (GetTempPathA(MAX_PATH,p)){
#if ENABLE_FILE_LOG
if(!g_hLogFile){char lp[MAX_PATH];strcpy_s(lp,MAX_PATH,p);strcat_s(lp,MAX_PATH,"exloud_net.log");g_hLogFile=CreateFileA(lp,FILE_APPEND_DATA,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);}
#endif
#if ENABLE_DATA_DUMP
if(!g_hDataDumpFile){char dp[MAX_PATH];strcpy_s(dp,MAX_PATH,p);strcat_s(dp,MAX_PATH,"exloud_data.log");g_hDataDumpFile=CreateFileA(dp,FILE_APPEND_DATA,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);}
#endif
}
#endif
LogMessage("--- EXLOUD Winsock Emulator v1.0.2 Initializing ---");
g_hGlobalMutex=CreateMutexA(NULL,FALSE,MUTEX_NAME);if(!g_hGlobalMutex){LogMessage("FATAL: Could not create mutex.");return;}
Lock();g_hSharedMemory=CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,(DWORD)sizeof(GLOBAL_NETWORK_STATE),SHARED_MEM_NAME);if(!g_hSharedMemory){Unlock();LogMessage("FATAL: Could not create shared memory.");return;}
BOOL first=(GetLastError()!=ERROR_ALREADY_EXISTS);g_pGlobalState=(GLOBAL_NETWORK_STATE*)MapViewOfFile(g_hSharedMemory,FILE_MAP_ALL_ACCESS,0,0,sizeof(GLOBAL_NETWORK_STATE));if(!g_pGlobalState){Unlock();LogMessage("FATAL: Could not map shared memory.");return;}
if(first){LogMessage("First process: initializing shared state.");memset(g_pGlobalState,0,sizeof(GLOBAL_NETWORK_STATE));g_pGlobalState->initializing_pid=GetCurrentProcessId();}else{LogMessage("Attached to existing state (init by PID: %lu).",g_pGlobalState->initializing_pid);}
SanitizeSharedState();Unlock();}
static void CleanupEmulator() { if(g_init_count<=0||InterlockedDecrement(&g_init_count)>0)return;LogMessage("--- Final Cleanup ---");
#if ENABLE_BEHAVIOR_ANALYSIS
Lock();if(g_pGlobalState){LogMessage("--- Socket Behavior Analysis (PID %lu) ---",GetCurrentProcessId());for(int i=0;i<MAX_SHARED_SOCKETS;i++){SHARED_SOCKET*s=&g_pGlobalState->sockets[i];if(s->in_use&&s->owner_pid==GetCurrentProcessId()){LogMessage("Socket "PTR_FORMAT": Sent=%lu, Recv=%lu, Pkts(1B/S/L): %lu/%lu/%lu", (UINT_PTR)s->fake_socket_id,s->behavior.total_bytes_sent,s->behavior.total_bytes_recv,s->behavior.single_byte_count,s->behavior.short_messages,s->behavior.long_messages);}}}Unlock();
#endif
#if ENABLE_MEMORY_TRACKING
ReportMemoryLeaks();
#endif
if(g_pGlobalState)UnmapViewOfFile(g_pGlobalState);if(g_hSharedMemory)CloseHandle(g_hSharedMemory);if(g_hGlobalMutex)CloseHandle(g_hGlobalMutex);g_pGlobalState=NULL;g_hSharedMemory=NULL;g_hGlobalMutex=NULL;if(g_hLogFile){CloseHandle(g_hLogFile);g_hLogFile=NULL;}
#if ENABLE_DATA_DUMP
if(g_hDataDumpFile){CloseHandle(g_hDataDumpFile);g_hDataDumpFile=NULL;}
#endif
}
static inline void EnsureInitialized() { if (!g_pGlobalState || !g_hGlobalMutex) InitializeEmulator(); }

// --- Winsock API Implementations ---
int WSAAPI ex_WSAStartup(WORD w, LPWSADATA d) { if(InterlockedIncrement(&g_init_count) == 1) InitializeEmulator(); LogMessage("WSAStartup"); if (d) { d->wVersion=MAKEWORD(2,2); d->wHighVersion=MAKEWORD(2,2); strcpy_s(d->szDescription, sizeof(d->szDescription), "EXLOUD Winsock Emulator v1.0.2"); } return 0; }
int WSAAPI ex_WSACleanup() { LogMessage("WSACleanup"); CleanupEmulator(); return 0; }
int WSAAPI ex_WSAGetLastError() { return g_tlsWSAError; }
void WSAAPI ex_WSASetLastError(int e) { g_tlsWSAError = e; }
SOCKET WSAAPI ex_socket(int af, int t, int p) { EnsureInitialized(); LogMessage("socket(af=%d, type=%d, proto=%d)", af, t, p); if (t!=SOCK_STREAM){ g_tlsWSAError=WSAESOCKTNOSUPPORT; return INVALID_SOCKET; } if (af!=AF_INET&&af!=AF_INET6){ g_tlsWSAError=WSAEAFNOSUPPORT; return INVALID_SOCKET; } Lock(); int i=FindFreeSocketSlot(); if(i==-1){Unlock(); g_tlsWSAError=WSAENOBUFS; return INVALID_SOCKET;} SHARED_SOCKET*s=&g_pGlobalState->sockets[i]; memset(s,0,sizeof(SHARED_SOCKET)); s->in_use=TRUE;s->owner_pid=GetCurrentProcessId();s->fake_socket_id=GenerateFakeSocket();s->peer_socket_index=-1; s->bind_addr.ss_family=(short)af; s->bind_addr_len=(af==AF_INET)?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6); SOCKET new_id=s->fake_socket_id; Unlock(); LogMessage(" -> " PTR_FORMAT,(UINT_PTR)new_id); return new_id; }
SOCKET WSAAPI ex_WSASocketA(int af,int t,int p,LPVOID i,GROUP g,DWORD f) {UNREFERENCED_PARAMETER(i);UNREFERENCED_PARAMETER(g);UNREFERENCED_PARAMETER(f);return ex_socket(af,t,p);}
SOCKET WSAAPI ex_WSASocketW(int af,int t,int p,LPVOID i,GROUP g,DWORD f) {UNREFERENCED_PARAMETER(i);UNREFERENCED_PARAMETER(g);UNREFERENCED_PARAMETER(f);return ex_socket(af,t,p);}
int WSAAPI ex_bind(SOCKET s,const struct sockaddr* n,int nl) {EnsureInitialized();if(!n||nl<(int)sizeof(struct sockaddr)){g_tlsWSAError=WSAEFAULT;return SOCKET_ERROR;}int f=n->sa_family;if(f!=AF_INET&&f!=AF_INET6){g_tlsWSAError=WSAEAFNOSUPPORT;return SOCKET_ERROR;}struct sockaddr_storage a;memset(&a,0,sizeof(a));memcpy(&a,n,min((int)sizeof(a),nl));unsigned short rp=GetSockaddrPort((const struct sockaddr*)&a);if(rp==0){Lock();while(1){unsigned short np=GetNextEphemeralPort();if(!PortInUse(np,f)){SetSockaddrPort((struct sockaddr*)&a,np);break;}}Unlock();}unsigned short fp=GetSockaddrPort((const struct sockaddr*)&a);LogMessage("bind("PTR_FORMAT") to port %u", (UINT_PTR)s,fp);Lock();SHARED_SOCKET*sock=FindSharedSocketById(s);if(!sock){Unlock();g_tlsWSAError=WSAENOTSOCK;return SOCKET_ERROR;}for(int i=0;i<MAX_SHARED_SOCKETS;i++){SHARED_SOCKET*x=&g_pGlobalState->sockets[i];if(!x->in_use||!x->is_bound||x==sock)continue;if(x->bind_addr.ss_family==f&&GetSockaddrPort((struct sockaddr*)&x->bind_addr)==fp){Unlock();LogMessage(" -> EADDRINUSE");g_tlsWSAError=WSAEADDRINUSE;return SOCKET_ERROR;}}sock->is_bound=TRUE;memcpy(&sock->bind_addr,&a,sizeof(a));sock->bind_addr_len=(f==AF_INET)?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6);Unlock();return 0;}
int WSAAPI ex_listen(SOCKET s, int b) { EnsureInitialized();LogMessage("listen("PTR_FORMAT")",(UINT_PTR)s);Lock();SHARED_SOCKET*sock=FindSharedSocketById(s);if(!sock||!sock->is_bound){Unlock();g_tlsWSAError=sock?WSAEINVAL:WSAENOTSOCK;return SOCKET_ERROR;}sock->is_listening=TRUE;Unlock();return 0;}
int WSAAPI ex_connect(SOCKET s, const struct sockaddr* n, int nl) { EnsureInitialized();if(!n||nl<(int)sizeof(struct sockaddr)){g_tlsWSAError=WSAEFAULT;return SOCKET_ERROR;}int f=n->sa_family;if(f!=AF_INET&&f!=AF_INET6){g_tlsWSAError=WSAEAFNOSUPPORT;return SOCKET_ERROR;}unsigned short p=GetSockaddrPort(n);LogMessage("connect("PTR_FORMAT") to port %u",(UINT_PTR)s,p);Lock();SHARED_SOCKET*c=FindSharedSocketById(s);if(!c){Unlock();g_tlsWSAError=WSAENOTSOCK;return SOCKET_ERROR;}AutoBindIfNeeded(c,f);int l=-1;for(int i=0;i<MAX_SHARED_SOCKETS;i++){SHARED_SOCKET*ls=&g_pGlobalState->sockets[i];if(ls->in_use&&ls->is_listening&&ls->bind_addr.ss_family==f&&GetSockaddrPort((struct sockaddr*)&ls->bind_addr)==p){l=i;break;}}if(l==-1){Unlock();LogMessage(" -> ECONNREFUSED");g_tlsWSAError=WSAECONNREFUSED;return SOCKET_ERROR;}SHARED_SOCKET*srv=&g_pGlobalState->sockets[l];if(srv->accept_queue_len>=MAX_PENDING_CONN){Unlock();LogMessage(" -> ECONNREFUSED (queue full)");g_tlsWSAError=WSAECONNREFUSED;return SOCKET_ERROR;}int si=FindFreeSocketSlot();if(si==-1){Unlock();g_tlsWSAError=WSAENOBUFS;return SOCKET_ERROR;}int ci=(int)(c-g_pGlobalState->sockets);SHARED_SOCKET*ss=&g_pGlobalState->sockets[si];memset(ss,0,sizeof(SHARED_SOCKET));ss->in_use=TRUE;ss->owner_pid=srv->owner_pid;ss->fake_socket_id=GenerateFakeSocket();ss->is_connected=TRUE;ss->peer_socket_index=ci;ss->is_bound=TRUE;ss->bind_addr=srv->bind_addr;ss->bind_addr_len=srv->bind_addr_len;c->is_connected=TRUE;c->peer_socket_index=si;srv->accept_queue[srv->accept_queue_len++]=si;unsigned short lp=GetSockaddrPort((struct sockaddr*)&srv->bind_addr);int fam=srv->bind_addr.ss_family;Unlock();char en[96];MakeAcceptEventName(en,sizeof(en),fam,lp);HANDLE h=OpenEventA(EVENT_MODIFY_STATE,FALSE,en);if(h){LogMessage(" -> Signaling accept");SetEvent(h);CloseHandle(h);}LogMessage(" -> Connected "PTR_FORMAT" <=> "PTR_FORMAT,(UINT_PTR)c->fake_socket_id,(UINT_PTR)ss->fake_socket_id);return 0;}
SOCKET WSAAPI ex_accept(SOCKET s, struct sockaddr* a, int* al) {EnsureInitialized();LogMessage("accept("PTR_FORMAT")",(UINT_PTR)s);char en[96];HANDLE h=NULL;Lock();SHARED_SOCKET*l=FindSharedSocketById(s);if(!l||!l->is_listening){Unlock();g_tlsWSAError=WSAEINVAL;return INVALID_SOCKET;}unsigned short p=GetSockaddrPort((struct sockaddr*)&l->bind_addr);int fam=l->bind_addr.ss_family;Unlock();MakeAcceptEventName(en,sizeof(en),fam,p);h=CreateEventA(NULL,FALSE,FALSE,en);if(!h){g_tlsWSAError=WSAENETDOWN;return INVALID_SOCKET;}while(1){Lock();l=FindSharedSocketById(s);if(l&&l->accept_queue_len>0){int si=l->accept_queue[0];for(int i=0;i<l->accept_queue_len-1;i++)l->accept_queue[i]=l->accept_queue[i+1];l->accept_queue_len--;SHARED_SOCKET*ss=&g_pGlobalState->sockets[si];SHARED_SOCKET*cs=&g_pGlobalState->sockets[ss->peer_socket_index];if(a&&al&&*al>=(int)sizeof(struct sockaddr)){int cl=min(*al,cs->bind_addr_len);memcpy(a,&cs->bind_addr,cl);*al=cl;}Unlock();CloseHandle(h);LogMessage(" -> Accepted "PTR_FORMAT,(UINT_PTR)ss->fake_socket_id);return ss->fake_socket_id;}BOOL nb=l?l->is_nonblocking:FALSE;Unlock();if(nb){CloseHandle(h);g_tlsWSAError=WSAEWOULDBLOCK;return INVALID_SOCKET;}LogMessage(" -> Waiting on accept...");WaitForSingleObject(h,INFINITE);}}
SOCKET WSAAPI ex_WSAAccept(SOCKET s, struct sockaddr* a, LPINT al, LPCONDITIONPROC lpfn, DWORD_PTR dc){UNREFERENCED_PARAMETER(lpfn);UNREFERENCED_PARAMETER(dc);return ex_accept(s,a,al);}

// [FIX] Correctly formatted preprocessor directives
int WSAAPI ex_send(SOCKET s, const char* b, int l, int f) {
    EnsureInitialized();
    UNREFERENCED_PARAMETER(f);
    if (l <= 0) return 0;
    HANDLE wh = NULL;
    char wen[96];
retry:
    Lock();
    SHARED_SOCKET* snd = FindSharedSocketById(s);
    if (!snd) { Unlock(); if (wh) CloseHandle(wh); g_tlsWSAError = WSAENOTSOCK; return SOCKET_ERROR; }
    if (snd->shutdown_flags & 2) { Unlock(); if (wh) CloseHandle(wh); g_tlsWSAError = WSAESHUTDOWN; return SOCKET_ERROR; }
    if (!snd->is_connected || snd->peer_socket_index == -1) { Unlock(); if (wh) CloseHandle(wh); g_tlsWSAError = WSAENOTCONN; return SOCKET_ERROR; }
    SHARED_SOCKET* rcv = &g_pGlobalState->sockets[snd->peer_socket_index];
    size_t fs = recv_free_space(rcv);
    int tw = (int)min((size_t)l, fs);
    if (tw > 0) {
        LogMessage("send(" PTR_FORMAT ", len=%d) -> wrote %d", (UINT_PTR)s, l, tw);
        char* buf = GetRecvBuffer(rcv);
        size_t tail = rcv->recv_tail;
        size_t cap = recv_capacity();
        size_t first = min((size_t)tw, cap - tail);
        memcpy(buf + tail, b, first);
        if ((size_t)tw > first) memcpy(buf, b + first, tw - first);
        rcv->recv_tail = (rcv->recv_tail + tw) % cap;
        SOCKET rid = rcv->fake_socket_id;
        #if ENABLE_BEHAVIOR_ANALYSIS
        snd->behavior.total_bytes_sent += tw;
        if (tw == 1) snd->behavior.single_byte_count++;
        else if (tw < 16) snd->behavior.short_messages++;
        else snd->behavior.long_messages++;
        #endif
        Unlock();
        #if ENABLE_DATA_DUMP
        DumpDataToFile("SEND", s, b, tw);
        #endif
        char ren[96];
        MakeReadEventName(ren, sizeof(ren), rid);
        HANDLE rh = OpenEventA(EVENT_MODIFY_STATE, FALSE, ren);
        if (rh) { SetEvent(rh); CloseHandle(rh); }
        if (wh) CloseHandle(wh);
        return tw;
    }
    BOOL nb = snd->is_nonblocking;
    if (!rcv->in_use) { Unlock(); if (wh) CloseHandle(wh); g_tlsWSAError = WSAECONNRESET; return SOCKET_ERROR; }
    Unlock();
    if (nb) { if (wh) CloseHandle(wh); g_tlsWSAError = WSAEWOULDBLOCK; return SOCKET_ERROR; }
    if (!wh) { MakeWriteEventName(wen, sizeof(wen), snd->fake_socket_id); wh = CreateEventA(NULL, FALSE, FALSE, wen); if (!wh) { g_tlsWSAError = WSAENETDOWN; return SOCKET_ERROR; } }
    LogMessage(" -> send(" PTR_FORMAT ") waiting", (UINT_PTR)s);
    WaitForSingleObject(wh, INFINITE);
    goto retry;
}

int WSAAPI ex_recv(SOCKET s, char* b, int l, int f) {
    EnsureInitialized();
    if (l <= 0) return 0;
    char ren[96];
    MakeReadEventName(ren, sizeof(ren), s);
    HANDLE h = CreateEventA(NULL, FALSE, FALSE, ren);
    if (!h) { g_tlsWSAError = WSAENETDOWN; return SOCKET_ERROR; }
    while (1) {
        Lock();
        SHARED_SOCKET* rcv = FindSharedSocketById(s);
        if (!rcv) { Unlock(); CloseHandle(h); g_tlsWSAError = WSAENOTSOCK; return SOCKET_ERROR; }
        if (rcv->shutdown_flags & 1) { Unlock(); CloseHandle(h); g_tlsWSAError = WSAESHUTDOWN; return SOCKET_ERROR; }
        size_t avail = recv_available(rcv);
        if (avail > 0) {
            int tr = (int)min((size_t)l, avail);
            char* buf = GetRecvBuffer(rcv);
            size_t head = rcv->recv_head;
            size_t cap = recv_capacity();
            size_t first = min((size_t)tr, cap - head);
            memcpy(b, buf + head, first);
            if ((size_t)tr > first) memcpy(b + first, buf, tr - first);
            int pi = rcv->peer_socket_index;
            SOCKET pid = INVALID_SOCKET;
            if (!(f & MSG_PEEK)) {
                rcv->recv_head = (rcv->recv_head + tr) % cap;
                if (pi != -1) pid = g_pGlobalState->sockets[pi].fake_socket_id;
                #if ENABLE_BEHAVIOR_ANALYSIS
                rcv->behavior.total_bytes_recv += tr;
                #endif
            }
            Unlock();
            CloseHandle(h);
            #if ENABLE_DATA_DUMP
            if (!(f & MSG_PEEK)) DumpDataToFile("RECV", s, b, tr);
            #endif
            if (!(f & MSG_PEEK) && pid != INVALID_SOCKET) {
                char wen[96];
                MakeWriteEventName(wen, sizeof(wen), pid);
                HANDLE wh = OpenEventA(EVENT_MODIFY_STATE, FALSE, wen);
                if (wh) { SetEvent(wh); CloseHandle(wh); }
            }
            LogMessage("recv(" PTR_FORMAT ", len=%d) -> read %d", (UINT_PTR)s, l, tr);
            return tr;
        }
        if (rcv->peer_socket_index != -1) {
            SHARED_SOCKET* p = &g_pGlobalState->sockets[rcv->peer_socket_index];
            if ((p->shutdown_flags & 2) != 0 || !p->in_use) { Unlock(); CloseHandle(h); return 0; }
        } else {
            Unlock();
            CloseHandle(h);
            return 0;
        }
        BOOL nb = rcv->is_nonblocking;
        Unlock();
        if (nb) { CloseHandle(h); g_tlsWSAError = WSAEWOULDBLOCK; return SOCKET_ERROR; }
        LogMessage(" -> recv(" PTR_FORMAT ") waiting", (UINT_PTR)s);
        WaitForSingleObject(h, INFINITE);
    }
}

int WSAAPI ex_closesocket(SOCKET s){EnsureInitialized();LogMessage("closesocket("PTR_FORMAT")",(UINT_PTR)s);Lock();SHARED_SOCKET*sock=FindSharedSocketById(s);if(!sock){Unlock();g_tlsWSAError=WSAENOTSOCK;return SOCKET_ERROR;}if(sock->peer_socket_index!=-1){SHARED_SOCKET*p=&g_pGlobalState->sockets[sock->peer_socket_index];p->is_connected=FALSE;p->peer_socket_index=-1;char r[96];MakeReadEventName(r,sizeof(r),p->fake_socket_id);HANDLE h1=OpenEventA(EVENT_MODIFY_STATE,FALSE,r);if(h1){SetEvent(h1);CloseHandle(h1);}char w[96];MakeWriteEventName(w,sizeof(w),p->fake_socket_id);HANDLE h2=OpenEventA(EVENT_MODIFY_STATE,FALSE,w);if(h2){SetEvent(h2);CloseHandle(h2);}}memset(sock,0,sizeof(SHARED_SOCKET));Unlock();return 0;}
int WSAAPI ex_shutdown(SOCKET s,int h){EnsureInitialized();LogMessage("shutdown("PTR_FORMAT",%d)",(UINT_PTR)s,h);Lock();SHARED_SOCKET*sock=FindSharedSocketById(s);if(!sock){Unlock();g_tlsWSAError=WSAENOTSOCK;return SOCKET_ERROR;}if(h==SD_RECEIVE||h==SD_BOTH)sock->shutdown_flags|=1;if(h==SD_SEND||h==SD_BOTH)sock->shutdown_flags|=2;if((h==SD_SEND||h==SD_BOTH)&&sock->peer_socket_index!=-1){SHARED_SOCKET*p=&g_pGlobalState->sockets[sock->peer_socket_index];char r[96];MakeReadEventName(r,sizeof(r),p->fake_socket_id);HANDLE hr=OpenEventA(EVENT_MODIFY_STATE,FALSE,r);if(hr){SetEvent(hr);CloseHandle(hr);}}Unlock();return 0;}
int WSAAPI ex_ioctlsocket(SOCKET s,long c,u_long*a){EnsureInitialized();if(!a){g_tlsWSAError=WSAEFAULT;return SOCKET_ERROR;}Lock();SHARED_SOCKET*sock=FindSharedSocketById(s);if(!sock){Unlock();g_tlsWSAError=WSAENOTSOCK;return SOCKET_ERROR;}if(c==FIONBIO){sock->is_nonblocking=(*a!=0);LogMessage("ioctlsocket(FIONBIO=%lu)",*a);}else if(c==FIONREAD){*a=(u_long)recv_available(sock);LogMessage("ioctlsocket(FIONREAD->%lu)",*a);}Unlock();return 0;}
int WSAAPI ex_getsockname(SOCKET s,struct sockaddr*n,int*nl){EnsureInitialized();if(!n||!nl){g_tlsWSAError=WSAEFAULT;return SOCKET_ERROR;}Lock();SHARED_SOCKET*sock=FindSharedSocketById(s);if(!sock){Unlock();g_tlsWSAError=WSAENOTSOCK;return SOCKET_ERROR;}if(!sock->is_bound){Unlock();memset(n,0,*nl);return 0;}int cl=min(*nl,sock->bind_addr_len);memcpy(n,&sock->bind_addr,cl);*nl=sock->bind_addr_len;Unlock();return 0;}
int WSAAPI ex_getpeername(SOCKET s,struct sockaddr*n,int*nl){EnsureInitialized();if(!n||!nl){g_tlsWSAError=WSAEFAULT;return SOCKET_ERROR;}Lock();SHARED_SOCKET*sock=FindSharedSocketById(s);if(!sock||!sock->is_connected||sock->peer_socket_index==-1){Unlock();g_tlsWSAError=WSAENOTCONN;return SOCKET_ERROR;}SHARED_SOCKET*p=&g_pGlobalState->sockets[sock->peer_socket_index];int cl=min(*nl,p->bind_addr_len);memcpy(n,&p->bind_addr,cl);*nl=p->bind_addr_len;Unlock();return 0;}
int WSAAPI ex_gethostname(char*n,int l){if(n&&l>0){strcpy_s(n,l,"virtual-pc");return 0;}g_tlsWSAError=WSAEFAULT;return SOCKET_ERROR;}
struct hostent*WSAAPI ex_gethostbyname(const char*n){LogMessage("gethostbyname('%s')->BLOCKED",n?n:"(null)");g_tlsWSAError=WSAHOST_NOT_FOUND;return NULL;}
int WSAAPI ex_getaddrinfo(PCSTR n,PCSTR s,const ADDRINFOA*h,PADDRINFOA*r){if(!r)return EAI_FAIL;*r=NULL;BOOL l=(n==NULL)||(_stricmp(n,"localhost")==0);BOOL v4=n&&(_stricmp(n,"127.0.0.1")==0);BOOL v6=n&&(_stricmp(n,"::1")==0);if(!l&&!v4&&!v6){LogMessage("getaddrinfo('%s')->BLOCKED",n);return EAI_FAIL;}unsigned short p=0;if(s&&*s){char*e=NULL;unsigned long v=strtoul(s,&e,10);if(*s=='\0'||(e&&*e!='\0')||v>65535)return EAI_SERVICE;p=(unsigned short)v;}int fh=h?h->ai_family:AF_UNSPEC;int st=h?h->ai_socktype:0;if(st&&st!=SOCK_STREAM)return EAI_SOCKTYPE;int w4=v4||(!v6&&(fh==AF_UNSPEC||fh==AF_INET));int w6=v6||(!v4&&(fh==AF_UNSPEC||fh==AF_INET6));PADDRINFOA head=NULL,tail=NULL;if(w6){PADDRINFOA ai=(PADDRINFOA)SAFE_ALLOC(sizeof(ADDRINFOA)+sizeof(struct sockaddr_in6),"getaddrinfo");if(!ai){if(head)ex_freeaddrinfo(head);return EAI_MEMORY;}struct sockaddr_in6*a6=(struct sockaddr_in6*)(ai+1);a6->sin6_family=AF_INET6;a6->sin6_addr=in6addr_loopback;a6->sin6_port=ex_htons(p);ai->ai_family=AF_INET6;ai->ai_socktype=SOCK_STREAM;ai->ai_protocol=IPPROTO_TCP;ai->ai_addrlen=sizeof(struct sockaddr_in6);ai->ai_addr=(struct sockaddr*)a6;if(!head)head=ai;else tail->ai_next=ai;tail=ai;}if(w4){PADDRINFOA ai=(PADDRINFOA)SAFE_ALLOC(sizeof(ADDRINFOA)+sizeof(struct sockaddr_in),"getaddrinfo");if(!ai){if(head)ex_freeaddrinfo(head);return EAI_MEMORY;}struct sockaddr_in*a=(struct sockaddr_in*)(ai+1);a->sin_family=AF_INET;a->sin_addr.s_addr=ex_inet_addr("127.0.0.1");a->sin_port=ex_htons(p);ai->ai_family=AF_INET;ai->ai_socktype=SOCK_STREAM;ai->ai_protocol=IPPROTO_TCP;ai->ai_addrlen=sizeof(struct sockaddr_in);ai->ai_addr=(struct sockaddr*)a;if(!head)head=ai;else tail->ai_next=ai;tail=ai;}if(!head)return EAI_FAIL;*r=head;return 0;}
void WSAAPI ex_freeaddrinfo(PADDRINFOA p){while(p){PADDRINFOA next=p->ai_next;SAFE_FREE(p);p=next;}}
int WSAAPI ex_GetAddrInfoW(PCWSTR n,PCWSTR s,const ADDRINFOW*h,PADDRINFOW*r){UNREFERENCED_PARAMETER(n);UNREFERENCED_PARAMETER(s);UNREFERENCED_PARAMETER(h);UNREFERENCED_PARAMETER(r);return EAI_FAIL;}
void WSAAPI ex_FreeAddrInfoW(PADDRINFOW p){while(p){PADDRINFOW next=p->ai_next;SAFE_FREE(p);p=next;}}
int WSAAPI ex_select(int n,fd_set*r,fd_set*w,fd_set*e,const struct timeval*t){UNREFERENCED_PARAMETER(n);EnsureInitialized();DWORD to=t?(t->tv_sec*1000+t->tv_usec/1000):INFINITE;DWORD start=GetTickCount();do{int rc=0;fd_set rr,rw,re;FD_ZERO(&rr);FD_ZERO(&rw);FD_ZERO(&re);Lock();if(r)for(u_int i=0;i<r->fd_count;i++){SHARED_SOCKET*s=FindSharedSocketById(r->fd_array[i]);if(s){BOOL pc=FALSE;if(s->is_connected&&s->peer_socket_index!=-1){SHARED_SOCKET*p=&g_pGlobalState->sockets[s->peer_socket_index];if(!p->in_use||(p->shutdown_flags&2))pc=TRUE;}if((s->is_listening&&s->accept_queue_len>0)||(recv_available(s)>0)||pc){FD_SET(s->fake_socket_id,&rr);rc++;}}}if(w)for(u_int i=0;i<w->fd_count;i++){SHARED_SOCKET*s=FindSharedSocketById(w->fd_array[i]);if(s&&s->is_connected&&s->peer_socket_index!=-1){if(recv_free_space(&g_pGlobalState->sockets[s->peer_socket_index])>0){FD_SET(s->fake_socket_id,&rw);rc++;}}}if(e){FD_ZERO(e);}Unlock();if(rc>0){if(r)*r=rr;if(w)*w=rw;g_tlsWSAError=0;return rc;}if(to==0)break;Sleep(10);}while(GetTickCount()-start<to);if(r)FD_ZERO(r);if(w)FD_ZERO(w);if(e)FD_ZERO(e);g_tlsWSAError=0;return 0;}
int WSAAPI ex_getsockopt(SOCKET s,int l,int o,char*ov,int*ol){if(!ov||!ol){g_tlsWSAError=WSAEFAULT;return SOCKET_ERROR;}EnsureInitialized();Lock();SHARED_SOCKET*sock=FindSharedSocketById(s);if(!sock){Unlock();g_tlsWSAError=WSAENOTSOCK;return SOCKET_ERROR;}if(l==SOL_SOCKET&&o==SO_ERROR&&*ol>=sizeof(int)){*(int*)ov=g_tlsWSAError;*ol=sizeof(int);g_tlsWSAError=0;}else if(l==SOL_SOCKET&&o==SO_TYPE&&*ol>=sizeof(int)){*(int*)ov=SOCK_STREAM;*ol=sizeof(int);}else if(l==SOL_SOCKET&&o==SO_LINGER&&*ol>=sizeof(struct linger)){memcpy(ov,&sock->linger_opts,sizeof(struct linger));*ol=sizeof(struct linger);}else if(l==IPPROTO_TCP&&o==TCP_NODELAY&&*ol>=sizeof(int)){*(int*)ov=sock->tcp_nodelay;*ol=sizeof(int);}Unlock();return 0;}
int WSAAPI ex_setsockopt(SOCKET s,int l,int o,const char*ov,int ol){if(!ov){g_tlsWSAError=WSAEFAULT;return SOCKET_ERROR;}EnsureInitialized();Lock();SHARED_SOCKET*sock=FindSharedSocketById(s);if(!sock){Unlock();g_tlsWSAError=WSAENOTSOCK;return SOCKET_ERROR;}if(l==SOL_SOCKET&&o==SO_LINGER&&ol>=sizeof(struct linger)){memcpy(&sock->linger_opts,ov,sizeof(struct linger));}else if(l==IPPROTO_TCP&&o==TCP_NODELAY&&ol>=sizeof(int)){sock->tcp_nodelay=(*(int*)ov!=0);}Unlock();return 0;}

// --- Stubs for linker ---
int WSAAPI ex_StubFail_NotSupp(void) { LogMessage("STUB: Call to unsupported function -> FAIL"); g_tlsWSAError = WSAEOPNOTSUPP; return SOCKET_ERROR; }
void   WSAAPI ex_StubVoid(void) { LogMessage("STUB: Call to void unsupported function."); }
LPVOID WSAAPI ex_StubReturnNull(void) { LogMessage("STUB: Call to unsupported function -> NULL"); g_tlsWSAError = WSAEOPNOTSUPP; return NULL; }
int WSAAPI ex_StubSuccess(void) { LogMessage("STUB: Call to unsupported function -> SUCCESS"); g_tlsWSAError = 0; return 0; }
int WSAAPI ex___WSAFDIsSet(SOCKET s, fd_set* set) { if (!set) return 0; for (u_int i=0;i<set->fd_count;i++) if (set->fd_array[i]==s) return 1; return 0; }
int WSAAPI ex_sendto(SOCKET s,const char*b,int l,int f,const struct sockaddr*t,int tl){ UNREFERENCED_PARAMETER(s);UNREFERENCED_PARAMETER(b);UNREFERENCED_PARAMETER(l);UNREFERENCED_PARAMETER(f);UNREFERENCED_PARAMETER(t);UNREFERENCED_PARAMETER(tl); return ex_StubFail_NotSupp(); }
int WSAAPI ex_recvfrom(SOCKET s,char*b,int l,int f,struct sockaddr*fr,int*fl){ UNREFERENCED_PARAMETER(s);UNREFERENCED_PARAMETER(b);UNREFERENCED_PARAMETER(l);UNREFERENCED_PARAMETER(f);UNREFERENCED_PARAMETER(fr);UNREFERENCED_PARAMETER(fl); return ex_StubFail_NotSupp(); }
struct protoent* WSAAPI ex_getprotobyname(const char* name) { UNREFERENCED_PARAMETER(name); return (struct protoent*)ex_StubReturnNull(); }
struct servent*  WSAAPI ex_getservbyname(const char* name, const char* proto) { UNREFERENCED_PARAMETER(name);UNREFERENCED_PARAMETER(proto); return (struct servent*)ex_StubReturnNull(); }
int WSAAPI ex_WSASend(SOCKET s,LPWSABUF lp,DWORD c,LPDWORD nb,DWORD f,LPWSAOVERLAPPED o,LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) { UNREFERENCED_PARAMETER(s);UNREFERENCED_PARAMETER(lp);UNREFERENCED_PARAMETER(c);UNREFERENCED_PARAMETER(nb);UNREFERENCED_PARAMETER(f);UNREFERENCED_PARAMETER(o);UNREFERENCED_PARAMETER(cr); return ex_StubFail_NotSupp(); }
int WSAAPI ex_WSARecv(SOCKET s,LPWSABUF lp,DWORD c,LPDWORD nb,LPDWORD f,LPWSAOVERLAPPED o,LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) { UNREFERENCED_PARAMETER(s);UNREFERENCED_PARAMETER(lp);UNREFERENCED_PARAMETER(c);UNREFERENCED_PARAMETER(nb);UNREFERENCED_PARAMETER(f);UNREFERENCED_PARAMETER(o);UNREFERENCED_PARAMETER(cr); return ex_StubFail_NotSupp(); }
int WSAAPI ex_WSAIoctl(SOCKET s,DWORD c,LPVOID in,DWORD cin,LPVOID out,DWORD cout,LPDWORD ret,LPWSAOVERLAPPED o,LPWSAOVERLAPPED_COMPLETION_ROUTINE r) { UNREFERENCED_PARAMETER(s);UNREFERENCED_PARAMETER(c);UNREFERENCED_PARAMETER(in);UNREFERENCED_PARAMETER(cin);UNREFERENCED_PARAMETER(out);UNREFERENCED_PARAMETER(cout);UNREFERENCED_PARAMETER(ret);UNREFERENCED_PARAMETER(o);UNREFERENCED_PARAMETER(r); if(c==FIONBIO && in) return ex_ioctlsocket(s, FIONBIO, (u_long*)in); if(c==FIONREAD && out) return ex_ioctlsocket(s, FIONREAD, (u_long*)out); return ex_StubFail_NotSupp(); }
struct hostent* WSAAPI ex_gethostbyaddr(const char* addr, int len, int type) { UNREFERENCED_PARAMETER(addr);UNREFERENCED_PARAMETER(len);UNREFERENCED_PARAMETER(type); return (struct hostent*)ex_StubReturnNull(); }
struct protoent* WSAAPI ex_getprotobynumber(int number) { UNREFERENCED_PARAMETER(number); return (struct protoent*)ex_StubReturnNull(); }
struct servent* WSAAPI ex_getservbyport(int port, const char* proto) { UNREFERENCED_PARAMETER(port);UNREFERENCED_PARAMETER(proto); return (struct servent*)ex_StubReturnNull(); }
int WSAAPI ex_getnameinfo(const struct sockaddr* sa, socklen_t salen, char* host, DWORD hostlen, char* serv, DWORD servlen, int flags) { UNREFERENCED_PARAMETER(sa);UNREFERENCED_PARAMETER(salen);UNREFERENCED_PARAMETER(host);UNREFERENCED_PARAMETER(hostlen);UNREFERENCED_PARAMETER(serv);UNREFERENCED_PARAMETER(servlen);UNREFERENCED_PARAMETER(flags); return ex_StubFail_NotSupp(); }
HANDLE WSAAPI ex_WSACreateEvent(void) { LogMessage("WSACreateEvent"); return CreateEventA(NULL, TRUE, FALSE, NULL); }
BOOL WSAAPI ex_WSACloseEvent(HANDLE h) { LogMessage("WSACloseEvent"); return h ? CloseHandle(h) : FALSE; }
BOOL WSAAPI ex_WSASetEvent(HANDLE h) { LogMessage("WSASetEvent"); return h ? SetEvent(h) : FALSE; }
BOOL WSAAPI ex_WSAResetEvent(HANDLE h) { LogMessage("WSAResetEvent"); return h ? ResetEvent(h) : FALSE; }
DWORD WSAAPI ex_WSAWaitForMultipleEvents(DWORD c, const HANDLE* h, BOOL f, DWORD d, BOOL a) { return WaitForMultipleObjectsEx(c, h, f, d, a); }
BOOL WSAAPI ex_WSAGetOverlappedResult(SOCKET s,LPWSAOVERLAPPED o,LPDWORD p,BOOL f,LPDWORD fl) { UNREFERENCED_PARAMETER(s);UNREFERENCED_PARAMETER(o);UNREFERENCED_PARAMETER(p);UNREFERENCED_PARAMETER(f);UNREFERENCED_PARAMETER(fl); g_tlsWSAError = WSAEOPNOTSUPP; return FALSE; }
int WSAAPI ex_WSAAsyncSelect(SOCKET s, HWND hWnd, u_int wMsg, long lEvent) { UNREFERENCED_PARAMETER(s);UNREFERENCED_PARAMETER(hWnd);UNREFERENCED_PARAMETER(wMsg);UNREFERENCED_PARAMETER(lEvent); return ex_StubFail_NotSupp(); }
int WSAAPI ex_WSAEventSelect(SOCKET s, HANDLE h, long l) { UNREFERENCED_PARAMETER(s);UNREFERENCED_PARAMETER(h);UNREFERENCED_PARAMETER(l); LogMessage("WSAEventSelect - STUB."); return 0; }
int WSAAPI ex_WSAEnumNetworkEvents(SOCKET s, HANDLE h, LPWSANETWORKEVENTS e) { UNREFERENCED_PARAMETER(s);UNREFERENCED_PARAMETER(h); if(e)memset(e,0,sizeof(WSANETWORKEVENTS)); return 0; }

// --- DllMain ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule); UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: DisableThreadLibraryCalls(hModule);
        #if ENABLE_MEMORY_TRACKING
        InitializeCriticalSection(&g_memory_lock);
        #endif
        break;
    case DLL_PROCESS_DETACH: CleanupEmulator();
        #if ENABLE_MEMORY_TRACKING
        DeleteCriticalSection(&g_memory_lock);
        #endif
        break;
    }
    return TRUE;
}