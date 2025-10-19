// dllmain.c - Повна, фінальна версія v16.0 (виправлені всі помилки)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#include <conio.h>
#else
#include <stdio.h>
#define _getch getchar
#endif

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")

// === НАЛАГОДЖУВАЛЬНІ КОНСТАНТИ ===
#define ENABLE_DEBUG_CONSOLE 0
#define ENABLE_FILE_LOGGING  0
#define ENABLE_DATA_DUMP     0
#define ENABLE_VERBOSE_LOG   0
#define ENABLE_MEMORY_TRACKING 1
#define VERBOSE_LOG_TIMEOUT  60000

#define DEFAULT_BUFFER_SIZE  65536
#define MAX_SOCKETS         1024
#define MAX_SELECT_HANDLES  64
#define EPHEMERAL_PORT_START 49152
#define EPHEMERAL_PORT_END   65535

// === ВИЗНАЧЕННЯ КОНСТАНТ ===
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0x40
#endif
#ifndef TCP_NODELAY
#define TCP_NODELAY 0x0001
#endif
#ifndef SO_EXCLUSIVEADDRUSE
#define SO_EXCLUSIVEADDRUSE ((int)(~SO_REUSEADDR))
#endif
#ifndef SO_LINGER
#define SO_LINGER 0x0080
#endif

#ifdef _MSC_VER
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL __thread
#endif

#ifdef _WIN64
#define PTR_FORMAT "%llX"
#define PTR_CAST(x) ((unsigned long long)(x))
#else
#define PTR_FORMAT "%lX"
#define PTR_CAST(x) ((unsigned long)(x))
#endif

// === ВЛАСНІ РЕАЛІЗАЦІЇ BYTE-ORDER ФУНКЦІЙ ===
static inline unsigned short my_htons(unsigned short hostshort) { return ((hostshort & 0xff) << 8) | ((hostshort & 0xff00) >> 8); }
static inline unsigned long my_htonl(unsigned long hostlong) { return ((hostlong & 0xff) << 24) | ((hostlong & 0xff00) << 8) | ((hostlong & 0xff0000) >> 8) | ((hostlong & 0xff000000) >> 24); }
static inline unsigned short my_ntohs(unsigned short netshort) { return my_htons(netshort); }
static inline unsigned long my_ntohl(unsigned long netlong) { return my_htonl(netlong); }
static inline unsigned long my_inet_addr(const char* cp) { if (!cp) return INADDR_NONE; unsigned int p[4]; if (sscanf_s(cp, "%u.%u.%u.%u", &p[0], &p[1], &p[2], &p[3]) != 4) return INADDR_NONE; if (p[0] > 255 || p[1] > 255 || p[2] > 255 || p[3] > 255) return INADDR_NONE; return (unsigned long)((p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0]); }

#define htons(x) my_htons(x)
#define htonl(x) my_htonl(x)
#define ntohs(x) my_ntohs(x)
#define ntohl(x) my_ntohl(x)
#define inet_addr(x) my_inet_addr(x)

// === ТИПИ ===
typedef enum { SIGNAL_NONE=0x00, SIGNAL_READY=0x01, SIGNAL_BUSY=0x02, SIGNAL_COMPLETE=0x03, SIGNAL_ERROR=0xFF } SIGNAL_BYTE;
typedef enum { SOCKET_TYPE_UNKNOWN=0, SOCKET_TYPE_SIGNAL, SOCKET_TYPE_CONTROL, SOCKET_TYPE_DATA, SOCKET_TYPE_SYNC } SOCKET_TYPE;
typedef struct _SOCKET_BEHAVIOR { DWORD short_messages; DWORD long_messages; DWORD single_byte_count; DWORD signal_byte_count; DWORD echo_requests; DWORD response_time_avg; BOOL bidirectional; BOOL request_response_pattern; SOCKET_TYPE detected_type; DWORD confidence; } SOCKET_BEHAVIOR;
typedef struct _ASYNC_SOCKET { SOCKET socket; SOCKET peer_socket; CRITICAL_SECTION cs_recv; CRITICAL_SECTION cs_send; char* recv_buffer; char* send_buffer; size_t recv_size; size_t send_size; size_t recv_len; size_t send_len; size_t recv_pos; size_t send_pos; HANDLE hReadEvent; HANDLE hWriteEvent; HANDLE hConnectEvent; HANDLE hAcceptEvent; HANDLE hCloseEvent; BOOL is_connected; BOOL was_connected; BOOL is_listening; BOOL is_nonblocking; BOOL is_async; BOOL is_closed; BOOL is_bound; BOOL allow_reuse_addr; BOOL exclusive_addr_use; BOOL tcp_nodelay; struct linger linger_opts; long network_events; HANDLE hEventSelect; HWND hAsyncSelectWnd; UINT uAsyncSelectMsg; long posted_async_events; struct _PENDING_IO* pending_recv; struct _PENDING_IO* pending_send; struct _PENDING_IO* pending_accept; HANDLE hCompletionPort; ULONG_PTR completion_key; struct sockaddr_in bind_addr; struct _ACCEPT_QUEUE* accept_queue; SOCKET_BEHAVIOR behavior; BOOL auto_detect_mode; DWORD first_data_tick; DWORD last_activity_tick; BOOL enable_auto_echo; DWORD echo_threshold; BOOL auto_echo; BYTE last_signal; DWORD signal_count; DWORD total_bytes_sent; DWORD total_bytes_recv; DWORD created_tick; DWORD created_thread; struct _ASYNC_SOCKET* next; } ASYNC_SOCKET;
typedef struct _PENDING_IO { SOCKET socket; LPWSAOVERLAPPED overlapped; LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine; LPWSABUF buffers; DWORD buffer_count; DWORD flags; DWORD bytes_transferred; DWORD error_code; BOOL is_complete; struct _PENDING_IO* next; } PENDING_IO;
typedef struct _ACCEPT_QUEUE { SOCKET client_socket; struct sockaddr_in client_addr; struct _ACCEPT_QUEUE* next; } ACCEPT_QUEUE;
typedef struct _PORT_BINDING { unsigned short port; ASYNC_SOCKET* listen_socket; struct _PORT_BINDING* next; } PORT_BINDING;
typedef struct _MEMORY_BLOCK { void* ptr; size_t size; char function[64]; DWORD thread_id; struct _MEMORY_BLOCK* next; } MEMORY_BLOCK;

// === ГЛОБАЛЬНІ ЗМІННІ ===
static CRITICAL_SECTION g_GlobalCS; static volatile BOOL g_IsInitialized = FALSE;
static ASYNC_SOCKET* g_AsyncSockets = NULL; static PENDING_IO* g_PendingOperations = NULL; static PORT_BINDING* g_PortBindings = NULL;
static HANDLE g_IoThread = NULL; static volatile BOOL g_IoThreadRunning = FALSE;
static volatile LONG g_WSAStartupCount = 0; static DWORD g_tlsWSAError = TLS_OUT_OF_INDEXES;
static volatile LONG g_NextSocketID = 1000; static volatile LONG g_EphemeralPort = EPHEMERAL_PORT_START;
static DWORD g_StartTickCount = 0;
#if ENABLE_FILE_LOGGING
static FILE* g_LogFile = NULL; static CRITICAL_SECTION g_LogCS;
#endif
#if ENABLE_DATA_DUMP
static FILE* g_DataFile = NULL; static CRITICAL_SECTION g_DataCS;
#endif
#if ENABLE_MEMORY_TRACKING
static MEMORY_BLOCK* g_memory_list = NULL; static CRITICAL_SECTION g_memory_lock;
static size_t g_total_allocated = 0; static size_t g_total_freed = 0; static size_t g_allocation_count = 0;
#endif

// === ПРОТОТИПИ ФУНКЦІЙ ===
static ASYNC_SOCKET* FindAsyncSocket(SOCKET s);
static void CompleteIoOperation(PENDING_IO* io, DWORD bytes_transferred, DWORD error);
int WSAAPI ex_connect(SOCKET s, const struct sockaddr* name, int namelen);
SOCKET WSAAPI ex_accept(SOCKET s, struct sockaddr* addr, int* addrlen);

// === ФУНКЦІЇ УПРАВЛІННЯ ПАМ'ЯТТЮ ===
#if ENABLE_MEMORY_TRACKING
void* TrackedAlloc(size_t size, const char* function) { if (size == 0) return NULL; void* ptr = malloc(size); if (!ptr) { return NULL; } memset(ptr, 0, size); EnterCriticalSection(&g_memory_lock); MEMORY_BLOCK* block = (MEMORY_BLOCK*)malloc(sizeof(MEMORY_BLOCK)); if (block) { block->ptr = ptr; block->size = size; strncpy_s(block->function, sizeof(block->function), function, _TRUNCATE); block->thread_id = GetCurrentThreadId(); block->next = g_memory_list; g_memory_list = block; g_total_allocated += size; g_allocation_count++; } LeaveCriticalSection(&g_memory_lock); return ptr; }
BOOL TrackedFree(void* ptr, const char* function) { if (!ptr) return TRUE; BOOL found = FALSE; EnterCriticalSection(&g_memory_lock); MEMORY_BLOCK** current = &g_memory_list; while (*current) { if ((*current)->ptr == ptr) { MEMORY_BLOCK* block = *current; *current = block->next; g_total_freed += block->size; g_allocation_count--; free(block); found = TRUE; break; } current = &(*current)->next; } LeaveCriticalSection(&g_memory_lock); free(ptr); return TRUE; }
void ReportMemoryLeaks() { EnterCriticalSection(&g_memory_lock); if (g_memory_list) { printf("[MEM] === MEMORY LEAKS DETECTED ===\n"); printf("[MEM] Total leaked: %zu bytes in %zu allocations\n", g_total_allocated - g_total_freed, g_allocation_count); MEMORY_BLOCK* current = g_memory_list; while (current) { printf("[MEM]   Leak: %zu bytes from %s (TID:%lu) at %p\n", current->size, current->function, current->thread_id, current->ptr); current = current->next; } } else { printf("[MEM] No memory leaks detected.\n"); } LeaveCriticalSection(&g_memory_lock); }
#define SAFE_ALLOC(size) TrackedAlloc(size, __FUNCTION__)
#define SAFE_FREE(ptr) TrackedFree(ptr, __FUNCTION__)
#else
#define SAFE_ALLOC(size) calloc(1, size)
#define SAFE_FREE(ptr) free(ptr)
#define ReportMemoryLeaks()
#endif

// === ДОПОМІЖНІ ФУНКЦІЇ ===
static void LogMessage(const char* format, ...) {
#if ENABLE_DEBUG_CONSOLE || ENABLE_FILE_LOGGING
    char buffer[2048]; va_list args; va_start(args, format); vsnprintf(buffer, sizeof(buffer), format, args); va_end(args);
    #if ENABLE_DEBUG_CONSOLE
    printf("[WS2_32] %s\n", buffer); fflush(stdout);
    #endif
    #if ENABLE_FILE_LOGGING
    EnterCriticalSection(&g_LogCS); if (g_LogFile) { SYSTEMTIME st; GetLocalTime(&st); fprintf(g_LogFile, "[%02d:%02d:%02d.%03d][TID:%08lX] %s\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, (unsigned long)GetCurrentThreadId(), buffer); fflush(g_LogFile); } LeaveCriticalSection(&g_LogCS);
    #endif
#endif
}
static void LogVerbose(const char* format, ...) {
#if ENABLE_VERBOSE_LOG
    if (g_StartTickCount && (GetTickCount() - g_StartTickCount) > VERBOSE_LOG_TIMEOUT) return;
    char buffer[2048]; va_list args; va_start(args, format); vsnprintf(buffer, sizeof(buffer), format, args); va_end(args); LogMessage("[VERBOSE] %s", buffer);
#endif
}
static void DumpDataToFile(const char* prefix, SOCKET s, const void* data, int len) {
#if ENABLE_DATA_DUMP
    if (!data || len <= 0) return; EnterCriticalSection(&g_DataCS); if (!g_DataFile) { char path[MAX_PATH]; GetTempPathA(MAX_PATH, path); strcat_s(path, MAX_PATH, "ws2_32_data.bin"); fopen_s(&g_DataFile, path, "wb"); }
    if (g_DataFile) { SYSTEMTIME st; GetLocalTime(&st); fprintf(g_DataFile, "\n[%02d:%02d:%02d.%03d] %s Socket=" PTR_FORMAT " (%d bytes)\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, prefix, PTR_CAST(s), len);
    for (int i = 0; i < len; i++) { if (i % 16 == 0) fprintf(g_DataFile, "%04X: ", i); fprintf(g_DataFile, "%02X ", ((unsigned char*)data)[i]); if (i % 16 == 15 || i == len - 1) { fprintf(g_DataFile, " |"); int start = (i / 16) * 16; for (int j = start; j <= i; j++) { char c = ((char*)data)[j]; fprintf(g_DataFile, "%c", (c >= 32 && c <= 126) ? c : '.'); } fprintf(g_DataFile, "|\n"); } } fflush(g_DataFile); }
    LeaveCriticalSection(&g_DataCS);
#endif
}
static void SetWSAError(int error) { if (g_tlsWSAError != TLS_OUT_OF_INDEXES) TlsSetValue(g_tlsWSAError, (LPVOID)(LONG_PTR)error); }
static int GetWSAError(void) { if (g_tlsWSAError != TLS_OUT_OF_INDEXES) return (int)(LONG_PTR)TlsGetValue(g_tlsWSAError); return WSAEINVAL; }
static SOCKET GenerateFakeSocket(void) { LONG id = InterlockedIncrement(&g_NextSocketID); DWORD tid = GetCurrentThreadId(); return (SOCKET)(UINT_PTR)((id << 16) | (tid & 0xFFFF)); }
static unsigned short GetEphemeralPort(void) { LONG port = InterlockedIncrement(&g_EphemeralPort); if (port > EPHEMERAL_PORT_END) { InterlockedExchange(&g_EphemeralPort, EPHEMERAL_PORT_START); port = EPHEMERAL_PORT_START; } return (unsigned short)port; }
static const char* GetSocketTypeName(SOCKET_TYPE type) { switch (type) { case SOCKET_TYPE_SIGNAL: return "SIGNAL"; case SOCKET_TYPE_CONTROL: return "CONTROL"; case SOCKET_TYPE_DATA: return "DATA"; case SOCKET_TYPE_SYNC: return "SYNC"; default: return "UNKNOWN"; } }

// === ДЕТЕКЦІЯ ТА АНАЛІЗ ===
static void DetermineSocketType(ASYNC_SOCKET* sock) { SOCKET_BEHAVIOR* behavior = &sock->behavior; DWORD total_messages = behavior->short_messages + behavior->long_messages + behavior->single_byte_count; if (total_messages < 3) { behavior->detected_type = SOCKET_TYPE_UNKNOWN; behavior->confidence = 0; return; } if (behavior->single_byte_count > total_messages * 0.7 && behavior->signal_byte_count > behavior->single_byte_count * 0.5) { behavior->detected_type = SOCKET_TYPE_SIGNAL; behavior->confidence = min(100, 85 + behavior->signal_byte_count); if (sock->enable_auto_echo && behavior->signal_byte_count >= sock->echo_threshold) { sock->auto_echo = TRUE; LogMessage("🔔 Socket " PTR_FORMAT ": AUTO-ECHO ENABLED", PTR_CAST(sock->socket)); } LogMessage("✅ Socket " PTR_FORMAT " detected as SIGNAL (confidence: %lu%%)", PTR_CAST(sock->socket), behavior->confidence); return; } if (behavior->request_response_pattern && behavior->bidirectional && behavior->short_messages > total_messages * 0.5) { behavior->detected_type = SOCKET_TYPE_CONTROL; behavior->confidence = min(100, 75 + behavior->echo_requests); LogMessage("✅ Socket " PTR_FORMAT " detected as CONTROL (confidence: %lu%%)", PTR_CAST(sock->socket), behavior->confidence); return; } DWORD time_span = sock->last_activity_tick - sock->first_data_tick; if (time_span > 1000 && total_messages < 20 && behavior->short_messages > total_messages * 0.8) { behavior->detected_type = SOCKET_TYPE_SYNC; behavior->confidence = 70; LogMessage("✅ Socket " PTR_FORMAT " detected as SYNC (confidence: %lu%%)", PTR_CAST(sock->socket), behavior->confidence); return; } if (behavior->long_messages > total_messages * 0.5) { behavior->detected_type = SOCKET_TYPE_DATA; behavior->confidence = 80; LogMessage("✅ Socket " PTR_FORMAT " detected as DATA (confidence: %lu%%)", PTR_CAST(sock->socket), behavior->confidence); return; } behavior->detected_type = SOCKET_TYPE_UNKNOWN; behavior->confidence = 30; }
static void AnalyzeSocketBehavior(ASYNC_SOCKET* sock, const void* data, int len, BOOL is_send) { if (!sock || !data || len <= 0) return; SOCKET_BEHAVIOR* behavior = &sock->behavior; DWORD now = GetTickCount(); if (sock->first_data_tick == 0) sock->first_data_tick = now; sock->last_activity_tick = now; if (len == 1) { behavior->single_byte_count++; BYTE byte = *(BYTE*)data; if (byte <= 0x03 || byte == 0xFF) { behavior->signal_byte_count++; LogVerbose("Detected signal byte 0x%02X", byte); } } else if (len < 10) behavior->short_messages++; else if (len > 100) behavior->long_messages++; if (is_send && sock->peer_socket != INVALID_SOCKET) { ASYNC_SOCKET* peer = FindAsyncSocket(sock->peer_socket); if (peer && peer->behavior.single_byte_count > 0) { behavior->request_response_pattern = TRUE; behavior->echo_requests++; } } if (sock->total_bytes_sent > 0 && sock->total_bytes_recv > 0) behavior->bidirectional = TRUE; DetermineSocketType(sock); }
static BYTE GenerateSmartResponse(BYTE signal) { switch (signal) { case 0x00: return 0x01; case 0x01: return 0x01; case 0x02: return 0x01; case 0x03: return 0x01; case 0xFF: return 0x01; default: return signal; } }
static void ProcessSmartSignalByte(ASYNC_SOCKET* sock, BYTE signal) { sock->last_signal = signal; sock->signal_count++; LogVerbose("Socket " PTR_FORMAT " received signal 0x%02X (count: %lu)", PTR_CAST(sock->socket), signal, sock->signal_count); if (sock->behavior.detected_type == SOCKET_TYPE_SIGNAL && sock->auto_echo && sock->peer_socket != INVALID_SOCKET) { ASYNC_SOCKET* peer = FindAsyncSocket(sock->peer_socket); if (peer) { BYTE response = GenerateSmartResponse(signal); EnterCriticalSection(&peer->cs_recv); if (peer->recv_size > peer->recv_len) { peer->recv_buffer[peer->recv_len++] = response; SetEvent(peer->hReadEvent); LogVerbose("🔁 Auto-echo: 0x%02X -> 0x%02X", signal, response); } LeaveCriticalSection(&peer->cs_recv); } } }

// === РОБОТА З ASYNC_SOCKET ===
static ASYNC_SOCKET* FindAsyncSocket(SOCKET s) { ASYNC_SOCKET* result = NULL; EnterCriticalSection(&g_GlobalCS); ASYNC_SOCKET* sock = g_AsyncSockets; while (sock) { if (sock->socket == s && !sock->is_closed) { result = sock; break; } sock = sock->next; } LeaveCriticalSection(&g_GlobalCS); return result; }
static ASYNC_SOCKET* CreateAsyncSocket(SOCKET s) { ASYNC_SOCKET* async_sock = (ASYNC_SOCKET*)SAFE_ALLOC(sizeof(ASYNC_SOCKET)); if (!async_sock) return NULL; async_sock->socket = s; async_sock->peer_socket = INVALID_SOCKET; async_sock->created_tick = GetTickCount(); async_sock->created_thread = GetCurrentThreadId(); async_sock->recv_size = DEFAULT_BUFFER_SIZE; async_sock->send_size = DEFAULT_BUFFER_SIZE; async_sock->recv_buffer = (char*)SAFE_ALLOC(async_sock->recv_size); async_sock->send_buffer = (char*)SAFE_ALLOC(async_sock->send_size); InitializeCriticalSection(&async_sock->cs_recv); InitializeCriticalSection(&async_sock->cs_send); async_sock->hReadEvent = CreateEvent(NULL, TRUE, FALSE, NULL); async_sock->hWriteEvent = CreateEvent(NULL, TRUE, TRUE, NULL); async_sock->hConnectEvent = CreateEvent(NULL, TRUE, FALSE, NULL); async_sock->hAcceptEvent = CreateEvent(NULL, TRUE, FALSE, NULL); async_sock->hCloseEvent = CreateEvent(NULL, TRUE, FALSE, NULL); async_sock->auto_detect_mode = TRUE; async_sock->enable_auto_echo = TRUE; async_sock->echo_threshold = 3; EnterCriticalSection(&g_GlobalCS); async_sock->next = g_AsyncSockets; g_AsyncSockets = async_sock; LeaveCriticalSection(&g_GlobalCS); LogMessage("Created socket " PTR_FORMAT " (TID:%08lX)", PTR_CAST(s), async_sock->created_thread); return async_sock; }
static ASYNC_SOCKET* FindOrCreateAsyncSocket(SOCKET s) { ASYNC_SOCKET* sock = FindAsyncSocket(s); if (!sock) sock = CreateAsyncSocket(s); return sock; }
static void FreeAsyncSocket(ASYNC_SOCKET* async_sock) { if (!async_sock) return; LogVerbose("Freeing socket " PTR_FORMAT, PTR_CAST(async_sock->socket)); EnterCriticalSection(&g_GlobalCS); ASYNC_SOCKET** pp = &g_AsyncSockets; while (*pp) { if (*pp == async_sock) { *pp = async_sock->next; break; } pp = &(*pp)->next; } LeaveCriticalSection(&g_GlobalCS); SAFE_FREE(async_sock->recv_buffer); SAFE_FREE(async_sock->send_buffer); DeleteCriticalSection(&async_sock->cs_recv); DeleteCriticalSection(&async_sock->cs_send); CloseHandle(async_sock->hReadEvent); CloseHandle(async_sock->hWriteEvent); CloseHandle(async_sock->hConnectEvent); CloseHandle(async_sock->hAcceptEvent); CloseHandle(async_sock->hCloseEvent); while (async_sock->accept_queue) { ACCEPT_QUEUE* q = async_sock->accept_queue; async_sock->accept_queue = q->next; SAFE_FREE(q); } SAFE_FREE(async_sock); }
static void CompleteIoOperation(PENDING_IO* io, DWORD bytes_transferred, DWORD error) { if (!io) return; io->bytes_transferred = bytes_transferred; io->error_code = error; io->is_complete = TRUE; LogVerbose("Completing IO op: %lu bytes, err=%lu", bytes_transferred, error); if (io->overlapped) { io->overlapped->Internal = (ULONG_PTR)error; io->overlapped->InternalHigh = (ULONG_PTR)bytes_transferred; if (io->overlapped->hEvent) SetEvent(io->overlapped->hEvent); } ASYNC_SOCKET* sock = FindAsyncSocket(io->socket); if (sock && sock->hCompletionPort) PostQueuedCompletionStatus(sock->hCompletionPort, bytes_transferred, sock->completion_key, io->overlapped); if (io->completion_routine) io->completion_routine(error, bytes_transferred, io->overlapped, 0); }
static void DumpSocketStatistics(void) { LogMessage("\n=== SOCKET STATISTICS WITH BEHAVIOR ANALYSIS ==="); DWORD total_sockets = 0, signal_sockets = 0, control_sockets = 0, data_sockets = 0, sync_sockets = 0, unknown_sockets = 0; DWORD total_bytes_sent = 0, total_bytes_recv = 0; EnterCriticalSection(&g_GlobalCS); ASYNC_SOCKET* sock = g_AsyncSockets; while (sock) { total_sockets++; total_bytes_sent += sock->total_bytes_sent; total_bytes_recv += sock->total_bytes_recv; switch (sock->behavior.detected_type) { case SOCKET_TYPE_SIGNAL: signal_sockets++; break; case SOCKET_TYPE_CONTROL: control_sockets++; break; case SOCKET_TYPE_DATA: data_sockets++; break; case SOCKET_TYPE_SYNC: sync_sockets++; break; default: unknown_sockets++; } if (sock->behavior.detected_type != SOCKET_TYPE_UNKNOWN) LogMessage("  Socket " PTR_FORMAT ": Type=%s, Conf=%lu%%, Signals=%lu, Echo=%s, Sent=%lu, Recv=%lu", PTR_CAST(sock->socket), GetSocketTypeName(sock->behavior.detected_type), sock->behavior.confidence, sock->behavior.signal_byte_count, sock->auto_echo ? "ON" : "OFF", sock->total_bytes_sent, sock->total_bytes_recv); sock = sock->next; } LeaveCriticalSection(&g_GlobalCS); LogMessage("\nTotal sockets: %lu (S:%lu C:%lu D:%lu Y:%lu U:%lu)", total_sockets, signal_sockets, control_sockets, data_sockets, sync_sockets, unknown_sockets); LogMessage("Total bytes sent: %lu, received: %lu", total_bytes_sent, total_bytes_recv); }

// === РОБОЧИЙ ПОТІК ===
static DWORD WINAPI AsyncIoWorkerThread(LPVOID param) { LogMessage("Async I/O worker thread started"); while (g_IoThreadRunning) { BOOL work_done = FALSE; EnterCriticalSection(&g_GlobalCS); PENDING_IO** p_io = &g_PendingOperations; while (*p_io) { PENDING_IO* io = *p_io; ASYNC_SOCKET* sock = FindAsyncSocket(io->socket); if (!sock || io->is_complete) { *p_io = io->next; SAFE_FREE(io); work_done = TRUE; continue; } if (io == sock->pending_recv) { DWORD bytes_read = 0; BOOL should_complete = FALSE; EnterCriticalSection(&sock->cs_recv); if (sock->recv_len > 0) { should_complete = TRUE; for (DWORD i = 0; i < io->buffer_count; i++) { size_t to_copy = min(io->buffers[i].len, sock->recv_len - sock->recv_pos); if(to_copy == 0) break; memcpy(io->buffers[i].buf, sock->recv_buffer + sock->recv_pos, to_copy); bytes_read += (DWORD)to_copy; sock->recv_pos += to_copy; } if (sock->recv_pos >= sock->recv_len) { sock->recv_len = 0; sock->recv_pos = 0; ResetEvent(sock->hReadEvent); } } else if (sock->is_closed) { should_complete = TRUE; } LeaveCriticalSection(&sock->cs_recv); if (should_complete) { sock->pending_recv = NULL; CompleteIoOperation(io, bytes_read, 0); work_done = TRUE; } } else if (io == sock->pending_send) { sock->pending_send = NULL; CompleteIoOperation(io, io->bytes_transferred, 0); work_done = TRUE; } p_io = &(*p_io)->next; } ASYNC_SOCKET* sock_sender = g_AsyncSockets; while (sock_sender) { if (sock_sender->is_connected && sock_sender->send_len > 0) { ASYNC_SOCKET* sock_receiver = FindAsyncSocket(sock_sender->peer_socket); if (sock_receiver) { EnterCriticalSection(&sock_sender->cs_send); EnterCriticalSection(&sock_receiver->cs_recv); size_t space_in_recv = sock_receiver->recv_size - sock_receiver->recv_len; size_t data_in_send = sock_sender->send_len - sock_sender->send_pos; size_t to_move = min(space_in_recv, data_in_send); if (to_move > 0) { memcpy(sock_receiver->recv_buffer + sock_receiver->recv_len, sock_sender->send_buffer + sock_sender->send_pos, to_move); sock_sender->send_pos += to_move; sock_receiver->recv_len += to_move; if (sock_sender->send_pos >= sock_sender->send_len) { sock_sender->send_len = 0; sock_sender->send_pos = 0; SetEvent(sock_sender->hWriteEvent); } SetEvent(sock_receiver->hReadEvent); work_done = TRUE; } LeaveCriticalSection(&sock_receiver->cs_recv); LeaveCriticalSection(&sock_sender->cs_send); } } sock_sender = sock_sender->next; } ASYNC_SOCKET* sock = g_AsyncSockets; while (sock) { long current_events = 0; if (sock->is_listening && sock->accept_queue) current_events |= FD_ACCEPT; if (sock->recv_len > 0) current_events |= FD_READ; if (sock->is_connected) current_events |= FD_WRITE; if (sock->is_closed) current_events |= FD_CLOSE; if (sock->hEventSelect && (current_events & sock->network_events)) { SetEvent(sock->hEventSelect); work_done = TRUE; } if (sock->hAsyncSelectWnd) { long events_to_post = current_events & sock->network_events; if (events_to_post) { long new_events = events_to_post & ~sock->posted_async_events; if (new_events) { PostMessage(sock->hAsyncSelectWnd, sock->uAsyncSelectMsg, (WPARAM)sock->socket, MAKELPARAM(new_events, 0)); sock->posted_async_events |= new_events; work_done = TRUE; } } else { sock->posted_async_events = 0; } } sock = sock->next; } LeaveCriticalSection(&g_GlobalCS); if (!work_done) Sleep(10); } LogMessage("Async I/O worker thread stopped"); return 0; }

// === WSA STARTUP/CLEANUP ===
int WSAAPI ex_WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData) {
    if (!g_IsInitialized) {
        InitializeCriticalSection(&g_GlobalCS);
        #if ENABLE_MEMORY_TRACKING
        InitializeCriticalSection(&g_memory_lock);
        #endif
        g_tlsWSAError = TlsAlloc(); g_StartTickCount = GetTickCount();
        #if ENABLE_FILE_LOGGING
        InitializeCriticalSection(&g_LogCS);
        #endif
        #if ENABLE_DATA_DUMP
        InitializeCriticalSection(&g_DataCS);
        #endif
        #if ENABLE_DEBUG_CONSOLE
        if (AllocConsole()) { FILE* fDummy; freopen_s(&fDummy, "CONOUT$", "w", stdout); freopen_s(&fDummy, "CONOUT$", "w", stderr); freopen_s(&fDummy, "CONIN$", "r", stdin); SetConsoleTitleA("WS2_32 Emulator v16.0"); printf("============================================\nWS2_32 Network Emulator v16.0\n============================================\n\n"); }
        #endif
        LogMessage("Process: %s", GetCommandLineA()); LogMessage("PID: %lu", GetCurrentProcessId());
        g_IsInitialized = TRUE;
    }
    LogMessage("WSAStartup called. Version: %d.%d, Count: %ld", HIBYTE(wVersionRequested), LOBYTE(wVersionRequested), g_WSAStartupCount);
    if (lpWSAData) { memset(lpWSAData, 0, sizeof(WSADATA)); lpWSAData->wVersion = MAKEWORD(2, 2); lpWSAData->wHighVersion = MAKEWORD(2, 2); lpWSAData->iMaxSockets = MAX_SOCKETS; lpWSAData->iMaxUdpDg = 65507; strcpy_s(lpWSAData->szDescription, sizeof(lpWSAData->szDescription), "WinSock 2.0 Emulator"); strcpy_s(lpWSAData->szSystemStatus, sizeof(lpWSAData->szSystemStatus), "Running"); }
    if (InterlockedIncrement(&g_WSAStartupCount) == 1) { EnterCriticalSection(&g_GlobalCS); if (!g_IoThread) { g_IoThreadRunning = TRUE; g_IoThread = CreateThread(NULL, 0, AsyncIoWorkerThread, NULL, 0, NULL); LogMessage("Started IO worker thread"); } LeaveCriticalSection(&g_GlobalCS); }
    SetWSAError(0); return 0;
}
int WSAAPI ex_WSACleanup(void) {
    if (!g_IsInitialized) return 0;
    LogMessage("WSACleanup called. Count: %ld", g_WSAStartupCount);
    if (InterlockedDecrement(&g_WSAStartupCount) <= 0) {
        g_WSAStartupCount = 0; LogMessage("=== WS2_32 Emulator v16.0 Shutting Down ==="); DumpSocketStatistics();
        if (g_IoThread) { g_IoThreadRunning = FALSE; WaitForSingleObject(g_IoThread, 5000); CloseHandle(g_IoThread); g_IoThread = NULL; LogMessage("Stopped IO worker thread"); }
        while (g_AsyncSockets) FreeAsyncSocket(g_AsyncSockets);
        while (g_PendingOperations) { PENDING_IO* io = g_PendingOperations; g_PendingOperations = io->next; SAFE_FREE(io); }
        while (g_PortBindings) { PORT_BINDING* pb = g_PortBindings; g_PortBindings = pb->next; SAFE_FREE(pb); }
        #if ENABLE_MEMORY_TRACKING
        ReportMemoryLeaks();
        #endif
        if (g_tlsWSAError != TLS_OUT_OF_INDEXES) { TlsFree(g_tlsWSAError); g_tlsWSAError = TLS_OUT_OF_INDEXES; }
        #if ENABLE_FILE_LOGGING
        if (g_LogFile) { fclose(g_LogFile); g_LogFile = NULL; } DeleteCriticalSection(&g_LogCS);
        #endif
        #if ENABLE_DATA_DUMP
        if (g_DataFile) { fclose(g_DataFile); g_DataFile = NULL; } DeleteCriticalSection(&g_DataCS);
        #endif
        #if ENABLE_MEMORY_TRACKING
        DeleteCriticalSection(&g_memory_lock);
        #endif
        // Не видаляємо g_GlobalCS тут, бо DllMain це зробить
        #if ENABLE_DEBUG_CONSOLE
        printf("\n=== Emulator Unloaded ===\nPress any key to close console...\n"); _getch(); FreeConsole();
        #endif
        g_IsInitialized = FALSE;
    }
    SetWSAError(0); return 0;
}

// === ОСНОВНІ ФУНКЦІЇ ===
SOCKET WSAAPI ex_socket(int af, int type, int protocol) { SOCKET s = GenerateFakeSocket(); CreateAsyncSocket(s); LogMessage("socket(af=%d, type=%d, proto=%d) -> " PTR_FORMAT, af, type, protocol, PTR_CAST(s)); SetWSAError(0); return s; }
SOCKET WSAAPI ex_WSASocketA(int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags) { SOCKET s = GenerateFakeSocket(); ASYNC_SOCKET* async_sock = CreateAsyncSocket(s); if (dwFlags & WSA_FLAG_OVERLAPPED) async_sock->is_async = TRUE; LogMessage("WSASocketA(af=%d, type=%d, proto=%d, flags=0x%lx) -> " PTR_FORMAT, af, type, protocol, dwFlags, PTR_CAST(s)); SetWSAError(0); return s; }
SOCKET WSAAPI ex_WSASocketW(int af, int type, int protocol, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags) { return ex_WSASocketA(af, type, protocol, (LPWSAPROTOCOL_INFOA)lpProtocolInfo, g, dwFlags); }
int WSAAPI ex_bind(SOCKET s, const struct sockaddr* addr, int namelen) { ASYNC_SOCKET* async_sock = FindOrCreateAsyncSocket(s); if (!async_sock) { SetWSAError(WSAENOTSOCK); return SOCKET_ERROR; } if (addr && namelen >= sizeof(struct sockaddr_in)) { struct sockaddr_in* sin = (struct sockaddr_in*)addr; unsigned short port = ntohs(sin->sin_port); if (port == 0) { port = GetEphemeralPort(); sin->sin_port = htons(port); } EnterCriticalSection(&g_GlobalCS); PORT_BINDING* pb = g_PortBindings; while (pb) { if (pb->port == port && !async_sock->allow_reuse_addr) { LeaveCriticalSection(&g_GlobalCS); LogMessage("bind(" PTR_FORMAT ") to port %u -> WSAEADDRINUSE", PTR_CAST(s), port); SetWSAError(WSAEADDRINUSE); return SOCKET_ERROR; } pb = pb->next; } pb = (PORT_BINDING*)SAFE_ALLOC(sizeof(PORT_BINDING)); pb->port = port; pb->listen_socket = async_sock; pb->next = g_PortBindings; g_PortBindings = pb; LeaveCriticalSection(&g_GlobalCS); memcpy(&async_sock->bind_addr, addr, sizeof(struct sockaddr_in)); async_sock->is_bound = TRUE; LogMessage("bind(" PTR_FORMAT ") to 127.0.0.1:%u -> OK", PTR_CAST(s), port); } SetWSAError(0); return 0; }
int WSAAPI ex_listen(SOCKET s, int backlog) { ASYNC_SOCKET* async_sock = FindAsyncSocket(s); if (!async_sock) { SetWSAError(WSAENOTSOCK); return SOCKET_ERROR; } async_sock->is_listening = TRUE; LogMessage("listen(" PTR_FORMAT ", backlog=%d) -> OK", PTR_CAST(s), backlog); SetWSAError(0); return 0; }
SOCKET WSAAPI ex_accept(SOCKET s, struct sockaddr* addr, int* addrlen) { ASYNC_SOCKET* async_sock = FindAsyncSocket(s); if (!async_sock || !async_sock->is_listening) { SetWSAError(WSAEINVAL); return INVALID_SOCKET; } EnterCriticalSection(&g_GlobalCS); if (async_sock->accept_queue) { ACCEPT_QUEUE* q = async_sock->accept_queue; async_sock->accept_queue = q->next; LeaveCriticalSection(&g_GlobalCS); SOCKET client_socket = q->client_socket; if (addr && addrlen && *addrlen >= sizeof(struct sockaddr_in)) { memcpy(addr, &q->client_addr, sizeof(struct sockaddr_in)); *addrlen = sizeof(struct sockaddr_in); } SAFE_FREE(q); if (!async_sock->accept_queue) ResetEvent(async_sock->hAcceptEvent); async_sock->posted_async_events &= ~FD_ACCEPT; LogMessage("accept(" PTR_FORMAT ") -> client " PTR_FORMAT, PTR_CAST(s), PTR_CAST(client_socket)); SetWSAError(0); return client_socket; } LeaveCriticalSection(&g_GlobalCS); if (async_sock->is_nonblocking) { SetWSAError(WSAEWOULDBLOCK); return INVALID_SOCKET; } LogVerbose("accept(" PTR_FORMAT ") -> waiting...", PTR_CAST(s)); WaitForSingleObject(async_sock->hAcceptEvent, INFINITE); return ex_accept(s, addr, addrlen); }
int WSAAPI ex_connect(SOCKET s, const struct sockaddr* name, int namelen) { ASYNC_SOCKET* async_sock = FindOrCreateAsyncSocket(s); if (!async_sock) { SetWSAError(WSAENOTSOCK); return SOCKET_ERROR; } if (async_sock->is_closed) { SetWSAError(WSAECONNRESET); return SOCKET_ERROR; } if (!async_sock->is_bound) { unsigned short port = GetEphemeralPort(); async_sock->bind_addr.sin_family = AF_INET; async_sock->bind_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); async_sock->bind_addr.sin_port = htons(port); async_sock->is_bound = TRUE; } if (name && namelen >= sizeof(struct sockaddr_in)) { const struct sockaddr_in* addr = (const struct sockaddr_in*)name; if (addr->sin_family == AF_INET) { unsigned long ip = ntohl(addr->sin_addr.s_addr); if ((ip >> 24) == 127) { unsigned short port = ntohs(addr->sin_port); EnterCriticalSection(&g_GlobalCS); ASYNC_SOCKET* listen_sock = g_AsyncSockets; while (listen_sock) { if (listen_sock->is_listening && listen_sock->is_bound && ntohs(listen_sock->bind_addr.sin_port) == port) { SOCKET accepted = GenerateFakeSocket(); ASYNC_SOCKET* accepted_sock = CreateAsyncSocket(accepted); async_sock->peer_socket = accepted; async_sock->is_connected = TRUE; accepted_sock->peer_socket = s; accepted_sock->is_connected = TRUE; ACCEPT_QUEUE* q = (ACCEPT_QUEUE*)SAFE_ALLOC(sizeof(ACCEPT_QUEUE)); q->client_socket = accepted; memcpy(&q->client_addr, &async_sock->bind_addr, sizeof(struct sockaddr_in)); q->next = listen_sock->accept_queue; listen_sock->accept_queue = q; SetEvent(listen_sock->hAcceptEvent); SetEvent(async_sock->hConnectEvent); if (async_sock->hAsyncSelectWnd && (async_sock->network_events & FD_CONNECT)) PostMessage(async_sock->hAsyncSelectWnd, async_sock->uAsyncSelectMsg, s, FD_CONNECT); LeaveCriticalSection(&g_GlobalCS); LogMessage("connect(" PTR_FORMAT ") to 127.0.0.1:%u -> OK (accepted as " PTR_FORMAT ")", PTR_CAST(s), port, PTR_CAST(accepted)); SetWSAError(0); return 0; } listen_sock = listen_sock->next; } LeaveCriticalSection(&g_GlobalCS); LogMessage("connect(" PTR_FORMAT ") to 127.0.0.1:%u -> REFUSED", PTR_CAST(s), port); SetWSAError(WSAECONNREFUSED); return SOCKET_ERROR; } } } LogMessage("connect(" PTR_FORMAT ") -> BLOCKED", PTR_CAST(s)); SetWSAError(WSAENETUNREACH); return SOCKET_ERROR; }
int WSAAPI ex_send(SOCKET s, const char* buf, int len, int flags) { ASYNC_SOCKET* sock = FindAsyncSocket(s); if (!sock) { SetWSAError(WSAENOTSOCK); return SOCKET_ERROR; } if (sock->is_closed) { SetWSAError(WSAECONNRESET); return SOCKET_ERROR; } if (!sock->is_connected) { SetWSAError(WSAENOTCONN); return SOCKET_ERROR; } DumpDataToFile("SEND", s, buf, len); if (sock->auto_detect_mode) AnalyzeSocketBehavior(sock, buf, len, TRUE); EnterCriticalSection(&sock->cs_send); size_t space = sock->send_size - sock->send_len; if (space == 0) { LeaveCriticalSection(&sock->cs_send); if (sock->is_nonblocking) { SetWSAError(WSAEWOULDBLOCK); return SOCKET_ERROR; } LogVerbose("send(" PTR_FORMAT ") waiting for buffer space...", PTR_CAST(s)); WaitForSingleObject(sock->hWriteEvent, INFINITE); return ex_send(s, buf, len, flags); } size_t to_send = min((size_t)len, space); memcpy(sock->send_buffer + sock->send_len, buf, to_send); sock->send_len += to_send; sock->total_bytes_sent += (DWORD)to_send; if (sock->send_len >= sock->send_size) ResetEvent(sock->hWriteEvent); LeaveCriticalSection(&sock->cs_send); if (sock->behavior.detected_type == SOCKET_TYPE_SIGNAL && sock->auto_echo && sock->peer_socket != INVALID_SOCKET && len == 1) { ASYNC_SOCKET* peer = FindAsyncSocket(sock->peer_socket); if (peer) ProcessSmartSignalByte(peer, (BYTE)buf[0]); } LogVerbose("send(" PTR_FORMAT ") -> sent %zu bytes [Type: %s]", PTR_CAST(s), to_send, GetSocketTypeName(sock->behavior.detected_type)); SetWSAError(0); return (int)to_send; }
int WSAAPI ex_recv(SOCKET s, char* buf, int len, int flags) { ASYNC_SOCKET* sock = FindAsyncSocket(s); if (!sock) { SetWSAError(WSAENOTSOCK); return SOCKET_ERROR; } if (sock->is_closed) return 0; if (!sock->is_connected) { SetWSAError(WSAENOTCONN); return SOCKET_ERROR; } EnterCriticalSection(&sock->cs_recv); if (sock->recv_len == 0) { LeaveCriticalSection(&sock->cs_recv); if (sock->is_closed) return 0; if (sock->is_nonblocking) { SetWSAError(WSAEWOULDBLOCK); return SOCKET_ERROR; } LogVerbose("recv(" PTR_FORMAT ") waiting for data...", PTR_CAST(s)); WaitForSingleObject(sock->hReadEvent, INFINITE); return ex_recv(s, buf, len, flags); } size_t to_recv = min((size_t)len, sock->recv_len - sock->recv_pos); memcpy(buf, sock->recv_buffer + sock->recv_pos, to_recv); if (!(flags & MSG_PEEK)) { sock->recv_pos += to_recv; sock->total_bytes_recv += (DWORD)to_recv; if (sock->recv_pos >= sock->recv_len) { sock->recv_len = 0; sock->recv_pos = 0; ResetEvent(sock->hReadEvent); } } LeaveCriticalSection(&sock->cs_recv); sock->posted_async_events &= ~FD_READ; DumpDataToFile("RECV", s, buf, (int)to_recv); if (sock->auto_detect_mode) AnalyzeSocketBehavior(sock, buf, (int)to_recv, FALSE); LogVerbose("recv(" PTR_FORMAT ") -> received %zu bytes", PTR_CAST(s), to_recv); SetWSAError(0); return (int)to_recv; }
int WSAAPI ex_select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout) { DWORD timeout_ms = timeout ? (timeout->tv_sec * 1000 + timeout->tv_usec / 1000) : INFINITE; DWORD start_tick = GetTickCount(); LogVerbose("select() called with timeout=%lu ms", timeout_ms); do { int ready_count = 0; fd_set res_read, res_write, res_except; FD_ZERO(&res_read); FD_ZERO(&res_write); FD_ZERO(&res_except); if (readfds) for (u_int i = 0; i < readfds->fd_count; i++) { ASYNC_SOCKET* sock = FindAsyncSocket(readfds->fd_array[i]); if (sock && ((sock->is_listening && sock->accept_queue) || sock->recv_len > 0 || sock->is_closed)) FD_SET(sock->socket, &res_read); } if (writefds) for (u_int i = 0; i < writefds->fd_count; i++) { ASYNC_SOCKET* sock = FindAsyncSocket(writefds->fd_array[i]); if (sock && sock->is_connected) FD_SET(sock->socket, &res_write); } if (readfds) *readfds = res_read; if (writefds) *writefds = res_write; if (exceptfds) FD_ZERO(exceptfds); ready_count = res_read.fd_count + res_write.fd_count; if (ready_count > 0 || timeout_ms == 0) { LogVerbose("select() returning %d ready sockets", ready_count); SetWSAError(0); return ready_count; } Sleep(10); } while (GetTickCount() - start_tick < timeout_ms); if (readfds) FD_ZERO(readfds); if (writefds) FD_ZERO(writefds); if (exceptfds) FD_ZERO(exceptfds); LogVerbose("select() timed out"); SetWSAError(0); return 0; }
int WSAAPI ex_setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen) { ASYNC_SOCKET* sock = FindAsyncSocket(s); if (!sock) { SetWSAError(WSAENOTSOCK); return SOCKET_ERROR; } if (level == SOL_SOCKET) { switch (optname) { case SO_REUSEADDR: if (optval && optlen >= sizeof(int)) sock->allow_reuse_addr = (*(int*)optval != 0); break; case SO_EXCLUSIVEADDRUSE: if (optval && optlen >= sizeof(int)) sock->exclusive_addr_use = (*(int*)optval != 0); break; case SO_LINGER: if (optval && optlen >= sizeof(struct linger)) memcpy(&sock->linger_opts, optval, sizeof(struct linger)); break; } } else if (level == IPPROTO_TCP && optname == TCP_NODELAY) { if (optval && optlen >= sizeof(int)) sock->tcp_nodelay = (*(int*)optval != 0); } SetWSAError(0); return 0; }
int WSAAPI ex_getsockopt(SOCKET s, int level, int optname, char* optval, int* optlen) { if (optval && optlen && *optlen >= sizeof(int)) { if (level == SOL_SOCKET && optname == SO_ERROR) { *(int*)optval = GetWSAError(); *optlen = sizeof(int); } else if (level == SOL_SOCKET && optname == SO_TYPE) { *(int*)optval = SOCK_STREAM; *optlen = sizeof(int); } else memset(optval, 0, *optlen); } SetWSAError(0); return 0; }
int WSAAPI ex_ioctlsocket(SOCKET s, long cmd, u_long* argp) { ASYNC_SOCKET* sock = FindAsyncSocket(s); if (!sock) { SetWSAError(WSAENOTSOCK); return SOCKET_ERROR; } if (argp) { if (cmd == FIONBIO) sock->is_nonblocking = (*argp != 0); else if (cmd == FIONREAD) { EnterCriticalSection(&sock->cs_recv); *argp = (u_long)sock->recv_len; LeaveCriticalSection(&sock->cs_recv); } } SetWSAError(0); return 0; }
int WSAAPI ex_closesocket(SOCKET s) { ASYNC_SOCKET* sock = FindAsyncSocket(s); if (!sock) { SetWSAError(WSAENOTSOCK); return SOCKET_ERROR; } sock->is_closed = TRUE; SetEvent(sock->hCloseEvent); if (sock->peer_socket != INVALID_SOCKET) { ASYNC_SOCKET* peer = FindAsyncSocket(sock->peer_socket); if (peer) { peer->is_connected = FALSE; peer->peer_socket = INVALID_SOCKET; SetEvent(peer->hCloseEvent); SetEvent(peer->hReadEvent); if (peer->hAsyncSelectWnd && (peer->network_events & FD_CLOSE)) PostMessage(peer->hAsyncSelectWnd, peer->uAsyncSelectMsg, peer->socket, FD_CLOSE); } } if (sock->is_listening && sock->is_bound) { EnterCriticalSection(&g_GlobalCS); PORT_BINDING** ppb = &g_PortBindings; while (*ppb) { if ((*ppb)->listen_socket == sock) { PORT_BINDING* to_remove = *ppb; *ppb = (*ppb)->next; SAFE_FREE(to_remove); break; } ppb = &(*ppb)->next; } LeaveCriticalSection(&g_GlobalCS); } Sleep(10); FreeAsyncSocket(sock); LogMessage("closesocket(" PTR_FORMAT ") -> OK", PTR_CAST(s)); SetWSAError(0); return 0; }
int WSAAPI ex_shutdown(SOCKET s, int how) { LogMessage("shutdown(" PTR_FORMAT ", how=%d) -> OK", PTR_CAST(s), how); SetWSAError(0); return 0; }
int WSAAPI ex_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) { ASYNC_SOCKET* sock = FindAsyncSocket(s); if (!sock || !sock->is_connected) { SetWSAError(WSAENOTCONN); return SOCKET_ERROR; } DWORD bytes_sent = 0; for(DWORD i = 0; i < dwBufferCount; i++) bytes_sent += lpBuffers[i].len; sock->total_bytes_sent += bytes_sent; if (lpNumberOfBytesSent) *lpNumberOfBytesSent = bytes_sent; if (lpOverlapped) { PENDING_IO* io = (PENDING_IO*)SAFE_ALLOC(sizeof(PENDING_IO)); io->overlapped = lpOverlapped; io->completion_routine = lpCompletionRoutine; io->bytes_transferred = bytes_sent; CompleteIoOperation(io, bytes_sent, 0); SAFE_FREE(io); LogMessage("WSASend(" PTR_FORMAT ") -> queued %lu bytes (overlapped)", PTR_CAST(s), bytes_sent); SetWSAError(WSA_IO_PENDING); return SOCKET_ERROR; } LogMessage("WSASend(" PTR_FORMAT ") -> sent %lu bytes (sync)", PTR_CAST(s), bytes_sent); SetWSAError(0); return 0; }
int WSAAPI ex_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) { ASYNC_SOCKET* sock = FindAsyncSocket(s); if (!sock) { SetWSAError(WSAENOTSOCK); return SOCKET_ERROR; } EnterCriticalSection(&sock->cs_recv); BOOL has_data = (sock->recv_len > 0); LeaveCriticalSection(&sock->cs_recv); if (has_data) { int bytes = ex_recv(s, lpBuffers[0].buf, lpBuffers[0].len, lpFlags ? *lpFlags : 0); if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = (bytes > 0) ? bytes : 0; if (lpOverlapped) { PENDING_IO* io = (PENDING_IO*)SAFE_ALLOC(sizeof(PENDING_IO)); io->overlapped = lpOverlapped; io->completion_routine = lpCompletionRoutine; CompleteIoOperation(io, (bytes > 0) ? bytes : 0, 0); SAFE_FREE(io); } return (bytes >= 0) ? 0 : SOCKET_ERROR; } if (!lpOverlapped && !sock->is_nonblocking) { int bytes = ex_recv(s, lpBuffers[0].buf, lpBuffers[0].len, 0); if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = (bytes > 0) ? bytes : 0; return (bytes >= 0) ? 0 : SOCKET_ERROR; } PENDING_IO* io = (PENDING_IO*)SAFE_ALLOC(sizeof(PENDING_IO)); if(!io) { SetWSAError(WSA_NOT_ENOUGH_MEMORY); return SOCKET_ERROR; } io->socket = s; io->overlapped = lpOverlapped; io->completion_routine = lpCompletionRoutine; io->buffers = lpBuffers; io->buffer_count = dwBufferCount; io->flags = lpFlags ? *lpFlags : 0; EnterCriticalSection(&g_GlobalCS); sock->pending_recv = io; io->next = g_PendingOperations; g_PendingOperations = io; LeaveCriticalSection(&g_GlobalCS); LogMessage("WSARecv(" PTR_FORMAT ") -> PENDING", PTR_CAST(s)); SetWSAError(WSA_IO_PENDING); return SOCKET_ERROR; }
int WSAAPI ex_WSAEventSelect(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents) { ASYNC_SOCKET* sock = FindOrCreateAsyncSocket(s); if (!sock) { SetWSAError(WSAENOTSOCK); return SOCKET_ERROR; } sock->hEventSelect = hEventObject; sock->network_events = lNetworkEvents; sock->is_async = TRUE; sock->is_nonblocking = TRUE; if (hEventObject && (((lNetworkEvents & FD_READ) && sock->recv_len > 0) || ((lNetworkEvents & FD_ACCEPT) && sock->accept_queue) || ((lNetworkEvents & FD_WRITE) && sock->is_connected))) SetEvent(hEventObject); LogMessage("WSAEventSelect(" PTR_FORMAT ", events=0x%lx) -> OK", PTR_CAST(s), lNetworkEvents); SetWSAError(0); return 0; }
int WSAAPI ex_WSAAsyncSelect(SOCKET s, HWND hWnd, u_int wMsg, long lEvent) { ASYNC_SOCKET* sock = FindOrCreateAsyncSocket(s); if (!sock) { SetWSAError(WSAENOTSOCK); return SOCKET_ERROR; } sock->hAsyncSelectWnd = hWnd; sock->uAsyncSelectMsg = wMsg; sock->network_events = lEvent; sock->posted_async_events = 0; sock->is_nonblocking = TRUE; sock->is_async = TRUE; LogMessage("WSAAsyncSelect(" PTR_FORMAT ", hWnd=%p, msg=0x%x, ev=0x%lx) -> OK", PTR_CAST(s), hWnd, wMsg, lEvent); SetWSAError(0); return 0; }
int WSAAPI ex_WSAGetLastError(void) { return GetWSAError(); }
void WSAAPI ex_WSASetLastError(int iError) { SetWSAError(iError); }
unsigned long WSAAPI ex_htonl(unsigned long hostlong) { return my_htonl(hostlong); }
unsigned short WSAAPI ex_htons(unsigned short hostshort) { return my_htons(hostshort); }
unsigned long WSAAPI ex_ntohl(unsigned long netlong) { return my_ntohl(netlong); }
unsigned short WSAAPI ex_ntohs(unsigned short netshort) { return my_ntohs(netshort); }
unsigned long WSAAPI ex_inet_addr(const char* cp) { return my_inet_addr(cp); }
char* WSAAPI ex_inet_ntoa(struct in_addr in) { static THREAD_LOCAL char buf[18]; unsigned char* b = (unsigned char*)&in.s_addr; sprintf_s(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]); return buf; }
int WSAAPI ex_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult) { if (pNodeName && (strcmp(pNodeName, "127.0.0.1") == 0 || strcmp(pNodeName, "localhost") == 0)) { LogMessage("getaddrinfo('%s') -> returning loopback", pNodeName); if (ppResult) { ADDRINFOA* result = (ADDRINFOA*)SAFE_ALLOC(sizeof(ADDRINFOA) + sizeof(struct sockaddr_in)); if (result) { result->ai_family = AF_INET; result->ai_socktype = SOCK_STREAM; result->ai_protocol = IPPROTO_TCP; result->ai_addrlen = sizeof(struct sockaddr_in); result->ai_addr = (struct sockaddr*)((char*)result + sizeof(ADDRINFOA)); struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr; addr->sin_family = AF_INET; addr->sin_addr.s_addr = inet_addr("127.0.0.1"); addr->sin_port = pServiceName ? htons((unsigned short)atoi(pServiceName)) : 0; *ppResult = result; SetWSAError(0); return 0; } } } LogMessage("getaddrinfo('%s') -> BLOCKED", pNodeName ? pNodeName : "NULL"); SetWSAError(WSAHOST_NOT_FOUND); return EAI_FAIL; }
int WSAAPI ex_GetAddrInfoW(PCWSTR p, PCWSTR s, const ADDRINFOW* h, PADDRINFOW* r) { LogMessage("GetAddrInfoW() -> BLOCKED"); return EAI_FAIL; }
void WSAAPI ex_freeaddrinfo(PADDRINFOA p) { if (p) SAFE_FREE(p); }
void WSAAPI ex_FreeAddrInfoW(PADDRINFOW p) { if (p) SAFE_FREE(p); }
struct hostent* WSAAPI ex_gethostbyname(const char* name) { LogMessage("gethostbyname('%s') -> BLOCKED", name ? name : "NULL"); SetWSAError(WSAHOST_NOT_FOUND); return NULL; }
int WSAAPI ex_gethostname(char* name, int namelen) { if (name && namelen > 0) { strcpy_s(name, namelen, "localhost"); SetWSAError(0); return 0; } SetWSAError(WSAEFAULT); return SOCKET_ERROR; }
int WSAAPI ex_getsockname(SOCKET s, struct sockaddr* name, int* namelen) { ASYNC_SOCKET* sock = FindAsyncSocket(s); if (sock && sock->is_bound && name && namelen) { int copy_len = min(*namelen, sizeof(struct sockaddr_in)); memcpy(name, &sock->bind_addr, copy_len); *namelen = sizeof(struct sockaddr_in); } SetWSAError(0); return 0; }
int WSAAPI ex_getpeername(SOCKET s, struct sockaddr* name, int* namelen) { ASYNC_SOCKET* sock = FindAsyncSocket(s); if (sock && sock->peer_socket != INVALID_SOCKET) { ASYNC_SOCKET* peer = FindAsyncSocket(sock->peer_socket); if (peer && peer->is_bound && name && namelen) { int copy_len = min(*namelen, sizeof(struct sockaddr_in)); memcpy(name, &peer->bind_addr, copy_len); *namelen = sizeof(struct sockaddr_in); SetWSAError(0); return 0; } } if (name && namelen && *namelen >= sizeof(struct sockaddr_in)) { memset(name, 0, *namelen); name->sa_family = AF_INET; *namelen = sizeof(struct sockaddr_in); } SetWSAError(0); return 0; }
WSAEVENT WSAAPI ex_WSACreateEvent(void) { HANDLE h = CreateEvent(NULL, TRUE, FALSE, NULL); LogVerbose("WSACreateEvent()->%p", h); return(WSAEVENT)h; }
BOOL WSAAPI ex_WSACloseEvent(WSAEVENT h) { LogVerbose("WSACloseEvent(%p)", h); return CloseHandle((HANDLE)h); }
BOOL WSAAPI ex_WSASetEvent(WSAEVENT h) { return SetEvent((HANDLE)h); }
BOOL WSAAPI ex_WSAResetEvent(WSAEVENT h) { return ResetEvent((HANDLE)h); }
DWORD WSAAPI ex_WSAWaitForMultipleEvents(DWORD c, const WSAEVENT* lph, BOOL f, DWORD d, BOOL a) { return WaitForMultipleObjectsEx(c, (const HANDLE*)lph, f, d, a); }
int WSAAPI ex_WSAEnumNetworkEvents(SOCKET s, WSAEVENT h, LPWSANETWORKEVENTS lp) { ASYNC_SOCKET* sock = FindAsyncSocket(s); if (!sock) { SetWSAError(WSAENOTSOCK); return SOCKET_ERROR; } if (lp) { memset(lp, 0, sizeof(WSANETWORKEVENTS)); if (sock->recv_len > 0) lp->lNetworkEvents |= FD_READ; if (sock->is_connected) lp->lNetworkEvents |= FD_WRITE; if (sock->accept_queue) lp->lNetworkEvents |= FD_ACCEPT; if (sock->is_closed) lp->lNetworkEvents |= FD_CLOSE; } if (h) ResetEvent((HANDLE)h); SetWSAError(0); return 0; }
BOOL WSAAPI ex_WSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED lp, LPDWORD lpcb, BOOL f, LPDWORD fl) { if (!lp) { SetWSAError(WSA_INVALID_PARAMETER); return FALSE; } if (f && lp->hEvent) WaitForSingleObject(lp->hEvent, INFINITE); if (lpcb) *lpcb = (DWORD)lp->InternalHigh; SetWSAError((int)lp->Internal); return (lp->Internal == 0); }
SOCKET WSAAPI ex_WSAAccept(SOCKET s, struct sockaddr* a, LPINT al, LPCONDITIONPROC lc, DWORD_PTR dc) { return ex_accept(s, a, al); }
int WSAAPI ex_WSAConnect(SOCKET s, const struct sockaddr* n, int nl, LPWSABUF cd, LPWSABUF ce, LPQOS sq, LPQOS gq) { return ex_connect(s, n, nl); }
BOOL PASCAL FAR ex_AcceptEx(SOCKET sListenSocket, SOCKET sAcceptSocket, PVOID lpOutputBuffer, DWORD dwReceiveDataLength, DWORD dwLocalAddressLength, DWORD dwRemoteAddressLength, LPDWORD lpdwBytesReceived, LPOVERLAPPED lpOverlapped) { LogMessage("AcceptEx(" PTR_FORMAT ", " PTR_FORMAT ") called", PTR_CAST(sListenSocket), PTR_CAST(sAcceptSocket)); PENDING_IO io = {0}; io.overlapped = lpOverlapped; CompleteIoOperation(&io, 0, WSAEOPNOTSUPP); SetWSAError(WSA_IO_PENDING); return FALSE; }
BOOL PASCAL FAR ex_ConnectEx(SOCKET s, const struct sockaddr* name, int namelen, PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped) { LogMessage("ConnectEx(" PTR_FORMAT ") called", PTR_CAST(s)); int result = ex_connect(s, name, namelen); PENDING_IO io = {0}; io.overlapped = lpOverlapped; CompleteIoOperation(&io, 0, (result == 0) ? 0 : GetWSAError()); if (result == 0) return TRUE; else { SetWSAError(WSA_IO_PENDING); return FALSE; } }
int WSAAPI ex_WSAIoctl(SOCKET s, DWORD c, LPVOID in, DWORD cin, LPVOID out, DWORD cout, LPDWORD ret, LPWSAOVERLAPPED o, LPWSAOVERLAPPED_COMPLETION_ROUTINE r) { LogMessage("WSAIoctl(" PTR_FORMAT ", cmd=0x%lX)", PTR_CAST(s), c); if (c == FIONBIO && in) return ex_ioctlsocket(s, FIONBIO, (u_long*)in); if (c == FIONREAD && out) return ex_ioctlsocket(s, FIONREAD, (u_long*)out); if (c == SIO_GET_EXTENSION_FUNCTION_POINTER && out && cout >= sizeof(void*)) { GUID* func_guid = (GUID*)in; GUID wsaid_acceptex = WSAID_ACCEPTEX; GUID wsaid_connectex = WSAID_CONNECTEX; if (IsEqualGUID(func_guid, &wsaid_acceptex)) { *(void**)out = ex_AcceptEx; if(ret) *ret = sizeof(void*); SetWSAError(0); return 0; } if (IsEqualGUID(func_guid, &wsaid_connectex)) { *(void**)out = ex_ConnectEx; if(ret) *ret = sizeof(void*); SetWSAError(0); return 0; } LogMessage("  -> Request for UNKNOWN extension function pointer"); SetWSAError(WSAEINVAL); return SOCKET_ERROR; } if (ret) *ret = 0; if (o) { PENDING_IO io={0}; io.overlapped=o; io.completion_routine=r; CompleteIoOperation(&io,0,0); } SetWSAError(0); return 0; }
#if (_WIN32_WINNT >= 0x0600)
int WSAAPI ex_WSAPoll(LPWSAPOLLFD fdArray, ULONG fds, INT timeout) { if (!fdArray || fds == 0) { SetWSAError(WSAEINVAL); return SOCKET_ERROR; } DWORD timeout_ms = (timeout < 0) ? INFINITE : (DWORD)timeout; DWORD start_tick = GetTickCount(); do { int ready_count = 0; for (ULONG i = 0; i < fds; i++) { fdArray[i].revents = 0; ASYNC_SOCKET* sock = FindAsyncSocket(fdArray[i].fd); if (!sock) { fdArray[i].revents = POLLNVAL; ready_count++; continue; } if (sock->is_closed) fdArray[i].revents |= POLLHUP; if ((fdArray[i].events & POLLIN) && ((sock->is_listening && sock->accept_queue) || sock->recv_len > 0)) fdArray[i].revents |= POLLRDNORM; if ((fdArray[i].events & POLLOUT) && sock->is_connected) fdArray[i].revents |= POLLWRNORM; if (fdArray[i].revents != 0) ready_count++; } if (ready_count > 0 || timeout_ms == 0) { SetWSAError(0); return ready_count; } Sleep(10); } while (GetTickCount() - start_tick < timeout_ms); SetWSAError(0); return 0; }
#else
int WSAAPI ex_WSAPoll(LPVOID fdArray, ULONG fds, INT timeout) { SetWSAError(WSAEOPNOTSUPP); return SOCKET_ERROR; }
#endif
int WSAAPI ex___WSAFDIsSet(SOCKET s, fd_set* set) { if (!set) return 0; for (u_int i = 0; i < set->fd_count; i++) if (set->fd_array[i] == s) return 1; return 0; }
int WSAAPI ex_sendto(SOCKET s, const char* b, int l, int f, const struct sockaddr* t, int tl) { LogMessage("sendto->BLOCKED"); SetWSAError(WSAENETUNREACH); return SOCKET_ERROR; }
int WSAAPI ex_recvfrom(SOCKET s, char* b, int l, int f, struct sockaddr* fr, int* fl) { LogMessage("recvfrom->BLOCKED"); SetWSAError(WSAEWOULDBLOCK); return SOCKET_ERROR; }
int WSAAPI ex_WSASendTo(SOCKET s,LPWSABUF b,DWORD bc,LPDWORD bs,DWORD f,const struct sockaddr* t,int tl,LPWSAOVERLAPPED o,LPWSAOVERLAPPED_COMPLETION_ROUTINE r){ LogMessage("WSASendTo->BLOCKED"); SetWSAError(WSAENETUNREACH); return SOCKET_ERROR;}
int WSAAPI ex_WSARecvFrom(SOCKET s,LPWSABUF b,DWORD bc,LPDWORD br,LPDWORD fl,struct sockaddr* f,LPINT fln,LPWSAOVERLAPPED o,LPWSAOVERLAPPED_COMPLETION_ROUTINE r){ LogMessage("WSARecvFrom->BLOCKED"); SetWSAError(WSAEWOULDBLOCK); return SOCKET_ERROR;}
int WSAAPI ex_WSADuplicateSocketA(SOCKET s, DWORD p, LPWSAPROTOCOL_INFOA i){ LogMessage("WSADuplicateSocketA->NOT_SUPP"); SetWSAError(WSAEOPNOTSUPP); return SOCKET_ERROR;}
int WSAAPI ex_WSADuplicateSocketW(SOCKET s, DWORD p, LPWSAPROTOCOL_INFOW i){ LogMessage("WSADuplicateSocketW->NOT_SUPP"); SetWSAError(WSAEOPNOTSUPP); return SOCKET_ERROR;}
int WSAAPI ex_WSAAddressToStringA(LPSOCKADDR a, DWORD al, LPWSAPROTOCOL_INFOA pi, LPSTR as, LPDWORD asl) { if (!a || !as || !asl) { SetWSAError(WSAEINVAL); return SOCKET_ERROR; } if (a->sa_family == AF_INET) { struct sockaddr_in* sin = (struct sockaddr_in*)a; char buffer[32]; sprintf_s(buffer,sizeof(buffer),"%s:%u",ex_inet_ntoa(sin->sin_addr), ntohs(sin->sin_port)); size_t len = strlen(buffer)+1; if(*asl<len){*asl=(DWORD)len; SetWSAError(WSAEFAULT); return SOCKET_ERROR;} strcpy_s(as, *asl, buffer); *asl=(DWORD)len; SetWSAError(0); return 0;} SetWSAError(WSAEINVAL); return SOCKET_ERROR;}
int WSAAPI ex_WSAAddressToStringW(LPSOCKADDR a,DWORD al,LPWSAPROTOCOL_INFOW pi,LPWSTR as,LPDWORD asl){LogMessage("WSAAddressToStringW->NOT_IMPL"); SetWSAError(WSAEOPNOTSUPP); return SOCKET_ERROR;}
int WSAAPI ex_WSAStringToAddressA(LPSTR s,INT f,LPWSAPROTOCOL_INFOA pi,LPSOCKADDR a,LPINT al){LogMessage("WSAStringToAddressA->NOT_IMPL"); SetWSAError(WSAEOPNOTSUPP); return SOCKET_ERROR;}
int WSAAPI ex_WSAStringToAddressW(LPWSTR s,INT f,LPWSAPROTOCOL_INFOW pi,LPSOCKADDR a,LPINT al){LogMessage("WSAStringToAddressW->NOT_IMPL"); SetWSAError(WSAEOPNOTSUPP); return SOCKET_ERROR;}
HANDLE WSAAPI ex_WSAAsyncGetHostByName(HWND h,u_int w,const char* n,char* b,int bl){LogMessage("WSAAsyncGetHostByName->BLOCKED"); SetWSAError(WSAHOST_NOT_FOUND); return NULL;}
HANDLE WSAAPI ex_WSAAsyncGetHostByAddr(HWND h,u_int w,const char* a,int l,int t,char* b,int bl){LogMessage("WSAAsyncGetHostByAddr->BLOCKED"); SetWSAError(WSAHOST_NOT_FOUND); return NULL;}
int WSAAPI ex_WSACancelAsyncRequest(HANDLE h){LogMessage("WSACancelAsyncRequest->OK"); SetWSAError(0); return 0;}
int WSAAPI ex_WSAEnumProtocolsA(LPINT p,LPWSAPROTOCOL_INFOA b,LPDWORD bl){LogMessage("WSAEnumProtocolsA->NOT_IMPL"); SetWSAError(WSAEOPNOTSUPP); return SOCKET_ERROR;}
int WSAAPI ex_WSAEnumProtocolsW(LPINT p,LPWSAPROTOCOL_INFOW b,LPDWORD bl){LogMessage("WSAEnumProtocolsW->NOT_IMPL"); SetWSAError(WSAEOPNOTSUPP); return SOCKET_ERROR;}
#if (_WIN32_WINNT >= 0x0600)
int WSAAPI ex_WSASendMsg(SOCKET h, LPWSAMSG m, DWORD f, LPDWORD bs, LPWSAOVERLAPPED o, LPWSAOVERLAPPED_COMPLETION_ROUTINE r) { LogMessage("WSASendMsg called"); if (!m) { SetWSAError(WSAEINVAL); return SOCKET_ERROR; } return ex_WSASend(h, m->lpBuffers, m->dwBufferCount, bs, f, o, r); }
#endif

// === ВИПРАВЛЕНО: Додано реалізації відсутніх заглушок ===
int WSAAPI ex_StubSuccess(void) { SetWSAError(0); return 0; }
void WSAAPI ex_StubVoid(void) { return; }
LPVOID WSAAPI ex_StubReturnNull(void) { SetWSAError(WSAEOPNOTSUPP); return NULL; }
SOCKET WSAAPI ex_StubReturnInvalidSocket(void) { SetWSAError(WSAEOPNOTSUPP); return INVALID_SOCKET; }
int WSAAPI ex_StubFail_NotSupp(void) { SetWSAError(WSAEOPNOTSUPP); return SOCKET_ERROR; }

// === DLL MAIN ===
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        InitializeCriticalSection(&g_GlobalCS);
        #if ENABLE_MEMORY_TRACKING
        InitializeCriticalSection(&g_memory_lock);
        #endif
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        if (g_IsInitialized) {
            ex_WSACleanup();
        }
        DeleteCriticalSection(&g_GlobalCS);
        #if ENABLE_MEMORY_TRACKING
        DeleteCriticalSection(&g_memory_lock);
        #endif
        break;
    }
    return TRUE;
}