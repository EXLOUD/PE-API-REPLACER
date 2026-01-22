#include "wininet_internal.h"

// ============================================================
// Helper Functions
// ============================================================

// Парсинг HTTP response headers
static BOOL ParseHttpHeaders(HEADER* h) {
    if (!h || h->sock == INVALID_SOCKET) return FALSE;
    
    char buffer[8192];
    int total = 0;
    int header_end = -1;
    
    // Читаємо заголовки байт за байтом поки не знайдемо \r\n\r\n
    while (total < (int)(sizeof(buffer) - 1)) {
        int r = recv(h->sock, buffer + total, 1, 0);
        if (r <= 0) {
            if (r == 0) break; // Connection closed
            if (WSAGetLastError() == 10035) continue; // WSAEWOULDBLOCK
            Log("ParseHttpHeaders: recv error %d", WSAGetLastError());
            return FALSE;
        }
        total++;
        
        // Перевіряємо на кінець заголовків
        if (total >= 4) {
            if (memcmp(buffer + total - 4, "\r\n\r\n", 4) == 0) {
                header_end = total;
                break;
            }
        }
    }
    
    if (header_end < 0) {
        Log("ParseHttpHeaders: header end not found");
        return FALSE;
    }
    
    buffer[total] = '\0';
    
    // Зберігаємо сирі заголовки
    h->response_headers = (char*)malloc(total + 1);
    if (h->response_headers) {
        memcpy(h->response_headers, buffer, total + 1);
        h->response_headers_len = (DWORD)total;
    }
    
    // Парсимо статус лінію: "HTTP/1.1 200 OK\r\n"
    char* line_end = strstr(buffer, "\r\n");
    if (line_end) {
        *line_end = '\0';
        
        int major, minor, status_temp;
        if (sscanf(buffer, "HTTP/%d.%d %d", &major, &minor, &status_temp) >= 3) {
            h->status_code = (DWORD)status_temp;
            
            // Знаходимо status text
            char* status_text_start = strchr(buffer, ' ');
            if (status_text_start) {
                status_text_start = strchr(status_text_start + 1, ' ');
                if (status_text_start) {
                    strncpy(h->status_text, status_text_start + 1, sizeof(h->status_text) - 1);
                    h->status_text[sizeof(h->status_text) - 1] = '\0';
                }
            }
            Log("ParseHttpHeaders: HTTP/%d.%d %lu %s", major, minor, 
                (unsigned long)h->status_code, h->status_text);
        }
        *line_end = '\r'; // Restore
    }
    
    // Парсимо важливі заголовки
    h->content_length = (DWORD)-1; // Unknown
    h->chunked = FALSE;
    
    // Content-Length
    char* cl = strstr(buffer, "Content-Length:");
    if (!cl) cl = strstr(buffer, "content-length:");
    if (cl) {
        cl += 15; // Skip "Content-Length:"
        while (*cl == ' ') cl++;
        h->content_length = (DWORD)atol(cl);
        Log("ParseHttpHeaders: Content-Length: %lu", (unsigned long)h->content_length);
    }
    
    // Transfer-Encoding: chunked
    if (strstr(buffer, "Transfer-Encoding: chunked") || 
        strstr(buffer, "transfer-encoding: chunked")) {
        h->chunked = TRUE;
        Log("ParseHttpHeaders: Chunked encoding detected");
    }
    
    // Content-Type
    char* ct = strstr(buffer, "Content-Type:");
    if (!ct) ct = strstr(buffer, "content-type:");
    if (ct) {
        ct += 13;
        while (*ct == ' ') ct++;
        char* ct_end = strstr(ct, "\r\n");
        if (ct_end) {
            size_t len = ct_end - ct;
            if (len >= sizeof(h->content_type)) len = sizeof(h->content_type) - 1;
            strncpy(h->content_type, ct, len);
            h->content_type[len] = '\0';
        }
    }
    
    h->headers_received = TRUE;
    h->content_read = 0;
    
    return TRUE;
}

// Знаходження заголовка у response
static char* FindHeader(HEADER* h, const char* header_name) {
    if (!h || !h->response_headers || !header_name) return NULL;
    
    // Case-insensitive search
    char* headers = h->response_headers;
    size_t name_len = strlen(header_name);
    
    char* pos = headers;
    while ((pos = strstr(pos, "\r\n")) != NULL) {
        pos += 2;
        if (_strnicmp(pos, header_name, name_len) == 0) {
            pos += name_len;
            if (*pos == ':') {
                pos++;
                while (*pos == ' ') pos++;
                return pos;
            }
        }
    }
    
    // Check first line too
    if (_strnicmp(headers, header_name, name_len) == 0) {
        char* p = headers + name_len;
        if (*p == ':') {
            p++;
            while (*p == ' ') p++;
            return p;
        }
    }
    
    return NULL;
}

// ============================================================
// InternetOpen
// ============================================================

HINTERNET WINAPI ex_InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, 
                                   LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags) {
    InitWinsock();
    
    HEADER* h = (HEADER*)calloc(1, sizeof(HEADER));
    if (!h) {
        SetLastError(ERROR_INTERNET_OUT_OF_HANDLES);
        return NULL;
    }
    
    h->type = HANDLE_ROOT;
    h->sock = INVALID_SOCKET;
    h->flags = dwFlags;
    h->content_length = (DWORD)-1;
    
    Log("InternetOpenA: agent='%s', access=%lu, flags=0x%lX", 
        lpszAgent ? lpszAgent : "NULL", (unsigned long)dwAccessType, (unsigned long)dwFlags);
    
    return (HINTERNET)h;
}

HINTERNET WINAPI ex_InternetOpenW(LPCWSTR lpszAgent, DWORD dwAccessType, 
                                   LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags) {
    char agentA[256] = {0};
    if (lpszAgent) {
        WideCharToMultiByte(CP_ACP, 0, lpszAgent, -1, agentA, sizeof(agentA), NULL, NULL);
    }
    return ex_InternetOpenA(agentA, dwAccessType, NULL, NULL, dwFlags);
}

// ============================================================
// InternetConnect
// ============================================================

HINTERNET WINAPI ex_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, 
                                      INTERNET_PORT nServerPort, LPCSTR lpszUserName, 
                                      LPCSTR lpszPassword, DWORD dwService, 
                                      DWORD dwFlags, DWORD_PTR dwContext) {
    if (!hInternet) {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }
    
    HEADER* h = (HEADER*)calloc(1, sizeof(HEADER));
    if (!h) {
        SetLastError(ERROR_INTERNET_OUT_OF_HANDLES);
        return NULL;
    }
    
    h->parent = hInternet;
    h->context = dwContext;
    h->sock = INVALID_SOCKET;
    h->flags = dwFlags;
    h->content_length = (DWORD)-1;
    
    // Встановлюємо порт за замовчуванням
    if (nServerPort == INTERNET_INVALID_PORT_NUMBER) {
        switch (dwService) {
            case INTERNET_SERVICE_FTP:
                h->port = INTERNET_DEFAULT_FTP_PORT;
                break;
            case INTERNET_SERVICE_HTTP:
                h->port = (dwFlags & INTERNET_FLAG_SECURE) ? 
                          INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
                break;
            default:
                h->port = INTERNET_DEFAULT_HTTP_PORT;
        }
    } else {
        h->port = nServerPort;
    }
    
    if (lpszServerName) {
        strncpy(h->host, lpszServerName, sizeof(h->host) - 1);
        h->host[sizeof(h->host) - 1] = '\0';
    }
    
    switch (dwService) {
        case INTERNET_SERVICE_FTP:
            h->type = HANDLE_FTP_CONNECT;
            Log("InternetConnectA: FTP to %s:%d", h->host, (int)h->port);
            break;
        case INTERNET_SERVICE_HTTP:
        default:
            h->type = HANDLE_HTTP_CONNECT;
            Log("InternetConnectA: HTTP to %s:%d", h->host, (int)h->port);
            break;
    }
    
    return (HINTERNET)h;
}

HINTERNET WINAPI ex_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, 
                                      INTERNET_PORT nServerPort, LPCWSTR lpszUserName, 
                                      LPCWSTR lpszPassword, DWORD dwService, 
                                      DWORD dwFlags, DWORD_PTR dwContext) {
    char serverA[INTERNET_MAX_HOST_NAME_LENGTH] = {0};
    if (lpszServerName) {
        WideCharToMultiByte(CP_ACP, 0, lpszServerName, -1, serverA, sizeof(serverA), NULL, NULL);
    }
    return ex_InternetConnectA(hInternet, serverA, nServerPort, NULL, NULL, 
                                dwService, dwFlags, dwContext);
}

// ============================================================
// HttpOpenRequest
// ============================================================

HINTERNET WINAPI ex_HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, 
                                      LPCSTR lpszObjectName, LPCSTR lpszVersion, 
                                      LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, 
                                      DWORD dwFlags, DWORD_PTR dwContext) {
    if (!hConnect) {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }
    
    HEADER* parent = (HEADER*)hConnect;
    HEADER* h = (HEADER*)calloc(1, sizeof(HEADER));
    if (!h) {
        SetLastError(ERROR_INTERNET_OUT_OF_HANDLES);
        return NULL;
    }
    
    h->type = HANDLE_HTTP_REQUEST;
    h->parent = hConnect;
    h->context = dwContext;
    h->sock = INVALID_SOCKET;
    h->flags = dwFlags;
    h->content_length = (DWORD)-1;
    
    // Копіюємо host/port з parent
    strncpy(h->host, parent->host, sizeof(h->host) - 1);
    h->host[sizeof(h->host) - 1] = '\0';
    h->port = parent->port;
    
    // Зберігаємо verb та path
    strncpy(h->verb, lpszVerb ? lpszVerb : "GET", sizeof(h->verb) - 1);
    h->verb[sizeof(h->verb) - 1] = '\0';
    strncpy(h->path, lpszObjectName ? lpszObjectName : "/", sizeof(h->path) - 1);
    h->path[sizeof(h->path) - 1] = '\0';
    
    Log("HttpOpenRequestA: %s %s (host: %s:%d, flags: 0x%lX)", 
        h->verb, h->path, h->host, (int)h->port, (unsigned long)dwFlags);
    
    return (HINTERNET)h;
}

HINTERNET WINAPI ex_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, 
                                      LPCWSTR lpszObjectName, LPCWSTR lpszVersion, 
                                      LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, 
                                      DWORD dwFlags, DWORD_PTR dwContext) {
    char verbA[32] = "GET";
    char pathA[INTERNET_MAX_PATH_LENGTH] = "/";
    
    if (lpszVerb) {
        WideCharToMultiByte(CP_ACP, 0, lpszVerb, -1, verbA, sizeof(verbA), NULL, NULL);
    }
    if (lpszObjectName) {
        WideCharToMultiByte(CP_ACP, 0, lpszObjectName, -1, pathA, sizeof(pathA), NULL, NULL);
    }
    
    return ex_HttpOpenRequestA(hConnect, verbA, pathA, NULL, NULL, NULL, dwFlags, dwContext);
}

// ============================================================
// HttpAddRequestHeaders
// ============================================================

BOOL WINAPI ex_HttpAddRequestHeadersA(HINTERNET hRequest, LPCSTR lpszHeaders, 
                                       DWORD dwHeadersLength, DWORD dwModifiers) {
    if (!hRequest) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    
    HEADER* h = (HEADER*)hRequest;
    
    if (!lpszHeaders) return TRUE;
    
    DWORD len = (dwHeadersLength == (DWORD)-1) ? (DWORD)strlen(lpszHeaders) : dwHeadersLength;
    
    if (h->request_headers) {
        // Append
        DWORD new_len = h->request_headers_len + len + 2;
        char* new_buf = (char*)realloc(h->request_headers, new_len + 1);
        if (!new_buf) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        memcpy(new_buf + h->request_headers_len, lpszHeaders, len);
        new_buf[h->request_headers_len + len] = '\0';
        h->request_headers = new_buf;
        h->request_headers_len += len;
    } else {
        h->request_headers = (char*)malloc(len + 1);
        if (!h->request_headers) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        memcpy(h->request_headers, lpszHeaders, len);
        h->request_headers[len] = '\0';
        h->request_headers_len = len;
    }
    
    Log("HttpAddRequestHeadersA: added %lu bytes", (unsigned long)len);
    return TRUE;
}

BOOL WINAPI ex_HttpAddRequestHeadersW(HINTERNET hRequest, LPCWSTR lpszHeaders, 
                                       DWORD dwHeadersLength, DWORD dwModifiers) {
    if (!lpszHeaders) return TRUE;
    
    int len = WideCharToMultiByte(CP_ACP, 0, lpszHeaders, 
                                   (dwHeadersLength == (DWORD)-1) ? -1 : (int)dwHeadersLength, 
                                   NULL, 0, NULL, NULL);
    char* headersA = (char*)malloc(len + 1);
    if (!headersA) return FALSE;
    
    WideCharToMultiByte(CP_ACP, 0, lpszHeaders, 
                        (dwHeadersLength == (DWORD)-1) ? -1 : (int)dwHeadersLength, 
                        headersA, len, NULL, NULL);
    headersA[len] = '\0';
    
    BOOL result = ex_HttpAddRequestHeadersA(hRequest, headersA, (DWORD)len, dwModifiers);
    free(headersA);
    return result;
}

// ============================================================
// HttpSendRequest - ПОВНА РЕАЛІЗАЦІЯ
// ============================================================

BOOL WINAPI ex_HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, 
                                 DWORD dwHeadersLength, LPVOID lpOptional, 
                                 DWORD dwOptionalLength) {
    if (!hRequest) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    
    HEADER* h = (HEADER*)hRequest;
    
    Log("HttpSendRequestA: %s %s://%s:%d%s", 
        h->verb, (h->flags & INTERNET_FLAG_SECURE) ? "https" : "http", 
        h->host, (int)h->port, h->path);
    
    // Перевірка на HTTPS (не підтримується без SSL)
    if (h->flags & INTERNET_FLAG_SECURE) {
        Log("HttpSendRequestA: HTTPS not supported in this emulation");
        SetLastError(ERROR_INTERNET_SECURITY_CHANNEL_ERROR);
        return FALSE;
    }
    
    // Резолвимо хост
    struct hostent* he = gethostbyname(h->host);
    if (!he) {
        Log("HttpSendRequestA: gethostbyname failed for '%s'", h->host);
        SetLastError(ERROR_INTERNET_NAME_NOT_RESOLVED);
        return FALSE;
    }
    
    // Створюємо сокет
    h->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (h->sock == INVALID_SOCKET) {
        Log("HttpSendRequestA: socket() failed");
        SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
        return FALSE;
    }
    
    // Підключаємось
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(h->port);
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    
    Log("HttpSendRequestA: connecting to %s:%d...", h->host, (int)h->port);
    
    if (connect(h->sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        Log("HttpSendRequestA: connect() failed, error %d", WSAGetLastError());
        closesocket(h->sock);
        h->sock = INVALID_SOCKET;
        SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
        return FALSE;
    }
    
    Log("HttpSendRequestA: connected!");
    
    // Формуємо HTTP запит
    char request[8192];
    int request_len = snprintf(request, sizeof(request),
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: WinINet-Emulator/1.0\r\n",
        h->verb, h->path, h->host);
    
    // Додаємо Content-Length для POST
    if (lpOptional && dwOptionalLength > 0) {
        request_len += snprintf(request + request_len, sizeof(request) - request_len,
            "Content-Length: %lu\r\n", (unsigned long)dwOptionalLength);
    }
    
    // Додаємо custom headers
    if (lpszHeaders && dwHeadersLength > 0) {
        DWORD headers_len = (dwHeadersLength == (DWORD)-1) ? 
                            (DWORD)strlen(lpszHeaders) : dwHeadersLength;
        if ((DWORD)request_len + headers_len < sizeof(request) - 4) {
            memcpy(request + request_len, lpszHeaders, headers_len);
            request_len += (int)headers_len;
        }
    }
    
    // Додаємо збережені headers
    if (h->request_headers && h->request_headers_len > 0) {
        if ((DWORD)request_len + h->request_headers_len < sizeof(request) - 4) {
            memcpy(request + request_len, h->request_headers, h->request_headers_len);
            request_len += (int)h->request_headers_len;
        }
    }
    
    // Закінчуємо заголовки
    request_len += snprintf(request + request_len, sizeof(request) - request_len, "\r\n");
    
    Log("HttpSendRequestA: sending request (%d bytes)", request_len);
    
    // Відправляємо заголовки
    if (send(h->sock, request, request_len, 0) == SOCKET_ERROR) {
        Log("HttpSendRequestA: send() failed");
        closesocket(h->sock);
        h->sock = INVALID_SOCKET;
        SetLastError(ERROR_INTERNET_CONNECTION_ABORTED);
        return FALSE;
    }
    
    // Відправляємо тіло (POST data)
    if (lpOptional && dwOptionalLength > 0) {
        if (send(h->sock, (const char*)lpOptional, (int)dwOptionalLength, 0) == SOCKET_ERROR) {
            Log("HttpSendRequestA: send body failed");
            closesocket(h->sock);
            h->sock = INVALID_SOCKET;
            SetLastError(ERROR_INTERNET_CONNECTION_ABORTED);
            return FALSE;
        }
        Log("HttpSendRequestA: sent %lu bytes of body", (unsigned long)dwOptionalLength);
    }
    
    // Парсимо response headers
    if (!ParseHttpHeaders(h)) {
        Log("HttpSendRequestA: failed to parse response headers");
        closesocket(h->sock);
        h->sock = INVALID_SOCKET;
        SetLastError(ERROR_HTTP_INVALID_SERVER_RESPONSE);
        return FALSE;
    }
    
    Log("HttpSendRequestA: SUCCESS - status %lu %s", 
        (unsigned long)h->status_code, h->status_text);
    return TRUE;
}

BOOL WINAPI ex_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, 
                                 DWORD dwHeadersLength, LPVOID lpOptional, 
                                 DWORD dwOptionalLength) {
    char* headersA = NULL;
    DWORD headersLenA = 0;
    
    if (lpszHeaders) {
        int len = WideCharToMultiByte(CP_ACP, 0, lpszHeaders, 
                                       (dwHeadersLength == (DWORD)-1) ? -1 : (int)dwHeadersLength, 
                                       NULL, 0, NULL, NULL);
        headersA = (char*)malloc(len + 1);
        if (headersA) {
            WideCharToMultiByte(CP_ACP, 0, lpszHeaders, 
                                (dwHeadersLength == (DWORD)-1) ? -1 : (int)dwHeadersLength, 
                                headersA, len, NULL, NULL);
            headersA[len] = '\0';
            headersLenA = (DWORD)len;
        }
    }
    
    BOOL result = ex_HttpSendRequestA(hRequest, headersA, headersLenA, lpOptional, dwOptionalLength);
    if (headersA) free(headersA);
    return result;
}

// ============================================================
// HttpQueryInfo - ПОВНА РЕАЛІЗАЦІЯ
// ============================================================

BOOL WINAPI ex_HttpQueryInfoA(HINTERNET hRequest, DWORD dwInfoLevel, 
                               LPVOID lpBuffer, LPDWORD lpdwBufferLength, 
                               LPDWORD lpdwIndex) {
    if (!hRequest) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    
    HEADER* h = (HEADER*)hRequest;
    DWORD query = dwInfoLevel & HTTP_QUERY_HEADER_MASK;
    DWORD flags = dwInfoLevel & HTTP_QUERY_MODIFIER_FLAGS_MASK;
    
    Log("HttpQueryInfoA: query=0x%lX, flags=0x%lX", (unsigned long)query, (unsigned long)flags);
    
    // Перевіряємо чи отримали відповідь
    if (!h->headers_received && query != HTTP_QUERY_REQUEST_METHOD) {
        SetLastError(ERROR_INTERNET_INCORRECT_HANDLE_STATE);
        return FALSE;
    }
    
    char temp_buffer[1024];
    DWORD result_len = 0;
    BOOL is_number = (flags & HTTP_QUERY_FLAG_NUMBER) != 0;
    
    switch (query) {
        case HTTP_QUERY_STATUS_CODE:
            if (is_number) {
                if (*lpdwBufferLength >= sizeof(DWORD)) {
                    *(DWORD*)lpBuffer = h->status_code;
                    *lpdwBufferLength = sizeof(DWORD);
                    Log("HttpQueryInfoA: STATUS_CODE = %lu", (unsigned long)h->status_code);
                    return TRUE;
                }
                *lpdwBufferLength = sizeof(DWORD);
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            } else {
                result_len = (DWORD)snprintf(temp_buffer, sizeof(temp_buffer), "%lu", 
                                              (unsigned long)h->status_code);
            }
            break;
            
        case HTTP_QUERY_STATUS_TEXT:
            strncpy(temp_buffer, h->status_text, sizeof(temp_buffer) - 1);
            temp_buffer[sizeof(temp_buffer) - 1] = '\0';
            result_len = (DWORD)strlen(temp_buffer);
            break;
            
        case HTTP_QUERY_CONTENT_LENGTH:
            if (h->content_length == (DWORD)-1) {
                SetLastError(ERROR_HTTP_HEADER_NOT_FOUND);
                return FALSE;
            }
            if (is_number) {
                if (*lpdwBufferLength >= sizeof(DWORD)) {
                    *(DWORD*)lpBuffer = h->content_length;
                    *lpdwBufferLength = sizeof(DWORD);
                    return TRUE;
                }
                *lpdwBufferLength = sizeof(DWORD);
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            } else {
                result_len = (DWORD)snprintf(temp_buffer, sizeof(temp_buffer), "%lu", 
                                              (unsigned long)h->content_length);
            }
            break;
            
        case HTTP_QUERY_CONTENT_TYPE:
            if (h->content_type[0] == '\0') {
                SetLastError(ERROR_HTTP_HEADER_NOT_FOUND);
                return FALSE;
            }
            strncpy(temp_buffer, h->content_type, sizeof(temp_buffer) - 1);
            temp_buffer[sizeof(temp_buffer) - 1] = '\0';
            result_len = (DWORD)strlen(temp_buffer);
            break;
            
        case HTTP_QUERY_RAW_HEADERS:
        case HTTP_QUERY_RAW_HEADERS_CRLF:
            if (!h->response_headers) {
                SetLastError(ERROR_HTTP_HEADER_NOT_FOUND);
                return FALSE;
            }
            if (*lpdwBufferLength > h->response_headers_len) {
                memcpy(lpBuffer, h->response_headers, h->response_headers_len);
                ((char*)lpBuffer)[h->response_headers_len] = '\0';
                *lpdwBufferLength = h->response_headers_len;
                return TRUE;
            }
            *lpdwBufferLength = h->response_headers_len + 1;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
            
        case HTTP_QUERY_REQUEST_METHOD:
            strncpy(temp_buffer, h->verb, sizeof(temp_buffer) - 1);
            temp_buffer[sizeof(temp_buffer) - 1] = '\0';
            result_len = (DWORD)strlen(temp_buffer);
            break;
            
        case HTTP_QUERY_VERSION: {
            // Знаходимо у відповіді
            if (h->response_headers) {
                char* ver_end = strstr(h->response_headers, " ");
                if (ver_end) {
                    size_t len = ver_end - h->response_headers;
                    if (len < sizeof(temp_buffer)) {
                        strncpy(temp_buffer, h->response_headers, len);
                        temp_buffer[len] = '\0';
                        result_len = (DWORD)len;
                    }
                }
            }
            if (result_len == 0) {
                strcpy(temp_buffer, "HTTP/1.1");
                result_len = 8;
            }
            break;
        }
        
        case HTTP_QUERY_LOCATION: {
            char* loc = FindHeader(h, "Location");
            if (!loc) {
                SetLastError(ERROR_HTTP_HEADER_NOT_FOUND);
                return FALSE;
            }
            char* loc_end = strstr(loc, "\r\n");
            if (loc_end) {
                size_t len = loc_end - loc;
                if (len < sizeof(temp_buffer)) {
                    strncpy(temp_buffer, loc, len);
                    temp_buffer[len] = '\0';
                    result_len = (DWORD)len;
                }
            }
            break;
        }
        
        case HTTP_QUERY_SERVER: {
            char* srv = FindHeader(h, "Server");
            if (!srv) {
                SetLastError(ERROR_HTTP_HEADER_NOT_FOUND);
                return FALSE;
            }
            char* srv_end = strstr(srv, "\r\n");
            if (srv_end) {
                size_t len = srv_end - srv;
                if (len < sizeof(temp_buffer)) {
                    strncpy(temp_buffer, srv, len);
                    temp_buffer[len] = '\0';
                    result_len = (DWORD)len;
                }
            }
            break;
        }
        
        default:
            Log("HttpQueryInfoA: unsupported query 0x%lX", (unsigned long)query);
            SetLastError(ERROR_HTTP_HEADER_NOT_FOUND);
            return FALSE;
    }
    
    // Copy string result
    if (result_len > 0) {
        if (*lpdwBufferLength > result_len) {
            memcpy(lpBuffer, temp_buffer, result_len + 1);
            *lpdwBufferLength = result_len;
            Log("HttpQueryInfoA: returning '%s'", temp_buffer);
            return TRUE;
        }
        *lpdwBufferLength = result_len + 1;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    
    SetLastError(ERROR_HTTP_HEADER_NOT_FOUND);
    return FALSE;
}

BOOL WINAPI ex_HttpQueryInfoW(HINTERNET hRequest, DWORD dwInfoLevel, 
                               LPVOID lpBuffer, LPDWORD lpdwBufferLength, 
                               LPDWORD lpdwIndex) {
    // Для числових запитів - напряму
    if (dwInfoLevel & HTTP_QUERY_FLAG_NUMBER) {
        return ex_HttpQueryInfoA(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex);
    }
    
    // Для рядків - конвертуємо
    DWORD bufSizeA = *lpdwBufferLength;
    char* bufA = (char*)malloc(bufSizeA);
    if (!bufA) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    
    BOOL result = ex_HttpQueryInfoA(hRequest, dwInfoLevel, bufA, &bufSizeA, lpdwIndex);
    
    if (result) {
        int wlen = MultiByteToWideChar(CP_ACP, 0, bufA, -1, NULL, 0);
        if ((DWORD)wlen * sizeof(WCHAR) <= *lpdwBufferLength) {
            MultiByteToWideChar(CP_ACP, 0, bufA, -1, (LPWSTR)lpBuffer, *lpdwBufferLength / sizeof(WCHAR));
            *lpdwBufferLength = (wlen - 1) * sizeof(WCHAR);
        } else {
            *lpdwBufferLength = wlen * sizeof(WCHAR);
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            result = FALSE;
        }
    } else {
        *lpdwBufferLength = (bufSizeA + 1) * sizeof(WCHAR);
    }
    
    free(bufA);
    return result;
}

// ============================================================
// InternetReadFile - ПОВНА РЕАЛІЗАЦІЯ
// ============================================================

BOOL WINAPI ex_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, 
                                 DWORD dwNumberOfBytesToRead, 
                                 LPDWORD lpdwNumberOfBytesRead) {
    if (!hFile || !lpdwNumberOfBytesRead) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    HEADER* h = (HEADER*)hFile;
    *lpdwNumberOfBytesRead = 0;
    
    if (h->sock == INVALID_SOCKET) {
        // No socket = EOF
        Log("InternetReadFile: no socket (EOF)");
        return TRUE;
    }
    
    // Перевіряємо чи досягли Content-Length
    if (h->content_length != (DWORD)-1 && h->content_read >= h->content_length) {
        Log("InternetReadFile: content-length reached (EOF)");
        return TRUE;
    }
    
    // Обмежуємо читання до залишку контенту
    DWORD to_read = dwNumberOfBytesToRead;
    if (h->content_length != (DWORD)-1) {
        DWORD remaining = h->content_length - h->content_read;
        if (to_read > remaining) to_read = remaining;
    }
    
    // Читаємо дані
    int received = recv(h->sock, (char*)lpBuffer, (int)to_read, 0);
    
    if (received > 0) {
        *lpdwNumberOfBytesRead = (DWORD)received;
        h->content_read += (DWORD)received;
        Log("InternetReadFile: read %d bytes (total: %lu/%lu)", 
            received, (unsigned long)h->content_read, (unsigned long)h->content_length);
    } else if (received == 0) {
        Log("InternetReadFile: connection closed (EOF)");
        closesocket(h->sock);
        h->sock = INVALID_SOCKET;
    } else {
        int err = WSAGetLastError();
        if (err == 10035) { // WSAEWOULDBLOCK
            // Non-blocking, no data available
            return TRUE;
        }
        Log("InternetReadFile: recv error %d", err);
        SetLastError(ERROR_INTERNET_CONNECTION_RESET);
        return FALSE;
    }
    
    return TRUE;
}

// ============================================================
// InternetQueryDataAvailable
// ============================================================

BOOL WINAPI ex_InternetQueryDataAvailable(HINTERNET hFile, LPDWORD lpdwNumberOfBytesAvailable,
                                           DWORD dwFlags, DWORD_PTR dwContext) {
    if (!hFile || !lpdwNumberOfBytesAvailable) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    HEADER* h = (HEADER*)hFile;
    
    if (h->sock == INVALID_SOCKET) {
        *lpdwNumberOfBytesAvailable = 0;
        return TRUE;
    }
    
    // Якщо знаємо Content-Length
    if (h->content_length != (DWORD)-1) {
        *lpdwNumberOfBytesAvailable = h->content_length - h->content_read;
        return TRUE;
    }
    
    // Інакше повертаємо "невідомо, але є дані"
    *lpdwNumberOfBytesAvailable = 1024; // Estimate
    return TRUE;
}

// ============================================================
// InternetCloseHandle
// ============================================================

BOOL WINAPI ex_InternetCloseHandle(HINTERNET hInternet) {
    if (!hInternet) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    
    HEADER* h = (HEADER*)hInternet;
    
    Log("InternetCloseHandle: type=%d", (int)h->type);
    
    // Закриваємо сокет
    if (h->sock != INVALID_SOCKET) {
        closesocket(h->sock);
        h->sock = INVALID_SOCKET;
    }
    
    // Звільняємо буфери
    if (h->request_headers) {
        free(h->request_headers);
        h->request_headers = NULL;
    }
    if (h->response_headers) {
        free(h->response_headers);
        h->response_headers = NULL;
    }
    if (h->overflow_buffer) {
        free(h->overflow_buffer);
        h->overflow_buffer = NULL;
    }
    
    free(h);
    return TRUE;
}

// ============================================================
// InternetQueryOption / InternetSetOption
// ============================================================

BOOL WINAPI ex_InternetQueryOptionA(HINTERNET hInternet, DWORD dwOption, 
                                     LPVOID lpBuffer, LPDWORD lpdwBufferLength) {
    Log("InternetQueryOptionA: option=%lu", (unsigned long)dwOption);
    
    switch (dwOption) {
        case INTERNET_OPTION_HANDLE_TYPE:
            if (*lpdwBufferLength >= sizeof(DWORD)) {
                if (hInternet) {
                    HEADER* h = (HEADER*)hInternet;
                    *(DWORD*)lpBuffer = (DWORD)h->type;
                } else {
                    *(DWORD*)lpBuffer = 0;
                }
                *lpdwBufferLength = sizeof(DWORD);
                return TRUE;
            }
            *lpdwBufferLength = sizeof(DWORD);
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
            
        case INTERNET_OPTION_URL:
            if (hInternet) {
                HEADER* h = (HEADER*)hInternet;
                char url[INTERNET_MAX_URL_LENGTH];
                int len = snprintf(url, sizeof(url), "http://%s:%d%s", 
                                   h->host, (int)h->port, h->path);
                if (*lpdwBufferLength > (DWORD)len) {
                    strcpy((char*)lpBuffer, url);
                    *lpdwBufferLength = (DWORD)len;
                    return TRUE;
                }
                *lpdwBufferLength = (DWORD)len + 1;
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            }
            break;
            
        case INTERNET_OPTION_SECURITY_FLAGS:
            if (*lpdwBufferLength >= sizeof(DWORD)) {
                *(DWORD*)lpBuffer = 0; // No security
                *lpdwBufferLength = sizeof(DWORD);
                return TRUE;
            }
            break;
            
        case INTERNET_OPTION_CONNECTED_STATE:
            if (*lpdwBufferLength >= sizeof(DWORD)) {
                *(DWORD*)lpBuffer = INTERNET_STATE_CONNECTED;
                *lpdwBufferLength = sizeof(DWORD);
                return TRUE;
            }
            break;
    }
    
    SetLastError(ERROR_INTERNET_INVALID_OPTION);
    return FALSE;
}

BOOL WINAPI ex_InternetQueryOptionW(HINTERNET hInternet, DWORD dwOption, 
                                     LPVOID lpBuffer, LPDWORD lpdwBufferLength) {
    // Для більшості опцій можна делегувати до A версії
    return ex_InternetQueryOptionA(hInternet, dwOption, lpBuffer, lpdwBufferLength);
}

BOOL WINAPI ex_InternetSetOptionA(HINTERNET hInternet, DWORD dwOption, 
                                   LPVOID lpBuffer, DWORD dwBufferLength) {
    Log("InternetSetOptionA: option=%lu", (unsigned long)dwOption);
    
    switch (dwOption) {
        case INTERNET_OPTION_CONNECT_TIMEOUT:
        case INTERNET_OPTION_SEND_TIMEOUT:
        case INTERNET_OPTION_RECEIVE_TIMEOUT:
            // Accept but ignore timeouts in this simple implementation
            return TRUE;
            
        case INTERNET_OPTION_SECURITY_FLAGS:
            // Accept security flags
            return TRUE;
            
        case INTERNET_OPTION_HTTP_DECODING:
            return TRUE;
            
        default:
            // Accept most options silently
            return TRUE;
    }
}

BOOL WINAPI ex_InternetSetOptionW(HINTERNET hInternet, DWORD dwOption, 
                                   LPVOID lpBuffer, DWORD dwBufferLength) {
    return ex_InternetSetOptionA(hInternet, dwOption, lpBuffer, dwBufferLength);
}

// ============================================================
// InternetOpenUrl - Convenience function
// ============================================================

HINTERNET WINAPI ex_InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl,
                                      LPCSTR lpszHeaders, DWORD dwHeadersLength,
                                      DWORD dwFlags, DWORD_PTR dwContext) {
    if (!hInternet || !lpszUrl) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    
    Log("InternetOpenUrlA: %s", lpszUrl);
    
    // Простий парсинг URL
    char host[INTERNET_MAX_HOST_NAME_LENGTH] = {0};
    char path[INTERNET_MAX_PATH_LENGTH] = "/";
    INTERNET_PORT port = INTERNET_DEFAULT_HTTP_PORT;
    BOOL secure = FALSE;
    
    const char* p = lpszUrl;
    
    // Skip scheme
    if (_strnicmp(p, "https://", 8) == 0) {
        secure = TRUE;
        port = INTERNET_DEFAULT_HTTPS_PORT;
        p += 8;
    } else if (_strnicmp(p, "http://", 7) == 0) {
        p += 7;
    }
    
    // Parse host
    const char* host_end = p;
    while (*host_end && *host_end != ':' && *host_end != '/' && *host_end != '?') {
        host_end++;
    }
    size_t host_len = host_end - p;
    if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
    strncpy(host, p, host_len);
    host[host_len] = '\0';
    
    p = host_end;
    
    // Parse port
    if (*p == ':') {
        p++;
        port = (INTERNET_PORT)atoi(p);
        while (*p >= '0' && *p <= '9') p++;
    }
    
    // Parse path
    if (*p == '/' || *p == '?') {
        strncpy(path, p, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    }
    
    // Create handles
    DWORD flags = dwFlags;
    if (secure) flags |= INTERNET_FLAG_SECURE;
    
    HINTERNET hConnect = ex_InternetConnectA(hInternet, host, port, NULL, NULL,
                                              INTERNET_SERVICE_HTTP, flags, dwContext);
    if (!hConnect) return NULL;
    
    HINTERNET hRequest = ex_HttpOpenRequestA(hConnect, "GET", path, NULL, NULL, NULL,
                                              flags, dwContext);
    if (!hRequest) {
        ex_InternetCloseHandle(hConnect);
        return NULL;
    }
    
    if (!ex_HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, NULL, 0)) {
        ex_InternetCloseHandle(hRequest);
        ex_InternetCloseHandle(hConnect);
        return NULL;
    }
    
    return hRequest;
}

HINTERNET WINAPI ex_InternetOpenUrlW(HINTERNET hInternet, LPCWSTR lpszUrl,
                                      LPCWSTR lpszHeaders, DWORD dwHeadersLength,
                                      DWORD dwFlags, DWORD_PTR dwContext) {
    char urlA[INTERNET_MAX_URL_LENGTH] = {0};
    if (lpszUrl) {
        WideCharToMultiByte(CP_ACP, 0, lpszUrl, -1, urlA, sizeof(urlA), NULL, NULL);
    }
    
    char* headersA = NULL;
    if (lpszHeaders) {
        int len = WideCharToMultiByte(CP_ACP, 0, lpszHeaders, 
                                       (dwHeadersLength == (DWORD)-1) ? -1 : (int)dwHeadersLength,
                                       NULL, 0, NULL, NULL);
        headersA = (char*)malloc(len + 1);
        if (headersA) {
            WideCharToMultiByte(CP_ACP, 0, lpszHeaders, 
                                (dwHeadersLength == (DWORD)-1) ? -1 : (int)dwHeadersLength,
                                headersA, len, NULL, NULL);
            headersA[len] = '\0';
        }
    }
    
    HINTERNET result = ex_InternetOpenUrlA(hInternet, urlA, headersA, 
                                            headersA ? (DWORD)strlen(headersA) : 0,
                                            dwFlags, dwContext);
    if (headersA) free(headersA);
    return result;
}

// ============================================================
// Connection State
// ============================================================

BOOL WINAPI ex_InternetGetConnectedState(LPDWORD lpdwFlags, DWORD dwReserved) {
    if (lpdwFlags) {
        *lpdwFlags = INTERNET_CONNECTION_LAN | INTERNET_CONNECTION_CONFIGURED;
    }
    return TRUE;
}

BOOL WINAPI ex_InternetGetConnectedStateExA(LPDWORD lpdwFlags, LPSTR lpszConnectionName,
                                             DWORD cchNameLen, DWORD dwReserved) {
    if (lpdwFlags) {
        *lpdwFlags = INTERNET_CONNECTION_LAN | INTERNET_CONNECTION_CONFIGURED;
    }
    if (lpszConnectionName && cchNameLen > 0) {
        strncpy(lpszConnectionName, "Local Area Connection", cchNameLen - 1);
        lpszConnectionName[cchNameLen - 1] = '\0';
    }
    return TRUE;
}

BOOL WINAPI ex_InternetGetConnectedStateExW(LPDWORD lpdwFlags, LPWSTR lpszConnectionName,
                                             DWORD cchNameLen, DWORD dwReserved) {
    if (lpdwFlags) {
        *lpdwFlags = INTERNET_CONNECTION_LAN | INTERNET_CONNECTION_CONFIGURED;
    }
    if (lpszConnectionName && cchNameLen > 0) {
        wcsncpy(lpszConnectionName, L"Local Area Connection", cchNameLen - 1);
        lpszConnectionName[cchNameLen - 1] = L'\0';
    }
    return TRUE;
}

BOOL WINAPI ex_InternetCheckConnectionA(LPCSTR lpszUrl, DWORD dwFlags, DWORD dwReserved) {
    Log("InternetCheckConnectionA: %s", lpszUrl ? lpszUrl : "NULL");
    return TRUE; // Always connected
}

BOOL WINAPI ex_InternetCheckConnectionW(LPCWSTR lpszUrl, DWORD dwFlags, DWORD dwReserved) {
    return TRUE;
}