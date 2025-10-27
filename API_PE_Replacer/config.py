# -*- coding: utf-8 -*-
# Файл конфігурації
# ВАЖЛИВО: Для бінарного патчингу довжина рядка для заміни
# МАЄ ЗБІГАТИСЯ з довжиною оригінального рядка.
# Використовуйте нульові байти \x00 для вирівнювання довжини.
DLL_REPLACEMENTS = {
    1: {'name': 'WINHTTP', 'replacements': {
        b'winhttp.dll': b'exhttp.dll\x00',
    }}, 
    
    2: {'name': 'WININET', 'replacements': {
        b'wininet.dll': b'exinet.dll\x00',
    }}, 
    
    3: {'name': 'WS2_32', 'replacements': {
        b'ws2_32.dll': b'exws2.dll\x00',
    }}, 
    
    4: {'name': 'SENSAPI', 'replacements': {
        b'sensapi.dll': b'exsens.dll\x00',
    }},
    
    5: {'name': 'IPHLPAPI', 'replacements': {
        b'iphlpapi.dll': b'exiphl.dll\x00\x00',
    }},
    
    6: {'name': 'URLMON', 'replacements': {
        b'urlmon.dll': b'exurlm.dll',
    }},
    
    7: {'name': 'NETAPI32', 'replacements': {
        b'netapi32.dll': b'exnetapi.dll',
    }},

    8: {'name': 'WSOCK32', 'replacements': {
        b'wsock32.dll': b'exws.dll\x00\x00\x00',
    }},
    
    9: {'name': 'WINTRUST', 'replacements': {
        b'wintrust.dll': b'extrust.dll\x00',
    }},

    10: {'name': 'MSWSOCK', 'replacements': {
        b'mswsock.dll': b'exmsw.dll\x00\x00',
    }},
}
