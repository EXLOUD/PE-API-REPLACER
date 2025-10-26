# -*- coding: utf-8 -*-
# Файл конфігурації
# ВАЖЛИВО: Для бінарного патчингу довжина рядка для заміни
# МАЄ ЗБІГАТИСЯ з довжиною оригінального рядка.
# Використовуйте нульові байти \x00 для вирівнювання довжини.
DLL_REPLACEMENTS = {
    1: {'name': 'WINHTTP', 'replacements': {
        b'WINHTTP.DLL': b'EXHTTP.DLL\x00',
        b'WINHTTP.dll': b'EXHTTP.dll\x00',
        b'winhttp.dll': b'EXHTTP.dll\x00',
        b'WinHttp.dll': b'EXHTTP.dll\x00',
        b'Winhttp.DLL': b'EXHTTP.DLL\x00',
        b'winHTTP.dll': b'EXHTTP.dll\x00',
        b'WINHTTP.Dll': b'EXHTTP.Dll\x00',
    }}, 
    
    2: {'name': 'WININET', 'replacements': {
        b'WININET.DLL': b'EXINET.DLL\x00',
        b'WININET.dll': b'EXINET.dll\x00',
        b'wininet.dll': b'EXINET.dll\x00',
        b'WinInet.dll': b'EXINET.dll\x00',
        b'Wininet.DLL': b'EXINET.DLL\x00',
        b'winINET.dll': b'EXINET.dll\x00',
        b'WININET.Dll': b'EXINET.Dll\x00',
    }}, 
    
    3: {'name': 'WS2_32', 'replacements': {
        b'WS2_32.DLL': b'EXWS2.DLL\x00',
        b'WS2_32.dll': b'EXWS2.dll\x00',
        b'ws2_32.dll': b'EXWS2.dll\x00',
        b'Ws2_32.dll': b'EXWS2.dll\x00',
        b'ws2_32.DLL': b'EXWS2.DLL\x00',
        b'wS2_32.Dll': b'EXWS2.Dll\x00',
        b'WS2_32.dLL': b'EXWS2.dLL\x00',
    }}, 
    
    4: {'name': 'SENSAPI', 'replacements': {
        b'SENSAPI.DLL': b'EXSENS.DLL\x00',
        b'SENSAPI.dll': b'EXSENS.dll\x00',
        b'sensapi.dll': b'EXSENS.dll\x00',
        b'SensApi.dll': b'EXSENS.dll\x00',
        b'Sensapi.DLL': b'EXSENS.DLL\x00',
        b'senSAPI.dll': b'EXSENS.dll\x00',
        b'SENSAPI.Dll': b'EXSENS.Dll\x00',
    }},
    
    5: {'name': 'IPHLPAPI', 'replacements': {
        b'IPHLPAPI.DLL': b'EXIPHL.DLL\x00\x00',
        b'IPHLPAPI.dll': b'EXIPHL.dll\x00\x00',
        b'iphlpapi.dll': b'EXIPHL.dll\x00\x00',
        b'IpHlpApi.dll': b'EXIPHL.dll\x00\x00',
        b'Iphlpapi.DLL': b'EXIPHL.DLL\x00\x00',
        b'ipHLPAPI.dll': b'EXIPHL.dll\x00\x00',
        b'IPHLPAPI.Dll': b'EXIPHL.Dll\x00\x00',
    }},
    
    6: {'name': 'URLMON', 'replacements': {
        b'URLMON.DLL': b'EXURLM.DLL',
        b'URLMON.dll': b'EXURLM.dll',
        b'urlmon.dll': b'EXURLM.dll',
        b'UrlMon.dll': b'EXURLM.dll',
        b'Urlmon.DLL': b'EXURLM.DLL',
        b'urlMON.dll': b'EXURLM.dll',
        b'URLMON.Dll': b'EXURLM.Dll',
    }},
    
    7: {'name': 'NETAPI32', 'replacements': {
        b'NETAPI32.DLL': b'EXNETAPI.DLL',
        b'NETAPI32.dll': b'EXNETAPI.dll',
        b'netapi32.dll': b'EXNETAPI.dll',
        b'NetApi32.dll': b'EXNETAPI.dll',
        b'Netapi32.dll': b'EXNETAPI.dll',
        b'netAPI32.dll': b'EXNETAPI.dll',
        b'NETAPI32.Dll': b'EXNETAPI.Dll',
        b'netapi32.DLL': b'EXNETAPI.DLL',
    }},

    8: {'name': 'WSOCK32', 'replacements': {
        b'WSOCK32.DLL': b'EXWS.DLL\x00\x00\x00',
        b'WSOCK32.dll': b'EXWS.dll\x00\x00\x00',
        b'wsock32.dll': b'EXWS.DLL\x00\x00\x00',
        b'Wsock32.dll': b'EXWS.DLL\x00\x00\x00',
        b'WSock32.dll': b'EXWS.DLL\x00\x00\x00',
        b'wsock32.DLL': b'EXWS.DLL\x00\x00\x00',
        b'WSOCK32.Dll': b'EXWS.Dll\x00\x00\x00',
        b'WSOck32.dll': b'EXWS.dll\x00\x00\x00',
    }},
    
    9: {'name': 'WINTRUST', 'replacements': {
        b'WINTRUST.DLL': b'EXTRUST.DLL\x00',
        b'WINTRUST.dll': b'EXTRUST.dll\x00',
        b'wintrust.dll': b'EXTRUST.dll\x00',
        b'WinTrust.dll': b'EXTRUST.dll\x00',
        b'Wintrust.DLL': b'EXTRUST.DLL\x00',
        b'winTRUST.dll': b'EXTRUST.dll\x00',
        b'WINTRUST.Dll': b'EXTRUST.Dll\x00',
    }},

    10: {'name': 'MSWSOCK', 'replacements': {
        b'MSWSOCK.DLL': b'EXMSW.DLL\x00\x00',
        b'mswSOCK.dll': b'EXMSW.dll\x00\x00',
        b'mswsock.dll': b'EXMSW.dll\x00\x00',
        b'MsWsock.dll': b'EXMSW.dll\x00\x00',
        b'Mswsock.DLL': b'EXMSW.DLL\x00\x00',
        b'msWSOCK.dll': b'EXMSW.dll\x00\x00',
        b'MSWSOCK.Dll': b'EXMSW.Dll\x00\x00',
    }},
}
