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
    }}, 
    2: {'name': 'WININET', 'replacements': {
        b'WININET.DLL': b'EXINET.DLL\x00',
        b'WININET.dll': b'EXINET.dll\x00',
        b'wininet.dll': b'EXINET.dll\x00',
        b'WinInet.dll': b'EXINET.dll\x00',
    }}, 
    3: {'name': 'WS2_32', 'replacements': {
        b'WS2_32.DLL': b'EXWS2.DLL\x00',
        b'WS2_32.dll': b'EXWS2.dll\x00',
        b'ws2_32.dll': b'EXWS2.dll\x00',
        b'Ws2_32.dll': b'EXWS2.dll\x00',
    }}, 
    4: {'name': 'SENSAPI', 'replacements': {
        b'SENSAPI.DLL': b'EXSENS.DLL\x00',
        b'SENSAPI.dll': b'EXSENS.dll\x00',
        b'sensapi.dll': b'EXSENS.dll\x00',
        b'SensApi.dll': b'EXSENS.dll\x00',
    }},
    5: {'name': 'IPHLPAPI', 'replacements': {
        b'IPHLPAPI.DLL': b'EXIPHL.DLL\x00\x00',
        b'IPHLPAPI.dll': b'EXIPHL.dll\x00\x00',
        b'iphlpapi.dll': b'EXIPHL.dll\x00\x00',
        b'IpHlpApi.dll': b'EXIPHL.dll\x00\x00',
    }},
    6: {'name': 'URLMON', 'replacements': {
        b'URLMON.DLL': b'EXURLM.DLL',
        b'URLMON.dll': b'EXURLM.dll',
        b'urlmon.dll': b'EXURLM.dll',
        b'UrlMon.dll': b'EXURLM.dll',
    }},
    
    # NETAPI32
    7: {'name': 'NETAPI32', 'replacements': {
        b'NETAPI32.DLL': b'EXNETAPI.DLL',
        b'NETAPI32.dll': b'EXNETAPI.dll',
        b'netapi32.dll': b'EXNETAPI.dll',
        b'NetApi32.dll': b'EXNETAPI.dll',
        b'Netapi32.dll': b'EXNETAPI.dll',
    }},
    
    # WSOCK32
    8: {'name': 'WSOCK32', 'replacements': {
        b'WSOCK32.DLL': b'EXWS.DLL\x00\x00\x00',
        b'WSOCK32.dll': b'EXWS.dll\x00\x00\x00',
        b'wsock32.dll': b'EXWS.DLL\x00\x00\x00',
        b'Wsock32.dll': b'EXWS.DLL\x00\x00\x00',
        b'WSock32.dll': b'EXWS.DLL\x00\x00\x00',
    }},
    
    9: {'name': 'WINTRUST', 'replacements': {
        b'WINTRUST.DLL': b'EXTRUST.DLL\x00',
        b'WINTRUST.dll': b'EXTRUST.dll\x00',
        b'wintrust.dll': b'EXTRUST.dll\x00',
        b'WinTrust.dll': b'EXTRUST.dll\x00',
    }},
    
    # # DirectX 8
    # 10: {'name': 'D3D8', 'replacements': {
        # b'D3D8.DLL': b'EXD8.DLL',
        # b'D3D8.dll': b'EXD8.dll',
        # b'd3d8.dll': b'EXD8.dll',
        # b'D3d8.dll': b'EXD8.dll',
    # }},
    
    # # DirectX 9
    # 11: {'name': 'D3D9', 'replacements': {
        # b'D3D9.DLL': b'EXD9.DLL',
        # b'D3D9.dll': b'EXD9.dll',
        # b'd3d9.dll': b'EXD9.dll',
        # b'D3d9.dll': b'EXD9.dll',
    # }},
    
    # # D3D10Core
    # 12: {'name': 'D3D10CORE', 'replacements': {
        # b'D3D10CORE.DLL': b'EXD10CORE.DLL',
        # b'D3D10CORE.dll': b'EXD10CORE.dll',
        # b'd3d10core.dll': b'EXD10CORE.dll',
        # b'D3d10core.dll': b'EXD10CORE.dll',
        # b'D3D10Core.dll': b'EXD10CORE.dll',
    # }},
    
    # # DirectX 11
    # 13: {'name': 'D3D11', 'replacements': {
        # b'D3D11.DLL': b'EXD11.DLL',
        # b'D3D11.dll': b'EXD11.dll',
        # b'd3d11.dll': b'EXD11.dll',
        # b'D3d11.dll': b'EXD11.dll',
    # }},
    
    # # DXGI (DirectX Graphics Infrastructure)
    # 14: {'name': 'DXGI', 'replacements': {
        # b'DXGI.DLL': b'EXGI.DLL',
        # b'DXGI.dll': b'EXGI.dll',
        # b'dxgi.dll': b'EXGI.dll',
        # b'Dxgi.dll': b'EXGI.dll',
    # }},

}
