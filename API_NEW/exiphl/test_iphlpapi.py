#!/usr/bin/env python3
"""
iphlpapi.DLL Diagnostic Test - Shows where it crashes
"""

import ctypes
from ctypes import wintypes
import sys
import traceback

print("="*70)
print("DIAGNOSTIC MODE - Testing each function individually")
print("="*70)

def safe_test(test_name, test_func):
    """Safely run a test and catch any errors"""
    print(f"\n{'='*70}")
    print(f">>> Testing: {test_name}")
    print(f"{'='*70}")
    try:
        result = test_func()
        print(f"✓ {test_name}: {'PASS' if result else 'FAIL'}")
        return result
    except Exception as e:
        print(f"✗ {test_name}: CRASHED")
        print(f"Error: {e}")
        traceback.print_exc()
        return False

# Simple test functions
def test_1_interfaces():
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    GetNumberOfInterfaces = iphlpapi.GetNumberOfInterfaces
    GetNumberOfInterfaces.argtypes = [ctypes.POINTER(wintypes.DWORD)]
    GetNumberOfInterfaces.restype = wintypes.DWORD
    
    num = wintypes.DWORD(0)
    result = GetNumberOfInterfaces(ctypes.byref(num))
    print(f"  Interfaces: {num.value}")
    return result == 0

def test_2_adapters_info():
    from ctypes import Structure, POINTER, c_char
    
    class IP_ADDRESS_STRING(Structure):
        _fields_ = [("String", c_char * 16)]
    
    class IP_ADDR_STRING(Structure):
        pass
    
    IP_ADDR_STRING._fields_ = [
        ("Next", POINTER(IP_ADDR_STRING)),
        ("IpAddress", IP_ADDRESS_STRING),
        ("IpMask", IP_ADDRESS_STRING),
        ("Context", wintypes.DWORD),
    ]
    
    class IP_ADAPTER_INFO(Structure):
        pass
    
    IP_ADAPTER_INFO._fields_ = [
        ("Next", POINTER(IP_ADAPTER_INFO)),
        ("ComboIndex", wintypes.DWORD),
        ("AdapterName", c_char * 260),
        ("Description", c_char * 132),
        ("AddressLength", wintypes.UINT),
        ("Address", wintypes.BYTE * 8),
        ("Index", wintypes.DWORD),
        ("Type", wintypes.UINT),
        ("DhcpEnabled", wintypes.UINT),
        ("CurrentIpAddress", POINTER(IP_ADDR_STRING)),
        ("IpAddressList", IP_ADDR_STRING),
        ("GatewayList", IP_ADDR_STRING),
        ("DhcpServer", IP_ADDR_STRING),
        ("HaveWins", wintypes.BOOL),
        ("PrimaryWinsServer", IP_ADDR_STRING),
        ("SecondaryWinsServer", IP_ADDR_STRING),
        ("LeaseObtained", wintypes.DWORD),
        ("LeaseExpires", wintypes.DWORD),
    ]
    
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    GetAdaptersInfo = iphlpapi.GetAdaptersInfo
    GetAdaptersInfo.argtypes = [POINTER(IP_ADAPTER_INFO), ctypes.POINTER(wintypes.ULONG)]
    GetAdaptersInfo.restype = wintypes.DWORD
    
    size = wintypes.ULONG(0)
    result = GetAdaptersInfo(None, ctypes.byref(size))
    print(f"  Buffer size: {size.value}")
    
    if result == 111 or result == 0:
        buffer = ctypes.create_string_buffer(size.value)
        adapter_info = ctypes.cast(buffer, POINTER(IP_ADAPTER_INFO))
        result = GetAdaptersInfo(adapter_info, ctypes.byref(size))
        print(f"  Result: {result}")
        return result == 0
    return False

def test_3_ip_addr_table():
    from ctypes import Structure, POINTER
    
    class MIB_IPADDRROW(Structure):
        _fields_ = [
            ("dwAddr", wintypes.DWORD),
            ("dwIndex", wintypes.DWORD),
            ("dwMask", wintypes.DWORD),
            ("dwBCastAddr", wintypes.DWORD),
            ("dwReasmSize", wintypes.DWORD),
            ("unused1", wintypes.USHORT),
            ("wType", wintypes.USHORT),
        ]
    
    class MIB_IPADDRTABLE(Structure):
        _fields_ = [
            ("dwNumEntries", wintypes.DWORD),
            ("table", MIB_IPADDRROW * 1),
        ]
    
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    GetIpAddrTable = iphlpapi.GetIpAddrTable
    GetIpAddrTable.argtypes = [POINTER(MIB_IPADDRTABLE), ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
    GetIpAddrTable.restype = wintypes.DWORD
    
    size = wintypes.ULONG(0)
    result = GetIpAddrTable(None, ctypes.byref(size), False)
    print(f"  Buffer size: {size.value}")
    
    if result == 122 or result == 111 or size.value > 0:
        buffer = ctypes.create_string_buffer(size.value)
        ip_table = ctypes.cast(buffer, POINTER(MIB_IPADDRTABLE))
        result = GetIpAddrTable(ip_table, ctypes.byref(size), False)
        print(f"  Result: {result}, Entries: {ip_table.contents.dwNumEntries if result == 0 else 0}")
        return result == 0
    return False

def test_4_ip_forward_table():
    from ctypes import Structure, POINTER
    
    class MIB_IPFORWARDROW(Structure):
        _fields_ = [
            ("dwForwardDest", wintypes.DWORD),
            ("dwForwardMask", wintypes.DWORD),
            ("dwForwardPolicy", wintypes.DWORD),
            ("dwForwardNextHop", wintypes.DWORD),
            ("dwForwardIfIndex", wintypes.DWORD),
            ("dwForwardType", wintypes.DWORD),
            ("dwForwardProto", wintypes.DWORD),
            ("dwForwardAge", wintypes.DWORD),
            ("dwForwardNextHopAS", wintypes.DWORD),
            ("dwForwardMetric1", wintypes.DWORD),
            ("dwForwardMetric2", wintypes.DWORD),
            ("dwForwardMetric3", wintypes.DWORD),
            ("dwForwardMetric4", wintypes.DWORD),
            ("dwForwardMetric5", wintypes.DWORD),
        ]
    
    class MIB_IPFORWARDTABLE(Structure):
        _fields_ = [
            ("dwNumEntries", wintypes.DWORD),
            ("table", MIB_IPFORWARDROW * 1),
        ]
    
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    GetIpForwardTable = iphlpapi.GetIpForwardTable
    GetIpForwardTable.argtypes = [POINTER(MIB_IPFORWARDTABLE), ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
    GetIpForwardTable.restype = wintypes.DWORD
    
    size = wintypes.ULONG(0)
    result = GetIpForwardTable(None, ctypes.byref(size), False)
    print(f"  Buffer size: {size.value}")
    
    if result == 122 or result == 111 or size.value > 0:
        buffer = ctypes.create_string_buffer(size.value)
        table = ctypes.cast(buffer, POINTER(MIB_IPFORWARDTABLE))
        result = GetIpForwardTable(table, ctypes.byref(size), False)
        print(f"  Result: {result}, Entries: {table.contents.dwNumEntries if result == 0 else 0}")
        return result == 0
    return False

def test_5_network_params():
    from ctypes import Structure, POINTER, c_char
    
    class IP_ADDRESS_STRING(Structure):
        _fields_ = [("String", c_char * 16)]
    
    class IP_ADDR_STRING(Structure):
        pass
    
    IP_ADDR_STRING._fields_ = [
        ("Next", POINTER(IP_ADDR_STRING)),
        ("IpAddress", IP_ADDRESS_STRING),
        ("IpMask", IP_ADDRESS_STRING),
        ("Context", wintypes.DWORD),
    ]
    
    class FIXED_INFO(Structure):
        _fields_ = [
            ("HostName", c_char * 132),
            ("DomainName", c_char * 132),
            ("CurrentDnsServer", POINTER(IP_ADDR_STRING)),
            ("DnsServerList", IP_ADDR_STRING),
            ("NodeType", wintypes.UINT),
            ("ScopeId", c_char * 260),
            ("EnableRouting", wintypes.UINT),
            ("EnableProxy", wintypes.UINT),
            ("EnableDns", wintypes.UINT),
        ]
    
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    GetNetworkParams = iphlpapi.GetNetworkParams
    GetNetworkParams.argtypes = [POINTER(FIXED_INFO), ctypes.POINTER(wintypes.ULONG)]
    GetNetworkParams.restype = wintypes.DWORD
    
    size = wintypes.ULONG(0)
    result = GetNetworkParams(None, ctypes.byref(size))
    print(f"  Buffer size: {size.value}")
    
    if result == 111 or result == 0:
        buffer = ctypes.create_string_buffer(size.value)
        info = ctypes.cast(buffer, POINTER(FIXED_INFO))
        result = GetNetworkParams(info, ctypes.byref(size))
        print(f"  Result: {result}")
        return result == 0
    return False

def test_6_tcp_table():
    from ctypes import Structure, POINTER
    
    class MIB_TCPROW(Structure):
        _fields_ = [
            ("dwState", wintypes.DWORD),
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwRemoteAddr", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
        ]
    
    class MIB_TCPTABLE(Structure):
        _fields_ = [
            ("dwNumEntries", wintypes.DWORD),
            ("table", MIB_TCPROW * 1),
        ]
    
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    GetTcpTable = iphlpapi.GetTcpTable
    GetTcpTable.argtypes = [POINTER(MIB_TCPTABLE), ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
    GetTcpTable.restype = wintypes.DWORD
    
    size = wintypes.ULONG(0)
    result = GetTcpTable(None, ctypes.byref(size), False)
    print(f"  Buffer size: {size.value}")
    
    if result == 122 or result == 111 or size.value > 0:
        buffer = ctypes.create_string_buffer(size.value)
        table = ctypes.cast(buffer, POINTER(MIB_TCPTABLE))
        result = GetTcpTable(table, ctypes.byref(size), False)
        print(f"  Result: {result}, Entries: {table.contents.dwNumEntries if result == 0 else 0}")
        return result == 0
    return False

def test_7_udp_table():
    from ctypes import Structure, POINTER
    
    class MIB_UDPROW(Structure):
        _fields_ = [
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
        ]
    
    class MIB_UDPTABLE(Structure):
        _fields_ = [
            ("dwNumEntries", wintypes.DWORD),
            ("table", MIB_UDPROW * 1),
        ]
    
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    GetUdpTable = iphlpapi.GetUdpTable
    GetUdpTable.argtypes = [POINTER(MIB_UDPTABLE), ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
    GetUdpTable.restype = wintypes.DWORD
    
    size = wintypes.ULONG(0)
    result = GetUdpTable(None, ctypes.byref(size), False)
    print(f"  Buffer size: {size.value}")
    
    if result == 122 or result == 111 or size.value > 0:
        buffer = ctypes.create_string_buffer(size.value)
        table = ctypes.cast(buffer, POINTER(MIB_UDPTABLE))
        result = GetUdpTable(table, ctypes.byref(size), False)
        print(f"  Result: {result}, Entries: {table.contents.dwNumEntries if result == 0 else 0}")
        return result == 0
    return False

def test_8_icmp():
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    
    IcmpCreateFile = iphlpapi.IcmpCreateFile
    IcmpCreateFile.argtypes = []
    IcmpCreateFile.restype = wintypes.HANDLE
    
    handle = IcmpCreateFile()
    print(f"  Handle: 0x{handle:X}")
    
    if handle and handle != wintypes.HANDLE(-1).value:
        IcmpCloseHandle = iphlpapi.IcmpCloseHandle
        IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        IcmpCloseHandle.restype = wintypes.BOOL
        
        result = IcmpCloseHandle(handle)
        print(f"  Closed: {result}")
        return True
    return False

def test_9_send_arp():
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    
    SendARP = iphlpapi.SendARP
    SendARP.argtypes = [
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.ULONG)
    ]
    SendARP.restype = wintypes.DWORD
    
    import struct
    dest_ip = struct.unpack('<L', bytes([192, 168, 1, 1]))[0]
    mac_addr = (ctypes.c_ubyte * 6)()
    mac_len = wintypes.ULONG(6)
    
    result = SendARP(dest_ip, 0, ctypes.byref(mac_addr), ctypes.byref(mac_len))
    print(f"  Result: {result} (expected failure in no-internet mode)")
    return True  # Consider it pass even if fails

def test_10_posix():
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    
    # Test if_indextoname
    print("  Testing if_indextoname...")
    if_indextoname = iphlpapi.if_indextoname
    if_indextoname.argtypes = [wintypes.ULONG, ctypes.c_char_p]
    if_indextoname.restype = ctypes.c_char_p
    
    name_buffer = ctypes.create_string_buffer(256)
    result = if_indextoname(1, name_buffer)
    print(f"    Result: {result}")
    
    # Test if_nametoindex
    print("  Testing if_nametoindex...")
    if_nametoindex = iphlpapi.if_nametoindex
    if_nametoindex.argtypes = [ctypes.c_char_p]
    if_nametoindex.restype = wintypes.ULONG
    
    index = if_nametoindex(b"ethernet_0")
    print(f"    Index: {index}")
    
    return True

def test_11_statistics():
    from ctypes import Structure, POINTER
    
    class MIB_IPSTATS(Structure):
        _fields_ = [
            ("dwForwarding", wintypes.DWORD),
            ("dwDefaultTTL", wintypes.DWORD),
            ("dwInReceives", wintypes.DWORD),
            ("dwInHdrErrors", wintypes.DWORD),
            ("dwInAddrErrors", wintypes.DWORD),
            ("dwForwDatagrams", wintypes.DWORD),
            ("dwInUnknownProtos", wintypes.DWORD),
            ("dwInDiscards", wintypes.DWORD),
            ("dwInDelivers", wintypes.DWORD),
            ("dwOutRequests", wintypes.DWORD),
            ("dwRoutingDiscards", wintypes.DWORD),
            ("dwOutDiscards", wintypes.DWORD),
            ("dwOutNoRoutes", wintypes.DWORD),
            ("dwReasmTimeout", wintypes.DWORD),
            ("dwReasmReqds", wintypes.DWORD),
            ("dwReasmOks", wintypes.DWORD),
            ("dwReasmFails", wintypes.DWORD),
            ("dwFragOks", wintypes.DWORD),
            ("dwFragFails", wintypes.DWORD),
            ("dwFragCreates", wintypes.DWORD),
            ("dwNumIf", wintypes.DWORD),
            ("dwNumAddr", wintypes.DWORD),
            ("dwNumRoutes", wintypes.DWORD),
        ]
    
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    GetIpStatistics = iphlpapi.GetIpStatistics
    GetIpStatistics.argtypes = [POINTER(MIB_IPSTATS)]
    GetIpStatistics.restype = wintypes.DWORD
    
    stats = MIB_IPSTATS()
    result = GetIpStatistics(ctypes.byref(stats))
    print(f"  Result: {result}, NumIf: {stats.dwNumIf if result == 0 else 0}")
    return result == 0

def test_12_convert_mask():
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    
    # Test ConvertLengthToIpv4Mask
    print("  Testing ConvertLengthToIpv4Mask...")
    ConvertLengthToIpv4Mask = iphlpapi.ConvertLengthToIpv4Mask
    ConvertLengthToIpv4Mask.argtypes = [wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)]
    ConvertLengthToIpv4Mask.restype = wintypes.DWORD
    
    test_cases = [
        (0, 0x00000000),   # /0  = 0.0.0.0
        (8, 0x000000FF),   # /8  = 255.0.0.0
        (16, 0x0000FFFF),  # /16 = 255.255.0.0
        (24, 0x00FFFFFF),  # /24 = 255.255.255.0
        (32, 0xFFFFFFFF),  # /32 = 255.255.255.255
    ]
    
    all_ok = True
    for prefix_len, expected_mask in test_cases:
        mask = wintypes.ULONG(0)
        result = ConvertLengthToIpv4Mask(prefix_len, ctypes.byref(mask))
        
        if result == 0:
            # Convert to readable format
            import struct, socket
            mask_str = socket.inet_ntoa(struct.pack('<L', mask.value))
            print(f"    /{prefix_len} -> {mask_str} (0x{mask.value:08X})")
            
            if mask.value != expected_mask:
                print(f"      ⚠ WARNING: Expected 0x{expected_mask:08X}")
                all_ok = False
        else:
            print(f"    /{prefix_len} -> ERROR {result}")
            all_ok = False
    
    # Test ConvertIpv4MaskToLength (reverse)
    print("  Testing ConvertIpv4MaskToLength...")
    ConvertIpv4MaskToLength = iphlpapi.ConvertIpv4MaskToLength
    ConvertIpv4MaskToLength.argtypes = [wintypes.ULONG, ctypes.POINTER(ctypes.c_uint8)]
    ConvertIpv4MaskToLength.restype = wintypes.DWORD
    
    test_masks = [
        (0x000000FF, 8),   # 255.0.0.0 -> /8
        (0x0000FFFF, 16),  # 255.255.0.0 -> /16
        (0x00FFFFFF, 24),  # 255.255.255.0 -> /24
    ]
    
    for mask_val, expected_len in test_masks:
        length = ctypes.c_uint8(0)
        result = ConvertIpv4MaskToLength(mask_val, ctypes.byref(length))
        
        if result == 0:
            import struct, socket
            mask_str = socket.inet_ntoa(struct.pack('<L', mask_val))
            print(f"    {mask_str} -> /{length.value}")
            
            if length.value != expected_len:
                print(f"      ⚠ WARNING: Expected /{expected_len}")
                all_ok = False
        else:
            print(f"    Mask 0x{mask_val:08X} -> ERROR {result}")
            all_ok = False
    
    return all_ok

def test_13_convert_interface():
    from ctypes import Union, Structure, POINTER
    
    # NET_LUID structure
    class NET_LUID(Union):
        class _Info(Structure):
            _fields_ = [
                ("Reserved", ctypes.c_ulonglong, 24),
                ("NetLuidIndex", ctypes.c_ulonglong, 24),
                ("IfType", ctypes.c_ulonglong, 16),
            ]
        _fields_ = [
            ("Value", ctypes.c_ulonglong),
            ("Info", _Info),
        ]
    
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    
    # Test ConvertInterfaceIndexToLuid
    print("  Testing ConvertInterfaceIndexToLuid...")
    ConvertInterfaceIndexToLuid = iphlpapi.ConvertInterfaceIndexToLuid
    ConvertInterfaceIndexToLuid.argtypes = [wintypes.ULONG, POINTER(NET_LUID)]
    ConvertInterfaceIndexToLuid.restype = wintypes.DWORD
    
    luid = NET_LUID()
    result = ConvertInterfaceIndexToLuid(1, ctypes.byref(luid))
    
    if result == 0:
        print(f"    Index 1 -> LUID 0x{luid.Value:016X}")
        print(f"      IfType: {luid.Info.IfType}")
        print(f"      NetLuidIndex: {luid.Info.NetLuidIndex}")
        
        # Test reverse conversion
        print("  Testing ConvertInterfaceLuidToIndex...")
        ConvertInterfaceLuidToIndex = iphlpapi.ConvertInterfaceLuidToIndex
        ConvertInterfaceLuidToIndex.argtypes = [POINTER(NET_LUID), ctypes.POINTER(wintypes.ULONG)]
        ConvertInterfaceLuidToIndex.restype = wintypes.DWORD
        
        index = wintypes.ULONG(0)
        result2 = ConvertInterfaceLuidToIndex(ctypes.byref(luid), ctypes.byref(index))
        
        if result2 == 0:
            print(f"    LUID 0x{luid.Value:016X} -> Index {index.value}")
            return index.value == 1  # Should match original
        else:
            print(f"    ERROR: {result2}")
            return False
    else:
        print(f"    ERROR: {result}")
        return False

def test_14_convert_guid():
    from ctypes import Structure, POINTER
    import ctypes
    
    iphlpapi = ctypes.WinDLL('iphlpapi.dll')
    
    # Test ConvertGuidToStringW
    print("  Testing ConvertGuidToStringW...")
    
    # GUID structure
    class GUID(Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", wintypes.BYTE * 8),
        ]
    
    ConvertGuidToStringW = iphlpapi.ConvertGuidToStringW
    ConvertGuidToStringW.argtypes = [
        ctypes.POINTER(GUID),
        ctypes.c_wchar_p,
        wintypes.DWORD
    ]
    ConvertGuidToStringW.restype = wintypes.DWORD
    
    # Test GUID: {12345678-1234-1234-1234-123456789ABC}
    test_guid = GUID()
    test_guid.Data1 = 0x12345678
    test_guid.Data2 = 0x1234
    test_guid.Data3 = 0x1234
    test_guid.Data4[0] = 0x12
    test_guid.Data4[1] = 0x34
    test_guid.Data4[2] = 0x12
    test_guid.Data4[3] = 0x34
    test_guid.Data4[4] = 0x56
    test_guid.Data4[5] = 0x78
    test_guid.Data4[6] = 0x9A
    test_guid.Data4[7] = 0xBC
    
    buffer = ctypes.create_unicode_buffer(40)
    result = ConvertGuidToStringW(ctypes.byref(test_guid), buffer, 40)
    
    if result == 0:
        print(f"    GUID -> {buffer.value}")
        return True
    else:
        print(f"    ERROR: {result}")
        return False

# Run all tests
def main():
    tests = [
        ("1. GetNumberOfInterfaces", test_1_interfaces),
        ("2. GetAdaptersInfo", test_2_adapters_info),
        ("3. GetIpAddrTable", test_3_ip_addr_table),
        ("4. GetIpForwardTable", test_4_ip_forward_table),
        ("5. GetNetworkParams", test_5_network_params),
        ("6. GetTcpTable", test_6_tcp_table),
        ("7. GetUdpTable", test_7_udp_table),
        ("8. ICMP Functions", test_8_icmp),
        ("9. SendARP", test_9_send_arp),
        ("10. POSIX Functions", test_10_posix),
        ("11. GetIpStatistics", test_11_statistics),
        ("12. ConvertLengthToIpv4Mask / ConvertIpv4MaskToLength", test_12_convert_mask),
        ("13. ConvertInterfaceIndexToLuid / ConvertInterfaceLuidToIndex", test_13_convert_interface),
        ("14. ConvertGuidToStringW", test_14_convert_guid),
    ]
    
    results = {}
    for name, func in tests:
        results[name] = safe_test(name, func)
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status} - {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    print("="*70)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFATAL ERROR: {e}")
        traceback.print_exc()
        sys.exit(1)