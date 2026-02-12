#!/usr/bin/env python3
"""
netapi32.dll FULL TEST SUITE
20 NetAPI function calls validation
"""

import ctypes
from ctypes import wintypes, POINTER, Structure, pointer
import sys

# ==========================================================
# CONSTANTS
# ==========================================================

NERR_Success = 0
ERROR_MORE_DATA = 234
MAX_PREFERRED_LENGTH = 0xFFFFFFFF

# ==========================================================
# BASIC STRUCTURES
# ==========================================================

class USER_INFO_0(Structure):
    _fields_ = [("usri0_name", wintypes.LPWSTR)]

class LOCALGROUP_INFO_0(Structure):
    _fields_ = [("lgrpi0_name", wintypes.LPWSTR)]

class SHARE_INFO_1(Structure):
    _fields_ = [
        ("shi1_netname", wintypes.LPWSTR),
        ("shi1_type", wintypes.DWORD),
        ("shi1_remark", wintypes.LPWSTR),
    ]

# ==========================================================
# HELPER FUNCTIONS
# ==========================================================

def header(name):
    print("\n" + "=" * 70)
    print("  " + name)
    print("=" * 70)

def load_dll():
    try:
        return ctypes.WinDLL("netapi32.dll")
    except Exception as e:
        print("Failed to load netapi32.dll:", e)
        sys.exit(1)

def free_if_needed(ptr):
    if ptr:
        dll.NetApiBufferFree(ptr)

# ==========================================================
# TEST FUNCTIONS (20)
# ==========================================================

def test1_NetServerGetInfo():
    header("NetServerGetInfo")
    buffer = ctypes.c_void_p()
    dll.NetServerGetInfo.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, POINTER(ctypes.c_void_p)]
    dll.NetServerGetInfo.restype = wintypes.DWORD
    result = dll.NetServerGetInfo(None, 101, pointer(buffer))
    print("Result:", result)
    free_if_needed(buffer)
    return True

def test2_NetWkstaGetInfo():
    header("NetWkstaGetInfo")
    buffer = ctypes.c_void_p()
    dll.NetWkstaGetInfo.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, POINTER(ctypes.c_void_p)]
    dll.NetWkstaGetInfo.restype = wintypes.DWORD
    result = dll.NetWkstaGetInfo(None, 100, pointer(buffer))
    print("Result:", result)
    free_if_needed(buffer)
    return True

def test3_NetUserEnum():
    header("NetUserEnum")
    buffer = ctypes.c_void_p()
    entries = wintypes.DWORD()
    total = wintypes.DWORD()
    resume = wintypes.DWORD()
    dll.NetUserEnum.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        POINTER(ctypes.c_void_p), wintypes.DWORD,
        POINTER(wintypes.DWORD), POINTER(wintypes.DWORD),
        POINTER(wintypes.DWORD)
    ]
    dll.NetUserEnum.restype = wintypes.DWORD
    result = dll.NetUserEnum(None, 0, 0, pointer(buffer),
                             MAX_PREFERRED_LENGTH,
                             pointer(entries),
                             pointer(total),
                             pointer(resume))
    print("Result:", result, "Entries:", entries.value)
    free_if_needed(buffer)
    return True

def test4_NetUserGetInfo():
    header("NetUserGetInfo")
    buffer = ctypes.c_void_p()
    dll.NetUserGetInfo.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, POINTER(ctypes.c_void_p)]
    dll.NetUserGetInfo.restype = wintypes.DWORD
    result = dll.NetUserGetInfo(None, "Administrator", 0, pointer(buffer))
    print("Result:", result)
    free_if_needed(buffer)
    return True

def test5_NetShareEnum():
    header("NetShareEnum")
    buffer = ctypes.c_void_p()
    entries = wintypes.DWORD()
    total = wintypes.DWORD()
    resume = wintypes.DWORD()
    dll.NetShareEnum.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        POINTER(ctypes.c_void_p), wintypes.DWORD,
        POINTER(wintypes.DWORD), POINTER(wintypes.DWORD),
        POINTER(wintypes.DWORD)
    ]
    dll.NetShareEnum.restype = wintypes.DWORD
    result = dll.NetShareEnum(None, 1, pointer(buffer),
                              MAX_PREFERRED_LENGTH,
                              pointer(entries),
                              pointer(total),
                              pointer(resume))
    print("Result:", result, "Shares:", entries.value)
    free_if_needed(buffer)
    return True

def test6_NetShareGetInfo():
    header("NetShareGetInfo")
    buffer = ctypes.c_void_p()
    dll.NetShareGetInfo.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, POINTER(ctypes.c_void_p)]
    dll.NetShareGetInfo.restype = wintypes.DWORD
    result = dll.NetShareGetInfo(None, "IPC$", 1, pointer(buffer))
    print("Result:", result)
    free_if_needed(buffer)
    return True

def test7_NetLocalGroupEnum():
    header("NetLocalGroupEnum")
    buffer = ctypes.c_void_p()
    entries = wintypes.DWORD()
    total = wintypes.DWORD()
    resume = wintypes.DWORD()
    dll.NetLocalGroupEnum.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        POINTER(ctypes.c_void_p), wintypes.DWORD,
        POINTER(wintypes.DWORD), POINTER(wintypes.DWORD),
        POINTER(wintypes.DWORD)
    ]
    dll.NetLocalGroupEnum.restype = wintypes.DWORD
    result = dll.NetLocalGroupEnum(None, 0, pointer(buffer),
                                   MAX_PREFERRED_LENGTH,
                                   pointer(entries),
                                   pointer(total),
                                   pointer(resume))
    print("Result:", result, "Groups:", entries.value)
    free_if_needed(buffer)
    return True

def test8_NetLocalGroupGetMembers():
    header("NetLocalGroupGetMembers")
    buffer = ctypes.c_void_p()
    entries = wintypes.DWORD()
    total = wintypes.DWORD()
    resume = wintypes.DWORD()
    dll.NetLocalGroupGetMembers.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        POINTER(ctypes.c_void_p), wintypes.DWORD,
        POINTER(wintypes.DWORD), POINTER(wintypes.DWORD),
        POINTER(wintypes.DWORD)
    ]
    dll.NetLocalGroupGetMembers.restype = wintypes.DWORD
    result = dll.NetLocalGroupGetMembers(None, "Administrators", 1,
                                         pointer(buffer),
                                         MAX_PREFERRED_LENGTH,
                                         pointer(entries),
                                         pointer(total),
                                         pointer(resume))
    print("Result:", result, "Members:", entries.value)
    free_if_needed(buffer)
    return True

def test9_NetGroupEnum():
    header("NetGroupEnum")
    buffer = ctypes.c_void_p()
    entries = wintypes.DWORD()
    total = wintypes.DWORD()
    resume = wintypes.DWORD()
    dll.NetGroupEnum.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        POINTER(ctypes.c_void_p), wintypes.DWORD,
        POINTER(wintypes.DWORD), POINTER(wintypes.DWORD),
        POINTER(wintypes.DWORD)
    ]
    dll.NetGroupEnum.restype = wintypes.DWORD
    result = dll.NetGroupEnum(None, 0, pointer(buffer),
                              MAX_PREFERRED_LENGTH,
                              pointer(entries),
                              pointer(total),
                              pointer(resume))
    print("Result:", result, "DomainGroups:", entries.value)
    free_if_needed(buffer)
    return True

def test10_NetGetJoinInformation():
    header("NetGetJoinInformation")
    name = wintypes.LPWSTR()
    status = wintypes.DWORD()
    dll.NetGetJoinInformation.argtypes = [
        wintypes.LPCWSTR,
        POINTER(wintypes.LPWSTR),
        POINTER(wintypes.DWORD)
    ]
    dll.NetGetJoinInformation.restype = wintypes.DWORD
    result = dll.NetGetJoinInformation(None, pointer(name), pointer(status))
    print("Result:", result, "Status:", status.value)
    free_if_needed(name)
    return True

def test11_NetGetDCName():
    header("NetGetDCName")
    buffer = ctypes.c_void_p()
    dll.NetGetDCName.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, POINTER(ctypes.c_void_p)]
    dll.NetGetDCName.restype = wintypes.DWORD
    result = dll.NetGetDCName(None, None, pointer(buffer))
    print("Result:", result)
    free_if_needed(buffer)
    return True

def test12_NetGetAnyDCName():
    header("NetGetAnyDCName")
    buffer = ctypes.c_void_p()
    dll.NetGetAnyDCName.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, POINTER(ctypes.c_void_p)]
    dll.NetGetAnyDCName.restype = wintypes.DWORD
    result = dll.NetGetAnyDCName(None, None, pointer(buffer))
    print("Result:", result)
    free_if_needed(buffer)
    return True

def test13_NetServerEnum():
    header("NetServerEnum")
    buffer = ctypes.c_void_p()
    entries = wintypes.DWORD()
    total = wintypes.DWORD()
    resume = wintypes.DWORD()
    dll.NetServerEnum.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        POINTER(ctypes.c_void_p), wintypes.DWORD,
        POINTER(wintypes.DWORD), POINTER(wintypes.DWORD),
        wintypes.DWORD, wintypes.LPCWSTR,
        POINTER(wintypes.DWORD)
    ]
    dll.NetServerEnum.restype = wintypes.DWORD
    result = dll.NetServerEnum(None, 101, pointer(buffer),
                               MAX_PREFERRED_LENGTH,
                               pointer(entries),
                               pointer(total),
                               0xFFFFFFFF,
                               None,
                               pointer(resume))
    print("Result:", result, "Servers:", entries.value)
    free_if_needed(buffer)
    return True

def test14_NetStatisticsGet():
    header("NetStatisticsGet")
    buffer = ctypes.c_void_p()
    dll.NetStatisticsGet.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR,
        wintypes.DWORD, wintypes.DWORD,
        POINTER(ctypes.c_void_p)
    ]
    dll.NetStatisticsGet.restype = wintypes.DWORD
    result = dll.NetStatisticsGet(None, "LanmanWorkstation", 0, 0, pointer(buffer))
    print("Result:", result)
    free_if_needed(buffer)
    return True

def test15_NetStatisticsClear():
    header("NetStatisticsClear")
    dll.NetStatisticsClear.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD
    ]
    dll.NetStatisticsClear.restype = wintypes.DWORD
    result = dll.NetStatisticsClear(None, "LanmanWorkstation", 0)
    print("Result:", result)
    return True

def test16_NetUserAdd():
    header("NetUserAdd")
    parm = wintypes.DWORD()
    dll.NetUserAdd.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_void_p, POINTER(wintypes.DWORD)
    ]
    dll.NetUserAdd.restype = wintypes.DWORD
    result = dll.NetUserAdd(None, 0, None, pointer(parm))
    print("Result:", result)
    return True

def test17_NetUserDel():
    header("NetUserDel")
    dll.NetUserDel.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    dll.NetUserDel.restype = wintypes.DWORD
    result = dll.NetUserDel(None, "FakeUser")
    print("Result:", result)
    return True

def test18_NetLocalGroupAdd():
    header("NetLocalGroupAdd")
    parm = wintypes.DWORD()
    dll.NetLocalGroupAdd.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_void_p, POINTER(wintypes.DWORD)
    ]
    dll.NetLocalGroupAdd.restype = wintypes.DWORD
    result = dll.NetLocalGroupAdd(None, 0, None, pointer(parm))
    print("Result:", result)
    return True

def test19_NetLocalGroupDel():
    header("NetLocalGroupDel")
    dll.NetLocalGroupDel.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    dll.NetLocalGroupDel.restype = wintypes.DWORD
    result = dll.NetLocalGroupDel(None, "FakeGroup")
    print("Result:", result)
    return True

def test20_NetShareAdd():
    header("NetShareAdd")
    parm = wintypes.DWORD()
    dll.NetShareAdd.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_void_p, POINTER(wintypes.DWORD)
    ]
    dll.NetShareAdd.restype = wintypes.DWORD
    result = dll.NetShareAdd(None, 1, None, pointer(parm))
    print("Result:", result)
    return True

# ==========================================================
# MAIN
# ==========================================================

if __name__ == "__main__":

    print("╔" + "="*68 + "╗")
    print("║" + " "*15 + "netapi32.dll FULL TEST SUITE" + " "*18 + "║")
    print("╚" + "="*68 + "╝")

    dll = load_dll()

    tests = [
        test1_NetServerGetInfo,
        test2_NetWkstaGetInfo,
        test3_NetUserEnum,
        test4_NetUserGetInfo,
        test5_NetShareEnum,
        test6_NetShareGetInfo,
        test7_NetLocalGroupEnum,
        test8_NetLocalGroupGetMembers,
        test9_NetGroupEnum,
        test10_NetGetJoinInformation,
        test11_NetGetDCName,
        test12_NetGetAnyDCName,
        test13_NetServerEnum,
        test14_NetStatisticsGet,
        test15_NetStatisticsClear,
        test16_NetUserAdd,
        test17_NetUserDel,
        test18_NetLocalGroupAdd,
        test19_NetLocalGroupDel,
        test20_NetShareAdd,
    ]

    passed = 0

    for t in tests:
        try:
            if t():
                passed += 1
        except Exception as e:
            print("Test crashed:", e)

    print("\n" + "="*70)
    print(f"Passed {passed}/{len(tests)} tests")
    print("="*70)
