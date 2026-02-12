#!/usr/bin/env python3
"""
SENSAPI Emulator Test Script

This script tests the SENSAPI.DLL emulator using Python's ctypes.

Windows Error Codes Reference:
    ERROR_SUCCESS (0)              - No error
    ERROR_NETWORK_UNREACHABLE (1231) - Network is unreachable
    ERROR_HOST_UNREACHABLE (1232)  - Host is unreachable
"""

import ctypes
from ctypes import wintypes
import sys

# SENSAPI constants
NETWORK_ALIVE_LAN = 0x00000001
NETWORK_ALIVE_WAN = 0x00000002
NETWORK_ALIVE_AOL = 0x00000004
NETWORK_ALIVE_INTERNET = 0x00000008

# Windows error codes
ERROR_SUCCESS = 0
ERROR_NETWORK_UNREACHABLE = 1231
ERROR_HOST_UNREACHABLE = 1232

# QOCINFO structure
class QOCINFO(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("dwInSpeed", wintypes.DWORD),
        ("dwOutSpeed", wintypes.DWORD),
    ]

def test_is_network_alive():
    """Test IsNetworkAlive function"""
    print("\n" + "="*60)
    print("Testing IsNetworkAlive()")
    print("="*60)
    
    try:
        # Load sensapi.dll with use_last_error=True
        sensapi = ctypes.WinDLL('sensapi.dll', use_last_error=True)
        
        # Get function
        IsNetworkAlive = sensapi.IsNetworkAlive
        IsNetworkAlive.argtypes = [ctypes.POINTER(wintypes.DWORD)]
        IsNetworkAlive.restype = wintypes.BOOL
        
        # Clear last error before call
        ctypes.set_last_error(0)
        
        # Call function
        flags = wintypes.DWORD(0)
        result = IsNetworkAlive(ctypes.byref(flags))
        
        # Get last error immediately after call
        last_error = ctypes.get_last_error()
        
        print(f"Result: {result}")
        print(f"Flags: 0x{flags.value:08X}")
        print(f"GetLastError(): {last_error} (0x{last_error:08X})")
        
        # Decode error code
        if last_error == ERROR_SUCCESS:
            print(f"  Error: ERROR_SUCCESS (no error)")
        elif last_error == ERROR_NETWORK_UNREACHABLE:
            print(f"  Error: ERROR_NETWORK_UNREACHABLE")
        else:
            print(f"  Error: Unknown ({last_error})")
        
        if result:
            print("✓ Network IS ALIVE")
            if flags.value & NETWORK_ALIVE_LAN:
                print("  - LAN connection detected")
            if flags.value & NETWORK_ALIVE_WAN:
                print("  - WAN connection detected")
            if flags.value & NETWORK_ALIVE_AOL:
                print("  - AOL connection detected")
            if flags.value & NETWORK_ALIVE_INTERNET:
                print("  - Internet connection detected")
        else:
            print("✗ Network is NOT alive")
            if flags.value == 0:
                print("  - No network connections")
        
        return result
        
    except Exception as e:
        print(f"ERROR: {e}")
        return False

def test_is_destination_reachable():
    """Test IsDestinationReachableA function"""
    print("\n" + "="*60)
    print("Testing IsDestinationReachableA()")
    print("="*60)
    
    destinations = [
        "www.google.com",
        "www.microsoft.com",
        "192.168.1.1",
        "8.8.8.8",
    ]
    
    try:
        # Load sensapi.dll with use_last_error=True to enable GetLastError()
        sensapi = ctypes.WinDLL('sensapi.dll', use_last_error=True)
        
        # Get function
        IsDestinationReachableA = sensapi.IsDestinationReachableA
        IsDestinationReachableA.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(QOCINFO)
        ]
        IsDestinationReachableA.restype = wintypes.BOOL
        
        for dest in destinations:
            print(f"\nChecking: {dest}")
            
            # Prepare QOCINFO structure
            qoc = QOCINFO()
            qoc.dwSize = ctypes.sizeof(QOCINFO)
            qoc.dwFlags = 0
            qoc.dwInSpeed = 0
            qoc.dwOutSpeed = 0
            
            # Clear last error before call
            ctypes.set_last_error(0)
            
            # Call function
            result = IsDestinationReachableA(
                dest.encode('ascii'),
                ctypes.byref(qoc)
            )
            
            # Get last error immediately after call
            last_error = ctypes.get_last_error()
            
            if result:
                print(f"  ✓ Reachable")
                print(f"    Flags: 0x{qoc.dwFlags:08X}")
                print(f"    In Speed: {qoc.dwInSpeed} bps")
                print(f"    Out Speed: {qoc.dwOutSpeed} bps")
            else:
                print(f"  ✗ NOT reachable")
                print(f"    GetLastError(): {last_error} (0x{last_error:08X})")
                
                # Decode error code
                if last_error == ERROR_NETWORK_UNREACHABLE:
                    print(f"    Error name: ERROR_NETWORK_UNREACHABLE")
                    print(f"    Meaning: Network destination is unreachable")
                elif last_error == ERROR_HOST_UNREACHABLE:
                    print(f"    Error name: ERROR_HOST_UNREACHABLE")
                    print(f"    Meaning: Host destination is unreachable")
                elif last_error == ERROR_SUCCESS:
                    print(f"    Error name: ERROR_SUCCESS")
                    print(f"    Meaning: No error set (unusual for FALSE result)")
                else:
                    print(f"    Error name: Unknown error code")
        
    except Exception as e:
        print(f"ERROR: {e}")

def test_scenario_offline_app():
    """Test application scenario in offline mode"""
    print("\n" + "="*60)
    print("Scenario: Application Logic (Offline Mode)")
    print("="*60)
    
    try:
        sensapi = ctypes.WinDLL('sensapi.dll', use_last_error=True)
        IsNetworkAlive = sensapi.IsNetworkAlive
        IsNetworkAlive.argtypes = [ctypes.POINTER(wintypes.DWORD)]
        IsNetworkAlive.restype = wintypes.BOOL
        
        ctypes.set_last_error(0)
        flags = wintypes.DWORD(0)
        network_available = IsNetworkAlive(ctypes.byref(flags))
        last_error = ctypes.get_last_error()
        
        print("\nApplication startup...")
        print(f"IsNetworkAlive() = {network_available}, LastError = {last_error}")
        
        if network_available:
            print("✓ Network detected - enabling online features:")
            print("  - Syncing data to cloud")
            print("  - Checking for updates")
            print("  - Loading online content")
            print("  - Enabling multiplayer features")
        else:
            print("✗ No network - switching to offline mode:")
            print("  - Using cached data")
            print("  - Skipping update checks")
            print("  - Disabling online features")
            print("  - Running in single-player mode")
        
    except Exception as e:
        print(f"ERROR: {e}")

def test_periodic_monitoring():
    """Test periodic network state monitoring"""
    print("\n" + "="*60)
    print("Scenario: Periodic Network Monitoring")
    print("="*60)
    
    import time
    
    try:
        sensapi = ctypes.WinDLL('sensapi.dll', use_last_error=True)
        IsNetworkAlive = sensapi.IsNetworkAlive
        IsNetworkAlive.argtypes = [ctypes.POINTER(wintypes.DWORD)]
        IsNetworkAlive.restype = wintypes.BOOL
        
        print("\nMonitoring network state for 5 seconds...\n")
        
        previous_state = None
        
        for i in range(5):
            ctypes.set_last_error(0)
            flags = wintypes.DWORD(0)
            current_state = IsNetworkAlive(ctypes.byref(flags))
            last_error = ctypes.get_last_error()
            
            if current_state != previous_state:
                if current_state:
                    print(f"[{i}s] *** Network CONNECTED *** (LastError={last_error})")
                else:
                    print(f"[{i}s] *** Network DISCONNECTED *** (LastError={last_error})")
                previous_state = current_state
            else:
                state_str = "ONLINE" if current_state else "OFFLINE"
                print(f"[{i}s] Network: {state_str} (flags: 0x{flags.value:02X}, LastError={last_error})")
            
            time.sleep(1)
        
    except Exception as e:
        print(f"ERROR: {e}")

def main():
    """Main test runner"""
    print("╔" + "="*58 + "╗")
    print("║" + " "*15 + "SENSAPI EMULATOR TEST SUITE" + " "*15 + "║")
    print("╚" + "="*58 + "╝")
    
    # Run all tests
    test_is_network_alive()
    test_is_destination_reachable()
    test_scenario_offline_app()
    test_periodic_monitoring()
    
    print("\n" + "="*60)
    print("All tests completed!")
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFATAL ERROR: {e}")
        sys.exit(1)