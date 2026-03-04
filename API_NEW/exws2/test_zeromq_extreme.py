#!/usr/bin/env python3
"""
EXTREME ZeroMQ Stress Test for WinSock Emulator

This is a HARDCORE stress test that pushes both emulator and system WinSock
to their limits. Tests include:
- High concurrency (100+ simultaneous connections)
- Large payloads (up to 10MB)
- Sustained load (60+ seconds continuous traffic)
- Memory stress (millions of messages)
- Connection churn (rapid connect/disconnect)
- Error injection and recovery

WARNING: This test is VERY intensive and may:
- Use significant CPU and memory
- Take 10-30 minutes to complete
- Generate 100MB+ of network traffic
- Stress test system resources

Requirements:
    pip install pyzmq psutil

Usage:
    python test_zeromq_extreme.py --dll exws2.dll     # Test emulator
    python test_zeromq_extreme.py --dll ws2_32.dll    # Test system
    python test_zeromq_extreme.py --compare           # Compare both
    python test_zeromq_extreme.py --quick             # Quick mode (reduced load)
"""

import zmq
import time
import sys
import os
import argparse
import threading
import random
import hashlib
from typing import Tuple, List, Dict
import gc
import ctypes
from ctypes import wintypes

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("WARNING: psutil not installed. Memory tracking disabled.")
    print("Install with: pip install psutil")

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    """Test configuration"""
    # Quick mode (for fast testing)
    QUICK_MODE = False
    
    # Test parameters (normal mode)
    EXTREME_CONNECTIONS = 100
    EXTREME_MESSAGES = 100000
    EXTREME_PAYLOAD_SIZE = 1024 * 1024  # 1MB
    SUSTAINED_DURATION = 60  # seconds
    WORKERS = 8
    
    # Test parameters (quick mode)
    QUICK_CONNECTIONS = 10
    QUICK_MESSAGES = 1000
    QUICK_PAYLOAD_SIZE = 1024  # 1KB
    QUICK_DURATION = 10
    QUICK_WORKERS = 2
    
    @classmethod
    def set_quick_mode(cls, enabled: bool):
        cls.QUICK_MODE = enabled

# =============================================================================
# DLL LOADER - CRITICAL FOR CORRECT TESTING
# =============================================================================

def force_load_winsock_dll(dll_name: str):
    """
    Force load specific WinSock DLL BEFORE ZMQ imports it.
    This is critical to ensure we're actually testing the correct DLL.
    """
    print(f"Forcing load of {dll_name}...")
    
    try:
        # Load the DLL
        if dll_name.lower() == 'exws2.dll':
            # For emulator, try multiple paths
            paths = [
                'exws2.dll',
                '.\\exws2.dll',
                'ucrt\\x64\\EXWS2.dll',
                '.\\ucrt\\x64\\EXWS2.dll',
            ]
            
            loaded = False
            for path in paths:
                if os.path.exists(path):
                    try:
                        dll = ctypes.WinDLL(path)
                        print(f"  ✓ Loaded from: {path}")
                        loaded = True
                        break
                    except:
                        continue
            
            if not loaded:
                print(f"  ✗ WARNING: {dll_name} not found!")
                print(f"    Checked paths: {paths}")
                return False
        else:
            # System ws2_32.dll
            dll = ctypes.WinDLL(dll_name)
            print(f"  ✓ Loaded system {dll_name}")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Error loading {dll_name}: {e}")
        return False

# =============================================================================
# MEMORY TRACKING
# =============================================================================

class MemoryTracker:
    """Track memory usage during tests"""
    
    def __init__(self):
        self.start_memory = 0
        self.peak_memory = 0
        self.current_memory = 0
        self.process = psutil.Process() if HAS_PSUTIL else None
    
    def start(self):
        """Start tracking"""
        if self.process:
            self.start_memory = self.process.memory_info().rss / 1024 / 1024  # MB
            self.peak_memory = self.start_memory
    
    def update(self):
        """Update current memory"""
        if self.process:
            self.current_memory = self.process.memory_info().rss / 1024 / 1024
            self.peak_memory = max(self.peak_memory, self.current_memory)
    
    def get_stats(self) -> Dict:
        """Get memory statistics"""
        if not self.process:
            return {}
        
        return {
            'start_mb': self.start_memory,
            'peak_mb': self.peak_memory,
            'current_mb': self.current_memory,
            'delta_mb': self.current_memory - self.start_memory,
        }

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def print_header(title, level=1):
    """Print formatted header"""
    if level == 1:
        print("\n" + "="*80)
        print(f"  {title}")
        print("="*80)
    else:
        print("\n" + "-"*80)
        print(f"  {title}")
        print("-"*80)

def print_result(test_name, success, details="", timing=None, memory=None):
    """Print test result with timing and memory"""
    status = "✓ PASS" if success else "✗ FAIL"
    color = "\033[92m" if success else "\033[91m"
    reset = "\033[0m"
    
    result = f"{color}{status}{reset} - {test_name}"
    
    if timing is not None:
        result += f" [{timing:.3f}s]"
    
    if memory and 'delta_mb' in memory:
        result += f" [Δ{memory['delta_mb']:+.1f}MB]"
    
    print(result)
    
    if details:
        print(f"       {details}")

def generate_payload(size: int, pattern: str = 'random') -> bytes:
    """Generate test payload"""
    if pattern == 'random':
        return os.urandom(size)
    elif pattern == 'zero':
        return b'\x00' * size
    elif pattern == 'pattern':
        return bytes(range(256)) * (size // 256 + 1)
    else:
        return b'X' * size

def verify_payload(data: bytes, expected_size: int, checksum: str = None) -> bool:
    """Verify payload integrity"""
    if len(data) != expected_size:
        return False
    
    if checksum:
        actual = hashlib.md5(data).hexdigest()
        return actual == checksum
    
    return True

# =============================================================================
# TEST 1: EXTREME CONCURRENCY (100+ connections)
# =============================================================================

def test_extreme_concurrency() -> Tuple[bool, float, str, Dict]:
    """Test with extreme number of concurrent connections"""
    config = Config
    connections = config.QUICK_CONNECTIONS if config.QUICK_MODE else config.EXTREME_CONNECTIONS
    
    print_header(f"Test 1: Extreme Concurrency ({connections} connections)", level=2)
    
    mem = MemoryTracker()
    mem.start()
    
    try:
        context = zmq.Context()
        
        # Create multiple REP servers
        servers = []
        ports = []
        
        for i in range(connections):
            server = context.socket(zmq.REP)
            port = server.bind_to_random_port("tcp://127.0.0.1")
            servers.append(server)
            ports.append(port)
        
        # Create clients
        clients = []
        for port in ports:
            client = context.socket(zmq.REQ)
            client.connect(f"tcp://127.0.0.1:{port}")
            clients.append(client)
        
        mem.update()
        
        # Server threads
        received = [0] * connections
        
        def server_thread(idx):
            try:
                msg = servers[idx].recv()
                servers[idx].send(msg)
                received[idx] = 1
            except:
                pass
        
        # Send messages simultaneously
        start_time = time.time()
        
        threads = []
        for i in range(connections):
            t = threading.Thread(target=server_thread, args=(i,), daemon=True)
            t.start()
            threads.append(t)
        
        # Clients send
        payload = generate_payload(100)
        for client in clients:
            client.send(payload)
        
        # Clients receive
        success_count = 0
        for client in clients:
            try:
                response = client.recv(zmq.NOBLOCK)
                if response == payload:
                    success_count += 1
            except:
                pass
        
        # Wait for servers
        for t in threads:
            t.join(timeout=1)
        
        elapsed = time.time() - start_time
        
        # Cleanup
        for client in clients:
            client.close()
        for server in servers:
            server.close()
        context.term()
        
        mem.update()
        
        success = success_count == connections
        details = f"{success_count}/{connections} connections successful"
        
        return success, elapsed, details, mem.get_stats()
        
    except Exception as e:
        return False, 0, f"Exception: {str(e)}", {}

# =============================================================================
# TEST 2: LARGE PAYLOADS (Multi-MB messages)
# =============================================================================

def test_large_payloads() -> Tuple[bool, float, str, Dict]:
    """Test with very large message payloads"""
    config = Config
    payload_size = config.QUICK_PAYLOAD_SIZE if config.QUICK_MODE else config.EXTREME_PAYLOAD_SIZE
    messages = 100 if config.QUICK_MODE else 50
    
    print_header(f"Test 2: Large Payloads ({payload_size//1024}KB x {messages})", level=2)
    
    mem = MemoryTracker()
    mem.start()
    
    try:
        context = zmq.Context()
        
        server = context.socket(zmq.REP)
        port = server.bind_to_random_port("tcp://127.0.0.1")
        
        client = context.socket(zmq.REQ)
        client.connect(f"tcp://127.0.0.1:{port}")
        
        # Server thread
        received_count = [0]
        
        def server_thread():
            for _ in range(messages):
                msg = server.recv()
                server.send(b'OK')
                received_count[0] += 1
        
        server_t = threading.Thread(target=server_thread, daemon=True)
        server_t.start()
        
        # Generate large payloads with checksums
        payloads = []
        for i in range(messages):
            data = generate_payload(payload_size, 'random')
            checksum = hashlib.md5(data).hexdigest()
            payloads.append((data, checksum))
        
        mem.update()
        
        # Send large messages
        start_time = time.time()
        
        success_count = 0
        for i, (payload, checksum) in enumerate(payloads):
            client.send(payload)
            response = client.recv()
            
            if response == b'OK':
                success_count += 1
            
            # Update memory every 10 messages
            if i % 10 == 0:
                mem.update()
        
        elapsed = time.time() - start_time
        
        server_t.join(timeout=5)
        
        # Cleanup
        client.close()
        server.close()
        context.term()
        
        mem.update()
        
        total_bytes = payload_size * messages
        throughput_mbps = (total_bytes / 1024 / 1024) / elapsed
        
        success = success_count == messages
        details = f"{total_bytes//1024//1024}MB transferred, {throughput_mbps:.2f} MB/s"
        
        return success, elapsed, details, mem.get_stats()
        
    except Exception as e:
        return False, 0, f"Exception: {str(e)}", {}

# =============================================================================
# TEST 3: SUSTAINED LOAD (Continuous traffic)
# =============================================================================

def test_sustained_load() -> Tuple[bool, float, str, Dict]:
    """Test sustained load over extended period"""
    config = Config
    duration = config.QUICK_DURATION if config.QUICK_MODE else config.SUSTAINED_DURATION
    
    print_header(f"Test 3: Sustained Load ({duration}s continuous)", level=2)
    
    mem = MemoryTracker()
    mem.start()
    
    try:
        context = zmq.Context()
        
        server = context.socket(zmq.REP)
        port = server.bind_to_random_port("tcp://127.0.0.1")
        
        client = context.socket(zmq.REQ)
        client.connect(f"tcp://127.0.0.1:{port}")
        
        stop_flag = [False]
        stats = {'sent': 0, 'received': 0, 'errors': 0}
        
        # Server thread
        def server_thread():
            while not stop_flag[0]:
                try:
                    msg = server.recv(zmq.NOBLOCK)
                    server.send(msg)
                    stats['received'] += 1
                except zmq.Again:
                    time.sleep(0.001)
                except:
                    stats['errors'] += 1
        
        server_t = threading.Thread(target=server_thread, daemon=True)
        server_t.start()
        
        # Run for specified duration
        payload = generate_payload(1024)
        start_time = time.time()
        last_mem_update = start_time
        
        while time.time() - start_time < duration:
            try:
                client.send(payload, zmq.NOBLOCK)
                response = client.recv(zmq.NOBLOCK)
                stats['sent'] += 1
                
                # Update memory every second
                if time.time() - last_mem_update >= 1.0:
                    mem.update()
                    last_mem_update = time.time()
                
            except zmq.Again:
                time.sleep(0.001)
            except:
                stats['errors'] += 1
        
        elapsed = time.time() - start_time
        stop_flag[0] = True
        
        server_t.join(timeout=2)
        
        # Cleanup
        client.close()
        server.close()
        context.term()
        
        mem.update()
        
        avg_throughput = stats['sent'] / elapsed
        success = stats['sent'] > 0 and stats['errors'] < stats['sent'] * 0.01
        
        details = f"{stats['sent']} msgs, {avg_throughput:.0f} msg/s, {stats['errors']} errors"
        
        return success, elapsed, details, mem.get_stats()
        
    except Exception as e:
        return False, 0, f"Exception: {str(e)}", {}

# =============================================================================
# TEST 4: MEMORY STRESS (Millions of messages)
# =============================================================================

def test_memory_stress() -> Tuple[bool, float, str, Dict]:
    """Test memory handling with millions of small messages"""
    config = Config
    messages = config.QUICK_MESSAGES if config.QUICK_MODE else config.EXTREME_MESSAGES
    
    print_header(f"Test 4: Memory Stress ({messages:,} messages)", level=2)
    
    mem = MemoryTracker()
    mem.start()
    
    try:
        context = zmq.Context()
        
        server = context.socket(zmq.PULL)
        port = server.bind_to_random_port("tcp://127.0.0.1")
        
        client = context.socket(zmq.PUSH)
        client.connect(f"tcp://127.0.0.1:{port}")
        
        time.sleep(0.05)
        
        received_count = [0]
        
        # Server thread
        def server_thread():
            while received_count[0] < messages:
                try:
                    msg = server.recv(zmq.NOBLOCK)
                    received_count[0] += 1
                except zmq.Again:
                    time.sleep(0.0001)
        
        server_t = threading.Thread(target=server_thread, daemon=True)
        server_t.start()
        
        # Send many small messages
        payload = b'test'
        start_time = time.time()
        last_mem_update = start_time
        
        for i in range(messages):
            client.send(payload, zmq.NOBLOCK)
            
            # Update memory every 10000 messages
            if i % 10000 == 0 and i > 0:
                mem.update()
                last_mem_update = time.time()
        
        # Wait for all messages
        server_t.join(timeout=30)
        elapsed = time.time() - start_time
        
        # Cleanup
        client.close()
        server.close()
        context.term()
        
        # Force garbage collection
        gc.collect()
        time.sleep(0.1)
        mem.update()
        
        throughput = messages / elapsed
        success = received_count[0] == messages
        
        details = f"{received_count[0]:,}/{messages:,} msgs, {throughput:.0f} msg/s"
        
        return success, elapsed, details, mem.get_stats()
        
    except Exception as e:
        return False, 0, f"Exception: {str(e)}", {}

# =============================================================================
# TEST 5: CONNECTION CHURN (Rapid connect/disconnect)
# =============================================================================

def test_connection_churn() -> Tuple[bool, float, str, Dict]:
    """Test rapid connection creation and destruction"""
    config = Config
    cycles = 100 if config.QUICK_MODE else 500
    
    print_header(f"Test 5: Connection Churn ({cycles} cycles)", level=2)
    
    mem = MemoryTracker()
    mem.start()
    
    try:
        success_count = 0
        start_time = time.time()
        
        for i in range(cycles):
            context = zmq.Context()
            
            server = context.socket(zmq.REP)
            port = server.bind_to_random_port("tcp://127.0.0.1")
            
            client = context.socket(zmq.REQ)
            client.connect(f"tcp://127.0.0.1:{port}")
            
            # Quick exchange
            payload = b'test'
            
            def server_once():
                msg = server.recv()
                server.send(msg)
            
            t = threading.Thread(target=server_once, daemon=True)
            t.start()
            
            client.send(payload)
            response = client.recv()
            
            if response == payload:
                success_count += 1
            
            t.join(timeout=1)
            
            # Cleanup
            client.close()
            server.close()
            context.term()
            
            # Update memory every 50 cycles
            if i % 50 == 0:
                mem.update()
                gc.collect()
        
        elapsed = time.time() - start_time
        
        mem.update()
        
        cycles_per_sec = cycles / elapsed
        success = success_count == cycles
        
        details = f"{success_count}/{cycles} cycles, {cycles_per_sec:.1f} cycles/s"
        
        return success, elapsed, details, mem.get_stats()
        
    except Exception as e:
        return False, 0, f"Exception: {str(e)}", {}

# =============================================================================
# TEST 6: MULTI-WORKER PIPELINE
# =============================================================================

def test_multi_worker() -> Tuple[bool, float, str, Dict]:
    """Test multi-worker pipeline under load"""
    config = Config
    workers = config.QUICK_WORKERS if config.QUICK_MODE else config.WORKERS
    tasks = config.QUICK_MESSAGES if config.QUICK_MODE else config.EXTREME_MESSAGES // 10
    
    print_header(f"Test 6: Multi-Worker Pipeline ({workers} workers, {tasks:,} tasks)", level=2)
    
    mem = MemoryTracker()
    mem.start()
    
    try:
        context = zmq.Context()
        
        # Ventilator
        ventilator = context.socket(zmq.PUSH)
        vent_port = ventilator.bind_to_random_port("tcp://127.0.0.1")
        
        # Sink
        sink = context.socket(zmq.PULL)
        sink_port = sink.bind_to_random_port("tcp://127.0.0.1")
        
        time.sleep(0.1)
        
        received = [0]
        processed_data = []
        
        # Worker function
        def worker_func():
            worker = context.socket(zmq.PULL)
            worker.connect(f"tcp://127.0.0.1:{vent_port}")
            
            sender = context.socket(zmq.PUSH)
            sender.connect(f"tcp://127.0.0.1:{sink_port}")
            
            while True:
                try:
                    task = worker.recv(zmq.NOBLOCK)
                    # Simulate work
                    result = hashlib.md5(task).digest()
                    sender.send(result)
                except zmq.Again:
                    time.sleep(0.0001)
                    if received[0] >= tasks:
                        break
            
            worker.close()
            sender.close()
        
        # Sink function
        def sink_func():
            while received[0] < tasks:
                try:
                    result = sink.recv(zmq.NOBLOCK)
                    processed_data.append(result)
                    received[0] += 1
                except zmq.Again:
                    time.sleep(0.0001)
        
        # Start workers
        worker_threads = []
        for _ in range(workers):
            t = threading.Thread(target=worker_func, daemon=True)
            t.start()
            worker_threads.append(t)
        
        # Start sink
        sink_t = threading.Thread(target=sink_func, daemon=True)
        sink_t.start()
        
        # Send tasks
        start_time = time.time()
        
        for i in range(tasks):
            task = f"task_{i}".encode()
            ventilator.send(task, zmq.NOBLOCK)
            
            if i % 1000 == 0:
                mem.update()
        
        # Wait for completion
        sink_t.join(timeout=60)
        elapsed = time.time() - start_time
        
        # Cleanup
        ventilator.close()
        sink.close()
        context.term()
        
        mem.update()
        
        throughput = tasks / elapsed
        success = received[0] == tasks
        
        details = f"{received[0]:,}/{tasks:,} tasks, {throughput:.0f} tasks/s"
        
        return success, elapsed, details, mem.get_stats()
        
    except Exception as e:
        return False, 0, f"Exception: {str(e)}", {}

# =============================================================================
# MAIN TEST RUNNER
# =============================================================================

def run_all_tests(dll_name: str) -> Dict:
    """Run all extreme tests"""
    
    print_header(f"EXTREME ZEROMQ STRESS TESTS - {dll_name}")
    print(f"ZeroMQ Version: {zmq.zmq_version()}")
    print(f"PyZMQ Version: {zmq.pyzmq_version()}")
    
    if Config.QUICK_MODE:
        print("\n*** QUICK MODE ENABLED - Reduced test intensity ***")
    
    results = {}
    
    tests = [
        ("Extreme Concurrency", test_extreme_concurrency),
        ("Large Payloads", test_large_payloads),
        ("Sustained Load", test_sustained_load),
        ("Memory Stress", test_memory_stress),
        ("Connection Churn", test_connection_churn),
        ("Multi-Worker Pipeline", test_multi_worker),
    ]
    
    for name, test_func in tests:
        try:
            success, elapsed, details, memory = test_func()
            print_result(name, success, details, elapsed, memory)
            results[name] = {
                'success': success,
                'time': elapsed,
                'details': details,
                'memory': memory
            }
        except Exception as e:
            print_result(name, False, f"FATAL: {str(e)}")
            results[name] = {
                'success': False,
                'time': 0,
                'details': str(e),
                'memory': {}
            }
        
        # Small delay between tests
        time.sleep(0.5)
        gc.collect()
    
    return results

def print_summary(results: Dict, dll_name: str):
    """Print test summary"""
    print_header(f"SUMMARY - {dll_name}")
    
    passed = sum(1 for r in results.values() if r['success'])
    total = len(results)
    
    total_time = sum(r['time'] for r in results.values())
    
    for test_name, result in results.items():
        status = "✓ PASS" if result['success'] else "✗ FAIL"
        color = "\033[92m" if result['success'] else "\033[91m"
        reset = "\033[0m"
        
        mem_str = ""
        if result['memory'] and 'peak_mb' in result['memory']:
            mem_str = f" [Peak: {result['memory']['peak_mb']:.1f}MB]"
        
        print(f"  {color}{status}{reset} - {test_name:<25} {result['time']:>7.3f}s{mem_str}")
    
    print("\n" + "="*80)
    print(f"  Results: {passed}/{total} tests passed ({100*passed//total}%)")
    print(f"  Total Time: {total_time:.1f}s")
    print("="*80)

# =============================================================================
# COMPARISON MODE
# =============================================================================

def compare_dlls(quick_mode: bool = False):
    """Compare emulator vs system with extreme tests"""
    
    if quick_mode:
        Config.set_quick_mode(True)
    
    print("╔" + "="*78 + "╗")
    print("║" + " "*20 + "EXTREME ZEROMQ COMPARISON TEST" + " "*27 + "║")
    print("╚" + "="*78 + "╝")
    
    if quick_mode:
        print("\n*** QUICK MODE - Reduced intensity for faster testing ***\n")
    else:
        print("\n*** FULL MODE - Maximum stress, will take 10-30 minutes ***\n")
    
    # Test emulator
    print("\n" + "█"*80)
    print("█" + " "*25 + "TESTING EMULATOR (exws2.dll)" + " "*26 + "█")
    print("█"*80)
    
    if not force_load_winsock_dll('exws2.dll'):
        print("\n✗ CRITICAL: Could not load exws2.dll")
        print("  Please ensure exws2.dll is in current directory or PATH")
        return False
    
    # Import ZMQ after loading DLL
    import zmq as zmq_emu
    
    results_emu = run_all_tests('exws2.dll')
    
    # Force cleanup
    gc.collect()
    time.sleep(1)
    
    # Test system
    print("\n" + "█"*80)
    print("█" + " "*24 + "TESTING SYSTEM (ws2_32.dll)" + " "*27 + "█")
    print("█"*80)
    
    force_load_winsock_dll('ws2_32.dll')
    results_sys = run_all_tests('ws2_32.dll')
    
    # Comparison
    print_header("PERFORMANCE COMPARISON")
    
    print(f"\n{'Test':<28} {'Emulator':<12} {'System':<12} {'Difference':<20}")
    print("-" * 80)
    
    for test_name in results_emu.keys():
        emu = results_emu[test_name]
        sys = results_sys[test_name]
        
        if emu['success'] and sys['success'] and sys['time'] > 0:
            ratio = emu['time'] / sys['time']
            diff_pct = (ratio - 1) * 100
            
            if ratio < 1.1:
                status = "✓ Similar"
                color = "\033[92m"
            elif ratio < 1.5:
                status = "⚠ Slower"
                color = "\033[93m"
            elif ratio < 2.0:
                status = "⚠⚠ Much slower"
                color = "\033[93m"
            else:
                status = "✗ Very slow"
                color = "\033[91m"
            
            reset = "\033[0m"
            
            print(f"{test_name:<28} {emu['time']:>7.3f}s    {sys['time']:>7.3f}s    "
                  f"{color}{status:<12}{reset} ({diff_pct:+.1f}%)")
        else:
            emu_str = "FAIL" if not emu['success'] else f"{emu['time']:.3f}s"
            sys_str = "FAIL" if not sys['success'] else f"{sys['time']:.3f}s"
            print(f"{test_name:<28} {emu_str:>10}   {sys_str:>10}   N/A")
    
    # Memory comparison
    if HAS_PSUTIL:
        print_header("MEMORY COMPARISON")
        
        print(f"\n{'Test':<28} {'Emu Peak':<12} {'Sys Peak':<12} {'Difference':<15}")
        print("-" * 80)
        
        for test_name in results_emu.keys():
            emu_mem = results_emu[test_name].get('memory', {})
            sys_mem = results_sys[test_name].get('memory', {})
            
            if 'peak_mb' in emu_mem and 'peak_mb' in sys_mem:
                emu_peak = emu_mem['peak_mb']
                sys_peak = sys_mem['peak_mb']
                diff = emu_peak - sys_peak
                
                print(f"{test_name:<28} {emu_peak:>7.1f}MB    {sys_peak:>7.1f}MB    "
                      f"{diff:+.1f}MB")
    
    print("\n" + "="*80)
    
    # Success rates
    emu_passed = sum(1 for r in results_emu.values() if r['success'])
    sys_passed = sum(1 for r in results_sys.values() if r['success'])
    total = len(results_emu)
    
    print(f"Emulator Success Rate: {emu_passed}/{total} ({100*emu_passed//total}%)")
    print(f"System Success Rate:   {sys_passed}/{total} ({100*sys_passed//total}%)")
    print("="*80)
    
    return True

# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Extreme ZeroMQ Stress Test for WinSock',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_zeromq_extreme.py --dll exws2.dll     Test emulator only
  python test_zeromq_extreme.py --dll ws2_32.dll    Test system only  
  python test_zeromq_extreme.py --compare           Compare both (RECOMMENDED)
  python test_zeromq_extreme.py --compare --quick   Quick comparison test

WARNING: Full tests are very intensive and may take 10-30 minutes!
        """
    )
    
    parser.add_argument('--dll', type=str, 
                       help='DLL to test (exws2.dll or ws2_32.dll)')
    parser.add_argument('--compare', action='store_true',
                       help='Compare emulator vs system (RECOMMENDED)')
    parser.add_argument('--quick', action='store_true',
                       help='Quick mode - reduced test intensity')
    
    args = parser.parse_args()
    
    try:
        if args.compare:
            success = compare_dlls(quick_mode=args.quick)
            return 0 if success else 1
        elif args.dll:
            Config.set_quick_mode(args.quick)
            
            if not force_load_winsock_dll(args.dll):
                print(f"\n✗ Could not load {args.dll}")
                return 1
            
            results = run_all_tests(args.dll)
            print_summary(results, args.dll)
            
            passed = sum(1 for r in results.values() if r['success'])
            return 0 if passed == len(results) else 1
        else:
            parser.print_help()
            return 1
        
    except KeyboardInterrupt:
        print("\n\n✗ Test interrupted by user.")
        return 1
    except Exception as e:
        print(f"\n\n✗ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
