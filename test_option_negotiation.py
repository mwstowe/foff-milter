#!/usr/bin/env python3
"""
Test script to verify option negotiation works correctly with sendmail.
"""

import socket
import struct
import sys
import time

def test_option_negotiation():
    """Test option negotiation specifically"""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    
    try:
        print("Testing option negotiation...")
        sock.connect('/var/run/foff-milter.sock')
        
        # Send option negotiation like sendmail would
        # Format: version(4) + actions(4) + protocol(4) + reserved(12)
        optneg_data = bytearray(24)
        
        # Version 6 (sendmail milter protocol version)
        struct.pack_into('>I', optneg_data, 0, 6)
        
        # Actions sendmail supports (all actions)
        struct.pack_into('>I', optneg_data, 4, 0x1FF)  # All actions
        
        # Protocol steps sendmail supports (all steps)
        struct.pack_into('>I', optneg_data, 8, 0x1FF)  # All protocol steps
        
        # Send the command
        length = len(optneg_data) + 1
        frame = struct.pack('>I', length) + b'O' + optneg_data
        sock.send(frame)
        print("Sent option negotiation request")
        
        # Read response
        length_data = sock.recv(4)
        if len(length_data) != 4:
            print("✗ Failed to read response length")
            return False
            
        length = struct.unpack('>I', length_data)[0]
        print(f"Response length: {length}")
        
        if length < 25:  # Should be at least 25 bytes (1 command + 24 data)
            print(f"✗ Response too short: {length} bytes")
            return False
            
        response_data = sock.recv(length)
        if len(response_data) != length:
            print(f"✗ Incomplete response: got {len(response_data)}, expected {length}")
            return False
            
        command = response_data[0:1]
        data = response_data[1:]
        
        if command != b'O':
            print(f"✗ Wrong response command: {command}")
            return False
            
        if len(data) != 24:
            print(f"✗ Wrong data length: {len(data)}, expected 24")
            return False
            
        # Parse the response
        version = struct.unpack('>I', data[0:4])[0]
        actions = struct.unpack('>I', data[4:8])[0]
        protocol = struct.unpack('>I', data[8:12])[0]
        
        print(f"✓ Received valid option negotiation response:")
        print(f"  Version: {version}")
        print(f"  Actions: 0x{actions:x}")
        print(f"  Protocol: 0x{protocol:x}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    finally:
        sock.close()

if __name__ == '__main__':
    time.sleep(1)
    if test_option_negotiation():
        print("✓ Option negotiation test PASSED")
        sys.exit(0)
    else:
        print("✗ Option negotiation test FAILED")
        sys.exit(1)
