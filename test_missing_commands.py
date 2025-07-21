#!/usr/bin/env python3
"""
Test script to verify SMFIC_MACRO and SMFIC_DATA commands work correctly.
"""

import socket
import struct
import sys
import time

def send_command(sock, command, data=b''):
    """Send a milter command with proper framing"""
    length = len(data) + 1  # +1 for command byte
    frame = struct.pack('>I', length) + command + data
    sock.send(frame)
    print(f"Sent command: {command} with {len(data)} bytes of data")

def read_response(sock):
    """Read a milter response"""
    try:
        # Read 4-byte length
        length_data = sock.recv(4)
        if len(length_data) != 4:
            return None, None
        
        length = struct.unpack('>I', length_data)[0]
        if length == 0:
            return None, None
            
        # Read response
        response_data = sock.recv(length)
        if len(response_data) != length:
            return None, None
            
        command = response_data[0:1]
        data = response_data[1:] if length > 1 else b''
        
        print(f"Received response: {command} with {len(data)} bytes of data")
        return command, data
    except Exception as e:
        print(f"Error reading response: {e}")
        return None, None

def test_missing_commands():
    """Test the previously missing commands"""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    
    try:
        print("Testing SMFIC_MACRO and SMFIC_DATA commands...")
        sock.connect('/var/run/foff-milter.sock')
        print("Connected successfully!")
        
        # Option negotiation
        print("\n1. Option negotiation...")
        send_command(sock, b'O', b'\x00\x00\x00\x06\x00\x00\x01\xff\x00\x00\x01\xff' + b'\x00' * 12)
        read_response(sock)
        
        # Connect
        print("\n2. Connection...")
        send_command(sock, b'C', b'service.engzeng.cn\x00')
        read_response(sock)
        
        # Test SMFIC_MACRO command (0x44 = 'D')
        print("\n3. Testing SMFIC_MACRO command...")
        macro_data = b'\x43' + b'j\x00hotel.baddomain.com\x00_\x00service.engzeng.cn\x00'  # Stage C (connect) macros
        send_command(sock, b'D', macro_data)
        cmd, data = read_response(sock)
        if cmd == b'c':
            print("✓ SMFIC_MACRO handled correctly")
        else:
            print(f"✗ SMFIC_MACRO failed: {cmd}")
            return False
        
        # HELO
        print("\n4. HELO...")
        send_command(sock, b'H', b'service.engzeng.cn\x00')
        read_response(sock)
        
        # MAIL FROM
        print("\n5. MAIL FROM...")
        send_command(sock, b'M', b'<order.xifrttg@service.engzeng.cn>\x00')
        read_response(sock)
        
        # RCPT TO
        print("\n6. RCPT TO...")
        send_command(sock, b'R', b'<mstowe@baddomain.com>\x00')
        read_response(sock)
        
        # Test SMFIC_DATA command (0x54 = 'T')
        print("\n7. Testing SMFIC_DATA command...")
        send_command(sock, b'T', b'')  # DATA command usually has no data
        cmd, data = read_response(sock)
        if cmd == b'c':
            print("✓ SMFIC_DATA handled correctly")
        else:
            print(f"✗ SMFIC_DATA failed: {cmd}")
            return False
        
        # Headers with Japanese content
        print("\n8. Headers...")
        send_command(sock, b'L', b'Subject\x00\xe7\x89\xb9\xe5\x88\xa5\xe3\x82\xaa\xe3\x83\x95\xe3\x82\xa1\xe3\x83\xbc\x00')  # Japanese "special offer"
        read_response(sock)
        
        send_command(sock, b'L', b'X-Mailer\x00service.engzeng.cn mailer\x00')
        read_response(sock)
        
        # End of headers - this should trigger rule evaluation
        print("\n9. End of headers (rule evaluation)...")
        send_command(sock, b'N', b'')
        cmd, data = read_response(sock)
        
        if cmd == b'y':  # SMFIR_REPLYCODE (reject)
            print(f"✓ Message REJECTED: {data.decode('utf-8', errors='ignore')}")
            return True
        elif cmd == b'c':  # SMFIR_CONTINUE (accept)
            print("✗ Message ACCEPTED (should have been rejected)")
            return False
        else:
            print(f"? Unknown response: {cmd}")
            return False
        
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        sock.close()

if __name__ == '__main__':
    print("FOFF Milter Missing Commands Test")
    print("=" * 40)
    
    time.sleep(1)
    
    if test_missing_commands():
        print("\n✓ Missing commands test PASSED")
        sys.exit(0)
    else:
        print("\n✗ Missing commands test FAILED")
        sys.exit(1)
