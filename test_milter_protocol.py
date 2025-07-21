#!/usr/bin/env python3
"""
Simple test script to simulate sendmail/postfix connecting to the FOFF milter
and sending a basic email transaction.
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

def test_milter():
    """Test the milter with a simulated email transaction"""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    
    try:
        print("Connecting to milter socket...")
        sock.connect('/tmp/foff-milter.sock')
        print("Connected successfully!")
        
        # Option negotiation
        print("\n1. Option negotiation...")
        send_command(sock, b'O', b'\x00\x00\x00\x00\x00\x00\x00\x00')
        read_response(sock)
        
        # Connect
        print("\n2. Connection...")
        send_command(sock, b'C', b'service.mail.cn\x00')
        read_response(sock)
        
        # HELO
        print("\n3. HELO...")
        send_command(sock, b'H', b'service.mail.cn\x00')
        read_response(sock)
        
        # MAIL FROM
        print("\n4. MAIL FROM...")
        send_command(sock, b'M', b'<spam@service.mail.cn>\x00')
        read_response(sock)
        
        # RCPT TO
        print("\n5. RCPT TO...")
        send_command(sock, b'R', b'<user@example.com>\x00')
        read_response(sock)
        
        # Headers
        print("\n6. Headers...")
        send_command(sock, b'L', b'Subject\x00\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf\x00')  # Japanese "hello"
        read_response(sock)
        
        send_command(sock, b'L', b'X-Mailer\x00service.mail.cn v2.1\x00')
        read_response(sock)
        
        # End of headers - this should trigger rule evaluation
        print("\n7. End of headers (rule evaluation)...")
        send_command(sock, b'N', b'')
        cmd, data = read_response(sock)
        
        if cmd == b'y':  # SMFIR_REPLYCODE (reject)
            print(f"✓ Message REJECTED: {data.decode('utf-8', errors='ignore')}")
        elif cmd == b'h':  # SMFIR_ADDHEADER (tag as spam)
            print(f"✓ Message TAGGED with header: {data.decode('utf-8', errors='ignore')}")
        elif cmd == b'c':  # SMFIR_CONTINUE (accept)
            print("✓ Message ACCEPTED")
        else:
            print(f"? Unknown response: {cmd}")
        
        # End of body
        print("\n8. End of body...")
        send_command(sock, b'E', b'')
        read_response(sock)
        
        # Quit
        print("\n9. Quit...")
        send_command(sock, b'Q', b'')
        
        print("\nTest completed successfully!")
        
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        sock.close()
    
    return True

if __name__ == '__main__':
    print("FOFF Milter Protocol Test")
    print("=" * 40)
    
    # Wait a moment for milter to start if needed
    time.sleep(1)
    
    if test_milter():
        print("\n✓ Milter protocol test PASSED")
        sys.exit(0)
    else:
        print("\n✗ Milter protocol test FAILED")
        sys.exit(1)
