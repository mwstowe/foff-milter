#!/usr/bin/env python3
"""
Test script to verify that legitimate emails are accepted by the milter.
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
        
        return command, data
    except Exception as e:
        return None, None

def test_legitimate_email():
    """Test with a legitimate email that should be accepted"""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    
    try:
        print("Testing legitimate email (should be ACCEPTED)...")
        sock.connect('/tmp/foff-milter.sock')
        
        # Option negotiation
        send_command(sock, b'O', b'\x00\x00\x00\x00\x00\x00\x00\x00')
        read_response(sock)
        
        # Connect from legitimate host
        send_command(sock, b'C', b'mail.legitimate.com\x00')
        read_response(sock)
        
        # HELO
        send_command(sock, b'H', b'mail.legitimate.com\x00')
        read_response(sock)
        
        # MAIL FROM legitimate sender
        send_command(sock, b'M', b'<user@legitimate.com>\x00')
        read_response(sock)
        
        # RCPT TO different user (not user@example.com)
        send_command(sock, b'R', b'<admin@example.com>\x00')
        read_response(sock)
        
        # Headers - English subject, legitimate mailer
        send_command(sock, b'L', b'Subject\x00Regular Business Email\x00')
        read_response(sock)
        
        send_command(sock, b'L', b'X-Mailer\x00Postfix 3.6.4\x00')
        read_response(sock)
        
        # End of headers - this should NOT trigger any rules
        send_command(sock, b'N', b'')
        cmd, data = read_response(sock)
        
        if cmd == b'c':  # SMFIR_CONTINUE (accept)
            print("✓ Legitimate email ACCEPTED (correct)")
            return True
        elif cmd == b'y':  # SMFIR_REPLYCODE (reject)
            print(f"✗ Legitimate email REJECTED (incorrect): {data.decode('utf-8', errors='ignore')}")
            return False
        elif cmd == b'h':  # SMFIR_ADDHEADER (tag as spam)
            print(f"✗ Legitimate email TAGGED (incorrect): {data.decode('utf-8', errors='ignore')}")
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
    time.sleep(1)
    if test_legitimate_email():
        sys.exit(0)
    else:
        sys.exit(1)
