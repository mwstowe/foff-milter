#!/usr/bin/env python3
"""
Test script to verify Sparkpost to user@example.com rule.
"""

import socket
import struct
import sys
import time

def send_command(sock, command, data=b''):
    length = len(data) + 1
    frame = struct.pack('>I', length) + command + data
    sock.send(frame)

def read_response(sock):
    try:
        length_data = sock.recv(4)
        if len(length_data) != 4:
            return None, None
        length = struct.unpack('>I', length_data)[0]
        if length == 0:
            return None, None
        response_data = sock.recv(length)
        if len(response_data) != length:
            return None, None
        command = response_data[0:1]
        data = response_data[1:] if length > 1 else b''
        return command, data
    except Exception as e:
        return None, None

def test_sparkpost_rule():
    """Test Sparkpost to user@example.com (should be REJECTED)"""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    
    try:
        print("Testing Sparkpost to user@example.com (should be REJECTED)...")
        sock.connect('/tmp/foff-milter.sock')
        
        send_command(sock, b'O', b'\x00\x00\x00\x00\x00\x00\x00\x00')
        read_response(sock)
        
        send_command(sock, b'C', b'sparkpost-relay.com\x00')
        read_response(sock)
        
        send_command(sock, b'H', b'sparkpost-relay.com\x00')
        read_response(sock)
        
        send_command(sock, b'M', b'<newsletter@company.com>\x00')
        read_response(sock)
        
        # This is the key - sending to user@example.com
        send_command(sock, b'R', b'<user@example.com>\x00')
        read_response(sock)
        
        send_command(sock, b'L', b'Subject\x00Your Weekly Newsletter\x00')
        read_response(sock)
        
        # This is the key - Sparkpost mailer
        send_command(sock, b'L', b'X-Mailer\x00relay.sparkpostmail.com v3.2\x00')
        read_response(sock)
        
        send_command(sock, b'N', b'')
        cmd, data = read_response(sock)
        
        if cmd == b'y':  # SMFIR_REPLYCODE (reject)
            print(f"✓ Sparkpost email REJECTED (correct): {data.decode('utf-8', errors='ignore')}")
            return True
        elif cmd == b'c':  # SMFIR_CONTINUE (accept)
            print("✗ Sparkpost email ACCEPTED (incorrect)")
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
    if test_sparkpost_rule():
        sys.exit(0)
    else:
        sys.exit(1)
