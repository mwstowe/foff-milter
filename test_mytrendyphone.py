import re

# Email data
return_path = "MAILER-DAEMON"
from_header = "info-h2t@untdstatdropromuniflamtionLfUHvWahz.com"
received_header = "from mytrendyphone.com (ip103-23-199-205.cloudhost.web.id [103.23.199.205] (may be forged))"

# Test current pattern
current_pattern = r".*\.mytrendyphone\.com"
print("=== TESTING CURRENT RULE ===")
print(f"Pattern: {current_pattern}")
print(f"Return-Path: {return_path}")
print(f"From: {from_header}")
print(f"Current rule matches Return-Path: {bool(re.search(current_pattern, return_path))}")
print(f"Current rule matches From: {bool(re.search(current_pattern, from_header))}")

# Test recommended patterns
print("\n=== TESTING RECOMMENDED PATTERNS ===")

# Pattern 1: HeaderPattern for Received
received_pattern = r".*mytrendyphone\.com.*"
print(f"Received pattern: {received_pattern}")
print(f"Matches Received header: {bool(re.search(received_pattern, received_header))}")

# Pattern 2: Actual sender domain
sender_pattern = r".*@.*untdstatdropromuniflamtionLfUHvWahz\.com$"
print(f"Actual sender pattern: {sender_pattern}")
print(f"Matches From header: {bool(re.search(sender_pattern, from_header))}")
