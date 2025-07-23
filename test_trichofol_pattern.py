import re

# Email data
return_path = "97148-203879-10156-21091-mstowe=baddomain.com@mail.trichofol.ru.com"
from_header = "Nellie@trichofol.ru.com"
reply_to = "Carolyn@trichofol.ru.com"

# Your current pattern
pattern = r".*\.ru\.com"

print("=== TESTING RUSSIAN SPAM RULE ===")
print(f"Pattern: {pattern}")
print(f"Return-Path: {return_path}")
print(f"From: {from_header}")
print(f"Reply-To: {reply_to}")
print()

# Test matches
return_match = re.search(pattern, return_path)
from_match = re.search(pattern, from_header)
reply_match = re.search(pattern, reply_to)

print("PATTERN MATCHING RESULTS:")
print(f"Return-Path matches: {'YES' if return_match else 'NO'}")
if return_match:
    print(f"  Matched: '{return_match.group()}'")

print(f"From matches: {'YES' if from_match else 'NO'}")
if from_match:
    print(f"  Matched: '{from_match.group()}'")

print(f"Reply-To matches: {'YES' if reply_match else 'NO'}")
if reply_match:
    print(f"  Matched: '{reply_match.group()}'")

print(f"\nRule should have triggered: {'YES' if from_match else 'NO'}")

# Test what the milter actually sees
print("\n=== WHAT MILTER SEES ===")
print("The milter checks the 'From' header for SenderPattern")
print(f"From header: {from_header}")
print(f"Pattern match: {'YES - SHOULD TAG' if from_match else 'NO - EXPLAINS WHY NO TAG'}")
