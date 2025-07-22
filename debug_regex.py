import re

sender = "WeirdShrub@javaburrn.rest"
print(f"Sender: '{sender}'")
print(f"Length: {len(sender)}")
print(f"Bytes: {sender.encode()}")

# Test simpler patterns
patterns = [
    r"javaburrn\.rest",
    r".*javaburrn\.rest",
    r".*@.*javaburrn\.rest",
    r".*@.*\.javaburrn\.rest",
    r".*@.*\.javaburrn\.rest$"
]

for pattern in patterns:
    match = re.search(pattern, sender)
    print(f"Pattern: {pattern:<30} Match: {'YES' if match else 'NO'}")
    if match:
        print(f"  Matched: '{match.group()}'")

# Test without escaping
print("\nTesting without escaping:")
pattern_no_escape = r".*@.*javaburrn.rest$"
match = re.search(pattern_no_escape, sender)
print(f"Pattern: {pattern_no_escape:<30} Match: {'YES' if match else 'NO'}")
