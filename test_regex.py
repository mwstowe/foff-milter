import re

sender = "WeirdShrub@javaburrn.rest"

patterns = [
    r".*@.*\.javaburrn\.rest$",
    r".*@.*\.javaburn\.rest$", 
    r".*@.*\.javabu.*rn\.rest$"
]

for i, pattern in enumerate(patterns, 1):
    match = re.search(pattern, sender)
    print(f"Pattern {i}: {pattern}")
    print(f"  Sender: {sender}")
    print(f"  Match: {'YES' if match else 'NO'}")
    print()
