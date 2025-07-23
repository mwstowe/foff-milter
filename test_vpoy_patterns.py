import re
import base64

# Email data
sender = "order.ixkavuy@service.vpoy.cn"
subject_b64 = "44GU5Yip55So5Lit44Gu44K144O844OT44K557aZ57aa44Gr5b+F6KaB44Gq5oOF5aCx44KS44GU56K66KqN44GP44Gg44GV44GE"

# Decode subject
try:
    subject = base64.b64decode(subject_b64).decode('utf-8')
    print(f"Decoded subject: {subject}")
except:
    subject = "DECODE_FAILED"

# Test patterns
patterns = [
    r".*@service\.[^.]+\.cn$",      # New pattern for service.vpoy.cn
    r".*@service\..*\.cn$",         # Original pattern for service.something.cn
    r"service\..*\.cn"              # Your current pattern
]

print(f"\nTesting sender: {sender}")
for i, pattern in enumerate(patterns, 1):
    match = re.search(pattern, sender)
    print(f"Pattern {i}: {pattern}")
    print(f"  Match: {'YES' if match else 'NO'}")
    if match:
        print(f"  Matched: '{match.group()}'")

# Check Japanese content
japanese_chars = re.findall(r'[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FAF]', subject)
print(f"\nJapanese characters in subject: {len(japanese_chars)} found")
print(f"Rule should trigger: {'YES' if japanese_chars else 'NO'}")
