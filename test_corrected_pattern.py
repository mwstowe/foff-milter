import re

sender = "no-reply.iqamsh@service.aqzdw.cn"

# Test the corrected pattern
sender_pattern = r".*@service\..*\.cn$"
print(f"Corrected SenderPattern: {sender_pattern}")
print(f"Testing against: {sender}")

match = re.search(sender_pattern, sender)
print(f"Match: {'YES' if match else 'NO'}")
if match:
    print(f"Matched: '{match.group()}'")
