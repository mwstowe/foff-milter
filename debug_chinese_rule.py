import re
import base64

# Test data from the actual email
sender = "no-reply.iqamsh@service.aqzdw.cn"
mailer = "Foxmail 6, 13, 102, 15 [cn]"
subject_b64 = "REhM44Gu55m66YCB54q25rOB44Gn44GZ77yaIOOCouOCr+OCt+ODp+ODo+OBjOW/heimgQ=="

# Decode the subject
try:
    subject_decoded = base64.b64decode(subject_b64).decode('utf-8')
    print(f"Decoded subject: {subject_decoded}")
except Exception as e:
    print(f"Failed to decode subject: {e}")
    subject_decoded = "DECODE_FAILED"

# Test the patterns
print("\n=== TESTING CHINESE SERVICE RULE ===")

# Pattern 1: MailerPattern for service.*.cn
mailer_pattern = r"service\..*\.cn"
print(f"\nMailer pattern: {mailer_pattern}")
print(f"Testing against sender: {sender}")
print(f"Testing against mailer: {mailer}")

sender_match = re.search(mailer_pattern, sender)
mailer_match = re.search(mailer_pattern, mailer)

print(f"Sender match: {'YES' if sender_match else 'NO'}")
if sender_match:
    print(f"  Matched: '{sender_match.group()}'")
    
print(f"Mailer match: {'YES' if mailer_match else 'NO'}")
if mailer_match:
    print(f"  Matched: '{mailer_match.group()}'")

# Pattern 2: Japanese language detection
print(f"\nSubject contains Japanese characters:")
print(f"Subject: {subject_decoded}")

# Simple Japanese character detection
japanese_chars = re.findall(r'[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FAF]', subject_decoded)
print(f"Japanese characters found: {len(japanese_chars)} characters")
if japanese_chars:
    print(f"Sample characters: {japanese_chars[:10]}")

print(f"\nRule should match: {'YES' if (sender_match or mailer_match) and japanese_chars else 'NO'}")
