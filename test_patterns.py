#!/usr/bin/env python3
import re

# Test email data
sender = "CVS1044_6873@fleetlogisticstrucks.site"
from_header = "CVS - Medicare Kit <Medicare701192@fleetlogisticstrucks.site>"
auth_header = "juliett.baddomain.com; dkim=fail reason=\"key not found in DNS\" (0-bit key; unprotected) header.d=ml.fleetlogisticstrucks.site header.i=catili@ml.fleetlogisticstrucks.site header.b=l9fB3a0+"
subject = "Re: Your Free Medicare Essentials Kit from CVS"
reply_to = "<replyhdwpkobuiabqxgfv@tbtdrdbmqikmjciedxxmuncefn.com>"

print("=== CVS Medicare Spam Analysis ===")
print(f"Sender: {sender}")
print(f"From: {from_header}")
print(f"Subject: {subject}")
print(f"Reply-To: {reply_to}")
print(f"Auth: {auth_header}")
print()

# Test Rule 42 patterns
print("=== Rule 42: Brand impersonation with authentication failures ===")

# 1. DKIM failure check
dkim_fail_pattern = re.compile(r"(?i)dkim=fail")
dkim_match = dkim_fail_pattern.search(auth_header)
print(f"1. DKIM fail pattern matches: {bool(dkim_match)}")
if dkim_match:
    print(f"   Matched: '{dkim_match.group()}'")

# 2. CVS brand impersonation check
cvs_pattern = re.compile(r"(?i).*(cvs).*")
cvs_match = cvs_pattern.search(from_header)
print(f"2. CVS brand pattern matches: {bool(cvs_match)}")
if cvs_match:
    print(f"   Matched: '{cvs_match.group()}'")

# 3. Exclusion pattern check (should NOT match)
exclusion_pattern = re.compile(r".*@(amazon|microsoft|apple|google|netflix|spotify|adobe|paypal|chase|wellsfargo|bankofamerica|citibank|capitalone|walmart|target|costco|homedepot|lowes|bestbuy|macys|nordstrom|cvs|walgreens|riteaid|medicare|medicaid|ssa|irs|usps|fedex|ups|dhl)\.com$")
exclusion_match = exclusion_pattern.search(sender)
print(f"3. Exclusion pattern matches sender: {bool(exclusion_match)}")
if exclusion_match:
    print(f"   Matched: '{exclusion_match.group()}' - THIS WOULD EXCLUDE THE EMAIL!")
else:
    print("   No match - email is NOT excluded")

print()
print("=== Rule 42 Conclusion ===")
if dkim_match and cvs_match and not exclusion_match:
    print("✅ Rule 42 SHOULD match this email (DKIM fail + CVS brand + not excluded)")
else:
    print("❌ Rule 42 should NOT match:")
    print(f"   DKIM fail: {bool(dkim_match)}")
    print(f"   CVS brand: {bool(cvs_match)}")
    print(f"   Not excluded: {not bool(exclusion_match)}")

print()
print("=== Rule 45: Suspicious TLDs ===")

# Test .site TLD pattern
site_tld_pattern = re.compile(r".*@.*\.(shop|store|online|site|website|web|click|download|loan|racing|review|science|work|party|date|stream|trade|bid|win|cricket|accountant|faith|men|gq|tk|ml|ga|cf|top|fun|live|life|world|today|news|info|buzz|cool|best|cheap|free|sale|sbs|xyz|pw|cc|tv|me|co|io|ly|be|ws|am|fm|to|cfd|icu|cyou|bond|lol|fans|club|vip|pro|tech)$")
site_match = site_tld_pattern.search(sender)
print(f"1. Suspicious TLD pattern matches: {bool(site_match)}")
if site_match:
    print(f"   Matched: '{site_match.group()}'")

# Test health spam content patterns
health_pattern = re.compile(r"(?i).*(secret.*health|miracle.*cure|breakthrough.*health|overnight.*result|instant.*result|amazing.*result|incredible.*result|shocking.*result|revolutionary.*health|ripped.*muscle|soaring.*testosterone|boost.*testosterone|enhance.*performance|increase.*stamina|empty.*bladder|bladder.*control|urinary.*health|prostate.*health|natural.*remedy|ancient.*remedy|health.*tonic|joint.*heal|joint.*repair|joint.*replacement|surgery.*alternative|without.*surgery|heal.*joint|repair.*joint).*")
health_match = health_pattern.search(subject)
print(f"2. Health spam content matches: {bool(health_match)}")

print()
print("=== Rule 45 Conclusion ===")
if site_match and health_match:
    print("✅ Rule 45 SHOULD match this email (suspicious TLD + health content)")
elif site_match:
    print("❌ Rule 45 should NOT match: has suspicious TLD but missing required health content")
else:
    print("❌ Rule 45 should NOT match: missing suspicious TLD")
