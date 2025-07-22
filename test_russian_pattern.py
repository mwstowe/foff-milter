import re

# Test the current pattern
pattern = r".*\.ru\.com"
test_domains = [
    "cartsgorilla.ru.com",
    "spam.ru.com", 
    "test@cartsgorilla.ru.com",
    "user@mail.cartsgorilla.ru.com",
    "sender@something.ru.com",
    "legitimate@example.com",
    "fake@russia.com"
]

print("Testing pattern:", pattern)
print("=" * 50)

for domain in test_domains:
    match = re.search(pattern, domain)
    print(f"Domain: {domain:<30} Match: {'YES' if match else 'NO'}")
    if match:
        print(f"  Matched part: '{match.group()}'")
    print()
