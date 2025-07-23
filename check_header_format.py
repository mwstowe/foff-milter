# Check the header format being sent
header_name = "X-Spam-Flag"
header_value = "YES"

# Current format
current_format = f"{header_name}\0{header_value}\0"
print("Current header format:")
print(f"Raw: {repr(current_format)}")
print(f"Bytes: {current_format.encode()}")
print(f"Length: {len(current_format.encode())}")

# Alternative formats to try
alt1 = f"{header_name}\0{header_value}"  # No trailing null
alt2 = f"{header_name}: {header_value}\0"  # With colon
alt3 = f"{header_name}: {header_value}"    # Standard format

print(f"\nAlternative 1 (no trailing null): {repr(alt1)}")
print(f"Alternative 2 (with colon): {repr(alt2)}")
print(f"Alternative 3 (standard): {repr(alt3)}")
