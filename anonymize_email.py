#!/usr/bin/env python3
"""
Email anonymization script for test suite
Replaces PII with generic placeholders while preserving email structure
"""

import re
import sys
import hashlib

def anonymize_email(content):
    """Anonymize email content by replacing PII with generic placeholders"""
    
    # Replace email addresses (preserve domain structure for testing)
    content = re.sub(r'\b[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', 
                     r'user@\1', content)
    
    # Replace phone numbers
    content = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '555-123-4567', content)
    
    # Replace names in From/To headers (preserve structure)
    content = re.sub(r'From:\s*"([^"]+)"\s*<', r'From: "Sender Name" <', content)
    content = re.sub(r'To:\s*"([^"]+)"\s*<', r'To: "Recipient Name" <', content)
    
    # Replace personal names in content (common patterns)
    content = re.sub(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b', 'John Doe', content)
    
    # Replace addresses (basic pattern)
    content = re.sub(r'\b\d+\s+[A-Z][a-z]+\s+(Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd)\b', 
                     '123 Main Street', content)
    
    # Replace credit card numbers
    content = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '1234-5678-9012-3456', content)
    
    # Replace SSN
    content = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '123-45-6789', content)
    
    return content

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 anonymize_email.py <email_file>")
        sys.exit(1)
    
    email_file = sys.argv[1]
    
    try:
        with open(email_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        anonymized = anonymize_email(content)
        print(anonymized)
        
    except Exception as e:
        print(f"Error processing {email_file}: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
