r"""
Encoding detection and decoding module.

Detects and decodes:
- Base64 encoding
- URL encoding (%XX)
- Unicode escapes (\uXXXX)

Used to detect obfuscated prompt injection attempts.
"""

import re
import base64
from typing import List, Dict
from urllib.parse import unquote


MIN_ENCODED_LENGTH = 20  # Minimum length to consider as encoded


def decode_and_scan(content: str) -> List[Dict]:
    """
    Detect and decode encoded content.
    
    Returns list of findings with:
    - encoding: Type of encoding detected
    - decoded: Decoded content
    - original: Original encoded string (truncated)
    """
    findings = []
    
    # Base64 detection
    findings.extend(_detect_base64(content))
    
    # URL encoding detection
    findings.extend(_detect_url_encoding(content))
    
    # Unicode escape detection
    findings.extend(_detect_unicode_escapes(content))
    
    return findings


def _detect_base64(content: str) -> List[Dict]:
    """Detect and decode Base64 strings."""
    findings = []
    
    # Pattern: Sequences of base64 characters (A-Za-z0-9+/) ending with 0-2 '=' padding
    b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    
    for match in re.finditer(b64_pattern, content):
        encoded = match.group()
        
        # Skip if not long enough
        if len(encoded) < MIN_ENCODED_LENGTH:
            continue
        
        try:
            # Add padding if needed
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += '=' * (4 - missing_padding)
            
            # Decode
            decoded_bytes = base64.b64decode(encoded, validate=True)
            decoded = decoded_bytes.decode('utf-8', errors='ignore')
            
            # Check if decoded content is meaningful (mostly printable)
            if len(decoded) > 10 and sum(c.isprintable() for c in decoded) / len(decoded) > 0.7:
                findings.append({
                    "encoding": "base64",
                    "decoded": decoded,
                    "original": match.group()[:50] + "..." if len(match.group()) > 50 else match.group()
                })
        except (base64.binascii.Error, ValueError, UnicodeDecodeError):
            # Not valid base64 or not UTF-8
            continue
    
    return findings


def _detect_url_encoding(content: str) -> List[Dict]:
    """Detect and decode URL-encoded strings."""
    findings = []
    
    # Pattern: Strings containing %XX sequences
    url_pattern = r'(?:%[0-9A-Fa-f]{2})+'
    
    matches = list(re.finditer(url_pattern, content))
    
    if not matches:
        return findings
    
    # Try decoding the entire content if it has URL encoding
    if len(matches) >= 3:  # At least 3 %XX sequences
        try:
            decoded = unquote(content)
            
            # Check if decoding changed the content significantly
            if decoded != content and len(decoded) > MIN_ENCODED_LENGTH:
                findings.append({
                    "encoding": "url",
                    "decoded": decoded,
                    "original": content[:50] + "..." if len(content) > 50 else content
                })
        except Exception:
            pass
    
    return findings


def _detect_unicode_escapes(content: str) -> List[Dict]:
    """Detect and decode Unicode escape sequences."""
    findings = []
    
    # Pattern: \uXXXX or \UXXXXXXXX
    unicode_pattern = r'(?:\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8})+'
    
    matches = list(re.finditer(unicode_pattern, content))
    
    if not matches:
        return findings
    
    # Try decoding if we have unicode escapes
    if len(matches) >= 2:
        try:
            # Python's decode can handle \uXXXX escapes
            decoded = content.encode().decode('unicode-escape')
            
            if decoded != content and len(decoded) > MIN_ENCODED_LENGTH:
                findings.append({
                    "encoding": "unicode_escape",
                    "decoded": decoded,
                    "original": content[:50] + "..." if len(content) > 50 else content
                })
        except Exception:
            pass
    
    return findings


def has_encoding(content: str) -> bool:
    """Quick check if content appears to be encoded."""
    # Base64-like pattern
    if re.search(r'[A-Za-z0-9+/]{30,}={0,2}', content):
        return True
    
    # URL encoding
    if re.search(r'(?:%[0-9A-Fa-f]{2}){3,}', content):
        return True
    
    # Unicode escapes
    if re.search(r'(?:\\u[0-9A-Fa-f]{4}){2,}', content):
        return True
    
    return False
