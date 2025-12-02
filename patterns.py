"""
Pattern Detection Module

This module detects common weak patterns in passwords such as:
- Sequential characters (abc, 123)
- Keyboard patterns (qwerty, asdf)
- Repeated characters (aaa, 111)
- Common substitutions (p@ssw0rd)
"""

import re
from typing import List, Set


# Common keyboard patterns
KEYBOARD_PATTERNS = [
    'qwerty', 'qwertyuiop', 'asdf', 'asdfgh', 'zxcv', 'zxcvbn',
    '123456', '12345678', '123456789', '1234567890',
    'abcdef', 'abcdefgh',
    'password', 'passw0rd', 'password1', 'password123',
    'admin', 'admin123', 'administrator',
    'letmein', 'welcome', 'monkey', 'dragon', 'master',
    'iloveyou', 'princess', 'qwerty123', 'football',
    'baseball', 'welcome123', 'login', 'pass', 'pass123'
]

# Sequential patterns
SEQUENCES = [
    'abcdefghijklmnopqrstuvwxyz',
    'zyxwvutsrqponmlkjihgfedcba',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'ZYXWVUTSRQPONMLKJIHGFEDCBA',
    '0123456789',
    '9876543210'
]


def load_common_passwords() -> Set[str]:
    """
    Load common passwords from file or return a default set.
    
    In a production environment, this could load from a file.
    For now, returns a set of common passwords.
    
    Returns:
        Set[str]: Set of common passwords (lowercase)
    """
    common = {
        'password', 'password123', 'password1', 'passw0rd',
        '123456', '12345678', '123456789', '1234567890',
        'qwerty', 'qwerty123', 'qwertyuiop',
        'admin', 'admin123', 'administrator',
        'letmein', 'welcome', 'monkey', 'dragon', 'master',
        'iloveyou', 'princess', 'football', 'baseball',
        'welcome123', 'login', 'pass', 'pass123',
        'asdf', 'asdfgh', 'zxcv', 'zxcvbn'
    }
    
    # Try to load from file if it exists
    try:
        with open('common_passwords.txt', 'r', encoding='utf-8') as f:
            additional = {line.strip().lower() for line in f if line.strip()}
            common.update(additional)
    except FileNotFoundError:
        pass  # Use default set
    
    return common


def detect_sequential_chars(password: str, min_length: int = 3) -> List[str]:
    """
    Detect sequential character patterns.
    
    Args:
        password (str): Password to check
        min_length (int): Minimum sequence length to detect
        
    Returns:
        List[str]: List of detected sequences
    """
    detected = []
    password_lower = password.lower()
    
    for seq in SEQUENCES:
        seq_lower = seq.lower()
        # Check forward sequence
        for i in range(len(seq_lower) - min_length + 1):
            pattern = seq_lower[i:i+min_length]
            if pattern in password_lower:
                detected.append(f"Sequential: {pattern}")
        
        # Check reverse sequence
        seq_reverse = seq_lower[::-1]
        for i in range(len(seq_reverse) - min_length + 1):
            pattern = seq_reverse[i:i+min_length]
            if pattern in password_lower:
                detected.append(f"Reverse sequential: {pattern}")
    
    return detected


def detect_keyboard_patterns(password: str) -> List[str]:
    """
    Detect keyboard layout patterns.
    
    Args:
        password (str): Password to check
        
    Returns:
        List[str]: List of detected keyboard patterns
    """
    detected = []
    password_lower = password.lower()
    
    for pattern in KEYBOARD_PATTERNS:
        if pattern.lower() in password_lower:
            detected.append(f"Keyboard pattern: {pattern}")
    
    return detected


def detect_repeated_chars(password: str, min_repeats: int = 3) -> List[str]:
    """
    Detect repeated characters.
    
    Args:
        password (str): Password to check
        min_repeats (int): Minimum number of repeats to flag
        
    Returns:
        List[str]: List of detected repeated patterns
    """
    detected = []
    
    # Find repeated characters
    pattern = rf'(.)\1{{{min_repeats - 1},}}'
    matches = re.finditer(pattern, password)
    
    for match in matches:
        char = match.group(1)
        count = len(match.group(0))
        detected.append(f"Repeated character: '{char}' repeated {count} times")
    
    return detected


def detect_common_substitutions(password: str) -> List[str]:
    """
    Detect common leet speak substitutions.
    
    Args:
        password (str): Password to check
        
    Returns:
        List[str]: List of detected substitutions
    """
    detected = []
    password_lower = password.lower()
    
    # Common substitutions
    substitutions = {
        '@': 'a', '4': 'a',
        '3': 'e',
        '1': 'i', '!': 'i',
        '0': 'o',
        '$': 's', '5': 's',
        '7': 't',
        '2': 'z'
    }
    
    # Check if password contains common substitution patterns
    common_words = ['password', 'admin', 'pass', 'test', 'user']
    
    for word in common_words:
        # Try to match with substitutions
        pattern = word
        for sub_char, original in substitutions.items():
            pattern = pattern.replace(original, f'[{original}{sub_char}]')
        
        if re.search(pattern, password_lower, re.IGNORECASE):
            detected.append(f"Common word with substitutions: {word}")
    
    return detected


def detect_all_letters_or_digits(password: str) -> bool:
    """
    Check if password contains only letters or only digits.
    
    Args:
        password (str): Password to check
        
    Returns:
        bool: True if password is all letters or all digits
    """
    return password.isalpha() or password.isdigit()


def detect_patterns(password: str) -> List[str]:
    """
    Detect all weak patterns in a password.
    
    Args:
        password (str): Password to check
        
    Returns:
        List[str]: List of all detected patterns
    """
    patterns = []
    
    # Skip pattern detection for very short passwords
    if len(password) < 3:
        return patterns
    
    # Sequential patterns
    patterns.extend(detect_sequential_chars(password))
    
    # Keyboard patterns
    patterns.extend(detect_keyboard_patterns(password))
    
    # Repeated characters
    patterns.extend(detect_repeated_chars(password))
    
    # Common substitutions
    patterns.extend(detect_common_substitutions(password))
    
    # All letters or all digits
    if detect_all_letters_or_digits(password):
        patterns.append("Only letters or only digits - add variety")
    
    return patterns

