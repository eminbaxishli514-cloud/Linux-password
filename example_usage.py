#!/usr/bin/env python3
"""
Example usage of the Password Strength Checker

This script demonstrates various ways to use the password checker module.
"""

from password_checker import PasswordChecker


def example_basic_check():
    """Basic password checking example."""
    print("=" * 60)
    print("Example 1: Basic Password Check")
    print("=" * 60)
    
    checker = PasswordChecker(min_length=8)
    password = "MySecure123!"
    
    results = checker.check_password(password)
    
    print(f"Password: {password}")
    print(f"Score: {results['score']}/100")
    print(f"Entropy: {results['entropy']} bits")
    print(f"Character types: {results['character_types']}")
    print(f"Suggestions: {results['suggestions']}")
    print()


def example_multiple_passwords():
    """Check multiple passwords at once."""
    print("=" * 60)
    print("Example 2: Checking Multiple Passwords")
    print("=" * 60)
    
    checker = PasswordChecker()
    passwords = [
        "weak",
        "password123",
        "StrongPass123",
        "Very$ecure!Pass123",
        "12345678",
        "qwerty",
    ]
    
    for password in passwords:
        results = checker.check_password(password)
        strength = "STRONG" if results['score'] >= 60 else \
                   "MODERATE" if results['score'] >= 40 else "WEAK"
        
        print(f"Password: {password:20} | Score: {results['score']:3}/100 | {strength}")
    
    print()


def example_custom_requirements():
    """Example with custom minimum length."""
    print("=" * 60)
    print("Example 3: Custom Minimum Length")
    print("=" * 60)
    
    # Require 12 character minimum
    checker = PasswordChecker(min_length=12)
    password = "Short123"
    
    results = checker.check_password(password)
    print(f"Password: {password}")
    print(f"Meets minimum length (12): {results['meets_min_length']}")
    print(f"Suggestions: {results['suggestions'][:2]}")
    print()


def example_detailed_analysis():
    """Detailed analysis of a password."""
    print("=" * 60)
    print("Example 4: Detailed Password Analysis")
    print("=" * 60)
    
    checker = PasswordChecker()
    password = "MyP@ssw0rd2024!"
    
    results = checker.check_password(password)
    
    print(f"Password: {password}")
    print(f"\nLength: {results['length']} characters")
    print(f"Meets minimum: {results['meets_min_length']}")
    print(f"\nCharacter Types:")
    for char_type, present in results['character_types'].items():
        status = "✓" if present else "✗"
        print(f"  {status} {char_type.title()}")
    
    print(f"\nEntropy: {results['entropy']} bits")
    print(f"Is Common: {results['is_common']}")
    
    if results['patterns']:
        print(f"\nPatterns Detected:")
        for pattern in results['patterns']:
            print(f"  - {pattern}")
    else:
        print(f"\nNo weak patterns detected")
    
    print(f"\nScore Breakdown:")
    for key, value in results['breakdown'].items():
        if key != 'total':
            print(f"  {key}: {value:.1f}")
    print(f"  Total: {results['breakdown']['total']:.1f}")
    
    print(f"\nSuggestions:")
    for i, suggestion in enumerate(results['suggestions'], 1):
        print(f"  {i}. {suggestion}")
    print()


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("Password Strength Checker - Usage Examples")
    print("=" * 60 + "\n")
    
    example_basic_check()
    example_multiple_passwords()
    example_custom_requirements()
    example_detailed_analysis()
    
    print("=" * 60)
    print("Examples completed!")
    print("=" * 60)

