#!/usr/bin/env python3
"""
Password Strength Checker CLI

Command-line interface for checking password strength.
Can be used interactively or with password as argument.
"""

import sys
import getpass
import argparse
from password_checker import PasswordChecker


def format_output(results: dict, verbose: bool = False) -> str:
    """
    Format check results for display.
    
    Args:
        results (dict): Results dictionary from check_password()
        verbose (bool): Whether to show detailed breakdown
        
    Returns:
        str: Formatted output string
    """
    output = []
    
    # Header
    output.append("=" * 60)
    output.append("Password Strength Report")
    output.append("=" * 60)
    
    # Score
    score = results['score']
    score_bar = '█' * (score // 2) + '░' * (50 - score // 2)
    
    if score >= 80:
        strength = "VERY STRONG"
        color_indicator = "🟢"
    elif score >= 60:
        strength = "STRONG"
        color_indicator = "🟡"
    elif score >= 40:
        strength = "MODERATE"
        color_indicator = "🟠"
    else:
        strength = "WEAK"
        color_indicator = "🔴"
    
    output.append(f"\n{color_indicator} Strength Score: {score}/100 ({strength})")
    output.append(f"[{score_bar}]")
    
    # Basic info
    output.append(f"\nPassword Length: {results['length']} characters")
    
    if not results['meets_min_length']:
        output.append("⚠️  WARNING: Password does not meet minimum length requirement")
    
    # Character types
    output.append("\nCharacter Types:")
    char_types = results['character_types']
    output.append(f"  {'✓' if char_types['uppercase'] else '✗'} Uppercase letters")
    output.append(f"  {'✓' if char_types['lowercase'] else '✗'} Lowercase letters")
    output.append(f"  {'✓' if char_types['digits'] else '✗'} Digits")
    output.append(f"  {'✓' if char_types['symbols'] else '✗'} Special symbols")
    
    # Entropy
    output.append(f"\nEntropy: {results['entropy']} bits")
    if results['entropy'] < 40:
        output.append("  ⚠️  Low entropy - password may be predictable")
    elif results['entropy'] >= 60:
        output.append("  ✓ Good entropy - password has high randomness")
    
    # Common password check
    if results['is_common']:
        output.append("\n⚠️  WARNING: This password is commonly used and easily guessable!")
    
    # Patterns
    if results['patterns']:
        output.append("\n⚠️  Detected Weak Patterns:")
        for pattern in results['patterns'][:5]:  # Limit to 5 patterns
            output.append(f"  • {pattern}")
        if len(results['patterns']) > 5:
            output.append(f"  ... and {len(results['patterns']) - 5} more")
    
    # Suggestions
    if results['suggestions']:
        output.append("\n💡 Suggestions for Improvement:")
        for i, suggestion in enumerate(results['suggestions'], 1):
            output.append(f"  {i}. {suggestion}")
    
    # Verbose breakdown
    if verbose:
        output.append("\n" + "-" * 60)
        output.append("Score Breakdown:")
        breakdown = results['breakdown']
        output.append(f"  Length: {breakdown.get('length', 0):.1f} points")
        output.append(f"  Diversity: {breakdown.get('diversity', 0):.1f} points")
        output.append(f"  Entropy: {breakdown.get('entropy', 0):.1f} points")
        if breakdown.get('pattern_penalty', 0) < 0:
            output.append(f"  Pattern Penalty: {breakdown['pattern_penalty']:.1f} points")
        if breakdown.get('common_password_penalty', 0) < 0:
            output.append(f"  Common Password Penalty: {breakdown['common_password_penalty']:.1f} points")
        output.append(f"  Total: {breakdown['total']:.1f} points")
    
    output.append("\n" + "=" * 60)
    
    return "\n".join(output)


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description='Password Strength Checker for Linux',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Interactive mode (password hidden)
  %(prog)s -p "MyPass123!"    # Check password from command line
  %(prog)s -v -p "Test123"    # Verbose output with score breakdown
  echo "password" | %(prog)s  # Check from stdin
        """
    )
    
    parser.add_argument(
        '-p', '--password',
        type=str,
        help='Password to check (if not provided, will prompt or read from stdin)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed score breakdown'
    )
    
    parser.add_argument(
        '--min-length',
        type=int,
        default=8,
        help='Minimum acceptable password length (default: 8)'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )
    
    args = parser.parse_args()
    
    # Get password
    password = args.password
    
    if not password:
        # Check if input is coming from stdin (pipe)
        if not sys.stdin.isatty():
            password = sys.stdin.read().strip()
        else:
            # Interactive prompt
            password = getpass.getpass("Enter password to check: ")
    
    if not password:
        print("Error: No password provided", file=sys.stderr)
        sys.exit(1)
    
    # Create checker and analyze
    checker = PasswordChecker(min_length=args.min_length)
    results = checker.check_password(password)
    
    # Output results
    if args.json:
        import json
        print(json.dumps(results, indent=2))
    else:
        output = format_output(results, verbose=args.verbose)
        print(output)
        
        # Exit code based on score
        if results['score'] < 40:
            sys.exit(2)  # Weak password
        elif results['score'] < 60:
            sys.exit(1)  # Moderate password
        # Exit 0 for strong passwords


if __name__ == '__main__':
    main()

