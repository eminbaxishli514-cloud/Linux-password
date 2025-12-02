"""
Password Strength Checker Module

This module provides comprehensive password strength checking functionality including:
- Character type validation (length, uppercase, lowercase, digits, symbols)
- Pattern detection for common weak patterns
- Entropy calculation for cryptographic strength
- Scoring system (0-100)
- Improvement suggestions
"""

import re
import math
from typing import Dict, List, Tuple, Set
from patterns import detect_patterns, load_common_passwords


class PasswordChecker:
    """
    A comprehensive password strength checker for Linux systems.
    
    Attributes:
        min_length (int): Minimum acceptable password length
        common_passwords (Set[str]): Set of common passwords to check against
    """
    
    def __init__(self, min_length: int = 8):
        """
        Initialize the password checker.
        
        Args:
            min_length (int): Minimum acceptable password length (default: 8)
        """
        self.min_length = min_length
        self.common_passwords = load_common_passwords()
    
    def check_length(self, password: str) -> Tuple[bool, int]:
        """
        Check password length.
        
        Args:
            password (str): Password to check
            
        Returns:
            Tuple[bool, int]: (meets_minimum, length)
        """
        length = len(password)
        return length >= self.min_length, length
    
    def check_character_types(self, password: str) -> Dict[str, bool]:
        """
        Check for presence of different character types.
        
        Args:
            password (str): Password to check
            
        Returns:
            Dict[str, bool]: Dictionary with keys 'uppercase', 'lowercase', 
                           'digits', 'symbols' indicating presence
        """
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_digits = bool(re.search(r'\d', password))
        has_symbols = bool(re.search(r'[^A-Za-z0-9]', password))
        
        return {
            'uppercase': has_uppercase,
            'lowercase': has_lowercase,
            'digits': has_digits,
            'symbols': has_symbols
        }
    
    def calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy (bits).
        
        Entropy is calculated based on the character set used:
        - Lowercase: 26 characters
        - Uppercase: 26 characters
        - Digits: 10 characters
        - Symbols: ~33 common symbols
        
        Args:
            password (str): Password to analyze
            
        Returns:
            float: Entropy in bits
        """
        char_types = self.check_character_types(password)
        
        # Determine character set size
        charset_size = 0
        if char_types['lowercase']:
            charset_size += 26
        if char_types['uppercase']:
            charset_size += 26
        if char_types['digits']:
            charset_size += 10
        if char_types['symbols']:
            charset_size += 33  # Common symbols
        
        # If no charset detected, assume lowercase only
        if charset_size == 0:
            charset_size = 26
        
        # Calculate entropy: log2(charset_size^length)
        length = len(password)
        entropy = length * math.log2(charset_size)
        
        return entropy
    
    def check_common_password(self, password: str) -> bool:
        """
        Check if password is in common passwords list.
        
        Args:
            password (str): Password to check
            
        Returns:
            bool: True if password is common, False otherwise
        """
        return password.lower() in self.common_passwords
    
    def calculate_score(self, password: str) -> Tuple[int, Dict]:
        """
        Calculate overall password strength score (0-100).
        
        Scoring breakdown:
        - Length: 0-30 points
        - Character diversity: 0-25 points
        - Entropy: 0-25 points
        - Pattern penalties: -50 to 0 points
        - Common password: -50 points
        
        Args:
            password (str): Password to score
            
        Returns:
            Tuple[int, Dict]: (score, breakdown_dict)
        """
        breakdown = {}
        score = 0
        
        # Length scoring (0-30 points)
        length = len(password)
        length_score = min(30, (length / 16) * 30)
        if length < self.min_length:
            length_score = 0
        breakdown['length'] = length_score
        score += length_score
        
        # Character diversity scoring (0-25 points)
        char_types = self.check_character_types(password)
        type_count = sum(char_types.values())
        diversity_score = (type_count / 4) * 25
        breakdown['diversity'] = diversity_score
        score += diversity_score
        
        # Entropy scoring (0-25 points)
        entropy = self.calculate_entropy(password)
        entropy_score = min(25, (entropy / 60) * 25)
        breakdown['entropy'] = entropy_score
        score += entropy_score
        
        # Pattern penalty
        patterns = detect_patterns(password)
        pattern_penalty = 0
        if patterns:
            # Apply penalties based on pattern severity
            pattern_penalty = -min(50, len(patterns) * 10)
        breakdown['pattern_penalty'] = pattern_penalty
        score += pattern_penalty
        
        # Common password penalty
        if self.check_common_password(password):
            breakdown['common_password_penalty'] = -50
            score -= 50
        else:
            breakdown['common_password_penalty'] = 0
        
        # Ensure score is between 0 and 100
        score = max(0, min(100, score))
        
        breakdown['total'] = score
        return int(score), breakdown
    
    def get_suggestions(self, password: str) -> List[str]:
        """
        Generate suggestions for improving password strength.
        
        Args:
            password (str): Password to analyze
            
        Returns:
            List[str]: List of improvement suggestions
        """
        suggestions = []
        
        # Length suggestions
        length = len(password)
        if length < self.min_length:
            suggestions.append(f"Increase length to at least {self.min_length} characters")
        elif length < 12:
            suggestions.append("Consider using at least 12 characters for better security")
        
        # Character type suggestions
        char_types = self.check_character_types(password)
        if not char_types['uppercase']:
            suggestions.append("Add uppercase letters")
        if not char_types['lowercase']:
            suggestions.append("Add lowercase letters")
        if not char_types['digits']:
            suggestions.append("Add numbers")
        if not char_types['symbols']:
            suggestions.append("Add special characters (!, @, #, $, %, etc.)")
        
        # Pattern suggestions
        patterns = detect_patterns(password)
        if patterns:
            suggestions.append("Avoid common patterns (sequences, keyboard patterns, repeated characters)")
        
        # Common password suggestion
        if self.check_common_password(password):
            suggestions.append("Avoid using common passwords")
        
        # Entropy suggestion
        entropy = self.calculate_entropy(password)
        if entropy < 40:
            suggestions.append("Use a more diverse mix of characters to increase entropy")
        
        # Default suggestion if password is already strong
        if not suggestions:
            suggestions.append("Password meets basic strength requirements")
        
        return suggestions
    
    def check_password(self, password: str) -> Dict:
        """
        Perform comprehensive password check and return detailed results.
        
        Args:
            password (str): Password to check
            
        Returns:
            Dict: Comprehensive check results including:
                - score: Overall score (0-100)
                - length: Password length
                - meets_min_length: Boolean
                - character_types: Dict of character type presence
                - entropy: Entropy in bits
                - is_common: Boolean indicating if password is common
                - patterns: List of detected patterns
                - suggestions: List of improvement suggestions
                - breakdown: Score breakdown dictionary
        """
        meets_min, length = self.check_length(password)
        char_types = self.check_character_types(password)
        entropy = self.calculate_entropy(password)
        is_common = self.check_common_password(password)
        patterns = detect_patterns(password)
        score, breakdown = self.calculate_score(password)
        suggestions = self.get_suggestions(password)
        
        return {
            'password': password,
            'score': score,
            'length': length,
            'meets_min_length': meets_min,
            'character_types': char_types,
            'entropy': round(entropy, 2),
            'is_common': is_common,
            'patterns': patterns,
            'suggestions': suggestions,
            'breakdown': breakdown
        }

