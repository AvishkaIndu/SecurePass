"""
Utility functions for SecurePass
Password generation and strength analysis
"""
import secrets
import string
import re
from typing import Tuple


class PasswordGenerator:
    """Secure password generation"""
    
    @staticmethod
    def generate(length: int = 16, use_upper: bool = True, 
                use_lower: bool = True, use_digits: bool = True,
                use_symbols: bool = True) -> str:
        """
        Generate cryptographically secure random password
        
        Args:
            length: Password length
            use_upper: Include uppercase letters
            use_lower: Include lowercase letters
            use_digits: Include digits
            use_symbols: Include special symbols
        
        Returns:
            Random password string
        """
        charset = ""
        
        if use_lower:
            charset += string.ascii_lowercase
        if use_upper:
            charset += string.ascii_uppercase
        if use_digits:
            charset += string.digits
        if use_symbols:
            charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not charset:
            charset = string.ascii_letters + string.digits
        
        # Ensure at least one character from each selected category
        password = []
        if use_lower:
            password.append(secrets.choice(string.ascii_lowercase))
        if use_upper:
            password.append(secrets.choice(string.ascii_uppercase))
        if use_digits:
            password.append(secrets.choice(string.digits))
        if use_symbols:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        
        # Fill remaining length with random characters
        remaining = length - len(password)
        password.extend(secrets.choice(charset) for _ in range(remaining))
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)


class PasswordStrengthChecker:
    """Analyze password strength"""
    
    @staticmethod
    def check_strength(password: str) -> Tuple[int, str, str]:
        """
        Calculate password strength score
        
        Args:
            password: Password to analyze
        
        Returns:
            Tuple of (score 0-100, strength label, color)
        """
        if not password:
            return (0, "No Password", "#808080")
        
        score = 0
        length = len(password)
        
        # Length scoring
        if length >= 8:
            score += 20
        if length >= 12:
            score += 10
        if length >= 16:
            score += 10
        if length >= 20:
            score += 10
        
        # Character variety
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            score += 15
        
        # Additional complexity
        if len(set(password)) > length * 0.6:  # High character diversity
            score += 10
        
        # Penalize common patterns
        common_patterns = ['123', 'abc', 'password', 'qwerty', '111', '000']
        for pattern in common_patterns:
            if pattern.lower() in password.lower():
                score -= 15
                break
        
        # Cap score
        score = max(0, min(100, score))
        
        # Determine label and color
        if score < 30:
            return (score, "Very Weak", "#e74c3c")
        elif score < 50:
            return (score, "Weak", "#e67e22")
        elif score < 70:
            return (score, "Fair", "#f39c12")
        elif score < 85:
            return (score, "Good", "#27ae60")
        else:
            return (score, "Excellent", "#2ecc71")
    
    @staticmethod
    def get_suggestions(password: str) -> list:
        """Get suggestions to improve password strength"""
        suggestions = []
        
        if len(password) < 12:
            suggestions.append("Use at least 12 characters")
        
        if not re.search(r'[a-z]', password):
            suggestions.append("Add lowercase letters")
        
        if not re.search(r'[A-Z]', password):
            suggestions.append("Add uppercase letters")
        
        if not re.search(r'\d', password):
            suggestions.append("Add numbers")
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            suggestions.append("Add special characters")
        
        common_patterns = ['123', 'abc', 'password', 'qwerty', '111']
        for pattern in common_patterns:
            if pattern.lower() in password.lower():
                suggestions.append("Avoid common patterns")
                break
        
        return suggestions


def format_timestamp(iso_timestamp: str) -> str:
    """Format ISO timestamp to readable string"""
    from datetime import datetime
    try:
        dt = datetime.fromisoformat(iso_timestamp)
        return dt.strftime("%Y-%m-%d %H:%M")
    except:
        return iso_timestamp
