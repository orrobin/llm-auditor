"""
LLM Auditor Module
Validates both input prompts and LLM outputs to prevent prompt injections
and sensitive data leakage.
"""

import re
from dataclasses import dataclass
from typing import List, Tuple
from enum import Enum


class ValidationStatus(Enum):
    """Status of validation check."""
    VALID = "valid"
    REJECTED = "rejected"


@dataclass
class ValidationResult:
    """Result of a validation check."""
    is_valid: bool
    reason: str = ""
    matched_pattern: str = ""
    
    @property
    def status(self) -> ValidationStatus:
        return ValidationStatus.VALID if self.is_valid else ValidationStatus.REJECTED


class LLMAuditor:
    """
    Audits LLM inputs and outputs to prevent prompt injections and data leakage.
    
    Usage:
        auditor = LLMAuditor()
        
        # Validate input before sending to LLM
        result = auditor.validate_input("user prompt here")
        if not result.is_valid:
            print(f"Rejected: {result.reason}")
        
        # Validate output before returning to user
        result = auditor.validate_output("LLM response here")
        if not result.is_valid:
            print(f"Blocked: {result.reason}")
    """
    
    # Input injection patterns to detect
    INPUT_PATTERNS: List[Tuple[str, str]] = [
        # Instruction override attempts
        (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?|guidelines?)", 
         "Attempt to override previous instructions"),
        (r"forget\s+(all\s+)?(your|the|previous|prior)?\s*(rules?|instructions?|constraints?|guidelines?)", 
         "Attempt to make LLM forget rules"),
        (r"disregard\s+(all\s+)?(previous|prior|above|earlier)?\s*(instructions?|rules?|prompts?)?", 
         "Attempt to disregard instructions"),
        (r"new\s+instructions?\s*:", 
         "Attempt to inject new instructions"),
        
        # Role manipulation
        (r"you\s+are\s+now\s+(a|an|the)\s+", 
         "Attempt to change LLM role"),
        (r"act\s+as\s+(if\s+you\s+are\s+)?(a|an|the)?\s*(different|new)", 
         "Attempt to change LLM behavior"),
        (r"pretend\s+(you\s+are|to\s+be)\s+(a|an)?", 
         "Attempt to make LLM pretend"),
        
        # System prompt extraction
        (r"(show|reveal|display|print|output|tell\s+me)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?)", 
         "Attempt to extract system prompt"),
        (r"what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|rules?|programming)", 
         "Attempt to extract system prompt"),
        
        # Data extraction attempts
        (r"(retrieve|access|get|fetch|extract|list|show)\s+(the\s+)?(top\s+\d+\s+)?(user|customer|client)?\s*(emails?|passwords?|credentials?|api\s*keys?|secrets?)", 
         "Attempt to extract sensitive data"),
        (r"(dump|export|download)\s+(all\s+)?(user|customer|client)?\s*(data|information|records?)", 
         "Attempt to dump data"),
        
        # SQL injection patterns
        (r"('\s*(or|and)\s*'?\d*\s*=\s*'?\d*)", 
         "Potential SQL injection"),
        (r"(union\s+select|drop\s+table|delete\s+from|insert\s+into)", 
         "SQL injection keywords"),
        
        # Code execution attempts
        (r"(exec|eval|execute|run)\s*\(\s*['\"]", 
         "Attempt to execute code"),
        (r"import\s+(os|subprocess|sys)\s*;?\s*(os|subprocess)?\.(system|popen|call)", 
         "Attempt to import dangerous modules"),
    ]
    
    # Output patterns to detect (sensitive data leakage)
    OUTPUT_PATTERNS: List[Tuple[str, str]] = [
        # API Keys
        (r"(sk_live_|sk_test_|api_key_|apikey_)[a-zA-Z0-9]{10,}", 
         "API key detected in output"),
        (r"(api[_-]?key|apikey)\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 
         "API key pattern detected"),
        (r"bearer\s+[a-zA-Z0-9_-]{20,}", 
         "Bearer token detected"),
        
        # AWS credentials
        (r"AKIA[0-9A-Z]{16}", 
         "AWS access key detected"),
        (r"aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9/+=]{40}['\"]?", 
         "AWS secret key detected"),
        
        # Private keys
        (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", 
         "Private key detected"),
        (r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----", 
         "SSH private key detected"),
        
        # Passwords in common formats
        (r"password\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?", 
         "Password pattern detected"),
        (r"(pwd|passwd|pass)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?", 
         "Password pattern detected"),
        
        # Credit card numbers
        (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", 
         "Credit card number detected"),
        
        # Social Security Numbers
        (r"\b\d{3}-\d{2}-\d{4}\b", 
         "SSN pattern detected"),
        
        # Database connection strings
        (r"(mongodb|mysql|postgresql|postgres|redis)://[^\s]+", 
         "Database connection string detected"),
        
        # JWT tokens
        (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", 
         "JWT token detected"),
    ]
    
    def __init__(self, 
                 additional_input_patterns: List[Tuple[str, str]] = None,
                 additional_output_patterns: List[Tuple[str, str]] = None,
                 case_sensitive: bool = False):
        """
        Initialize the LLM Auditor.
        
        Args:
            additional_input_patterns: Extra patterns to check in inputs
            additional_output_patterns: Extra patterns to check in outputs
            case_sensitive: Whether pattern matching should be case-sensitive
        """
        self.input_patterns = self.INPUT_PATTERNS.copy()
        self.output_patterns = self.OUTPUT_PATTERNS.copy()
        
        if additional_input_patterns:
            self.input_patterns.extend(additional_input_patterns)
        if additional_output_patterns:
            self.output_patterns.extend(additional_output_patterns)
            
        self.case_sensitive = case_sensitive
        self._flags = 0 if case_sensitive else re.IGNORECASE
    
    def validate_input(self, text: str) -> ValidationResult:
        """
        Validate input prompt before sending to LLM.
        
        Args:
            text: The user input to validate
            
        Returns:
            ValidationResult with is_valid=True if safe, False if injection detected
        """
        if not text or not text.strip():
            return ValidationResult(is_valid=True)
        
        for pattern, reason in self.input_patterns:
            match = re.search(pattern, text, self._flags)
            if match:
                return ValidationResult(
                    is_valid=False,
                    reason=reason,
                    matched_pattern=match.group(0)
                )
        
        return ValidationResult(is_valid=True)
    
    def validate_output(self, text: str) -> ValidationResult:
        """
        Validate LLM output before returning to user.
        
        Args:
            text: The LLM response to validate
            
        Returns:
            ValidationResult with is_valid=True if safe, False if sensitive data detected
        """
        if not text or not text.strip():
            return ValidationResult(is_valid=True)
        
        for pattern, reason in self.output_patterns:
            match = re.search(pattern, text, self._flags)
            if match:
                return ValidationResult(
                    is_valid=False,
                    reason=reason,
                    matched_pattern=match.group(0)
                )
        
        return ValidationResult(is_valid=True)
    
    def audit(self, input_text: str = None, output_text: str = None) -> dict:
        """
        Audit both input and output in a single call.
        
        Args:
            input_text: The user input to validate (optional)
            output_text: The LLM response to validate (optional)
            
        Returns:
            Dictionary with 'input' and 'output' ValidationResults
        """
        results = {}
        
        if input_text is not None:
            results['input'] = self.validate_input(input_text)
        
        if output_text is not None:
            results['output'] = self.validate_output(output_text)
        
        return results
    
    def add_input_pattern(self, pattern: str, reason: str) -> None:
        """Add a custom input validation pattern."""
        self.input_patterns.append((pattern, reason))
    
    def add_output_pattern(self, pattern: str, reason: str) -> None:
        """Add a custom output validation pattern."""
        self.output_patterns.append((pattern, reason))


# Convenience functions for quick usage
def validate_input(text: str) -> ValidationResult:
    """Quick validation of input text."""
    return LLMAuditor().validate_input(text)


def validate_output(text: str) -> ValidationResult:
    """Quick validation of output text."""
    return LLMAuditor().validate_output(text)
