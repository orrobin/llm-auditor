"""
Robust JSON Parser Module
Handles parsing JSON from LLM responses, including:
- Extracting JSON from markdown code blocks
- Handling malformed JSON
- Schema validation
"""

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union


@dataclass
class ParseResult:
    """Result of a JSON parsing attempt."""
    success: bool
    data: Any = None
    error: str = ""
    raw_json: str = ""


class JSONParser:
    """
    Robust JSON parser for LLM responses.
    
    Handles common issues with LLM-generated JSON:
    - JSON wrapped in markdown code blocks
    - Trailing commas
    - Single quotes instead of double quotes
    - Unquoted keys
    - Comments in JSON
    
    Usage:
        parser = JSONParser()
        
        # Parse JSON from LLM response
        result = parser.parse(llm_response)
        if result.success:
            print(result.data)
        else:
            print(f"Error: {result.error}")
    """
    
    # Pattern to extract JSON from markdown code blocks
    CODE_BLOCK_PATTERN = re.compile(
        r'```(?:json)?\s*\n?([\s\S]*?)\n?```',
        re.IGNORECASE
    )
    
    # Pattern to find JSON objects/arrays
    JSON_PATTERN = re.compile(
        r'(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}|\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\])',
        re.DOTALL
    )
    
    def __init__(self, strict: bool = False):
        """
        Initialize the JSON parser.
        
        Args:
            strict: If True, don't attempt to fix malformed JSON
        """
        self.strict = strict
    
    def parse(self, text: str) -> ParseResult:
        """
        Parse JSON from text, handling various formats.
        
        Args:
            text: Text containing JSON (possibly wrapped in markdown)
            
        Returns:
            ParseResult with parsed data or error message
        """
        if not text or not text.strip():
            return ParseResult(success=False, error="Empty input")
        
        # Try to extract from markdown code block first
        json_str = self._extract_from_code_block(text)
        
        if not json_str:
            json_str = text.strip()
        
        # Try direct parsing first
        result = self._try_parse(json_str)
        if result.success:
            return result
        
        # If strict mode, return the error
        if self.strict:
            return result
        
        # Try to fix common issues
        fixed_json = self._fix_json(json_str)
        result = self._try_parse(fixed_json)
        if result.success:
            result.raw_json = fixed_json
            return result
        
        # Try to find JSON within the text
        found_json = self._find_json_in_text(text)
        if found_json:
            result = self._try_parse(found_json)
            if result.success:
                result.raw_json = found_json
                return result
        
        return ParseResult(
            success=False,
            error=f"Could not parse JSON: {result.error}",
            raw_json=json_str
        )
    
    def parse_multiple(self, text: str) -> List[ParseResult]:
        """
        Extract and parse multiple JSON objects from text.
        
        Args:
            text: Text potentially containing multiple JSON objects
            
        Returns:
            List of ParseResults for each JSON found
        """
        results = []
        
        # First check for code blocks
        code_blocks = self.CODE_BLOCK_PATTERN.findall(text)
        for block in code_blocks:
            result = self._try_parse(block.strip())
            if result.success:
                results.append(result)
        
        # If found in code blocks, return those
        if results:
            return results
        
        # Otherwise, try to find JSON objects/arrays in the text
        matches = self.JSON_PATTERN.findall(text)
        for match in matches:
            result = self._try_parse(match)
            if result.success:
                results.append(result)
        
        return results
    
    def validate_schema(self, data: Any, schema: Dict) -> tuple[bool, str]:
        """
        Simple schema validation for parsed JSON.
        
        Args:
            data: Parsed JSON data
            schema: Schema dict with 'type' and optional 'required', 'properties'
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        expected_type = schema.get('type')
        
        # Type checking
        type_map = {
            'object': dict,
            'array': list,
            'string': str,
            'number': (int, float),
            'integer': int,
            'boolean': bool,
            'null': type(None)
        }
        
        if expected_type and expected_type in type_map:
            expected = type_map[expected_type]
            if not isinstance(data, expected):
                return False, f"Expected {expected_type}, got {type(data).__name__}"
        
        # Check required fields for objects
        if expected_type == 'object' and isinstance(data, dict):
            required = schema.get('required', [])
            for field in required:
                if field not in data:
                    return False, f"Missing required field: {field}"
            
            # Validate properties
            properties = schema.get('properties', {})
            for key, prop_schema in properties.items():
                if key in data:
                    is_valid, error = self.validate_schema(data[key], prop_schema)
                    if not is_valid:
                        return False, f"Field '{key}': {error}"
        
        # Check array items
        if expected_type == 'array' and isinstance(data, list):
            items_schema = schema.get('items')
            if items_schema:
                for i, item in enumerate(data):
                    is_valid, error = self.validate_schema(item, items_schema)
                    if not is_valid:
                        return False, f"Item {i}: {error}"
        
        return True, ""
    
    def _extract_from_code_block(self, text: str) -> Optional[str]:
        """Extract JSON from markdown code block."""
        match = self.CODE_BLOCK_PATTERN.search(text)
        if match:
            return match.group(1).strip()
        return None
    
    def _try_parse(self, json_str: str) -> ParseResult:
        """Attempt to parse JSON string."""
        try:
            data = json.loads(json_str)
            return ParseResult(success=True, data=data, raw_json=json_str)
        except json.JSONDecodeError as e:
            return ParseResult(success=False, error=str(e), raw_json=json_str)
    
    def _fix_json(self, json_str: str) -> str:
        """Attempt to fix common JSON issues."""
        fixed = json_str
        
        # Remove trailing commas before ] or }
        fixed = re.sub(r',\s*([}\]])', r'\1', fixed)
        
        # Remove JavaScript-style comments
        fixed = re.sub(r'//.*?$', '', fixed, flags=re.MULTILINE)
        fixed = re.sub(r'/\*.*?\*/', '', fixed, flags=re.DOTALL)
        
        # Replace single quotes with double quotes (careful with apostrophes)
        # Only replace quotes that are likely JSON string delimiters
        fixed = re.sub(r"(?<=[{,:\[\s])'([^']*)'(?=[,}\]:\s])", r'"\1"', fixed)
        
        # Quote unquoted keys
        fixed = re.sub(r'(\{|,)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":', fixed)
        
        return fixed
    
    def _find_json_in_text(self, text: str) -> Optional[str]:
        """Find JSON object or array in text."""
        # Try to find the outermost { } or [ ]
        stack = []
        start = -1
        
        for i, char in enumerate(text):
            if char in '{[':
                if not stack:
                    start = i
                stack.append(char)
            elif char in '}]':
                if stack:
                    expected = '{' if char == '}' else '['
                    if stack[-1] == expected:
                        stack.pop()
                        if not stack and start >= 0:
                            return text[start:i+1]
        
        return None


# Convenience function
def parse_json(text: str, strict: bool = False) -> ParseResult:
    """Quick JSON parsing from text."""
    return JSONParser(strict=strict).parse(text)
