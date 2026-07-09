# LLM Utilities

Reusable Python utilities for LLM projects.

## Modules

### 1. LLM Auditor (`llm_utils.LLMAuditor`)
Validates inputs and outputs to prevent prompt injections and sensitive data leakage.

```python
from llm_utils import LLMAuditor

auditor = LLMAuditor()

# Validate input before sending to LLM
result = auditor.validate_input("user prompt here")
if not result.is_valid:
    print(f"Rejected: {result.reason}")

# Validate output before returning to user
result = auditor.validate_output("LLM response here")
if not result.is_valid:
    print(f"Blocked: {result.reason}")
```

### 2. JSON Parser (`llm_utils.JSONParser`)
Robustly parses JSON from LLM responses.

```python
from llm_utils import JSONParser

parser = JSONParser()

# Parse JSON from markdown code blocks
result = parser.parse(llm_response)
if result.success:
    print(result.data)

# Validate against schema
is_valid, error = parser.validate_schema(data, schema)
```

## Running the Demo

```bash
cd examples
python demo.py
```

## Input Patterns Detected
- Instruction override attempts ("ignore previous instructions")
- Role manipulation ("you are now a...")
- System prompt extraction
- Data extraction attempts
- SQL injection patterns

## Output Patterns Detected
- API keys (sk_live_*, aws keys, etc.)
- Passwords and secrets
- Credit card numbers
- Private keys
- Database connection strings
