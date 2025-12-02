# Linux Password Strength Checker

A comprehensive Python password strength checker designed for Linux systems. This tool evaluates passwords based on length, character diversity, entropy, pattern detection, and provides actionable suggestions for improvement.

## Features

- ✅ **Comprehensive Checks**: Validates length, uppercase, lowercase, digits, and symbols
- 🔍 **Pattern Detection**: Identifies common weak patterns (sequences, keyboard patterns, repeated characters)
- 📊 **Entropy Calculation**: Estimates cryptographic strength in bits
- 📈 **Scoring System**: Provides a 0-100 score based on multiple factors
- 💡 **Improvement Suggestions**: Actionable recommendations to strengthen passwords
- 🚫 **Common Password Detection**: Checks against known weak passwords
- 🔌 **PAM Integration Ready**: Instructions included for Linux PAM integration
- 🐍 **Modular Design**: Clean, documented, and extensible codebase

## Requirements

- Python 3.6 or higher
- Linux operating system (for PAM integration)

## Installation

1. Clone or download this repository:

```bash
cd Linux_password
```

2. Ensure Python 3 is installed:

```bash
python3 --version
```

3. Make the main script executable (optional):

```bash
chmod +x main.py
```

## Usage

### Command Line Interface

#### Interactive Mode (Password Hidden)

```bash
python3 main.py
```

#### Direct Password Input

```bash
python3 main.py -p "MyPassword123!"
```

#### Verbose Output with Score Breakdown

```bash
python3 main.py -v -p "Test123"
```

#### JSON Output (for scripting)

```bash
python3 main.py --json -p "Password123"
```

#### From Standard Input

```bash
echo "password123" | python3 main.py
```

#### Custom Minimum Length

```bash
python3 main.py --min-length 12 -p "MyPass"
```

### Command Line Options

```
Options:
  -h, --help            Show help message
  -p, --password PWD    Password to check
  -v, --verbose         Show detailed score breakdown
  --min-length LEN      Minimum acceptable length (default: 8)
  --json                Output results in JSON format
```

### Python API

You can also use the password checker as a Python module:

```python
from password_checker import PasswordChecker

# Create checker instance
checker = PasswordChecker(min_length=8)

# Check a password
results = checker.check_password("MyPassword123!")

# Access results
print(f"Score: {results['score']}/100")
print(f"Length: {results['length']}")
print(f"Entropy: {results['entropy']} bits")
print(f"Suggestions: {results['suggestions']}")
```

#### Available Methods

```python
# Check length
meets_min, length = checker.check_length(password)

# Check character types
char_types = checker.check_character_types(password)
# Returns: {'uppercase': bool, 'lowercase': bool, 'digits': bool, 'symbols': bool}

# Calculate entropy
entropy = checker.calculate_entropy(password)

# Calculate score
score, breakdown = checker.calculate_score(password)

# Get suggestions
suggestions = checker.get_suggestions(password)

# Full check
results = checker.check_password(password)
```

## Scoring System

The password strength is scored from 0-100 based on:

- **Length (0-30 points)**: Longer passwords score higher (up to 30 points)
- **Character Diversity (0-25 points)**: Mix of uppercase, lowercase, digits, symbols
- **Entropy (0-25 points)**: Cryptographic strength based on character set
- **Pattern Penalties (-50 to 0)**: Deductions for weak patterns
- **Common Password Penalty (-50)**: Severe penalty for known weak passwords

### Score Interpretation

- **80-100**: Very Strong - Excellent password
- **60-79**: Strong - Good password with minor improvements possible
- **40-59**: Moderate - Acceptable but could be improved
- **0-39**: Weak - Should be strengthened before use

## Example Output

```
============================================================
Password Strength Report
============================================================

🟢 Strength Score: 85/100 (VERY STRONG)
[████████████████████████████████████████░░░░░░░░░░░░]

Password Length: 14 characters

Character Types:
  ✓ Uppercase letters
  ✓ Lowercase letters
  ✓ Digits
  ✓ Special symbols

Entropy: 65.4 bits
  ✓ Good entropy - password has high randomness

💡 Suggestions for Improvement:
  1. Password meets basic strength requirements

============================================================
```

## Pattern Detection

The checker identifies various weak patterns:

- **Sequential characters**: `abc`, `123`, `zyx`
- **Keyboard patterns**: `qwerty`, `asdf`, `zxcv`
- **Repeated characters**: `aaa`, `111`, `###`
- **Common substitutions**: `p@ssw0rd`, `adm1n`
- **Single character type**: All letters or all digits

## Common Passwords

The tool checks against a list of common passwords. You can extend this list by creating a `common_passwords.txt` file (one password per line) in the same directory.

## PAM Integration

For integrating with Linux PAM (Pluggable Authentication Modules), see [PAM_INTEGRATION.md](PAM_INTEGRATION.md) for detailed instructions.

Brief overview:

1. Install `pam_python` module
2. Copy password checker files to system location
3. Create PAM Python module
4. Configure PAM configuration files
5. Test thoroughly

**⚠️ Important**: Always test PAM integration in a virtual machine or isolated environment first!

## Project Structure

```
Linux_password/
├── password_checker.py    # Main password checking logic
├── patterns.py            # Pattern detection module
├── main.py               # CLI interface
├── README.md             # This file
├── PAM_INTEGRATION.md    # PAM integration guide
└── common_passwords.txt  # Optional: extended common passwords list
```

## Module Documentation

### password_checker.py

Main module containing the `PasswordChecker` class with all password validation logic.

### patterns.py

Pattern detection module that identifies weak patterns in passwords.

## Exit Codes

When using the CLI:

- `0`: Strong password (score ≥ 60)
- `1`: Moderate password (score 40-59)
- `2`: Weak password (score < 40)

This allows scripting integration:

```bash
if python3 main.py -p "$password"; then
    echo "Password accepted"
else
    echo "Password rejected"
fi
```

## Security Considerations

- **Never log passwords**: The tool does not log passwords, but be cautious when integrating
- **File permissions**: Keep Python files secure (readable by authorized users only)
- **Testing**: Always test PAM integration in a safe environment
- **Entropy**: Higher entropy means better security, aim for 40+ bits minimum

## Customization

You can customize the checker by:

1. **Adjusting scoring weights** in `PasswordChecker.calculate_score()`
2. **Adding custom patterns** in `patterns.py`
3. **Modifying minimum requirements** via constructor parameters
4. **Extending common passwords list** via `common_passwords.txt`

## Contributing

Feel free to extend the functionality:

- Add more pattern detections
- Improve entropy calculations
- Add support for passphrase checking
- Integrate with password databases
- Add localization support

## License

This project is provided as-is for educational and practical use on Linux systems.

## Troubleshooting

### Import Errors

If you get import errors, ensure both `password_checker.py` and `patterns.py` are in the same directory or in your Python path.

### PAM Integration Issues

- Check PAM logs: `/var/log/auth.log` or `/var/log/secure`
- Verify file permissions and ownership
- Ensure `pam_python` module is installed
- Test in isolated environment first

### Permission Denied

Ensure scripts have proper execute permissions:

```bash
chmod +x main.py
```

## Examples

### Check password from script

```bash
#!/bin/bash
PASSWORD="UserPassword123!"
python3 main.py -p "$PASSWORD"
```

### Use in Python script

```python
#!/usr/bin/env python3
from password_checker import PasswordChecker

checker = PasswordChecker(min_length=10)

passwords = ["weak", "Strong123!", "VeryStrong!@#Pass456"]

for pwd in passwords:
    result = checker.check_password(pwd)
    print(f"{pwd}: {result['score']}/100")
```

## References

- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- Linux PAM Documentation: `man pam`

---

**Note**: This tool is designed for Linux systems. While the Python code may run on other platforms, PAM integration is Linux-specific.

