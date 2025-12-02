# PAM Integration Instructions

This document provides instructions for integrating the password strength checker with Linux PAM (Pluggable Authentication Modules).

## Overview

PAM integration allows the password checker to validate passwords during system authentication or password change operations. This ensures that users cannot set weak passwords on the system.

## Method 1: Using pam_python Module

The `pam_python` module allows you to use Python scripts in PAM configuration.

### Prerequisites

```bash
# Install pam_python (may vary by distribution)
# Debian/Ubuntu:
sudo apt-get install libpam-python

# CentOS/RHEL/Fedora:
sudo yum install pam_python
# or
sudo dnf install pam_python

# Arch Linux:
sudo pacman -S libpam-python
```

### Installation Steps

1. **Install the password checker** (if not already installed):

```bash
# Copy files to system location
sudo mkdir -p /usr/local/lib/password-checker
sudo cp password_checker.py patterns.py /usr/local/lib/password-checker/
sudo chmod 644 /usr/local/lib/password-checker/*.py
```

2. **Create PAM Python module**:

Create `/usr/local/lib/password-checker/pam_password_check.py`:

```python
#!/usr/bin/env python3
"""
PAM module for password strength checking
"""

import sys
sys.path.insert(0, '/usr/local/lib/password-checker')

from password_checker import PasswordChecker

def pam_sm_chauthtok(pamh, flags, argv):
    """
    PAM password change hook
    Called when user changes password
    """
    try:
        # Get new password
        password = pamh.authtok
        
        if not password:
            # Prompt for password
            msg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "New password: ")
            resp = pamh.conversation(msg)
            password = resp.resp
        
        # Check password strength
        checker = PasswordChecker(min_length=8)
        results = checker.check_password(password)
        
        # Require minimum score
        min_score = 40  # Adjust as needed
        if results['score'] < min_score:
            error_msg = "Password is too weak. "
            error_msg += "Suggestions:\n"
            for suggestion in results['suggestions'][:3]:
                error_msg += f"  - {suggestion}\n"
            
            pamh.conversation(pamh.Message(pamh.PAM_ERROR_MSG, error_msg))
            return pamh.PAM_AUTHTOK_ERR
        
        # Check minimum length
        if not results['meets_min_length']:
            error_msg = f"Password must be at least {checker.min_length} characters."
            pamh.conversation(pamh.Message(pamh.PAM_ERROR_MSG, error_msg))
            return pamh.PAM_AUTHTOK_ERR
        
        # Check if password is too common
        if results['is_common']:
            error_msg = "Password is too common. Please choose a different one."
            pamh.conversation(pamh.Message(pamh.PAM_ERROR_MSG, error_msg))
            return pamh.PAM_AUTHTOK_ERR
        
        return pamh.PAM_SUCCESS
        
    except Exception as e:
        # Log error (check /var/log/auth.log or similar)
        return pamh.PAM_AUTHTOK_ERR

def pam_sm_authenticate(pamh, flags, argv):
    """Not used for password checking, only for changes"""
    return pamh.PAM_IGNORE

def pam_sm_setcred(pamh, flags, argv):
    """Not used"""
    return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
    """Not used"""
    return pamh.PAM_SUCCESS
```

3. **Set proper permissions**:

```bash
sudo chmod 755 /usr/local/lib/password-checker/pam_password_check.py
sudo chown root:root /usr/local/lib/password-checker/pam_password_check.py
```

4. **Configure PAM**:

Edit `/etc/pam.d/common-password` (Debian/Ubuntu) or `/etc/pam.d/passwd` (Red Hat/CentOS):

**For Debian/Ubuntu**, add to `/etc/pam.d/common-password`:

```
password    required    pam_python.so /usr/local/lib/password-checker/pam_password_check.py
```

**For Red Hat/CentOS/Fedora**, add to `/etc/pam.d/passwd`:

```
password    required    pam_python.so /usr/local/lib/password-checker/pam_password_check.py
```

**Important**: Make sure this line appears BEFORE the `pam_unix.so` line to validate before password is set.

Example full configuration:

```
password    requisite   pam_python.so /usr/local/lib/password-checker/pam_password_check.py
password    [success=1 default=ignore]  pam_unix.so obscure sha512
password    requisite   pam_deny.so
password    required    pam_permit.so
```

5. **Test the configuration**:

```bash
# Test password change
passwd testuser

# Check PAM logs if there are issues
sudo tail -f /var/log/auth.log  # Debian/Ubuntu
sudo tail -f /var/log/secure    # Red Hat/CentOS
```

## Method 2: Using External Script with pam_pwquality

Alternatively, you can use `pam_pwquality` (or `pam_cracklib`) for basic checks and add the Python checker as a wrapper script.

1. **Create wrapper script** at `/usr/local/bin/check_password_strength.sh`:

```bash
#!/bin/bash
# Password strength checker wrapper for PAM

export PYTHONPATH="/usr/local/lib/password-checker:$PYTHONPATH"
/usr/bin/python3 -c "
from password_checker import PasswordChecker
import sys

password = sys.stdin.read().strip()
checker = PasswordChecker(min_length=8)
results = checker.check_password(password)

if results['score'] < 40:
    sys.exit(1)
if not results['meets_min_length']:
    sys.exit(1)
if results['is_common']:
    sys.exit(1)
sys.exit(0)
" <<< "$1"
```

2. **Make executable**:

```bash
sudo chmod +x /usr/local/bin/check_password_strength.sh
```

3. **Configure in PAM** (this method is less integrated but simpler).

## Method 3: Using Systemd Service (Alternative Approach)

For checking passwords during user creation (via useradd), create a wrapper script:

1. **Create wrapper** at `/usr/local/bin/checkpasswd`:

```bash
#!/bin/bash
python3 /usr/local/lib/password-checker/main.py -p "$1"
```

2. **Use in user creation scripts** or integrate with your user management system.

## Testing

Before deploying in production:

1. **Test in a virtual machine** or isolated environment first
2. **Keep a root shell open** in case you lock yourself out
3. **Test with various password strengths** to ensure proper rejection/acceptance
4. **Verify error messages** are clear and helpful

## Troubleshooting

- **PAM errors**: Check `/var/log/auth.log` or `/var/log/secure`
- **Python import errors**: Verify PYTHONPATH and file permissions
- **Permission denied**: Ensure scripts are owned by root and have correct permissions
- **Locked out**: Boot into single-user mode or recovery mode to fix PAM configuration

## Security Considerations

1. **File permissions**: All Python files should be readable only by root
2. **Logging**: Consider logging password check failures (but NOT the passwords themselves)
3. **Performance**: The checker is fast, but for large systems, consider caching common passwords list
4. **Bypass protection**: Ensure PAM configuration cannot be easily bypassed

## Customization

You can customize the checker behavior by modifying the PAM module script:

- Adjust `min_score` threshold (line ~30)
- Change minimum length requirement
- Modify error messages
- Add logging of failed attempts
- Integrate with external password databases

## Notes

- **Backup PAM configs** before modifying: `sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.backup`
- **Test thoroughly** in a non-production environment
- Some distributions may have different PAM module locations or naming conventions
- The `pam_python` module must match your Python version (Python 3.x)

## References

- PAM Documentation: `man pam`
- pam_python: Check your distribution's documentation
- Python PAM bindings: Various libraries available (python-pam, etc.)

