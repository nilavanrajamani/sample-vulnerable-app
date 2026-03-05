# Sample Vulnerable Payment Application

This is a deliberately insecure Flask application designed to demonstrate various PCI DSS compliance violations. It should NOT be used in production or with real payment data.

## Purpose

This application is created to test the `pci-auditor` tool. It contains numerous PCI DSS violations across multiple files to ensure comprehensive testing of the scanner.

## Violations Included

- **Rule 3.3.1**: Hardcoded and stored PANs, CVVs
- **Rule 3.3.2**: CVV storage after authorization
- **Rule 3.4.1**: PAN storage without encryption
- **Rule 3.5.1**: Hardcoded cryptographic keys
- **Rule 4.2.1**: HTTP usage, weak TLS protocols
- **Rule 6.2.4**: SQL injection, XSS, command injection
- **Rule 7.2.1**: Overly permissive access control
- **Rule 8.3.1**: Weak password hashing (MD5)
- **Rule 8.6.1**: Hardcoded passwords and API keys
- **Rule 10.2.1**: Missing audit logging
- **Rule 12.3.3**: Deprecated crypto algorithms (DES)

## Files

- `app.py`: Main Flask application with API endpoints
- `database.py`: Database operations with SQL injection
- `config.py`: Configuration with hardcoded secrets
- `payment.py`: Payment processing logic
- `utils.py`: Utility functions with various vulnerabilities

## Running

```bash
pip install -r requirements.txt
python app.py
```

## Testing with pci-auditor

To test the pci-auditor tool on this application:

```bash
pci-auditor scan codebase --path /path/to/sample-vulnerable-app
```

This should detect numerous violations across all the files.