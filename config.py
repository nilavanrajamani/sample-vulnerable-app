# Configuration file with hardcoded secrets

# Database configuration
DATABASE_URL = "sqlite:///payments.db"
DATABASE_USER = "admin"
DATABASE_PASSWORD = "supersecret123"  # Hardcoded password (Rule 8.6.1)

# Payment gateway keys
STRIPE_SECRET_KEY = "your_stripe_secret_key_here"  # Hardcoded API key
PAYPAL_CLIENT_ID = "paypal_client_id_here"
PAYPAL_CLIENT_SECRET = "paypal_secret_here"  # Hardcoded secret

# Encryption settings
AES_KEY = "1234567890123456"  # Weak/hardcoded key (Rule 3.5.1)
IV = "abcdefghijklmnop"  # Hardcoded IV

# Logging configuration
LOG_LEVEL = "DEBUG"
LOG_FILE = "/var/log/payments.log"

# Test data with PAN (Rule 3.3.1)
TEST_CARDS = [
    {"pan": "4111111111111111", "cvv": "123", "expiry": "12/25"},
    {"pan": "5555555555554444", "cvv": "456", "expiry": "06/26"},
    {"pan": "378282246310005", "cvv": "789", "expiry": "09/27"}  # Amex with CVV
]

# SSL/TLS configuration
SSL_CERT_PATH = "/path/to/cert.pem"
SSL_KEY_PATH = "/path/to/key.pem"

# Deprecated crypto (Rule 12.3.3)
CRYPTO_ALGORITHM = "DES"  # DES is deprecated

# Access control (Rule 7.2.1)
ALLOWED_IPS = ["0.0.0.0/0"]  # Overly permissive

# Audit logging disabled (Rule 10.2.1)
ENABLE_AUDIT_LOG = False