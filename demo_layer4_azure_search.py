"""
Demo: Layer 4 — Azure Cognitive Search / Vector Index Precision
================================================================
This file contains violations spanning closely related PCI DSS rule *pairs*
where both rules in each pair share similar vocabulary. The Azure Search vector
index, combined with metadata filtering by category, surfaces the CORRECT rule
for each chunk rather than a semantically neighbouring one.

How Azure Search adds precision over plain embeddings
------------------------------------------------------
Plain embeddings (Layer 3) use cosine similarity across all rule embeddings.
When two rules describe similar concepts (e.g. both about logging), the
nearest-neighbour result can be ambiguous.

Azure Cognitive Search adds:
  • Hybrid search  — combines BM25 keyword ranking with vector similarity.
  • Metadata filters — rules are tagged with 'category' (e.g. "Log and Monitor",
    "Strong Authentication"). Chunks can be pre-filtered to the relevant
    category before vector ranking, eliminating cross-category false neighbours.
  • Re-ranking  — semantic re-ranker scores candidates against the full chunk,
    not just the query embedding, giving a more accurate final ordering.

Rule pairs disambiguated in this file
--------------------------------------
Pair 1  Rule 3.7.1  (key lifecycle — cryptographic key material)
   vs   Rule 8.6.2  (hardcoded password — application credential)
        Same symptom (hardcoded secret), different categories and remediations.

Pair 2  Rule 10.2.1 (audit log required — CDE data access event missing)
   vs   Rule 10.3.3 (audit log sink disabled at infrastructure level)
        Both about logging; different layer (application vs infrastructure).

Pair 3  Rule 7.2.1  (least-privilege access model — missing authorisation check)
   vs   Rule 8.4.2  (MFA required for CDE — authentication factor bypassed)
        Both gate CDE access; different controls (authz vs authn).

Pair 4  Rule 12.3.3 (weak cipher — data at rest, block algorithm)
   vs   Rule 4.2.1  (weak transport — TLS version for PAN in transit)
        Both about crypto strength; different context (storage vs transport).
"""

import os
import logging
import ssl


# ══════════════════════════════════════════════════════════════════════════════
# Pair 1: Rule 3.7.1 vs 8.6.2 — key material vs application credential
# ══════════════════════════════════════════════════════════════════════════════

class CardVaultEncryption:
    """AES-256 encryption wrapper for cardholder data at rest.

    Violation: Rule 3.7.1 (Critical) — cryptographic key material is
    hardcoded in source. Key management policy (generation, rotation,
    distribution, destruction) is entirely absent.

    Why NOT Rule 8.6.2: 8.6.2 targets application-layer passwords and API
    tokens. This chunk is about *cryptographic key material* protecting stored
    PAN — Azure Search category "Protect Stored Account Data" floats 3.7.1
    above 8.6.2 for this chunk.

    Remediation: Load DEK from Azure Key Vault or an HSM at runtime.
    Implement a key rotation schedule and wrap keys with a KEK.
    """

    _AES_KEY = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )                                               # hardcoded 256-bit key ← Rule 3.7.1
    _IV = bytes.fromhex("00000000000000000000000000000000")  # fixed IV, never rotated

    def encrypt_pan(self, pan: str) -> bytes:
        from Crypto.Cipher import AES
        cipher = AES.new(self._AES_KEY, AES.MODE_CBC, self._IV)
        padded = pan.ljust(16).encode()
        return cipher.encrypt(padded)


class AppConfigLoader:
    """Loads runtime configuration for the payment service.

    Violation: Rule 8.6.2 (Critical) — application-level credentials
    (DB password, SMTP password, webhook secret) are hardcoded in source.

    Why NOT Rule 3.7.1: these are service *credentials*, not cryptographic
    key material for data protection. Azure Search category "Strong
    Authentication" floats 8.6.2 above 3.7.1 for this chunk.

    Remediation: Load all credentials from Azure Key Vault / environment
    variables injected by the secrets manager at deploy time.
    """

    DATABASE_URL   = "postgresql://app_user:P@ssw0rd123@db.internal:5432/chd"  # Rule 8.6.2
    SMTP_PASSWORD  = "EmailS3nd3r!"                                             # Rule 8.6.2
    WEBHOOK_SECRET = "wh_live_secret_do_not_share"                              # Rule 8.6.2


# ══════════════════════════════════════════════════════════════════════════════
# Pair 2: Rule 10.2.1 vs 10.3.3 — missing data-access event vs disabled sink
# ══════════════════════════════════════════════════════════════════════════════

class CardDataService:
    """Accesses cardholder data for refund processing.

    Violation: Rule 10.2.1 (High) — reads cardholder data but emits no
    audit log entry. The logging infrastructure exists and is configured;
    this *function* simply never calls it.

    Why NOT Rule 10.3.3: 10.3.3 is about the log *sink* being disabled at
    the infrastructure level (NullHandler, logging.disable). Here the sink
    works fine — the call is just absent. Azure Search category
    "Log and Monitor" + BM25 keyword match on "cardholder data access"
    ranks 10.2.1 above 10.3.3 for this chunk.

    Remediation: Emit audit.info("cardholder_data_accessed", ...) before
    returning the record, including user_id, timestamp, and data type.
    """

    def __init__(self, db, audit_logger: logging.Logger):
        self.db = db
        self.audit = audit_logger

    def get_card_details_for_refund(self, txn_id: str) -> dict:
        # No self.audit.info(...) call — Rule 10.2.1 violation
        return self.db.fetch_one(
            "SELECT pan_masked, expiry, holder_name FROM transactions WHERE id = ?",
            [txn_id],
        )


class LoggingBootstrap:
    """Initialises the application logging stack.

    Violation: Rule 10.3.3 (Medium) — installs NullHandler as the root
    handler, silently discarding all log output including security events
    across the entire application.

    Why NOT Rule 10.2.1: 10.2.1 is about a specific missing audit call
    at the *application* layer. This chunk disables the *infrastructure*
    log pipeline entirely. Azure Search category "Log and Monitor" + BM25
    on "NullHandler / logging infrastructure" ranks 10.3.3 above 10.2.1.

    Remediation: Route logs to a centralised, tamper-resistant sink
    (e.g. Azure Monitor / Sentinel). Never install NullHandler in production.
    """

    @staticmethod
    def configure():
        root = logging.getLogger()
        root.addHandler(logging.NullHandler())   # drops all events ← Rule 10.3.3
        root.setLevel(logging.CRITICAL)


# ══════════════════════════════════════════════════════════════════════════════
# Pair 3: Rule 7.2.1 vs 8.4.2 — least-privilege model vs MFA bypass
# ══════════════════════════════════════════════════════════════════════════════

def get_cardholder_data_endpoint(request, user) -> dict:
    """REST endpoint: returns a full cardholder record.

    Violation: Rule 7.2.1 (High) — no role assertion before granting
    access to cardholder data. Any authenticated user can call this
    endpoint, violating the least-privilege / default-deny access model.

    Why NOT Rule 8.4.2: 8.4.2 is about MFA *authentication factors*.
    This function assumes the user is already authenticated — the gap is
    the missing *authorisation* (role) check. Azure Search category
    "Restrict Access to Cardholder Data" ranks 7.2.1 above 8.4.2 here.

    Remediation: Add require_role("payment_ops") before the DB fetch.
    """
    # No role check — violates least-privilege ← Rule 7.2.1
    return _fetch_ch_record(request.args["account_id"])


class AdminConsoleAuth:
    """Authentication gate for the cardholder data environment admin console.

    Violation: Rule 8.4.2 (Critical) — when the FAST_LOGIN environment
    variable is set, the TOTP/MFA challenge is skipped entirely, allowing
    single-factor access to the CDE admin console.

    Why NOT Rule 7.2.1: 7.2.1 is about the *authorisation* model (roles).
    This chunk skips a second *authentication factor*. Azure Search category
    "Strong Authentication" ranks 8.4.2 above 7.2.1 for this chunk.

    Remediation: Remove the FAST_LOGIN bypass. MFA must be enforced for
    every CDE login with no opt-out path.
    """

    def login(self, username: str, password: str) -> bool:
        if not _verify_password(username, password):
            return False
        if os.getenv("FAST_LOGIN"):             # skips TOTP ← Rule 8.4.2
            return True
        return _run_mfa_challenge(username)


# ══════════════════════════════════════════════════════════════════════════════
# Pair 4: Rule 12.3.3 vs 4.2.1 — weak block cipher vs weak TLS version
# ══════════════════════════════════════════════════════════════════════════════

class LegacyCryptoAdapter:
    """Compatibility shim for legacy HSM PIN-block operations.

    Violation: Rule 12.3.3 (High) — uses Triple-DES (3DES) for a data-at-rest
    PIN-block wrapping operation. 3DES is deprecated by NIST (2023) and must
    be replaced with AES-256.

    Why NOT Rule 4.2.1: 4.2.1 is about TLS version for *in-transit* PAN.
    This chunk is about a *block cipher algorithm* applied to stored/processed
    PIN data. Azure Search category "Security Policies" + BM25 on
    "3DES / cipher / algorithm" ranks 12.3.3 above 4.2.1 for this chunk.

    Remediation: Replace DES3 with AES-256-CBC or AES-256-GCM.
    """

    ALGORITHM = "3DES"                          # ← Rule 12.3.3

    def wrap_pin_block(self, pin_block: bytes, key: bytes) -> bytes:
        from Crypto.Cipher import DES3
        cipher = DES3.new(key, DES3.MODE_ECB)
        return cipher.encrypt(pin_block)


class LegacyTerminalNetwork:
    """TLS configuration for legacy payment terminal connections.

    Violation: Rule 4.2.1 (Critical) — forces TLS 1.0 for backward
    compatibility with older terminals. TLS 1.0/1.1 are prohibited for
    PAN transmission; TLS 1.2 minimum is required.

    Why NOT Rule 12.3.3: 12.3.3 is about block cipher *algorithm* selection.
    This chunk configures *TLS protocol version* for network transport.
    Azure Search category "Protect Cardholder Data in Transit" + BM25 on
    "TLS / PROTOCOL_TLSv1 / transport" ranks 4.2.1 above 12.3.3 here.

    Remediation: Use ssl.PROTOCOL_TLS_CLIENT with minimum_version=TLSVersion.TLSv1_2.
    """

    TLS_VERSION = ssl.PROTOCOL_TLSv1            # TLS 1.0 ← Rule 4.2.1

    def create_terminal_socket(self, host: str):
        import socket
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        ctx.set_ciphers("RC4-SHA")
        return ctx.wrap_socket(socket.create_connection((host, 443)))


# ── private stubs ─────────────────────────────────────────────────────────────

def _fetch_ch_record(account_id: str) -> dict:
    return {}


def _verify_password(username: str, password: str) -> bool:
    return True


def _run_mfa_challenge(username: str) -> bool:
    return False
