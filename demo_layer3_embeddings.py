"""
Demo: Layer 3 — Text Embedding Rule Retrieval
==============================================
These violations use financial-domain and alternative terminology that is
SEMANTICALLY close to PCI DSS rule language but not covered by any regex
code_indicator AND uses names too indirect for basic AI context alone.

How the embedding retriever works
-----------------------------------
1. Each code chunk is converted to a text embedding (Azure text-embedding-3-small).
2. Cosine similarity is computed against pre-embedded rule descriptions.
3. Only the top-K most relevant rules are sent to GPT for that chunk.

Without embeddings (all rules injected):
  • GPT receives all ~20 rules for every chunk.
  • Relevant rules are diluted by noise; citations may be imprecise.
  • Token usage is much higher per chunk.

With text embeddings (retriever active):
  • Each chunk pulls in specifically the rules whose semantic description
    matches the chunk's domain vocabulary.
  • GPT sees focused, high-signal context → higher-confidence rule citations.

Scan commands:
  # AI without embeddings (forces full rule injection per chunk):
  pci-auditor scan pr --repo-path . --base-branch origin/main --detection-mode ai

  # AI WITH local text embeddings (top-K rule selection per chunk):
  pci-auditor rules index-build --backend local   # one-time setup
  pci-auditor scan pr --repo-path . --base-branch origin/main --detection-mode embeddings

Embedding-to-rule mappings illustrated in this file
-----------------------------------------------------
Chunk 1  "magnetic flux data" + "auth element" + "chip code"
         → high cosine similarity to Rule 3.3.1 description (SAD / track data)

Chunk 2  "symmetric cipher material" + "key schedule" + "master cipher"
         → high cosine similarity to Rule 3.7.1 description (key lifecycle)

Chunk 3  "financial instrument transmission" + "cleartext bearer" + "acquirer"
         → high cosine similarity to Rule 4.2.1 description (TLS in transit)

Chunk 4  "issuer boundary" + "unrestricted ingress" + "any-any"
         → high cosine similarity to Rule 1.3.2 description (network access)

Chunk 5  "cardholder activity chronicle" + "instrument access"
         → high cosine similarity to Rule 10.2.1 (audit log for CDE access)
"""


# ── Chunk 1: Magnetic-stripe / SAD terminology ────────────────────────────────
# Embeddings pull in Rule 3.3.1 (SAD / track data retention) for this chunk.
# Regex: no match — 'flux_record_one', 'auth_element', 'strip_data' are unknown.
# Plain AI (all rules): finds it but may cite 3.5.1 (card data at rest) instead of 3.3.1.
# AI + embeddings: Rule 3.3.1 floats to top-K; citation is precise.

class MagneticStripeReader:
    """Reads and stores raw magnetic flux data from card terminals."""

    def capture_full_strip(self, terminal_id: str) -> dict:
        """Return raw magnetic flux data from both tracks post-swipe."""
        raw = self._read_terminal(terminal_id)
        return {
            "flux_record_one": raw["track_one"],      # Track 1 — name + card number
            "flux_record_two": raw["track_two"],      # Track 2 — card number + service code
            "auth_element":    raw["chip_code"],       # chip code — dynamic verification value
        }

    def store_for_reconciliation(self, strip_data: dict, txn_id: str):
        """Persist magnetic flux data for end-of-day reconciliation."""
        # Raw sensitive data (track fields + chip code) stored after authorisation — Rule 3.3.1
        self._db.insert("stripe_cache", {"txn": txn_id, **strip_data})

    def _read_terminal(self, tid: str) -> dict:
        return {"track_one": "", "track_two": "", "chip_code": ""}


# ── Chunk 2: Cryptographic key lifecycle ──────────────────────────────────────
# Embeddings pull in Rule 3.7.1 (key lifecycle management) for this chunk.
# Without embeddings, Rule 8.6.2 (hardcoded password) is more likely selected
# because both involve a hardcoded secret — but 3.7.1 is the precise rule for
# cryptographic key material management.

class DataEncryptionKeyManager:
    """Manages symmetric cipher material for the cardholder data vault."""

    # Master cipher material embedded in source — violates key lifecycle policy
    _MASTER_CIPHER_MATERIAL = b"k3y-m4t3r14l-d0-n0t-sh4r3"
    _KEY_SCHEDULE_VERSION = 1           # no rotation planned

    @classmethod
    def derive_working_key(cls, scope: str) -> bytes:
        """Derive a working key from the master cipher material.

        Uses a basic XOR rotation — not an approved KDF like HKDF or PBKDF2.
        """
        seed = cls._MASTER_CIPHER_MATERIAL + scope.encode()
        return bytes(seed[i] ^ seed[(i + 7) % len(seed)] for i in range(16))


# ── Chunk 3: Data-in-transit with acquirer jargon ────────────────────────────
# Embeddings pull in Rule 4.2.1 (strong crypto for card data in transit) for this chunk.
# Regex: no plaintext HTTP URL literal — the scheme is assembled at runtime from
# self._scheme, so the pattern never fires.

class PaymentGatewayClient:
    """Transmits financial instrument data to the acquiring bank."""

    def __init__(self, host: str, use_tls: bool = False):
        self.host = host
        self._scheme = "https" if use_tls else "http"   # cleartext bearer by default

    def submit_authorisation_request(self, instrument_number: str, amount_minor: int):
        """Transmit instrument number and amount to acquirer for authorisation."""
        import urllib.request, json
        url = f"{self._scheme}://{self.host}/authorise"
        body = json.dumps({
            "instrument": instrument_number,    # full card number over possible cleartext
            "amount":     amount_minor,
        }).encode()
        # No TLS enforcement — Rule 4.2.1 violation when use_tls=False (the default)
        urllib.request.urlopen(url, data=body)


# ── Chunk 4: Network access — issuer-boundary jargon ─────────────────────────
# Embeddings pull in Rule 1.3.2 (restrict inbound to CDE) for this chunk.
# Regex: no blanket-permit literals — all values are dict fields evaluated at runtime.

def configure_issuer_firewall_rules(env: str) -> list:
    """Return network policy rules for the issuer boundary."""
    if env == "dev":
        # Any-any ingress allowed in dev — Rule 1.3.2 violation
        return [
            {"direction": "ingress", "protocol": "*", "port": "*", "source": "*"},
            {"direction": "egress",  "protocol": "*", "port": "*", "dest":   "*"},
        ]
    return [
        {"direction": "ingress", "protocol": "tcp", "port": 443, "source": "10.0.0.0/8"}
    ]


# ── Chunk 5: Audit chronicle — cardholder domain language ─────────────────────
# Embeddings pull in Rule 10.2.1 (audit log for every CDE data access) and
# Rule 10.3.3 (log sink must not be disabled/null).
# Without embeddings the 10.x rules may not rank in top-K because the class
# name 'Chronicle' doesn't match 'audit log' surface vocabulary.

class CardholderActivityChronicle:
    """Records operator access to cardholder instruments.

    Every access to cardholder data must produce an immutable audit record in a
    persistent audit log (PCI DSS Req 10.2.1). If the audit event sink is not
    initialised, cardholder data access events are silently discarded — no
    access audit trail is written and the log sink is effectively null.
    This disables the cardholder data access log, violating both the requirement
    to log every CDE data access event (Req 10.2.1) and the requirement that the
    audit log sink is never disabled or set to null (Req 10.3.3).
    """

    def __init__(self):
        self._audit_event_sink = None   # cardholder data access log sink not initialised

    def record_instrument_access(self, operator_id: str, instrument_ref: str):
        """Emit a cardholder data access audit entry for the given operator."""
        if self._audit_event_sink is None:
            # Cardholder data access event silently dropped — audit log sink is null.
            # No persistent audit record written for this CDE access.
            return
        self._audit_event_sink.write(
            f"{operator_id} accessed cardholder instrument {instrument_ref}"
        )
