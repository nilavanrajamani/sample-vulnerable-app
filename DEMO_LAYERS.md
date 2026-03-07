# PCI Auditor — Demo Layer Validation

This document records the results of running `pci-auditor` against the four demo
files with progressively richer detection capabilities. It explains **why each
detection layer matters** and provides the concrete findings produced by each.

---

## How to run the scans yourself

```bash
# Pattern-only (no AI, no embeddings)
pci-auditor scan pr --repo-path . --base-branch origin/main --no-ai

# AI model only (no embedding retriever)
pci-auditor scan pr --repo-path . --base-branch origin/main

# Full stack: AI + Azure Search vector index
pci-auditor scan pr --repo-path . --base-branch origin/main
# (requires AZURE_OPENAI_EMBEDDING_DEPLOYMENT and AZURE_SEARCH_* env vars)
```

---

## Detection layer overview

| Layer | File | Regex | AI | Embeddings / Azure Search |
|-------|------|-------|----|--------------------------|
| 1 | `demo_layer1_regex.py` | ✅ catches all | not needed | not needed |
| 2 | `demo_layer2_ai.py` | ❌ 0 findings | ✅ catches all | not needed |
| 3 | `demo_layer3_embeddings.py` | ❌ 0 findings | ⚠️ imprecise | ✅ precise citations |
| 4 | `demo_layer4_azure_search.py` | ✅ partial | ⚠️ ambiguous pairs | ✅ disambiguates pairs |

---

## Layer 1 — Regex Pattern Detection (`demo_layer1_regex.py`)

**Scan command:** `pci-auditor scan pr --repo-path . --base-branch origin/main --no-ai`

**Why this layer matters:**  
The cheapest and fastest detection stage. A library of regular expressions
(`code_indicators` per rule) fires on exact keyword matches — no model call is
needed. This catches the most obvious violations: hardcoded card numbers,
credential assignments, deprecated import names, and insecure API calls.

**Validated findings (11 total, `source=pattern`):**

| Line | Rule | Severity | Trigger | Snippet |
|------|------|----------|---------|---------|
| 31 | 3.3.1 | CRITICAL | 16-digit PAN literal | `PRIMARY_ACCOUNT_NUMBER = "4111111111111111"` |
| 38 | 8.6.2 | CRITICAL | `password =` credential assignment | `password = "Sup3rS3cret!"` |
| 45 | 4.2.1 | CRITICAL | `http://` URL in payment endpoint | `PAYMENT_GATEWAY_URL = "http://payments.example.com/charge"` |
| 52 | 8.6.1 | HIGH | `md5` in function name | `def hash_password_md5(raw: str) -> str:` |
| 56 | 8.6.1 | HIGH | `sha1` in function name | `def hash_password_sha1(raw: str) -> str:` |
| 63 | 12.3.3 | HIGH | `DES3`, `ARC4` import | `from Crypto.Cipher import DES3, ARC4` |
| 71 | 4.2.1.1 | MEDIUM | `verify=False` in HTTPS call | `return requests.post(PAYMENT_GATEWAY_URL, ..., verify=False)` |
| 77 | 8.3.6 | HIGH | `MIN_PASSWORD_LENGTH = 8` | Password length below PCI minimum of 12 |
| 90 | 7.2.1 | HIGH | `SELECT * FROM` string concat | `"SELECT * FROM cards WHERE id = " + user_input` |
| 90 | 10.2.1 | HIGH | string-concatenated query | Same line — query without parameterisation or audit |
| 95 | 6.2.4 | HIGH | `eval(` call | `return eval(expression)` |

> **Note on comment filtering:** the scanner now skips matches that fall inside
> comment regions (language-aware), so keywords in inline comments or docstrings
> do **not** produce false positives.

---

## Layer 2 — AI Model Detection (`demo_layer2_ai.py`)

**Scan commands:**

```bash
# Should produce 0 findings — regex cannot see these violations:
pci-auditor scan pr --repo-path . --base-branch origin/main --no-ai

# Should produce 6 findings — AI infers intent from context:
pci-auditor scan pr --repo-path . --base-branch origin/main
```

**Why this layer matters:**  
Real-world violations rarely use the exact keywords a regex library was trained
on. Developers use generic variable names (`account_ref`, `auth_element`,
`sec_code`) and encode violations in business logic control-flow — a missing
audit call, a default-allow fallback on auth error, an environment-flag MFA
bypass. Only an LLM can understand *what the code is doing* rather than what it
literally says.

**Regex scan result: 0 findings**

All variable names, function names and structure deliberately avoid the keywords
in every `code_indicator` entry. The violations are:

- Structural: a missing `self.audit.info(...)` call (10.2.1) — no regex can
  match an *absent* statement.
- Generic naming: `auth_element`, `account_digits`, `verification`, `instrument`
  — none match any code_indicator pattern.
- Multi-line logic: the `except Exception … pass / return True` pattern spans
  multiple lines; single-line bare-handler patterns don't match it.
- Semantic equivalence: `SKIP_SECOND_FACTOR` is functionally identical to
  disabling MFA but has no keyword the regex list knows about.

**Expected AI findings (6 total, `source=ai`):**

| Rule | Severity | Violation | Why regex misses |
|------|----------|-----------|-----------------|
| 3.4.1 | HIGH | `get_payment_instrument_details` returns `full_number` unmasked | Key `instrument` doesn't match any indicator |
| 3.3.1 | CRITICAL | `AuthorizationProcessor` stores `auth_element` (security code) in `audit_log` post-auth | Variable `auth_element` not in indicator list |
| 3.3.2 | CRITICAL | `stage_payment` caches raw `account_digits` + `verification` in session dict pre-auth | Generic dict keys; not `session["cvv"]` etc. |
| 10.2.1 | HIGH | `CardholderRepository.retrieve_for_dispute` queries cardholder data but never calls audit logger | *Negative* pattern — absence of a call |
| 10.7.2 | MEDIUM | `authenticate_admin_user` swallows auth failure and returns `True` | Multi-line try/pass/return pattern |
| 8.4.2 | CRITICAL | `require_elevated_access` skips TOTP when `SKIP_SECOND_FACTOR` is set | Env var name has no semantic match in indicators |

---

## Layer 3 — Text Embedding Rule Retrieval (`demo_layer3_embeddings.py`)

**Scan commands:**

```bash
# 0 findings — no regex matches:
pci-auditor scan pr --repo-path . --base-branch origin/main --no-ai

# AI findings, but rule citations may be imprecise (all rules injected per chunk):
pci-auditor scan pr --repo-path . --base-branch origin/main

# AI findings with precise citations (embedding retriever selects top-K rules per chunk):
pci-auditor scan pr --repo-path . --base-branch origin/main
# (AZURE_OPENAI_EMBEDDING_DEPLOYMENT must be configured)
```

**Why this layer matters:**  
This file uses **financial-domain jargon** — "magnetic flux data", "symmetric
cipher material", "key schedule", "financial instrument transmission",
"cardholder activity chronicle". None of these phrases appear in any rule's
`code_indicator`, yet each chunk maps to a specific PCI DSS rule by *semantic
meaning*.

Without embeddings, the AI receives all ~20 rules for every chunk. The relevant
rules are diluted by noise and citations can be imprecise — e.g. a chunk about
cryptographic key material might be cited as Rule 8.6.2 (hardcoded password)
rather than the more precise Rule 3.7.1 (key lifecycle management). Embeddings
solve this by:

1. Converting each code chunk to a vector embedding.
2. Computing cosine similarity against pre-embedded rule descriptions.
3. Sending only the **top-K** most semantically relevant rules to the AI.

**Regex scan result: 0 findings**

Every keyword is deliberately abstracted: no `http://` URL (scheme is
assembled at runtime), no `hashlib.md5` call, no `0.0.0.0/0` string, no
`NullHandler` class reference anywhere in this file.

**Expected AI findings (5 chunks → 5 rules, `source=ai`):**

| Chunk | Domain vocabulary used | Closest rule (with embeddings) | Without embeddings |
|-------|------------------------|--------------------------------|--------------------|
| 1 — `MagneticStripeReader` | "magnetic flux data", "chip code", "flux_record_one" | **3.3.1** SAD / track data retention | May cite 3.5.1 (card at rest) |
| 2 — `DataEncryptionKeyManager` | "symmetric cipher material", "key schedule", "master cipher" | **3.7.1** Cryptographic key lifecycle | May cite 8.6.2 (hardcoded password) |
| 3 — `PaymentGatewayClient` | "financial instrument", "acquirer", `_scheme = "http"` | **4.2.1** Strong crypto in transit | Likely correct but token-heavy |
| 4 — `configure_issuer_firewall_rules` | "issuer boundary", "any-any ingress", `"protocol": "*"` | **1.3.2** Restrict inbound to CDE | May cite 1.2.x generic network |
| 5 — `CardholderActivityChronicle` | "cardholder activity chronicle", `_sink = None` | **10.2.1 + 10.3.3** Audit log | May omit 10.3.3 without retriever |

---

## Layer 4 — Azure Cognitive Search Precision (`demo_layer4_azure_search.py`)

**Scan commands:**

```bash
# Partial findings — regex catches the obvious symptoms:
pci-auditor scan pr --repo-path . --base-branch origin/main --no-ai

# AI findings present but rule disambiguation may be wrong for related pairs:
pci-auditor scan pr --repo-path . --base-branch origin/main

# Correct rule cited for every pair:
pci-auditor scan pr --repo-path . --base-branch origin/main
# (full Azure Search config required)
```

**Why this layer matters:**  
When two PCI DSS rules share similar vocabulary (both about logging, both about
crypto strength, both about CDE access), plain cosine similarity can surface the
wrong rule. Azure Cognitive Search adds **hybrid BM25 + vector ranking** plus
**metadata category filters**, enabling disambiguation of rule *pairs* that
describe related but distinct controls.

**Regex scan result: 10 findings** — the pattern scanner catches the literal
symptoms (`3DES`, `ssl.PROTOCOL_TLSv1`, `hardcoded_aes_key`, `SMTP_PASSWORD`,
`logging.NullHandler`). However, it cannot distinguish *which* rule in a
semantically similar pair is the correct citation.

**Validated regex findings (10 total, `source=pattern`):**

| Line | Rule | Severity | Snippet |
|------|------|----------|---------|
| 67 | 3.7.1 | HIGH | `hardcoded_aes_key = bytes.fromhex(...)` |
| 75 | 3.7.1 | HIGH | `cipher = AES.new(self.hardcoded_aes_key, ...)` |
| 95 | 8.6.2 | CRITICAL | `SMTP_PASSWORD = "EmailS3nd3r!"` |
| 151 | 10.3.3 | MEDIUM | `root.addHandler(logging.NullHandler())` |
| 204 | 2.2.1 | HIGH | `class LegacyCryptoAdapter:` |
| 218 | 12.3.3 | HIGH | `ALGORITHM = "3DES"` |
| 226 | 2.2.1 | HIGH | `class LegacyTerminalNetwork:` |
| 241 | 4.2.1 | CRITICAL | `TLS_VERSION = ssl.PROTOCOL_TLSv1` |
| 245 | 4.2.1 | CRITICAL | `ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)` |
| 246 | 12.3.3 | HIGH | `ctx.set_ciphers("RC4-SHA")` |

**Rule pairs disambiguated by Azure Search (expected AI findings):**

| Pair | Correct rule | Confused with | Azure Search signal | Violation |
|------|-------------|---------------|--------------------|-|
| 1 | **3.7.1** | 8.6.2 | Category "Protect Stored Account Data" | `hardcoded_aes_key` — cryptographic key material (not just a password) in `CardVaultEncryption` |
| 1 | **8.6.2** | 3.7.1 | Category "Strong Authentication" | `SMTP_PASSWORD` — application credential (not crypto key) in `AppConfigLoader` |
| 2 | **10.2.1** | 10.3.3 | BM25 "cardholder data access" + category "Log and Monitor" | `CardDataService.get_card_details_for_refund` never emits audit call |
| 2 | **10.3.3** | 10.2.1 | BM25 "null-sink / log-stack" + category "Log and Monitor" | `LoggingBootstrap.configure` installs `NullHandler` at root |
| 3 | **7.2.1** | 8.4.2 | Category "Restrict Access to Cardholder Data" | `get_cardholder_data_endpoint` — no role check (authorisation) |
| 3 | **8.4.2** | 7.2.1 | Category "Strong Authentication" | `AdminConsoleAuth.login` skips TOTP when `FAST_LOGIN` set (authentication) |
| 4 | **12.3.3** | 4.2.1 | BM25 "old-cipher / cipher / algorithm" | `LegacyCryptoAdapter` uses `3DES` for stored PIN data |
| 4 | **4.2.1** | 12.3.3 | BM25 "old-tls / tls-constant / transport" | `LegacyTerminalNetwork` forces `ssl.PROTOCOL_TLSv1` for network transport |

---

## Summary — Why each layer is essential

```
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 1: Regex          Fast, free, zero latency                   │
│           Catches:  Hardcoded literals, known crypto names,         │
│                     URL schemes, credential assignments             │
│           Misses:   Generic variable names, logic-level violations, │
│                     absent calls, multi-line patterns               │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 2: AI model       Understands intent and context             │
│           Catches:  All Layer 1 + business-logic violations,        │
│                     obfuscated names, negative patterns             │
│           Misses:   Domain jargon that maps to a specific rule      │
│                     only by semantic similarity                     │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 3: Text Embeddings  Semantic rule selection per chunk        │
│           Catches:  All Layer 2 + domain-vocabulary violations      │
│           Reduces:  Token cost (top-K rules only) and imprecision   │
│           Misses:   Disambiguation of closely related rule pairs    │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 4: Azure Search   Hybrid BM25 + vector + category filter     │
│           Catches:  All Layer 3 + correct rule for ambiguous pairs  │
│           Adds:     Rule-pair disambiguation, re-ranking,           │
│                     metadata-guided context filtering               │
└─────────────────────────────────────────────────────────────────────┘
```

Each layer is **additive** — the scanner runs all active layers in sequence and
deduplicates by `(rule_id, line_number)`, so enabling AI or embeddings never
removes findings already caught by patterns.
