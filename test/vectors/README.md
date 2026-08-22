# Conformance Vectors

Cross-implementation verification fixtures for mcp-audit-gateway's canonicalization and hash chain.

## Two hash operations, two guarantees

This implementation uses two distinct hash operations for different purposes:

**Canonical hash (signing):** SHA-256 of a tuple-array serialization with a fixed 11-field order. The attestation field is excluded (it cannot sign itself). This form is cross-language reproducible — any implementation that follows the field order and null rule will produce identical bytes.

**Chain hash (linking):** SHA-256 of `JSON.stringify(fullRecord)` including the attestation field. This binds the signature into the chain sequence. It depends on JavaScript insertion order and is JS-authoritative — other languages must serialize keys in the documented order to verify.

## Running the verifiers

```bash
# JavaScript (Node.js 18+)
node verify.mjs

# Python (3.7+)
python3 verify.py
```

## Regenerating vectors

```bash
node generate.mjs
```

The generator uses the same canonicalization logic as `src/attestation/signer.ts`. If the source changes, regenerate and re-run both verifiers to confirm cross-language agreement.

## Vector coverage

| Vector | Tests |
|--------|-------|
| genesis_all_fields | All fields populated, first record in chain |
| genesis_null_optionals | Absent optional fields serialize as null |
| error_with_code | success: false with negative error code |
| zero_duration | durationMs: 0 boundary |
| invalid_params_error | Different JSON-RPC error code |
| unicode_in_fields | CJK and emoji in string fields |
| max_safe_integer_duration | durationMs: 9007199254740991 (2^53-1) |
| empty_string_tool_name | Empty string vs null distinction |
| chain[0-2] | Three linked records with attestation |
| dual_hash_demo | Same fields, different attestation: proves canonical hash matches while chain hash differs |
