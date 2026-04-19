---
name: nmkr-identity
description: >
  Create and manage Atala PRISM DIDs and W3C Verifiable Credentials for Cardano
  projects via the `nmkr-identity` CLI. Covers offline DID/VC/CIP-725 metadata
  generation and the remote `/api/v1` platform client (identity.nmkr.io). Use
  when the user says "create DID", "NMKR identity", "Verifiable Credential",
  "CIP-725 metadata", "sign VC", "PRISM DID", or references the
  atala-prism-platform repo.
---

# NMKR Identity CLI + API

## What it does

Two surfaces, one binary (`nmkr-identity`):

1. **Local (offline)** — produces JSON artifacts (DID Document, VC, CIP-725 metadata) using only the `token_identity` library. Nothing touches the network.
2. **Remote (`nmkr-identity remote ...`)** — talks to an NMKR Identity platform (defaults to `https://identity.nmkr.io`) over bearer-token-authenticated `/api/v1` endpoints.

Use local for developers producing artifacts for their own chain. Use remote when the user wants a platform-managed DID that the public can verify via `identity.nmkr.io/api/credentials/<id>`.

## Prerequisites

- Python 3.10+ with the repo installed (`pip install -e .` from the repo root, or `pip install token-identity` once published).
- Provides two entry points: `nmkr-identity` (preferred) and `token-identity` (legacy alias).
- For remote: an API token from https://identity.nmkr.io/settings — generated once, stored hashed on the server.

## Local recipes

### Generate a fresh keypair
```bash
nmkr-identity key new --out key.json
# or inline
nmkr-identity key new
```
The private key hex is shown **once** to stderr. Treat it like a cold-wallet seed.

### Create a DID Document
```bash
nmkr-identity did create \
  --collection "Acme GmbH" \
  --website https://acme.test \
  --twitter @acme \
  --privkey-hex "$PRIVKEY_HEX" \
  --out did.json
```
Omit `--privkey-hex` to generate a new key — it's printed to stderr.

### Issue a signed Verifiable Credential
```bash
nmkr-identity vc issue \
  --did did.json \
  --label "Genesis Drop" \
  --policy-id <hex_policy_id> \
  --asset AcmeAsset \
  --privkey-hex "$PRIVKEY_HEX" \
  --out vc.json
```

### Generate signed CIP-725 metadata
```bash
nmkr-identity metadata generate \
  --did did.json \
  --policy-id <hex_policy_id> \
  --collection "Acme GmbH" \
  --vc-url https://identity.nmkr.io/api/credentials/42 \
  --privkey-hex "$PRIVKEY_HEX" \
  --out metadata.json
```

### Verify a DID + metadata pair
```bash
nmkr-identity verify --did did.json --metadata metadata.json
# exits 0 on success, 3 on failure
```

## Remote recipes

### Login (one-time)
```bash
nmkr-identity remote login --token "$NMKR_TOKEN"
# Optional: --url https://staging.identity.nmkr.io
```
Stored at `~/.nmkr-identity/config.json` (chmod 600). You can skip login entirely by exporting `NMKR_IDENTITY_TOKEN` (and optionally `NMKR_IDENTITY_URL`).

### Create a platform DID
```bash
nmkr-identity remote did create --company "Acme GmbH" --website https://acme.test --description "On-chain identity" --out did.json
```
The response contains `privkey_hex` and `passphrase` — **save both immediately**, they are not retrievable later.

### Issue a credential + sign metadata
```bash
# Using the raw private key returned from `did create`:
nmkr-identity remote vc issue \
  --did-id 42 \
  --label "Genesis Drop" \
  --policy-id <hex_policy_id> \
  --asset AcmeAsset \
  --privkey-hex "$PRIVKEY_HEX"

nmkr-identity remote vc metadata 123 \
  --privkey-hex "$PRIVKEY_HEX" \
  --description "Genesis drop"

# Or using the passphrase (server-decrypts the stored encrypted key):
nmkr-identity remote vc issue --did-id 42 --label L --policy-id P --passphrase "$PASS"
```

### Housekeeping
```bash
nmkr-identity remote whoami
nmkr-identity remote did list
nmkr-identity remote vc list --did-id 42
nmkr-identity remote vc revoke 123 --reason "duplicate issuance"
```

## Key handling rules

1. **Never echo** `privkey_hex` or `passphrase` to chat. If capturing for later steps, pipe through `jq -r` into a shell variable and reference by name.
2. Prefer `--privkey-file` or `--passphrase-file` over `--privkey-hex`/`--passphrase` in scripts so secrets don't end up in shell history.
3. `--privkey-hex` env var fallback: `NMKR_IDENTITY_PRIVKEY_HEX`.
4. Remote tokens live at `~/.nmkr-identity/config.json` — treat like an SSH key.

## API surface reference (remote)

All endpoints require `Authorization: Bearer <token>`.

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/api/v1/me` | Current user |
| POST | `/api/v1/dids` | Create DID (returns one-time `privkey_hex` + `passphrase`) |
| GET  | `/api/v1/dids` | List caller's DIDs |
| GET  | `/api/v1/dids/<id>` | DID + attestations + credentials |
| POST | `/api/v1/dids/<id>/credentials` | Issue VC (needs signing key) |
| GET  | `/api/v1/dids/<id>/credentials` | List VCs on DID |
| GET  | `/api/v1/credentials/<id>` | VC detail |
| POST | `/api/v1/credentials/<id>/revoke` | Revoke |
| POST | `/api/v1/credentials/<id>/metadata` | Generate signed CIP-725 (needs signing key) |

For signing POSTs, body accepts either `{"privkey_hex": "..."}` or `{"passphrase": "..."}`.

## Common failure modes

- `401 unauthorized` — token missing, wrong, or revoked. Run `remote login` again or fetch a new token from `/settings`.
- `422 credential is missing policy_id` — metadata generation needs a VC with `credentialSubject.policyID`. Re-issue the VC with `--policy-id`.
- Schema validation: policy IDs must be hex-only (`^[a-f0-9]+$`) to pass CIP-725 schema validation.
- `403 forbidden` — the token belongs to a different account than the DID/credential owner.

## Repository pointers

- CLI entry: `token_identity/cli.py` (+ `token_identity/cli_remote.py`)
- HTTP client: `token_identity/remote.py`
- API v1: `webapp/api_v1.py`
- DID/VC core: `token_identity/prism_did.py`
- Models: `webapp/models.py`
- Live platform: https://identity.nmkr.io
