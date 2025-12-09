Token Identity Standard: Real World Asset Verification (Atala PRISM)

Overview
- Implements the bidirectional verification standard using Atala PRISM DIDs and Cardano token metadata ("725").
- Provides Python library + CLI to create and verify:
  - DID Document with embedded policy/asset references and social proofs
  - Token Metadata linking to DID and signed by the DID key

Features
- secp256k1 signing using deterministic ECDSA.
- Canonical JSON signing (sort_keys=True) for DID payload and token metadata.
- JSON Schemas for DID Document and Token Metadata.
- CLI for generation and verification flows.

Quickstart
- Install Python 3.10+
- Install dependencies: `python3 -m pip install -r requirements.txt`
- Generate example: `python3 -m token_identity.examples.example_usage`

Web App
- Start the server: `python3 app.py`
- Open: http://localhost:8000
- Enter company info and submit. The server generates a DID and shows the DID and full DID Document.

Production-ish setup
- Docker (with Postgres): `docker-compose up --build`
- Env vars:
  - `DATABASE_URL` (e.g., `postgresql+psycopg2://user:pass@host:5432/db`)
  - `SECRET_KEY` (set in production)
  - `ADMIN_EMAIL`, `ADMIN_PASSWORD` (bootstrap admin)
  - `VERIFIER_PRIVKEY_HEX` (stable platform verifier key)
  - `SESSION_COOKIE_SECURE=1` (when using HTTPS)

Features implemented
- Accounts: register/login/logout, email verification (dev shows verify link), password reset (dev shows link)
- Dashboard: create and store DID, encrypted private key, KYC status
- Admin: approve and generate platform verifier attestation with notes
- DID detail: view DID doc, upload documents, generate signed 725 metadata with your passphrase
- API: `/api/dids/<id>` returns DID doc + attestations
- Health check: `/healthz`

Notes
- Dev SQLite schema auto-rebuilds if it detects old schema (drops all tables). Use Postgres + migrations for production.
- CSRF enabled via Flask‑WTF; rate limits on login/register via Flask‑Limiter.

CLI
- `token-identity generate-did --policy-id <id> --collection <name> [--asset <asset>] [--twitter @handle ...] [--discord id ...] [--website url ...] [--rwa-asset-type type --rwa-jurisdiction juris --rwa-registration number] [--out did.json]`
- `token-identity generate-metadata --did did.json --policy-id <id> --collection <name> [--out metadata.json]`
- `token-identity verify --did did.json --metadata metadata.json`

Notes
- The DID id suffix is a sha256 of `policy_id:collection_name[:asset_name]`.
- JWK public key uses base64url encoding without padding as per JsonWebKey2020.
- Proof type uses `EcdsaSecp256k1Signature2019` with deterministic ECDSA signatures.
- The metadata standard key uses `"725"` and includes a `files` entry referencing the DID id and a `proof` signed by the DID key.

Security
- Keep your private key secure. The example and CLI generate an in-memory key if one is not provided.
- For production, inject your own private key via `--privkey-hex` or environment variable.

Licensing
- No license is included. Provide one if needed.
