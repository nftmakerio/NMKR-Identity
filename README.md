NMKR Identity — Atala PRISM DID + VC + Cardano 725 Metadata

What this does
- Create a company DID (public key identity) and keep your private key encrypted client‑side.
- After KYC, the platform issues a Verifiable Credential (VC) attesting to your DID.
- You create per‑project/asset VCs signed by your DID.
- Generate Cardano 725 metadata signed by your DID that references your DID (and VC URL) for on‑chain use.
- Verifiers cryptographically check: DID Document → VC → Platform VC → 725 metadata, all under your DID’s public key.

How it works (end‑to‑end)
1) Create DID
- Enter company details; download your one‑time key (we never store plaintext keys).

2) KYC & Review
- Upload documents; an admin reviews and approves.

3) Platform Attestation (VC)
- On approval, the platform issues a signed VC about your DID (issuer = platform DID).

4) Credentials
- For each asset/project, you create a VC (issuer = your DID). Required: policy ID (scopes the claim).

5) Token Metadata (725)
- Generate 725 JSON that references your DID and VC URL, signed with the same DID key. Save, view and download each version in the UI.

What gets signed
- DID Document: Self‑signed by your DID key (public JWK inside the document).
- Platform Attestation: A VC signed by the platform DID, referencing your DID (and policy).
- Credential VC: Per asset/project, signed by your DID key (issuer = your DID).
- 725 Metadata: Signed by your DID key; references your DID (and VC URL) in files[].

Verification path (what third parties do)
- Start at the VC: issuer is your DID.
- Resolve DID → Verify DID Document signature (using public JWK inside it).
- Verify VC signature (using DID public key).
- Verify platform attestation VC signature (using platform public key).
- Verify 725 metadata signature (using DID public key) and confirm it references the same DID (and VC URL).
- Check credential status endpoint for active/revoked.

Public endpoints (no auth)
- VC JSON: `GET /api/credentials/<id>`
- VC status: `GET /api/credentials/<id>/status` → `{ id, type: "SimpleStatus", status }`
- DID + attestations: `GET /api/dids/<did_id>/public`

UI quick tour
- DIDs (Dashboard): Your DIDs as parents; credentials listed beneath with a “+” to add.
- DID Overview: DID chip, pretty DID JSON, platform attestations.
- Credential Detail: Actions (Verify, Download VC, Open Public VC), 725 generator, saved metadata history with downloads.
- Verify button: Reproduces a full third‑party verification with pass/fail per step.

Run locally
- Requirements: Python 3.10+
- Install deps: `python3 -m pip install -r requirements.txt`
- Start dev server: `python3 app.py`
- Open: http://localhost:8000 (dev only; do not use dev server in production)

Environment
- `SECRET_KEY`: Flask secret (set in production).
- `DATABASE_URL`: e.g., `postgresql+psycopg2://user:pass@host:5432/db` (default uses local SQLite `app.db`).
- `ADMIN_EMAIL`, `ADMIN_PASSWORD`: bootstrap admin (updated at startup if they change).
- `VERIFIER_PRIVKEY_HEX`: 32‑byte hex to pin a stable platform verifier key.
- `BASE_URL`: Optional. If set (e.g., `https://identity.nmkr.io`), used for link generation; otherwise the app falls back to the current host dynamically.
- `SESSION_COOKIE_SECURE=1`: when running behind HTTPS.

Docker (optional)
- `docker-compose up --build` (example compose included; harden for production).

CLI (library utilities)
- Generate DID:
  `python -m token_identity.cli generate-did --policy-id <id> --collection <name> [--asset <asset>] [--website url ...] [--privkey-hex hex] [--out did.json]`
- Generate 725:
  `python -m token_identity.cli generate-metadata --did did.json --policy-id <id> --collection <name> [--privkey-hex hex] [--out metadata.json]`
- Verify (DID + 725):
  `python -m token_identity.cli verify --did did.json --metadata metadata.json [--privkey-hex hex]`

Security
- Never commit or expose your private key. The app only stores an encrypted version; you download your key for signing.
- The dev server (`python app.py`) is for development only (debug + reloader). Use a proper WSGI/ASGI server in production.

Notes
- CSRF protection (Flask‑WTF) and basic rate limits (Flask‑Limiter) are enabled.
- In dev (SQLite), schema is auto‑managed and may drop/recreate on certain changes. Use Postgres + migrations for production.

License
- No license included. Add one if needed.
