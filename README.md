# NMKR Identity

> Atala PRISM DIDs + Verifiable Credentials + Cardano 725 metadata — end‑to‑end, verifiable, and simple.

---

## 1) What This Is

NMKR Identity lets projects prove who they are with a company DID, issue project/asset credentials, and ship Cardano 725 metadata that points back to those proofs — all signed with the same DID key.

- Company DID (your public key identity)
- Platform Attestation VC (our signed statement about your DID)
- Credential VC per project/asset (signed by your DID)
- Cardano 725 metadata (signed by your DID) that references your DID and VC URL

Verifiers check DID → VC → Platform VC → 725, all under your DID public key.

---

## 2) How It Works

1. Create DID
   - Enter company info; download your one‑time key. We never keep plaintext keys.
2. KYC & Review
   - Upload docs; admin reviews and approves.
3. Platform Attestation (VC)
   - We issue a VC (issuer = platform DID) referencing your DID (and policy).
4. Credentials
   - You create a VC per asset/project (issuer = your DID). Policy ID is required to scope the claim.
5. 725 Metadata
   - Generate signed metadata that references your DID (+ VC URL). Every version is saved and downloadable.

---

## 3) What Gets Signed

- DID Document — self‑signed by your DID key (public JWK inside)
- Platform Attestation — a VC signed by our platform DID (references your DID and policy)
- Credential VC — per asset/project, signed by your DID key
- 725 Metadata — signed by your DID key; references your DID (+ VC URL) in `files[]`

---

## 4) Verification (What Others Do)

- Start at the VC (issuer = DID)
- Resolve DID → verify DID Document signature (using its public JWK)
- Verify VC signature (using DID public key)
- Verify platform attestation VC signature (using platform public key)
- Verify 725 metadata signature (using DID public key) and confirm it references the same DID (+ VC URL)
- Check credential status (active/revoked)

In the UI, press “Verify” on a credential — the app runs every step and shows pass/fail.

---

## 5) Public Endpoints

- VC JSON
  - `GET /api/credentials/<id>`
- VC Status
  - `GET /api/credentials/<id>/status` → `{ id, type: "SimpleStatus", status }`
- DID + Attestations
  - `GET /api/dids/<did_id>/public`

All are safe to expose (they’re public material). Signatures are what give trust.

---

## 6) Web UI Tour

- DIDs (Dashboard) — DIDs as parents; credentials listed beneath with a “+” button
- DID Overview — DID chip, pretty DID JSON, platform attestation VCs
- Credential Detail — Verify, Download VC, Open Public VC, Generate 725, Saved metadata versions (download)

---

## 7) Run Locally

- Python 3.10+
- Install deps:
  ```bash
  python3 -m pip install -r requirements.txt
  ```
- Start dev server:
  ```bash
  python3 app.py
  ```
- Open: http://localhost:8000 (dev only; use a production server in prod)

### Environment Variables

- `SECRET_KEY` — Flask secret (set in production)
- `DATABASE_URL` — e.g., `postgresql+psycopg2://user:pass@host:5432/db` (defaults to `sqlite:///app.db`)
- `ADMIN_EMAIL`, `ADMIN_PASSWORD` — bootstrap/update admin at startup
- `VERIFIER_PRIVKEY_HEX` — 32‑byte hex; pins a stable platform verifier key
- `BASE_URL` — if set (e.g., `https://identity.nmkr.io`), used for link generation; otherwise the app falls back to the current host dynamically
- `SESSION_COOKIE_SECURE=1` — when serving behind HTTPS

### Docker (optional)

```bash
docker-compose up --build
```

---

## 8) CLI (Library Utilities)

- Generate DID:
  ```bash
  python -m token_identity.cli generate-did     --policy-id <policy> --collection <name>     [--asset <asset>] [--website url ...]     [--privkey-hex hex] [--out did.json]
  ```
- Generate 725 metadata:
  ```bash
  python -m token_identity.cli generate-metadata     --did did.json --policy-id <policy> --collection <name>     [--privkey-hex hex] [--out metadata.json]
  ```
- Verify (DID + 725):
  ```bash
  python -m token_identity.cli verify --did did.json --metadata metadata.json
  ```

---

## 9) Security

- Never expose or commit your private key. The app only stores an encrypted version; you download and hold the key for signing.
- The dev server (`python app.py`) is for development (debug + reloader). Use a production WSGI/ASGI server in prod and set strong secrets.

---

## 10) Notes

- CSRF (Flask‑WTF) and basic rate limits (Flask‑Limiter) are enabled.
- In dev (SQLite), schema changes can trigger rebuilds. Use Postgres + migrations for production.

---

## 11) License

- No license included. Add one if needed.
