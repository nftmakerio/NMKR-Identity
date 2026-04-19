# NMKR Identity

> Atala PRISM DIDs + Verifiable Credentials + Cardano 725 metadata — end‑to‑end, verifiable, and simple.

**Ways to use it:**
- **Web app** — [identity.nmkr.io](https://identity.nmkr.io) self-service wizard
- **CLI** — `nmkr-identity` for local offline generation and remote platform calls ([§8](#8-cli))
- **JSON API** — bearer-token `/api/v1/*` endpoints for programmatic integration ([§8b](#8b-public-json-api-v1))
- **Claude Code skill** — [`skills/nmkr-identity/SKILL.md`](skills/nmkr-identity/SKILL.md) teaches an AI agent the full flow ([§8c](#8c-claude-code-skill))

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

## 8) CLI

Installed via `pip install -e .` (entry points: `nmkr-identity` preferred, `token-identity` legacy alias).

### Local — offline artifact generation

```bash
nmkr-identity key new                                # generate a keypair
nmkr-identity did create --collection "Acme" \
  --website https://acme.test --out did.json         # create a DID Document
nmkr-identity vc issue --did did.json --label "Genesis" \
  --policy-id <hex> --privkey-hex $KEY --out vc.json
nmkr-identity metadata generate --did did.json \
  --policy-id <hex> --collection "Acme" \
  --privkey-hex $KEY --out metadata.json
nmkr-identity verify --did did.json --metadata metadata.json
```

Private keys resolve from `--privkey-hex`, `--privkey-file`, or the `NMKR_IDENTITY_PRIVKEY_HEX` env var. Legacy `generate-did` / `generate-metadata` commands still work.

### Remote — talk to identity.nmkr.io

```bash
# one-time: mint a token at /settings and save it locally
nmkr-identity remote login --token $TOKEN
# or skip and export NMKR_IDENTITY_TOKEN (optionally NMKR_IDENTITY_URL)

nmkr-identity remote whoami
nmkr-identity remote did create --company "Acme GmbH" --website https://acme.test
# ^ returns one-time privkey_hex + passphrase — save them!

nmkr-identity remote did list
nmkr-identity remote vc issue --did-id 42 --label Genesis \
  --policy-id <hex> --privkey-hex $KEY
nmkr-identity remote vc metadata 123 --privkey-hex $KEY --description "Genesis drop"
nmkr-identity remote vc revoke 123 --reason "duplicate"
```

## 8b) Public JSON API (v1)

Bearer-token authenticated, issued from `/settings/token` (hashed server-side).

| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/api/v1/me` | Current user |
| POST   | `/api/v1/dids` | Create DID (one-time `privkey_hex` + `passphrase` returned) |
| GET    | `/api/v1/dids` | List caller's DIDs |
| GET    | `/api/v1/dids/<id>` | DID + attestations + credentials |
| POST   | `/api/v1/dids/<id>/credentials` | Issue a VC (needs signing key) |
| GET    | `/api/v1/dids/<id>/credentials` | List VCs on a DID |
| GET    | `/api/v1/credentials/<id>` | VC detail |
| POST   | `/api/v1/credentials/<id>/revoke` | Revoke |
| POST   | `/api/v1/credentials/<id>/metadata` | Signed CIP-725 metadata |

Write endpoints that sign material accept either `{"privkey_hex": "..."}` (raw 32-byte hex) or `{"passphrase": "..."}` (server decrypts the stored encrypted key).

## 8c) Claude Code Skill

A drop-in [Claude Code](https://claude.com/claude-code) skill lives at [`skills/nmkr-identity/SKILL.md`](skills/nmkr-identity/SKILL.md). It teaches an AI agent the CLI surface, the `/api/v1` endpoints, and the common recipes (create DID → issue VC → generate CIP-725 metadata) as a single conversational flow.

Install it into your Claude Code user directory:

```bash
# from the repo root
mkdir -p ~/.claude/skills/nmkr-identity
cp skills/nmkr-identity/SKILL.md ~/.claude/skills/nmkr-identity/
# or symlink so updates track the repo
ln -s "$PWD/skills/nmkr-identity" ~/.claude/skills/nmkr-identity
```

The skill auto-triggers when you mention phrases like *"create DID"*, *"NMKR identity"*, *"Verifiable Credential"*, *"CIP-725 metadata"*, *"sign VC"*, or *"PRISM DID"* in Claude Code. It documents key-handling rules (never echo `privkey_hex` / `passphrase` to chat, prefer `--privkey-file` over flags in scripts), common failure modes, and both local and remote command recipes.

Agents that aren't on Claude Code can still use the CLI directly — `nmkr-identity` takes the same inputs the skill describes.

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
