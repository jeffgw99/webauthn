# WebAuthn Passkey Demo

Minimal localhost WebAuthn playground using Fastify + @simplewebauthn/server on the backend and React/Vite/Tailwind on the frontend. State is persisted to JSON on disk for easy inspection.

## Prerequisites
- Node.js 20+
- A platform authenticator or security key (passkeys work on localhost)

## Install
```bash
npm install          # installs root + server + client deps (postinstall runs)
# or run separately: npm --prefix server install && npm --prefix client install
```

## Run
```bash
npm run dev
```
- API: http://localhost:3000 (Fastify + CORS for http://localhost:5173)
- UI: http://localhost:5173 (Vite dev server)
- Root script uses `concurrently` to start both.

## Storage
All server state is JSON on disk under `server/data/`:
- `users.json`: `{ "users": { "<username>": { "id": "<uuid>", "username": "<username>", "createdAt": "<iso>" } } }`
- `challenges.json`: `{ "challenges": { "<username>": { "registration": { "challenge": "...", "createdAt": "<iso>" }, "authentication": { "challenge": "...", "createdAt": "<iso>" } } } }`
- `credentials.json`: `{ "credentials": { "<username>": [ { "credentialID_b64url": "...", "publicKey_b64url": "...", "counter": 0, "transports": ["usb","nfc","ble","internal"], "aaguid": "...", "createdAt": "<iso>", "lastUsedAt": "<iso>" } ] } }`

Files are written atomically (tmp + rename) and created on first run. A `/debug/reset` endpoint wipes them back to empty defaults; the UI exposes a **Clear server JSON** button for demo use.

Extra debug endpoints/UI helpers:
- `GET /debug/state` to inspect current JSON.
- `POST /debug/remove-user { username }` removes the user + their credentials/challenges.
- `POST /debug/remove-credential { username, credentialID }` removes a single credential.
- The UI’s “Server JSON” panel lets you refresh and prune entries without leaving the page.

## Notes
- Frontend uses @simplewebauthn/browser for `startRegistration` / `startAuthentication`.
- Timeline shows each WebAuthn step; debug panel reveals sanitized JSON payloads.
- Works over HTTP on localhost only (expected origin: http://localhost:5173, RP ID: localhost).
