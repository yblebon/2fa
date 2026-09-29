# 2fa

Single-page, client-side TOTP authenticator (`docs/`). Secrets are encrypted in `localStorage`
(PBKDF2-SHA256 600k → AES-256-GCM); nothing leaves the browser.

## Layout
- `docs/index.html` – markup, styles, and the Content-Security-Policy
- `docs/app.js` – all application code (no inline scripts, so the CSP forbids them)
- `docs/vendor/` – pinned copies of `otpauth@9.1.2` and `html5-qrcode@2.3.8` (no CDN at runtime)

## Backups
Export writes `<app>-<version>-<UTC yyyymmddThhmmZ>.json`, e.g. `2fa-v2.4.1-20260929T1437Z.json`.
Import accepts backups from every earlier release (v5 and v6 files, any file name) and asks for the
backup's password before replacing anything. Bump `APP_VERSION` in `docs/app.js` on release.

## Hosting caveat
`localStorage` is scoped to the *origin*, not the path. On `https://<user>.github.io/2fa/` every other
project page under the same `github.io` origin can read the (encrypted) vault. Serve this from its own
origin (custom domain or dedicated user/org site) and rely on a strong master password.
