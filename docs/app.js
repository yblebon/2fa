'use strict';

const APP_NAME    = '2fa';
const APP_VERSION = 'v2.4.1';

const VAULT_V6   = 'vault_v6';
const VAULT_V5   = 'vault_v5';
const ITERS_V6   = 600_000;
const ITERS_V5   = 100_000;
const IDLE_MS    = 5 * 60 * 1000;
const LOCK_KEY     = 'vault_lockout';
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS   = 30_000;
const MIN_PASS_LEN = 12;
const BASE32_RE  = /^[A-Z2-7]+=*$/;
const ENC        = new TextEncoder();
const DEC        = new TextDecoder();
const CIRCUMF    = 2 * Math.PI * 14;
const IDX_AAD    = ENC.encode('2fa|index');
const ALGOS      = ['SHA1', 'SHA256', 'SHA512'];

// Avatar palette: [bg, fg]
const PALETTE = [
  ['#1e3a5f','#60a5fa'],['#1a3a2a','#4ade80'],['#3b1f4e','#c084fc'],
  ['#3a1f1f','#f87171'],['#2e2a14','#fbbf24'],['#1a3340','#22d3ee'],
];
function avatarStyle(label) {
  const i = [...label].reduce((a,c) => a + c.charCodeAt(0), 0) % PALETTE.length;
  return PALETTE[i];
}

const $ = id => document.getElementById(id);

let sessionKey     = null;
let sessionSalt    = null;   // salt (array) the in-memory key was derived from
let unlocking      = false;
let lockoutTimer   = null;
let renderTimer    = null;
let idleTimer      = null;
let idleLockTimer  = null;
let lastIdleReset  = 0;
let scannerInst    = null;
let renderGen      = 0;      // bumped to abort renders that are superseded or outlived by a lock
let tamperWarn     = false;  // account list changed outside the app
let pendingScan    = null;   // TOTP parameters from a scanned QR, valid while the secret field is untouched
let pendingImport  = null;
const entryCache   = new Map();   // account -> decrypted secret + TOTP object; cleared on lock

// All vault mutations run one at a time, so two quick add/delete actions can't overwrite each other.
let mutationChain = Promise.resolve();
function withMutation(fn) {
  const p = mutationChain.then(fn);
  mutationChain = p.catch(() => {});
  return p;
}

/* ── Idle ──────────────────────────────────────────────────────────────────── */
function resetIdle() {
  clearTimeout(idleTimer); clearTimeout(idleLockTimer);
  const bar = $('idle-bar');
  bar.style.width = '100%'; bar.style.background = 'var(--cyan)';
  idleTimer = setTimeout(() => {
    bar.style.width = '0'; bar.style.background = 'var(--red)';
    idleLockTimer = setTimeout(lockVault, 900);
  }, IDLE_MS);
}
['click','keydown','mousemove','touchstart'].forEach(ev =>
  document.addEventListener(ev, () => {
    if (!sessionKey) return;
    const now = Date.now();
    if (now - lastIdleReset < 500) return;
    lastIdleReset = now;
    resetIdle();
  }, { passive: true })
);

/* ── Crypto ────────────────────────────────────────────────────────────────── */
async function deriveKey(password, salt, iters = ITERS_V6) {
  const raw = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iters, hash: 'SHA-256' },
    raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
// `aad` (optional) is authenticated but not encrypted: it binds a ciphertext to its context.
async function symEncrypt(key, pt, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const params = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = aad;
  const ct = await crypto.subtle.encrypt(params, key, ENC.encode(pt));
  return { cipher: Array.from(new Uint8Array(ct)), iv: Array.from(iv) };
}
async function symDecrypt(key, { cipher, iv }, aad) {
  const params = { name: 'AES-GCM', iv: new Uint8Array(iv) };
  if (aad) params.additionalData = aad;
  const pt = await crypto.subtle.decrypt(params, key, new Uint8Array(cipher));
  return DEC.decode(pt);
}
const encrypt = (pt, aad) => symEncrypt(sessionKey, pt, aad);

/* ── Account records ───────────────────────────────────────────────────────── */
// fmt 2: the secret and its TOTP parameters are one JSON payload, authenticated together with the
// account's id and label, so a label can't be swapped onto another account's ciphertext.
// Records without `fmt` (all earlier versions) hold a bare base32 secret and no AAD; they are
// still readable and are upgraded in place on first unlock.
const accountAad = (id, label) => ENC.encode(`2fa|acct|${id}|${label}`);

async function sealAccount(id, label, payload) {
  return { id, label, fmt: 2, ...(await encrypt(JSON.stringify(payload), accountAad(id, label))) };
}
async function openAccount(key, acc) {
  if (acc.fmt === 2) return JSON.parse(await symDecrypt(key, acc, accountAad(acc.id, acc.label)));
  return { s: await symDecrypt(key, acc) };
}
async function getEntry(acc) {
  const ck = `${acc.id || ''}:${acc.iv.join(',')}`;
  let e = entryCache.get(ck);
  if (e) return e;
  const p = await openAccount(sessionKey, acc);
  const period = Number.isInteger(p.p) ? p.p : 30;
  e = {
    period,
    digits: Number.isInteger(p.d) ? p.d : 6,
    totp: new OTPAuth.TOTP({
      secret: OTPAuth.Secret.fromBase32(p.s),
      algorithm: ALGOS.includes(p.a) ? p.a : 'SHA1',
      digits: Number.isInteger(p.d) ? p.d : 6,
      period,
    }),
  };
  entryCache.set(ck, e);
  return e;
}

/* ── Vault I/O ─────────────────────────────────────────────────────────────── */
function loadRaw(key = VAULT_V6) {
  const r = localStorage.getItem(key);
  return r ? JSON.parse(r) : null;
}
function isBytes(a, len) {
  return Array.isArray(a) && (len === undefined || a.length === len) && a.length <= 1 << 20 &&
         a.every(n => Number.isInteger(n) && n >= 0 && n <= 255);
}
function validateShape(v) {
  if (!v || typeof v !== 'object') return false;
  if (!isBytes(v.salt, 16)) return false;
  if (!v.test || !isBytes(v.test.cipher) || !isBytes(v.test.iv, 12)) return false;
  if (v.idx !== undefined && !(v.idx && isBytes(v.idx.cipher) && isBytes(v.idx.iv, 12))) return false;
  if (!Array.isArray(v.accounts) || v.accounts.length > 5000) return false;
  for (const a of v.accounts) {
    if (!a || typeof a !== 'object') return false;
    if (typeof a.label !== 'string' || a.label.length > 10_000) return false;
    if (!isBytes(a.cipher) || !isBytes(a.iv, 12)) return false;
    if (a.id !== undefined && typeof a.id !== 'string') return false;
    if (a.fmt !== undefined && (a.fmt !== 2 || !a.id)) return false;
  }
  return true;
}

// `salt` MUST be the salt sessionKey was derived from. Only pass it when creating a vault;
// afterwards it is read back from the stored vault. (Never generate a fresh salt in here:
// the key in memory would no longer match what is stored, and the vault could never be reopened.)
async function saveVault(accounts, salt) {
  let s = salt;
  if (!s) {
    const ex = loadRaw();
    if (!ex) throw new Error('saveVault: no existing vault and no salt supplied');
    // Another tab replaced the vault (import / wipe / migration) since we unlocked: our key no
    // longer matches the stored salt, and writing would make the vault unopenable.
    if (sessionSalt && ex.salt.join() !== sessionSalt.join()) throw new Error('Vault changed in another tab');
    s = new Uint8Array(ex.salt);
  }
  const test = await encrypt('verify');
  const idx  = await encrypt(JSON.stringify(accounts.map(a => a.id).sort()), IDX_AAD);
  localStorage.setItem(VAULT_V6, JSON.stringify({ version: 6, accounts, salt: Array.from(s), test, idx }));
  tamperWarn = false;
}

// true = matches, false = accounts were added/removed/replaced outside the app, null = no index yet
async function checkIndex(v) {
  if (!v.idx) return null;
  try {
    const ids = JSON.parse(await symDecrypt(sessionKey, v.idx, IDX_AAD));
    const now = v.accounts.map(a => a.id || '').sort();
    return ids.length === now.length && ids.every((x, i) => x === now[i]);
  } catch { return false; }
}

// Runs after every unlock: gives legacy accounts an id and fmt-2 protection, and adds the account
// index to vaults that predate it. Backups made by any earlier version go through here.
function upgradeVault() {
  return withMutation(async () => {
    const v = loadRaw();
    const idxOk = await checkIndex(v);
    tamperWarn = idxOk === false;
    let changed = false;
    const accounts = [];
    for (const a of v.accounts) {
      if (a.id && a.fmt === 2) { accounts.push(a); continue; }
      try {
        const id = a.id || crypto.randomUUID();
        accounts.push(await sealAccount(id, a.label, { s: await symDecrypt(sessionKey, a) }));
        changed = true;
      } catch { accounts.push(a); tamperWarn = true; }
    }
    // A mismatching index is left alone so the warning survives until the user acts on it.
    if (idxOk !== false && !tamperWarn && (changed || idxOk === null)) await saveVault(accounts);
  });
}

/* ── v5 → v6 migration ─────────────────────────────────────────────────────── */
// v5 used 100k PBKDF2 iterations; v6 uses 600k with the same salt.
// We decrypt each secret with the old key and re-encrypt with the new one.
async function migrateV5(password) {
  const v5 = loadRaw(VAULT_V5);
  if (!v5 || !validateShape(v5)) return false;
  const oldKey = await deriveKey(password, new Uint8Array(v5.salt), ITERS_V5);
  try { await symDecrypt(oldKey, v5.test); }
  catch { return false; } // wrong password

  // New key, same salt (keeps the exported backup portable)
  sessionKey  = await deriveKey(password, new Uint8Array(v5.salt), ITERS_V6);
  sessionSalt = v5.salt;

  const accounts = [];
  for (const acc of v5.accounts) {
    const secret = await symDecrypt(oldKey, acc);
    accounts.push(await sealAccount(acc.id || crypto.randomUUID(), acc.label, { s: secret }));
  }
  await saveVault(accounts, new Uint8Array(v5.salt));
  localStorage.removeItem(VAULT_V5);
  return true;
}

/* ── Lockout ────────────────────────────────────────────────────────────────── */
// Persisted in localStorage so a page reload doesn't reset it, and enforced inside
// unlockVault() so pressing Enter can't bypass a disabled button.
// NOTE: this is only a speed bump for guessing through the UI. Anyone who can read
// localStorage can attack the ciphertext offline; the real protection is password
// strength + the PBKDF2 cost.
function getLockout() {
  try {
    const s = JSON.parse(localStorage.getItem(LOCK_KEY));
    if (s && Number.isFinite(s.fails) && Number.isFinite(s.until)) {
      // clamp so a clock set far into the future can't lock the user out for good
      return { fails: s.fails, until: Math.min(s.until, Date.now() + LOCKOUT_MS) };
    }
  } catch {}
  return { fails: 0, until: 0 };
}
function setLockout(s) { try { localStorage.setItem(LOCK_KEY, JSON.stringify(s)); } catch {} }
function lockoutRemaining() { return Math.max(0, getLockout().until - Date.now()); }

function syncLockoutUI() {
  const btn = $('unlock-btn');
  const ms  = lockoutRemaining();
  clearTimeout(lockoutTimer);
  if (ms > 0) {
    btn.disabled = true;
    setErr('fail-msg', `Too many attempts — wait ${Math.ceil(ms / 1000)} s.`);
    lockoutTimer = setTimeout(syncLockoutUI, 500);
  } else {
    btn.disabled = unlocking;
    const s = getLockout();
    if (s.until) { setLockout({ fails: 0, until: 0 }); setErr('fail-msg', ''); }
  }
}

function refreshLockCopy() {
  const fresh = !localStorage.getItem(VAULT_V6) && !localStorage.getItem(VAULT_V5);
  $('lock-title').textContent = fresh ? 'Create vault' : 'Unlock vault';
  $('lock-sub').textContent   = fresh
    ? `Choose a master password (at least ${MIN_PASS_LEN} characters). It cannot be recovered if you forget it.`
    : 'Enter your master password to access your codes.';
  $('unlock-btn').textContent = fresh ? 'Create' : 'Unlock';
  $('master-pass').autocomplete = fresh ? 'new-password' : 'current-password';

  // Tell the user a vault is already stored here (the account count is stored unencrypted).
  const notice = $('vault-notice');
  notice.classList.toggle('visible', !fresh);
  if (!fresh) {
    let n = null;
    for (const k of [VAULT_V6, VAULT_V5]) {
      try { const v = JSON.parse(localStorage.getItem(k)); if (v && Array.isArray(v.accounts)) { n = v.accounts.length; break; } } catch {}
    }
    notice.textContent = '🔒 Vault locked — ' + (n === null ? 'an existing vault is loaded on this device.'
      : `${n} account${n === 1 ? '' : 's'} stored on this device.`);
  }
}

/* ── Unlock / lock ──────────────────────────────────────────────────────────── */
async function unlockVault() {
  if (unlocking) return;                       // no parallel guesses (Enter held / double click)
  const input = $('master-pass');
  const pass  = input.value;
  if (!pass) return;
  if (lockoutRemaining() > 0) { syncLockoutUI(); return; }

  unlocking = true;
  $('unlock-btn').disabled = true;
  setErr('fail-msg', '');
  try {
    const v6       = loadRaw();
    const v5exists = !!localStorage.getItem(VAULT_V5);

    // Brand new vault
    if (!v6 && !v5exists) {
      if (pass.length < MIN_PASS_LEN) {
        setErr('fail-msg', `Choose a master password of at least ${MIN_PASS_LEN} characters.`);
        return;
      }
      const salt = crypto.getRandomValues(new Uint8Array(16));
      sessionKey  = await deriveKey(pass, salt);
      sessionSalt = Array.from(salt);
      input.value = '';                        // password no longer needed in the DOM
      await saveVault([], salt);               // persist the SAME salt the key came from
      setLockout({ fails: 0, until: 0 });
      return showVault();
    }

    // Migrate v5
    if (!v6 && v5exists) {
      if (await migrateV5(pass)) {
        input.value = '';
        setLockout({ fails: 0, until: 0 });
        return showVault();
      }
      sessionKey = null; sessionSalt = null;
      return bumpFailed();
    }

    // Normal v6
    if (!validateShape(v6)) throw new Error('vault_v6 has an unexpected shape');
    let ok = false;
    try {
      sessionKey  = await deriveKey(pass, new Uint8Array(v6.salt));
      sessionSalt = v6.salt;
      input.value = '';                        // clear as soon as the key exists
      await symDecrypt(sessionKey, v6.test);
      ok = true;
    } catch { sessionKey = null; sessionSalt = null; }
    if (!ok) return bumpFailed();

    await upgradeVault();
    setLockout({ fails: 0, until: 0 });
    showVault();
  } catch (err) {
    console.error(err);
    sessionKey = null; sessionSalt = null;
    setErr('fail-msg', 'Could not open the vault (storage error or corrupted data).');
  } finally {
    unlocking = false;
    syncLockoutUI();
  }
}

function bumpFailed() {
  const fails = getLockout().fails + 1;
  if (fails >= MAX_ATTEMPTS) {
    setLockout({ fails: 0, until: Date.now() + LOCKOUT_MS });   // message shown by syncLockoutUI()
  } else {
    setLockout({ fails, until: 0 });
    const left = MAX_ATTEMPTS - fails;
    setErr('fail-msg', `Wrong password — ${left} attempt${left === 1 ? '' : 's'} left.`);
  }
}

function lockVault() {
  sessionKey = null; sessionSalt = null;
  renderGen++;                                 // aborts any render still awaiting a decrypt
  entryCache.clear();
  tamperWarn = false; pendingScan = null; pendingImport = null;
  clearInterval(renderTimer); renderTimer = null;
  clearTimeout(idleTimer); clearTimeout(idleLockTimer);
  stopScanner();
  $('accs').replaceChildren();                 // no codes left in the DOM while locked
  $('vault-warn').classList.remove('visible');
  $('search-bar').value = '';
  $('new-label').value = ''; $('new-secret').value = ''; setErr('add-err', '');
  ['export-modal', 'import-modal'].forEach(closeModal);
  $('export-pass').value = ''; $('import-pass').value = '';
  $('vault-screen').style.display = 'none';
  $('lock-screen').style.display  = 'block';
  $('master-pass').value = '';
  setErr('fail-msg', '');
  refreshLockCopy();
  syncLockoutUI();
}

function showVault() {
  $('lock-screen').style.display  = 'none';
  $('vault-screen').style.display = 'block';
  resetIdle();
  renderAccounts();
  if (!renderTimer) renderTimer = setInterval(renderAccounts, 1000);
}

// Another tab changed the vault: our key/salt may be stale, so lock rather than risk a bad write.
window.addEventListener('storage', e => {
  if (e.key !== null && e.key !== VAULT_V6 && e.key !== VAULT_V5) return;
  if (sessionKey) {
    lockVault();
    setErr('fail-msg', 'The vault was changed in another tab — locked. Unlock again to continue.');
  } else {
    refreshLockCopy();
  }
});

/* ── Render ─────────────────────────────────────────────────────────────────── */
async function renderAccounts() {
  if (!sessionKey) return;
  const gen       = ++renderGen;
  const container = $('accs');
  const search    = $('search-bar').value.toLowerCase();
  let vault;
  try { vault = loadRaw(); } catch { return; }

  const accounts = vault?.accounts ?? [];
  const list = accounts.filter(a => !search || a.label.toLowerCase().includes(search));

  const items = [];
  let bad = 0;
  for (const acc of list) {
    try { items.push({ acc, e: await getEntry(acc) }); }
    catch { bad++; }
    if (gen !== renderGen || !sessionKey) return;   // superseded by a newer render, or locked meanwhile
  }

  const warn = $('vault-warn');
  const msg = [
    tamperWarn && 'Accounts were added, removed or replaced outside this app.',
    bad && `${bad} account${bad === 1 ? '' : 's'} failed its integrity check and ${bad === 1 ? 'is' : 'are'} hidden.`,
  ].filter(Boolean).join(' ');
  warn.textContent = msg;
  warn.classList.toggle('visible', !!msg);

  const frag = document.createDocumentFragment();

  if (!items.length) {
    const el = document.createElement('div');
    el.className = 'empty';
    el.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
      <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>`;
    el.append(accounts.length ? 'No results.' : 'No accounts yet.');
    frag.appendChild(el);
    container.replaceChildren(frag);
    return;
  }

  for (const { acc, e } of items) {
    const timeLeft = e.period - (Math.floor(Date.now() / 1000) % e.period);
    const pct      = timeLeft / e.period;
    const code     = e.totp.generate();

    const [avatarBg, avatarFg] = avatarStyle(acc.label);
    const urgent    = timeLeft <= Math.min(7, e.period / 4);
    const dashOff   = (CIRCUMF * (1 - pct)).toFixed(2);

    // Card
    const card = document.createElement('div');
    card.className = 'acc';
    card.tabIndex = 0;
    card.setAttribute('role', 'button');
    card.setAttribute('aria-label', `Copy code for ${acc.label}`);

    // Avatar
    const av = document.createElement('div');
    av.className = 'acc-avatar';
    av.style.cssText = `background:${avatarBg};color:${avatarFg}`;
    av.textContent = [...acc.label].slice(0, 2).join('').toUpperCase();

    // Body
    const body = document.createElement('div');
    body.className = 'acc-body';

    const name = document.createElement('div');
    name.className = 'acc-name';
    name.textContent = acc.label;

    const codeEl = document.createElement('div');
    codeEl.className = 'acc-code';
    const half = Math.ceil(code.length / 2);
    codeEl.textContent = code.slice(0, half) + ' ' + code.slice(half);

    const hint = document.createElement('div');
    hint.className = 'acc-hint';
    hint.textContent = 'tap to copy';

    body.append(name, codeEl, hint);

    // Ring countdown
    const ring = document.createElement('div');
    ring.className = 'acc-ring';
    ring.innerHTML = `<svg width="36" height="36" viewBox="0 0 36 36">
      <circle class="ring-bg" cx="18" cy="18" r="14" fill="none" stroke-width="3"/>
      <circle class="ring-fg${urgent ? ' urgent' : ''}" cx="18" cy="18" r="14" fill="none"
        stroke-width="3" stroke-linecap="round"
        stroke-dasharray="${CIRCUMF.toFixed(2)}" stroke-dashoffset="${dashOff}"/>
    </svg><div class="ring-num">${timeLeft}</div>`;

    // Delete
    const del = document.createElement('button');
    del.className = 'acc-del';
    del.setAttribute('aria-label', 'Delete ' + acc.label);
    del.innerHTML = `<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
      <path d="M5 5l10 10M15 5L5 15"/>
    </svg>`;
    del.addEventListener('click', ev => { ev.stopPropagation(); deleteAccount(acc.id); });

    card.append(av, body, ring, del);
    const copy = () => {
      const flash = t => { hint.textContent = t; setTimeout(() => { hint.textContent = 'tap to copy'; }, 1800); };
      navigator.clipboard.writeText(code).then(() => flash('✓ copied'), () => flash('copy failed'));
    };
    card.addEventListener('click', copy);
    card.addEventListener('keydown', ev => {
      if (ev.target === card && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); copy(); }
    });

    frag.appendChild(card);
  }
  container.replaceChildren(frag);
}

/* ── Add account ────────────────────────────────────────────────────────────── */
async function addAccount() {
  setErr('add-err', '');
  const label  = $('new-label').value.trim() || 'Unnamed';
  const secret = $('new-secret').value.replace(/\s+/g,'').toUpperCase();
  if (!secret || !sessionKey) return;
  if (!BASE32_RE.test(secret)) { setErr('add-err', 'Invalid secret: must be base32 (A–Z, 2–7).'); return; }
  const params = pendingScan ?? { a: 'SHA1', d: 6, p: 30 };
  try {
    new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret), algorithm: params.a, digits: params.d, period: params.p }).generate();
  } catch { setErr('add-err', 'Does not produce a valid TOTP code.'); return; }

  try {
    await withMutation(async () => {
      const vault = loadRaw();
      vault.accounts.push(await sealAccount(crypto.randomUUID(), label, { s: secret, ...params }));
      await saveVault(vault.accounts);
    });
  } catch (err) {
    console.error(err);
    setErr('add-err', 'Could not save the account.');
    return;
  }
  $('new-label').value  = '';
  $('new-secret').value = '';
  pendingScan = null;
  renderAccounts();
}

/* ── Delete account ─────────────────────────────────────────────────────────── */
// Delete by stable id, not by list position: with a search filter active the position in the
// rendered list is not the position in the vault, and another tab may have changed the vault.
async function deleteAccount(id) {
  if (!id) return;
  const target = loadRaw()?.accounts.find(a => a.id === id);
  if (!target) return;                         // already gone
  if (!confirm(`Remove "${target.label}"?`)) return;
  try {
    await withMutation(async () => {
      const vault = loadRaw();                 // re-read: storage may have changed while the dialog was open
      await saveVault(vault.accounts.filter(a => a.id !== id));
    });
    renderAccounts();
  } catch (err) {
    console.error(err);
    alert('Could not save changes — the account was not removed.');
  }
}

/* ── Hard reset ─────────────────────────────────────────────────────────────── */
function hardReset() {
  if (prompt('Type WIPE to permanently delete all vault data:') !== 'WIPE') return;
  if (!confirm('This cannot be undone. All accounts will be lost.')) return;
  localStorage.removeItem(VAULT_V6);
  localStorage.removeItem(VAULT_V5);
  location.reload();
}

/* ── Modals ─────────────────────────────────────────────────────────────────── */
function openModal(id, focusId) {
  $(id).classList.add('open');
  setTimeout(() => $(focusId)?.focus(), 60);
}
function closeModal(id) { $(id).classList.remove('open'); }

/* ── Export ─────────────────────────────────────────────────────────────────── */
// <app>-<version>-<UTC yyyymmddThhmmZ>, e.g. 2fa-v2.4.1-20260929T1437Z
function backupBaseName(now = new Date()) {
  const ts = now.toISOString().slice(0, 16).replace(/[-:]/g, '') + 'Z';
  return `${APP_NAME}-${APP_VERSION}-${ts}`;
}

async function confirmExport() {
  const pass = $('export-pass').value;
  if (!pass) { setErr('export-err', 'Enter your password.'); return; }
  let raw, vault;
  try { raw = localStorage.getItem(VAULT_V6); vault = JSON.parse(raw); }
  catch { vault = null; }
  if (!vault || !validateShape(vault)) { setErr('export-err', 'No readable vault to export.'); return; }
  try {
    const key = await deriveKey(pass, new Uint8Array(vault.salt));
    await symDecrypt(key, vault.test);
  } catch { setErr('export-err', 'Wrong password.'); return; }

  const blob = new Blob([raw], { type: 'application/json' });
  const a = Object.assign(document.createElement('a'), {
    href: URL.createObjectURL(blob),
    download: `${backupBaseName()}.json`,
  });
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  $('export-pass').value = '';
  closeModal('export-modal');
}

/* ── Import ─────────────────────────────────────────────────────────────────── */
// True only if replacing would actually destroy something. The accounts array is stored
// unencrypted (only each secret is encrypted), so an empty vault can be recognised without
// the password. Anything unparsable or unexpected is treated as data, to stay on the safe side.
function existingVaultHasData() {
  for (const k of [VAULT_V6, VAULT_V5]) {
    const raw = localStorage.getItem(k);
    if (!raw) continue;
    try {
      const v = JSON.parse(raw);
      if (!(v && Array.isArray(v.accounts) && v.accounts.length === 0)) return true;
    } catch { return true; }
  }
  return false;
}

// Accepts backups from every earlier release: v6 files (version 6) and v5 files (version 5, or no
// version field). Anything else is refused.
function importBackup(e) {
  const file = e.target.files[0]; if (!file) return;
  const r = new FileReader();
  r.onload = ev => {
    let parsed;
    try { parsed = JSON.parse(ev.target.result); }
    catch { alert('Invalid file: not valid JSON.'); return; }
    if (!validateShape(parsed)) { alert('Invalid file: unrecognised vault format.'); return; }
    if (parsed.version !== 6 && parsed.version !== 5 && parsed.version !== undefined) {
      alert('Invalid file: unsupported backup version.'); return;
    }
    pendingImport = { text: ev.target.result, parsed };
    $('import-pass').value = '';
    setErr('import-err', '');
    openModal('import-modal', 'import-pass');
  };
  r.readAsText(file);
  e.target.value = '';
}

// The backup must open with the password given, and every account in it must decrypt, before it
// is allowed to replace anything.
async function confirmImport() {
  if (!pendingImport) return;
  const pass = $('import-pass').value;
  if (!pass) { setErr('import-err', 'Enter the backup password.'); return; }
  const { text, parsed } = pendingImport;
  const isV6 = parsed.version === 6;
  $('import-go').disabled = true;
  try {
    let key;
    try {
      key = await deriveKey(pass, new Uint8Array(parsed.salt), isV6 ? ITERS_V6 : ITERS_V5);
      await symDecrypt(key, parsed.test);
    } catch { setErr('import-err', 'Wrong password for this backup.'); return; }
    try { for (const a of parsed.accounts) await openAccount(key, a); }
    catch { setErr('import-err', 'This backup is damaged: an account failed its integrity check.'); return; }

    if (existingVaultHasData() && !confirm('Replace current vault with this backup?')) return;
    localStorage.setItem(isV6 ? VAULT_V6 : VAULT_V5, text);
    localStorage.removeItem(isV6 ? VAULT_V5 : VAULT_V6);
    pendingImport = null;
    $('import-pass').value = '';
    location.reload();
  } finally { $('import-go').disabled = false; }
}

/* ── QR Scanner ─────────────────────────────────────────────────────────────── */
// Parses an otpauth://totp/… URI and validates every parameter that changes the generated code.
function parseOtpauth(text) {
  const url = new URL(text);
  if (url.protocol !== 'otpauth:') throw new Error('Not an otpauth:// QR code.');
  if (url.hostname !== 'totp') throw new Error('Only time-based (TOTP) accounts are supported.');
  const q = url.searchParams;
  const secret = (q.get('secret') || '').replace(/\s+/g, '').toUpperCase();
  if (!BASE32_RE.test(secret)) throw new Error('QR has an invalid secret.');
  const a = (q.get('algorithm') || 'SHA1').toUpperCase();
  if (!ALGOS.includes(a)) throw new Error(`Unsupported algorithm: ${a}.`);
  const d = q.has('digits') ? Number(q.get('digits')) : 6;
  if (!Number.isInteger(d) || d < 6 || d > 8) throw new Error('Unsupported number of digits.');
  const p = q.has('period') ? Number(q.get('period')) : 30;
  if (!Number.isInteger(p) || p < 1 || p > 300) throw new Error('Unsupported period.');

  let path = url.pathname.replace(/^\/+/, '');
  try { path = decodeURIComponent(path); } catch {}
  const sep = path.indexOf(':');
  const pathIssuer = sep >= 0 ? path.slice(0, sep) : '';
  const account    = (sep >= 0 ? path.slice(sep + 1) : path).trim();
  const issuer     = (q.get('issuer') || pathIssuer).trim();
  const label = (issuer && account ? `${issuer} (${account})` : issuer || account || 'Scanned')
    .replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 64);
  return { secret, label, params: { a, d, p } };
}

async function stopScanner() {
  const s = scannerInst;
  scannerInst = null;
  $('reader-wrap').style.display = 'none';
  if (s) await s.stop().catch(() => {});
}

async function toggleScanner() {
  setErr('add-err', '');
  if (scannerInst) { await stopScanner(); return; }
  $('reader-wrap').style.display = 'block';
  const inst = scannerInst = new Html5Qrcode('reader');
  inst.start({ facingMode: 'environment' }, { fps: 10, qrbox: 230 }, text => {
    // First decode ends the scan either way, so a bad code can't fire repeatedly at 10 fps.
    stopScanner();
    try {
      const { secret, label, params } = parseOtpauth(text);
      $('new-secret').value = secret;
      $('new-label').value  = label;
      pendingScan = params;
    } catch (err) {
      setErr('add-err', err.message || 'Unrecognised QR format.');
    }
  }).catch(() => { setErr('add-err', 'Could not start the camera.'); stopScanner(); });
}

/* ── Util ───────────────────────────────────────────────────────────────────── */
function setErr(id, msg) { $(id).textContent = msg; }

/* ── Wiring & on load ───────────────────────────────────────────────────────── */
const onEnter = (id, fn) => $(id).addEventListener('keydown', e => { if (e.key === 'Enter') fn(); });
$('unlock-btn').addEventListener('click', unlockVault);
onEnter('master-pass', unlockVault);
$('import-file').addEventListener('change', importBackup);
$('search-bar').addEventListener('input', renderAccounts);
$('lock-btn').addEventListener('click', lockVault);
$('scan-btn').addEventListener('click', toggleScanner);
$('add-btn').addEventListener('click', addAccount);
$('new-secret').addEventListener('input', () => { pendingScan = null; });   // hand-edited: scanned params no longer apply
$('export-open').addEventListener('click', () => {
  $('export-pass').value = ''; setErr('export-err', '');
  openModal('export-modal', 'export-pass');
});
$('export-cancel').addEventListener('click', () => closeModal('export-modal'));
$('export-go').addEventListener('click', confirmExport);
onEnter('export-pass', confirmExport);
$('import-cancel').addEventListener('click', () => { pendingImport = null; $('import-pass').value = ''; closeModal('import-modal'); });
$('import-go').addEventListener('click', confirmImport);
onEnter('import-pass', confirmImport);
$('wipe-btn').addEventListener('click', hardReset);

$('app-ver').textContent = APP_VERSION;
if (localStorage.getItem(VAULT_V5) && !localStorage.getItem(VAULT_V6)) {
  const n = $('migrate-notice');
  n.classList.add('visible');
  n.textContent = '↑ Legacy vault detected — it will be automatically upgraded after you unlock.';
}
refreshLockCopy();
syncLockoutUI();
