// ---------- helpers ----------
const enc = new TextEncoder();
const dec = new TextDecoder();

function b64(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64d(str) {
  if (!str) return new ArrayBuffer(0);

  // strip whitespace / accidental PEM headers
  str = String(str)
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "")
    .trim();

  // base64url -> base64
  str = str.replace(/-/g, "+").replace(/_/g, "/");

  // pad
  while (str.length % 4 !== 0) str += "=";

  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}


function randBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}
async function sha256(buf) {
  return await crypto.subtle.digest("SHA-256", buf);
}

// ---------- key storage (encrypted private key) ----------
async function deriveKey(unlockKey, salt) {
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(unlockKey), "PBKDF2", false, ["deriveKey"]);
  return await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function storeKeys(username, unlockKey, privPkcs8B64, pubSpkiB64) {
  const salt = randBytes(16);
  const iv = randBytes(12);
  const kek = await deriveKey(unlockKey, salt);

  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    kek,
    b64d(privPkcs8B64)
  );

  const obj = {
    username,
    pubSpkiB64,
    saltB64: b64(salt),
    ivB64: b64(iv),
    encPrivB64: b64(ct)
  };
  localStorage.setItem(`keys:${username}`, JSON.stringify(obj));
  return obj;
}

async function loadPrivateKey(username, unlockKey) {
  const raw = localStorage.getItem(`keys:${username}`);
  if (!raw) throw new Error("No local keys found for this username. Register first.");
  const obj = JSON.parse(raw);

  const salt = new Uint8Array(b64d(obj.saltB64));
  const iv = new Uint8Array(b64d(obj.ivB64));
  const kek = await deriveKey(unlockKey, salt);

  const privPkcs8 = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    kek,
    b64d(obj.encPrivB64)
  );

    const privKey = await crypto.subtle.importKey(
    "pkcs8",
    privPkcs8,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );

  // ALSO return the same decrypted PKCS#8 so we can import it as ECDH
  return { privKey, pubSpkiB64: obj.pubSpkiB64, privPkcs8B64: b64(privPkcs8) };
}

async function generateKeypair() {
  const kp = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const pubSpki = await crypto.subtle.exportKey("spki", kp.publicKey);
  const privPkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
  return { pubSpkiB64: b64(pubSpki), privPkcs8B64: b64(privPkcs8) };
}

async function generateAndStoreKeys(username, unlockKey) {
  const { pubSpkiB64, privPkcs8B64 } = await generateKeypair();
  const bundle = await storeKeys(username, unlockKey, privPkcs8B64, pubSpkiB64);
  return bundle;
}

async function ensureLocalKeyBundle(username) {
  const raw = localStorage.getItem(`keys:${username}`);
  if (raw) return true;
  const r = await fetch(`/api/users/${encodeURIComponent(username)}/key-bundle`);
  const d = await r.json();
  if (!d.ok) throw new Error(d.error || "Key bundle not found");
  const obj = {
    username: d.username,
    pubSpkiB64: d.publicKeyB64,
    saltB64: d.saltB64,
    ivB64: d.ivB64,
    encPrivB64: d.encPrivB64
  };
  localStorage.setItem(`keys:${username}`, JSON.stringify(obj));
  return true;
}

// ---------- sign requests ----------
async function signText(privKey, text) {
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privKey,
    enc.encode(text)
  );
  return b64(sig);
}

// ---------- verify signatures ----------
async function importVerifyKeyFromSpkiB64(pubSpkiB64) {
  const spki = b64d(pubSpkiB64);
  return crypto.subtle.importKey(
    "spki",
    spki,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

async function verifyText(pubKey, text, signatureB64) {
  const sigBuf = b64d(signatureB64);
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    pubKey,
    sigBuf,
    enc.encode(text)
  );
}

// make them accessible from HTML onclick handlers
window.importVerifyKeyFromSpkiB64 = importVerifyKeyFromSpkiB64;
window.verifyText = verifyText;

// ---------- AES-GCM encrypt file ----------
async function aesGcmEncrypt(rawKeyBytes, plaintextBuf) {
  const key = await crypto.subtle.importKey("raw", rawKeyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = randBytes(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBuf);
  return { ivB64: b64(iv), ctB64: b64(ct) };
}
async function aesGcmDecrypt(rawKeyBytes, ivB64, ctB64) {
  const key = await crypto.subtle.importKey("raw", rawKeyBytes, "AES-GCM", false, ["decrypt"]);
  const iv = new Uint8Array(b64d(ivB64));
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, b64d(ctB64));
  return pt;
}

// ---------- wrap AES file key using ephemeral ECDH + AES-GCM ----------
async function wrapFileKeyForRecipient(recipientPubSpkiB64, fileKeyBytes) {
  // generate ephemeral ECDH keypair
  const eph = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const ephPubSpki = await crypto.subtle.exportKey("spki", eph.publicKey);

  // import recipient ECDH public key
  const recipientPub = await crypto.subtle.importKey(
    "spki",
    b64d(recipientPubSpkiB64),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  // derive shared secret bits
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: recipientPub },
    eph.privateKey,
    256
  );

  // KDF = SHA-256(shared) -> AES key
  const kdf = await sha256(shared);
  const wrapKeyBytes = new Uint8Array(kdf); // 32 bytes
  const wrapEnc = await aesGcmEncrypt(wrapKeyBytes, fileKeyBytes.buffer);

  return {
    ephPubB64: b64(ephPubSpki),
    wrapIvB64: wrapEnc.ivB64,
    wrapCtB64: wrapEnc.ctB64
  };
}

async function unwrapFileKey(recipientPrivSignKey, recipientPrivEcdhKey, ephPubB64, wrapIvB64, wrapCtB64) {
  // NOTE: to keep it simple, we reuse the same keypair for ECDSA and ECDH is not allowed by WebCrypto.
  // So for this project, we use ECDSA keys only for signing and do ECDH by importing the same private key bytes separately as ECDH.

  const ephPub = await crypto.subtle.importKey(
    "spki",
    b64d(ephPubB64),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: ephPub },
    recipientPrivEcdhKey,
    256
  );

  const kdf = await sha256(shared);
  const wrapKeyBytes = new Uint8Array(kdf);
  const fileKeyBuf = await aesGcmDecrypt(wrapKeyBytes, wrapIvB64, wrapCtB64);
  return new Uint8Array(fileKeyBuf);
}

// Import same private PKCS8 bytes as ECDH for deriveBits
async function importPrivAsECDH(privPkcs8B64) {
  return await crypto.subtle.importKey(
    "pkcs8",
    b64d(privPkcs8B64),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"]
  );
}

// ---------- session ----------
function setSession(username, role) {
  localStorage.setItem("session", JSON.stringify({ username, role }));
}
function getSession() {
  const s = localStorage.getItem("session");
  return s ? JSON.parse(s) : null;
}
function clearSession() {
  const s = getSession();
  if (s?.username) clearUnlockKey(s.username);
  localStorage.removeItem("session");
}

// ---------- unlock key UX ----------
const UNLOCK_TTL_MS = 10 * 60 * 1000; // 10 minutes in this tab
function unlockStorageKey(username) { return `unlock:${username}`; }
function cacheUnlockKey(username, key) {
  sessionStorage.setItem(unlockStorageKey(username), JSON.stringify({
    key,
    ts: Date.now()
  }));
}
function getCachedUnlockKey(username) {
  const raw = sessionStorage.getItem(unlockStorageKey(username));
  if (!raw) return null;
  try {
    const obj = JSON.parse(raw);
    if (!obj?.key || !obj?.ts) return null;
    if ((Date.now() - obj.ts) > UNLOCK_TTL_MS) return null;
    return obj.key;
  } catch {
    return null;
  }
}
function clearUnlockKey(username) {
  sessionStorage.removeItem(unlockStorageKey(username));
}
let __unlockModalInit = false;
function ensureUnlockModal() {
  if (__unlockModalInit) return;
  __unlockModalInit = true;
  const wrap = document.createElement("div");
  wrap.id = "unlockModal";
  wrap.className = "unlock-modal hidden";
  wrap.innerHTML = `
    <div class="unlock-card" role="dialog" aria-modal="true" aria-labelledby="unlockTitle">
      <h3 id="unlockTitle">Unlock Required</h3>
      <p id="unlockMsg">Enter your unlock key.</p>
      <input id="unlockInput" type="password" placeholder="Unlock key" autocomplete="current-password" />
      <div class="unlock-actions">
        <button id="unlockCancel" class="btn btn-muted" type="button">Cancel</button>
        <button id="unlockOk" class="btn btn-primary" type="button">Continue</button>
      </div>
    </div>
  `;
  document.body.appendChild(wrap);
}
async function promptUnlockKey(reason) {
  ensureUnlockModal();
  const modal = document.getElementById("unlockModal");
  const msg = document.getElementById("unlockMsg");
  const input = document.getElementById("unlockInput");
  const ok = document.getElementById("unlockOk");
  const cancel = document.getElementById("unlockCancel");

  msg.textContent = reason || "Enter your unlock key.";
  input.value = "";

  return await new Promise((resolve) => {
    const close = (val) => {
      modal.classList.add("hidden");
      ok.removeEventListener("click", onOk);
      cancel.removeEventListener("click", onCancel);
      input.removeEventListener("keydown", onKey);
      resolve(val);
    };
    const onOk = () => close(input.value || null);
    const onCancel = () => close(null);
    const onKey = (e) => {
      if (e.key === "Enter") onOk();
      if (e.key === "Escape") onCancel();
    };

    ok.addEventListener("click", onOk);
    cancel.addEventListener("click", onCancel);
    input.addEventListener("keydown", onKey);
    modal.classList.remove("hidden");
    setTimeout(() => input.focus(), 0);
  });
}

async function getUnlockKey(username, reason) {
  const cached = getCachedUnlockKey(username);
  if (cached) return cached;
  const key = await promptUnlockKey(reason || "Enter your unlock key:");
  if (!key) return null;
  cacheUnlockKey(username, key);
  return key;
}
async function getPrivateKeyWithUnlock(username, reason) {
  let key = await getUnlockKey(username, reason);
  if (!key) return null;
  try {
    return await loadPrivateKey(username, key);
  } catch (e) {
    clearUnlockKey(username);
    key = await getUnlockKey(username, "Unlock key incorrect. Try again:");
    if (!key) throw e;
    return await loadPrivateKey(username, key);
  }
}

// ---------- last contract convenience ----------
function setLastContractId(contractId) {
  if (!contractId) return;
  sessionStorage.setItem("lastContractId", contractId);
}
function getLastContractId() {
  return sessionStorage.getItem("lastContractId");
}
function updateAuditNavLink() {
  const links = document.querySelectorAll('[data-audit-scope="contract"]');
  if (!links.length) return;
  const last = getLastContractId();
  if (!last) return;
  for (const link of links) {
    link.setAttribute("href", `/audit.html?id=${encodeURIComponent(last)}`);
  }
}
