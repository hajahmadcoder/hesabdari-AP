/* =========================================================
   دفتر — بک‌اند یکپارچه (یک Worker واحد)
   ترکیب hesabdari-auth + hesabdari-data + hesabdari-personal + بخش ادمین hesabdari-panel
   سیستم ورود: توکن Bearer (برای کاربران عادی)، به‌علاوه کوکی psid (مخصوص پنل مدیریت مستقل)
   نیاز به D1 binding با نام DB — همان دیتابیس قبلی.
   Secrets/vars لازم: TELEGRAM_BOT_TOKEN, SUPER_ADMIN_TELEGRAM_ID, OWNER_TELEGRAM_ID,
   WEBAPP_URL, TELEGRAM_WEBHOOK_SECRET (اختیاری), TELEGRAM_BOT_USERNAME (اختیاری),
   ADMIN_PANEL_URL (اختیاری — آدرس پنل مدیریت مستقل)
   ========================================================= */

/* ---------- ابزارهای کمکی ---------- */
function randId(len) {
  const digits = "0123456789";
  let s = "";
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  for (let i = 0; i < len; i++) s += digits[arr[i] % 10];
  return s;
}
function randAlnumId(len) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  let s = "";
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  for (let i = 0; i < len; i++) s += chars[arr[i] % chars.length];
  return s;
}
async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" }, keyMaterial, 256
  );
  return Array.from(new Uint8Array(bits)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function getBearerToken(request) {
  const h = request.headers.get("Authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}
function publicUser(u) {
  const daysRemaining = u.sub_active && u.sub_expires ? Math.max(0, Math.ceil((new Date(u.sub_expires) - new Date()) / 86400000)) : null;
  return {
    id: u.id, firstName: u.first_name, lastName: u.last_name, username: u.username,
    role: u.role, blocked: !!u.blocked,
    province: u.province || null, district: u.district || null,
    photo: u.profile_photo || null, createdAt: u.created_at || null,
    pinEnabled: !!u.pin_hash,
    subscription: { active: !!u.sub_active, expiresAt: u.sub_expires, daysRemaining },
    limits: {
      storeLimit: u.store_limit != null ? u.store_limit : FREE_LIMITS.stores,
      customerLimit: u.sub_active ? (u.customer_limit != null ? u.customer_limit : null) : (u.customer_limit != null ? u.customer_limit : FREE_LIMITS.customers),
      transactionLimit: u.sub_active ? (u.transaction_limit != null ? u.transaction_limit : null) : (u.transaction_limit != null ? u.transaction_limit : FREE_LIMITS.transactions),
      staffLimit: u.sub_active ? (u.staff_limit != null ? u.staff_limit : null) : (u.staff_limit != null ? u.staff_limit : FREE_LIMITS.staff),
    },
  };
}

/* ---------- CORS ---------- */
function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}
function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { "Content-Type": "application/json", ...corsHeaders(origin) },
  });
}

const FREE_LIMITS = { stores: 1, customers: 15, transactions: 100, staff: 0 };

// دامنه‌های مجاز برای اثر انگشت/فیس (WebAuthn): هم سایت روی هاست، هم نسخه‌ی کلودفلر (که اپ اندروید هم از آن استفاده می‌کند)
// هر دامنه اعتبارنامه‌ی جدا دارد؛ کاربر روی هر دامنه یک‌بار دستگاهش را ثبت می‌کند.
const ALLOWED_RP_ORIGINS = ["https://ap.coder-team.ir", "https://hesabdariap.pages.dev"];
function rpIdFor(origin) {
  return ALLOWED_RP_ORIGINS.includes(origin) ? new URL(origin).hostname : "hesabdariap.pages.dev";
}

function esc4tg(s) {
  return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
async function notifyOwnerTelegram(env, text) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.OWNER_TELEGRAM_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: env.OWNER_TELEGRAM_ID, text, parse_mode: "HTML" }),
    });
  } catch {}
}

function isValidPin(pin) { return typeof pin === "string" && /^[0-9]{4,6}$/.test(pin); }

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
function bytesToB64url(bytes) {
  const arr = new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function cborDecode(bytes) {
  let offset = 0;
  function readUint(len) { let v = 0; for (let i = 0; i < len; i++) v = v * 256 + bytes[offset++]; return v; }
  function decodeItem() {
    const initial = bytes[offset++];
    const major = initial >> 5;
    const ai = initial & 0x1f;
    let len;
    if (ai < 24) len = ai;
    else if (ai === 24) len = readUint(1);
    else if (ai === 25) len = readUint(2);
    else if (ai === 26) len = readUint(4);
    else if (ai === 27) len = readUint(8);
    else throw new Error("cbor: unsupported ai " + ai);
    switch (major) {
      case 0: return len;
      case 1: return -1 - len;
      case 2: { const b = bytes.slice(offset, offset + len); offset += len; return b; }
      case 3: { const b = bytes.slice(offset, offset + len); offset += len; return new TextDecoder().decode(b); }
      case 4: { const arr = []; for (let i = 0; i < len; i++) arr.push(decodeItem()); return arr; }
      case 5: { const m = new Map(); for (let i = 0; i < len; i++) { const k = decodeItem(); const v = decodeItem(); m.set(k, v); } return m; }
      case 6: return decodeItem();
      case 7: { if (ai === 20) return false; if (ai === 21) return true; if (ai === 22) return null; throw new Error("cbor: unsupported simple " + ai); }
      default: throw new Error("cbor: unsupported major " + major);
    }
  }
  const value = decodeItem();
  return { value, length: offset };
}

function parseAuthData(authData) {
  let offset = 0;
  const rpIdHash = authData.slice(0, 32); offset += 32;
  const flags = authData[offset]; offset += 1;
  const counter = (authData[offset] << 24) | (authData[offset + 1] << 16) | (authData[offset + 2] << 8) | authData[offset + 3]; offset += 4;
  const result = { rpIdHash, flags, counter, userPresent: !!(flags & 0x01), userVerified: !!(flags & 0x04) };
  if (flags & 0x40) {
    offset += 16;
    const credIdLen = (authData[offset] << 8) | authData[offset + 1]; offset += 2;
    const credentialId = authData.slice(offset, offset + credIdLen); offset += credIdLen;
    const { value: coseKeyMap, length: consumed } = cborDecode(authData.slice(offset));
    offset += consumed;
    result.credentialId = credentialId;
    result.coseKeyMap = coseKeyMap;
  }
  return result;
}

function coseKeyToJwk(m) {
  const kty = m.get(1);
  const alg = m.get(3);
  if (kty === 2) {
    const x = m.get(-2), y = m.get(-3);
    return { jwk: { kty: "EC", crv: "P-256", x: bytesToB64url(x), y: bytesToB64url(y), ext: true }, alg };
  }
  if (kty === 3) {
    const n = m.get(-1), e = m.get(-2);
    return { jwk: { kty: "RSA", n: bytesToB64url(n), e: bytesToB64url(e), ext: true }, alg };
  }
  throw new Error("نوع کلید پشتیبانی نمی‌شود");
}

function derToRawEcdsaSig(der) {
  let offset = 0;
  if (der[offset++] !== 0x30) throw new Error("bad der");
  let seqLen = der[offset++];
  if (seqLen & 0x80) { const n = seqLen & 0x7f; seqLen = 0; for (let i = 0; i < n; i++) seqLen = (seqLen << 8) | der[offset++]; }
  if (der[offset++] !== 0x02) throw new Error("bad der r");
  let rLen = der[offset++];
  let r = Array.from(der.slice(offset, offset + rLen)); offset += rLen;
  if (der[offset++] !== 0x02) throw new Error("bad der s");
  let sLen = der[offset++];
  let s = Array.from(der.slice(offset, offset + sLen));
  function fix32(arr) { arr = arr.slice(); while (arr.length > 32 && arr[0] === 0) arr.shift(); while (arr.length < 32) arr.unshift(0); return arr; }
  const out = new Uint8Array(64);
  out.set(fix32(r), 0); out.set(fix32(s), 32);
  return out;
}

async function importPublicKey(jwk) {
  if (jwk.kty === "EC") return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  if (jwk.kty === "RSA") return crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  throw new Error("کلید پشتیبانی نمی‌شود");
}
async function verifyAssertionSignature(cred, authDataBytes, clientDataJSONBytes, signatureBytes) {
  const jwk = JSON.parse(cred.public_key);
  const key = await importPublicKey(jwk);
  const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSONBytes));
  const signedData = new Uint8Array(authDataBytes.length + clientDataHash.length);
  signedData.set(authDataBytes, 0); signedData.set(clientDataHash, authDataBytes.length);
  let sig = signatureBytes, algo;
  if (jwk.kty === "EC") { sig = derToRawEcdsaSig(signatureBytes); algo = { name: "ECDSA", hash: "SHA-256" }; }
  else { algo = { name: "RSASSA-PKCS1-v1_5" }; }
  return crypto.subtle.verify(algo, key, sig, signedData);
}

async function elevateSession(request, env) {
  const token = getBearerToken(request);
  const elevated = new Date(Date.now() + 10 * 60000).toISOString();
  await env.DB.prepare("UPDATE sessions SET elevated_until = ? WHERE token = ?").bind(elevated, token).run();
  return elevated;
}

async function ensureSubscriptionCurrent(env, user) {
  if (user.sub_active && user.sub_expires && new Date(user.sub_expires) <= new Date()) {
    await env.DB.prepare(
      "UPDATE users SET sub_active = 0, sub_expires = NULL, store_limit = ?, customer_limit = ?, transaction_limit = ?, staff_limit = ? WHERE id = ?"
    ).bind(FREE_LIMITS.stores, FREE_LIMITS.customers, FREE_LIMITS.transactions, FREE_LIMITS.staff, user.id).run();
    const logId = randId(10);
    await env.DB.prepare("INSERT INTO subscription_logs (id, user_id, action, days, created_at) VALUES (?, ?, 'expired', 0, ?)")
      .bind(logId, user.id, new Date().toISOString()).run();
    return {
      ...user, sub_active: 0, sub_expires: null,
      store_limit: FREE_LIMITS.stores, customer_limit: FREE_LIMITS.customers,
      transaction_limit: FREE_LIMITS.transactions, staff_limit: FREE_LIMITS.staff,
    };
  }
  return user;
}

async function getSessionUser(request, env) {
  const token = getBearerToken(request);
  if (!token) return null;
  const sess = await env.DB.prepare("SELECT * FROM sessions WHERE token = ? AND expires_at > ?")
    .bind(token, new Date().toISOString()).first();
  if (!sess) return null;
  const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(sess.user_id).first();
  if (!user) return null;
  return await ensureSubscriptionCurrent(env, user);
}

function parseDeviceLabel(ua) {
  if (!ua) return "دستگاه ناشناس";
  if (/android/i.test(ua)) return "اندروید";
  if (/iphone|ipad|ios/i.test(ua)) return "آیفون/آیپد";
  if (/windows/i.test(ua)) return "ویندوز";
  if (/mac os/i.test(ua)) return "مک";
  return "مرورگر دیگر";
}

async function register(request, env, origin) {
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const firstName = (body.firstName || "").trim();
  const lastName = (body.lastName || "").trim();
  const username = (body.username || "").trim();
  const password = body.password || "";
  const province = (body.province || "").trim() || null;
  const district = (body.district || "").trim() || null;
  if (!firstName || !lastName || !username || !password) return json({ error: "همه فیلدها الزامی است" }, 400, origin);
  if (password.length < 4) return json({ error: "رمز عبور باید حداقل ۴ کاراکتر باشد" }, 400, origin);

  const exists = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
  if (exists) return json({ error: "این نام کاربری قبلا استفاده شده است" }, 400, origin);

  const countRow = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
  const role = countRow.c === 0 ? "admin" : "user";

  const salt = randId(20);
  const hash = await hashPassword(password, salt);
  const id = randAlnumId(12);
  const now = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO users (id, first_name, last_name, username, password_hash, salt, role, blocked, sub_active, sub_expires, province, district, store_limit, customer_limit, transaction_limit, staff_limit, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, firstName, lastName, username, hash, salt, role, province, district, FREE_LIMITS.stores, FREE_LIMITS.customers, FREE_LIMITS.transactions, FREE_LIMITS.staff, now).run();

  const token = crypto.randomUUID();
  const expires = new Date(Date.now() + 30 * 86400000).toISOString();
  await env.DB.prepare("INSERT INTO sessions (token, user_id, created_at, expires_at, device) VALUES (?, ?, ?, ?, ?)")
    .bind(token, id, now, expires, parseDeviceLabel(request.headers.get("User-Agent"))).run();

  const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
  await notifyOwnerTelegram(env, `👤 کاربر جدید ثبت‌نام کرد\nنام: ${esc4tg(firstName)} ${esc4tg(lastName)}\nیوزرنیم: @${esc4tg(username)}${province ? "\nولایت: " + esc4tg(province) : ""}`);
  return json({ ok: true, token, user: publicUser(user) }, 200, origin);
}

async function login(request, env, origin) {
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const username = (body.username || "").trim();
  const password = body.password || "";
  if (!username || !password) return json({ error: "نام کاربری و رمز عبور را وارد کنید" }, 400, origin);

  const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
  if (!user) return json({ error: "نام کاربری یا رمز عبور اشتباه است" }, 401, origin);

  const hash = await hashPassword(password, user.salt);
  if (hash !== user.password_hash) return json({ error: "نام کاربری یا رمز عبور اشتباه است" }, 401, origin);
  if (user.blocked) return json({ error: "حساب کاربری شما مسدود شده است" }, 403, origin);

  const token = crypto.randomUUID();
  const now = new Date().toISOString();
  const expires = new Date(Date.now() + 30 * 86400000).toISOString();
  await env.DB.prepare("INSERT INTO sessions (token, user_id, created_at, expires_at, device) VALUES (?, ?, ?, ?, ?)")
    .bind(token, user.id, now, expires, parseDeviceLabel(request.headers.get("User-Agent"))).run();

  return json({ ok: true, token, user: publicUser(user) }, 200, origin);
}

async function logout(request, user, env, origin) {
  const token = getBearerToken(request);
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
  return json({ ok: true }, 200, origin);
}

async function me(user, env, origin) {
  if (!user) return json({ user: null }, 200, origin);
  return json({ user: publicUser(user) }, 200, origin);
}

async function updateMyProfile(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const firstName = (body.firstName || "").trim();
  const lastName = (body.lastName || "").trim();
  const province = (body.province || "").trim() || null;
  const district = (body.district || "").trim() || null;
  if (!firstName || !lastName) return json({ error: "نام و نام خانوادگی الزامی است" }, 400, origin);

  if (body.photoBase64 !== undefined) {
    const photo = (body.photoBase64 || "").trim();
    if (photo && photo.length > 400000) return json({ error: "حجم عکس زیاد است" }, 400, origin);
    await env.DB.prepare("UPDATE users SET first_name = ?, last_name = ?, province = ?, district = ?, profile_photo = ? WHERE id = ?")
      .bind(firstName, lastName, province, district, photo || null, user.id).run();
  } else {
    await env.DB.prepare("UPDATE users SET first_name = ?, last_name = ?, province = ?, district = ? WHERE id = ?")
      .bind(firstName, lastName, province, district, user.id).run();
  }
  const updated = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(user.id).first();
  return json({ ok: true, user: publicUser(updated) }, 200, origin);
}

async function changeMyPassword(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const { currentPassword, newPassword, confirmPassword } = body;
  if (!currentPassword || !newPassword || !confirmPassword) return json({ error: "همه فیلدها الزامی است" }, 400, origin);
  if (newPassword !== confirmPassword) return json({ error: "رمز جدید و تکرار آن یکسان نیستند" }, 400, origin);
  if (newPassword.length < 4) return json({ error: "رمز جدید باید حداقل ۴ کاراکتر باشد" }, 400, origin);
  const hash = await hashPassword(currentPassword, user.salt);
  if (hash !== user.password_hash) return json({ error: "رمز عبور فعلی اشتباه است" }, 400, origin);
  const newSalt = randId(20);
  const newHash = await hashPassword(newPassword, newSalt);
  await env.DB.prepare("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?").bind(newHash, newSalt, user.id).run();
  return json({ ok: true }, 200, origin);
}

async function mySessions(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const currentToken = getBearerToken(request);
  const rows = await env.DB.prepare("SELECT * FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC")
    .bind(user.id, new Date().toISOString()).all();
  return json({
    sessions: rows.results.map((s) => ({ id: s.token, device: s.device || "دستگاه ناشناس", createdAt: s.created_at, current: s.token === currentToken })),
  }, 200, origin);
}

async function revokeAllSessions(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const currentToken = getBearerToken(request);
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND token != ?").bind(user.id, currentToken || "").run();
  return json({ ok: true }, 200, origin);
}

async function mySubscriptionLogs(user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const logs = await env.DB.prepare("SELECT * FROM subscription_logs WHERE user_id = ? ORDER BY created_at DESC").bind(user.id).all();
  return json({ logs: logs.results.map((l) => ({ id: l.id, action: l.action, days: l.days, date: l.created_at })) }, 200, origin);
}

async function setPin(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const { password, pin, confirmPin } = body;
  if (!password) return json({ error: "برای تنظیم پین، رمز عبور حساب را وارد کنید" }, 400, origin);
  if (!isValidPin(pin)) return json({ error: "پین باید بین ۴ تا ۶ رقم باشد" }, 400, origin);
  if (pin !== confirmPin) return json({ error: "پین و تکرار آن یکسان نیستند" }, 400, origin);
  const hash = await hashPassword(password, user.salt);
  if (hash !== user.password_hash) return json({ error: "رمز عبور اشتباه است" }, 400, origin);
  const salt = randId(20);
  const pinHash = await hashPassword(pin, salt);
  await env.DB.prepare("UPDATE users SET pin_hash = ?, pin_salt = ? WHERE id = ?").bind(pinHash, salt, user.id).run();
  return json({ ok: true }, 200, origin);
}

async function disablePin(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  if (!body.password) return json({ error: "رمز عبور را وارد کنید" }, 400, origin);
  const hash = await hashPassword(body.password, user.salt);
  if (hash !== user.password_hash) return json({ error: "رمز عبور اشتباه است" }, 400, origin);
  await env.DB.prepare("UPDATE users SET pin_hash = NULL, pin_salt = NULL WHERE id = ?").bind(user.id).run();
  return json({ ok: true }, 200, origin);
}

async function verifyPin(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  if (!user.pin_hash) return json({ error: "پین تنظیم نشده است" }, 400, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  if (!isValidPin(body.pin)) return json({ error: "پین نامعتبر است" }, 400, origin);
  const hash = await hashPassword(body.pin, user.pin_salt);
  if (hash !== user.pin_hash) return json({ error: "پین اشتباه است" }, 401, origin);
  const elevatedUntil = await elevateSession(request, env);
  return json({ ok: true, elevatedUntil }, 200, origin);
}

async function webauthnRegisterOptions(user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const challenge = bytesToB64url(crypto.getRandomValues(new Uint8Array(32)));
  await env.DB.prepare("DELETE FROM webauthn_challenges WHERE user_id = ?").bind(user.id).run();
  await env.DB.prepare("INSERT INTO webauthn_challenges (id, user_id, challenge, created_at) VALUES (?, ?, ?, ?)")
    .bind(randId(10), user.id, challenge, new Date().toISOString()).run();
  const existing = await env.DB.prepare("SELECT credential_id FROM webauthn_credentials WHERE user_id = ?").bind(user.id).all();
  return json({
    challenge,
    rp: { name: "دفتر", id: rpIdFor(origin) },
    user: { id: bytesToB64url(new TextEncoder().encode(user.id)), name: user.username, displayName: user.first_name + " " + user.last_name },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
    authenticatorSelection: { userVerification: "required", residentKey: "discouraged" },
    timeout: 60000,
    excludeCredentials: existing.results.map((c) => ({ id: c.credential_id, type: "public-key" })),
  }, 200, origin);
}

async function webauthnRegisterVerify(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const ch = await env.DB.prepare("SELECT * FROM webauthn_challenges WHERE user_id = ?").bind(user.id).first();
  if (!ch) return json({ error: "چالش امنیتی منقضی شده، دوباره تلاش کنید" }, 400, origin);

  const clientDataBytes = b64urlToBytes(body.response.clientDataJSON);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
  if (clientData.type !== "webauthn.create") return json({ error: "نوع درخواست نامعتبر است" }, 400, origin);
  if (clientData.challenge !== ch.challenge) return json({ error: "چالش امنیتی مطابقت ندارد" }, 400, origin);
  if (!ALLOWED_RP_ORIGINS.includes(clientData.origin)) return json({ error: "دامنه معتبر نیست" }, 400, origin);

  const attObjBytes = b64urlToBytes(body.response.attestationObject);
  const { value: attMap } = cborDecode(attObjBytes);
  const authData = parseAuthData(attMap.get("authData"));
  if (!authData.userPresent) return json({ error: "تایید حضور کاربر انجام نشد" }, 400, origin);
  if (!authData.credentialId) return json({ error: "داده اعتبارسنجی ناقص است" }, 400, origin);

  const { jwk, alg } = coseKeyToJwk(authData.coseKeyMap);
  const credentialIdB64 = bytesToB64url(authData.credentialId);
  const dup = await env.DB.prepare("SELECT id FROM webauthn_credentials WHERE credential_id = ?").bind(credentialIdB64).first();
  if (dup) return json({ error: "این دستگاه قبلا ثبت شده است" }, 400, origin);
  const cnt = await env.DB.prepare("SELECT COUNT(*) as c FROM webauthn_credentials WHERE user_id = ?").bind(user.id).first();
  if (cnt.c >= 5) return json({ error: "حداکثر ۵ دستگاه قابل ثبت است" }, 400, origin);

  const id = randId(10);
  const now = new Date().toISOString();
  const deviceLabel = (body.deviceLabel || "").trim() || "دستگاه ناشناس";
  await env.DB.prepare(
    "INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, alg, counter, device_label, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(id, user.id, credentialIdB64, JSON.stringify(jwk), alg, authData.counter, deviceLabel, now).run();
  await env.DB.prepare("DELETE FROM webauthn_challenges WHERE user_id = ?").bind(user.id).run();

  return json({ ok: true, credential: { id, deviceLabel, createdAt: now } }, 200, origin);
}

async function webauthnAuthOptions(user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const creds = await env.DB.prepare("SELECT credential_id FROM webauthn_credentials WHERE user_id = ?").bind(user.id).all();
  if (!creds.results.length) return json({ error: "دستگاهی برای ورود بیومتریک ثبت نشده است" }, 404, origin);
  const challenge = bytesToB64url(crypto.getRandomValues(new Uint8Array(32)));
  await env.DB.prepare("DELETE FROM webauthn_challenges WHERE user_id = ?").bind(user.id).run();
  await env.DB.prepare("INSERT INTO webauthn_challenges (id, user_id, challenge, created_at) VALUES (?, ?, ?, ?)")
    .bind(randId(10), user.id, challenge, new Date().toISOString()).run();
  return json({
    challenge, rpId: rpIdFor(origin), userVerification: "required", timeout: 60000,
    allowCredentials: creds.results.map((c) => ({ id: c.credential_id, type: "public-key" })),
  }, 200, origin);
}

async function webauthnAuthVerify(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const ch = await env.DB.prepare("SELECT * FROM webauthn_challenges WHERE user_id = ?").bind(user.id).first();
  if (!ch) return json({ error: "چالش امنیتی منقضی شده، دوباره تلاش کنید" }, 400, origin);
  const cred = await env.DB.prepare("SELECT * FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?").bind(body.id, user.id).first();
  if (!cred) return json({ error: "دستگاه شناسایی نشد" }, 404, origin);

  const clientDataBytes = b64urlToBytes(body.response.clientDataJSON);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
  if (clientData.type !== "webauthn.get") return json({ error: "نوع درخواست نامعتبر است" }, 400, origin);
  if (clientData.challenge !== ch.challenge) return json({ error: "چالش امنیتی مطابقت ندارد" }, 400, origin);
  if (!ALLOWED_RP_ORIGINS.includes(clientData.origin)) return json({ error: "دامنه معتبر نیست" }, 400, origin);

  const authDataBytes = b64urlToBytes(body.response.authenticatorData);
  const sigBytes = b64urlToBytes(body.response.signature);
  const ok = await verifyAssertionSignature(cred, authDataBytes, clientDataBytes, sigBytes);
  if (!ok) return json({ error: "تایید هویت ناموفق بود" }, 401, origin);

  await env.DB.prepare("DELETE FROM webauthn_challenges WHERE user_id = ?").bind(user.id).run();
  const elevatedUntil = await elevateSession(request, env);
  return json({ ok: true, elevatedUntil }, 200, origin);
}

async function listWebauthnCredentials(user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const rows = await env.DB.prepare("SELECT id, device_label, created_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC").bind(user.id).all();
  return json({ credentials: rows.results.map((r) => ({ id: r.id, deviceLabel: r.device_label, createdAt: r.created_at })) }, 200, origin);
}

async function deleteWebauthnCredential(credId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  await env.DB.prepare("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?").bind(credId, user.id).run();
  return json({ ok: true }, 200, origin);
}

async function myPendingGrants(user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const rows = await env.DB.prepare("SELECT * FROM subscription_grants WHERE user_id = ? AND status = 'pending' ORDER BY granted_at DESC").bind(user.id).all();
  return json({
    grants: rows.results.map((g) => ({
      id: g.id, days: g.days, storeLimit: g.store_limit, customerLimit: g.customer_limit, transactionLimit: g.transaction_limit, staffLimit: g.staff_limit, grantedAt: g.granted_at,
    })),
  }, 200, origin);
}

async function activateGrant(grantId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const grant = await env.DB.prepare("SELECT * FROM subscription_grants WHERE id = ? AND user_id = ?").bind(grantId, user.id).first();
  if (!grant) return json({ error: "درخواست اشتراک یافت نشد" }, 404, origin);
  if (grant.status !== "pending") return json({ error: "این درخواست قبلا فعال شده است" }, 400, origin);

  const now = new Date().toISOString();
  const expires = new Date(Date.now() + grant.days * 86400000).toISOString();
  await env.DB.prepare(
    "UPDATE users SET sub_active = 1, sub_expires = ?, store_limit = ?, customer_limit = ?, transaction_limit = ?, staff_limit = ? WHERE id = ?"
  ).bind(expires, grant.store_limit, grant.customer_limit, grant.transaction_limit, grant.staff_limit, user.id).run();
  await env.DB.prepare("UPDATE subscription_grants SET status = 'activated', activated_at = ? WHERE id = ?").bind(now, grantId).run();

  const logId = randId(10);
  await env.DB.prepare("INSERT INTO subscription_logs (id, user_id, action, days, created_at) VALUES (?, ?, 'activate', ?, ?)")
    .bind(logId, user.id, grant.days, now).run();

  return json({ ok: true, active: true, expiresAt: expires }, 200, origin);
}

async function ensureSeedPlans(env) {
  const count = await env.DB.prepare("SELECT COUNT(*) as c FROM plans").first();
  if (count.c > 0) return;
  const now = new Date().toISOString();
  const defaults = [
    { name: "پایه", description: "برای مغازه‌داران با تعداد مشتری متوسط", days: 30, storeLimit: 2, customerLimit: 100, transactionLimit: 1000, staffLimit: 2, sort: 1 },
    { name: "حرفه‌ای", description: "برای کسب‌وکارهای فعال با چند فروشگاه", days: 30, storeLimit: 5, customerLimit: 500, transactionLimit: null, staffLimit: 5, sort: 2 },
    { name: "تجاری", description: "بدون محدودیت — برای شبکه‌های بزرگ فروشگاهی", days: 30, storeLimit: null, customerLimit: null, transactionLimit: null, staffLimit: null, sort: 3 },
  ];
  for (const p of defaults) {
    await env.DB.prepare(
      "INSERT INTO plans (id, name, description, days, store_limit, customer_limit, transaction_limit, staff_limit, sort_order, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)"
    ).bind(randId(10), p.name, p.description, p.days, p.storeLimit, p.customerLimit, p.transactionLimit, p.staffLimit, p.sort, now).run();
  }
}
function planOut(p) {
  return {
    id: p.id, name: p.name, description: p.description, days: p.days,
    storeLimit: p.store_limit, customerLimit: p.customer_limit, transactionLimit: p.transaction_limit, staffLimit: p.staff_limit,
    active: !!p.active, sortOrder: p.sort_order,
  };
}
async function listPlans(user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  await ensureSeedPlans(env);
  const rows = await env.DB.prepare("SELECT * FROM plans WHERE active = 1 ORDER BY sort_order ASC, created_at ASC").all();
  return json({ plans: rows.results.map(planOut) }, 200, origin);
}

async function createPlanRequest(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const planId = (body.planId || "").trim();
  const plan = await env.DB.prepare("SELECT * FROM plans WHERE id = ? AND active = 1").bind(planId).first();
  if (!plan) return json({ error: "پلن یافت نشد" }, 404, origin);

  const existing = await env.DB.prepare("SELECT id FROM plan_requests WHERE user_id = ? AND status = 'pending'").bind(user.id).first();
  if (existing) return json({ error: "شما یک درخواست در انتظار بررسی دارید" }, 400, origin);

  const id = randId(10);
  const now = new Date().toISOString();
  await env.DB.prepare("INSERT INTO plan_requests (id, user_id, plan_id, status, created_at) VALUES (?, ?, ?, 'pending', ?)")
    .bind(id, user.id, planId, now).run();
  await notifyOwnerTelegram(env, `📩 درخواست اشتراک جدید\nکاربر: ${esc4tg(user.first_name)} ${esc4tg(user.last_name)} (@${esc4tg(user.username)})\nپلن: ${esc4tg(plan.name)}`);
  return json({ ok: true }, 200, origin);
}
async function myPlanRequests(user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const rows = await env.DB.prepare(
    `SELECT pr.*, p.name as plan_name FROM plan_requests pr JOIN plans p ON p.id = pr.plan_id WHERE pr.user_id = ? ORDER BY pr.created_at DESC LIMIT 10`
  ).bind(user.id).all();
  return json({
    requests: rows.results.map((r) => ({ id: r.id, planName: r.plan_name, status: r.status, date: r.created_at })),
  }, 200, origin);
}

async function myBroadcasts(user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const rows = await env.DB.prepare(
    `SELECT * FROM broadcasts WHERE target_type = 'all'
       OR (target_type = 'province' AND target_province = ?)
       OR (target_type = 'district' AND target_province = ? AND target_district = ?)
     ORDER BY created_at DESC LIMIT 30`
  ).bind(user.province || "", user.province || "", user.district || "").all();
  return json({
    broadcasts: rows.results.map((b) => ({ id: b.id, message: b.message, date: b.created_at })),
  }, 200, origin);
}
async function isElevated(request, env) {
  const token = getBearerToken(request);
  if (!token) return false;
  const sess = await env.DB.prepare("SELECT elevated_until FROM sessions WHERE token = ?").bind(token).first();
  return !!(sess && sess.elevated_until && new Date(sess.elevated_until) > new Date());
}

const CURRENCY_SYMBOLS = { AFN: "؋", IRT: "تومان" };
const ABOUT_TEXT = "📒 دفتر\nسامانه‌ی حسابداری و مدیریت مشتریان فروشگاه — ثبت بدهی/پرداخت، یادآوری سررسید، و مدیریت آنلاین حساب از طریق تلگرام.";

function randCode(len) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  for (let i = 0; i < len; i++) s += chars[arr[i] % chars.length];
  return s;
}

async function tgApi(env, method, payload) {
  if (!env.TELEGRAM_BOT_TOKEN) return null;
  try {
    const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return await res.json();
  } catch { return null; }
}
async function sendTelegramMessage(env, chatId, text, replyMarkup) {
  if (!chatId) return;
  const payload = { chat_id: chatId, text, parse_mode: "HTML" };
  if (replyMarkup) payload.reply_markup = replyMarkup;
  await tgApi(env, "sendMessage", payload);
}
async function sendTelegramPhoto(env, chatId, fileId, caption, replyMarkup) {
  if (!chatId) return;
  const payload = { chat_id: chatId, photo: fileId, caption, parse_mode: "HTML" };
  if (replyMarkup) payload.reply_markup = replyMarkup;
  await tgApi(env, "sendPhoto", payload);
}
async function answerCallbackQuery(env, id, text) {
  await tgApi(env, "answerCallbackQuery", { callback_query_id: id, text: text || undefined });
}

function customerMainKeyboard(webAppUrl) {
  return {
    keyboard: [
      [{ text: "🏦 حساب من", web_app: { url: webAppUrl } }],
      [{ text: "ℹ️ درباره ما" }, { text: "📥 دانلود اپلیکیشن" }],
    ],
    resize_keyboard: true,
  };
}
function ownerMainKeyboard(webAppUrl) {
  return {
    keyboard: [
      [{ text: "🏪 مدیریت فروشگاه", web_app: { url: webAppUrl } }],
      [{ text: "🧾 فیش‌های در انتظار" }, { text: "📋 درخواست‌های تسویه/وجه" }],
      [{ text: "ℹ️ درباره ما" }],
    ],
    resize_keyboard: true,
  };
}
function adminMainKeyboard() {
  return {
    keyboard: [
      [{ text: "📊 آمار کلی سیستم" }], [{ text: "🏪 لیست فروشگاه‌ها" }],
      [{ text: "🛠 اجرای مایگریشن دیتابیس" }],
    ],
    resize_keyboard: true,
  };
}

async function runD1Migration(chatId, env) {
  const statements = [
    "ALTER TABLE stores ADD COLUMN telegram_owner_chat_id TEXT",
    "ALTER TABLE stores ADD COLUMN telegram_link_code TEXT",
    "ALTER TABLE stores ADD COLUMN card_afn_number TEXT",
    "ALTER TABLE stores ADD COLUMN card_afn_holder TEXT",
    "ALTER TABLE stores ADD COLUMN card_irt_number TEXT",
    "ALTER TABLE stores ADD COLUMN card_irt_holder TEXT",
    `CREATE TABLE IF NOT EXISTS payment_receipts (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, store_id TEXT NOT NULL,
      currency TEXT NOT NULL, amount REAL NOT NULL, photo_file_id TEXT,
      status TEXT NOT NULL DEFAULT 'awaiting_photo', created_at TEXT NOT NULL, resolved_at TEXT
    )`,
    "ALTER TABLE settlement_requests ADD COLUMN kind TEXT DEFAULT 'settlement'",
    "ALTER TABLE settlement_requests ADD COLUMN amount REAL",
    "ALTER TABLE settlement_requests ADD COLUMN currency TEXT",
    "CREATE INDEX IF NOT EXISTS idx_stores_telegram_link_code ON stores(telegram_link_code)",
    "CREATE INDEX IF NOT EXISTS idx_payment_receipts_store ON payment_receipts(store_id)",
    "CREATE INDEX IF NOT EXISTS idx_payment_receipts_customer_status ON payment_receipts(customer_id, status)",
  ];
  const results = [];
  for (const sql of statements) {
    try {
      await env.DB.prepare(sql).run();
      results.push("✅ " + sql.slice(0, 40).replace(/\s+/g, " "));
    } catch (err) {
      results.push("⚠️ (رد شد، احتمالاً از قبل بوده) " + sql.slice(0, 40).replace(/\s+/g, " "));
    }
  }
  await sendTelegramMessage(env, chatId, "نتیجه‌ی مایگریشن:\n\n" + results.join("\n"));
  return new Response("ok");
}

async function computeCustomerBalance(env, customerId, currency) {
  const rows = await env.DB.prepare(
    "SELECT type, SUM(amount) as total FROM transactions WHERE customer_id = ? AND currency = ? GROUP BY type"
  ).bind(customerId, currency).all();
  let debt = 0, payment = 0;
  rows.results.forEach((r) => { if (r.type === "debt") debt = r.total; else payment = r.total; });
  return debt - payment;
}

async function notifyTelegramTransaction(env, customer, store, type, currency, amount, note, dueDate) {
  const link = await env.DB.prepare("SELECT * FROM telegram_links WHERE customer_id = ?").bind(customer.id).first();
  if (!link) return;
  const bal = await computeCustomerBalance(env, customer.id, currency);
  const symbol = CURRENCY_SYMBOLS[currency] || currency;
  const label = type === "debt" ? "🔴 بدهی جدید ثبت شد" : "🟢 پرداخت جدید ثبت شد";
  let text = `${label}\nفروشگاه: ${esc4tg(store.name)}\nمبلغ: ${amount.toLocaleString("fa-IR")} ${symbol}`;
  if (note) text += `\nبابت: ${esc4tg(note)}`;
  if (type === "debt" && dueDate) text += `\nسررسید پرداخت: ${dueDate}`;
  text += `\nمانده‌ی فعلی حساب شما: ${Math.abs(bal).toLocaleString("fa-IR")} ${symbol} ${bal > 0 ? "(بدهکار)" : bal < 0 ? "(بستانکار)" : "(تسویه)"}`;
  await sendTelegramMessage(env, link.chat_id, text);
}

async function telegramWebhook(request, env, origin) {
  if (env.TELEGRAM_WEBHOOK_SECRET) {
    const secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
    if (secret !== env.TELEGRAM_WEBHOOK_SECRET) return new Response("forbidden", { status: 403 });
  }
  let update; try { update = await request.json(); } catch { return new Response("ok"); }

  if (update.callback_query) { await handleCallback(update.callback_query, env); return new Response("ok"); }

  const msg = update.message;
  if (!msg) return new Response("ok");
  const chatId = String(msg.chat.id);

  if (msg.photo && msg.photo.length) return await handleReceiptPhoto(chatId, msg, env);

  const text = (msg.text || "").trim();
  if (!text) return new Response("ok");

  if (text.startsWith("/start")) return await handleStart(chatId, text, msg, env);

  switch (text) {
    case "ℹ️ درباره ما":
      await sendTelegramMessage(env, chatId, ABOUT_TEXT);
      return new Response("ok");
    case "📥 دانلود اپلیکیشن":
      await sendTelegramMessage(env, chatId, "این قابلیت به‌زودی فعال می‌شود.");
      return new Response("ok");
    case "🧾 فیش‌های در انتظار":
      return await listPendingReceiptsForOwner(chatId, env);
    case "📋 درخواست‌های تسویه/وجه":
      return await listPendingSettlementsForOwner(chatId, env);
    case "📊 آمار کلی سیستم":
      return await sendAdminStats(chatId, env);
    case "🏪 لیست فروشگاه‌ها":
      return await sendAdminStoreList(chatId, env);
    case "🛠 اجرای مایگریشن دیتابیس":
      if (env.SUPER_ADMIN_TELEGRAM_ID && chatId === String(env.SUPER_ADMIN_TELEGRAM_ID)) return await runD1Migration(chatId, env);
      break;
  }

  if (env.SUPER_ADMIN_TELEGRAM_ID && chatId === String(env.SUPER_ADMIN_TELEGRAM_ID) && /^[A-Za-z0-9]{5,10}$/.test(text)) {
    return await adminLookupStoreLink(chatId, text.trim(), env);
  }

  await sendTelegramMessage(env, chatId, "لطفاً از دکمه‌های پایین صفحه استفاده کنید 🙏");
  return new Response("ok");
}

async function adminLookupStoreLink(chatId, storeId, env) {
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(storeId).first();
  if (!store) { await sendTelegramMessage(env, chatId, "فروشگاهی با این شناسه یافت نشد."); return new Response("ok"); }
  let code = store.telegram_link_code;
  if (!code) {
    code = randCode(12);
    await env.DB.prepare("UPDATE stores SET telegram_link_code = ? WHERE id = ?").bind(code, storeId).run();
  }
  const me = await tgApi(env, "getMe", {});
  const username = me && me.result ? me.result.username : null;
  const link = username ? `https://t.me/${username}?start=${code}` : `(کد: ${code})`;
  await sendTelegramMessage(env, chatId,
    `🏪 ${esc4tg(store.name)}\nوضعیت اتصال مالک: ${store.telegram_owner_chat_id ? "متصل ✅" : "متصل نیست ❌"}\n\nلینک اتصال مالک:\n${link}`);
  return new Response("ok");
}

async function handleStart(chatId, text, msg, env) {
  const payload = (text.split(" ")[1] || "").trim();
  const webAppBase = env.WEBAPP_URL;

  if (env.SUPER_ADMIN_TELEGRAM_ID && chatId === String(env.SUPER_ADMIN_TELEGRAM_ID) && !payload) {
    await sendTelegramMessage(env, chatId, "👑 به پنل مدیریت کل سیستم «دفتر» خوش آمدید.", adminMainKeyboard());
    await sendTelegramMessage(env, chatId, "برای پنل کامل مدیریت (کاربران، فروشگاه‌ها، اشتراک‌ها) روی دکمه‌ی زیر بزن — در مرورگر گوشی باز می‌شود:", {
      inline_keyboard: [[{ text: "🖥 باز کردن پنل مدیریت کامل", url: env.ADMIN_PANEL_URL || "https://ownerhesabdariap.pages.dev/" }]],
    });
    return new Response("ok");
  }

  if (!payload) {
    await sendTelegramMessage(env, chatId, "سلام 👋\nبرای اتصال، از لینک اختصاصی حساب مشتری یا لینک مدیریت فروشگاه خود استفاده کنید.");
    return new Response("ok");
  }

  if (/^[A-Z0-9]{12}$/.test(payload)) {
    const store = await env.DB.prepare("SELECT * FROM stores WHERE telegram_link_code = ?").bind(payload).first();
    if (store) {
      await env.DB.prepare("UPDATE stores SET telegram_owner_chat_id = ? WHERE id = ?").bind(chatId, store.id).run();
      const url = `${webAppBase}?store=${store.id}`;
      await sendTelegramMessage(env, chatId,
        `✅ اتصال موفق.\nشما اکنون مدیر فروشگاه «${esc4tg(store.name)}» در تلگرام هستید و فیش‌ها/درخواست‌های مشتریان اینجا برایتان ارسال می‌شود.`,
        ownerMainKeyboard(url));
      return new Response("ok");
    }
  }

  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(payload).first();
  if (!customer) { await sendTelegramMessage(env, chatId, "❌ لینک نامعتبر است."); return new Response("ok"); }
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
  await env.DB.prepare("DELETE FROM telegram_links WHERE customer_id = ?").bind(payload).run();
  const telegramName = [msg.from?.first_name, msg.from?.last_name].filter(Boolean).join(" ") || (msg.from?.username ? "@" + msg.from.username : "");
  await env.DB.prepare("INSERT INTO telegram_links (id, customer_id, chat_id, telegram_name, linked_at) VALUES (?, ?, ?, ?, ?)")
    .bind(randId(10), payload, chatId, telegramName, new Date().toISOString()).run();
  const url = `${webAppBase}?customer=${payload}`;
  await sendTelegramMessage(env, chatId,
    `✅ متصل شدید.\nسلام ${esc4tg(customer.name)}، از این پس می‌توانید حساب خود نزد «${esc4tg(store ? store.name : "")}» را همین‌جا مدیریت کنید.`,
    customerMainKeyboard(url));
  return new Response("ok");
}

async function handleCallback(cq, env) {
  const chatId = String(cq.message.chat.id);
  const data = cq.data || "";
  if (data.startsWith("rcpt_ok:") || data.startsWith("rcpt_no:")) {
    await handleReceiptDecision(data, env);
  }
  await answerCallbackQuery(env, cq.id);
}

async function handleReceiptPhoto(chatId, msg, env) {
  const link = await env.DB.prepare("SELECT * FROM telegram_links WHERE chat_id = ?").bind(chatId).first();
  if (!link) return new Response("ok");
  const draft = await env.DB.prepare(
    "SELECT * FROM payment_receipts WHERE customer_id = ? AND status = 'awaiting_photo' ORDER BY created_at DESC LIMIT 1"
  ).bind(link.customer_id).first();
  if (!draft) {
    await sendTelegramMessage(env, chatId, "درخواست پرداخت فعالی برای دریافت فیش یافت نشد. ابتدا از «حساب من» گزینه پرداخت را انتخاب کنید.");
    return new Response("ok");
  }
  const photos = msg.photo;
  const fileId = photos[photos.length - 1].file_id;
  await env.DB.prepare("UPDATE payment_receipts SET photo_file_id = ?, status = 'pending' WHERE id = ?").bind(fileId, draft.id).run();

  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(link.customer_id).first();
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(draft.store_id).first();
  await sendTelegramMessage(env, chatId, "✅ فیش دریافت شد و برای بررسی نزد فروشگاه ارسال شد.");

  if (store && store.telegram_owner_chat_id) {
    const symbol = CURRENCY_SYMBOLS[draft.currency] || draft.currency;
    const caption = `🧾 فیش پرداخت جدید\nمشتری: ${esc4tg(customer.name)}\nمبلغ: ${draft.amount.toLocaleString("fa-IR")} ${symbol}`;
    await sendTelegramPhoto(env, store.telegram_owner_chat_id, fileId, caption, {
      inline_keyboard: [[
        { text: "✅ تایید و ثبت پرداخت", callback_data: `rcpt_ok:${draft.id}` },
        { text: "❌ رد فیش", callback_data: `rcpt_no:${draft.id}` },
      ]],
    });
  }
  return new Response("ok");
}

async function handleReceiptDecision(data, env) {
  const [action, receiptId] = data.split(":");
  const receipt = await env.DB.prepare("SELECT * FROM payment_receipts WHERE id = ?").bind(receiptId).first();
  if (!receipt || receipt.status !== "pending") return;
  const link = await env.DB.prepare("SELECT chat_id FROM telegram_links WHERE customer_id = ?").bind(receipt.customer_id).first();

  if (action === "rcpt_ok") {
    await env.DB.prepare("INSERT INTO transactions (id, customer_id, type, currency, amount, note, created_at) VALUES (?, ?, 'payment', ?, ?, ?, ?)")
      .bind(randId(10), receipt.customer_id, receipt.currency, receipt.amount, "پرداخت از طریق تلگرام", new Date().toISOString()).run();
    await env.DB.prepare("UPDATE payment_receipts SET status = 'approved', resolved_at = ? WHERE id = ?").bind(new Date().toISOString(), receiptId).run();
    if (link) await sendTelegramMessage(env, link.chat_id, "✅ پرداخت شما تایید و در حساب ثبت شد.");
  } else {
    await env.DB.prepare("UPDATE payment_receipts SET status = 'rejected', resolved_at = ? WHERE id = ?").bind(new Date().toISOString(), receiptId).run();
    if (link) await sendTelegramMessage(env, link.chat_id, "❌ فیش شما رد شد. لطفاً دوباره تلاش کنید یا با فروشگاه تماس بگیرید.");
  }
}

async function listPendingReceiptsForOwner(chatId, env) {
  const store = await env.DB.prepare("SELECT * FROM stores WHERE telegram_owner_chat_id = ?").bind(chatId).first();
  if (!store) { await sendTelegramMessage(env, chatId, "شما به هیچ فروشگاهی به‌عنوان مدیر وصل نیستید."); return new Response("ok"); }
  const rows = await env.DB.prepare(
    `SELECT pr.*, c.name as customer_name FROM payment_receipts pr JOIN customers c ON c.id = pr.customer_id
     WHERE pr.store_id = ? AND pr.status = 'pending' ORDER BY pr.created_at DESC LIMIT 10`
  ).bind(store.id).all();
  if (!rows.results.length) { await sendTelegramMessage(env, chatId, "فیش در انتظار بررسی وجود ندارد."); return new Response("ok"); }
  for (const r of rows.results) {
    const symbol = CURRENCY_SYMBOLS[r.currency] || r.currency;
    await sendTelegramPhoto(env, chatId, r.photo_file_id,
      `مشتری: ${esc4tg(r.customer_name)}\nمبلغ: ${r.amount.toLocaleString("fa-IR")} ${symbol}`,
      { inline_keyboard: [[
        { text: "✅ تایید", callback_data: `rcpt_ok:${r.id}` },
        { text: "❌ رد", callback_data: `rcpt_no:${r.id}` },
      ]] });
  }
  return new Response("ok");
}

async function listPendingSettlementsForOwner(chatId, env) {
  const store = await env.DB.prepare("SELECT * FROM stores WHERE telegram_owner_chat_id = ?").bind(chatId).first();
  if (!store) { await sendTelegramMessage(env, chatId, "شما به هیچ فروشگاهی به‌عنوان مدیر وصل نیستید."); return new Response("ok"); }
  const rows = await env.DB.prepare(
    `SELECT sr.*, c.name as customer_name FROM settlement_requests sr JOIN customers c ON c.id = sr.customer_id
     WHERE sr.store_id = ? AND sr.status = 'pending' ORDER BY sr.created_at DESC LIMIT 15`
  ).bind(store.id).all();
  if (!rows.results.length) { await sendTelegramMessage(env, chatId, "درخواست در انتظاری وجود ندارد."); return new Response("ok"); }
  const lines = rows.results.map((r) => {
    if (r.kind === "cash") {
      const symbol = CURRENCY_SYMBOLS[r.currency] || r.currency;
      return `💰 درخواست وجه — ${esc4tg(r.customer_name)} — ${Number(r.amount).toLocaleString("fa-IR")} ${symbol}`;
    }
    return `📋 درخواست تسویه — ${esc4tg(r.customer_name)}`;
  });
  await sendTelegramMessage(env, chatId, "درخواست‌های در انتظار:\n\n" + lines.join("\n") + "\n\nبررسی و تایید نهایی از طریق پنل وب انجام می‌شود.");
  return new Response("ok");
}

async function sendAdminStats(chatId, env) {
  if (!env.SUPER_ADMIN_TELEGRAM_ID || chatId !== String(env.SUPER_ADMIN_TELEGRAM_ID)) return new Response("ok");
  const stores = await env.DB.prepare("SELECT COUNT(*) as c FROM stores").first();
  const customers = await env.DB.prepare("SELECT COUNT(*) as c FROM customers").first();
  const users = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
  await sendTelegramMessage(env, chatId, `📊 آمار کلی سیستم\n\nکاربران: ${users.c}\nفروشگاه‌ها: ${stores.c}\nمشتریان: ${customers.c}`);
  return new Response("ok");
}
async function sendAdminStoreList(chatId, env) {
  if (!env.SUPER_ADMIN_TELEGRAM_ID || chatId !== String(env.SUPER_ADMIN_TELEGRAM_ID)) return new Response("ok");
  const rows = await env.DB.prepare("SELECT id, name, blocked FROM stores ORDER BY created_at DESC LIMIT 20").all();
  const lines = rows.results.map((s) => `${s.blocked ? "🚫" : "🟢"} ${esc4tg(s.name)} (${s.id})`);
  await sendTelegramMessage(env, chatId, "🏪 آخرین فروشگاه‌ها:\n\n" + (lines.join("\n") || "چیزی یافت نشد") + "\n\nمدیریت کامل از طریق پنل وب.");
  return new Response("ok");
}

async function telegramStatus(customerId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const access = await getAccessibleStore(env, user.id, customer.store_id);
  if (!access) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const link = await env.DB.prepare("SELECT telegram_name, linked_at FROM telegram_links WHERE customer_id = ?").bind(customerId).first();
  return json({ linked: !!link, telegramName: link ? link.telegram_name : null, linkedAt: link ? link.linked_at : null }, 200, origin);
}
async function telegramUnlink(customerId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
  if (!store || store.owner_id !== user.id) return json({ error: "فقط مالک فروشگاه می‌تواند اتصال را قطع کند" }, 403, origin);
  await env.DB.prepare("DELETE FROM telegram_links WHERE customer_id = ?").bind(customerId).run();
  return json({ ok: true }, 200, origin);
}

async function publicCustomerBalances(customerId, env, origin) {
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  if (customer.blocked) return json({ error: "شناسه شما مسدود شده است" }, 403, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
  const balAFN = await computeCustomerBalance(env, customerId, "AFN");
  const balIRT = await computeCustomerBalance(env, customerId, "IRT");
  return json({
    customerName: customer.name,
    storeName: store ? store.name : "",
    balances: { AFN: balAFN, IRT: balIRT },
    cards: store ? {
      AFN: { number: store.card_afn_number || null, holder: store.card_afn_holder || null },
      IRT: { number: store.card_irt_number || null, holder: store.card_irt_holder || null },
    } : {},
  }, 200, origin);
}
async function createPaymentReceiptDraftRoute(request, env, origin) {
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const { customerId, currency, amount } = body;
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  if (customer.blocked) return json({ error: "شناسه شما مسدود شده است" }, 403, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
  if (!store || store.blocked) return json({ error: "این فروشگاه توسط مدیر سیستم مسدود شده است" }, 403, origin);
  if (!["AFN", "IRT"].includes(currency) || !amount || Number(amount) <= 0) return json({ error: "اطلاعات نامعتبر است" }, 400, origin);
  const existing = await env.DB.prepare(
    "SELECT id FROM payment_receipts WHERE customer_id = ? AND status IN ('awaiting_photo','pending')"
  ).bind(customerId).first();
  if (existing) return json({ error: "شما یک درخواست پرداخت در حال بررسی دارید" }, 400, origin);
  const id = randId(10);
  await env.DB.prepare("INSERT INTO payment_receipts (id, customer_id, store_id, currency, amount, status, created_at) VALUES (?, ?, ?, ?, ?, 'awaiting_photo', ?)")
    .bind(id, customerId, customer.store_id, currency, Number(amount), new Date().toISOString()).run();
  return json({ ok: true, receiptId: id }, 200, origin);
}
async function createCashRequestRoute(request, env, origin) {
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const { customerId, currency, amount } = body;
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  if (customer.blocked) return json({ error: "شناسه شما مسدود شده است" }, 403, origin);
  if (!["AFN", "IRT"].includes(currency) || !amount || Number(amount) <= 0) return json({ error: "مبلغ نامعتبر است" }, 400, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
  if (!store || store.blocked) return json({ error: "این فروشگاه توسط مدیر سیستم مسدود شده است" }, 403, origin);
  const existing = await env.DB.prepare(
    "SELECT id FROM settlement_requests WHERE customer_id = ? AND status = 'pending' AND kind = 'cash'"
  ).bind(customerId).first();
  if (existing) return json({ error: "شما یک درخواست وجه در حال بررسی دارید" }, 400, origin);
  const id = randId(10);
  await env.DB.prepare("INSERT INTO settlement_requests (id, customer_id, store_id, status, kind, amount, currency, created_at) VALUES (?, ?, ?, 'pending', 'cash', ?, ?, ?)")
    .bind(id, customerId, customer.store_id, Number(amount), currency, new Date().toISOString()).run();
  if (store.telegram_owner_chat_id) {
    const symbol = CURRENCY_SYMBOLS[currency] || currency;
    await sendTelegramMessage(env, store.telegram_owner_chat_id,
      `💰 درخواست وجه جدید\nمشتری: ${esc4tg(customer.name)}\nمبلغ: ${Number(amount).toLocaleString("fa-IR")} ${symbol}`);
  }
  return json({ ok: true }, 200, origin);
}

async function publicStorePanelSummary(storeId, env, origin) {
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(storeId).first();
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  const settlements = await env.DB.prepare(
    `SELECT sr.*, c.name as customer_name FROM settlement_requests sr JOIN customers c ON c.id = sr.customer_id
     WHERE sr.store_id = ? AND sr.status = 'pending' ORDER BY sr.created_at DESC LIMIT 20`
  ).bind(storeId).all();
  const receiptsCount = await env.DB.prepare(
    "SELECT COUNT(*) as c FROM payment_receipts WHERE store_id = ? AND status = 'pending'"
  ).bind(storeId).first();
  return json({
    storeName: store.name,
    telegramConnected: !!store.telegram_owner_chat_id,
    pendingReceiptsCount: receiptsCount.c || 0,
    pendingRequests: settlements.results.map((r) => ({
      customerName: r.customer_name, kind: r.kind || "settlement",
      amount: r.amount, currency: r.currency, date: r.created_at,
    })),
  }, 200, origin);
}

async function updateStoreCards(storeId, request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const store = await getOwnedStore(env, user.id, storeId);
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  await env.DB.prepare("UPDATE stores SET card_afn_number=?, card_afn_holder=?, card_irt_number=?, card_irt_holder=? WHERE id=?")
    .bind((body.cardAfnNumber || "").trim() || null, (body.cardAfnHolder || "").trim() || null,
          (body.cardIrtNumber || "").trim() || null, (body.cardIrtHolder || "").trim() || null, storeId).run();
  return json({ ok: true }, 200, origin);
}
async function getOrCreateStoreTelegramLink(storeId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const store = await getOwnedStore(env, user.id, storeId);
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  let code = store.telegram_link_code;
  if (!code) {
    code = randCode(12);
    await env.DB.prepare("UPDATE stores SET telegram_link_code = ? WHERE id = ?").bind(code, storeId).run();
  }
  return json({ ok: true, code, linked: !!store.telegram_owner_chat_id, botUsername: env.TELEGRAM_BOT_USERNAME || null }, 200, origin);
}

async function disconnectStoreTelegramOwner(storeId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const store = await getOwnedStore(env, user.id, storeId);
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  await env.DB.prepare("UPDATE stores SET telegram_owner_chat_id = NULL WHERE id = ?").bind(storeId).run();
  return json({ ok: true }, 200, origin);
}

async function renameStore(storeId, request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const store = await getOwnedStore(env, user.id, storeId);
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const name = (body.name || "").trim();
  if (!name) return json({ error: "نام فروشگاه نمی‌تواند خالی باشد" }, 400, origin);
  if (name.length > 60) return json({ error: "نام فروشگاه خیلی طولانی است" }, 400, origin);
  await env.DB.prepare("UPDATE stores SET name = ? WHERE id = ?").bind(name, storeId).run();
  return json({ ok: true, name }, 200, origin);
}

async function sendDueDateReminders(env) {
  const today = new Date(); today.setUTCHours(0, 0, 0, 0);
  const in3 = new Date(today.getTime() + 3 * 86400000);
  const rows = await env.DB.prepare(
    `SELECT t.* FROM transactions t WHERE t.type = 'debt' AND t.due_date IS NOT NULL AND t.due_date != ''`
  ).all();
  for (const t of rows.results) {
    const due = new Date(t.due_date);
    if (isNaN(due.getTime())) continue;
    const bal = await computeCustomerBalance(env, t.customer_id, t.currency);
    if (bal <= 0) continue;
    let reminderType = null;
    if (due < today) reminderType = "overdue";
    else if (due <= in3) reminderType = "duesoon";
    if (!reminderType) continue;
    const already = await env.DB.prepare(
      "SELECT id FROM telegram_reminders_sent WHERE transaction_id = ? AND reminder_type = ?"
    ).bind(t.id, reminderType).first();
    if (already) continue;
    const link = await env.DB.prepare("SELECT * FROM telegram_links WHERE customer_id = ?").bind(t.customer_id).first();
    if (!link) continue;
    const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(t.customer_id).first();
    const store = customer ? await env.DB.prepare("SELECT name FROM stores WHERE id = ?").bind(customer.store_id).first() : null;
    const symbol = CURRENCY_SYMBOLS[t.currency] || t.currency;
    const text = reminderType === "overdue"
      ? `⏰ یادآوری: سررسید بدهی شما نزد «${esc4tg(store ? store.name : "")}» گذشته است.\nمبلغ: ${t.amount.toLocaleString("fa-IR")} ${symbol}\nمانده‌ی فعلی: ${bal.toLocaleString("fa-IR")} ${symbol}`
      : `⏰ یادآوری: سررسید بدهی شما نزد «${esc4tg(store ? store.name : "")}» نزدیک است (${t.due_date}).\nمبلغ: ${t.amount.toLocaleString("fa-IR")} ${symbol}`;
    await sendTelegramMessage(env, link.chat_id, text);
    await env.DB.prepare(
      "INSERT INTO telegram_reminders_sent (id, transaction_id, reminder_type, sent_at) VALUES (?, ?, ?, ?)"
    ).bind(randId(10), t.id, reminderType, new Date().toISOString()).run();
  }
}

async function getOwnedStore(env, userId, storeId) {
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(storeId).first();
  if (!store || store.owner_id !== userId) return null;
  return store;
}
async function getAccessibleStore(env, userId, storeId) {
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(storeId).first();
  if (!store) return null;
  if (store.owner_id === userId) return { store, role: "owner" };
  const staff = await env.DB.prepare("SELECT id FROM store_staff WHERE store_id = ? AND user_id = ?").bind(storeId, userId).first();
  if (staff) return { store, role: "staff" };
  return null;
}

async function listMyStores(user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const ownedRes = await env.DB.prepare("SELECT * FROM stores WHERE owner_id = ? ORDER BY created_at ASC").bind(user.id).all();
  const staffRes = await env.DB.prepare(
    `SELECT s.* FROM stores s JOIN store_staff ss ON ss.store_id = s.id WHERE ss.user_id = ? ORDER BY ss.created_at ASC`
  ).bind(user.id).all();
  const roleByStore = {};
  ownedRes.results.forEach((s) => { roleByStore[s.id] = "owner"; });
  staffRes.results.forEach((s) => { if (!roleByStore[s.id]) roleByStore[s.id] = "staff"; });
  const stores = [...ownedRes.results, ...staffRes.results.filter((s) => !ownedRes.results.some((o) => o.id === s.id))];
  if (!stores.length) return json({ stores: [] }, 200, origin);

  const ids = stores.map((s) => s.id);
  const placeholders = ids.map(() => "?").join(",");
  const custRows = await env.DB.prepare(`SELECT store_id, COUNT(*) as cnt FROM customers WHERE store_id IN (${placeholders}) GROUP BY store_id`).bind(...ids).all();
  const custCountByStore = {};
  custRows.results.forEach((r) => { custCountByStore[r.store_id] = r.cnt; });

  const txRows = await env.DB.prepare(
    `SELECT c.store_id as store_id, t.currency, t.type, SUM(t.amount) as total
     FROM transactions t JOIN customers c ON t.customer_id = c.id WHERE c.store_id IN (${placeholders}) GROUP BY c.store_id, t.currency, t.type`
  ).bind(...ids).all();
  const balByStore = {};
  txRows.results.forEach((r) => {
    balByStore[r.store_id] ||= {};
    balByStore[r.store_id][r.currency] = (balByStore[r.store_id][r.currency] || 0) + (r.type === "debt" ? r.total : -r.total);
  });

  const out = stores.map((s) => ({
    id: s.id, name: s.name, storeUsername: s.store_username, blocked: !!s.blocked, photo: s.photo || null,
    address: s.address || null, phone: s.phone || null, hours: s.hours || null,
    cardAfnNumber: s.card_afn_number || null, cardAfnHolder: s.card_afn_holder || null,
    cardIrtNumber: s.card_irt_number || null, cardIrtHolder: s.card_irt_holder || null,
    telegramLinked: !!s.telegram_owner_chat_id,
    role: roleByStore[s.id], customerCount: custCountByStore[s.id] || 0, balances: balByStore[s.id] || {},
  }));
  return json({ stores: out }, 200, origin);
}

async function createStore(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const countRow = await env.DB.prepare("SELECT COUNT(*) as c FROM stores WHERE owner_id = ?").bind(user.id).first();
  const isAdmin = user.role === "admin";
  const storeLimit = user.store_limit != null ? user.store_limit : 1;
  if (!isAdmin && countRow.c >= storeLimit) {
    return json({ error: `شما به سقف مجاز فروشگاه (${storeLimit} فروشگاه) رسیده‌اید. برای افزایش سقف با مدیر سیستم تماس بگیرید.` }, 403, origin);
  }

  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const name = (body.name || "").trim();
  const storeUsername = (body.storeUsername || "").trim();
  if (!name || !storeUsername) return json({ error: "نام فروشگاه و نام کاربری الزامی است" }, 400, origin);

  const taken = await env.DB.prepare("SELECT id FROM stores WHERE store_username = ?").bind(storeUsername).first();
  if (taken) return json({ error: "این نام کاربری فروشگاه قبلا استفاده شده است" }, 400, origin);

  const id = randCode(7);
  const now = new Date().toISOString();
  await env.DB.prepare("INSERT INTO stores (id, owner_id, name, store_username, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(id, user.id, name, storeUsername, now).run();

  return json({ ok: true, store: { id, name, storeUsername, blocked: false, photo: null, customerCount: 0, balances: {} } }, 200, origin);
}

async function updateStorePhoto(storeId, request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const store = await getOwnedStore(env, user.id, storeId);
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const photo = (body.photoBase64 || "").trim();
  if (photo && photo.length > 400000) return json({ error: "حجم عکس زیاد است" }, 400, origin);
  await env.DB.prepare("UPDATE stores SET photo = ? WHERE id = ?").bind(photo || null, storeId).run();
  return json({ ok: true, photo: photo || null }, 200, origin);
}

async function updateStoreInfo(storeId, request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const store = await getOwnedStore(env, user.id, storeId);
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  await env.DB.prepare("UPDATE stores SET address = ?, phone = ?, hours = ? WHERE id = ?")
    .bind((body.address || "").trim() || null, (body.phone || "").trim() || null, (body.hours || "").trim() || null, storeId).run();
  return json({ ok: true }, 200, origin);
}

async function createStaffInvite(storeId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const store = await getOwnedStore(env, user.id, storeId);
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  if (user.role !== "admin" && user.staff_limit != null) {
    const ownedIds = await env.DB.prepare("SELECT id FROM stores WHERE owner_id = ?").bind(user.id).all();
    const ids = ownedIds.results.map((s) => s.id);
    const placeholders = ids.map(() => "?").join(",");
    const cnt = ids.length ? await env.DB.prepare(`SELECT COUNT(*) as c FROM store_staff WHERE store_id IN (${placeholders})`).bind(...ids).first() : { c: 0 };
    if (cnt.c >= user.staff_limit) {
      return json({ error: `سقف مجاز تعداد کارمند (${user.staff_limit} نفر) پر شده است. برای افزایش سقف، اشتراک خود را ارتقا دهید.` }, 403, origin);
    }
  }
  const code = randCode(6);
  await env.DB.prepare("INSERT INTO staff_invites (code, store_id, used, created_at) VALUES (?, ?, 0, ?)")
    .bind(code, storeId, new Date().toISOString()).run();
  return json({ ok: true, code }, 200, origin);
}

async function joinStoreAsStaff(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const code = (body.code || "").trim().toUpperCase();
  if (!code) return json({ error: "کد دعوت الزامی است" }, 400, origin);
  const invite = await env.DB.prepare("SELECT * FROM staff_invites WHERE code = ?").bind(code).first();
  if (!invite || invite.used) return json({ error: "کد دعوت نامعتبر یا استفاده‌شده است" }, 404, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(invite.store_id).first();
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  if (store.owner_id === user.id) return json({ error: "شما مالک این فروشگاه هستید" }, 400, origin);
  const existing = await env.DB.prepare("SELECT id FROM store_staff WHERE store_id = ? AND user_id = ?").bind(invite.store_id, user.id).first();
  if (!existing) {
    await env.DB.prepare("INSERT INTO store_staff (id, store_id, user_id, created_at) VALUES (?, ?, ?, ?)")
      .bind(randId(10), invite.store_id, user.id, new Date().toISOString()).run();
  }
  await env.DB.prepare("UPDATE staff_invites SET used = 1 WHERE code = ?").bind(code).run();
  return json({ ok: true, storeId: invite.store_id, storeName: store.name }, 200, origin);
}

async function listStaff(storeId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const store = await getOwnedStore(env, user.id, storeId);
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  const rows = await env.DB.prepare(
    `SELECT ss.id as staff_id, ss.user_id, ss.created_at, u.first_name, u.last_name, u.username FROM store_staff ss JOIN users u ON u.id = ss.user_id WHERE ss.store_id = ? ORDER BY ss.created_at ASC`
  ).bind(storeId).all();
  return json({
    staff: rows.results.map((r) => ({ id: r.staff_id, userId: r.user_id, name: `${r.first_name} ${r.last_name}`, username: r.username, joinedAt: r.created_at })),
  }, 200, origin);
}

async function removeStaff(storeId, staffId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const store = await getOwnedStore(env, user.id, storeId);
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  await env.DB.prepare("DELETE FROM store_staff WHERE id = ? AND store_id = ?").bind(staffId, storeId).run();
  return json({ ok: true }, 200, origin);
}

async function listCustomers(user, env, origin, storeId) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  if (!storeId) return json({ error: "شناسه فروشگاه الزامی است" }, 400, origin);
  const access = await getAccessibleStore(env, user.id, storeId);
  if (!access) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  const store = access.store;
  if (access.role === "owner") { try { await generateDueRecurring(store.id, env); } catch {} }

  const customers = await env.DB.prepare("SELECT * FROM customers WHERE store_id = ? ORDER BY created_at DESC").bind(store.id).all();
  const txs = await env.DB.prepare(
    `SELECT t.* FROM transactions t JOIN customers c ON t.customer_id = c.id WHERE c.store_id = ?`
  ).bind(store.id).all();

  const byCustomer = {};
  for (const t of txs.results) {
    (byCustomer[t.customer_id] ||= []).push({ id: t.id, type: t.type, currency: t.currency, amount: t.amount, note: t.note, date: t.created_at, dueDate: t.due_date, category: t.category, receiptPhoto: t.receipt_photo });
  }
  const result = customers.results.map((c) => ({
    id: c.id, name: c.name, nationalId: c.national_id, phone: c.phone, phoneCountry: c.phone_country,
    province: c.province, district: c.district, village: c.village, blocked: !!c.blocked,
    viewCount: c.view_count || 0, lastViewedAt: c.last_viewed_at, hasNote: !!c.private_note,
    transactions: byCustomer[c.id] || [],
  }));
  return json({ customers: result, myRole: access.role }, 200, origin);
}

async function createCustomer(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const storeId = (body.storeId || "").trim();
  if (!storeId) return json({ error: "شناسه فروشگاه الزامی است" }, 400, origin);
  const access = await getAccessibleStore(env, user.id, storeId);
  if (!access) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  const store = access.store;
  if (store.blocked) return json({ error: "این فروشگاه توسط مدیر سیستم مسدود شده است" }, 403, origin);

  const name = (body.name || "").trim();
  if (!name) return json({ error: "نام مشتری الزامی است" }, 400, origin);

  const owner = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(store.owner_id).first();
  if (owner && owner.role !== "admin" && owner.customer_limit != null) {
    const cnt = await env.DB.prepare("SELECT COUNT(*) as c FROM customers WHERE store_id = ?").bind(store.id).first();
    if (cnt.c >= owner.customer_limit) {
      return json({ error: `سقف مجاز تعداد مشتری (${owner.customer_limit} مشتری) برای این فروشگاه پر شده است.` }, 403, origin);
    }
  }

  const id = randId(10);
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO customers (id, store_id, name, national_id, phone, phone_country, province, district, village, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, store.id, name, body.nationalId || null, body.phone || null, body.phoneCountry || null, body.province || null, body.district || null, body.village || null, now).run();

  return json({
    ok: true,
    customer: { id, name, nationalId: body.nationalId, phone: body.phone, phoneCountry: body.phoneCountry, province: body.province, district: body.district, village: body.village, blocked: false, transactions: [] },
  }, 200, origin);
}

async function customerDetail(customerId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();

  const isOwner = store && store.owner_id === user.id;
  let isStaff = false;
  let isLinked = false;
  if (!isOwner) {
    const staff = await env.DB.prepare("SELECT id FROM store_staff WHERE store_id = ? AND user_id = ?").bind(customer.store_id, user.id).first();
    isStaff = !!staff;
  }
  if (!isOwner && !isStaff) {
    const link = await env.DB.prepare("SELECT id FROM store_links WHERE user_id = ? AND customer_id = ?").bind(user.id, customerId).first();
    isLinked = !!link;
  }
  if (!isOwner && !isStaff && !isLinked) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  if (!isOwner && isLinked && customer.blocked) {
    return json({ error: "شناسه شما نزد این فروشگاه مسدود شده است. لطفا با صاحب فروشگاه ارتباط بگیرید." }, 403, origin);
  }

  const txs = await env.DB.prepare("SELECT * FROM transactions WHERE customer_id = ? ORDER BY created_at ASC").bind(customerId).all();
  return json({
    customer: {
      id: customer.id, name: customer.name, nationalId: customer.national_id,
      phone: customer.phone, phoneCountry: customer.phone_country,
      province: customer.province, district: customer.district, village: customer.village, blocked: !!customer.blocked,
      hasNote: !!customer.private_note,
      transactions: txs.results.map((t) => ({ id: t.id, type: t.type, currency: t.currency, amount: t.amount, note: t.note, date: t.created_at, dueDate: t.due_date, category: t.category, receiptPhoto: t.receipt_photo })),
    },
    store: { id: store.id, name: store.name },
    canEdit: isOwner,
    canAdd: isOwner || isStaff,
  }, 200, origin);
}

async function updateCustomer(customerId, request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
  if (!store || store.owner_id !== user.id) return json({ error: "فقط مالک فروشگاه می‌تواند اطلاعات مشتری را ویرایش کند" }, 403, origin);

  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const name = (body.name || "").trim();
  if (!name) return json({ error: "نام مشتری الزامی است" }, 400, origin);

  await env.DB.prepare(
    `UPDATE customers SET name = ?, national_id = ?, phone = ?, phone_country = ?, province = ?, district = ?, village = ? WHERE id = ?`
  ).bind(name, body.nationalId || null, body.phone || null, body.phoneCountry || null, body.province || null, body.district || null, body.village || null, customerId).run();

  return json({
    ok: true,
    customer: { id: customerId, name, nationalId: body.nationalId, phone: body.phone, phoneCountry: body.phoneCountry, province: body.province, district: body.district, village: body.village, blocked: !!customer.blocked },
  }, 200, origin);
}

async function updateCustomerNote(customerId, request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const access = await getAccessibleStore(env, user.id, customer.store_id);
  if (!access) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const note = (body.note || "").slice(0, 2000);
  await env.DB.prepare("UPDATE customers SET private_note = ? WHERE id = ?").bind(note || null, customerId).run();
  return json({ ok: true, note }, 200, origin);
}

async function revealCustomerNote(customerId, request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const access = await getAccessibleStore(env, user.id, customer.store_id);
  if (!access) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  if (!(await isElevated(request, env))) {
    return json({ error: "برای مشاهده یادداشت خصوصی، هویت خود را تایید کنید", needsElevation: true }, 428, origin);
  }
  return json({ note: customer.private_note || "" }, 200, origin);
}

async function toggleCustomerBlock(customerId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
  if (!store || store.owner_id !== user.id) return json({ error: "فقط مالک فروشگاه می‌تواند مشتری را مسدود کند" }, 403, origin);
  const newBlocked = customer.blocked ? 0 : 1;
  await env.DB.prepare("UPDATE customers SET blocked = ? WHERE id = ?").bind(newBlocked, customerId).run();
  return json({ ok: true, blocked: !!newBlocked }, 200, origin);
}

async function deleteCustomer(customerId, request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
  if (!store || store.owner_id !== user.id) return json({ error: "فقط مالک فروشگاه می‌تواند مشتری را حذف کند" }, 403, origin);
  if (!(await isElevated(request, env))) {
    return json({ error: "برای حذف مشتری، هویت خود را تایید کنید", needsElevation: true }, 428, origin);
  }
  await env.DB.prepare("DELETE FROM transactions WHERE customer_id = ?").bind(customerId).run();
  await env.DB.prepare("DELETE FROM store_links WHERE customer_id = ?").bind(customerId).run();
  await env.DB.prepare("DELETE FROM customers WHERE id = ?").bind(customerId).run();
  return json({ ok: true }, 200, origin);
}

async function addTransaction(customerId, request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const access = await getAccessibleStore(env, user.id, customer.store_id);
  if (!access) return json({ error: "فقط مالک یا کارمند فروشگاه می‌تواند تراکنش ثبت کند" }, 403, origin);
  const store = access.store;
  if (store.blocked) return json({ error: "این فروشگاه توسط مدیر سیستم مسدود شده است" }, 403, origin);

  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const { type, currency, amount, note, dueDate, category, receiptPhoto } = body;
  if (!["debt", "payment"].includes(type)) return json({ error: "نوع تراکنش نامعتبر است" }, 400, origin);
  if (!currency || !amount || Number(amount) <= 0) return json({ error: "مبلغ نامعتبر است" }, 400, origin);
  if (receiptPhoto && receiptPhoto.length > 400000) return json({ error: "حجم عکس رسید زیاد است" }, 400, origin);

  const owner = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(store.owner_id).first();
  if (owner && owner.role !== "admin" && owner.transaction_limit != null) {
    const cnt = await env.DB.prepare("SELECT COUNT(*) as c FROM transactions WHERE customer_id = ?").bind(customerId).first();
    if (cnt.c >= owner.transaction_limit) {
      return json({ error: `سقف مجاز تعداد تراکنش (${owner.transaction_limit} تراکنش) برای این مشتری پر شده است.` }, 403, origin);
    }
  }

  const id = randId(10);
  const now = new Date().toISOString();
  await env.DB.prepare("INSERT INTO transactions (id, customer_id, type, currency, amount, note, due_date, category, receipt_photo, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(id, customerId, type, currency, Number(amount), note || null, (type === "debt" && dueDate) ? dueDate : null, category || null, receiptPhoto || null, now).run();

  try { await notifyTelegramTransaction(env, customer, store, type, currency, Number(amount), note, (type === "debt" ? dueDate : null)); } catch {}

  return json({ ok: true, transaction: { id, type, currency, amount: Number(amount), note, dueDate: (type === "debt" ? dueDate : null) || null, category: category || null, receiptPhoto: receiptPhoto || null, date: now } }, 200, origin);
}

async function updateTransaction(customerId, txId, request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
  if (!store || store.owner_id !== user.id) return json({ error: "فقط مالک فروشگاه می‌تواند تراکنش را ویرایش کند" }, 403, origin);

  const tx = await env.DB.prepare("SELECT * FROM transactions WHERE id = ? AND customer_id = ?").bind(txId, customerId).first();
  if (!tx) return json({ error: "تراکنش یافت نشد" }, 404, origin);

  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const { type, currency, amount, note, dueDate, category, receiptPhoto } = body;
  if (!["debt", "payment"].includes(type)) return json({ error: "نوع تراکنش نامعتبر است" }, 400, origin);
  if (!currency || !amount || Number(amount) <= 0) return json({ error: "مبلغ نامعتبر است" }, 400, origin);
  if (receiptPhoto && receiptPhoto.length > 400000) return json({ error: "حجم عکس رسید زیاد است" }, 400, origin);

  await env.DB.prepare("UPDATE transactions SET type = ?, currency = ?, amount = ?, note = ?, due_date = ?, category = ?, receipt_photo = ? WHERE id = ?")
    .bind(type, currency, Number(amount), note || null, (type === "debt" && dueDate) ? dueDate : null, category || null, receiptPhoto || null, txId).run();

  return json({ ok: true, transaction: { id: txId, type, currency, amount: Number(amount), note, dueDate: (type === "debt" ? dueDate : null) || null, category: category || null, receiptPhoto: receiptPhoto || null, date: tx.created_at } }, 200, origin);
}

async function deleteTransaction(customerId, txId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
  if (!store || store.owner_id !== user.id) return json({ error: "فقط مالک فروشگاه می‌تواند تراکنش را حذف کند" }, 403, origin);
  const tx = await env.DB.prepare("SELECT id FROM transactions WHERE id = ? AND customer_id = ?").bind(txId, customerId).first();
  if (!tx) return json({ error: "تراکنش یافت نشد" }, 404, origin);
  await env.DB.prepare("DELETE FROM transactions WHERE id = ?").bind(txId).run();
  return json({ ok: true }, 200, origin);
}

async function listLinks(user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const links = await env.DB.prepare(
    `SELECT l.id as link_id, l.profile_json as profile_json, c.id as customer_id, c.name as customer_name, s.id as store_id, s.name as store_name
     FROM store_links l JOIN customers c ON l.customer_id = c.id JOIN stores s ON c.store_id = s.id WHERE l.user_id = ?`
  ).bind(user.id).all();

  const customerIds = links.results.map((l) => l.customer_id);
  let txByCustomer = {};
  if (customerIds.length) {
    const placeholders = customerIds.map(() => "?").join(",");
    const txs = await env.DB.prepare(`SELECT * FROM transactions WHERE customer_id IN (${placeholders})`).bind(...customerIds).all();
    for (const t of txs.results) {
      (txByCustomer[t.customer_id] ||= []).push({ id: t.id, type: t.type, currency: t.currency, amount: t.amount, note: t.note, date: t.created_at });
    }
  }
  const result = links.results.map((l) => {
    let profile = null;
    if (l.profile_json) { try { profile = JSON.parse(l.profile_json); } catch {} }
    return {
      linkId: l.link_id,
      profile,
      customer: { id: l.customer_id, name: l.customer_name, transactions: txByCustomer[l.customer_id] || [] },
      store: { id: l.store_id, name: l.store_name },
    };
  });
  return json({ links: result }, 200, origin);
}

async function createLink(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const customerId = (body.customerId || "").trim();
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  if (customer.blocked) return json({ error: "شناسه شما نزد این فروشگاه مسدود شده است. لطفا با صاحب فروشگاه ارتباط بگیرید." }, 403, origin);

  const existing = await env.DB.prepare("SELECT id FROM store_links WHERE user_id = ? AND customer_id = ?").bind(user.id, customerId).first();
  if (existing) return json({ ok: true, alreadyLinked: true }, 200, origin);

  const id = randId(10);
  const now = new Date().toISOString();
  await env.DB.prepare("INSERT INTO store_links (id, user_id, customer_id, created_at) VALUES (?, ?, ?, ?)").bind(id, user.id, customerId, now).run();
  return json({ ok: true }, 200, origin);
}

async function lookupLink(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const customerId = (body.customerId || "").trim();
  if (!customerId) return json({ error: "شناسه را وارد کنید" }, 400, origin);

  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری‌ای با این شناسه یافت نشد" }, 404, origin);
  if (customer.blocked) return json({ error: "شناسه شما نزد این فروشگاه مسدود شده است. لطفا با صاحب فروشگاه ارتباط بگیرید." }, 403, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
  const owner = store ? await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(store.owner_id).first() : null;

  return json({
    customer: { id: customer.id, name: customer.name },
    store: store ? { id: store.id, name: store.name } : null,
    owner: owner ? { firstName: owner.first_name, lastName: owner.last_name } : null,
  }, 200, origin);
}

async function deleteLink(linkId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const link = await env.DB.prepare("SELECT * FROM store_links WHERE id = ? AND user_id = ?").bind(linkId, user.id).first();
  if (!link) return json({ error: "یافت نشد" }, 404, origin);
  await env.DB.prepare("DELETE FROM store_links WHERE id = ?").bind(linkId).run();
  return json({ ok: true }, 200, origin);
}

async function updateLinkProfile(linkId, request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const link = await env.DB.prepare("SELECT * FROM store_links WHERE id = ? AND user_id = ?").bind(linkId, user.id).first();
  if (!link) return json({ error: "یافت نشد" }, 404, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const profile = {
    firstName: (body.firstName || "").trim(),
    lastName: (body.lastName || "").trim(),
    province: (body.province || "").trim(),
    district: (body.district || "").trim(),
    device: (body.device || "").trim(),
  };
  await env.DB.prepare("UPDATE store_links SET profile_json = ? WHERE id = ?").bind(JSON.stringify(profile), linkId).run();
  return json({ ok: true, profile }, 200, origin);
}

async function customerSelfProfile(customerId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
  if (!store || store.owner_id !== user.id) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const link = await env.DB.prepare("SELECT * FROM store_links WHERE customer_id = ? ORDER BY created_at DESC LIMIT 1").bind(customerId).first();
  let profile = null;
  if (link && link.profile_json) { try { profile = JSON.parse(link.profile_json); } catch {} }
  return json({ profile, hasLinkedAccount: !!link }, 200, origin);
}

async function joinedCustomers(storeId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const store = await getOwnedStore(env, user.id, storeId);
  if (!store) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const rows = await env.DB.prepare(
    `SELECT l.created_at as joined_at, l.profile_json as profile_json, c.name as customer_name
     FROM store_links l JOIN customers c ON l.customer_id = c.id
     WHERE c.store_id = ? ORDER BY l.created_at DESC`
  ).bind(storeId).all();
  return json({
    joined: rows.results.map((r) => {
      let profile = null;
      if (r.profile_json) { try { profile = JSON.parse(r.profile_json); } catch {} }
      return { joinedAt: r.joined_at, customerName: r.customer_name, profile };
    }),
  }, 200, origin);
}

async function globalSearchCustomers(user, env, origin, q) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  if (!q || q.trim().length < 2) return json({ results: [] }, 200, origin);
  const query = "%" + q.trim() + "%";
  const owned = await env.DB.prepare("SELECT id FROM stores WHERE owner_id = ?").bind(user.id).all();
  const staffed = await env.DB.prepare("SELECT store_id FROM store_staff WHERE user_id = ?").bind(user.id).all();
  const storeIds = [...new Set([...owned.results.map((s) => s.id), ...staffed.results.map((s) => s.store_id)])];
  if (!storeIds.length) return json({ results: [] }, 200, origin);
  const placeholders = storeIds.map(() => "?").join(",");
  const rows = await env.DB.prepare(
    `SELECT c.*, s.name as store_name FROM customers c JOIN stores s ON s.id = c.store_id
     WHERE c.store_id IN (${placeholders}) AND (c.name LIKE ? OR c.id LIKE ? OR c.phone LIKE ?) LIMIT 30`
  ).bind(...storeIds, query, query, query).all();
  return json({
    results: rows.results.map((c) => ({
      id: c.id, name: c.name, phone: c.phone, province: c.province, blocked: !!c.blocked,
      storeId: c.store_id, storeName: c.store_name,
    })),
  }, 200, origin);
}

async function publicCustomerView(customerId, env, origin) {
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "حسابی با این شناسه یافت نشد" }, 404, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);

  if (customer.blocked) {
    return json({ error: "شناسه شما نزد این فروشگاه مسدود شده است. لطفا با صاحب فروشگاه ارتباط بگیرید." }, 403, origin);
  }

  await env.DB.prepare("UPDATE customers SET view_count = COALESCE(view_count, 0) + 1, last_viewed_at = ? WHERE id = ?")
    .bind(new Date().toISOString(), customerId).run();

  const txs = await env.DB.prepare("SELECT * FROM transactions WHERE customer_id = ? ORDER BY created_at ASC").bind(customerId).all();
  return json({
    customer: {
      id: customer.id, name: customer.name, province: customer.province, district: customer.district,
      transactions: txs.results.map((t) => ({ id: t.id, type: t.type, currency: t.currency, amount: t.amount, note: t.note, date: t.created_at, category: t.category })),
    },
    store: { id: store.id, name: store.name, photo: store.photo || null, address: store.address || null, phone: store.phone || null, hours: store.hours || null },
  }, 200, origin);
}

async function createSettlementRequest(customerId, env, origin) {
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  if (customer.blocked) return json({ error: "شناسه شما مسدود شده است" }, 403, origin);
  const existing = await env.DB.prepare("SELECT id FROM settlement_requests WHERE customer_id = ? AND status = 'pending'").bind(customerId).first();
  if (existing) return json({ error: "شما پیش‌تر یک درخواست تسویه ارسال کرده‌اید که هنوز بررسی نشده است" }, 400, origin);
  const id = randId(10);
  const now = new Date().toISOString();
  await env.DB.prepare("INSERT INTO settlement_requests (id, customer_id, store_id, status, created_at) VALUES (?, ?, ?, 'pending', ?)")
    .bind(id, customerId, customer.store_id, now).run();
  try {
    const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(customer.store_id).first();
    if (store && store.telegram_owner_chat_id) {
      await sendTelegramMessage(env, store.telegram_owner_chat_id, `📋 درخواست تسویه جدید\nمشتری: ${esc4tg(customer.name)}`);
    }
  } catch {}
  return json({ ok: true }, 200, origin);
}

async function listSettlementRequests(storeId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const access = await getAccessibleStore(env, user.id, storeId);
  if (!access) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  const rows = await env.DB.prepare(
    `SELECT sr.*, c.name as customer_name FROM settlement_requests sr JOIN customers c ON c.id = sr.customer_id
     WHERE sr.store_id = ? AND sr.status = 'pending' ORDER BY sr.created_at DESC`
  ).bind(storeId).all();
  return json({
    requests: rows.results.map((r) => ({ id: r.id, customerId: r.customer_id, customerName: r.customer_name, kind: r.kind || "settlement", amount: r.amount, currency: r.currency, date: r.created_at })),
  }, 200, origin);
}

async function resolveSettlementRequest(requestId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const reqRow = await env.DB.prepare("SELECT * FROM settlement_requests WHERE id = ?").bind(requestId).first();
  if (!reqRow) return json({ error: "درخواست یافت نشد" }, 404, origin);
  const access = await getAccessibleStore(env, user.id, reqRow.store_id);
  if (!access) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  await env.DB.prepare("UPDATE settlement_requests SET status = 'resolved', resolved_at = ? WHERE id = ?")
    .bind(new Date().toISOString(), requestId).run();
  return json({ ok: true }, 200, origin);
}

async function generateDueRecurring(storeId, env) {
  const rows = await env.DB.prepare(
    `SELECT rt.* FROM recurring_transactions rt JOIN customers c ON c.id = rt.customer_id
     WHERE c.store_id = ? AND rt.active = 1`
  ).bind(storeId).all();
  const now = new Date();
  const curKey = `${now.getFullYear()}-${now.getMonth() + 1}`;
  for (const rt of rows.results) {
    const lastKey = rt.last_generated ? rt.last_generated.slice(0, 7).replace(/^(\d{4})-0?(\d{1,2})$/, (m, y, mo) => `${y}-${Number(mo)}`) : null;
    if (lastKey === curKey) continue;
    if (now.getDate() < rt.day_of_month) continue;
    const id = randId(10);
    const nowIso = now.toISOString();
    await env.DB.prepare("INSERT INTO transactions (id, customer_id, type, currency, amount, note, category, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(id, rt.customer_id, rt.type, rt.currency, rt.amount, rt.note, rt.category, nowIso).run();
    await env.DB.prepare("UPDATE recurring_transactions SET last_generated = ? WHERE id = ?").bind(curKey, rt.id).run();
    try {
      const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(rt.customer_id).first();
      const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(storeId).first();
      if (customer && store) await notifyTelegramTransaction(env, customer, store, rt.type, rt.currency, rt.amount, rt.note || "تراکنش تکرارشونده ماهانه", null);
    } catch {}
  }
}
async function createRecurring(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const customerId = (body.customerId || "").trim();
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const store = await getOwnedStore(env, user.id, customer.store_id);
  if (!store) return json({ error: "فقط مالک فروشگاه می‌تواند تراکنش تکرارشونده بسازد" }, 403, origin);

  const { type, currency, amount, note, category, dayOfMonth } = body;
  if (!["debt", "payment"].includes(type)) return json({ error: "نوع تراکنش نامعتبر است" }, 400, origin);
  if (!currency || !amount || Number(amount) <= 0) return json({ error: "مبلغ نامعتبر است" }, 400, origin);
  const day = Math.min(28, Math.max(1, Number(dayOfMonth) || 1));

  const id = randId(10);
  const now = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO recurring_transactions (id, customer_id, type, currency, amount, note, category, day_of_month, active, last_generated, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, ?)"
  ).bind(id, customerId, type, currency, Number(amount), note || null, category || null, day, now).run();

  return json({ ok: true, recurring: { id, type, currency, amount: Number(amount), note, category, dayOfMonth: day } }, 200, origin);
}
async function listRecurring(customerId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(customerId).first();
  if (!customer) return json({ error: "مشتری یافت نشد" }, 404, origin);
  const access = await getAccessibleStore(env, user.id, customer.store_id);
  if (!access) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const rows = await env.DB.prepare("SELECT * FROM recurring_transactions WHERE customer_id = ? ORDER BY created_at DESC").bind(customerId).all();
  return json({
    recurring: rows.results.map((r) => ({ id: r.id, type: r.type, currency: r.currency, amount: r.amount, note: r.note, category: r.category, dayOfMonth: r.day_of_month, active: !!r.active })),
  }, 200, origin);
}
async function deleteRecurring(recId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const rec = await env.DB.prepare("SELECT * FROM recurring_transactions WHERE id = ?").bind(recId).first();
  if (!rec) return json({ error: "یافت نشد" }, 404, origin);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?").bind(rec.customer_id).first();
  const store = customer ? await getOwnedStore(env, user.id, customer.store_id) : null;
  if (!store) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  await env.DB.prepare("DELETE FROM recurring_transactions WHERE id = ?").bind(recId).run();
  return json({ ok: true }, 200, origin);
}

async function exportStoreBackup(storeId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const store = await getOwnedStore(env, user.id, storeId);
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  const customers = await env.DB.prepare("SELECT * FROM customers WHERE store_id = ?").bind(storeId).all();
  const txs = await env.DB.prepare(
    `SELECT t.* FROM transactions t JOIN customers c ON t.customer_id = c.id WHERE c.store_id = ?`
  ).bind(storeId).all();
  const byCustomer = {};
  for (const t of txs.results) (byCustomer[t.customer_id] ||= []).push(t);
  return json({
    exportedAt: new Date().toISOString(),
    store: { id: store.id, name: store.name, storeUsername: store.store_username, address: store.address, phone: store.phone, hours: store.hours },
    customers: customers.results.map((c) => ({
      id: c.id, name: c.name, nationalId: c.national_id, phone: c.phone, province: c.province, district: c.district, village: c.village,
      transactions: (byCustomer[c.id] || []).map((t) => ({ type: t.type, currency: t.currency, amount: t.amount, note: t.note, date: t.created_at, category: t.category, dueDate: t.due_date })),
    })),
  }, 200, origin);
}

async function lookupStoreByUsername(request, env, origin) {
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const code = (body.storeUsername || "").trim();
  if (!code) return json({ error: "شناسه فروشگاه را وارد کنید" }, 400, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE store_username = ? OR id = ?").bind(code, code).first();
  if (!store) return json({ error: "فروشگاهی با این شناسه یافت نشد" }, 404, origin);
  const owner = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(store.owner_id).first();
  return json({ store: { id: store.id, name: store.name, storeUsername: store.store_username }, owner: owner ? { firstName: owner.first_name, lastName: owner.last_name } : null }, 200, origin);
}

async function createJoinRequest(request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const storeId = (body.storeId || "").trim();
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(storeId).first();
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);

  const existing = await env.DB.prepare("SELECT * FROM join_requests WHERE store_id = ? AND requester_user_id = ? AND status = 'pending'")
    .bind(storeId, user.id).first();
  if (existing) return json({ ok: true, alreadyPending: true }, 200, origin);

  const id = randId(10);
  const now = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO join_requests (id, store_id, requester_user_id, requester_name, status, reason, created_at, resolved_at) VALUES (?, ?, ?, ?, 'pending', NULL, ?, NULL)"
  ).bind(id, storeId, user.id, `${user.first_name} ${user.last_name}`, now).run();

  return json({ ok: true }, 200, origin);
}

async function myJoinRequests(user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const rows = await env.DB.prepare(
    `SELECT jr.*, s.name as store_name FROM join_requests jr JOIN stores s ON jr.store_id = s.id WHERE jr.requester_user_id = ? ORDER BY jr.created_at DESC`
  ).bind(user.id).all();
  return json({
    requests: rows.results.map((r) => ({ id: r.id, storeName: r.store_name, status: r.status, reason: r.reason, createdAt: r.created_at, resolvedAt: r.resolved_at })),
  }, 200, origin);
}

async function storeJoinRequests(storeId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const store = await getOwnedStore(env, user.id, storeId);
  if (!store) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const rows = await env.DB.prepare("SELECT * FROM join_requests WHERE store_id = ? AND status = 'pending' ORDER BY created_at ASC").bind(storeId).all();
  return json({ requests: rows.results.map((r) => ({ id: r.id, requesterName: r.requester_name, createdAt: r.created_at })) }, 200, origin);
}

async function approveJoinRequest(requestId, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const jr = await env.DB.prepare("SELECT * FROM join_requests WHERE id = ?").bind(requestId).first();
  if (!jr) return json({ error: "درخواست یافت نشد" }, 404, origin);
  const store = await getOwnedStore(env, user.id, jr.store_id);
  if (!store) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  if (jr.status !== "pending") return json({ error: "این درخواست قبلا بررسی شده است" }, 400, origin);

  const customerId = randId(10);
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO customers (id, store_id, name, national_id, phone, phone_country, province, district, village, created_at) VALUES (?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, ?)`
  ).bind(customerId, jr.store_id, jr.requester_name, now).run();

  const linkId = randId(10);
  await env.DB.prepare("INSERT INTO store_links (id, user_id, customer_id, created_at) VALUES (?, ?, ?, ?)")
    .bind(linkId, jr.requester_user_id, customerId, now).run();

  await env.DB.prepare("UPDATE join_requests SET status = 'approved', resolved_at = ? WHERE id = ?").bind(now, requestId).run();
  return json({ ok: true }, 200, origin);
}

async function rejectJoinRequest(requestId, request, user, env, origin) {
  if (!user) return json({ error: "ابتدا وارد شوید" }, 401, origin);
  const jr = await env.DB.prepare("SELECT * FROM join_requests WHERE id = ?").bind(requestId).first();
  if (!jr) return json({ error: "درخواست یافت نشد" }, 404, origin);
  const store = await getOwnedStore(env, user.id, jr.store_id);
  if (!store) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  if (jr.status !== "pending") return json({ error: "این درخواست قبلا بررسی شده است" }, 400, origin);

  let body; try { body = await request.json(); } catch { body = {}; }
  const now = new Date().toISOString();
  await env.DB.prepare("UPDATE join_requests SET status = 'rejected', reason = ?, resolved_at = ? WHERE id = ?")
    .bind(body.reason || "بدون دلیل", now, requestId).run();
  return json({ ok: true }, 200, origin);
}
function balanceOfPersonal(txs, currency) {
  return txs.filter((t) => t.currency === currency).reduce((sum, t) => sum + (t.type === "given" ? t.amount : -t.amount), 0);
}

/* =========================================================
   حسابداری شخصی — summary + contacts
   ========================================================= */
async function personalSummary(user, env, origin) {
  const rows = await env.DB.prepare(
    `SELECT pt.currency, pt.type, SUM(pt.amount) as total FROM personal_transactions pt
     JOIN personal_contacts pc ON pc.id = pt.contact_id WHERE pc.owner_id = ? GROUP BY pt.currency, pt.type`
  ).bind(user.id).all();
  const balances = {};
  rows.results.forEach((r) => {
    balances[r.currency] = (balances[r.currency] || 0) + (r.type === "given" ? r.total : -r.total);
  });
  return json({ balances }, 200, origin);
}

async function listContacts(user, env, origin, params) {
  const contacts = await env.DB.prepare("SELECT * FROM personal_contacts WHERE owner_id = ? ORDER BY created_at DESC").bind(user.id).all();
  const ids = contacts.results.map((c) => c.id);
  let txByContact = {};
  if (ids.length) {
    const placeholders = ids.map(() => "?").join(",");
    const txs = await env.DB.prepare(`SELECT * FROM personal_transactions WHERE contact_id IN (${placeholders}) ORDER BY tx_date ASC, created_at ASC`).bind(...ids).all();
    for (const t of txs.results) {
      (txByContact[t.contact_id] ||= []).push({ id: t.id, type: t.type, currency: t.currency, amount: t.amount, note: t.note, category: t.category, date: t.tx_date || t.created_at });
    }
  }
  let result = contacts.results.map((c) => ({
    id: c.id, firstName: c.first_name, lastName: c.last_name, phone: c.phone,
    province: c.province, district: c.district,
    transactions: txByContact[c.id] || [],
  }));

  const province = params.get("province");
  const status = params.get("status");
  if (province) result = result.filter((c) => c.province === province);
  if (status && status !== "all") {
    result = result.filter((c) => {
      const currencies = [...new Set(c.transactions.map((t) => t.currency))];
      const bals = currencies.map((cur) => balanceOfPersonal(c.transactions, cur));
      if (status === "settled") return bals.every((b) => b === 0);
      if (status === "debtor") return bals.some((b) => b > 0);
      if (status === "creditor") return bals.some((b) => b < 0) && !bals.some((b) => b > 0);
      return true;
    });
  }
  return json({ contacts: result }, 200, origin);
}

async function createContact(request, user, env, origin) {
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const firstName = (body.firstName || "").trim();
  if (!firstName) return json({ error: "نام الزامی است" }, 400, origin);
  const id = randId(10);
  const now = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO personal_contacts (id, owner_id, first_name, last_name, phone, province, district, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(id, user.id, firstName, (body.lastName || "").trim() || null, (body.phone || "").trim() || null, body.province || null, body.district || null, now).run();
  return json({ ok: true, contact: { id, firstName, lastName: body.lastName, phone: body.phone, province: body.province, district: body.district, transactions: [] } }, 200, origin);
}

async function getOwnedContact(env, userId, contactId) {
  const c = await env.DB.prepare("SELECT * FROM personal_contacts WHERE id = ?").bind(contactId).first();
  if (!c || c.owner_id !== userId) return null;
  return c;
}

async function contactDetail(contactId, user, env, origin) {
  const contact = await getOwnedContact(env, user.id, contactId);
  if (!contact) return json({ error: "یافت نشد" }, 404, origin);
  const txs = await env.DB.prepare("SELECT * FROM personal_transactions WHERE contact_id = ? ORDER BY tx_date ASC, created_at ASC").bind(contactId).all();
  return json({
    contact: {
      id: contact.id, firstName: contact.first_name, lastName: contact.last_name, phone: contact.phone,
      province: contact.province, district: contact.district,
      transactions: txs.results.map((t) => ({ id: t.id, type: t.type, currency: t.currency, amount: t.amount, note: t.note, category: t.category, date: t.tx_date || t.created_at })),
    },
  }, 200, origin);
}

async function updateContact(contactId, request, user, env, origin) {
  const contact = await getOwnedContact(env, user.id, contactId);
  if (!contact) return json({ error: "یافت نشد" }, 404, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const firstName = (body.firstName || "").trim();
  if (!firstName) return json({ error: "نام الزامی است" }, 400, origin);
  await env.DB.prepare(
    "UPDATE personal_contacts SET first_name = ?, last_name = ?, phone = ?, province = ?, district = ? WHERE id = ?"
  ).bind(firstName, (body.lastName || "").trim() || null, (body.phone || "").trim() || null, body.province || null, body.district || null, contactId).run();
  return json({ ok: true }, 200, origin);
}

async function deleteContact(contactId, user, env, origin) {
  const contact = await getOwnedContact(env, user.id, contactId);
  if (!contact) return json({ error: "یافت نشد" }, 404, origin);
  await env.DB.prepare("DELETE FROM personal_transactions WHERE contact_id = ?").bind(contactId).run();
  await env.DB.prepare("DELETE FROM personal_contacts WHERE id = ?").bind(contactId).run();
  return json({ ok: true }, 200, origin);
}

/* =========================================================
   حسابداری شخصی — transactions
   ========================================================= */
async function addTx(contactId, request, user, env, origin) {
  const contact = await getOwnedContact(env, user.id, contactId);
  if (!contact) return json({ error: "یافت نشد" }, 404, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const { type, currency, amount, note, category, date } = body;
  if (!["given", "received"].includes(type)) return json({ error: "نوع تراکنش نامعتبر است" }, 400, origin);
  if (!currency || !amount || Number(amount) <= 0) return json({ error: "مبلغ نامعتبر است" }, 400, origin);

  const id = randId(10);
  const now = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO personal_transactions (id, contact_id, type, currency, amount, note, category, tx_date, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(id, contactId, type, currency, Number(amount), note || null, category || null, date || now, now).run();

  return json({ ok: true, transaction: { id, type, currency, amount: Number(amount), note, category, date: date || now } }, 200, origin);
}

async function updateTx(txId, request, user, env, origin) {
  const tx = await env.DB.prepare("SELECT * FROM personal_transactions WHERE id = ?").bind(txId).first();
  if (!tx) return json({ error: "یافت نشد" }, 404, origin);
  const contact = await getOwnedContact(env, user.id, tx.contact_id);
  if (!contact) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const { type, currency, amount, note, category, date } = body;
  if (!["given", "received"].includes(type)) return json({ error: "نوع تراکنش نامعتبر است" }, 400, origin);
  if (!currency || !amount || Number(amount) <= 0) return json({ error: "مبلغ نامعتبر است" }, 400, origin);
  await env.DB.prepare(
    "UPDATE personal_transactions SET type = ?, currency = ?, amount = ?, note = ?, category = ?, tx_date = ? WHERE id = ?"
  ).bind(type, currency, Number(amount), note || null, category || null, date || tx.tx_date, txId).run();
  return json({ ok: true }, 200, origin);
}

async function deleteTx(txId, user, env, origin) {
  const tx = await env.DB.prepare("SELECT * FROM personal_transactions WHERE id = ?").bind(txId).first();
  if (!tx) return json({ error: "یافت نشد" }, 404, origin);
  const contact = await getOwnedContact(env, user.id, tx.contact_id);
  if (!contact) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  await env.DB.prepare("DELETE FROM personal_transactions WHERE id = ?").bind(txId).run();
  return json({ ok: true }, 200, origin);
}
function getCookie(request, name) {
  const c = request.headers.get("Cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : null;
}
function panelCookie(token) {
  return `psid=${token}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=2592000`;
}
function clearPanelCookie() {
  return `psid=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`;
}
function jsonH(data, status, origin, extraHeaders) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { "Content-Type": "application/json", ...corsHeaders(origin), ...(extraHeaders || {}) },
  });
}

async function getPanelAuthed(request, env) {
  const token = getCookie(request, "psid");
  if (!token) return false;
  const sess = await env.DB.prepare("SELECT * FROM panel_sessions WHERE token = ? AND expires_at > ?")
    .bind(token, new Date().toISOString()).first();
  return !!sess;
}
function adminAuthorized(user, panelAuthed) {
  return !!panelAuthed || !!(user && user.role === "admin");
}

async function logAdminAction(env, user, action, targetType, targetId, detail) {
  try {
    const id = randId(10);
    const adminName = user ? `${user.first_name || ""} ${user.last_name || ""}`.trim() || user.username : "پنل مدیریت";
    await env.DB.prepare(
      "INSERT INTO admin_action_logs (id, admin_id, admin_name, action, target_type, target_id, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(id, user ? user.id : "panel", adminName, action, targetType || null, targetId || null, detail || null, new Date().toISOString()).run();
  } catch {}
}

/* =========================================================
   admin
   ========================================================= */
async function adminListUsers(user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const users = await env.DB.prepare("SELECT * FROM users ORDER BY created_at ASC").all();
  const storesRes = await env.DB.prepare("SELECT * FROM stores").all();
  const stores = storesRes.results;
  const storesByOwner = {};
  stores.forEach((s) => { (storesByOwner[s.owner_id] ||= []).push(s); });

  const custRows = await env.DB.prepare("SELECT store_id, COUNT(*) as cnt FROM customers GROUP BY store_id").all();
  const custCountByStore = {};
  custRows.results.forEach((r) => { custCountByStore[r.store_id] = r.cnt; });

  const txRows = await env.DB.prepare(
    `SELECT c.store_id as store_id, t.currency, t.type, SUM(t.amount) as total
     FROM transactions t JOIN customers c ON t.customer_id = c.id GROUP BY c.store_id, t.currency, t.type`
  ).all();
  const balByStore = {};
  txRows.results.forEach((r) => {
    balByStore[r.store_id] ||= {};
    balByStore[r.store_id][r.currency] = (balByStore[r.store_id][r.currency] || 0) + (r.type === "debt" ? r.total : -r.total);
  });

  const usersOut = users.results.map((u) => {
    const myStores = storesByOwner[u.id] || [];
    let store = null;
    if (myStores.length === 1) {
      const s = myStores[0];
      store = { id: s.id, name: s.name, storeUsername: s.store_username, blocked: !!s.blocked, customerCount: custCountByStore[s.id] || 0, balances: balByStore[s.id] || {} };
    } else if (myStores.length > 1) {
      const combinedBalances = {};
      let combinedCustomers = 0;
      let anyBlocked = false;
      myStores.forEach((s) => {
        combinedCustomers += custCountByStore[s.id] || 0;
        anyBlocked = anyBlocked || !!s.blocked;
        const b = balByStore[s.id] || {};
        Object.keys(b).forEach((cur) => { combinedBalances[cur] = (combinedBalances[cur] || 0) + b[cur]; });
      });
      store = {
        id: myStores.map((s) => s.id).join(","), name: `${myStores.length} فروشگاه (${myStores.map((s) => s.name).join("، ")})`,
        storeUsername: myStores[0].store_username, blocked: anyBlocked, customerCount: combinedCustomers, balances: combinedBalances,
        multi: true, storeIds: myStores.map((s) => s.id),
      };
    }
    return { ...publicUser(u), store };
  });

  const userNameById = {};
  users.results.forEach((u) => { userNameById[u.id] = { firstName: u.first_name, lastName: u.last_name, username: u.username }; });
  const storesOut = stores.map((s) => ({
    id: s.id, name: s.name, storeUsername: s.store_username, blocked: !!s.blocked,
    ownerId: s.owner_id, ownerFirstName: (userNameById[s.owner_id] || {}).firstName || "", ownerLastName: (userNameById[s.owner_id] || {}).lastName || "",
    ownerUsername: (userNameById[s.owner_id] || {}).username || "",
    customerCount: custCountByStore[s.id] || 0, balances: balByStore[s.id] || {}, createdAt: s.created_at,
  }));

  const stats = {
    totalUsers: users.results.length,
    blockedUsers: users.results.filter((u) => u.blocked).length,
    activeUsers: users.results.filter((u) => !u.blocked).length,
    activeSubs: users.results.filter((u) => u.sub_active && u.sub_expires && new Date(u.sub_expires) > new Date()).length,
    totalStores: stores.length,
    blockedStores: stores.filter((s) => s.blocked).length,
  };

  return json({ users: usersOut, stores: storesOut, stats }, 200, origin);
}

async function adminToggleBlock(targetId, user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const target = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(targetId).first();
  if (!target) return json({ error: "کاربر یافت نشد" }, 404, origin);
  if (target.role === "admin") return json({ error: "امکان مسدودسازی مدیر وجود ندارد" }, 400, origin);
  const newBlocked = target.blocked ? 0 : 1;
  await env.DB.prepare("UPDATE users SET blocked = ? WHERE id = ?").bind(newBlocked, targetId).run();
  await logAdminAction(env, user, newBlocked ? "block_user" : "unblock_user", "user", targetId, `${target.first_name} ${target.last_name} (@${target.username})`);
  return json({ ok: true, blocked: !!newBlocked }, 200, origin);
}

async function adminToggleStoreBlock(storeId, user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(storeId).first();
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  const newBlocked = store.blocked ? 0 : 1;
  await env.DB.prepare("UPDATE stores SET blocked = ? WHERE id = ?").bind(newBlocked, storeId).run();
  await logAdminAction(env, user, newBlocked ? "block_store" : "unblock_store", "store", storeId, store.name);
  return json({ ok: true, blocked: !!newBlocked }, 200, origin);
}

async function adminSetSubscription(targetId, request, user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const days = Number(body.days) || 0;
  const target = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(targetId).first();
  if (!target) return json({ error: "کاربر یافت نشد" }, 404, origin);
  const now = new Date().toISOString();

  if (days > 0) {
    const storeLimit = body.storeLimit != null && body.storeLimit !== "" ? Math.max(1, Number(body.storeLimit)) : 1;
    const customerLimit = body.customerLimit != null && body.customerLimit !== "" ? Math.max(1, Number(body.customerLimit)) : null;
    const transactionLimit = body.transactionLimit != null && body.transactionLimit !== "" ? Math.max(1, Number(body.transactionLimit)) : null;
    const staffLimit = body.staffLimit != null && body.staffLimit !== "" ? Math.max(0, Number(body.staffLimit)) : null;
    const planId = body.planId || null;
    const grantId = randId(10);
    await env.DB.prepare(
      "INSERT INTO subscription_grants (id, user_id, days, store_limit, customer_limit, transaction_limit, staff_limit, plan_id, status, granted_at, activated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL)"
    ).bind(grantId, targetId, days, storeLimit, customerLimit, transactionLimit, staffLimit, planId, now).run();
    const logId = randId(10);
    await env.DB.prepare("INSERT INTO subscription_logs (id, user_id, action, days, created_at) VALUES (?, ?, 'granted', ?, ?)")
      .bind(logId, targetId, days, now).run();
    await logAdminAction(env, user, "grant_subscription", "user", targetId, `${target.first_name} ${target.last_name} — ${days} روز`);
    return json({ ok: true, granted: true }, 200, origin);
  } else {
    await env.DB.prepare(
      "UPDATE users SET sub_active = 0, sub_expires = NULL, store_limit = ?, customer_limit = ?, transaction_limit = ?, staff_limit = ? WHERE id = ?"
    ).bind(FREE_LIMITS.stores, FREE_LIMITS.customers, FREE_LIMITS.transactions, FREE_LIMITS.staff, targetId).run();
    const logId = randId(10);
    await env.DB.prepare("INSERT INTO subscription_logs (id, user_id, action, days, created_at) VALUES (?, ?, 'deactivate', 0, ?)")
      .bind(logId, targetId, now).run();
    await logAdminAction(env, user, "deactivate_subscription", "user", targetId, `${target.first_name} ${target.last_name}`);
    return json({ ok: true, active: false, expiresAt: null }, 200, origin);
  }
}

async function adminSubscriptionLogs(targetId, user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const logs = await env.DB.prepare("SELECT * FROM subscription_logs WHERE user_id = ? ORDER BY created_at DESC").bind(targetId).all();
  return json({ logs: logs.results.map((l) => ({ id: l.id, action: l.action, days: l.days, date: l.created_at })) }, 200, origin);
}

const ADMIN_ACTION_LABELS = {
  block_user: "مسدودسازی کاربر", unblock_user: "رفع مسدودی کاربر",
  block_store: "مسدودسازی فروشگاه", unblock_store: "رفع مسدودی فروشگاه",
  grant_subscription: "اعطای اشتراک", deactivate_subscription: "لغو اشتراک",
  delete_plan: "حذف پلن", approve_plan_request: "تایید درخواست پلن", reject_plan_request: "رد درخواست پلن",
  reset_password: "بازنشانی رمز عبور", send_broadcast: "ارسال پیام همگانی",
};

async function adminListActionLogs(user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const rows = await env.DB.prepare("SELECT * FROM admin_action_logs ORDER BY created_at DESC LIMIT 100").all();
  return json({
    logs: rows.results.map((l) => ({
      id: l.id, adminName: l.admin_name, action: l.action, actionLabel: ADMIN_ACTION_LABELS[l.action] || l.action,
      targetType: l.target_type, targetId: l.target_id, detail: l.detail, date: l.created_at,
    })),
  }, 200, origin);
}

async function adminViewStoreCustomers(storeId, user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const store = await env.DB.prepare("SELECT * FROM stores WHERE id = ?").bind(storeId).first();
  if (!store) return json({ error: "فروشگاه یافت نشد" }, 404, origin);
  const customers = await env.DB.prepare("SELECT * FROM customers WHERE store_id = ? ORDER BY created_at DESC").bind(storeId).all();
  const txs = await env.DB.prepare(
    `SELECT t.* FROM transactions t JOIN customers c ON t.customer_id = c.id WHERE c.store_id = ?`
  ).bind(storeId).all();
  const byCustomer = {};
  for (const t of txs.results) (byCustomer[t.customer_id] ||= []).push({ type: t.type, currency: t.currency, amount: t.amount, note: t.note, date: t.created_at });
  return json({
    store: { id: store.id, name: store.name, storeUsername: store.store_username },
    customers: customers.results.map((c) => ({
      id: c.id, name: c.name, phone: c.phone, province: c.province, blocked: !!c.blocked,
      transactions: byCustomer[c.id] || [],
    })),
  }, 200, origin);
}

async function adminGrowthStats(user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const users = await env.DB.prepare("SELECT created_at FROM users").all();
  const activations = await env.DB.prepare("SELECT created_at FROM subscription_logs WHERE action = 'activate'").all();
  const weekKey = (iso) => {
    const d = new Date(iso);
    const onejan = new Date(d.getFullYear(), 0, 1);
    const week = Math.ceil(((d - onejan) / 86400000 + onejan.getDay() + 1) / 7);
    return `${d.getFullYear()}-W${week}`;
  };
  const last8Weeks = [];
  const now = new Date();
  for (let i = 7; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 7 * 86400000);
    last8Weeks.push(weekKey(d.toISOString()));
  }
  const regCounts = Object.fromEntries(last8Weeks.map((w) => [w, 0]));
  users.results.forEach((u) => { const w = weekKey(u.created_at); if (w in regCounts) regCounts[w]++; });
  const actCounts = Object.fromEntries(last8Weeks.map((w) => [w, 0]));
  activations.results.forEach((a) => { const w = weekKey(a.created_at); if (w in actCounts) actCounts[w]++; });
  return json({
    weeks: last8Weeks,
    registrations: last8Weeks.map((w) => regCounts[w]),
    activations: last8Weeks.map((w) => actCounts[w]),
  }, 200, origin);
}

/* =========================================================
   plans admin
   ========================================================= */
async function adminListPlans(user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  await ensureSeedPlans(env);
  const rows = await env.DB.prepare("SELECT * FROM plans ORDER BY sort_order ASC, created_at ASC").all();
  return json({ plans: rows.results.map(planOut) }, 200, origin);
}
async function adminCreatePlan(request, user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const name = (body.name || "").trim();
  const days = Number(body.days) || 30;
  if (!name) return json({ error: "نام پلن الزامی است" }, 400, origin);
  const id = randId(10);
  const now = new Date().toISOString();
  const numOrNull = (v) => (v != null && v !== "" ? Math.max(0, Number(v)) : null);
  await env.DB.prepare(
    "INSERT INTO plans (id, name, description, days, store_limit, customer_limit, transaction_limit, staff_limit, sort_order, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)"
  ).bind(id, name, (body.description || "").trim() || null, days, numOrNull(body.storeLimit), numOrNull(body.customerLimit), numOrNull(body.transactionLimit), numOrNull(body.staffLimit), Number(body.sortOrder) || 0, now).run();
  const p = await env.DB.prepare("SELECT * FROM plans WHERE id = ?").bind(id).first();
  return json({ ok: true, plan: planOut(p) }, 200, origin);
}
async function adminUpdatePlan(planId, request, user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const existing = await env.DB.prepare("SELECT * FROM plans WHERE id = ?").bind(planId).first();
  if (!existing) return json({ error: "پلن یافت نشد" }, 404, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const numOrNull = (v) => (v != null && v !== "" ? Math.max(0, Number(v)) : null);
  const name = (body.name || existing.name || "").trim();
  await env.DB.prepare(
    "UPDATE plans SET name = ?, description = ?, days = ?, store_limit = ?, customer_limit = ?, transaction_limit = ?, staff_limit = ?, sort_order = ?, active = ? WHERE id = ?"
  ).bind(
    name, (body.description ?? existing.description) || null, Number(body.days) || existing.days,
    body.storeLimit !== undefined ? numOrNull(body.storeLimit) : existing.store_limit,
    body.customerLimit !== undefined ? numOrNull(body.customerLimit) : existing.customer_limit,
    body.transactionLimit !== undefined ? numOrNull(body.transactionLimit) : existing.transaction_limit,
    body.staffLimit !== undefined ? numOrNull(body.staffLimit) : existing.staff_limit,
    body.sortOrder !== undefined ? Number(body.sortOrder) : existing.sort_order,
    body.active !== undefined ? (body.active ? 1 : 0) : existing.active,
    planId
  ).run();
  const p = await env.DB.prepare("SELECT * FROM plans WHERE id = ?").bind(planId).first();
  return json({ ok: true, plan: planOut(p) }, 200, origin);
}
async function adminDeletePlan(planId, user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const plan = await env.DB.prepare("SELECT * FROM plans WHERE id = ?").bind(planId).first();
  await env.DB.prepare("DELETE FROM plans WHERE id = ?").bind(planId).run();
  await logAdminAction(env, user, "delete_plan", "plan", planId, plan ? plan.name : null);
  return json({ ok: true }, 200, origin);
}

/* =========================================================
   plan requests admin
   ========================================================= */
async function adminListPlanRequests(user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const rows = await env.DB.prepare(
    `SELECT pr.*, p.name as plan_name, u.first_name, u.last_name, u.username
     FROM plan_requests pr JOIN plans p ON p.id = pr.plan_id JOIN users u ON u.id = pr.user_id
     WHERE pr.status = 'pending' ORDER BY pr.created_at ASC`
  ).all();
  return json({
    requests: rows.results.map((r) => ({
      id: r.id, planId: r.plan_id, planName: r.plan_name, userId: r.user_id,
      userName: `${r.first_name} ${r.last_name}`, username: r.username, date: r.created_at,
    })),
  }, 200, origin);
}
async function adminResolvePlanRequest(requestId, action, user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const reqRow = await env.DB.prepare("SELECT * FROM plan_requests WHERE id = ? AND status = 'pending'").bind(requestId).first();
  if (!reqRow) return json({ error: "درخواست یافت نشد" }, 404, origin);
  const now = new Date().toISOString();

  if (action === "reject") {
    await env.DB.prepare("UPDATE plan_requests SET status = 'rejected', resolved_at = ? WHERE id = ?").bind(now, requestId).run();
    await logAdminAction(env, user, "reject_plan_request", "plan_request", requestId, null);
    return json({ ok: true }, 200, origin);
  }
  const plan = await env.DB.prepare("SELECT * FROM plans WHERE id = ?").bind(reqRow.plan_id).first();
  if (!plan) return json({ error: "پلن یافت نشد" }, 404, origin);
  const grantId = randId(10);
  await env.DB.prepare(
    "INSERT INTO subscription_grants (id, user_id, days, store_limit, customer_limit, transaction_limit, staff_limit, plan_id, status, granted_at, activated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL)"
  ).bind(grantId, reqRow.user_id, plan.days, plan.store_limit, plan.customer_limit, plan.transaction_limit, plan.staff_limit, plan.id, now).run();
  const logId = randId(10);
  await env.DB.prepare("INSERT INTO subscription_logs (id, user_id, action, days, created_at) VALUES (?, ?, 'granted', ?, ?)")
    .bind(logId, reqRow.user_id, plan.days, now).run();
  await env.DB.prepare("UPDATE plan_requests SET status = 'approved', resolved_at = ? WHERE id = ?").bind(now, requestId).run();
  await logAdminAction(env, user, "approve_plan_request", "plan_request", requestId, plan.name);
  return json({ ok: true }, 200, origin);
}

/* =========================================================
   broadcast admin
   ========================================================= */
async function adminCreateBroadcast(request, user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const message = (body.message || "").trim();
  if (!message) return json({ error: "متن پیام الزامی است" }, 400, origin);
  const targetType = ["all", "province", "district"].includes(body.targetType) ? body.targetType : "all";
  const targetProvince = targetType !== "all" ? (body.targetProvince || "").trim() : null;
  const targetDistrict = targetType === "district" ? (body.targetDistrict || "").trim() : null;
  if (targetType === "province" && !targetProvince) return json({ error: "انتخاب ولایت الزامی است" }, 400, origin);
  if (targetType === "district" && (!targetProvince || !targetDistrict)) return json({ error: "انتخاب ولایت و ولسوالی الزامی است" }, 400, origin);
  const id = randId(10);
  const now = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO broadcasts (id, message, target_type, target_province, target_district, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(id, message, targetType, targetProvince, targetDistrict, now).run();
  await logAdminAction(env, user, "send_broadcast", "broadcast", id, message.slice(0, 60));
  return json({ ok: true, broadcast: { id, message, targetType, targetProvince, targetDistrict, date: now } }, 200, origin);
}

async function adminListBroadcasts(user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const rows = await env.DB.prepare("SELECT * FROM broadcasts ORDER BY created_at DESC LIMIT 50").all();
  return json({
    broadcasts: rows.results.map((b) => ({
      id: b.id, message: b.message, targetType: b.target_type, targetProvince: b.target_province, targetDistrict: b.target_district, date: b.created_at,
    })),
  }, 200, origin);
}

async function adminResetPassword(targetId, user, panelAuthed, env, origin) {
  if (!adminAuthorized(user, panelAuthed)) return json({ error: "دسترسی مجاز نیست" }, 403, origin);
  const target = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(targetId).first();
  if (!target) return json({ error: "کاربر یافت نشد" }, 404, origin);
  const newPassword = randAlnumId(8);
  const salt = randId(20);
  const hash = await hashPassword(newPassword, salt);
  await env.DB.prepare("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?").bind(hash, salt, targetId).run();
  await logAdminAction(env, user, "reset_password", "user", targetId, `${target.first_name} ${target.last_name} (@${target.username})`);
  return json({ ok: true, newPassword }, 200, origin);
}

/* =========================================================
   standalone admin-panel password (independent of user accounts)
   ========================================================= */
async function panelLogin(request, env, origin) {
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const password = body.password || "";
  if (!password) return json({ error: "رمز عبور را وارد کنید" }, 400, origin);
  const cfg = await env.DB.prepare("SELECT * FROM panel_auth WHERE id = 1").first();
  if (!cfg) return json({ error: "رمز پنل هنوز تنظیم نشده است" }, 500, origin);
  const hash = await hashPassword(password, cfg.salt);
  if (hash !== cfg.password_hash) return json({ error: "رمز عبور اشتباه است" }, 401, origin);
  const token = crypto.randomUUID();
  const now = new Date().toISOString();
  const expires = new Date(Date.now() + 30 * 86400000).toISOString();
  await env.DB.prepare("INSERT INTO panel_sessions (token, created_at, expires_at) VALUES (?, ?, ?)").bind(token, now, expires).run();
  return jsonH({ ok: true }, 200, origin, { "Set-Cookie": panelCookie(token) });
}

async function panelLogout(request, env, origin) {
  const token = getCookie(request, "psid");
  if (token) await env.DB.prepare("DELETE FROM panel_sessions WHERE token = ?").bind(token).run();
  return jsonH({ ok: true }, 200, origin, { "Set-Cookie": clearPanelCookie() });
}

async function panelChangePassword(request, panelAuthed, env, origin) {
  if (!panelAuthed) return json({ error: "ابتدا وارد پنل شوید" }, 401, origin);
  let body; try { body = await request.json(); } catch { return json({ error: "درخواست نامعتبر است" }, 400, origin); }
  const { currentPassword, newPassword, confirmPassword } = body;
  if (!currentPassword || !newPassword || !confirmPassword) return json({ error: "همه فیلدها الزامی است" }, 400, origin);
  if (newPassword !== confirmPassword) return json({ error: "رمز جدید و تکرار آن یکسان نیستند" }, 400, origin);
  if (newPassword.length < 4) return json({ error: "رمز جدید باید حداقل ۴ کاراکتر باشد" }, 400, origin);
  const cfg = await env.DB.prepare("SELECT * FROM panel_auth WHERE id = 1").first();
  if (!cfg) return json({ error: "تنظیمات پنل یافت نشد" }, 500, origin);
  const hash = await hashPassword(currentPassword, cfg.salt);
  if (hash !== cfg.password_hash) return json({ error: "رمز عبور فعلی اشتباه است" }, 400, origin);
  const newSalt = randId(20);
  const newHash = await hashPassword(newPassword, newSalt);
  await env.DB.prepare("UPDATE panel_auth SET password_hash = ?, salt = ? WHERE id = 1").bind(newHash, newSalt).run();
  return json({ ok: true }, 200, origin);
}

/* =========================================================
   ورودی اصلی Worker یکپارچه — auth + data + personal + admin/panel
   ========================================================= */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "*";
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = request.method;

    if (method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(origin) });

    try {
      const user = await getSessionUser(request, env);
      const panelAuthed = await getPanelAuthed(request, env);
      const mm = (re) => path.match(re);

      // ===================== auth =====================
      if (path === "/api/auth/register" && method === "POST") return await register(request, env, origin);
      if (path === "/api/auth/login" && method === "POST") return await login(request, env, origin);
      if (path === "/api/auth/logout" && method === "POST") return await logout(request, user, env, origin);

      if (path === "/api/me" && method === "GET") return await me(user, env, origin);
      if (path === "/api/me" && method === "POST") return await updateMyProfile(request, user, env, origin);
      if (path === "/api/me/password" && method === "POST") return await changeMyPassword(request, user, env, origin);
      if (path === "/api/me/sessions" && method === "GET") return await mySessions(request, user, env, origin);
      if (path === "/api/me/sessions/revoke-others" && method === "POST") return await revokeAllSessions(request, user, env, origin);
      if (path === "/api/me/subscription-logs" && method === "GET") return await mySubscriptionLogs(user, env, origin);
      if (path === "/api/me/subscription-grants" && method === "GET") return await myPendingGrants(user, env, origin);
      if (path === "/api/me/plan-requests" && method === "GET") return await myPlanRequests(user, env, origin);
      if (path === "/api/me/broadcasts" && method === "GET") return await myBroadcasts(user, env, origin);

      if (path === "/api/me/pin" && method === "POST") return await setPin(request, user, env, origin);
      if (path === "/api/me/pin" && method === "DELETE") return await disablePin(request, user, env, origin);
      if (path === "/api/me/pin/verify" && method === "POST") return await verifyPin(request, user, env, origin);

      if (path === "/api/me/webauthn/register-options" && method === "POST") return await webauthnRegisterOptions(user, env, origin);
      if (path === "/api/me/webauthn/register-verify" && method === "POST") return await webauthnRegisterVerify(request, user, env, origin);
      if (path === "/api/me/webauthn/auth-options" && method === "POST") return await webauthnAuthOptions(user, env, origin);
      if (path === "/api/me/webauthn/auth-verify" && method === "POST") return await webauthnAuthVerify(request, user, env, origin);
      if (path === "/api/me/webauthn/credentials" && method === "GET") return await listWebauthnCredentials(user, env, origin);
      { const g = mm(/^\/api\/me\/webauthn\/credentials\/([^/]+)$/); if (g && method === "DELETE") return await deleteWebauthnCredential(g[1], user, env, origin); }

      { const g = mm(/^\/api\/subscription-grants\/([^/]+)\/activate$/); if (g && method === "POST") return await activateGrant(g[1], user, env, origin); }

      if (path === "/api/plans" && method === "GET") return await listPlans(user, env, origin);
      if (path === "/api/plan-requests" && method === "POST") return await createPlanRequest(request, user, env, origin);

      // ===================== data: stores =====================
      if (path === "/api/stores" && method === "GET") return await listMyStores(user, env, origin);
      if (path === "/api/stores" && method === "POST") return await createStore(request, user, env, origin);
      if (path === "/api/stores/lookup" && method === "POST") return await lookupStoreByUsername(request, env, origin);
      { const g = mm(/^\/api\/stores\/([^/]+)\/photo$/); if (g && method === "POST") return await updateStorePhoto(g[1], request, user, env, origin); }
      { const g = mm(/^\/api\/stores\/([^/]+)\/info$/); if (g && method === "POST") return await updateStoreInfo(g[1], request, user, env, origin); }
      { const g = mm(/^\/api\/stores\/([^/]+)\/cards$/); if (g && method === "POST") return await updateStoreCards(g[1], request, user, env, origin); }
      { const g = mm(/^\/api\/stores\/([^/]+)\/telegram-owner-link$/); if (g && method === "GET") return await getOrCreateStoreTelegramLink(g[1], user, env, origin); }
      { const g = mm(/^\/api\/stores\/([^/]+)\/telegram-owner-link$/); if (g && method === "DELETE") return await disconnectStoreTelegramOwner(g[1], user, env, origin); }
      { const g = mm(/^\/api\/stores\/([^/]+)\/rename$/); if (g && method === "POST") return await renameStore(g[1], request, user, env, origin); }
      { const g = mm(/^\/api\/stores\/([^/]+)\/backup$/); if (g && method === "GET") return await exportStoreBackup(g[1], user, env, origin); }
      { const g = mm(/^\/api\/stores\/([^/]+)\/settlement-requests$/); if (g && method === "GET") return await listSettlementRequests(g[1], user, env, origin); }
      { const g = mm(/^\/api\/settlement-requests\/([^/]+)\/resolve$/); if (g && method === "POST") return await resolveSettlementRequest(g[1], user, env, origin); }
      { const g = mm(/^\/api\/public\/customer\/([^/]+)\/settlement-request$/); if (g && method === "POST") return await createSettlementRequest(g[1], env, origin); }
      { const g = mm(/^\/api\/public\/customer\/([^/]+)\/balances$/); if (g && method === "GET") return await publicCustomerBalances(g[1], env, origin); }
      { const g = mm(/^\/api\/public\/store\/([^/]+)\/panel-summary$/); if (g && method === "GET") return await publicStorePanelSummary(g[1], env, origin); }
      if (path === "/api/public/telegram/payment-request" && method === "POST") return await createPaymentReceiptDraftRoute(request, env, origin);
      if (path === "/api/public/telegram/cash-request" && method === "POST") return await createCashRequestRoute(request, env, origin);
      if (path === "/api/recurring" && method === "POST") return await createRecurring(request, user, env, origin);
      { const g = mm(/^\/api\/customers\/([^/]+)\/recurring$/); if (g && method === "GET") return await listRecurring(g[1], user, env, origin); }
      { const g = mm(/^\/api\/recurring\/([^/]+)$/); if (g && method === "DELETE") return await deleteRecurring(g[1], user, env, origin); }
      { const g = mm(/^\/api\/stores\/([^/]+)\/staff-invite$/); if (g && method === "POST") return await createStaffInvite(g[1], user, env, origin); }
      { const g = mm(/^\/api\/stores\/([^/]+)\/staff$/); if (g && method === "GET") return await listStaff(g[1], user, env, origin); }
      { const g = mm(/^\/api\/stores\/([^/]+)\/staff\/([^/]+)$/); if (g && method === "DELETE") return await removeStaff(g[1], g[2], user, env, origin); }
      if (path === "/api/staff/join" && method === "POST") return await joinStoreAsStaff(request, user, env, origin);
      if (path === "/api/customers/search" && method === "GET") return await globalSearchCustomers(user, env, origin, url.searchParams.get("q"));
      { const g = mm(/^\/api\/public\/customer\/([^/]+)$/); if (g && method === "GET") return await publicCustomerView(g[1], env, origin); }

      { const g = mm(/^\/api\/stores\/([^/]+)\/joined$/); if (g && method === "GET") return await joinedCustomers(g[1], user, env, origin); }
      { const g = mm(/^\/api\/stores\/([^/]+)\/join-requests$/); if (g && method === "GET") return await storeJoinRequests(g[1], user, env, origin); }

      // ===================== data: join requests =====================
      if (path === "/api/join-requests" && method === "POST") return await createJoinRequest(request, user, env, origin);
      if (path === "/api/join-requests" && method === "GET") return await myJoinRequests(user, env, origin);
      { const g = mm(/^\/api\/join-requests\/([^/]+)\/approve$/); if (g && method === "POST") return await approveJoinRequest(g[1], user, env, origin); }
      { const g = mm(/^\/api\/join-requests\/([^/]+)\/reject$/); if (g && method === "POST") return await rejectJoinRequest(g[1], request, user, env, origin); }

      // ===================== data: customers =====================
      if (path === "/api/customers" && method === "GET") return await listCustomers(user, env, origin, url.searchParams.get("storeId"));
      if (path === "/api/customers" && method === "POST") return await createCustomer(request, user, env, origin);
      { const g = mm(/^\/api\/customers\/([^/]+)\/self-profile$/); if (g && method === "GET") return await customerSelfProfile(g[1], user, env, origin); }
      { const g = mm(/^\/api\/customers\/([^/]+)\/block$/); if (g && method === "POST") return await toggleCustomerBlock(g[1], user, env, origin); }
      { const g = mm(/^\/api\/customers\/([^/]+)\/transactions\/([^/]+)$/); if (g && method === "POST") return await updateTransaction(g[1], g[2], request, user, env, origin); }
      { const g = mm(/^\/api\/customers\/([^/]+)\/transactions\/([^/]+)$/); if (g && method === "DELETE") return await deleteTransaction(g[1], g[2], user, env, origin); }
      { const g = mm(/^\/api\/customers\/([^/]+)\/transactions$/); if (g && method === "POST") return await addTransaction(g[1], request, user, env, origin); }
      { const g = mm(/^\/api\/customers\/([^/]+)\/note$/); if (g && method === "GET") return await revealCustomerNote(g[1], request, user, env, origin); }
      { const g = mm(/^\/api\/customers\/([^/]+)$/); if (g && method === "GET") return await customerDetail(g[1], user, env, origin); }
      { const g = mm(/^\/api\/customers\/([^/]+)$/); if (g && method === "POST") return await updateCustomer(g[1], request, user, env, origin); }
      { const g = mm(/^\/api\/customers\/([^/]+)\/note$/); if (g && method === "POST") return await updateCustomerNote(g[1], request, user, env, origin); }
      { const g = mm(/^\/api\/customers\/([^/]+)$/); if (g && method === "DELETE") return await deleteCustomer(g[1], request, user, env, origin); }

      if (path === "/api/telegram/webhook" && method === "POST") return await telegramWebhook(request, env, origin);
      { const g = mm(/^\/api\/customers\/([^/]+)\/telegram-status$/); if (g && method === "GET") return await telegramStatus(g[1], user, env, origin); }
      { const g = mm(/^\/api\/customers\/([^/]+)\/telegram-link$/); if (g && method === "DELETE") return await telegramUnlink(g[1], user, env, origin); }

      // ===================== data: links =====================
      if (path === "/api/links" && method === "GET") return await listLinks(user, env, origin);
      if (path === "/api/links" && method === "POST") return await createLink(request, user, env, origin);
      if (path === "/api/links/lookup" && method === "POST") return await lookupLink(request, user, env, origin);
      { const g = mm(/^\/api\/links\/([^/]+)\/profile$/); if (g && method === "POST") return await updateLinkProfile(g[1], request, user, env, origin); }
      { const g = mm(/^\/api\/links\/([^/]+)$/); if (g && method === "DELETE") return await deleteLink(g[1], user, env, origin); }

      // ===================== personal =====================
      if (!user && path.startsWith("/api/personal/")) return json({ error: "ابتدا وارد شوید" }, 401, origin);
      if (path === "/api/personal/summary" && method === "GET") return await personalSummary(user, env, origin);
      if (path === "/api/personal/contacts" && method === "GET") return await listContacts(user, env, origin, url.searchParams);
      if (path === "/api/personal/contacts" && method === "POST") return await createContact(request, user, env, origin);
      { const g = mm(/^\/api\/personal\/contacts\/([^/]+)$/); if (g && method === "GET") return await contactDetail(g[1], user, env, origin); }
      { const g = mm(/^\/api\/personal\/contacts\/([^/]+)$/); if (g && method === "POST") return await updateContact(g[1], request, user, env, origin); }
      { const g = mm(/^\/api\/personal\/contacts\/([^/]+)$/); if (g && method === "DELETE") return await deleteContact(g[1], user, env, origin); }
      { const g = mm(/^\/api\/personal\/contacts\/([^/]+)\/transactions$/); if (g && method === "POST") return await addTx(g[1], request, user, env, origin); }
      { const g = mm(/^\/api\/personal\/transactions\/([^/]+)$/); if (g && method === "POST") return await updateTx(g[1], request, user, env, origin); }
      { const g = mm(/^\/api\/personal\/transactions\/([^/]+)$/); if (g && method === "DELETE") return await deleteTx(g[1], user, env, origin); }

      // ===================== admin / panel =====================
      if (path === "/api/panel/login" && method === "POST") return await panelLogin(request, env, origin);
      if (path === "/api/panel/logout" && method === "POST") return await panelLogout(request, env, origin);
      if (path === "/api/panel/session" && method === "GET") return json({ authenticated: panelAuthed }, 200, origin);
      if (path === "/api/panel/password" && method === "POST") return await panelChangePassword(request, panelAuthed, env, origin);

      if (path === "/api/admin/users" && method === "GET") return await adminListUsers(user, panelAuthed, env, origin);
      { const g = mm(/^\/api\/admin\/users\/([^/]+)\/block$/); if (g && method === "POST") return await adminToggleBlock(g[1], user, panelAuthed, env, origin); }
      { const g = mm(/^\/api\/admin\/users\/([^/]+)\/subscription$/); if (g && method === "POST") return await adminSetSubscription(g[1], request, user, panelAuthed, env, origin); }
      { const g = mm(/^\/api\/admin\/users\/([^/]+)\/subscription-logs$/); if (g && method === "GET") return await adminSubscriptionLogs(g[1], user, panelAuthed, env, origin); }
      { const g = mm(/^\/api\/admin\/stores\/([^/]+)\/block$/); if (g && method === "POST") return await adminToggleStoreBlock(g[1], user, panelAuthed, env, origin); }
      { const g = mm(/^\/api\/admin\/users\/([^/]+)\/reset-password$/); if (g && method === "POST") return await adminResetPassword(g[1], user, panelAuthed, env, origin); }
      if (path === "/api/admin/broadcast" && method === "POST") return await adminCreateBroadcast(request, user, panelAuthed, env, origin);
      if (path === "/api/admin/broadcasts" && method === "GET") return await adminListBroadcasts(user, panelAuthed, env, origin);
      if (path === "/api/admin/action-logs" && method === "GET") return await adminListActionLogs(user, panelAuthed, env, origin);
      if (path === "/api/admin/growth-stats" && method === "GET") return await adminGrowthStats(user, panelAuthed, env, origin);
      { const g = mm(/^\/api\/admin\/stores\/([^/]+)\/customers$/); if (g && method === "GET") return await adminViewStoreCustomers(g[1], user, panelAuthed, env, origin); }
      if (path === "/api/admin/plans" && method === "GET") return await adminListPlans(user, panelAuthed, env, origin);
      if (path === "/api/admin/plans" && method === "POST") return await adminCreatePlan(request, user, panelAuthed, env, origin);
      { const g = mm(/^\/api\/admin\/plans\/([^/]+)$/); if (g && method === "POST") return await adminUpdatePlan(g[1], request, user, panelAuthed, env, origin); }
      { const g = mm(/^\/api\/admin\/plans\/([^/]+)$/); if (g && method === "DELETE") return await adminDeletePlan(g[1], user, panelAuthed, env, origin); }
      if (path === "/api/admin/plan-requests" && method === "GET") return await adminListPlanRequests(user, panelAuthed, env, origin);
      { const g = mm(/^\/api\/admin\/plan-requests\/([^/]+)\/approve$/); if (g && method === "POST") return await adminResolvePlanRequest(g[1], "approve", user, panelAuthed, env, origin); }
      { const g = mm(/^\/api\/admin\/plan-requests\/([^/]+)\/reject$/); if (g && method === "POST") return await adminResolvePlanRequest(g[1], "reject", user, panelAuthed, env, origin); }

      return json({ error: "مسیر یافت نشد" }, 404, origin);
    } catch (err) {
      return json({ error: "خطای سرور: " + (err.message || "نامشخص") }, 500, origin);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(sendDueDateReminders(env));
  },
};
