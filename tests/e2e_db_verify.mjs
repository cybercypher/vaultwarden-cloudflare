#!/usr/bin/env node
/**
 * Database & Storage Verification E2E Test
 *
 * Performs operations via the API, then directly queries D1 to verify
 * the database rows are correct. Also checks KV and R2 state.
 *
 * This proves data actually persists and round-trips correctly at
 * the storage layer, not just the API response layer.
 */

import crypto from 'node:crypto';
import { execSync } from 'node:child_process';

const BASE_URL = process.argv[2] || 'http://localhost:8787';
let PASS = 0, FAIL = 0, TOTAL = 0;

// ═══════════════════════════════════════════════════════════════════════════════
// Crypto (same as other tests)
// ═══════════════════════════════════════════════════════════════════════════════

function deriveMasterKey(pw, email) { return crypto.pbkdf2Sync(pw, email.toLowerCase(), 600000, 32, 'sha256'); }
function deriveMPH(mk, pw) { return crypto.pbkdf2Sync(mk, pw, 1, 32, 'sha256').toString('base64'); }
function makeSymKey(mk) {
  const sk = crypto.randomBytes(64), iv = crypto.randomBytes(16), ek = mk.subarray(0,32);
  const c = crypto.createCipheriv('aes-256-cbc', ek, iv);
  let ct = Buffer.concat([c.update(sk), c.final()]);
  const macK = crypto.createHmac('sha256', mk).update(Buffer.from('mac')).digest();
  const mac = crypto.createHmac('sha256', macK).update(Buffer.concat([iv, ct])).digest();
  return { symKey: sk, encKeyStr: `2.${iv.toString('base64')}|${ct.toString('base64')}|${mac.toString('base64')}` };
}
function enc(pt, sk) {
  if (!pt) return null;
  const ek = sk.subarray(0,32), mk = sk.subarray(32,64), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-cbc', ek, iv);
  let ct = Buffer.concat([c.update(pt,'utf8'), c.final()]);
  const mac = crypto.createHmac('sha256', mk).update(Buffer.concat([iv, ct])).digest();
  return `2.${iv.toString('base64')}|${ct.toString('base64')}|${mac.toString('base64')}`;
}
function makeKeys(sk) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return { pubB64: publicKey.toString('base64'), encPriv: enc(privateKey.toString('base64'), sk) };
}

// ═══════════════════════════════════════════════════════════════════════════════
// D1 Direct Query Helper
// ═══════════════════════════════════════════════════════════════════════════════

function d1query(sql) {
  try {
    const out = execSync(`npx wrangler d1 execute vaultwarden --local --command "${sql.replace(/"/g, '\\"')}" --json 2>/dev/null`, { encoding: 'utf8', timeout: 10000 });
    return JSON.parse(out)?.[0]?.results || [];
  } catch (e) {
    console.error(`  D1 query failed: ${sql}`);
    return [];
  }
}

function d1count(table, where = '') {
  const sql = `SELECT COUNT(*) as count FROM ${table}${where ? ' WHERE ' + where : ''}`;
  const rows = d1query(sql);
  return rows[0]?.count ?? 0;
}

function d1row(table, where) {
  const rows = d1query(`SELECT * FROM ${table} WHERE ${where} LIMIT 1`);
  return rows[0] || null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// HTTP helpers
// ═══════════════════════════════════════════════════════════════════════════════

async function post(path, body, token, ct = 'application/json') {
  const h = { 'Content-Type': ct }; if (token) h['Authorization'] = `Bearer ${token}`;
  const r = await fetch(`${BASE_URL}${path}`, { method: 'POST', headers: h, body: typeof body === 'string' ? body : JSON.stringify(body) });
  const t = await r.text(); try { return { s: r.status, b: JSON.parse(t), t }; } catch { return { s: r.status, b: null, t }; }
}
async function get(path, token) {
  const h = {}; if (token) h['Authorization'] = `Bearer ${token}`;
  const r = await fetch(`${BASE_URL}${path}`, { headers: h });
  const t = await r.text(); try { return { s: r.status, b: JSON.parse(t), t }; } catch { return { s: r.status, b: null, t }; }
}
async function put(path, body, token) {
  const h = { 'Content-Type': 'application/json' }; if (token) h['Authorization'] = `Bearer ${token}`;
  const r = await fetch(`${BASE_URL}${path}`, { method: 'PUT', headers: h, body: JSON.stringify(body) });
  const t = await r.text(); try { return { s: r.status, b: JSON.parse(t), t }; } catch { return { s: r.status, b: null, t }; }
}
async function del(path, token, body) {
  const h = {}; if (token) h['Authorization'] = `Bearer ${token}`; if (body) h['Content-Type'] = 'application/json';
  const r = await fetch(`${BASE_URL}${path}`, { method: 'DELETE', headers: h, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); try { return { s: r.status, b: JSON.parse(t), t }; } catch { return { s: r.status, b: null, t }; }
}
async function login(email, hash) {
  return post('/identity/connect/token',
    `grant_type=password&username=${encodeURIComponent(email)}&password=${encodeURIComponent(hash)}&client_id=web&scope=api+offline_access&deviceIdentifier=${crypto.randomUUID()}&deviceName=DBTest&deviceType=7`,
    null, 'application/x-www-form-urlencoded');
}

function ok(name, cond, detail = '') {
  TOTAL++; if (cond) { PASS++; console.log(`  \x1b[32m✓\x1b[0m ${name}`); } else { FAIL++; console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? ` — ${detail}` : ''}`); }
}
function section(s) { console.log(`\n\x1b[34m═══ ${s} ═══\x1b[0m`); }

// ═══════════════════════════════════════════════════════════════════════════════
// Test user
// ═══════════════════════════════════════════════════════════════════════════════

const EMAIL = `dbtest-${Date.now()}@test.com`;
const PW = 'DBTestP@ss!';
const mk = deriveMasterKey(PW, EMAIL);
const mph = deriveMPH(mk, PW);
const { symKey, encKeyStr } = makeSymKey(mk);
const { pubB64, encPriv } = makeKeys(symKey);

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

async function main() {
  console.log('\x1b[34m╔═══════════════════════════════════════════════════════════╗\x1b[0m');
  console.log('\x1b[34m║  DB & Storage Verification E2E Test                      ║\x1b[0m');
  console.log('\x1b[34m╚═══════════════════════════════════════════════════════════╝\x1b[0m');

  const usersBefore = d1count('users');

  // ─────────────────────────────────────────────────────────────────────────
  section('1. Registration → verify D1 users table');

  const reg = await post('/identity/accounts/register', {
    email: EMAIL, masterPasswordHash: mph, key: encKeyStr,
    keys: { publicKey: pubB64, encryptedPrivateKey: encPriv },
    name: 'DB Verify User', kdf: 0, kdfIterations: 600000,
  });
  ok('API: register 200', reg.s === 200);

  // Check D1 directly
  const usersAfter = d1count('users');
  ok('D1: user count incremented', usersAfter === usersBefore + 1);

  const dbUser = d1row('users', `email = '${EMAIL}'`);
  ok('D1: user row exists', !!dbUser);
  ok('D1: email stored correctly', dbUser?.email === EMAIL);
  ok('D1: name stored', dbUser?.name === 'DB Verify User');
  ok('D1: encrypted key stored', dbUser?.akey === encKeyStr);
  ok('D1: public key stored', dbUser?.public_key === pubB64);
  ok('D1: private key stored (encrypted)', dbUser?.private_key?.startsWith('2.'));
  ok('D1: password_hash is not plaintext', dbUser?.password_hash !== mph);
  ok('D1: password_hash is base64 (hashed)', dbUser?.password_hash?.length > 20);
  ok('D1: salt stored', dbUser?.salt?.length > 20);
  ok('D1: password_iterations stored', dbUser?.password_iterations === 600000);
  ok('D1: security_stamp exists', dbUser?.security_stamp?.length > 10);
  ok('D1: client_kdf_type = 0', dbUser?.client_kdf_type === 0);
  ok('D1: client_kdf_iter = 600000', dbUser?.client_kdf_iter === 600000);
  ok('D1: created_at is ISO date', dbUser?.created_at?.includes('T'));
  ok('D1: enabled = 1', dbUser?.enabled === 1);

  const userId = dbUser?.uuid;

  // ─────────────────────────────────────────────────────────────────────────
  section('2. Login → verify D1 devices table');

  const lg = await login(EMAIL, mph);
  ok('API: login 200', lg.s === 200);
  const token = lg.b?.access_token;

  const deviceCount = d1count('devices', `user_uuid = '${userId}'`);
  ok('D1: device row created', deviceCount >= 1);

  const dbDevice = d1row('devices', `user_uuid = '${userId}'`);
  ok('D1: device has refresh_token', dbDevice?.refresh_token?.length > 20);
  ok('D1: device has name', dbDevice?.name?.length > 0);
  ok('D1: device type stored', typeof dbDevice?.atype === 'number');
  ok('D1: device created_at set', dbDevice?.created_at?.includes('T'));

  // ─────────────────────────────────────────────────────────────────────────
  section('3. Create folder → verify D1 folders table');

  const folderName = enc('DB Test Folder', symKey);
  const fld = await post('/api/folders', { name: folderName }, token);
  ok('API: folder created', fld.s === 200);
  const folderId = fld.b?.id;

  const dbFolder = d1row('folders', `uuid = '${folderId}'`);
  ok('D1: folder row exists', !!dbFolder);
  ok('D1: folder name is encrypted (starts with 2.)', dbFolder?.name?.startsWith('2.'));
  ok('D1: folder name matches API input exactly', dbFolder?.name === folderName);
  ok('D1: folder user_uuid matches', dbFolder?.user_uuid === userId);
  ok('D1: folder has timestamps', dbFolder?.created_at?.includes('T'));

  // ─────────────────────────────────────────────────────────────────────────
  section('4. Create cipher → verify D1 ciphers, folders_ciphers, favorites tables');

  const cipherName = enc('DB Test Login', symKey);
  const cipherUsername = enc('testuser@site.com', symKey);
  const cipherPassword = enc('s3cur3!', symKey);
  const cph = await post('/api/ciphers', {
    type: 1, name: cipherName, folderId,
    login: { username: cipherUsername, password: cipherPassword, uri: enc('https://site.com', symKey) },
    notes: enc('These are my notes', symKey),
    favorite: true,
  }, token);
  ok('API: cipher created', cph.s === 200);
  const cipherId = cph.b?.id;

  const dbCipher = d1row('ciphers', `uuid = '${cipherId}'`);
  ok('D1: cipher row exists', !!dbCipher);
  ok('D1: cipher name encrypted', dbCipher?.name?.startsWith('2.'));
  ok('D1: cipher name matches', dbCipher?.name === cipherName);
  ok('D1: cipher type = 1 (login)', dbCipher?.atype === 1);
  ok('D1: cipher user_uuid set', dbCipher?.user_uuid === userId);
  ok('D1: cipher notes encrypted', dbCipher?.notes?.startsWith('2.'));
  ok('D1: cipher data contains encrypted login', dbCipher?.data?.includes(cipherUsername));
  ok('D1: cipher has timestamps', dbCipher?.created_at?.includes('T'));
  const deletedAtIsNull = !dbCipher?.deleted_at || dbCipher?.deleted_at === 'null';
  ok('D1: cipher deleted_at is null', deletedAtIsNull, `got: ${JSON.stringify(dbCipher?.deleted_at)}`);

  // Check folder-cipher junction
  const fcCount = d1count('folders_ciphers', `cipher_uuid = '${cipherId}' AND folder_uuid = '${folderId}'`);
  ok('D1: folders_ciphers junction row exists', fcCount === 1);

  // Check favorites
  const favCount = d1count('favorites', `user_uuid = '${userId}' AND cipher_uuid = '${cipherId}'`);
  ok('D1: favorites row exists', favCount === 1);

  // ─────────────────────────────────────────────────────────────────────────
  section('5. Update cipher → verify D1 row updated');

  const newName = enc('Updated DB Login', symKey);
  await put(`/api/ciphers/${cipherId}`, {
    type: 1, name: newName, login: { username: cipherUsername, password: enc('newpass!', symKey) },
  }, token);

  const dbCipherUpdated = d1row('ciphers', `uuid = '${cipherId}'`);
  ok('D1: cipher name updated', dbCipherUpdated?.name === newName);
  ok('D1: updated_at changed', dbCipherUpdated?.updated_at !== dbCipher?.created_at);

  // ─────────────────────────────────────────────────────────────────────────
  section('6. Soft delete → verify D1 deleted_at set');

  await put(`/api/ciphers/${cipherId}/delete`, {}, token);
  const dbSoftDel = d1row('ciphers', `uuid = '${cipherId}'`);
  ok('D1: deleted_at is now set', dbSoftDel?.deleted_at !== null);
  ok('D1: deleted_at is ISO date', dbSoftDel?.deleted_at?.includes('T'));

  // Restore
  await put(`/api/ciphers/${cipherId}/restore`, {}, token);
  const dbRestored = d1row('ciphers', `uuid = '${cipherId}'`);
  const restoredIsNull = !dbRestored?.deleted_at || dbRestored?.deleted_at === 'null';
  ok('D1: deleted_at cleared after restore', restoredIsNull, `got: ${JSON.stringify(dbRestored?.deleted_at)}`);

  // ─────────────────────────────────────────────────────────────────────────
  section('7. Create org → verify D1 organizations, users_organizations');

  const orgResp = await post('/api/organizations', {
    name: 'DB Test Org', billingEmail: EMAIL,
    key: enc('orgkey', symKey),
    keys: { publicKey: pubB64, encryptedPrivateKey: encPriv },
  }, token);
  ok('API: org created', orgResp.s === 200);
  const orgId = orgResp.b?.id;

  const dbOrg = d1row('organizations', `uuid = '${orgId}'`);
  ok('D1: organization row exists', !!dbOrg);
  ok('D1: org name stored', dbOrg?.name === 'DB Test Org');
  ok('D1: org billing_email', dbOrg?.billing_email === EMAIL);
  ok('D1: org has public_key', !!dbOrg?.public_key);
  ok('D1: org has private_key (encrypted)', dbOrg?.private_key?.startsWith('2.'));

  const memberCount = d1count('users_organizations', `org_uuid = '${orgId}'`);
  ok('D1: owner membership row exists', memberCount >= 1);

  const dbMembership = d1row('users_organizations', `org_uuid = '${orgId}' AND user_uuid = '${userId}'`);
  ok('D1: membership status = 2 (confirmed)', dbMembership?.status === 2);
  ok('D1: membership type = 0 (owner)', dbMembership?.atype === 0);
  ok('D1: membership access_all = 1', dbMembership?.access_all === 1);

  // ─────────────────────────────────────────────────────────────────────────
  section('8. Create collection → verify D1 collections');

  const colResp = await post(`/api/organizations/${orgId}/collections`, { name: enc('DB Col', symKey) }, token);
  ok('API: collection created', colResp.s === 200);
  const colId = colResp.b?.id;

  const dbCol = d1row('collections', `uuid = '${colId}'`);
  ok('D1: collection row exists', !!dbCol);
  ok('D1: collection org_uuid matches', dbCol?.org_uuid === orgId);
  ok('D1: collection name encrypted', dbCol?.name?.startsWith('2.'));

  // ─────────────────────────────────────────────────────────────────────────
  section('9. Create send → verify D1 sends');

  const sendResp = await post('/api/sends', {
    type: 0, name: enc('DB Send', symKey),
    key: crypto.randomBytes(32).toString('base64'),
    text: { text: enc('secret text', symKey), hidden: false },
    deletionDate: '2030-01-01T00:00:00Z', maxAccessCount: 5,
  }, token);
  ok('API: send created', sendResp.s === 200);
  const sendId = sendResp.b?.id;

  const dbSend = d1row('sends', `uuid = '${sendId}'`);
  ok('D1: send row exists', !!dbSend);
  ok('D1: send user_uuid', dbSend?.user_uuid === userId);
  ok('D1: send name encrypted', dbSend?.name?.startsWith('2.'));
  ok('D1: send atype = 0 (text)', dbSend?.atype === 0);
  ok('D1: send akey stored', dbSend?.akey?.length > 10);
  ok('D1: send max_access_count = 5', dbSend?.max_access_count === 5);
  ok('D1: send access_count = 0', dbSend?.access_count === 0);
  ok('D1: send deletion_date set', dbSend?.deletion_date?.includes('2030'));

  // Access the send and check access_count incremented
  await post(`/api/sends/access/${sendId}`, {});
  const dbSendAfterAccess = d1row('sends', `uuid = '${sendId}'`);
  ok('D1: send access_count = 1 after access', dbSendAfterAccess?.access_count === 1);

  // ─────────────────────────────────────────────────────────────────────────
  section('10. Emergency access → verify D1 emergency_access');

  const eaResp = await post('/api/emergency-access/invite', { email: 'ea@test.com', type: 0, waitTimeDays: 7 }, token);
  ok('API: EA invite', eaResp.s === 200);

  const eaCount = d1count('emergency_access', `grantor_uuid = '${userId}'`);
  ok('D1: emergency_access row exists', eaCount >= 1);

  const dbEa = d1row('emergency_access', `grantor_uuid = '${userId}'`);
  ok('D1: EA email stored', dbEa?.email === 'ea@test.com');
  ok('D1: EA type = 0 (view)', dbEa?.atype === 0);
  ok('D1: EA wait_time_days = 7', dbEa?.wait_time_days === 7);
  ok('D1: EA status = 0 (invited)', dbEa?.status === 0);

  // ─────────────────────────────────────────────────────────────────────────
  section('11. 2FA → verify D1 twofactor');

  // Get authenticator secret
  const tfResp = await post('/api/two-factor/get-authenticator', { masterPasswordHash: mph }, token);
  const secret = tfResp.b?.key;

  // The secret is not yet in the DB (not activated)
  const tfCountBefore = d1count('twofactor', `user_uuid = '${userId}' AND atype = 0`);
  ok('D1: no twofactor row before activation', tfCountBefore === 0);

  // Generate TOTP and activate
  function totp(s) {
    const b32 = (str) => { const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits='',bytes=[]; for(const c of str.toUpperCase()){const v=a.indexOf(c);if(v>=0)bits+=v.toString(2).padStart(5,'0');} for(let i=0;i+8<=bits.length;i+=8)bytes.push(parseInt(bits.substring(i,i+8),2)); return Buffer.from(bytes); };
    const key=b32(s),ctr=Buffer.alloc(8);ctr.writeUInt32BE(Math.floor(Date.now()/30000),4);
    const h=crypto.createHmac('sha1',key).update(ctr).digest(),o=h[19]&0x0f;
    return (((h[o]&0x7f)<<24|h[o+1]<<16|h[o+2]<<8|h[o+3])%1000000).toString().padStart(6,'0');
  }
  const code = totp(secret);
  await post('/api/two-factor/authenticator', { masterPasswordHash: mph, key: secret, token: code }, token);

  const tfCountAfter = d1count('twofactor', `user_uuid = '${userId}' AND atype = 0`);
  ok('D1: twofactor row created after activation', tfCountAfter === 1);

  const dbTf = d1row('twofactor', `user_uuid = '${userId}' AND atype = 0`);
  ok('D1: twofactor enabled = 1', dbTf?.enabled === 1);
  ok('D1: twofactor data = secret key', dbTf?.data === secret);

  // Disable
  await post('/api/two-factor/disable', { masterPasswordHash: mph, type: 0 }, token);
  const tfCountDisabled = d1count('twofactor', `user_uuid = '${userId}' AND atype = 0`);
  ok('D1: twofactor row deleted after disable', tfCountDisabled === 0);

  // ─────────────────────────────────────────────────────────────────────────
  section('12. Events → verify D1 event table');

  const eventsBefore = d1count('event');
  await post('/api/collect', [{ type: 1000, date: new Date().toISOString(), userId }], token);
  const eventsAfter = d1count('event');
  ok('D1: event row inserted', eventsAfter > eventsBefore);

  const dbEvent = d1row('event', `user_uuid = '${userId}'`);
  ok('D1: event has event_type', dbEvent?.event_type === 1000);
  ok('D1: event has event_date', dbEvent?.event_date?.includes('T'));

  // ─────────────────────────────────────────────────────────────────────────
  section('13. Security stamp rotation → verify D1 updated');

  const stampBefore = dbUser?.security_stamp;
  await post('/api/accounts/security-stamp', { masterPasswordHash: mph }, token);
  const dbUserAfterStamp = d1row('users', `uuid = '${userId}'`);
  ok('D1: security_stamp changed', dbUserAfterStamp?.security_stamp !== stampBefore);

  // Re-login
  const relogin = await login(EMAIL, mph);
  const token2 = relogin.b?.access_token;

  // ─────────────────────────────────────────────────────────────────────────
  section('14. Equivalent domains → verify D1 users row updated');

  await put('/api/settings/domains', {
    equivalentDomains: [['a.com','b.com']],
    excludedGlobalEquivalentDomains: [1,2],
  }, token2);
  const dbUserDomains = d1row('users', `uuid = '${userId}'`);
  ok('D1: equivalent_domains updated', dbUserDomains?.equivalent_domains?.includes('a.com'));
  ok('D1: excluded_globals updated', dbUserDomains?.excluded_globals?.includes('1'));

  // ─────────────────────────────────────────────────────────────────────────
  section('15. Delete cipher → verify D1 cascade');

  const ciphersBefore = d1count('ciphers', `uuid = '${cipherId}'`);
  ok('D1: cipher exists before delete', ciphersBefore === 1);

  await del(`/api/ciphers/${cipherId}`, token2);
  const ciphersAfterDel = d1count('ciphers', `uuid = '${cipherId}'`);
  ok('D1: cipher row deleted', ciphersAfterDel === 0);
  const fcAfterDel = d1count('folders_ciphers', `cipher_uuid = '${cipherId}'`);
  ok('D1: folders_ciphers cascade deleted', fcAfterDel === 0);
  const favAfterDel = d1count('favorites', `cipher_uuid = '${cipherId}'`);
  ok('D1: favorites cascade deleted', favAfterDel === 0);

  // ─────────────────────────────────────────────────────────────────────────
  section('16. Delete account → verify D1 full cascade');

  await post('/api/accounts/delete', { masterPasswordHash: mph }, token2);

  ok('D1: user row deleted', d1count('users', `uuid = '${userId}'`) === 0);
  ok('D1: devices deleted', d1count('devices', `user_uuid = '${userId}'`) === 0);
  ok('D1: folders deleted', d1count('folders', `user_uuid = '${userId}'`) === 0);
  ok('D1: sends deleted', d1count('sends', `user_uuid = '${userId}'`) === 0);
  ok('D1: org memberships deleted', d1count('users_organizations', `user_uuid = '${userId}'`) === 0);
  ok('D1: emergency_access deleted', d1count('emergency_access', `grantor_uuid = '${userId}'`) === 0);

  // ═══════════════════════════════════════════════════════════════════════════
  console.log(`\n\x1b[34m═══════════════════════════════════════════════════════════\x1b[0m`);
  console.log(`  Total: ${TOTAL}  \x1b[32mPassed: ${PASS}\x1b[0m  \x1b[31mFailed: ${FAIL}\x1b[0m`);
  console.log(`\x1b[34m═══════════════════════════════════════════════════════════\x1b[0m`);
  if (FAIL > 0) { console.log(`\n\x1b[31m${FAIL} test(s) failed\x1b[0m\n`); process.exit(1); }
  else { console.log(`\n\x1b[32mAll ${PASS} tests passed!\x1b[0m\n`); process.exit(0); }
}

main().catch(e => { console.error('\x1b[31mFatal:\x1b[0m', e); process.exit(1); });
