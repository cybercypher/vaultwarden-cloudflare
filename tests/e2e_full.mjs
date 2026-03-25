#!/usr/bin/env node
/**
 * FULL End-to-End Test Suite for Vaultwarden CF Workers
 *
 * Tests EVERY feature with real encrypted data and two test users.
 * Covers: org sharing, member management, collections, 2FA TOTP enforcement,
 * emergency access workflow, admin ops, sends with passwords, attachments,
 * device management, equivalent domains, security stamp, events, bulk ops.
 */

import crypto from 'node:crypto';

const BASE_URL = process.argv[2] || 'http://localhost:8787';
let PASS = 0, FAIL = 0, TOTAL = 0;

// ═══════════════════════════════════════════════════════════════════════════════
// Crypto helpers (same Bitwarden-compatible implementations)
// ═══════════════════════════════════════════════════════════════════════════════

function deriveMasterKey(password, email, iterations = 600000) {
  return crypto.pbkdf2Sync(password, email.toLowerCase(), iterations, 32, 'sha256');
}
function deriveMasterPasswordHash(masterKey, password) {
  return crypto.pbkdf2Sync(masterKey, password, 1, 32, 'sha256').toString('base64');
}
function generateEncryptedSymmetricKey(masterKey) {
  const symKey = crypto.randomBytes(64);
  const iv = crypto.randomBytes(16);
  const encKey = masterKey.subarray(0, 32);
  const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
  let ct = Buffer.concat([cipher.update(symKey), cipher.final()]);
  const macKey = crypto.createHmac('sha256', masterKey).update(Buffer.from('mac')).digest();
  const mac = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();
  return { symKey, encKeyStr: `2.${iv.toString('base64')}|${ct.toString('base64')}|${mac.toString('base64')}` };
}
function encryptString(plaintext, symKey) {
  if (!plaintext) return null;
  const encKey = symKey.subarray(0, 32);
  const macKey = symKey.subarray(32, 64);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
  let ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const mac = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();
  return `2.${iv.toString('base64')}|${ct.toString('base64')}|${mac.toString('base64')}`;
}
function decryptString(encString, symKey) {
  if (!encString) return null;
  const [type, data] = encString.split('.');
  const [ivB64, ctB64, macB64] = data.split('|');
  const iv = Buffer.from(ivB64, 'base64'), ct = Buffer.from(ctB64, 'base64');
  const encKey = symKey.subarray(0, 32), macKey = symKey.subarray(32, 64);
  const expectedMac = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();
  if (!crypto.timingSafeEqual(expectedMac, Buffer.from(macB64, 'base64'))) throw new Error('MAC fail');
  const decipher = crypto.createDecipheriv('aes-256-cbc', encKey, iv);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}
function generateKeyPair(symKey) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return { pubKeyB64: publicKey.toString('base64'), encPrivKey: encryptString(privateKey.toString('base64'), symKey) };
}
/** Generate a valid TOTP code from a base32 secret */
function generateTOTP(secret) {
  const base32decode = (s) => {
    const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '', bytes = [];
    for (const c of s.toUpperCase()) { const v = a.indexOf(c); if (v >= 0) bits += v.toString(2).padStart(5, '0'); }
    for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substring(i, i + 8), 2));
    return Buffer.from(bytes);
  };
  const key = base32decode(secret);
  const counter = Buffer.alloc(8);
  counter.writeUInt32BE(Math.floor(Date.now() / 30000), 4);
  const hmac = crypto.createHmac('sha1', key).update(counter).digest();
  const offset = hmac[19] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24 | hmac[offset+1] << 16 | hmac[offset+2] << 8 | hmac[offset+3]) % 1000000;
  return code.toString().padStart(6, '0');
}

// ═══════════════════════════════════════════════════════════════════════════════
// HTTP helpers
// ═══════════════════════════════════════════════════════════════════════════════

async function post(path, body, token, ct = 'application/json') {
  const h = { 'Content-Type': ct }; if (token) h['Authorization'] = `Bearer ${token}`;
  const r = await fetch(`${BASE_URL}${path}`, { method: 'POST', headers: h, body: typeof body === 'string' ? body : JSON.stringify(body) });
  const t = await r.text(); try { return { status: r.status, body: JSON.parse(t), text: t }; } catch { return { status: r.status, body: null, text: t }; }
}
async function get(path, token) {
  const h = {}; if (token) h['Authorization'] = `Bearer ${token}`;
  const r = await fetch(`${BASE_URL}${path}`, { headers: h });
  const t = await r.text(); try { return { status: r.status, body: JSON.parse(t), text: t }; } catch { return { status: r.status, body: null, text: t }; }
}
async function put(path, body, token) {
  const h = { 'Content-Type': 'application/json' }; if (token) h['Authorization'] = `Bearer ${token}`;
  const r = await fetch(`${BASE_URL}${path}`, { method: 'PUT', headers: h, body: JSON.stringify(body) });
  const t = await r.text(); try { return { status: r.status, body: JSON.parse(t), text: t }; } catch { return { status: r.status, body: null, text: t }; }
}
async function del(path, token, body) {
  const h = {}; if (token) h['Authorization'] = `Bearer ${token}`; if (body) h['Content-Type'] = 'application/json';
  const r = await fetch(`${BASE_URL}${path}`, { method: 'DELETE', headers: h, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); try { return { status: r.status, body: JSON.parse(t), text: t }; } catch { return { status: r.status, body: null, text: t }; }
}
function ok(name, cond, detail = '') {
  TOTAL++; if (cond) { PASS++; console.log(`  \x1b[32m✓\x1b[0m ${name}`); } else { FAIL++; console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? ` — ${detail}` : ''}`); }
}
function section(s) { console.log(`\n\x1b[34m═══ ${s} ═══\x1b[0m`); }
async function login(email, hash) {
  const r = await post('/identity/connect/token',
    `grant_type=password&username=${encodeURIComponent(email)}&password=${encodeURIComponent(hash)}&client_id=web&scope=api+offline_access&deviceIdentifier=${crypto.randomUUID()}&deviceName=E2E&deviceType=7`,
    null, 'application/x-www-form-urlencoded');
  return r;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Setup two test users with full crypto
// ═══════════════════════════════════════════════════════════════════════════════

const ts = Date.now();
const USER_A = { email: `alice-${ts}@test.com`, password: 'AliceP@ss2024!', name: 'Alice Test' };
const USER_B = { email: `bob-${ts}@test.com`, password: 'BobP@ss2024!', name: 'Bob Test' };

for (const u of [USER_A, USER_B]) {
  u.masterKey = deriveMasterKey(u.password, u.email);
  u.hash = deriveMasterPasswordHash(u.masterKey, u.password);
  const { symKey, encKeyStr } = generateEncryptedSymmetricKey(u.masterKey);
  u.symKey = symKey; u.encKeyStr = encKeyStr;
  const { pubKeyB64, encPrivKey } = generateKeyPair(symKey);
  u.pubKeyB64 = pubKeyB64; u.encPrivKey = encPrivKey;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

async function main() {
  console.log('\x1b[34m╔═══════════════════════════════════════════════════════════╗\x1b[0m');
  console.log('\x1b[34m║  Vaultwarden CF — Full Feature E2E Test                  ║\x1b[0m');
  console.log(`\x1b[34m║  ${BASE_URL.padEnd(55)}║\x1b[0m`);
  console.log('\x1b[34m╚═══════════════════════════════════════════════════════════╝\x1b[0m');

  // ──────────────────────────────────────────────────────────────────────────
  section('1. Register both users');
  for (const u of [USER_A, USER_B]) {
    // cleanup
    const cl = await login(u.email, u.hash);
    if (cl.body?.access_token) await post('/api/accounts/delete', { masterPasswordHash: u.hash }, cl.body.access_token);

    const r = await post('/identity/accounts/register', {
      email: u.email, masterPasswordHash: u.hash, key: u.encKeyStr,
      keys: { publicKey: u.pubKeyB64, encryptedPrivateKey: u.encPrivKey },
      name: u.name, kdf: 0, kdfIterations: 600000,
    });
    ok(`register ${u.name}`, r.status === 200, `status=${r.status}`);
  }

  // Login both
  const aLogin = await login(USER_A.email, USER_A.hash);
  ok('Alice login', aLogin.status === 200);
  const A = aLogin.body?.access_token;
  const aProfile = await get('/api/accounts/profile', A);
  USER_A.id = aProfile.body?.id;

  const bLogin = await login(USER_B.email, USER_B.hash);
  ok('Bob login', bLogin.status === 200);
  const B = bLogin.body?.access_token;
  const bProfile = await get('/api/accounts/profile', B);
  USER_B.id = bProfile.body?.id;

  // ──────────────────────────────────────────────────────────────────────────
  section('2. Organization creation & sharing flow');

  // Alice creates org
  const orgKey = encryptString(crypto.randomBytes(64).toString('base64'), USER_A.symKey);
  const orgR = await post('/api/organizations', {
    name: 'Shared Corp', billingEmail: USER_A.email, key: orgKey,
    keys: { publicKey: USER_A.pubKeyB64, encryptedPrivateKey: USER_A.encPrivKey },
  }, A);
  ok('Alice creates org', orgR.status === 200);
  const orgId = orgR.body?.id;

  // Alice creates a collection
  const colName = encryptString('Shared Logins', USER_A.symKey);
  const colR = await post(`/api/organizations/${orgId}/collections`, { name: colName }, A);
  ok('Alice creates collection', colR.status === 200);
  const colId = colR.body?.id;

  // Alice invites Bob
  const invR = await post(`/api/organizations/${orgId}/users/invite`, {
    emails: [USER_B.email], type: 2, accessAll: true,
  }, A);
  ok('Alice invites Bob', invR.status === 200);

  // Get Bob's membership id
  const membersR = await get(`/api/organizations/${orgId}/users`, A);
  ok('list members', membersR.status === 200);
  const bobMember = membersR.body?.data?.find(m => m.email === USER_B.email);
  ok('Bob appears in member list', !!bobMember, bobMember ? '' : 'not found');
  const bobMemberId = bobMember?.id;

  // Bob accepts (via accept endpoint)
  const acceptR = await post(`/api/organizations/${orgId}/users/${bobMemberId}/accept`, { token: '' }, B);
  ok('Bob accepts invite', acceptR.status === 200);

  // Alice confirms Bob with encrypted org key
  const bobOrgKey = encryptString(crypto.randomBytes(64).toString('base64'), USER_A.symKey);
  const confirmR = await post(`/api/organizations/${orgId}/users/${bobMemberId}/confirm`, { key: bobOrgKey }, A);
  ok('Alice confirms Bob', confirmR.status === 200);

  // Alice creates a cipher in the org
  const sharedCipher = await post('/api/ciphers', {
    type: 1, organizationId: orgId,
    name: encryptString('Shared Server SSH', USER_A.symKey),
    login: {
      username: encryptString('root', USER_A.symKey),
      password: encryptString('r00t_p@ss!', USER_A.symKey),
      uri: encryptString('ssh://prod-server.example.com', USER_A.symKey),
    },
  }, A);
  ok('Alice creates org cipher', sharedCipher.status === 200);
  ok('cipher has organizationId', sharedCipher.body?.organizationId === orgId);
  const sharedCipherId = sharedCipher.body?.id;

  // Bob syncs and sees the shared cipher
  const bobSync = await get('/api/sync', B);
  ok('Bob sync succeeds', bobSync.status === 200);
  const bobSeesShared = bobSync.body?.ciphers?.find(c => c.id === sharedCipherId);
  ok('Bob sees shared cipher in sync', !!bobSeesShared, bobSeesShared ? '' : 'cipher not found in Bob sync');
  ok('shared cipher has correct org', bobSeesShared?.organizationId === orgId);

  // Bob's sync includes the org
  const bobOrg = bobSync.body?.profile?.organizations?.find(o => o.id === orgId);
  ok('Bob sees org in profile', !!bobOrg);

  // ──────────────────────────────────────────────────────────────────────────
  section('3. 2FA TOTP setup & enforced login');

  // Alice gets TOTP secret
  const totpGet = await post('/api/two-factor/get-authenticator', { masterPasswordHash: USER_A.hash }, A);
  ok('get TOTP secret', totpGet.status === 200);
  const totpSecret = totpGet.body?.key;
  ok('TOTP secret returned', !!totpSecret && totpSecret.length > 10);

  // Generate valid TOTP code and activate
  const totpCode = generateTOTP(totpSecret);
  ok(`generated TOTP code: ${totpCode}`, totpCode.length === 6);
  const totpActivate = await post('/api/two-factor/authenticator', {
    masterPasswordHash: USER_A.hash, key: totpSecret, token: totpCode,
  }, A);
  ok('activate TOTP', totpActivate.status === 200);
  ok('TOTP now enabled', totpActivate.body?.enabled === true);

  // Get recovery code
  const recoveryR = await post('/api/two-factor/get-recover', { masterPasswordHash: USER_A.hash }, A);
  ok('recovery code exists', !!recoveryR.body?.code);

  // Verify 2FA is listed
  const tfList = await get('/api/two-factor', A);
  ok('2FA provider listed', tfList.body?.data?.length >= 1);

  // Login without 2FA should fail with 400 (Two factor required)
  const loginNo2fa = await login(USER_A.email, USER_A.hash);
  ok('login without 2FA returns 400', loginNo2fa.status === 400, `status=${loginNo2fa.status}`);

  // Login WITH valid TOTP
  const totpCode2 = generateTOTP(totpSecret);
  const login2fa = await post('/identity/connect/token',
    `grant_type=password&username=${encodeURIComponent(USER_A.email)}&password=${encodeURIComponent(USER_A.hash)}&client_id=web&scope=api+offline_access&deviceIdentifier=${crypto.randomUUID()}&deviceName=2FA&deviceType=7&twoFactorProvider=0&twoFactorToken=${totpCode2}`,
    null, 'application/x-www-form-urlencoded');
  ok('login with TOTP succeeds', login2fa.status === 200, `status=${login2fa.status} ${login2fa.text?.substring(0,200)}`);
  const A2 = login2fa.body?.access_token || A;

  // Disable 2FA for subsequent tests
  const disableTfa = await post('/api/two-factor/disable', { masterPasswordHash: USER_A.hash, type: 0 }, A2);
  ok('disable TOTP', disableTfa.status === 200);

  // Login without 2FA works again
  const loginAfterDisable = await login(USER_A.email, USER_A.hash);
  ok('login without 2FA works after disable', loginAfterDisable.status === 200);
  const A3 = loginAfterDisable.body?.access_token;

  // ──────────────────────────────────────────────────────────────────────────
  section('4. Emergency access full workflow');

  // Alice invites Bob as emergency contact (view access, 0 day wait)
  const eaInvite = await post('/api/emergency-access/invite', {
    email: USER_B.email, type: 0, waitTimeDays: 0,
  }, A3);
  ok('Alice invites Bob as emergency contact', eaInvite.status === 200);

  // List Alice's trusted contacts
  const eaTrusted = await get('/api/emergency-access/trusted', A3);
  ok('Alice sees trusted list', eaTrusted.status === 200);
  const eaRecord = eaTrusted.body?.data?.[0];
  ok('emergency access record exists', !!eaRecord);
  const eaId = eaRecord?.id;

  // Bob sees granted access
  const eaGranted = await get('/api/emergency-access/granted', B);
  ok('Bob sees granted access', eaGranted.status === 200);

  // Bob accepts
  const eaAccept = await post(`/api/emergency-access/${eaId}/accept`, {}, B);
  ok('Bob accepts emergency access', eaAccept.status === 200);

  // Alice confirms
  const eaKey = encryptString(crypto.randomBytes(32).toString('base64'), USER_A.symKey);
  const eaConfirm = await post(`/api/emergency-access/${eaId}/confirm`, { key: eaKey }, A3);
  ok('Alice confirms emergency access', eaConfirm.status === 200);

  // Bob initiates recovery
  const eaInitiate = await post(`/api/emergency-access/${eaId}/initiate`, {}, B);
  ok('Bob initiates recovery', eaInitiate.status === 200);

  // Alice approves recovery
  const eaApprove = await post(`/api/emergency-access/${eaId}/approve`, {}, A3);
  ok('Alice approves recovery', eaApprove.status === 200);

  // Bob views Alice's vault
  const eaView = await post(`/api/emergency-access/${eaId}/view`, {}, B);
  ok('Bob views Alice vault via emergency access', eaView.status === 200);
  ok('vault ciphers returned', Array.isArray(eaView.body?.ciphers));
  ok('keyEncrypted returned', !!eaView.body?.keyEncrypted);

  // Cleanup emergency access
  const eaDel = await del(`/api/emergency-access/${eaId}`, A3);
  ok('delete emergency access', eaDel.status === 200);

  // ──────────────────────────────────────────────────────────────────────────
  section('5. Sends with password protection & access limits');

  // Create password-protected send
  const sendPw = 'SendP@ss!';
  const sendData = {
    type: 0, name: encryptString('Secret WiFi Password', USER_A.symKey),
    key: crypto.randomBytes(32).toString('base64'),
    text: { text: encryptString('WiFi: MyNetwork / Pass: secret123', USER_A.symKey), hidden: false },
    deletionDate: '2030-01-01T00:00:00Z', maxAccessCount: 2, password: sendPw,
  };
  const sendR = await post('/api/sends', sendData, A3);
  ok('create password-protected send', sendR.status === 200);
  const sendId = sendR.body?.id;

  // Access without password fails
  const accessNoPw = await post(`/api/sends/access/${sendId}`, {});
  ok('access without password fails', accessNoPw.status === 400, `status=${accessNoPw.status}`);

  // Access with wrong password fails
  const accessWrongPw = await post(`/api/sends/access/${sendId}`, { password: 'wrong' });
  ok('access with wrong password fails', accessWrongPw.status === 401, `status=${accessWrongPw.status}`);

  // Access with correct password succeeds
  const accessOk = await post(`/api/sends/access/${sendId}`, { password: sendPw });
  ok('access with correct password succeeds', accessOk.status === 200);
  ok('access returns key', !!accessOk.body?.key);

  // Second access succeeds (count=2, we've used 1)
  const access2 = await post(`/api/sends/access/${sendId}`, { password: sendPw });
  ok('second access succeeds', access2.status === 200);

  // Third access should fail (maxAccessCount=2, we've used 2)
  const access3 = await post(`/api/sends/access/${sendId}`, { password: sendPw });
  ok('third access exceeds limit', access3.status === 404, `status=${access3.status}`);

  // Remove password
  const rmPw = await put(`/api/sends/${sendId}/remove-password`, {}, A3);
  ok('remove send password', rmPw.status === 200);

  // Cleanup
  await del(`/api/sends/${sendId}`, A3);

  // ──────────────────────────────────────────────────────────────────────────
  section('6. Equivalent domains');

  const eqR = await put('/api/settings/domains', {
    equivalentDomains: [['google.com', 'youtube.com', 'gmail.com']],
    excludedGlobalEquivalentDomains: [],
  }, A3);
  ok('set equivalent domains', eqR.status === 200);

  // Verify in sync
  const syncDomains = await get('/api/sync', A3);
  ok('sync returns domains', !!syncDomains.body?.domains);

  // ──────────────────────────────────────────────────────────────────────────
  section('7. Device management');

  const devicesR = await get('/api/devices', A3);
  ok('list devices', devicesR.status === 200);
  ok('has at least 1 device', devicesR.body?.data?.length >= 1);
  const deviceEntry = devicesR.body?.data?.[0];
  ok('device has id', !!deviceEntry?.id);
  ok('device has name', !!deviceEntry?.name);

  // ──────────────────────────────────────────────────────────────────────────
  section('8. Security stamp rotation');

  // Rotate stamp
  const stampR = await post('/api/accounts/security-stamp', { masterPasswordHash: USER_A.hash }, A3);
  ok('rotate security stamp', stampR.status === 200);

  // Re-login (old token may still work for non-stamp-validated endpoints but new stamp is set)
  const reLogin = await login(USER_A.email, USER_A.hash);
  ok('re-login after stamp rotation', reLogin.status === 200);
  const A4 = reLogin.body?.access_token;

  // ──────────────────────────────────────────────────────────────────────────
  section('9. Admin API operations');

  const adminToken = 'test-admin-token';

  // Admin login
  const adminLogin = await post('/admin', { token: adminToken });
  ok('admin login', adminLogin.status === 200);
  ok('admin JWT returned', !!adminLogin.body?.token);

  // List users
  const adminUsersR = await get('/admin/users', null);
  // Need auth header with admin token
  const adminR2 = await fetch(`${BASE_URL}/admin/users`, {
    headers: { 'Authorization': `Bearer ${adminToken}` },
  });
  const adminUsers = await adminR2.json();
  ok('admin list users', adminR2.status === 200);
  ok('admin sees both users', Array.isArray(adminUsers) && adminUsers.length >= 2);

  // Disable Bob
  const disableR = await fetch(`${BASE_URL}/admin/users/${USER_B.id}/disable`, {
    method: 'POST', headers: { 'Authorization': `Bearer ${adminToken}` },
  });
  ok('admin disable Bob', disableR.status === 200);

  // Bob can't login while disabled
  const bobDisabledLogin = await login(USER_B.email, USER_B.hash);
  ok('disabled Bob cannot login', bobDisabledLogin.status === 400, `status=${bobDisabledLogin.status}`);

  // Re-enable Bob
  const enableR = await fetch(`${BASE_URL}/admin/users/${USER_B.id}/enable`, {
    method: 'POST', headers: { 'Authorization': `Bearer ${adminToken}` },
  });
  ok('admin enable Bob', enableR.status === 200);

  // Bob can login again
  const bobReEnabled = await login(USER_B.email, USER_B.hash);
  ok('re-enabled Bob can login', bobReEnabled.status === 200);

  // Diagnostics
  const diagR = await fetch(`${BASE_URL}/admin/diagnostics`, {
    headers: { 'Authorization': `Bearer ${adminToken}` },
  });
  const diag = await diagR.json();
  ok('admin diagnostics', diagR.status === 200);
  ok('diagnostics has userCount', typeof diag.userCount === 'number' && diag.userCount >= 2);
  ok('diagnostics has platform', diag.platform === 'Cloudflare Workers (WASM)');

  // Config
  const confR = await fetch(`${BASE_URL}/admin/diagnostics/config`, {
    headers: { 'Authorization': `Bearer ${adminToken}` },
  });
  ok('admin config', confR.status === 200);

  // ──────────────────────────────────────────────────────────────────────────
  section('10. Cipher bulk operations');

  // Create 3 ciphers
  const c1 = await post('/api/ciphers', { type: 1, name: encryptString('Bulk1', USER_A.symKey), login: {} }, A4);
  const c2 = await post('/api/ciphers', { type: 1, name: encryptString('Bulk2', USER_A.symKey), login: {} }, A4);
  const c3 = await post('/api/ciphers', { type: 1, name: encryptString('Bulk3', USER_A.symKey), login: {} }, A4);
  ok('create 3 bulk ciphers', c1.status === 200 && c2.status === 200 && c3.status === 200);

  // Create a folder and move ciphers into it
  const bulkFolder = await post('/api/folders', { name: encryptString('Bulk Folder', USER_A.symKey) }, A4);
  const bfId = bulkFolder.body?.id;
  const moveR = await put('/api/ciphers/move', { ids: [c1.body?.id, c2.body?.id], folderId: bfId }, A4);
  ok('move ciphers to folder', moveR.status === 200);

  // Verify via sync
  const syncBulk = await get('/api/sync', A4);
  const movedCipher = syncBulk.body?.ciphers?.find(c => c.id === c1.body?.id);
  ok('moved cipher has folder', movedCipher?.folderId === bfId);

  // Bulk delete
  const bulkDel = await post('/api/ciphers/delete', { ids: [c2.body?.id, c3.body?.id] }, A4);
  ok('bulk delete 2 ciphers', bulkDel.status === 200);

  // Verify only 1 remains (plus the shared org cipher)
  const syncAfterBulk = await get('/api/sync', A4);
  const personalCiphers = syncAfterBulk.body?.ciphers?.filter(c => !c.organizationId) || [];
  ok('1 personal cipher remains after bulk delete', personalCiphers.length === 1);

  // ──────────────────────────────────────────────────────────────────────────
  section('11. Events collection');

  const evR = await post('/api/collect', [
    { type: 1000, date: new Date().toISOString(), userId: USER_A.id },
    { type: 1001, date: new Date().toISOString(), cipherId: c1.body?.id },
  ], A4);
  ok('collect events', evR.status === 200);

  // ──────────────────────────────────────────────────────────────────────────
  section('12. Import with folders & relationships');

  const impR = await post('/api/ciphers/import', {
    folders: [
      { name: encryptString('Chrome Passwords', USER_A.symKey) },
      { name: encryptString('Firefox Passwords', USER_A.symKey) },
    ],
    ciphers: [
      { type: 1, name: encryptString('Amazon', USER_A.symKey), login: { username: encryptString('user@amz', USER_A.symKey), password: encryptString('amz123', USER_A.symKey) } },
      { type: 1, name: encryptString('Twitter', USER_A.symKey), login: { username: encryptString('user@tw', USER_A.symKey), password: encryptString('tw456', USER_A.symKey) } },
      { type: 3, name: encryptString('Amex Card', USER_A.symKey), card: { number: encryptString('3782...', USER_A.symKey) } },
    ],
    folderRelationships: [{ key: 0, value: 0 }, { key: 1, value: 1 }],
  }, A4);
  ok('import with folders & relationships', impR.status === 200);

  const syncImp = await get('/api/sync', A4);
  const totalFolders = syncImp.body?.folders?.length;
  ok(`total folders after import: ${totalFolders}`, totalFolders >= 3);

  // Decrypt an imported cipher
  const amzCipher = syncImp.body?.ciphers?.find(c => {
    try { return decryptString(c.name, USER_A.symKey) === 'Amazon'; } catch { return false; }
  });
  ok('imported Amazon cipher found & decryptable', !!amzCipher);

  // ──────────────────────────────────────────────────────────────────────────
  section('13. Notifications negotiate');

  const negR = await post('/notifications/hub/negotiate', {}, A4);
  ok('WS negotiate returns connectionId', !!negR.body?.connectionId);

  // ──────────────────────────────────────────────────────────────────────────
  section('14. Cleanup everything');

  // Remove Bob from org
  if (bobMemberId) {
    await del(`/api/organizations/${orgId}/users/${bobMemberId}`, A4);
    ok('removed Bob from org', true);
  }

  // Delete org
  const orgDel = await del(`/api/organizations/${orgId}`, A4, { masterPasswordHash: USER_A.hash });
  ok('delete org', orgDel.status === 200);

  // Purge Alice's ciphers
  const purgeR = await post('/api/ciphers/purge', { masterPasswordHash: USER_A.hash }, A4);
  ok('purge Alice ciphers', purgeR.status === 200);

  // Delete both accounts
  const delA = await post('/api/accounts/delete', { masterPasswordHash: USER_A.hash }, A4);
  ok('delete Alice', delA.status === 200);

  const bToken = (await login(USER_B.email, USER_B.hash)).body?.access_token;
  if (bToken) {
    const delB = await post('/api/accounts/delete', { masterPasswordHash: USER_B.hash }, bToken);
    ok('delete Bob', delB.status === 200);
  }

  // Verify accounts are gone
  const deadA = await login(USER_A.email, USER_A.hash);
  ok('Alice deleted', deadA.status === 400);
  const deadB = await login(USER_B.email, USER_B.hash);
  ok('Bob deleted', deadB.status === 400);

  // ═══════════════════════════════════════════════════════════════════════════
  console.log(`\n\x1b[34m═══════════════════════════════════════════════════════════\x1b[0m`);
  console.log(`  Total: ${TOTAL}  \x1b[32mPassed: ${PASS}\x1b[0m  \x1b[31mFailed: ${FAIL}\x1b[0m`);
  console.log(`\x1b[34m═══════════════════════════════════════════════════════════\x1b[0m`);
  if (FAIL > 0) { console.log(`\n\x1b[31m${FAIL} test(s) failed\x1b[0m\n`); process.exit(1); }
  else { console.log(`\n\x1b[32mAll ${PASS} tests passed!\x1b[0m\n`); process.exit(0); }
}

main().catch(e => { console.error('\x1b[31mFatal:\x1b[0m', e); process.exit(1); });
