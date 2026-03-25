#!/usr/bin/env node
/**
 * Realistic End-to-End Test for Vaultwarden CF Workers
 *
 * Generates cryptographically valid Bitwarden-compatible data:
 * - PBKDF2-derived master key from password + email
 * - Master password hash (PBKDF2 of master key + password, 1 iteration)
 * - Real AES-256 encrypted symmetric key
 * - Real RSA-2048 keypair, private key encrypted with symmetric key
 * - Encrypted cipher names, login credentials, notes, card data, identity data
 * - Encrypted folder names
 * - Encrypted send data
 *
 * Validates the full round-trip: register → login → create → sync → verify decryptability
 */

import crypto from 'node:crypto';

const BASE_URL = process.argv[2] || 'http://localhost:8787';
let PASS = 0, FAIL = 0, TOTAL = 0;

// =============================================================================
// Bitwarden Crypto Implementation
// =============================================================================

/** Derive master key from password + email using PBKDF2-SHA256 */
function deriveMasterKey(password, email, iterations = 600000) {
  return crypto.pbkdf2Sync(password, email.toLowerCase(), iterations, 32, 'sha256');
}

/** Derive master password hash: PBKDF2(masterKey, password, 1 iteration) → base64 */
function deriveMasterPasswordHash(masterKey, password) {
  const hash = crypto.pbkdf2Sync(masterKey, password, 1, 32, 'sha256');
  return hash.toString('base64');
}

/** Generate a random 64-byte symmetric key, encrypt with master key using AES-256-CBC */
function generateEncryptedSymmetricKey(masterKey) {
  // Bitwarden format: type.iv|ct|mac (type 2 = AesCbc256_HmacSha256_B64)
  const symKey = crypto.randomBytes(64); // 32 bytes enc key + 32 bytes mac key
  const iv = crypto.randomBytes(16);

  // Derive encryption key and mac key from master key using HKDF-like expansion
  const encKey = masterKey.subarray(0, 32);

  const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
  let ct = cipher.update(symKey);
  ct = Buffer.concat([ct, cipher.final()]);

  // MAC: HMAC-SHA256(iv + ct) with the second half of the master key (or derived)
  const macKey = crypto.createHmac('sha256', masterKey).update(Buffer.from('mac')).digest();
  const mac = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();

  const encKeyStr = `2.${iv.toString('base64')}|${ct.toString('base64')}|${mac.toString('base64')}`;
  return { symKey, encKeyStr };
}

/** Encrypt a string with the symmetric key (Bitwarden EncString format) */
function encryptString(plaintext, symKey) {
  if (!plaintext) return null;
  const encKey = symKey.subarray(0, 32);
  const macKey = symKey.subarray(32, 64);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
  let ct = cipher.update(plaintext, 'utf8');
  ct = Buffer.concat([ct, cipher.final()]);

  const mac = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();

  return `2.${iv.toString('base64')}|${ct.toString('base64')}|${mac.toString('base64')}`;
}

/** Decrypt a Bitwarden EncString */
function decryptString(encString, symKey) {
  if (!encString) return null;
  const parts = encString.split('.');
  if (parts.length !== 2 || parts[0] !== '2') throw new Error(`Unsupported enc type: ${parts[0]}`);

  const [ivB64, ctB64, macB64] = parts[1].split('|');
  const iv = Buffer.from(ivB64, 'base64');
  const ct = Buffer.from(ctB64, 'base64');

  const encKey = symKey.subarray(0, 32);
  const macKey = symKey.subarray(32, 64);

  // Verify MAC
  const expectedMac = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();
  const actualMac = Buffer.from(macB64, 'base64');
  if (!crypto.timingSafeEqual(expectedMac, actualMac)) {
    throw new Error('MAC verification failed');
  }

  const decipher = crypto.createDecipheriv('aes-256-cbc', encKey, iv);
  let pt = decipher.update(ct);
  pt = Buffer.concat([pt, decipher.final()]);
  return pt.toString('utf8');
}

/** Generate RSA-2048 keypair, return public key (base64 DER) and encrypted private key */
function generateEncryptedKeyPair(symKey) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  const pubKeyB64 = publicKey.toString('base64');
  const encPrivKey = encryptString(privateKey.toString('base64'), symKey);

  return { pubKeyB64, encPrivKey };
}

// =============================================================================
// HTTP Helpers
// =============================================================================

async function post(path, body, token, contentType = 'application/json') {
  const headers = { 'Content-Type': contentType };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const resp = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers,
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  const text = await resp.text();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: resp.status, body: json, text };
}

async function get(path, token) {
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const resp = await fetch(`${BASE_URL}${path}`, { headers });
  const text = await resp.text();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: resp.status, body: json, text };
}

async function put(path, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const resp = await fetch(`${BASE_URL}${path}`, {
    method: 'PUT',
    headers,
    body: JSON.stringify(body),
  });
  const text = await resp.text();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: resp.status, body: json, text };
}

async function del(path, token, body) {
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (body) headers['Content-Type'] = 'application/json';
  const resp = await fetch(`${BASE_URL}${path}`, {
    method: 'DELETE',
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await resp.text();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: resp.status, body: json, text };
}

function assert(name, condition, detail = '') {
  TOTAL++;
  if (condition) {
    PASS++;
    console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  } else {
    FAIL++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? ` (${detail})` : ''}`);
  }
}

function section(name) {
  console.log(`\n\x1b[34m═══ ${name} ═══\x1b[0m`);
}

// =============================================================================
// Test Data
// =============================================================================

const TEST_EMAIL = `test-${Date.now()}@example.com`;
const TEST_PASSWORD = 'SuperSecureP@ssw0rd!2024';
const TEST_NAME = 'Realistic Test User';
const KDF_ITERATIONS = 600000;

// Derive all crypto material
const masterKey = deriveMasterKey(TEST_PASSWORD, TEST_EMAIL, KDF_ITERATIONS);
const masterPasswordHash = deriveMasterPasswordHash(masterKey, TEST_PASSWORD);
const { symKey, encKeyStr } = generateEncryptedSymmetricKey(masterKey);
const { pubKeyB64, encPrivKey } = generateEncryptedKeyPair(symKey);

// Pre-encrypt test vault data
const FOLDER_NAME = encryptString('Work Passwords', symKey);
const CIPHER_LOGIN = {
  type: 1,
  name: encryptString('GitHub Account', symKey),
  notes: encryptString('My main GitHub account for work', symKey),
  login: {
    username: encryptString('user@github.com', symKey),
    password: encryptString('gh_p@ssw0rd_2024!', symKey),
    uri: encryptString('https://github.com/login', symKey),
    totp: encryptString('JBSWY3DPEHPK3PXP', symKey),
  },
  favorite: true,
};
const CIPHER_CARD = {
  type: 3,
  name: encryptString('Visa Credit Card', symKey),
  card: {
    cardholderName: encryptString('John Doe', symKey),
    number: encryptString('4111111111111111', symKey),
    expMonth: encryptString('12', symKey),
    expYear: encryptString('2028', symKey),
    code: encryptString('123', symKey),
    brand: encryptString('Visa', symKey),
  },
};
const CIPHER_IDENTITY = {
  type: 4,
  name: encryptString('Personal Identity', symKey),
  identity: {
    firstName: encryptString('John', symKey),
    lastName: encryptString('Doe', symKey),
    email: encryptString('john@example.com', symKey),
    phone: encryptString('+1-555-0123', symKey),
    address1: encryptString('123 Main St', symKey),
    city: encryptString('Springfield', symKey),
    state: encryptString('IL', symKey),
    postalCode: encryptString('62701', symKey),
    country: encryptString('US', symKey),
  },
};
const CIPHER_NOTE = {
  type: 2,
  name: encryptString('API Keys Backup', symKey),
  notes: encryptString('AWS_KEY=AKIA...\nAWS_SECRET=wJal...', symKey),
  secureNote: { type: 0 },
};
const SEND_TEXT = {
  type: 0,
  name: encryptString('Shared WiFi Password', symKey),
  key: Buffer.from(crypto.randomBytes(32)).toString('base64'),
  text: { text: encryptString('MyWiFiPass123!', symKey), hidden: false },
  deletionDate: '2030-01-01T00:00:00Z',
  maxAccessCount: 3,
};

// =============================================================================
// Main Test Flow
// =============================================================================

async function main() {
  console.log('\x1b[34m╔═══════════════════════════════════════════════════════════╗\x1b[0m');
  console.log('\x1b[34m║  Vaultwarden CF - Realistic Crypto E2E Test Suite        ║\x1b[0m');
  console.log(`\x1b[34m║  Target: ${BASE_URL.padEnd(47)}║\x1b[0m`);
  console.log(`\x1b[34m║  User: ${TEST_EMAIL.padEnd(49)}║\x1b[0m`);
  console.log('\x1b[34m╚═══════════════════════════════════════════════════════════╝\x1b[0m');

  // ── Cleanup ──
  section('Cleanup previous test data');
  const cleanLogin = await post('/identity/connect/token',
    `grant_type=password&username=${encodeURIComponent(TEST_EMAIL)}&password=${encodeURIComponent(masterPasswordHash)}&client_id=web&scope=api&deviceIdentifier=cleanup&deviceName=Cleanup&deviceType=7`,
    null, 'application/x-www-form-urlencoded');
  if (cleanLogin.body?.access_token) {
    await post('/api/accounts/delete', { masterPasswordHash }, cleanLogin.body.access_token);
  }
  console.log('  Done.');

  // ── Register ──
  section('Registration with real crypto');
  const regResp = await post('/identity/accounts/register', {
    email: TEST_EMAIL,
    masterPasswordHash,
    key: encKeyStr,
    keys: { publicKey: pubKeyB64, encryptedPrivateKey: encPrivKey },
    name: TEST_NAME,
    kdf: 0,
    kdfIterations: KDF_ITERATIONS,
  });
  assert('register succeeds', regResp.status === 200, `status=${regResp.status} ${regResp.text?.substring(0, 100)}`);

  // ── Prelogin ──
  section('Prelogin returns correct KDF params');
  const prelogin = await post('/identity/accounts/prelogin', { email: TEST_EMAIL });
  assert('prelogin status 200', prelogin.status === 200);
  assert('kdf type matches', prelogin.body?.kdf === 0);
  assert('kdf iterations matches', prelogin.body?.kdfIterations === KDF_ITERATIONS);

  // ── Login ──
  section('Login with derived password hash');
  const loginResp = await post('/identity/connect/token',
    `grant_type=password&username=${encodeURIComponent(TEST_EMAIL)}&password=${encodeURIComponent(masterPasswordHash)}&client_id=web&scope=api+offline_access&deviceIdentifier=e2e-test-device&deviceName=E2E+Test+Browser&deviceType=7`,
    null, 'application/x-www-form-urlencoded');
  assert('login succeeds', loginResp.status === 200, `status=${loginResp.status} ${loginResp.text?.substring(0, 200)}`);
  assert('access_token returned', !!loginResp.body?.access_token);
  assert('refresh_token returned', !!loginResp.body?.refresh_token);
  assert('Key matches registered key', loginResp.body?.Key === encKeyStr);
  assert('PrivateKey matches registered key', loginResp.body?.PrivateKey === encPrivKey);
  assert('Kdf matches', loginResp.body?.Kdf === 0);
  assert('KdfIterations matches', loginResp.body?.KdfIterations === KDF_ITERATIONS);

  const token = loginResp.body?.access_token;
  const refreshToken = loginResp.body?.refresh_token;
  if (!token) { console.log('\n\x1b[31mCannot continue without access token\x1b[0m'); process.exit(1); }

  // ── Refresh Token ──
  section('Refresh token login');
  const refreshResp = await post('/identity/connect/token',
    `grant_type=refresh_token&refresh_token=${encodeURIComponent(refreshToken)}`,
    null, 'application/x-www-form-urlencoded');
  assert('refresh login succeeds', refreshResp.status === 200);
  assert('new access_token returned', !!refreshResp.body?.access_token);
  const token2 = refreshResp.body?.access_token || token;

  // ── Profile ──
  section('Profile with real data');
  const profile = await get('/api/accounts/profile', token2);
  assert('profile status 200', profile.status === 200);
  assert('email matches', profile.body?.email === TEST_EMAIL);
  assert('name matches', profile.body?.name === TEST_NAME);
  assert('key matches', profile.body?.key === encKeyStr);
  assert('privateKey matches', profile.body?.privateKey === encPrivKey);
  const userId = profile.body?.id;

  // ── Create Folder with encrypted name ──
  section('Folders with encrypted names');
  const folderResp = await post('/api/folders', { name: FOLDER_NAME }, token2);
  assert('folder created', folderResp.status === 200);
  assert('folder name is encrypted', folderResp.body?.name?.startsWith('2.'));
  assert('folder name matches', folderResp.body?.name === FOLDER_NAME);
  const folderId = folderResp.body?.id;

  // ── Create Ciphers with encrypted data (all 4 types) ──
  section('Ciphers with encrypted vault data');

  // Login cipher
  const loginCipher = await post('/api/ciphers', { ...CIPHER_LOGIN, folderId }, token2);
  assert('login cipher created', loginCipher.status === 200);
  assert('login cipher name encrypted', loginCipher.body?.name?.startsWith('2.'));
  assert('login cipher type=1', loginCipher.body?.type === 1);
  assert('login cipher in folder', loginCipher.body?.folderId === folderId);
  assert('login cipher is favorite', loginCipher.body?.favorite === true);
  const loginCipherId = loginCipher.body?.id;

  // Card cipher
  const cardCipher = await post('/api/ciphers', CIPHER_CARD, token2);
  assert('card cipher created', cardCipher.status === 200);
  assert('card cipher type=3', cardCipher.body?.type === 3);
  const cardCipherId = cardCipher.body?.id;

  // Identity cipher
  const idCipher = await post('/api/ciphers', CIPHER_IDENTITY, token2);
  assert('identity cipher created', idCipher.status === 200);
  assert('identity cipher type=4', idCipher.body?.type === 4);

  // Secure note cipher
  const noteCipher = await post('/api/ciphers', CIPHER_NOTE, token2);
  assert('secure note created', noteCipher.status === 200);
  assert('secure note type=2', noteCipher.body?.type === 2);

  // ── Sync and verify encrypted data round-trips ──
  section('Sync: verify encrypted data round-trips');
  const sync = await get('/api/sync', token2);
  assert('sync status 200', sync.status === 200);
  assert('sync has 4 ciphers', sync.body?.ciphers?.length === 4);
  assert('sync has 1 folder', sync.body?.folders?.length === 1);

  // Find the login cipher in sync response
  const syncedLogin = sync.body?.ciphers?.find(c => c.id === loginCipherId);
  assert('login cipher found in sync', !!syncedLogin);
  assert('synced name matches original', syncedLogin?.name === CIPHER_LOGIN.name);

  // Decrypt the synced cipher name to verify round-trip
  try {
    const decryptedName = decryptString(syncedLogin.name, symKey);
    assert('decrypted cipher name = "GitHub Account"', decryptedName === 'GitHub Account');
  } catch (e) {
    assert('decrypt cipher name failed', false, e.message);
  }

  // Decrypt folder name from sync
  const syncedFolder = sync.body?.folders?.find(f => f.id === folderId);
  try {
    const decryptedFolder = decryptString(syncedFolder?.name, symKey);
    assert('decrypted folder name = "Work Passwords"', decryptedFolder === 'Work Passwords');
  } catch (e) {
    assert('decrypt folder name failed', false, e.message);
  }

  // Decrypt secure note from sync
  const syncedNote = sync.body?.ciphers?.find(c => c.type === 2);
  try {
    const decryptedNotes = decryptString(syncedNote?.notes, symKey);
    assert('decrypted note contains "AWS_KEY"', decryptedNotes?.includes('AWS_KEY'));
  } catch (e) {
    assert('decrypt notes failed', false, e.message);
  }

  // ── Update cipher with new encrypted data ──
  section('Update cipher with re-encrypted data');
  const newName = encryptString('GitHub Enterprise Account', symKey);
  const newPassword = encryptString('new_gh_p@ss_2025!', symKey);
  const updateResp = await put(`/api/ciphers/${loginCipherId}`, {
    type: 1,
    name: newName,
    login: {
      username: CIPHER_LOGIN.login.username,
      password: newPassword,
      uri: CIPHER_LOGIN.login.uri,
    },
  }, token2);
  assert('cipher updated', updateResp.status === 200);
  assert('updated name matches', updateResp.body?.name === newName);

  // Verify update via direct GET
  const getCipher = await get(`/api/ciphers/${loginCipherId}`, token2);
  try {
    const decName = decryptString(getCipher.body?.name, symKey);
    assert('updated name decrypts correctly', decName === 'GitHub Enterprise Account');
  } catch (e) {
    assert('decrypt updated name failed', false, e.message);
  }

  // ── Soft delete and restore ──
  section('Soft delete and restore');
  const softDel = await put(`/api/ciphers/${cardCipherId}/delete`, {}, token2);
  assert('soft delete succeeds', softDel.status === 200);

  // Verify it's gone from visible list
  const listAfterDel = await get('/api/ciphers', token2);
  const visibleIds = listAfterDel.body?.data?.map(c => c.id) || [];
  assert('deleted cipher not in visible list', !visibleIds.includes(cardCipherId));

  // Restore
  const restore = await put(`/api/ciphers/${cardCipherId}/restore`, {}, token2);
  assert('restore succeeds', restore.status === 200);

  // ── Send with encrypted data ──
  section('Send with encrypted data');
  const sendResp = await post('/api/sends', SEND_TEXT, token2);
  assert('send created', sendResp.status === 200);
  assert('send name encrypted', sendResp.body?.name?.startsWith('2.'));
  const sendId = sendResp.body?.id;

  // Access send publicly
  const accessResp = await post(`/api/sends/access/${sendId}`, {});
  assert('send access succeeds', accessResp.status === 200);
  assert('send key returned', !!accessResp.body?.key);
  assert('send name matches', accessResp.body?.name === SEND_TEXT.name);

  // Delete send
  const delSend = await del(`/api/sends/${sendId}`, token2);
  assert('send deleted', delSend.status === 200);

  // ── Organization with encrypted key ──
  section('Organization with real encrypted key');
  const orgKey = encryptString(crypto.randomBytes(64).toString('base64'), symKey);
  const orgResp = await post('/api/organizations', {
    name: 'Test Corp',
    billingEmail: TEST_EMAIL,
    key: orgKey,
    keys: { publicKey: pubKeyB64, encryptedPrivateKey: encPrivKey },
  }, token2);
  assert('org created', orgResp.status === 200);
  const orgId = orgResp.body?.id;

  // Create collection
  const colName = encryptString('Engineering Passwords', symKey);
  const colResp = await post(`/api/organizations/${orgId}/collections`, { name: colName }, token2);
  assert('collection created', colResp.status === 200);

  // ── Import with encrypted data ──
  section('Import with encrypted data');
  const importFolder = encryptString('Imported from Chrome', symKey);
  const importCipher1 = {
    type: 1,
    name: encryptString('Netflix', symKey),
    login: {
      username: encryptString('user@netflix.com', symKey),
      password: encryptString('netflix_pass_123', symKey),
      uri: encryptString('https://netflix.com', symKey),
    },
  };
  const importCipher2 = {
    type: 1,
    name: encryptString('Spotify', symKey),
    login: {
      username: encryptString('user@spotify.com', symKey),
      password: encryptString('spotify_pass_456', symKey),
    },
  };
  const importResp = await post('/api/ciphers/import', {
    folders: [{ name: importFolder }],
    ciphers: [importCipher1, importCipher2],
    folderRelationships: [{ key: 0, value: 0 }],
  }, token2);
  assert('import succeeds', importResp.status === 200);

  // Verify import via sync
  const sync2 = await get('/api/sync', token2);
  assert('sync has 6 ciphers after import', sync2.body?.ciphers?.length === 6);
  assert('sync has 2 folders after import', sync2.body?.folders?.length === 2);

  // Find imported cipher and decrypt
  const netflixCipher = sync2.body?.ciphers?.find(c => {
    try { return decryptString(c.name, symKey) === 'Netflix'; } catch { return false; }
  });
  assert('imported Netflix cipher found and decryptable', !!netflixCipher);

  // ── Password change with re-encrypted key ──
  section('Password change with new crypto');
  const NEW_PASSWORD = 'EvenMoreSecure2025!!';
  const newMasterKey = deriveMasterKey(NEW_PASSWORD, TEST_EMAIL, KDF_ITERATIONS);
  const newMasterPasswordHash = deriveMasterPasswordHash(newMasterKey, NEW_PASSWORD);
  const { encKeyStr: newEncKeyStr } = generateEncryptedSymmetricKey(newMasterKey);

  const pwChangeResp = await post('/api/accounts/password', {
    masterPasswordHash,
    newMasterPasswordHash,
    key: newEncKeyStr,
  }, token2);
  assert('password change succeeds', pwChangeResp.status === 200);

  // Login with new password
  const newLoginResp = await post('/identity/connect/token',
    `grant_type=password&username=${encodeURIComponent(TEST_EMAIL)}&password=${encodeURIComponent(newMasterPasswordHash)}&client_id=web&scope=api+offline_access&deviceIdentifier=e2e-new-device&deviceName=New+Device&deviceType=7`,
    null, 'application/x-www-form-urlencoded');
  assert('login with new password succeeds', newLoginResp.status === 200);
  assert('new Key returned', newLoginResp.body?.Key === newEncKeyStr);
  const token3 = newLoginResp.body?.access_token;

  // Old password should fail
  const oldLoginResp = await post('/identity/connect/token',
    `grant_type=password&username=${encodeURIComponent(TEST_EMAIL)}&password=${encodeURIComponent(masterPasswordHash)}&client_id=web&scope=api&deviceIdentifier=old&deviceName=Old&deviceType=7`,
    null, 'application/x-www-form-urlencoded');
  assert('old password rejected', oldLoginResp.status === 400);

  // ── Vault data still accessible after password change ──
  section('Vault data survives password change');
  const sync3 = await get('/api/sync', token3);
  assert('sync still works after pw change', sync3.status === 200);
  assert('still has 6 ciphers', sync3.body?.ciphers?.length === 6);
  assert('still has 2 folders', sync3.body?.folders?.length === 2);

  // The cipher data is encrypted with the original symKey (not the master password)
  // so it should still be decryptable with symKey
  const ghCipher = sync3.body?.ciphers?.find(c => c.id === loginCipherId);
  try {
    const name = decryptString(ghCipher?.name, symKey);
    assert('cipher still decryptable after pw change', name === 'GitHub Enterprise Account');
  } catch (e) {
    assert('cipher decrypt after pw change failed', false, e.message);
  }

  // ── Cleanup ──
  section('Cleanup');
  await del(`/api/organizations/${orgId}`, token3, { masterPasswordHash: newMasterPasswordHash });
  await post('/api/ciphers/purge', { masterPasswordHash: newMasterPasswordHash }, token3);
  const deleteResp = await post('/api/accounts/delete', { masterPasswordHash: newMasterPasswordHash }, token3);
  assert('account deleted', deleteResp.status === 200);

  // Verify account is gone
  const deadLogin = await post('/identity/connect/token',
    `grant_type=password&username=${encodeURIComponent(TEST_EMAIL)}&password=${encodeURIComponent(newMasterPasswordHash)}&client_id=web&scope=api&deviceIdentifier=dead&deviceName=Dead&deviceType=7`,
    null, 'application/x-www-form-urlencoded');
  assert('deleted account cannot login', deadLogin.status === 400);

  // ── Summary ──
  console.log('\n\x1b[34m═══════════════════════════════════════════════════════════\x1b[0m');
  console.log(`  Total: ${TOTAL}  \x1b[32mPassed: ${PASS}\x1b[0m  \x1b[31mFailed: ${FAIL}\x1b[0m`);
  console.log('\x1b[34m═══════════════════════════════════════════════════════════\x1b[0m');

  if (FAIL > 0) {
    console.log(`\n\x1b[31m${FAIL} test(s) failed\x1b[0m\n`);
    process.exit(1);
  } else {
    console.log(`\n\x1b[32mAll ${PASS} tests passed!\x1b[0m\n`);
    process.exit(0);
  }
}

main().catch(e => {
  console.error('\x1b[31mFatal error:\x1b[0m', e);
  process.exit(1);
});
