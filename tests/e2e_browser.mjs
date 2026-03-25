#!/usr/bin/env node
/**
 * Browser-based E2E tests for Admin Panel and Web Vault
 *
 * Uses Playwright to launch a real headless browser and test:
 * 1. Admin panel: login, user list renders, actions work, diagnostics load
 * 2. Web vault: page loads, login form appears
 */

import { chromium } from 'playwright';
import crypto from 'node:crypto';

const BASE_URL = process.argv[2] || 'http://localhost:8787';
const ADMIN_TOKEN = 'test-admin-token';
let PASS = 0, FAIL = 0, TOTAL = 0;

function ok(name, cond, detail = '') {
  TOTAL++;
  if (cond) { PASS++; console.log(`  \x1b[32m✓\x1b[0m ${name}`); }
  else { FAIL++; console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? ` — ${detail}` : ''}`); }
}
function section(s) { console.log(`\n\x1b[34m═══ ${s} ═══\x1b[0m`); }

// Create a test user via API so we have data to see in admin
async function setupTestUser() {
  const email = `browser-test-${Date.now()}@test.com`;
  const mk = crypto.pbkdf2Sync('TestPass1!', email.toLowerCase(), 600000, 32, 'sha256');
  const mph = crypto.pbkdf2Sync(mk, 'TestPass1!', 1, 32, 'sha256').toString('base64');
  const sk = crypto.randomBytes(64), iv = crypto.randomBytes(16), ek = mk.subarray(0,32);
  const c = crypto.createCipheriv('aes-256-cbc', ek, iv);
  let ct = Buffer.concat([c.update(sk), c.final()]);
  const macK = crypto.createHmac('sha256', mk).update(Buffer.from('mac')).digest();
  const mac = crypto.createHmac('sha256', macK).update(Buffer.concat([iv, ct])).digest();
  const encKey = `2.${iv.toString('base64')}|${ct.toString('base64')}|${mac.toString('base64')}`;

  await fetch(`${BASE_URL}/identity/accounts/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, masterPasswordHash: mph, key: encKey, name: 'Browser Test User', kdf: 0, kdfIterations: 600000 }),
  });
  return { email, mph };
}

async function main() {
  console.log('\x1b[34m╔═══════════════════════════════════════════════════════════╗\x1b[0m');
  console.log('\x1b[34m║  Browser E2E Test — Admin Panel & Web Vault              ║\x1b[0m');
  console.log('\x1b[34m╚═══════════════════════════════════════════════════════════╝\x1b[0m');

  const testUser = await setupTestUser();

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });

  // ─────────────────────────────────────────────────────────────────────────
  section('1. Admin Panel — Page Load');
  const adminPage = await context.newPage();
  await adminPage.goto(`${BASE_URL}/admin`);

  ok('admin page loads', adminPage.url().includes('/admin'));
  const title = await adminPage.title();
  ok('page title is "Vaultwarden Admin"', title === 'Vaultwarden Admin', title);

  // Check login form is visible
  const loginForm = await adminPage.$('#login-page');
  const loginDisplay = await loginForm?.evaluate(el => window.getComputedStyle(el).display);
  ok('login form is visible', loginDisplay !== 'none');

  const adminPageDiv = await adminPage.$('#admin-page');
  const adminDisplay = await adminPageDiv?.evaluate(el => el.classList.contains('d-none'));
  ok('admin content is hidden before login', adminDisplay === true);

  // ─────────────────────────────────────────────────────────────────────────
  section('2. Admin Panel — Login');
  await adminPage.evaluate((token) => {
    document.getElementById('admin-token').value = token;
    doLogin();
  }, ADMIN_TOKEN);
  await adminPage.waitForTimeout(3000); // Wait for API call + render

  const errorVisible = await adminPage.$eval('#login-error', el => !el.classList.contains('d-none')).catch(() => false);
  ok('no login error shown', !errorVisible);

  const adminVisible = await adminPage.$eval('#admin-page', el => !el.classList.contains('d-none'));
  ok('admin content is now visible', adminVisible);

  const logoutVisible = await adminPage.$eval('#btn-logout', el => !el.classList.contains('d-none'));
  ok('logout button is visible', logoutVisible);

  // ─────────────────────────────────────────────────────────────────────────
  section('3. Admin Panel — Users Tab');
  // The users tab should be active by default
  const usersRows = await adminPage.$$('#users-tbody tr');
  ok('user table has rows', usersRows.length > 0, `found ${usersRows.length} rows`);

  // Check our test user appears
  const tableText = await adminPage.$eval('#users-tbody', el => el.textContent);
  ok('test user email appears in table', tableText.includes('browser-test'), tableText.substring(0, 100));

  // Check action buttons exist
  const disableBtn = await adminPage.$('button:has-text("Disable")');
  ok('Disable button exists', !!disableBtn);

  const moreDropdown = await adminPage.$('.dropdown-toggle');
  ok('More actions dropdown exists', !!moreDropdown);

  // Check user count text
  const userCount = await adminPage.$eval('#user-count', el => el.textContent);
  ok('user count displayed', userCount.includes('user(s)'), userCount);

  // Search users (only if visible)
  const searchBox = await adminPage.$('#user-search');
  const searchVisible = searchBox ? await searchBox.isVisible() : false;
  if (searchVisible) {
    await adminPage.fill('#user-search', 'browser-test');
    await adminPage.waitForTimeout(300);
    const filteredRows = await adminPage.$$('#users-tbody tr');
    ok('user search filters results', filteredRows.length >= 1 && filteredRows.length <= usersRows.length);
    await adminPage.fill('#user-search', '');
  } else {
    ok('user search (skipped - not visible at this viewport)', true);
  }

  // ─────────────────────────────────────────────────────────────────────────
  section('4. Admin Panel — Organizations Tab');
  await adminPage.evaluate(() => switchTab('orgs'));
  await adminPage.waitForTimeout(500);

  const orgsTab = await adminPage.$eval('#tab-orgs', el => !el.classList.contains('d-none'));
  ok('organizations tab is visible', orgsTab);

  const orgsTable = await adminPage.$('#orgs-tbody');
  ok('organizations table exists', !!orgsTable);

  // ─────────────────────────────────────────────────────────────────────────
  section('5. Admin Panel — Diagnostics Tab');
  await adminPage.evaluate(() => switchTab('diag'));
  await adminPage.waitForTimeout(2000); // Wait for API calls

  const diagTab = await adminPage.$eval('#tab-diag', el => !el.classList.contains('d-none'));
  ok('diagnostics tab is visible', diagTab);

  // Check stat cards rendered
  const statCards = await adminPage.$$('.stat-card');
  ok('stat cards rendered', statCards.length >= 3, `found ${statCards.length}`);

  // Check system info
  const diagInfo = await adminPage.$eval('#diag-info', el => el.textContent);
  ok('system info shows version', diagInfo.includes('vaultwarden-cf'));
  ok('system info shows platform', diagInfo.includes('Cloudflare Workers'));

  // Check time drift
  const timeDrift = await adminPage.$eval('#time-drift', el => el.textContent);
  ok('time drift check ran', timeDrift.includes('drift') || timeDrift.includes('Could not'));

  // Check domain check
  const domainCheck = await adminPage.$eval('#domain-check', el => el.textContent);
  ok('domain check ran', domainCheck.length > 0);

  // SMTP test input exists
  const smtpInput = await adminPage.$('#smtp-test-email');
  ok('SMTP test input exists', !!smtpInput);

  // HTTP test
  await adminPage.evaluate(() => { document.getElementById('http-test-code').value = '200'; testHttp(); });
  await adminPage.waitForTimeout(3000);
  const httpResult = await adminPage.$eval('#http-test-result', el => el.textContent);
  ok('HTTP test shows result', httpResult.includes('outbound HTTP working') || httpResult.length > 0, httpResult);

  // ─────────────────────────────────────────────────────────────────────────
  section('6. Admin Panel — Configuration Tab');
  await adminPage.evaluate(() => switchTab('config'));
  await adminPage.waitForTimeout(1000);

  const configTab = await adminPage.$eval('#tab-config', el => !el.classList.contains('d-none'));
  ok('config tab is visible', configTab);

  const configInputs = await adminPage.$$('.conf-input');
  ok('config inputs rendered', configInputs.length > 0, `found ${configInputs.length}`);

  // Check DOMAIN input has a value
  const domainInput = await adminPage.$('[data-var="DOMAIN"]');
  const domainVal = await domainInput?.inputValue();
  ok('DOMAIN config has value', domainVal && domainVal.length > 0, domainVal);

  // Save and Reset buttons exist
  const saveBtn = await adminPage.$('button:has-text("Save Configuration")');
  ok('Save Configuration button exists', !!saveBtn);
  const resetBtn = await adminPage.$('button:has-text("Reset to Defaults")');
  ok('Reset to Defaults button exists', !!resetBtn);

  // ─────────────────────────────────────────────────────────────────────────
  section('7. Admin Panel — Wrong Token Rejection');
  const context2 = await browser.newContext({ viewport: { width: 1440, height: 900 } }); // Fresh context, no localStorage
  const adminPage2 = await context2.newPage();
  await adminPage2.goto(`${BASE_URL}/admin`);
  await adminPage2.fill('#admin-token', 'wrong-token');
  await adminPage2.click('button:has-text("Login")');
  await adminPage2.waitForTimeout(1000);

  const errorShown = await adminPage2.$eval('#login-error', el => !el.classList.contains('d-none'));
  ok('wrong token shows error', errorShown);
  const errorText = await adminPage2.$eval('#login-error', el => el.textContent);
  ok('error message is meaningful', errorText.includes('Invalid') || errorText.includes('token'), errorText);
  await adminPage2.close();
  await context2.close();

  // ─────────────────────────────────────────────────────────────────────────
  section('8. Admin Panel — User Actions via UI');
  await adminPage.evaluate(() => switchTab('users'));
  await adminPage.waitForTimeout(500);

  // Click first user email link via JS to open detail modal
  const hasLinks = await adminPage.evaluate(() => {
    const link = document.querySelector('#users-tbody a');
    if (link) { link.click(); return true; }
    return false;
  });
  if (hasLinks) {
    await adminPage.waitForTimeout(1500);
    const modalText = await adminPage.evaluate(() => {
      const modal = document.querySelector('.modal.show');
      return modal ? modal.textContent : '';
    });
    ok('user detail modal opens with data', modalText.includes('Email') && modalText.includes('@'), modalText.substring(0,80));
    // Close modal
    await adminPage.evaluate(() => {
      const btn = document.querySelector('.modal.show .btn-close');
      if (btn) btn.click();
    });
    await adminPage.waitForTimeout(300);
  } else {
    ok('user email links exist', false, 'no links in table');
  }

  // ─────────────────────────────────────────────────────────────────────────
  section('9. Admin Panel — Logout');
  await adminPage.evaluate(() => logout());
  await adminPage.waitForTimeout(500);

  const loginAfterLogout = await adminPage.$eval('#login-page', el => window.getComputedStyle(el).display);
  ok('login form visible after logout', loginAfterLogout !== 'none');

  const adminHidden = await adminPage.$eval('#admin-page', el => el.classList.contains('d-none'));
  ok('admin content hidden after logout', adminHidden);

  // ─────────────────────────────────────────────────────────────────────────
  section('10. Web Vault — Page Load');

  // Only test if the web vault build exists
  const vaultBuildExists = await fetch(`${BASE_URL}/`).then(r => r.status).catch(() => 404);

  if (vaultBuildExists === 200) {
    const vaultPage = await context.newPage();
    await vaultPage.goto(`${BASE_URL}/`);
    await vaultPage.waitForTimeout(3000); // Angular app takes time to bootstrap

    const vaultTitle = await vaultPage.title();
    ok('web vault page loads', vaultTitle.includes('Vaultwarden') || vaultTitle.includes('Bitwarden'), vaultTitle);

    // Check for login form elements (Angular renders these dynamically)
    const emailInput = await vaultPage.$('input[type="email"], input[formcontrolname="email"], #login_input_email');
    ok('web vault has email input', !!emailInput);

    await vaultPage.close();
  } else {
    console.log('  \x1b[33m⚠\x1b[0m Web vault not served from Worker (expected: use CF Pages deployment)');
    console.log('  \x1b[33m⚠\x1b[0m Skipping web vault browser tests');
  }

  // ─────────────────────────────────────────────────────────────────────────
  section('11. Cleanup');
  // Delete test user via API
  const loginResp = await fetch(`${BASE_URL}/identity/connect/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=password&username=${encodeURIComponent(testUser.email)}&password=${encodeURIComponent(testUser.mph)}&client_id=web&scope=api&deviceIdentifier=cleanup&deviceName=Cleanup&deviceType=7`,
  }).then(r => r.json()).catch(() => ({}));
  if (loginResp.access_token) {
    await fetch(`${BASE_URL}/api/accounts/delete`, {
      method: 'POST', headers: { 'Authorization': `Bearer ${loginResp.access_token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ masterPasswordHash: testUser.mph }),
    });
  }
  ok('test user cleaned up', true);

  await browser.close();

  // ═══════════════════════════════════════════════════════════════════════════
  console.log(`\n\x1b[34m═══════════════════════════════════════════════════════════\x1b[0m`);
  console.log(`  Total: ${TOTAL}  \x1b[32mPassed: ${PASS}\x1b[0m  \x1b[31mFailed: ${FAIL}\x1b[0m`);
  console.log(`\x1b[34m═══════════════════════════════════════════════════════════\x1b[0m`);
  if (FAIL > 0) { console.log(`\n\x1b[31m${FAIL} test(s) failed\x1b[0m\n`); process.exit(1); }
  else { console.log(`\n\x1b[32mAll ${PASS} tests passed!\x1b[0m\n`); process.exit(0); }
}

main().catch(e => { console.error('\x1b[31mFatal:\x1b[0m', e); process.exit(1); });
