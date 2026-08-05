'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const plugin = require('./main');
const t = plugin.__test;

function hasType(diag, type) {
  return diag.findings.some(f => f.type === type);
}

function diag(input) {
  return t.diagnoseCors(input);
}

async function run() {
  const results = [];
  async function check(name, fn) {
    try {
      await fn();
      results.push(['PASS', name]);
    } catch (err) {
      results.push(['FAIL', name, err.message]);
      throw err;
    }
  }

  await check('exports all Insomnia action arrays', () => {
    assert(Array.isArray(plugin.workspaceActions));
    assert(Array.isArray(plugin.requestGroupActions));
    assert(Array.isArray(plugin.requestActions));
    assert.strictEqual(plugin.workspaceActions[0].label, 'CORS Doctor: Export Report');
  });

  await check('case-insensitive header normalization from arrays and objects', () => {
    const h = t.normalizeHeaders([{ name: 'Access-Control-Allow-Origin', value: 'https://x.test' }, ['Vary', 'Origin'], { key: 'X-Test', value: '1' }]);
    assert.strictEqual(h['access-control-allow-origin'], 'https://x.test');
    assert.strictEqual(h.vary, 'Origin');
    assert.strictEqual(h['x-test'], '1');
    assert.strictEqual(t.headerValue(h, 'ACCESS-control-ALLOW-origin'), 'https://x.test');
  });

  await check('clean credentialed CORS passes', () => {
    const d = diag({
      request: { method: 'POST', headers: [{ name: 'Origin', value: 'https://app.example.com' }, { name: 'Authorization', value: 'Bearer demo' }] },
      responseHeaders: [
        ['Access-Control-Allow-Origin', 'https://app.example.com'],
        ['Access-Control-Allow-Credentials', 'true'],
        ['Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS'],
        ['Access-Control-Allow-Headers', 'Authorization, Content-Type'],
        ['Vary', 'Origin'],
      ],
    });
    assert.strictEqual(d.status, 'pass');
    assert.strictEqual(d.score, 100);
  });

  await check('wildcard + credentials fails', () => {
    const d = diag({
      request: { method: 'GET', headers: [{ name: 'Origin', value: 'https://app.example.com' }] },
      responseHeaders: [['Access-Control-Allow-Origin', '*'], ['Access-Control-Allow-Credentials', 'true']],
    });
    assert.strictEqual(d.status, 'fail');
    assert(hasType(d, 'wildcard-with-credentials'));
  });

  await check('missing allow origin fails', () => {
    const d = diag({ request: { method: 'GET', headers: [{ name: 'Origin', value: 'https://app.example.com' }] }, responseHeaders: [['Vary', 'Origin']] });
    assert.strictEqual(d.status, 'fail');
    assert(hasType(d, 'missing-allow-origin'));
  });

  await check('origin mismatch fails', () => {
    const d = diag({
      request: { method: 'GET', headers: [{ name: 'Origin', value: 'https://app.example.com' }] },
      responseHeaders: [['Access-Control-Allow-Origin', 'https://admin.example.com'], ['Vary', 'Origin']],
    });
    assert.strictEqual(d.status, 'fail');
    assert(hasType(d, 'origin-mismatch'));
  });

  await check('non-simple method with absent allow-methods is flagged', () => {
    const d = diag({
      request: { method: 'PUT', headers: [{ name: 'Origin', value: 'https://app.example.com' }] },
      responseHeaders: [['Access-Control-Allow-Origin', 'https://app.example.com'], ['Vary', 'Origin']],
    });
    assert(hasType(d, 'missing-allow-methods'), 'expected missing-allow-methods finding');
  });

  await check('non-simple method omitted from allow-methods is flagged', () => {
    const d = diag({
      request: { method: 'PATCH', headers: [{ name: 'Origin', value: 'https://app.example.com' }] },
      responseHeaders: [['Access-Control-Allow-Origin', 'https://app.example.com'], ['Access-Control-Allow-Methods', 'GET, POST'], ['Vary', 'Origin']],
    });
    assert(hasType(d, 'method-not-allowed'));
  });

  await check('custom headers with absent allow-headers are flagged', () => {
    const d = diag({
      request: { method: 'POST', headers: [{ name: 'Origin', value: 'https://app.example.com' }, { name: 'X-Client-Version', value: '1' }] },
      responseHeaders: [['Access-Control-Allow-Origin', 'https://app.example.com'], ['Access-Control-Allow-Methods', 'POST'], ['Vary', 'Origin']],
    });
    assert(hasType(d, 'headers-not-allowed'));
  });

  await check('content-type json is flagged unless allowed', () => {
    const d = diag({
      request: { method: 'POST', headers: [{ name: 'Origin', value: 'https://app.example.com' }, { name: 'Content-Type', value: 'application/json' }] },
      responseHeaders: [['Access-Control-Allow-Origin', 'https://app.example.com'], ['Access-Control-Allow-Methods', 'POST'], ['Vary', 'Origin']],
    });
    assert(hasType(d, 'content-type-not-allowed'));
  });

  await check('dynamic origin without Vary is warn', () => {
    const d = diag({
      request: { method: 'GET', headers: [{ name: 'Origin', value: 'https://app.example.com' }] },
      responseHeaders: [['Access-Control-Allow-Origin', 'https://app.example.com']],
    });
    assert.strictEqual(d.status, 'warn');
    assert(hasType(d, 'missing-vary-origin'));
  });

  await check('pasted response headers fallback parses only valid header rows', () => {
    const rows = t.parsePastedHeaders('Access-Control-Allow-Origin: https://app.example.com\n# comment\nnot valid\nVary: Origin');
    assert.deepStrictEqual(rows, [['Access-Control-Allow-Origin', 'https://app.example.com'], ['Vary', 'Origin']]);
  });

  await check('Markdown report includes fix block and no undefined text', () => {
    const d = diag({ request: { method: 'PUT', headers: [{ name: 'Origin', value: 'https://app.example.com' }] }, responseHeaders: [] });
    const md = t.makeMarkdown(d);
    assert(md.includes('# Insomnia CORS Doctor Report'));
    assert(md.includes('## Copy-paste server-side fix'));
    assert(!md.includes('undefined'));
    assert(!md.includes('null'));
  });

  await check('action writes prompted fallback report', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cors-doctor-hard-'));
    try {
      const out = path.join(tmp, 'report.md');
      const alerts = [];
      const ctx = {
        request: { method: 'GET', headers: [{ name: 'Origin', value: 'https://app.example.com' }] },
        response: { headers: [] },
        app: {
          showSaveDialog: async () => out,
          getPath: async () => tmp,
          prompt: async () => 'Access-Control-Allow-Origin: https://app.example.com\nVary: Origin',
          alert: async (title, message) => alerts.push({ title, message }),
        },
      };
      await plugin.requestActions[0].action(ctx);
      const md = fs.readFileSync(out, 'utf8');
      assert(md.includes('CORS result: pass'));
      assert.strictEqual(alerts.length, 1);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  await check('npm tarball install harness passes', () => {
    childProcess.execFileSync('node', ['qa-packaged.js'], { cwd: process.cwd(), stdio: 'pipe' });
  });

  for (const r of results) console.log(r.join(' | '));
  console.log(`HARD_QA_PASS ${results.length} checks`);
}

run().catch(err => { console.error(err.stack || err); process.exit(1); });
