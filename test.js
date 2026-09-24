'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const plugin = require('./main');
const t = plugin.__test;

const sample = {
  request: {
    method: 'PUT',
    url: 'https://api.example.com/users/42',
    headers: [
      { name: 'Origin', value: 'https://app.example.com' },
      { name: 'Authorization', value: 'Bearer demo' },
      { name: 'X-Client-Version', value: '1.2.3' },
      { name: 'Access-Control-Request-Private-Network', value: 'true' },
    ],
  },
  responseHeaders: [
    ['Access-Control-Allow-Origin', '*'],
    ['Access-Control-Allow-Credentials', 'true'],
    ['Access-Control-Allow-Methods', 'GET, POST'],
    ['Access-Control-Allow-Headers', 'Content-Type'],
  ],
};

function contextFor(output) {
  const alerts = [];
  return {
    alerts,
    request: sample.request,
    response: { headers: sample.responseHeaders },
    app: {
      showSaveDialog: async () => output,
      getPath: async key => key === 'documents' ? os.tmpdir() : '',
      alert: async (title, message) => alerts.push({ title, message }),
      prompt: async () => '',
    },
  };
}

async function main() {
  assert(Array.isArray(plugin.workspaceActions));
  assert(Array.isArray(plugin.requestGroupActions));
  assert(Array.isArray(plugin.requestActions));

  const headerMap = t.normalizeHeaders(sample.responseHeaders);
  assert.strictEqual(headerMap['access-control-allow-origin'], '*');
  assert.strictEqual(t.headerValue(headerMap, 'Access-Control-Allow-Credentials'), 'true');

  const diagnosis = t.diagnoseCors(sample);
  const types = new Set(diagnosis.findings.map(f => f.type));
  for (const expected of ['wildcard-with-credentials', 'method-not-allowed', 'headers-not-allowed', 'missing-vary-origin', 'private-network-not-allowed']) {
    assert(types.has(expected), expected);
  }
  assert.strictEqual(diagnosis.status, 'fail');
  assert.strictEqual(diagnosis.score, 15);
  assert(diagnosis.requestedHeaders.includes('authorization'));
  assert(diagnosis.requestedHeaders.includes('x-client-version'));

  const good = t.diagnoseCors({
    request: { method: 'GET', headers: [{ name: 'Origin', value: 'https://app.example.com' }] },
    responseHeaders: [
      ['Access-Control-Allow-Origin', 'https://app.example.com'],
      ['Access-Control-Allow-Credentials', 'true'],
      ['Access-Control-Allow-Methods', 'GET, POST'],
      ['Access-Control-Allow-Headers', 'Authorization, X-Client-Version'],
      ['Vary', 'Origin'],
    ],
  });
  assert.strictEqual(good.status, 'pass');
  assert.strictEqual(good.findings.length, 0);

  const preflight = t.diagnoseCors({
    request: {
      method: 'OPTIONS',
      headers: [
        { name: 'Origin', value: 'https://app.example.com' },
        { name: 'Access-Control-Request-Method', value: 'PATCH' },
        { name: 'Access-Control-Request-Headers', value: 'X-Client-Version, Authorization, x-client-version' },
      ],
    },
    responseHeaders: [
      ['Access-Control-Allow-Origin', 'https://app.example.com'],
      ['Access-Control-Allow-Methods', 'GET, POST'],
      ['Access-Control-Allow-Headers', 'Authorization'],
      ['Vary', 'Origin'],
    ],
  });
  assert.strictEqual(preflight.method, 'PATCH');
  assert.deepStrictEqual(preflight.requestedHeaders, ['authorization', 'x-client-version']);
  assert(preflight.findings.some(f => f.type === 'method-not-allowed'));
  assert(preflight.findings.some(f => f.type === 'headers-not-allowed' && f.preview === 'x-client-version'));

  const noPna = t.makeMarkdown(good);
  assert(!noPna.includes('Access-Control-Allow-Private-Network: true'));
  const pna = t.diagnoseCors({
    request: { method: 'GET', headers: [{ name: 'Origin', value: 'https://app.example.com' }, { name: 'Access-Control-Request-Private-Network', value: 'true' }] },
    responseHeaders: [['Access-Control-Allow-Origin', 'https://app.example.com'], ['Vary', 'Origin']],
  });
  assert(pna.privateNetworkRequested);
  assert(t.makeMarkdown(pna).includes('Access-Control-Allow-Private-Network: true'));

  assert.strictEqual(t.normalizeSaveDialogResult('/tmp/report.md'), '/tmp/report.md');
  assert.strictEqual(t.normalizeSaveDialogResult({ filePath: '/tmp/report.md', canceled: false }), '/tmp/report.md');
  assert.strictEqual(t.normalizeSaveDialogResult({ canceled: true }), null);

  const report = t.makeMarkdown(diagnosis);
  assert(report.includes('# Insomnia CORS Doctor Report'));
  assert(report.includes('CORS result: fail'));
  assert(report.includes('Quality score: 15/100'));
  assert(report.includes('## Browser-facing explanation'));
  assert(report.includes('wildcard-with-credentials'));
  assert(report.includes('## Copy-paste server-side fix'));

  const missingMethods = t.diagnoseCors({
    request: { method: 'PUT', headers: [{ name: 'Origin', value: 'https://app.example.com' }] },
    responseHeaders: [['Access-Control-Allow-Origin', 'https://app.example.com'], ['Vary', 'Origin']],
  });
  assert(missingMethods.findings.some(f => f.type === 'missing-allow-methods'));

  const pasted = t.parsePastedHeaders('Access-Control-Allow-Origin: https://app.example.com\nVary: Origin');
  assert.deepStrictEqual(pasted[0], ['Access-Control-Allow-Origin', 'https://app.example.com']);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cors-doctor-'));
  try {
    for (const action of [plugin.workspaceActions[0], plugin.requestGroupActions[0], plugin.requestActions[0]]) {
      const out = path.join(tmp, Math.random().toString(36).slice(2) + '.md');
      const ctx = contextFor(out);
      await action.action(ctx);
      const text = fs.readFileSync(out, 'utf8');
      assert(text.includes('Insomnia CORS Doctor Report'));
      assert(text.includes('wildcard-with-credentials'));
      assert.strictEqual(ctx.alerts.length, 1);
    }
    const objectOut = path.join(tmp, 'object.md');
    await plugin.requestActions[0].action(contextFor({ filePath: objectOut, canceled: false }));
    assert(fs.readFileSync(objectOut, 'utf8').includes('Insomnia CORS Doctor Report'), 'object save dialog result writes report');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  console.log('PASS: all tests');
}

main().catch(e => { console.error(e.stack || e); process.exit(1); });
