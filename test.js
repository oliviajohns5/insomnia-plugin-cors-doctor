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
  for (const expected of ['wildcard-with-credentials', 'method-not-allowed', 'headers-not-allowed', 'missing-vary-origin']) {
    assert(types.has(expected), expected);
  }
  assert.strictEqual(diagnosis.status, 'fail');
  assert.strictEqual(diagnosis.score, 30);
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

  const report = t.makeMarkdown(diagnosis);
  assert(report.includes('# Insomnia CORS Doctor Report'));
  assert(report.includes('CORS result: fail'));
  assert(report.includes('Quality score: 30/100'));
  assert(report.includes('## Browser-facing explanation'));
  assert(report.includes('wildcard-with-credentials'));
  assert(report.includes('## Copy-paste server-side fix'));

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
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  console.log('PASS: all tests');
}

main().catch(e => { console.error(e.stack || e); process.exit(1); });
