'use strict';

const assert = require('assert');
const plugin = require('insomnia-plugin-cors-doctor');
const t = plugin.__test;

assert(Array.isArray(plugin.workspaceActions), 'workspaceActions export');
assert(Array.isArray(plugin.requestGroupActions), 'requestGroupActions export');
assert(Array.isArray(plugin.requestActions), 'requestActions export');
assert.strictEqual(plugin.workspaceActions[0].label, 'CORS Doctor: Export Report');

const diagnosis = t.diagnoseCors({
  request: { method: 'OPTIONS', headers: [
    { name: 'Origin', value: 'https://app.example.com' },
    { name: 'Access-Control-Request-Method', value: 'PUT' },
    { name: 'Access-Control-Request-Headers', value: 'Authorization, X-Trace-Id' },
  ] },
  responseHeaders: [['Access-Control-Allow-Origin', '*'], ['Access-Control-Allow-Credentials', 'true'], ['Access-Control-Allow-Methods', 'GET'], ['Access-Control-Allow-Headers', 'Authorization']],
});
assert.strictEqual(diagnosis.status, 'fail');
assert.strictEqual(diagnosis.method, 'PUT');
assert.deepStrictEqual(diagnosis.requestedHeaders, ['authorization', 'x-trace-id']);
assert(diagnosis.findings.some(f => f.type === 'method-not-allowed'));
assert(diagnosis.findings.some(f => f.type === 'headers-not-allowed'));
assert(t.makeMarkdown(diagnosis).includes('CORS Doctor Report'));
assert(!t.makeMarkdown(diagnosis).includes('Access-Control-Allow-Private-Network: true'));
console.log('PASS: packaged plugin integration harness');
