'use strict';

const assert = require('assert');
const plugin = require('insomnia-plugin-cors-doctor');
const t = plugin.__test;

assert(Array.isArray(plugin.workspaceActions), 'workspaceActions export');
assert(Array.isArray(plugin.requestGroupActions), 'requestGroupActions export');
assert(Array.isArray(plugin.requestActions), 'requestActions export');
assert.strictEqual(plugin.workspaceActions[0].label, 'CORS Doctor: Export Report');

const diagnosis = t.diagnoseCors({
  request: { method: 'PUT', headers: [{ name: 'Origin', value: 'https://app.example.com' }, { name: 'Authorization', value: 'Bearer demo' }] },
  responseHeaders: [['Access-Control-Allow-Origin', '*'], ['Access-Control-Allow-Credentials', 'true'], ['Access-Control-Allow-Methods', 'GET']],
});
assert.strictEqual(diagnosis.status, 'fail');
assert(t.makeMarkdown(diagnosis).includes('CORS Doctor Report'));
console.log('PASS: packaged plugin integration harness');
