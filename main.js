'use strict';

const SIMPLE_REQUEST_HEADERS = new Set(['accept', 'accept-language', 'content-language', 'content-type']);
const SIMPLE_METHODS = new Set(['GET', 'HEAD', 'POST']);
const SIMPLE_CONTENT_TYPES = new Set(['application/x-www-form-urlencoded', 'multipart/form-data', 'text/plain']);
const CORS_RESPONSE_HEADERS = [
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'access-control-allow-methods',
  'access-control-allow-headers',
  'access-control-expose-headers',
  'access-control-max-age',
  'access-control-allow-private-network',
  'vary',
];

function safeString(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

function normalizeName(name) {
  return safeString(name).trim().toLowerCase();
}

function normalizeHeaders(headers) {
  const out = {};
  if (!headers) return out;
  if (Array.isArray(headers)) {
    for (const item of headers) {
      if (Array.isArray(item)) {
        const name = normalizeName(item[0]);
        if (name) out[name] = safeString(item[1]).trim();
      } else if (item && typeof item === 'object') {
        const name = normalizeName(item.name || item.key || item.header || item[0]);
        if (name) out[name] = safeString(item.value ?? item.val ?? item[1]).trim();
      }
    }
    return out;
  }
  if (typeof headers === 'object') {
    for (const [key, value] of Object.entries(headers)) {
      const name = normalizeName(key);
      if (name) out[name] = safeString(value).trim();
    }
  }
  return out;
}

function headerValue(map, name) {
  return map[normalizeName(name)] || '';
}

function splitHeaderList(value) {
  return safeString(value).split(',').map(v => v.trim().toLowerCase()).filter(Boolean);
}

function parsePastedHeaders(text) {
  const rows = [];
  for (const rawLine of safeString(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const idx = line.indexOf(':');
    if (idx < 1) continue;
    rows.push([line.slice(0, idx).trim(), line.slice(idx + 1).trim()]);
  }
  return rows;
}

function requestHeaders(request) {
  return normalizeHeaders(request && (request.headers || request.header || request.requestHeaders));
}

function responseHeaders(input) {
  return normalizeHeaders(input && (input.responseHeaders || input.headers || (input.response && input.response.headers)));
}

function requestOrigin(requestHeadersMap) {
  return headerValue(requestHeadersMap, 'origin');
}

function uniqueSorted(values) {
  return Array.from(new Set(values.map(normalizeName).filter(Boolean))).sort();
}

function requestedMethod(input, requestHeadersMap) {
  const preflightMethod = headerValue(requestHeadersMap, 'access-control-request-method').trim().toUpperCase();
  if (preflightMethod) return preflightMethod;
  const request = (input && input.request) || {};
  return safeString(request.method || (input && input.method) || 'GET').toUpperCase();
}

function requestedHeaderNames(requestHeadersMap) {
  const preflightHeaders = splitHeaderList(headerValue(requestHeadersMap, 'access-control-request-headers'));
  if (preflightHeaders.length) return uniqueSorted(preflightHeaders);
  return uniqueSorted(Object.keys(requestHeadersMap)
    .filter(h => !SIMPLE_REQUEST_HEADERS.has(h))
    .filter(h => !h.startsWith('access-control-request-'))
    .filter(h => !['origin', 'host', 'content-length', 'user-agent', 'accept-encoding', 'connection'].includes(h)));
}

function add(findings, severity, type, message, preview, fix, penalty) {
  findings.push({ severity, type, message, preview: safeString(preview).slice(0, 220), fix, penalty });
}

function diagnoseCors(input) {
  const request = input.request || {};
  const reqHeaders = requestHeaders(request);
  const resHeaders = responseHeaders(input);
  const method = requestedMethod(input, reqHeaders);
  const origin = requestOrigin(reqHeaders) || safeString(input.origin || '');
  const requestedHeaders = requestedHeaderNames(reqHeaders);
  const allowOrigin = headerValue(resHeaders, 'access-control-allow-origin');
  const allowCreds = headerValue(resHeaders, 'access-control-allow-credentials').toLowerCase();
  const allowMethods = splitHeaderList(headerValue(resHeaders, 'access-control-allow-methods')).map(m => m.toUpperCase());
  const allowHeaders = splitHeaderList(headerValue(resHeaders, 'access-control-allow-headers'));
  const allowPrivateNetwork = headerValue(resHeaders, 'access-control-allow-private-network').toLowerCase();
  const privateNetworkRequested = headerValue(reqHeaders, 'access-control-request-private-network').toLowerCase() === 'true';
  const vary = splitHeaderList(headerValue(resHeaders, 'vary'));
  const findings = [];

  if (!allowOrigin) {
    add(findings, 'high', 'missing-allow-origin', 'Response does not include Access-Control-Allow-Origin.', 'header missing', 'Return Access-Control-Allow-Origin for allowed browser origins.', 30);
  } else if (allowOrigin !== '*' && origin && allowOrigin !== origin) {
    add(findings, 'high', 'origin-mismatch', 'Allowed origin does not match the request Origin.', `origin=${origin}; allowed=${allowOrigin}`, 'Echo the allowed Origin exactly or configure it in the server allowlist.', 25);
  }

  if (allowOrigin === '*' && allowCreds === 'true') {
    add(findings, 'high', 'wildcard-with-credentials', 'Wildcard origin cannot be used with credentials in browsers.', 'Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true', 'Return the specific Origin value and include Vary: Origin.', 25);
  }

  if (!SIMPLE_METHODS.has(method) && !allowMethods.length) {
    add(findings, 'medium', 'missing-allow-methods', 'Response does not include Access-Control-Allow-Methods for a non-simple method.', method, `Return Access-Control-Allow-Methods including ${method}.`, 15);
  } else if (!['GET', 'HEAD'].includes(method) && allowMethods.length && !allowMethods.includes(method)) {
    add(findings, 'medium', 'method-not-allowed', 'Requested method is not listed in Access-Control-Allow-Methods.', `${method}; allowed=${allowMethods.join(', ')}`, `Add ${method} to Access-Control-Allow-Methods.`, 15);
  }

  const missingHeaders = requestedHeaders.filter(h => !allowHeaders.includes(h));
  if (missingHeaders.length) {
    add(findings, 'medium', 'headers-not-allowed', 'Non-simple request headers are not listed in Access-Control-Allow-Headers.', missingHeaders.join(', '), `Add ${missingHeaders.join(', ')} to Access-Control-Allow-Headers.`, 15);
  }

  const contentType = headerValue(reqHeaders, 'content-type').split(';')[0].trim().toLowerCase();
  if (contentType && !SIMPLE_CONTENT_TYPES.has(contentType) && !allowHeaders.includes('content-type')) {
    add(findings, 'medium', 'content-type-not-allowed', 'Non-simple Content-Type usually requires Access-Control-Allow-Headers: Content-Type.', contentType, 'Add Content-Type to Access-Control-Allow-Headers.', 10);
  }

  if (privateNetworkRequested && allowPrivateNetwork !== 'true') {
    add(findings, 'medium', 'private-network-not-allowed', 'Private Network Access preflight is requested but not allowed by the response.', 'Access-Control-Request-Private-Network: true', 'Return Access-Control-Allow-Private-Network: true only for trusted origins that should reach private network resources.', 15);
  }

  if (allowOrigin && allowOrigin !== '*' && !vary.includes('origin')) {
    add(findings, 'low', 'missing-vary-origin', 'Dynamic origin responses should include Vary: Origin.', `Access-Control-Allow-Origin: ${allowOrigin}`, 'Add Vary: Origin so caches do not mix CORS responses across origins.', 15);
  }
  if (allowOrigin === '*' && allowCreds === 'true' && !vary.includes('origin')) {
    add(findings, 'low', 'missing-vary-origin', 'Credentialed CORS should include Vary: Origin when origin is dynamic.', 'Vary header missing Origin', 'Add Vary: Origin when returning a request-specific origin.', 15);
  }

  const totalPenalty = findings.reduce((sum, f) => sum + (f.penalty || 0), 0);
  const score = Math.max(0, 100 - totalPenalty);
  const high = findings.filter(f => f.severity === 'high').length;
  const status = high ? 'fail' : findings.length ? 'warn' : 'pass';
  return {
    status,
    score,
    method,
    origin,
    requestedHeaders,
    privateNetworkRequested,
    responseCorsHeaders: Object.fromEntries(Object.entries(resHeaders).filter(([k]) => CORS_RESPONSE_HEADERS.includes(k))),
    findings,
  };
}

function makeServerFix(diagnosis) {
  const origin = diagnosis.origin || 'https://your-frontend.example';
  const method = diagnosis.method || 'GET';
  const headers = diagnosis.requestedHeaders.length ? diagnosis.requestedHeaders.join(', ') : 'Content-Type, Authorization';
  const lines = [
    '```http',
    `Access-Control-Allow-Origin: ${origin}`,
    'Access-Control-Allow-Credentials: true',
    `Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS${method && !['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(method) ? ', ' + method : ''}`,
    `Access-Control-Allow-Headers: ${headers}`,
    'Vary: Origin',
  ];
  if (diagnosis.privateNetworkRequested) lines.push('Access-Control-Allow-Private-Network: true');
  lines.push('```');
  return lines.join('\n');
}

function makeMarkdown(diagnosis) {
  const rows = diagnosis.findings.map(f => `| ${f.severity} | ${f.type} | ${f.message} | ${String(f.preview).replace(/\|/g, '\\|')} | ${String(f.fix).replace(/\|/g, '\\|')} |`).join('\n');
  const responseRows = Object.entries(diagnosis.responseCorsHeaders).map(([k, v]) => `- ${k}: ${v}`).join('\n') || '- none found';
  const findings = rows || '| low | none | No obvious CORS issue detected. |  |  |';
  return `# Insomnia CORS Doctor Report\n\nGenerated: ${new Date().toISOString()}\n\nLocal-only report. No network calls, no telemetry, no backend.\n\n## Summary\n\n- CORS result: ${diagnosis.status}\n- Quality score: ${diagnosis.score}/100\n- Request Origin: ${diagnosis.origin || '(not set)'}\n- Request Method: ${diagnosis.method}\n- Non-simple request headers: ${diagnosis.requestedHeaders.join(', ') || 'none'}\n\n## Browser-facing explanation\n\n${diagnosis.status === 'pass' ? 'This response looks compatible with the inspected browser CORS request.' : 'A browser may block this request even if Insomnia can send it, because browser CORS enforcement depends on response headers from the API server.'}\n\n## Response CORS headers\n\n${responseRows}\n\n## Findings\n\n| Severity | Type | Message | Preview | Fix |\n|---|---|---|---|---|\n${findings}\n\n## Copy-paste server-side fix\n\n${makeServerFix(diagnosis)}\n`;
}

async function getWritableExportPath(context, fileName) {
  const path = require('path');
  const candidates = [];
  if (context.app && typeof context.app.getPath === 'function') {
    for (const key of ['documents', 'desktop', 'downloads', 'userData', 'home']) {
      try { const v = await context.app.getPath(key); if (v) candidates.push(v); } catch {}
    }
  }
  candidates.push(process.env.HOME || process.env.USERPROFILE || process.cwd());
  return path.join(candidates.find(Boolean) || '.', fileName);
}


function normalizeSaveDialogResult(result) {
  if (!result) return null;
  if (typeof result === 'string') return result;
  if (typeof result === 'object') {
    if (result.canceled) return null;
    if (typeof result.filePath === 'string' && result.filePath) return result.filePath;
    if (typeof result.path === 'string' && result.path) return result.path;
  }
  return null;
}

async function collectInput(context) {
  const request = context.request || {};
  let headers = (context.response && context.response.headers) || context.responseHeaders || [];
  if ((!headers || (Array.isArray(headers) && !headers.length)) && context.app && typeof context.app.prompt === 'function') {
    const pasted = await context.app.prompt('CORS Doctor: paste response headers', { label: 'Response headers', submitName: 'Use Headers', cancelable: true, defaultValue: '' });
    headers = parsePastedHeaders(pasted || '');
  }
  return { request, responseHeaders: headers };
}

const action = {
  label: 'CORS Doctor: Export Report',
  icon: 'fa-stethoscope',
  action: async (context) => {
    const input = await collectInput(context);
    const report = makeMarkdown(diagnoseCors(input));
    const fs = require('fs');
    let output = null;
    if (context.app && typeof context.app.showSaveDialog === 'function') output = normalizeSaveDialogResult(await context.app.showSaveDialog({ defaultPath: 'insomnia-cors-doctor-report.md' }));
    if (!output) output = await getWritableExportPath(context, 'insomnia-cors-doctor-report.md');
    fs.writeFileSync(output, report, 'utf8');
    if (context.app && typeof context.app.alert === 'function') await context.app.alert('CORS Doctor report exported', output);
  },
};

module.exports.workspaceActions = [action];
module.exports.requestGroupActions = [action];
module.exports.requestActions = [action];
module.exports.__test = { collectInput, diagnoseCors, getWritableExportPath, headerValue, makeMarkdown, normalizeHeaders, normalizeSaveDialogResult, parsePastedHeaders, requestedHeaderNames, requestedMethod, splitHeaderList, uniqueSorted };
