# insomnia-plugin-cors-doctor

[![npm version](https://img.shields.io/npm/v/insomnia-plugin-cors-doctor.svg)](https://www.npmjs.com/package/insomnia-plugin-cors-doctor)
[![license: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Local-only CORS diagnosis reports for Insomnia. v1.0.3 semantically parses browser preflight request headers and only recommends Private Network Access response headers when requested.

## Why

CORS failures are common and confusing because the request can work in API clients but fail in browsers. This plugin turns request/response headers into a local report with exact fixes.

## Features

- Diagnoses `Access-Control-Allow-Origin`, credentials, methods, headers, Private Network Access, and `Vary: Origin`
- Flags wildcard origin + credentials
- Flags missing allowed methods and headers, including semantic `Access-Control-Request-Method` and `Access-Control-Request-Headers` preflight checks
- Flags missing `Vary: Origin` for dynamic origins
- Explains the likely browser-facing problem
- Includes copy-paste server-side header examples
- Supports paste-response-headers fallback when Insomnia Desktop does not expose response headers
- Local Markdown export
- No cloud
- No telemetry
- No backend
- No dependencies

## Install

From Insomnia:

1. Open **Preferences** → **Plugins**
2. Enter `insomnia-plugin-cors-doctor`
3. Click **Install Plugin**

Manual macOS install:

```bash
cd "$HOME/Library/Application Support/Insomnia/plugins"
npm install insomnia-plugin-cors-doctor
```

Linux plugin path:

```text
~/.config/Insomnia/plugins/
```

Windows plugin path:

```text
%APPDATA%\Insomnia\plugins\
```

## Usage

Run:

```text
CORS Doctor: Export Report
```

The action is exposed through:

- `workspaceActions`
- `requestGroupActions`
- `requestActions`

In Insomnia 13, this may appear in the **New Request** dropdown or request/folder action menus.

## Example report

```markdown
# Insomnia CORS Doctor Report

## Summary

- CORS result: fail
- Quality score: 30/100
- Request Origin: https://app.example.com
- Request Method: PUT
- Non-simple request headers: authorization, x-client-version

## Findings

| Severity | Type | Message | Preview | Fix |
|---|---|---|---|---|
| high | wildcard-with-credentials | Wildcard origin cannot be used with credentials in browsers. | Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true | Return the specific Origin value and include Vary: Origin. |
| medium | method-not-allowed | Requested method is not listed in Access-Control-Allow-Methods. | PUT; allowed=GET, POST | Add PUT to Access-Control-Allow-Methods. |
```

## Privacy

CORS Doctor is local-only.

- It does not call a backend.
- It does not use analytics.
- It does not need credentials.
- It writes a local Markdown file.

## Development

```bash
git clone https://github.com/oliviajohns5/insomnia-plugin-cors-doctor.git
cd insomnia-plugin-cors-doctor
npm test
npm run test:packaged
npm pack --dry-run
```

## Verified QA

- `node --check main.js`
- `node --check test.js`
- `node --check real-insomnia-packaged-test.js`
- `node --check qa-packaged.js`
- `npm test`
- `npm run test:hard`
- `npm run test:packaged`
- `npm pack --dry-run`
- isolated tarball install
- package metadata validation
- credential literal scan

## Requirements

- Insomnia
- Node.js/npm only for development or publishing

## License

MIT

## Changelog

### 1.0.3

- Parses preflight `Access-Control-Request-Method` and `Access-Control-Request-Headers` as the requested browser method/header set.
- Recommends `Access-Control-Allow-Private-Network` only when `Access-Control-Request-Private-Network: true` is present.

### 1.0.2

- Adds Private Network Access preflight diagnostics for Access-Control-Request-Private-Network.
