'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const root = process.cwd();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cors-doctor-packaged-'));
try {
  const packOutput = childProcess.execFileSync('npm', ['pack', '--silent'], { cwd: root, encoding: 'utf8' }).trim().split(/\r?\n/).pop();
  const tarball = path.join(root, packOutput);
  assert(fs.existsSync(tarball), 'tarball created');
  childProcess.execFileSync('npm', ['init', '-y'], { cwd: tmp, stdio: 'ignore' });
  childProcess.execFileSync('npm', ['install', tarball, '--ignore-scripts'], { cwd: tmp, stdio: 'ignore' });
  childProcess.execFileSync(process.execPath, [path.join(root, 'real-insomnia-packaged-test.js')], {
    cwd: tmp,
    env: Object.assign({}, process.env, { NODE_PATH: path.join(tmp, 'node_modules') }),
    stdio: 'inherit',
  });
  fs.rmSync(tarball, { force: true });
  console.log('PASS: npm tarball install + packaged plugin integration');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
