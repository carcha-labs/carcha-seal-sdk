// Builds the Node-API addon with cargo and copies it next to index.js as
// seal-hwid.<target>.node, the local file index.js loads first.
// --npm also copies it into npm/<target>/, the platform package CI publishes.
'use strict';
const { execFileSync } = require('node:child_process');
const { copyFileSync } = require('node:fs');
const path = require('node:path');
const { target } = require('../target');

const root = path.join(__dirname, '..');
const name = target();
if (!name) throw new Error(`no prebuilt target for ${process.platform}-${process.arch}`);
execFileSync('cargo', ['build', '--release'], { cwd: root, stdio: 'inherit' });

const lib = {
  darwin: 'libseal_hwid_node.dylib',
  linux: 'libseal_hwid_node.so',
  win32: 'seal_hwid_node.dll',
}[process.platform];

const file = `seal-hwid.${name}.node`;
const built = path.join(root, 'target', 'release', lib);
copyFileSync(built, path.join(root, file));
if (process.argv.includes('--npm')) copyFileSync(built, path.join(root, 'npm', name, file));
console.log(`built ${file}`);
