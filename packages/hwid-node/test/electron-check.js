// Loads the addon inside Electron's main process and prints the result.
// Run from packages/hwid-node:
//   npx electron test/electron-check.js   (with electron installed)
'use strict';
const { app } = require('electron');

app.whenReady().then(() => {
  let code = 0;
  try {
    const hwid = require('..');
    const c = hwid.collect('product-a');
    console.log(`electron ${process.versions.electron}, node ${process.versions.node}, napi ${process.versions.napi}`);
    console.log(`hwid ${hwid.version()}, vm: ${c.vm}`);
    for (const x of c.components) console.log(`${x.kind.padEnd(6)} ${x.hash}`);
    for (const n of c.notes) console.log(`not read: ${n}`);
    if (c.components.length === 0) code = 1;
  } catch (e) {
    console.error(e);
    code = 1;
  }
  app.exit(code);
});
