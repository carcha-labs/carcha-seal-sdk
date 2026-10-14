#!/usr/bin/env node
// licensekit-encrypt: encrypts a file for a feature with its content key, for your build.
//   LICENSEKIT_FEATURE_KEY=<key from the console> npx -p @carchalabs/licensekit-core licensekit-encrypt --feature pro in.js out.js.lke
// The key is read from LICENSEKIT_FEATURE_KEY or --key-file, never from the command line, so it
// does not end up in shell history or process lists.
import { readFileSync, writeFileSync } from 'node:fs';
import { encryptForFeature } from './index';

const USAGE = [
  'Usage: licensekit-encrypt --feature <name> [--key-file <file>] <input> <output>',
  '',
  "Encrypts <input> for a feature with the feature's content key (console: Products, Feature keys).",
  'The key comes from the LICENSEKIT_FEATURE_KEY environment variable or from --key-file.',
  'Your app opens <output> with kit.decrypt(feature, data) on a device whose license includes the feature.',
];

export function runEncrypt(args: string[], env: Record<string, string | undefined>, io: { out: (s: string) => void; err: (s: string) => void }): number {
  let feature: string | undefined;
  let keyFile: string | undefined;
  const files: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--feature') feature = args[++i];
    else if (args[i] === '--key-file') keyFile = args[++i];
    else if (args[i] === '--help' || args[i] === '-h') {
      USAGE.forEach(io.out);
      return 0;
    } else files.push(args[i]);
  }
  if (!feature || files.length !== 2) {
    USAGE.forEach(io.err);
    return 2;
  }
  const encoded = (keyFile ? readFileSync(keyFile, 'utf8') : env.LICENSEKIT_FEATURE_KEY ?? '').trim();
  const key = Buffer.from(encoded, 'base64url');
  if (!/^[A-Za-z0-9_-]+$/.test(encoded) || key.length !== 32) {
    io.err('The feature key must be the 32-byte base64url key shown in the console (LICENSEKIT_FEATURE_KEY or --key-file).');
    return 2;
  }
  const [input, output] = files;
  writeFileSync(output, encryptForFeature(key, feature, readFileSync(input)));
  io.out(`Encrypted ${input} for "${feature}" -> ${output}`);
  return 0;
}

if (require.main === module) {
  process.exitCode = runEncrypt(process.argv.slice(2), process.env, { out: (s) => console.log(s), err: (s) => console.error(s) });
}
