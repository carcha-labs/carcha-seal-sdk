import { readFileSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import { LicenseError, LicenseKit, LicenseKitOptions, LicenseState } from '@carchalabs/licensekit-electron';

export const PRODUCT = 'licensekit-demo';
export const DEFAULT_SERVER_URL = 'https://licensekit.carchalabs.com';
export const DEVICE_NAME = 'LicenseKit quickstart';
const COMMAND = 'npx @carchalabs/licensekit-quickstart';

export interface RunOptions {
  out: (line: string) => void;
  storageDir?: string;
  serverUrl?: string;
  publicKeys?: string[];
  fetchImpl?: typeof fetch;
  machineId?: () => Promise<string>;
  /** Passed to the SDK (tests simulate machines; the CLI itself reads the hardware). */
  hardware?: LicenseKitOptions['hardware'];
}

const USAGE = [
  `Usage: ${COMMAND} <command>`,
  '',
  'Commands:',
  '  activate <license-key>  Activate this computer and save a signed lease',
  '  status                  Check the license. Works offline from the saved lease',
  "  deactivate              Release this computer's seat",
  '',
  'Get a trial key at https://licensekit.carchalabs.com/#try',
];

export function bundledPublicKeys(): string[] {
  return ['current.pem', 'next.pem'].map((file) => readFileSync(join(__dirname, '..', 'public-keys', file), 'utf8'));
}

export function defaultStorageDir(os: string, env: Record<string, string | undefined>, home: string): string {
  if (os === 'darwin') return join(home, 'Library', 'Application Support', 'licensekit-quickstart');
  if (os === 'win32') return join(env.APPDATA ?? join(home, 'AppData', 'Roaming'), 'licensekit-quickstart');
  return join(env.XDG_CONFIG_HOME || join(home, '.config'), 'licensekit-quickstart');
}

const minute = (iso: string) => `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;

function report(state: LicenseState, out: (line: string) => void) {
  out(`Status: ${state.status}`);
  if (state.message) out(state.message);
  if (state.customer) out(`Licensed to: ${state.customer}`);
  if (state.status === 'valid' || state.status === 'grace') {
    out(`Features: ${state.features.length ? state.features.join(', ') : 'none'}`);
    out(`Expires: ${state.expiresAt ? minute(state.expiresAt) : 'never'}`);
    if (state.revalidateBy) out(`${state.status === 'valid' ? 'Check in by' : 'Works offline until'}: ${minute(state.revalidateBy)}`);
  }
}

export async function run(args: string[], options: RunOptions): Promise<number> {
  const { out } = options;
  const [command, key] = args;
  if (command === 'help' || command === '--help' || command === '-h') {
    USAGE.forEach((line) => out(line));
    return 0;
  }
  if (!['activate', 'status', 'deactivate'].includes(command ?? '') || (command === 'activate' && !key)) {
    USAGE.forEach((line) => out(line));
    return 2;
  }
  const kit = new LicenseKit({
    serverUrl: options.serverUrl ?? DEFAULT_SERVER_URL,
    product: PRODUCT,
    publicKey: options.publicKeys ?? bundledPublicKeys(),
    storageDir: options.storageDir ?? defaultStorageDir(platform(), process.env, homedir()),
    appVersion: '0.3.0',
    fetchImpl: options.fetchImpl,
    machineId: options.machineId,
    hardware: options.hardware,
  });
  if (command === 'activate') {
    try {
      const state = await kit.activate(key, DEVICE_NAME);
      report(state, out);
      out('Saved lease: not encrypted. A terminal has no system keychain; an Electron app uses safeStorage.');
      out(`Turn off the network and run "${COMMAND} status" to check it offline.`);
      return 0;
    } catch (e) {
      out(`Activation failed: ${e instanceof LicenseError ? e.message : String(e)}`);
      return 1;
    }
  }
  if (command === 'deactivate') {
    try {
      await kit.deactivate();
      out("This computer's seat is released.");
      return 0;
    } catch (e) {
      out(`Deactivation failed: ${e instanceof LicenseError ? e.message : String(e)}`);
      return 1;
    }
  }
  const state = await kit.check();
  if (state.status === 'unlicensed') {
    out('Status: unlicensed');
    out(`Run "${COMMAND} activate <license-key>" first.`);
    return 1;
  }
  report(state, out);
  out(`Checked: ${state.offline ? 'offline, from the signed lease saved on this computer' : 'online'}`);
  return state.status === 'valid' || state.status === 'grace' ? 0 : 1;
}
