import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { cpus, hostname, networkInterfaces, platform } from 'node:os';
import { win32 } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/**
 * The OS tools are run by absolute path, never looked up through PATH: an app started from a terminal inherits the
 * user's PATH, and a fake `ioreg` or `reg` placed first in it could report another computer's id.
 */
export const IOREG = '/usr/sbin/ioreg';
export const REG_EXE = [
  'C:\\Windows\\System32\\reg.exe',
  win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'reg.exe'),
].filter((file, index, all) => all.indexOf(file) === index);
export const LINUX_ID_FILES = ['/etc/machine-id', '/var/lib/dbus/machine-id'];

export interface MachineIdDeps {
  platform?: NodeJS.Platform;
  /** Attempts to read the OS id before giving up (default 3). */
  attempts?: number;
  /** Pause between attempts (default 250 ms, doubled each time). */
  delayMs?: number;
  /**
   * Use hostname + CPU + MAC when the OS id cannot be read. Off by default: that value differs from the OS id, so the
   * same computer would look like a new device and take another seat.
   */
  allowFallback?: boolean;
  run?: (file: string, args: string[], options: { timeout: number; windowsHide: boolean }) => Promise<{ stdout: string }>;
  readText?: (file: string) => Promise<string>;
}

/** The OS id could not be read; licensing on this computer cannot continue until it can. */
export class MachineIdUnavailableError extends Error {
  readonly code = 'machine_id_unavailable';
  constructor() {
    super('This computer\'s id could not be read. Try again; if it keeps failing, contact the app\'s support.');
    this.name = 'MachineIdUnavailableError';
  }
}

/** Reads a stable, OS-provided machine id, retrying a few times. Throws MachineIdUnavailableError unless allowFallback. */
export async function readMachineId(deps: MachineIdDeps = {}): Promise<string> {
  const attempts = Math.max(1, deps.attempts ?? 3);
  let delay = deps.delayMs ?? 250;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const id = await readOsMachineId(deps);
    if (id) return id;
    if (attempt < attempts) {
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay *= 2;
    }
  }
  if (deps.allowFallback) return `fallback:${fallbackTraits()}`;
  throw new MachineIdUnavailableError();
}

/** One attempt; null when the OS id is not available. */
async function readOsMachineId(deps: MachineIdDeps): Promise<string | null> {
  const os = deps.platform ?? platform();
  const run = deps.run ?? ((file, args, options) => execFileAsync(file, args, options));
  const readText = deps.readText ?? ((file) => readFile(file, 'utf8'));
  try {
    if (os === 'darwin') {
      const { stdout } = await run(IOREG, ['-rd1', '-c', 'IOPlatformExpertDevice'], { timeout: 3000, windowsHide: true });
      const m = stdout.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
      if (m) return `mac:${m[1]}`;
    } else if (os === 'win32') {
      for (const reg of REG_EXE) {
        try {
          // /reg:64 reads the 64-bit registry view, so a 32-bit build sees the same MachineGuid.
          const { stdout } = await run(reg, ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid', '/reg:64'], {
            timeout: 3000,
            windowsHide: true,
          });
          const m = stdout.match(/MachineGuid\s+REG_SZ\s+([\w-]+)/i);
          if (m) return `win:${m[1]}`;
        } catch {
          /* try the next location */
        }
      }
    } else {
      for (const f of LINUX_ID_FILES) {
        const id = (await readText(f).catch(() => '')).trim();
        if (id) return `linux:${id}`;
      }
    }
  } catch {
    /* fall through */
  }
  return null;
}

function fallbackTraits(): string {
  const macs = Object.values(networkInterfaces())
    .flat()
    .filter((i) => i && !i.internal && i.mac && i.mac !== '00:00:00:00:00:00')
    .map((i) => i!.mac)
    .sort();
  return [hostname(), cpus()[0]?.model ?? '', macs[0] ?? ''].join('|');
}
