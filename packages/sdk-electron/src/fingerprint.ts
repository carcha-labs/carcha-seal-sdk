import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { cpus, hostname, networkInterfaces, platform } from 'node:os';
import { promisify } from 'node:util';

const run = promisify(execFile);

/** Reads a stable, OS-provided machine id. Falls back to hardware traits if unavailable. */
export async function readMachineId(): Promise<string> {
  try {
    const os = platform();
    if (os === 'darwin') {
      const { stdout } = await run('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], { timeout: 3000 });
      const m = stdout.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
      if (m) return `mac:${m[1]}`;
    } else if (os === 'win32') {
      const { stdout } = await run('reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'], {
        timeout: 3000,
        windowsHide: true,
      });
      const m = stdout.match(/MachineGuid\s+REG_SZ\s+([\w-]+)/i);
      if (m) return `win:${m[1]}`;
    } else {
      for (const f of ['/etc/machine-id', '/var/lib/dbus/machine-id']) {
        const id = (await readFile(f, 'utf8').catch(() => '')).trim();
        if (id) return `linux:${id}`;
      }
    }
  } catch {
    /* fall through */
  }
  return `fallback:${fallbackTraits()}`;
}

function fallbackTraits(): string {
  const macs = Object.values(networkInterfaces())
    .flat()
    .filter((i) => i && !i.internal && i.mac && i.mac !== '00:00:00:00:00:00')
    .map((i) => i!.mac)
    .sort();
  return [hostname(), cpus()[0]?.model ?? '', macs[0] ?? ''].join('|');
}
