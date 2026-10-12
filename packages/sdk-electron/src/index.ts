import { KeyObject } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { hostname, platform } from 'node:os';
import { join } from 'node:path';
import { hashFingerprint, keySet, LeaseClaims, LeaseFailure, verifyLease } from '@carchalabs/licensekit-core';
import { readMachineId } from './fingerprint';

export { readMachineId };

export type LicenseStatus = 'valid' | 'grace' | 'invalid' | 'unlicensed' | 'clock_suspect';

export interface LicenseState {
  status: LicenseStatus;
  offline: boolean;
  storageProtected: boolean;
  reason?: string;
  message?: string;
  customer?: string;
  features: string[];
  expiresAt: string | null;
  maintenanceUntil?: string | null;
  revalidateBy?: string;
  keyHint?: string;
}

export interface SecureStore {
  encrypt(plain: string): Buffer | Promise<Buffer>;
  decrypt(cipher: Buffer): string | Promise<string>;
  isProtected?(): boolean;
}

export interface LicenseKitOptions {
  serverUrl: string;
  product: string;
  publicKey: string | string[];
  storageDir: string;
  appVersion?: string;
  graceDays?: number;
  secureStore?: SecureStore;
  requestTimeoutMs?: number;
  fetchImpl?: typeof fetch;
  machineId?: () => Promise<string>;
  now?: () => number;
}

interface Stored {
  licenseKey: string;
  token: string;
  lastSeen?: number;
}

const DEFINITIVE = new Set(['invalid_key', 'not_activated', 'license_suspended', 'license_revoked', 'license_expired']);
const CLOCK_TOLERANCE_SECONDS = 24 * 3600;
const DEFAULT_GRACE_DAYS = 7;
const CLOCK_MESSAGE = 'The date and time on this computer look wrong. Correct them, then connect to the internet.';

export class LicenseError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = 'LicenseError';
  }
}

const REASON_TEXT: Record<LeaseFailure, string> = {
  malformed: 'The saved license is damaged. Please activate again.',
  bad_signature: 'The saved license was modified. Please activate again.',
  unsupported_algorithm: 'Please update the app.',
  wrong_type: 'Please update the app.',
  unknown_key: 'Please update the app.',
  wrong_issuer: 'This license was issued by a different license server.',
  not_yet_valid: CLOCK_MESSAGE,
  wrong_product: 'This license is for a different product.',
  wrong_device: 'This license is activated on another device.',
  expired: 'Your license has expired.',
  revalidation_required: 'Connect to the internet to confirm your license.',
};

const toIso = (seconds: number) => new Date(seconds * 1000).toISOString();

export class LicenseKit {
  private readonly file: string;
  private readonly keys: Map<string, KeyObject>;
  private fingerprintCache?: string;

  constructor(private readonly opts: LicenseKitOptions) {
    this.file = join(opts.storageDir, 'license.dat');
    this.keys = keySet(Array.isArray(opts.publicKey) ? opts.publicKey : [opts.publicKey]);
  }

  private get fetch() {
    return this.opts.fetchImpl ?? fetch;
  }

  private nowSec() {
    return Math.floor((this.opts.now?.() ?? Date.now()) / 1000);
  }

  private get storageProtected(): boolean {
    const store = this.opts.secureStore;
    return store !== undefined && (store.isProtected?.() ?? true);
  }

  async fingerprint(): Promise<string> {
    if (!this.fingerprintCache) {
      const raw = await (this.opts.machineId ?? readMachineId)();
      this.fingerprintCache = hashFingerprint(raw, this.opts.product);
    }
    return this.fingerprintCache;
  }

  private async load(): Promise<Stored | null> {
    try {
      const buf = await readFile(this.file);
      const text = this.opts.secureStore ? await this.opts.secureStore.decrypt(buf) : buf.toString('utf8');
      return JSON.parse(text);
    } catch {
      return null;
    }
  }

  private async save(stored: Stored) {
    await mkdir(this.opts.storageDir, { recursive: true });
    const text = JSON.stringify(stored);
    await writeFile(this.file, this.opts.secureStore ? await this.opts.secureStore.encrypt(text) : text, { mode: 0o600 });
  }

  private async clear() {
    await rm(this.file, { force: true });
  }

  private async post(path: string, body: Record<string, unknown>): Promise<any> {
    let res: Response;
    try {
      res = await this.fetch(this.opts.serverUrl.replace(/\/+$/, '') + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.opts.requestTimeoutMs ?? 8000),
      });
    } catch {
      throw new LicenseError('network', 'Could not reach the license server.');
    }
    const json: any = await res.json().catch(() => ({}));
    if (!res.ok) throw new LicenseError(json.error ?? 'server_error', json.message ?? `License server error (${res.status})`, res.status);
    return json;
  }

  private emptyState(status: LicenseStatus, offline: boolean, extra: Partial<LicenseState> = {}): LicenseState {
    return { status, offline, storageProtected: this.storageProtected, features: [], expiresAt: null, ...extra };
  }

  private stateFromLease(stored: Stored, offline: boolean): LicenseState {
    const fingerprintHash = this.fingerprintCache!;
    const now = this.nowSec();
    const keyHint = `${stored.licenseKey.slice(0, 7)}…${stored.licenseKey.slice(-4)}`;
    if (offline && stored.lastSeen !== undefined && now < stored.lastSeen - CLOCK_TOLERANCE_SECONDS) {
      return this.emptyState('clock_suspect', offline, { reason: 'clock_rollback', message: CLOCK_MESSAGE, keyHint });
    }
    const verifyOptions = { keys: this.keys, product: this.opts.product, fingerprintHash, now };
    const strict = verifyLease(stored.token, verifyOptions);
    const fromClaims = (claims: LeaseClaims) => ({
      customer: claims.cus,
      features: claims.feat,
      expiresAt: claims.exp === undefined ? null : toIso(claims.exp),
      maintenanceUntil: claims.mnt === undefined ? null : toIso(claims.mnt),
      storageProtected: this.storageProtected,
      keyHint,
    });
    if (strict.ok) {
      return { status: 'valid', offline, ...fromClaims(strict.claims), revalidateBy: toIso(strict.claims.rev) };
    }
    if (strict.reason === 'not_yet_valid') {
      return this.emptyState('clock_suspect', offline, { reason: 'lease_from_future', message: CLOCK_MESSAGE, keyHint });
    }
    if (strict.reason === 'revalidation_required' && strict.claims) {
      const grace = strict.claims.grc ?? (this.opts.graceDays ?? DEFAULT_GRACE_DAYS) * 86400;
      const lenient = verifyLease(stored.token, { ...verifyOptions, graceSeconds: grace });
      if (lenient.ok) {
        return {
          status: 'grace',
          offline,
          reason: 'offline_grace',
          message: 'Working offline. Connect to the internet soon to keep using the app.',
          ...fromClaims(lenient.claims),
          revalidateBy: toIso(Math.min(lenient.claims.rev + grace, lenient.claims.exp ?? Infinity)),
        };
      }
    }
    return this.emptyState('invalid', offline, { reason: strict.reason, message: REASON_TEXT[strict.reason], keyHint });
  }

  async activate(licenseKey: string, machineName = hostname()): Promise<LicenseState> {
    const fingerprint = await this.fingerprint();
    const key = licenseKey.trim().toUpperCase();
    const response = await this.post('/v1/activate', {
      licenseKey: key,
      product: this.opts.product,
      fingerprint,
      machineName: machineName.slice(0, 80),
      platform: platform(),
      appVersion: this.opts.appVersion,
    });
    const stored: Stored = { licenseKey: key, token: response.token, lastSeen: this.nowSec() };
    const state = this.stateFromLease(stored, false);
    if (state.status !== 'valid') throw new LicenseError(state.status === 'clock_suspect' ? 'clock_suspect' : state.reason ?? 'invalid', state.message ?? 'Server returned an unusable license');
    await this.save(stored);
    return state;
  }

  async check(): Promise<LicenseState> {
    await this.fingerprint();
    const stored = await this.load();
    if (!stored) return this.emptyState('unlicensed', false);
    try {
      const response = await this.post('/v1/validate', {
        licenseKey: stored.licenseKey,
        product: this.opts.product,
        fingerprint: this.fingerprintCache,
        appVersion: this.opts.appVersion,
      });
      const fresh: Stored = { ...stored, token: response.token, lastSeen: this.nowSec() };
      await this.save(fresh);
      return this.stateFromLease(fresh, false);
    } catch (e) {
      if (e instanceof LicenseError && DEFINITIVE.has(e.code)) {
        return this.emptyState('invalid', false, { reason: e.code, message: e.message });
      }
      const state = this.stateFromLease(stored, true);
      if (state.status === 'valid' || state.status === 'grace') {
        await this.save({ ...stored, lastSeen: Math.max(stored.lastSeen ?? 0, this.nowSec()) });
      }
      return state;
    }
  }

  async deactivate(): Promise<void> {
    const stored = await this.load();
    if (!stored) return;
    try {
      await this.post('/v1/deactivate', { licenseKey: stored.licenseKey, product: this.opts.product, fingerprint: await this.fingerprint() });
    } catch (e) {
      if (!(e instanceof LicenseError && (e.code === 'not_activated' || e.code === 'invalid_key'))) throw e;
    }
    await this.clear();
  }

  static hasFeature(state: LicenseState, feature: string): boolean {
    return (state.status === 'valid' || state.status === 'grace') && state.features.includes(feature);
  }
}
