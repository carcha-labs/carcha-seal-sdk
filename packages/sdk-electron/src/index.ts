import { KeyObject } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { hostname, platform } from 'node:os';
import { join } from 'node:path';
import { hashFingerprint, keySet, LeaseClaims, LeaseFailure, verifyLease } from '@carchalabs/licensekit-core';
import { MachineIdUnavailableError, readMachineId } from './fingerprint';

export { MachineIdUnavailableError, readMachineId };

/** This SDK's version, sent to the server so vendors can see (and require) which SDK each device runs. */
// eslint-disable-next-line @typescript-eslint/no-require-imports
export const SDK_VERSION: string = require('../package.json').version;

export type LicenseStatus = 'valid' | 'grace' | 'invalid' | 'unlicensed' | 'clock_suspect';

/**
 * Something the server asks the app to act on: sdk_update_recommended (update LicenseKit in the app) or
 * app_update_recommended (the vendor's minimum app version), each with minimum and requiredFrom.
 */
export interface LicenseNotice {
  code: string;
  minimum?: string;
  /** ISO date from which an older SDK is refused; null when the update is only recommended. */
  requiredFrom?: string | null;
}

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
  /** From the last successful check-in; kept while offline. The app decides how to show them. */
  notices?: LicenseNotice[];
}

/** Hashed hardware components (see @carchalabs/licensekit-hwid); the server matches a device by them. */
export interface HardwareReport {
  components: { kind: string; hash: string }[];
  /** True when the device runs as a virtual machine. */
  vm: boolean;
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
  /** Use hostname + CPU + MAC when the OS machine id cannot be read (default false; see readMachineId). */
  allowFallbackFingerprint?: boolean;
  /**
   * Hardware components sent with each request, so the device keeps its seat after a new disk, network
   * card or OS install. Default: read with @carchalabs/licensekit-hwid when it is installed; nothing is
   * sent when it is not (or cannot load on this platform). false: never send them. A function: your own.
   */
  hardware?: false | (() => HardwareReport | null | Promise<HardwareReport | null>);
  now?: () => number;
}

interface Stored {
  licenseKey: string;
  /** Signed lease. Absent after the server refused this device: nothing is left to verify offline. */
  token?: string;
  lastSeen?: number;
  /** The server's last definitive refusal, kept so an offline check reports it instead of an old lease. */
  refused?: { code: string; message: string; at: number };
  notices?: LicenseNotice[];
}

type Leased = Stored & { token: string };

const DEFINITIVE = new Set(['invalid_key', 'not_activated', 'license_suspended', 'license_revoked', 'license_expired', 'sdk_update_required', 'app_update_required', 'vm_not_allowed']);
/** The native hardware module. A non-literal require: bundlers leave it to Node, which must load the .node file from disk. */
const HWID_PACKAGE = '@carchalabs/licensekit-hwid';
/** The server accepts at most this many components. */
const MAX_COMPONENTS = 32;
/** The license itself is gone: forget the key too. The other refusals can be undone on the server (resume, renew,
 *  re-activate), so the key is kept and the next successful online check restores the license on its own. */
const FORGET_KEY = new Set(['invalid_key', 'license_revoked']);
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

function noticesFrom(response: any): { notices?: LicenseNotice[] } {
  const list = Array.isArray(response?.notices) ? response.notices.filter((n: any) => n && typeof n.code === 'string') : [];
  return list.length ? { notices: list } : {};
}

export class LicenseKit {
  private readonly file: string;
  private readonly keys: Map<string, KeyObject>;
  private fingerprintCache?: string;
  private hardwareCache?: Promise<HardwareReport | null>;

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
      let raw: string;
      try {
        raw = await (this.opts.machineId ?? (() => readMachineId({ allowFallback: this.opts.allowFallbackFingerprint })))();
      } catch (e) {
        if (e instanceof MachineIdUnavailableError) throw new LicenseError(e.code, e.message);
        throw e;
      }
      this.fingerprintCache = hashFingerprint(raw, this.opts.product);
    }
    return this.fingerprintCache;
  }

  /** Read once per instance: hardware does not change while the app runs. Never throws. */
  private hardware(): Promise<{ components?: HardwareReport['components']; vm?: boolean }> {
    this.hardwareCache ??= (async () => {
      const source = this.opts.hardware;
      if (source === false) return null;
      try {
        if (source) return await source();
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const hwid = require(HWID_PACKAGE);
        const { components, vm } = hwid.collect(`licensekit:${this.opts.product}`);
        return { components, vm };
      } catch {
        return null; // not installed, or no module for this platform: send nothing, as before
      }
    })();
    return this.hardwareCache.then((report) =>
      report && report.components.length ? { components: report.components.slice(0, MAX_COMPONENTS), vm: report.vm === true } : {},
    );
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

  private stateFromLease(stored: Leased, offline: boolean): LicenseState {
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
      ...(stored.notices ? { notices: stored.notices } : {}),
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
      sdkVersion: SDK_VERSION,
      ...(await this.hardware()),
    });
    const stored: Leased = { licenseKey: key, token: response.token, lastSeen: this.nowSec(), ...noticesFrom(response) };
    const state = this.stateFromLease(stored, false);
    if (state.status !== 'valid') throw new LicenseError(state.status === 'clock_suspect' ? 'clock_suspect' : state.reason ?? 'invalid', state.message ?? 'Server returned an unusable license');
    await this.save(stored);
    return state;
  }

  async check(): Promise<LicenseState> {
    try {
      await this.fingerprint();
    } catch (e) {
      // Nothing is changed on disk: the next check tries to read the id again.
      if (e instanceof LicenseError && e.code === 'machine_id_unavailable') return this.emptyState('invalid', false, { reason: e.code, message: e.message });
      throw e;
    }
    const stored = await this.load();
    if (!stored) return this.emptyState('unlicensed', false);
    try {
      const response = await this.post('/v1/validate', {
        licenseKey: stored.licenseKey,
        product: this.opts.product,
        fingerprint: this.fingerprintCache,
        appVersion: this.opts.appVersion,
        sdkVersion: SDK_VERSION,
        ...(await this.hardware()),
      });
      const fresh: Leased = { licenseKey: stored.licenseKey, token: response.token, lastSeen: this.nowSec(), ...noticesFrom(response) };
      await this.save(fresh);
      return this.stateFromLease(fresh, false);
    } catch (e) {
      const keyHint = `${stored.licenseKey.slice(0, 7)}…${stored.licenseKey.slice(-4)}`;
      if (e instanceof LicenseError && DEFINITIVE.has(e.code)) {
        // Persist the refusal: drop the signed lease so going offline cannot bring the license back.
        if (FORGET_KEY.has(e.code)) await this.clear();
        else await this.save({ licenseKey: stored.licenseKey, lastSeen: stored.lastSeen, refused: { code: e.code, message: e.message, at: this.nowSec() } });
        return this.emptyState('invalid', false, { reason: e.code, message: e.message, keyHint });
      }
      if (!stored.token) {
        const refused = stored.refused ?? { code: 'not_activated', message: 'This device is not activated for this license' };
        return this.emptyState('invalid', true, { reason: refused.code, message: refused.message, keyHint });
      }
      const state = this.stateFromLease({ ...stored, token: stored.token }, true);
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
      await this.post('/v1/deactivate', {
        licenseKey: stored.licenseKey,
        product: this.opts.product,
        fingerprint: await this.fingerprint(),
        ...(await this.hardware()),
      });
    } catch (e) {
      if (!(e instanceof LicenseError && (e.code === 'not_activated' || e.code === 'invalid_key'))) throw e;
    }
    await this.clear();
  }

  static hasFeature(state: LicenseState, feature: string): boolean {
    return (state.status === 'valid' || state.status === 'grace') && state.features.includes(feature);
  }
}
