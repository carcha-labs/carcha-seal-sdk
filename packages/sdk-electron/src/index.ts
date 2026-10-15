import { KeyObject } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { hostname, platform } from 'node:os';
import { join } from 'node:path';
import { decodeLease, decryptFeature, hashFingerprint, keySet, LeaseClaims, LeaseFailure, LeaseVerifyOptions, LeaseVerifyResult, verifyLease } from '@carchalabs/licensekit-core';
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
  /** True when the license came from an offline license file (activateOffline); renew it with a new file. */
  offlineActivated?: boolean;
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
  /** Activated from an offline license file: check() never calls the server; a new file renews it. */
  offline?: boolean;
}

type Leased = Stored & { token: string };

/** File formats of offline activation, shared with the license server. */
const OFFLINE_REQUEST_FORMAT = 'licensekit-offline-request';
const OFFLINE_LICENSE_FORMAT = 'licensekit-offline-license';
const OFFLINE_DEACTIVATION_FORMAT = 'licensekit-offline-deactivation';

const DEFINITIVE = new Set(['invalid_key', 'not_activated', 'license_suspended', 'license_revoked', 'license_expired', 'sdk_update_required', 'app_update_required', 'vm_not_allowed']);
/** The native hardware module. A non-literal require: bundlers leave it to Node, which must load the .node file from disk. */
const HWID_PACKAGE = '@carchalabs/licensekit-hwid';
/** The native module's lease verifier (@carchalabs/licensekit-hwid 0.2+): its keys are compiled in. */
interface NativeLease {
  verifyLease(token: string, check: { product: string; fingerprintHash: string; now: number; graceSeconds?: number }): { ok: boolean; reason?: string };
  leaseKeyIds(): string[];
  /** This machine's X25519 public key from its hardware (base64url), or null. */
  devicePublicKey?(key: string): string | null;
  /** @carchalabs/licensekit-hwid 0.2+ with feature keys. */
  decryptFeature?(
    token: string,
    check: { product: string; fingerprintHash: string; now: number; graceSeconds?: number },
    licenseKey: string,
    feature: string,
    data: Buffer,
  ): { ok: boolean; data?: Buffer; reason?: string };
}

/** Loads the native module once per process; null when it is not installed or has no build for this platform. */
let hwidModule: any;
function loadHwid(): any {
  if (hwidModule === undefined) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      hwidModule = require(HWID_PACKAGE);
    } catch {
      hwidModule = null;
    }
  }
  return hwidModule;
}

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
  /** The native lease verifier, when it trusts every key this app was given (undefined = not looked up yet). */
  private nativeLease?: NativeLease | null;
  private deviceKeyCache?: string | null;

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
        const hwid = loadHwid();
        if (!hwid) return null;
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

  /**
   * The device's public key, sent with activation and check-ins so the server wraps feature keys for
   * this machine only. Only when the native module verifies for this app (it then also decrypts, with
   * the matching secret it derives itself) and hardware is not turned off. Never throws.
   */
  private deviceKey(): { devicePublicKey?: string } {
    if (this.deviceKeyCache === undefined) {
      let key: string | null = null;
      try {
        const native = this.opts.hardware === false ? null : this.native();
        if (native && typeof native.devicePublicKey === 'function' && typeof native.decryptFeature === 'function') {
          key = native.devicePublicKey(`licensekit:${this.opts.product}`);
        }
      } catch {
        key = null;
      }
      this.deviceKeyCache = key;
    }
    return this.deviceKeyCache ? { devicePublicKey: this.deviceKeyCache } : {};
  }

  /**
   * The native verifier, used only when its compiled-in keys include every key this app was given:
   * an app that trusts other keys (a self-hosted server) is checked by the JavaScript verifier alone.
   */
  private native(): NativeLease | null {
    if (this.nativeLease === undefined) {
      const hwid = loadHwid();
      let native: NativeLease | null = null;
      if (hwid && typeof hwid.verifyLease === 'function' && typeof hwid.leaseKeyIds === 'function') {
        const trusted = new Set<string>(hwid.leaseKeyIds());
        if ([...this.keys.keys()].every((kid) => trusted.has(kid))) native = hwid;
      }
      this.nativeLease = native;
    }
    return this.nativeLease;
  }

  /**
   * Verifies a lease twice, in JavaScript and in the native module, when the native verifier applies.
   * Both follow the same rules, so a different answer means one of them was tampered with: the lease
   * is then treated as modified.
   */
  private verify(token: string, options: LeaseVerifyOptions): LeaseVerifyResult {
    const result = verifyLease(token, options);
    const native = this.native();
    if (!native) return result;
    const check = native.verifyLease(token, {
      product: options.product,
      fingerprintHash: options.fingerprintHash,
      now: options.now ?? Math.floor(Date.now() / 1000),
      ...(options.graceSeconds !== undefined ? { graceSeconds: options.graceSeconds } : {}),
    });
    const agree = check.ok === result.ok && (result.ok || check.reason === result.reason);
    return agree ? result : { ok: false, reason: 'bad_signature' };
  }

  private stateFromLease(stored: Leased, offline: boolean): LicenseState {
    const fingerprintHash = this.fingerprintCache!;
    const now = this.nowSec();
    const keyHint = `${stored.licenseKey.slice(0, 7)}…${stored.licenseKey.slice(-4)}`;
    if (offline && stored.lastSeen !== undefined && now < stored.lastSeen - CLOCK_TOLERANCE_SECONDS) {
      return this.emptyState('clock_suspect', offline, { reason: 'clock_rollback', message: CLOCK_MESSAGE, keyHint });
    }
    const verifyOptions = { keys: this.keys, product: this.opts.product, fingerprintHash, now };
    const strict = this.verify(stored.token, verifyOptions);
    const fromClaims = (claims: LeaseClaims) => ({
      customer: claims.cus,
      features: claims.feat,
      expiresAt: claims.exp === undefined ? null : toIso(claims.exp),
      maintenanceUntil: claims.mnt === undefined ? null : toIso(claims.mnt),
      storageProtected: this.storageProtected,
      keyHint,
      ...(stored.notices ? { notices: stored.notices } : {}),
      ...(stored.offline ? { offlineActivated: true } : {}),
    });
    if (strict.ok) {
      return { status: 'valid', offline, ...fromClaims(strict.claims), revalidateBy: toIso(strict.claims.rev) };
    }
    if (strict.reason === 'not_yet_valid') {
      return this.emptyState('clock_suspect', offline, { reason: 'lease_from_future', message: CLOCK_MESSAGE, keyHint });
    }
    if (strict.reason === 'revalidation_required' && strict.claims) {
      const grace = strict.claims.grc ?? (this.opts.graceDays ?? DEFAULT_GRACE_DAYS) * 86400;
      const lenient = this.verify(stored.token, { ...verifyOptions, graceSeconds: grace });
      if (lenient.ok) {
        return {
          status: 'grace',
          offline,
          reason: 'offline_grace',
          message: stored.offline
            ? 'This offline license is past its renewal date. Load a new offline license file soon to keep using the app.'
            : 'Working offline. Connect to the internet soon to keep using the app.',
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
      ...this.deviceKey(),
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
    if (stored.offline && stored.token) {
      // Activated from an offline license file: the machine is not expected to reach the server.
      const state = this.stateFromLease({ ...stored, token: stored.token }, true);
      if (state.status === 'valid' || state.status === 'grace') {
        await this.save({ ...stored, lastSeen: Math.max(stored.lastSeen ?? 0, this.nowSec()) });
      }
      return state;
    }
    try {
      const response = await this.post('/v1/validate', {
        licenseKey: stored.licenseKey,
        product: this.opts.product,
        fingerprint: this.fingerprintCache,
        appVersion: this.opts.appVersion,
        sdkVersion: SDK_VERSION,
        ...(await this.hardware()),
        ...this.deviceKey(),
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

  /**
   * Decrypts data you encrypted for a feature (encryptForFeature in @carchalabs/licensekit-core, with the
   * feature's content key from the console). Works offline: it uses the saved lease, which must be valid
   * (or in its offline grace period), grant the feature and carry its key, and the saved license key.
   * The native module does the work when it trusts this app's keys, so the content key never reaches
   * JavaScript; without it the JavaScript implementation is used. Throws a LicenseError:
   * `unlicensed`, a lease failure reason, `clock_suspect`, `feature_not_licensed` or `decrypt_failed`.
   */
  async decrypt(feature: string, data: Uint8Array): Promise<Buffer> {
    const fingerprintHash = await this.fingerprint();
    const stored = await this.load();
    if (!stored?.token) throw new LicenseError('unlicensed', 'This device has no license.');
    const leased: Leased = { ...stored, token: stored.token };
    const state = this.stateFromLease(leased, true);
    if (state.status !== 'valid' && state.status !== 'grace') {
      throw new LicenseError(state.status === 'clock_suspect' ? 'clock_suspect' : (state.reason ?? 'invalid'), state.message ?? 'The license is not valid.');
    }
    const claims = decodeLease(leased.token)?.claims;
    const graceSeconds = state.status === 'grace' ? (claims?.grc ?? (this.opts.graceDays ?? DEFAULT_GRACE_DAYS) * 86400) : 0;
    const check = { product: this.opts.product, fingerprintHash, now: this.nowSec(), ...(graceSeconds ? { graceSeconds } : {}) };
    const native = this.native();
    const result: { ok: boolean; data?: Buffer; reason?: string } =
      native && typeof native.decryptFeature === 'function'
        ? native.decryptFeature(leased.token, check, leased.licenseKey, feature, Buffer.from(data))
        : decryptFeature(leased.token, { keys: this.keys, ...check }, leased.licenseKey, feature, Buffer.from(data));
    if (result.ok && result.data) return Buffer.from(result.data);
    if (result.reason === 'not_licensed') throw new LicenseError('feature_not_licensed', `This license does not include "${feature}".`);
    if (result.reason === 'decrypt_failed') throw new LicenseError('decrypt_failed', 'The data could not be decrypted with this license.');
    throw new LicenseError(result.reason ?? 'invalid', REASON_TEXT[result.reason as LeaseFailure] ?? 'The license is not valid.');
  }

  /**
   * Offline activation, step 1 on a machine that cannot reach the server: the request file (JSON text)
   * the user takes to a connected device. The license server turns it into a license file at
   * POST /v1/offline/activate (or its offline activation page). It holds what activate() would send:
   * the license key, this device's fingerprint and hashed hardware parts, never raw serial numbers.
   */
  async offlineRequest(licenseKey: string, machineName = hostname()): Promise<string> {
    const fingerprint = await this.fingerprint();
    const activation = {
      licenseKey: licenseKey.trim().toUpperCase(),
      product: this.opts.product,
      fingerprint,
      machineName: machineName.slice(0, 80),
      platform: platform(),
      appVersion: this.opts.appVersion,
      sdkVersion: SDK_VERSION,
      ...(await this.hardware()),
      ...this.deviceKey(),
    };
    return JSON.stringify({ format: OFFLINE_REQUEST_FORMAT, version: 1, activation }, null, 2);
  }

  /**
   * Offline activation, step 2: loads the license file the server issued for this machine's request.
   * It is verified like an online lease (signature, product, this device) and then saved; from then on
   * check() works without the server until the lease's renewal date plus the offline grace. Throws a
   * LicenseError: `invalid_file`, `wrong_product`, or a lease failure reason such as `wrong_device`.
   */
  async activateOffline(licenseFile: string): Promise<LicenseState> {
    await this.fingerprint();
    let file: any;
    try {
      file = JSON.parse(licenseFile);
    } catch {
      throw new LicenseError('invalid_file', 'This is not a LicenseKit offline license file.');
    }
    if (!file || file.format !== OFFLINE_LICENSE_FORMAT || file.version !== 1 || typeof file.token !== 'string' || typeof file.licenseKey !== 'string') {
      throw new LicenseError('invalid_file', 'This is not a LicenseKit offline license file.');
    }
    if (file.product !== this.opts.product) throw new LicenseError('wrong_product', 'This offline license file is for another product.');
    const stored: Leased = { licenseKey: file.licenseKey.trim().toUpperCase(), token: file.token, lastSeen: this.nowSec(), offline: true };
    const state = this.stateFromLease(stored, true);
    if (state.status !== 'valid') {
      throw new LicenseError(state.status === 'clock_suspect' ? 'clock_suspect' : state.reason ?? 'invalid', state.message ?? 'This offline license file cannot be used on this computer.');
    }
    await this.save(stored);
    return state;
  }

  /**
   * Gives an offline machine's seat back: removes the license from this device and returns the
   * deactivation file (JSON text) for the vendor, who frees the seat by uploading it in the console.
   * Throws `unlicensed` when there is no license to remove.
   */
  async deactivateOffline(): Promise<string> {
    const stored = await this.load();
    if (!stored?.token) throw new LicenseError('unlicensed', 'This device has no license.');
    await this.clear();
    return JSON.stringify({ format: OFFLINE_DEACTIVATION_FORMAT, version: 1, product: this.opts.product, token: stored.token }, null, 2);
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
