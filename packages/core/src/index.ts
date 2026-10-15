import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
  KeyObject,
} from 'node:crypto';

export const LEASE_ALGORITHM = 'Ed25519';
export const LEASE_TYPE = 'licensekit-lease+jwt';
export const LEASE_ISSUER = 'licensekit';
export const DEFAULT_LEEWAY_SECONDS = 300;

export interface LeaseHeader {
  alg: string;
  typ: string;
  kid: string;
}

export interface LeaseClaims {
  iss: string;
  sub: string;
  aud: string;
  jti: string;
  iat: number;
  nbf: number;
  exp?: number;
  rev: number;
  fp: string;
  feat: string[];
  cus?: string;
  grc?: number;
  mnt?: number;
  /** Wrapped feature content keys, by feature (see wrapFeatureKey). */
  fk?: Record<string, string>;
  /** The server's one-off X25519 public key (base64url) when fk is wrapped for a device key. */
  epk?: string;
}

export interface PublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid: string;
  alg: typeof LEASE_ALGORITHM;
  use: 'sig';
}

export type LeaseFailure =
  | 'malformed'
  | 'unsupported_algorithm'
  | 'wrong_type'
  | 'unknown_key'
  | 'bad_signature'
  | 'wrong_issuer'
  | 'wrong_product'
  | 'wrong_device'
  | 'not_yet_valid'
  | 'expired'
  | 'revalidation_required';

export type LeaseVerifyResult =
  | { ok: true; header: LeaseHeader; claims: LeaseClaims }
  | { ok: false; reason: LeaseFailure; claims?: LeaseClaims };

export type KeyInput = string | KeyObject;

export interface LeaseVerifyOptions {
  keys: KeyInput[] | Map<string, KeyObject>;
  product: string;
  fingerprintHash: string;
  issuer?: string;
  now?: number;
  graceSeconds?: number;
  leewaySeconds?: number;
}

const toBase64Url = (buf: Buffer) => buf.toString('base64url');
const fromBase64Url = (text: string) => Buffer.from(text, 'base64url');
const BASE64URL = /^[A-Za-z0-9_-]+$/;

function asPrivateKey(key: KeyInput): KeyObject {
  return typeof key === 'string' ? createPrivateKey(key) : key;
}

function asPublicKey(key: KeyInput): KeyObject {
  if (typeof key === 'string') return createPublicKey(key);
  return key.type === 'private' ? createPublicKey(key) : key;
}

export function generateSigningKeys(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

export function publicKeyFromPrivate(privateKeyPem: string): string {
  return createPublicKey(createPrivateKey(privateKeyPem)).export({ type: 'spki', format: 'pem' }).toString();
}

function ed25519PublicX(key: KeyInput): string {
  const jwk = asPublicKey(key).export({ format: 'jwk' });
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error('Only Ed25519 keys are supported');
  }
  return jwk.x;
}

export function keyId(key: KeyInput): string {
  const canonical = JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: ed25519PublicX(key) });
  return toBase64Url(createHash('sha256').update(canonical, 'utf8').digest());
}

export function publicJwk(key: KeyInput): PublicJwk {
  return { kty: 'OKP', crv: 'Ed25519', x: ed25519PublicX(key), kid: keyId(key), alg: LEASE_ALGORITHM, use: 'sig' };
}

export function keySet(keys: KeyInput[]): Map<string, KeyObject> {
  const set = new Map<string, KeyObject>();
  for (const key of keys) {
    const publicKey = asPublicKey(key);
    set.set(keyId(publicKey), publicKey);
  }
  return set;
}

export function signLease(claims: LeaseClaims, privateKey: KeyInput): string {
  const key = asPrivateKey(privateKey);
  const header: LeaseHeader = { alg: LEASE_ALGORITHM, typ: LEASE_TYPE, kid: keyId(key) };
  const signingInput = `${toBase64Url(Buffer.from(JSON.stringify(header), 'utf8'))}.${toBase64Url(Buffer.from(JSON.stringify(claims), 'utf8'))}`;
  const signature = sign(null, Buffer.from(signingInput, 'ascii'), key);
  return `${signingInput}.${toBase64Url(signature)}`;
}

function parseSegment(segment: string): unknown {
  if (!BASE64URL.test(segment)) return null;
  try {
    return JSON.parse(fromBase64Url(segment).toString('utf8'));
  } catch {
    return null;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isLeaseClaims(value: unknown): value is LeaseClaims {
  if (!isObject(value)) return false;
  const strings = ['iss', 'sub', 'aud', 'jti', 'fp'].every((name) => typeof value[name] === 'string');
  const numbers = ['iat', 'nbf', 'rev'].every((name) => Number.isFinite(value[name]));
  const expiry = value.exp === undefined || Number.isFinite(value.exp);
  const features = Array.isArray(value.feat) && value.feat.every((feature) => typeof feature === 'string');
  const customer = value.cus === undefined || typeof value.cus === 'string';
  const optionalTimes = ['grc', 'mnt'].every((name) => value[name] === undefined || (Number.isFinite(value[name]) && (value[name] as number) >= 0));
  const featureKeys = value.fk === undefined || (isObject(value.fk) && Object.values(value.fk).every((wrapped) => typeof wrapped === 'string'));
  const ephemeral = value.epk === undefined || typeof value.epk === 'string';
  return strings && numbers && expiry && features && customer && optionalTimes && featureKeys && ephemeral;
}

export function decodeLease(token: string): { header: LeaseHeader; claims: LeaseClaims } | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const header = parseSegment(parts[0]);
  const claims = parseSegment(parts[1]);
  if (!isObject(header) || !isLeaseClaims(claims)) return null;
  return { header: header as unknown as LeaseHeader, claims };
}

export function verifyLease(token: string, options: LeaseVerifyOptions): LeaseVerifyResult {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) return { ok: false, reason: 'malformed' };
  const [encodedHeader, encodedClaims, encodedSignature] = parts;

  const header = parseSegment(encodedHeader);
  if (!isObject(header)) return { ok: false, reason: 'malformed' };
  if (header.alg !== LEASE_ALGORITHM) return { ok: false, reason: 'unsupported_algorithm' };
  if (header.typ !== LEASE_TYPE) return { ok: false, reason: 'wrong_type' };
  // RFC 7515 4.1.11: a header that names critical extensions the verifier does not understand must be rejected.
  // Leases use none, so any "crit" makes the lease invalid.
  if ('crit' in header) return { ok: false, reason: 'malformed' };

  const keys = options.keys instanceof Map ? options.keys : keySet(options.keys);
  const key = typeof header.kid === 'string' ? keys.get(header.kid) : undefined;
  if (!key) return { ok: false, reason: 'unknown_key' };

  if (!BASE64URL.test(encodedSignature)) return { ok: false, reason: 'malformed' };
  let signatureValid = false;
  try {
    signatureValid = verify(null, Buffer.from(`${encodedHeader}.${encodedClaims}`, 'ascii'), key, fromBase64Url(encodedSignature));
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) return { ok: false, reason: 'bad_signature' };

  const claims = parseSegment(encodedClaims);
  if (!isLeaseClaims(claims)) return { ok: false, reason: 'malformed' };

  if (claims.iss !== (options.issuer ?? LEASE_ISSUER)) return { ok: false, reason: 'wrong_issuer', claims };
  if (claims.aud !== options.product) return { ok: false, reason: 'wrong_product', claims };
  if (claims.fp !== options.fingerprintHash) return { ok: false, reason: 'wrong_device', claims };

  // The same clock-skew leeway on both ends (RFC 7519 4.1.4, 4.1.5).
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const leeway = options.leewaySeconds ?? DEFAULT_LEEWAY_SECONDS;
  if (now + leeway < claims.nbf) return { ok: false, reason: 'not_yet_valid', claims };
  if (claims.exp !== undefined && now - leeway >= claims.exp) return { ok: false, reason: 'expired', claims };
  if (now >= claims.rev + (options.graceSeconds ?? 0)) return { ok: false, reason: 'revalidation_required', claims };

  return { ok: true, header: header as unknown as LeaseHeader, claims };
}

export function hashFingerprint(rawFingerprint: string, product: string): string {
  return createHash('sha256').update(`licensekit:${product}:${rawFingerprint}`).digest('hex');
}

const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const LICENSE_KEY_PREFIX = 'LK';

// 28 symbols x 5 bits = 140 random bits, above the 128-bit minimum for a
// bearer secret (OWASP ASVS 5.0 V6.1.1 / NIST SP 800-63B). Seven groups of
// four keep the format readable. Keys issued with four groups (80 bits)
// still normalize and hash the same way, so they keep working.
const LICENSE_KEY_SYMBOLS = 28;

export function generateLicenseKey(): string {
  // 256 is a multiple of 32, so byte & 31 picks each symbol uniformly.
  const bytes = randomBytes(LICENSE_KEY_SYMBOLS);
  const body = Array.from(bytes, (byte) => CROCKFORD_ALPHABET[byte & 31]).join('');
  return `${LICENSE_KEY_PREFIX}-${body.match(/.{4}/g)!.join('-')}`;
}

export function normalizeLicenseKey(input: string): string {
  let body = input.toUpperCase().replace(/[\s-]/g, '');
  if (body.startsWith(LICENSE_KEY_PREFIX)) body = body.slice(LICENSE_KEY_PREFIX.length);
  body = body.replace(/[IL]/g, '1').replace(/O/g, '0');
  const groups = body.match(/.{1,4}/g) ?? [];
  return [LICENSE_KEY_PREFIX, ...groups].join('-');
}

export function hashLicenseKey(input: string): string {
  return createHash('sha256').update(normalizeLicenseKey(input)).digest('hex');
}

export function legacyLicenseKeyHash(input: string): string {
  return createHash('sha256').update(input.trim().toUpperCase()).digest('hex');
}

// ---- Feature keys -------------------------------------------------------------------------
//
// Each feature of a product has a secret 256-bit content key on the server. The vendor encrypts
// data for a feature with it (encryptForFeature). A lease carries every licensed feature's content
// key wrapped for that lease (claim "fk"): AES-256-GCM (NIST SP 800-38D) under a key derived with
// HKDF-SHA256 (RFC 5869) from the license key, the product, the device fingerprint and the lease id.
// So only a holder of the license key, on the device the lease was issued to, can unwrap it.

const FEATURE_WRAP_SALT = Buffer.from('licensekit feature key v1', 'utf8');
const ENCRYPTED_MAGIC = Buffer.from('LKE1', 'ascii');
const GCM_NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;

export class FeatureCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FeatureCryptoError';
  }
}

/** A new random content key for a feature (32 bytes). */
export function generateFeatureKey(): Buffer {
  return randomBytes(32);
}

/** The key a lease's feature keys are wrapped with: HKDF-SHA256 over the normalized license key. */
export function featureWrapKey(licenseKey: string, product: string, fingerprintHash: string, leaseId: string): Buffer {
  const info = Buffer.from(`${product}\n${fingerprintHash}\n${leaseId}`, 'utf8');
  return Buffer.from(hkdfSync('sha256', Buffer.from(normalizeLicenseKey(licenseKey), 'utf8'), FEATURE_WRAP_SALT, info, 32));
}

function seal(key: Buffer, plaintext: Buffer, aad: string, nonce: Buffer): Buffer {
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: GCM_TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  return Buffer.concat([nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function open(key: Buffer, sealed: Buffer, aad: string): Buffer {
  if (sealed.length < GCM_NONCE_BYTES + GCM_TAG_BYTES) throw new FeatureCryptoError('too short');
  const nonce = sealed.subarray(0, GCM_NONCE_BYTES);
  const tag = sealed.subarray(sealed.length - GCM_TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: GCM_TAG_BYTES });
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(sealed.subarray(GCM_NONCE_BYTES, sealed.length - GCM_TAG_BYTES)), decipher.final()]);
  } catch {
    throw new FeatureCryptoError('authentication failed');
  }
}

/** Wraps a feature's content key for one lease (the value of claims.fk[feature]), base64url. */
export function wrapFeatureKey(contentKey: Buffer, wrapKey: Buffer, feature: string, nonce: Buffer = randomBytes(GCM_NONCE_BYTES)): string {
  if (contentKey.length !== 32) throw new FeatureCryptoError('a content key is 32 bytes');
  return toBase64Url(seal(wrapKey, contentKey, `fk:${feature}`, nonce));
}

export function unwrapFeatureKey(wrapped: string, wrapKey: Buffer, feature: string): Buffer {
  if (!BASE64URL.test(wrapped)) throw new FeatureCryptoError('not base64url');
  const key = open(wrapKey, fromBase64Url(wrapped), `fk:${feature}`);
  if (key.length !== 32) throw new FeatureCryptoError('a content key is 32 bytes');
  return key;
}

/** Encrypts data for a feature: "LKE1" || nonce || AES-256-GCM ciphertext || tag, the feature as associated data. */
export function encryptForFeature(contentKey: Buffer, feature: string, data: Buffer, nonce: Buffer = randomBytes(GCM_NONCE_BYTES)): Buffer {
  if (contentKey.length !== 32) throw new FeatureCryptoError('a content key is 32 bytes');
  return Buffer.concat([ENCRYPTED_MAGIC, seal(contentKey, data, `LKE1:${feature}`, nonce)]);
}

export function decryptForFeature(contentKey: Buffer, feature: string, encrypted: Buffer): Buffer {
  if (encrypted.length < ENCRYPTED_MAGIC.length || !encrypted.subarray(0, ENCRYPTED_MAGIC.length).equals(ENCRYPTED_MAGIC)) {
    throw new FeatureCryptoError('not data encrypted for Carcha Seal');
  }
  return open(contentKey, encrypted.subarray(ENCRYPTED_MAGIC.length), `LKE1:${feature}`);
}

// ---- Device keys -----------------------------------------------------------------------------
//
// A device can have an X25519 key pair derived from its hardware (the native module does this; the
// secret never leaves it). When the device sends its public key, the server wraps the lease's feature
// keys for it: a one-off X25519 key per lease (claim epk), the shared secret (RFC 7748) and the license
// key go through HKDF-SHA256 with the product, fingerprint, lease id and both public keys. Only that
// device's hardware gives the secret, so a copied license file opens nothing on another machine.

const DEVICE_WRAP_SALT = Buffer.from('licensekit feature key v2 device', 'utf8');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

function x25519Private(secret: Buffer): KeyObject {
  if (secret.length !== 32) throw new FeatureCryptoError('an X25519 key is 32 bytes');
  return createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, secret]), format: 'der', type: 'pkcs8' });
}

function x25519Public(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new FeatureCryptoError('an X25519 key is 32 bytes');
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

/** X25519 (RFC 7748); OpenSSL refuses low-order public keys, which surface as a FeatureCryptoError. */
function x25519(privateKey: KeyObject, publicKey: KeyObject): Buffer {
  try {
    return diffieHellman({ privateKey, publicKey });
  } catch {
    throw new FeatureCryptoError('invalid device or server key');
  }
}

function rawPublic(key: KeyObject): Buffer {
  return (key.export({ format: 'der', type: 'spki' }) as Buffer).subarray(X25519_SPKI_PREFIX.length);
}

/** The X25519 public key of a device secret (32 bytes each). */
export function devicePublicKey(deviceSecret: Buffer): Buffer {
  return rawPublic(createPublicKey(x25519Private(deviceSecret)));
}

function deviceWrapKey(shared: Buffer, licenseKey: string, product: string, fingerprintHash: string, leaseId: string, epk: Buffer, devicePublic: Buffer): Buffer {
  // RFC 7748 6.1: an all-zero shared secret means a low-order public key; refuse it.
  if (shared.every((b) => b === 0)) throw new FeatureCryptoError('invalid device or server key');
  const ikm = Buffer.concat([shared, Buffer.from(normalizeLicenseKey(licenseKey), 'utf8')]);
  const info = Buffer.from(`${product}\n${fingerprintHash}\n${leaseId}\n${toBase64Url(epk)}\n${toBase64Url(devicePublic)}`, 'utf8');
  return Buffer.from(hkdfSync('sha256', ikm, DEVICE_WRAP_SALT, info, 32));
}

/** Server side: a one-off key pair for this lease and the wrap key for the device's public key. */
export function featureWrapKeyForDevice(
  licenseKey: string,
  product: string,
  fingerprintHash: string,
  leaseId: string,
  devicePublic: Buffer,
  ephemeralSecret: Buffer = randomBytes(32),
): { wrapKey: Buffer; epk: string } {
  const ephemeral = x25519Private(ephemeralSecret);
  const epk = rawPublic(createPublicKey(ephemeral));
  const shared = x25519(ephemeral, x25519Public(devicePublic));
  return { wrapKey: deviceWrapKey(shared, licenseKey, product, fingerprintHash, leaseId, epk, devicePublic), epk: toBase64Url(epk) };
}

/** Device side: the wrap key from the device secret and the lease's epk. */
export function deviceFeatureWrapKey(licenseKey: string, product: string, fingerprintHash: string, leaseId: string, deviceSecret: Buffer, epk: string): Buffer {
  if (!BASE64URL.test(epk)) throw new FeatureCryptoError('epk is not base64url');
  const epkRaw = fromBase64Url(epk);
  const shared = x25519(x25519Private(deviceSecret), x25519Public(epkRaw));
  return deviceWrapKey(shared, licenseKey, product, fingerprintHash, leaseId, epkRaw, devicePublicKey(deviceSecret));
}

export type FeatureDecryptResult =
  | { ok: true; data: Buffer }
  | { ok: false; reason: LeaseFailure | 'not_licensed' | 'decrypt_failed' };

/**
 * Verifies the lease, unwraps the feature's content key for this license key and device, and
 * decrypts data encrypted for the feature. The native module does the same (decryptFeature).
 */
export function decryptFeature(
  token: string,
  options: LeaseVerifyOptions,
  licenseKey: string,
  feature: string,
  encrypted: Buffer,
  deviceSecret?: Buffer,
): FeatureDecryptResult {
  const verified = verifyLease(token, options);
  if (!verified.ok) return { ok: false, reason: verified.reason };
  const wrapped = verified.claims.fk?.[feature];
  if (!verified.claims.feat.includes(feature) || typeof wrapped !== 'string') return { ok: false, reason: 'not_licensed' };
  try {
    const { epk, jti } = verified.claims;
    if (epk !== undefined && !deviceSecret) return { ok: false, reason: 'decrypt_failed' };
    const wrapKey =
      epk !== undefined
        ? deviceFeatureWrapKey(licenseKey, options.product, options.fingerprintHash, jti, deviceSecret!, epk)
        : featureWrapKey(licenseKey, options.product, options.fingerprintHash, jti);
    return { ok: true, data: decryptForFeature(unwrapFeatureKey(wrapped, wrapKey, feature), feature, encrypted) };
  } catch {
    return { ok: false, reason: 'decrypt_failed' };
  }
}
