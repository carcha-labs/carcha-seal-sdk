import {
  createHash,
  createPrivateKey,
  createPublicKey,
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
  return strings && numbers && expiry && features && customer && optionalTimes;
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
