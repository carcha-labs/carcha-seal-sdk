export type ComponentKind = 'uuid' | 'board' | 'disk' | 'mac' | 'os' | 'cpu' | 'gpu';

export interface Component {
  kind: ComponentKind;
  /** Lowercase hex HMAC-SHA256 of the component, keyed by the product. */
  hash: string;
}

export interface Collected {
  /** Version of the result shape. */
  format: number;
  /** True when a hypervisor was detected (best effort). */
  vm: boolean;
  components: Component[];
  /** Why kinds are missing: the failing call and its error code, never a value. */
  notes: string[];
}

/** Reads this machine's components and hashes each with the product key. */
export function collect(key: string | Buffer): Collected;

export interface LeaseCheck {
  product: string;
  fingerprintHash: string;
  /** Seconds since the Unix epoch; default: now. */
  now?: number;
  graceSeconds?: number;
  leewaySeconds?: number;
  issuer?: string;
}

export interface LeaseVerdict {
  ok: boolean;
  /** The failure reason, as @carchalabs/seal-core names it; absent when ok. */
  reason?: string;
  /** Id of the key that signed the lease; present when ok. */
  kid?: string;
}

/**
 * Verifies a lease with the public keys compiled into this build and the same rules,
 * order and reasons as verifyLease in @carchalabs/seal-core.
 */
export function verifyLease(token: string, check: LeaseCheck): LeaseVerdict;

export interface FeatureDecrypt {
  ok: boolean;
  /** The plaintext; present when ok. */
  data?: Buffer;
  /** A lease failure reason, 'not_licensed' or 'decrypt_failed'; absent when ok. */
  reason?: string;
}

/**
 * Verifies the lease (compiled-in keys), unwraps the feature's content key for this license key and
 * device, and decrypts data encrypted for the feature (encryptForFeature in @carchalabs/seal-core). The
 * content key never reaches JavaScript.
 */
export function decryptFeature(token: string, check: LeaseCheck, licenseKey: string, feature: string, data: Buffer): FeatureDecrypt;

/** Ids of the lease signing keys this build trusts (keyId in @carchalabs/seal-core). */
export function leaseKeyIds(): string[];

/**
 * This machine's X25519 device public key (base64url) for a product key, derived from its system UUID,
 * motherboard serial, system disk serial and OS install id; null when it reports none of them. The
 * secret half never leaves the module. It changes when one of those parts changes.
 */
export function devicePublicKey(key: string | Buffer): string | null;

/** Version of the native core, e.g. "0.1.0". */
export function version(): string;
