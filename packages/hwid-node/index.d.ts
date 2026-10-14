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
  /** The failure reason, as @carchalabs/licensekit-core names it; absent when ok. */
  reason?: string;
  /** Id of the key that signed the lease; present when ok. */
  kid?: string;
}

/**
 * Verifies a lease with the public keys compiled into this build and the same rules,
 * order and reasons as verifyLease in @carchalabs/licensekit-core.
 */
export function verifyLease(token: string, check: LeaseCheck): LeaseVerdict;

/** Ids of the lease signing keys this build trusts (keyId in @carchalabs/licensekit-core). */
export function leaseKeyIds(): string[];

/** Version of the native core, e.g. "0.1.0". */
export function version(): string;
