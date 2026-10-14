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

/** Version of the native core, e.g. "0.1.0". */
export function version(): string;
