// Runs a client scenario through the SDK: a fixed machine id, a scripted license server and a set clock, one step
// after another on the same storage. What each step sends and returns is the SDK's behaviour that the native SDKs
// (packages/client) must reproduce; packages/client/tests/make-vectors.js records it, client-vectors.test.ts checks
// that the recorded file still matches this SDK. Named *.test.ts so it is not published.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LicenseError, MachineIdUnavailableError, Seal } from './index';

/** The server's answer to the step's one request: a JSON body, a raw text body, or no connection. */
export type ScriptedResponse = { status: number; body?: unknown; raw?: string } | { network: true };

export interface ScenarioStep {
  call: 'activate' | 'check' | 'deactivate' | 'offlineRequest' | 'activateOffline' | 'deactivateOffline' | 'decrypt';
  /** activate / offlineRequest: [licenseKey, machineName?]; activateOffline: [file]; decrypt: [feature, base64 data]. */
  args?: unknown[];
  /** The device clock for this step, milliseconds since the Unix epoch. */
  nowMs: number;
  response?: ScriptedResponse;
}

export interface Scenario {
  name: string;
  options: { product: string; publicKey: string[]; graceDays?: number; appVersion?: string };
  /** The raw OS machine id; null when it cannot be read. */
  machineId: string | null;
  steps: ScenarioStep[];
}

export interface StepOutcome {
  /** What the SDK sent: path and JSON body, the SDK version and platform replaced by placeholders. */
  requests: { path: string; body: unknown }[];
  result: { ok: true; value: unknown } | { ok: false; error: { code: string; message: string } };
}

const SERVER = 'https://seal.example.com';

/** Values that differ by SDK and platform, so every SDK's output can be compared with the same file. */
export function placeholders(value: any): any {
  if (!value || typeof value !== 'object') return value;
  const copy = { ...value };
  if ('sdkVersion' in copy) copy.sdkVersion = '<sdk-version>';
  if ('platform' in copy) copy.platform = '<platform>';
  if (copy.activation) copy.activation = placeholders(copy.activation);
  return copy;
}

export async function runScenario(scenario: Scenario): Promise<StepOutcome[]> {
  const dir = mkdtempSync(join(tmpdir(), 'seal-scenario-'));
  let step: ScenarioStep = scenario.steps[0];
  let requests: StepOutcome['requests'] = [];
  const fetchImpl = (async (url: string, init: RequestInit) => {
    requests.push({ path: url.slice(SERVER.length), body: placeholders(JSON.parse(String(init.body))) });
    const response = step.response;
    if (!response || 'network' in response) throw new TypeError('fetch failed');
    const text = response.raw ?? JSON.stringify(response.body ?? {});
    return new Response(text, { status: response.status, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  const seal = new Seal({
    serverUrl: SERVER,
    product: scenario.options.product,
    publicKey: scenario.options.publicKey,
    storageDir: dir,
    ...(scenario.options.graceDays !== undefined ? { graceDays: scenario.options.graceDays } : {}),
    ...(scenario.options.appVersion !== undefined ? { appVersion: scenario.options.appVersion } : {}),
    hardware: false,
    fetchImpl,
    machineId: async () => {
      if (scenario.machineId === null) throw new MachineIdUnavailableError();
      return scenario.machineId;
    },
    now: () => step.nowMs,
  });
  const outcomes: StepOutcome[] = [];
  try {
    for (step of scenario.steps) {
      requests = [];
      const args = step.args ?? [];
      let result: StepOutcome['result'];
      try {
        const value = await call(seal, step.call, args);
        result = { ok: true, value };
      } catch (e) {
        if (!(e instanceof LicenseError)) throw e;
        result = { ok: false, error: { code: e.code, message: e.message } };
      }
      outcomes.push({ requests, result });
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return outcomes;
}

async function call(seal: Seal, name: ScenarioStep['call'], args: unknown[]): Promise<unknown> {
  switch (name) {
    case 'activate':
      return seal.activate(args[0] as string, args[1] as string | undefined);
    case 'check':
      return seal.check();
    case 'deactivate':
      await seal.deactivate();
      return null;
    case 'offlineRequest':
      return placeholders(JSON.parse(await seal.offlineRequest(args[0] as string, args[1] as string | undefined)));
    case 'activateOffline':
      return seal.activateOffline(args[0] as string);
    case 'deactivateOffline':
      return JSON.parse(await seal.deactivateOffline());
    case 'decrypt':
      return (await seal.decrypt(args[0] as string, Buffer.from(args[1] as string, 'base64'))).toString('base64');
  }
}
