// The client scenarios in packages/client/tests/vectors.json (what the native SDKs must reproduce) still match this
// SDK: every step sends the same requests and returns the same result. Regenerate the file with
// packages/client/tests/make-vectors.js after a deliberate change to the SDK's behaviour.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runScenario, Scenario, StepOutcome } from './scenario-runner.test';

const file = JSON.parse(readFileSync(join(__dirname, '../../client/tests/vectors.json'), 'utf8')) as {
  scenarios: (Scenario & { outcomes: StepOutcome[] })[];
};

test('the client vectors cover enough scenarios', () => {
  assert.ok(file.scenarios.length >= 25);
});

for (const { outcomes, ...scenario } of file.scenarios) {
  test(`client vector: ${scenario.name}`, async () => {
    // As JSON, the form the file and the native SDKs have: a field set to undefined is a field not present.
    assert.deepStrictEqual(JSON.parse(JSON.stringify(await runScenario(scenario))), outcomes);
  });
}
