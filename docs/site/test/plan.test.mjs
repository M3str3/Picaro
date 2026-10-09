/**
 * Plan-builder model tests.
 *
 * Run with `npm test` (Node's built-in test runner). The unit tests exercise
 * `plan.js` against the real catalogue; `takesPayload`'s category fallback is
 * checked against a tiny stub catalogue.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import yaml from 'js-yaml';

import {
  baseState,
  newPayload,
  fieldsOf,
  takesPayload,
  makeStep,
  emitYaml,
  advisories,
  stepWarning,
  stepPayloadName,
  stubLabel,
  splitArgs,
} from '../src/components/plan-builder/plan.js';
import { buildTechniqueCatalog } from '../scripts/catalog.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');

/** The real catalogue, keyed by technique id. */
const CATALOG = buildTechniqueCatalog(repoRoot);
const TECH = Object.fromEntries(CATALOG.techniques.map((t) => [t.id, t]));

/** Parse the YAML the builder emits. */
const parse = (state) => yaml.load(emitYaml(state, TECH));

/** A payload entry with sensible defaults. */
const payload = (name, overrides = {}) => ({ ...newPayload({ name }), ...overrides });

function stateWith(payloads, steps) {
  const state = baseState();
  state.payloads = payloads;
  state.steps = steps;
  return state;
}

/* ------------------------------------------------------------------ */
/* YAML emission                                                      */
/* ------------------------------------------------------------------ */

test('a fresh state declares a single payload and no steps', () => {
  const state = baseState();
  assert.equal(state.payloads.length, 1);
  assert.equal(state.payloads[0].name, 'payload');
  assert.deepEqual(state.steps, []);
});

test('a single payload is implicit: the Execution step emits no params.payload', () => {
  const state = stateWith([payload('payload')], [makeStep('reflective_loading', TECH)]);
  const doc = parse(state);
  assert.deepEqual(Object.keys(doc.build.payloads), ['payload']);
  assert.equal(doc.runtime[0].params, undefined);
});

test('with several payloads every Execution step names the one it loads', () => {
  const state = stateWith(
    [payload('dropper', { format: 'shellcode' }), payload('implant', { format: 'pe' })],
    [
      makeStep('reflective_loading', TECH, { payload: 'dropper' }),
      makeStep('process_hollowing', TECH, { payload: 'implant' }),
    ],
  );
  const doc = parse(state);
  assert.deepEqual(Object.keys(doc.build.payloads), ['dropper', 'implant']);
  assert.equal(doc.runtime[0].params.payload, 'dropper');
  assert.equal(doc.runtime[1].params.payload, 'implant');
});

test('a step that names no payload falls back to the first one', () => {
  const state = stateWith(
    [payload('first'), payload('second')],
    [makeStep('reflective_loading', TECH)],
  );
  const doc = parse(state);
  assert.equal(doc.runtime[0].params.payload, 'first');
});

test('the network_stager always names its payload', () => {
  const state = stateWith(
    [payload('implant', { format: 'shellcode', source: 'https://example.invalid/i.bin' })],
    [
      makeStep('network_stager', TECH, { payload: 'implant', url: 'https://example.invalid/i.bin' }),
      makeStep('reflective_loading', TECH, { payload: 'implant' }),
    ],
  );
  const doc = parse(state);
  assert.equal(doc.runtime[0].params.payload, 'implant');
  assert.equal(doc.runtime[0].params.url, 'https://example.invalid/i.bin');
  // A single payload is still implicit for the loader that consumes it.
  assert.equal(doc.runtime[1].params, undefined);
});

test('a payload keeps its own format, args and name', () => {
  const state = stateWith(
    [payload('recon', { source: './a.bin', format: 'shellcode', args: '--phase=recon, -v' })],
    [makeStep('reflective_loading', TECH, { payload: 'recon' })],
  );
  const doc = parse(state);
  assert.equal(doc.build.payloads.recon.source, './a.bin');
  assert.equal(doc.build.payloads.recon.format, 'shellcode');
  assert.deepEqual(doc.build.payloads.recon.args, ['--phase=recon', '-v']);
});

/* ------------------------------------------------------------------ */
/* validation (mirrors plan::validate)                                */
/* ------------------------------------------------------------------ */

const hasErr = (notes, re) => notes.some((n) => n.level === 'err' && re.test(n.text));

test('a chain without an Execution technique is an error', () => {
  const state = stateWith([payload('payload')], [makeStep('sleep', TECH)]);
  assert.ok(hasErr(advisories(state, TECH), /execution technique/));
});

test('a terminal technique that is not last is an error', () => {
  const state = stateWith(
    [payload('m', { format: 'dotnet' })],
    [makeStep('dotnet_hosting', TECH, { payload: 'm' }), makeStep('sleep', TECH)],
  );
  assert.ok(hasErr(advisories(state, TECH), /must be the last step/));
});

test('a terminal technique as the last step is fine', () => {
  const state = stateWith(
    [payload('m', { format: 'dotnet' })],
    [makeStep('sleep', TECH), makeStep('dotnet_hosting', TECH, { payload: 'm' })],
  );
  assert.ok(!hasErr(advisories(state, TECH), /must be the last step/));
});

test('a managed payload needs .NET hosting', () => {
  const state = stateWith(
    [payload('m', { format: 'dotnet' })],
    [makeStep('reflective_loading', TECH, { payload: 'm' })],
  );
  const notes = advisories(state, TECH);
  assert.ok(notes.some((n) => n.level === 'warn' && /managed \(\.NET\)/.test(n.text)));
  // The format mismatch itself is shown on the step's own card.
  const warning = stepWarning(state.steps[0], state, TECH);
  assert.equal(warning.level, 'err');
  assert.match(warning.text, /Does not accept format 'dotnet'/);
});

test('network_stager whose payload is loaded before it is an error', () => {
  const state = stateWith(
    [payload('s', { format: 'shellcode', source: 'https://example.invalid/s.bin' })],
    [
      makeStep('reflective_loading', TECH, { payload: 's' }),
      makeStep('network_stager', TECH, { payload: 's', url: 'https://example.invalid/s.bin' }),
    ],
  );
  assert.ok(hasErr(advisories(state, TECH), /must come after the stager/));
});

test('a correctly ordered stager reports what it ignores', () => {
  const state = stateWith(
    [payload('s', { format: 'shellcode', source: 'ignored-anyway' })],
    [
      makeStep('network_stager', TECH, { payload: 's', url: 'https://example.invalid/s.bin' }),
      makeStep('reflective_loading', TECH, { payload: 's' }),
    ],
  );
  const notes = advisories(state, TECH);
  assert.ok(!hasErr(notes, /stager/));
  assert.ok(notes.some((n) => n.level === 'info' && /source' is ignored/.test(n.text)));
});

test('two stagers is an error', () => {
  const state = stateWith(
    [payload('s', { format: 'shellcode', source: 'https://example.invalid/s.bin' })],
    [
      makeStep('network_stager', TECH, { payload: 's', url: 'https://example.invalid/s.bin' }),
      makeStep('network_stager', TECH, { payload: 's', url: 'https://example.invalid/s.bin' }),
      makeStep('reflective_loading', TECH, { payload: 's' }),
    ],
  );
  assert.ok(hasErr(advisories(state, TECH), /Only one network_stager/));
});

test('duplicate payload names are an error', () => {
  const state = stateWith([payload('a'), payload('a')], [makeStep('reflective_loading', TECH)]);
  assert.ok(hasErr(advisories(state, TECH), /both named 'a'/));
});

test('an empty payload source is an error', () => {
  const state = stateWith([payload('a', { source: '' })], [makeStep('reflective_loading', TECH)]);
  assert.ok(hasErr(advisories(state, TECH), /empty source/));
});

test('a step that does not accept the payload format is flagged on its card', () => {
  const state = stateWith(
    [payload('s', { format: 'pe' })],
    [makeStep('early_bird', TECH, { payload: 's' })],
  );
  const warning = stepWarning(state.steps[0], state, TECH);
  assert.equal(warning.level, 'err');
  assert.match(warning.text, /shellcode/);
});

/* ------------------------------------------------------------------ */
/* catalogue integration                                              */
/* ------------------------------------------------------------------ */

test('the catalogue marks every payload-taking technique', () => {
  for (const t of CATALOG.techniques.filter((t) => t.category === 'execution')) {
    assert.equal(t.takes_payload, true, `${t.id} should take a payload`);
  }
  assert.equal(TECH.network_stager.takes_payload, true);
  assert.equal(TECH.patch_amsi.takes_payload, false);
  assert.equal(TECH.bouncer.takes_payload, false);
});

test('takesPayload trusts the catalogue and falls back to the category', () => {
  assert.equal(takesPayload('reflective_loading', TECH), true);
  assert.equal(takesPayload('network_stager', TECH), true);
  assert.equal(takesPayload('patch_amsi', TECH), false);
  assert.equal(takesPayload('whatever', { whatever: { category: 'execution' } }), true);
  assert.equal(takesPayload('whatever', { whatever: { category: 'preparation' } }), false);
});

test('fieldsOf reads the Rust struct, drops payload and keeps types', () => {
  const stager = fieldsOf(TECH.network_stager);
  assert.ok(!stager.some((f) => f.key === 'payload'), 'payload is rendered as a picker');
  const downloader = stager.find((f) => f.key === 'downloader');
  assert.equal(downloader.type, 'select');
  assert.ok(downloader.options.includes('powershell'));

  const bouncer = fieldsOf(TECH.bouncer);
  const notInVm = bouncer.find((f) => f.key === 'not_in_vm');
  assert.equal(notInVm.type, 'bool');
  assert.equal(notInVm.def, true, 'a boolean default survives the string round-trip');
  const minRam = bouncer.find((f) => f.key === 'min_ram_mb');
  assert.equal(minRam.type, 'number');
});

test('stepPayloadName resolves the effective payload', () => {
  const state = stateWith([payload('a'), payload('b')], []);
  const step = makeStep('reflective_loading', TECH);
  assert.equal(stepPayloadName(step, state), 'a');
  step.params.payload = 'b';
  assert.equal(stepPayloadName(step, state), 'b');
});

test('splitArgs trims and drops empties', () => {
  assert.deepEqual(splitArgs(' a, b ,, c '), ['a', 'b', 'c']);
  assert.deepEqual(splitArgs(''), []);
});

test('a custom stub template is emitted under build.stub.path', () => {
  const state = stateWith([payload('payload')], [makeStep('sleep', TECH)]);
  state.stubPath = './examples/stubs/custom.rs';
  const doc = parse(state);
  assert.equal(doc.build.stub.path, './examples/stubs/custom.rs');
});

test('no stub block is emitted for the built-in stub', () => {
  const state = stateWith([payload('payload')], [makeStep('sleep', TECH)]);
  const doc = parse(state);
  assert.equal(doc.build.stub, undefined);
});

test('stubLabel names the built-in stub or the template basename', () => {
  assert.equal(stubLabel(baseState()), 'Built-in stub');
  assert.equal(stubLabel({ stubPath: '' }), 'Built-in stub');
  assert.equal(stubLabel({ stubPath: './a/b/custom.rs' }), 'custom.rs');
  assert.equal(stubLabel({ stubPath: 'C:\\stubs\\mine.rs' }), 'mine.rs');
});
