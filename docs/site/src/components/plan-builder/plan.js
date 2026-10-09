/**
 * Plan builder — pure plan model.
 *
 * Everything that turns the builder's `state` into a schema-6 YAML document and
 * everything that reports a problem `plan::validate` would lives here, with no
 * DOM access. `app.js` only renders this and wires events, so the model can be
 * unit-tested directly (docs/site/test/plan.test.mjs) and stays readable.
 *
 * The catalogue is always passed in (`TECH`, keyed by technique id) rather than
 * imported, so this module has no build-time coupling to the assembler.
 */

/** The picker's sections (mirrors `TechniqueDef::Category`). */
export const SECTIONS = [
  ['preparation', 'Preparation'],
  ['execution', 'Execution'],
  ['control', 'Control'],
];

/** Formats `build.payloads.<name>.format` accepts. */
export const PAYLOAD_FORMATS = ['pe', 'dll', 'shellcode', 'dotnet'];

/** A fresh payload block — one entry of `build.payloads`. */
export function newPayload(overrides = {}) {
  return { name: 'payload', source: './payload.exe', format: 'pe', args: '', ...overrides };
}

/**
 * The builder's initial state: one payload and an empty chain. Everything else
 * is the schema's default, so the emitted YAML stays minimal.
 */
export function baseState() {
  return {
    name: 'plan',
    out: './dist/packed.exe',
    kind: 'exe',
    arch: 'x64',
    strings: false,
    syscalls: 'none',
    resolver: 'hells_gate',
    proxy: false,
    stubPath: '',
    signLab: false,
    identity: false,
    debug: false,
    payloads: [newPayload()],
    steps: [],
  };
}

/** `min_ram_mb` → `Min Ram Mb`. */
export function humanize(key) {
  return String(key)
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim();
}

/**
 * Whether a technique takes a `params.payload` — an Execution technique, or the
 * control-plane `network_stager` that stages one. Read from the catalogue's
 * `takes_payload` (derived from the Rust `Params` struct), with a category
 * fallback for a catalogue assembled before that flag existed.
 */
export function takesPayload(id, TECH) {
  const def = TECH[id];
  if (!def) return false;
  if (typeof def.takes_payload === 'boolean') return def.takes_payload;
  return def.category === 'execution';
}

/**
 * The editable fields of a technique's step. Prefers the Rust `Params` struct
 * (`paramDocs`: every field, with type, default and allowed values) over the
 * curated `fields` from `params_example`, which is only a fallback for a
 * technique without a `Params` struct. The `payload` field is dropped: it is
 * rendered as a payload picker, not a free-text box.
 */
export function fieldsOf(def) {
  const docs = def?.paramDocs;
  if (Array.isArray(docs) && docs.length) {
    return docs
      .filter((d) => d.key !== 'payload')
      .map((d) => {
        const options = Array.isArray(d.options) ? d.options : [];
        let type = 'text';
        if (options.length) type = 'select';
        else if (d.type === 'boolean') type = 'bool';
        else if (d.type === 'integer') type = 'number';
        else if (d.type === 'list') type = 'list';

        let value = d.default == null ? (type === 'select' ? options[0] : '') : d.default;
        // `paramDocs` stringifies every default; a boolean must stay a boolean so
        // the checkbox and the emitted `true`/`false` are correct.
        if (type === 'bool') value = value === true || value === 'true';
        if (type === 'select' && value === '') value = options[0];

        let label = humanize(d.key);
        if (type === 'list') label += ' (comma-separated)';
        return {
          key: d.key,
          label,
          type,
          options,
          def: value,
          help: d.description || '',
          required: !!d.required,
        };
      });
  }
  return (def?.fields || []).map((f) => ({
    ...f,
    options: f.options || [],
    help: '',
    required: false,
  }));
}

/** A new runtime step for `id`, with each field at its catalogue default. */
export function makeStep(id, TECH, overrides = {}) {
  const params = {};
  for (const f of fieldsOf(TECH[id])) {
    if (f.type === 'fixed') continue;
    params[f.key] = overrides[f.key] !== undefined ? overrides[f.key] : f.def;
  }
  if (takesPayload(id, TECH)) params.payload = overrides.payload ?? '';
  return { id, params, open: false };
}

/** The payload entry named `name`, if any. */
export function payloadByName(state, name) {
  return state.payloads.find((p) => p.name === name);
}

/** The payload an Execution/stager step loads: its own name, else the only one. */
export function stepPayloadName(step, state) {
  const own = step.params?.payload;
  if (typeof own === 'string' && own) return own;
  return state.payloads[0]?.name ?? '';
}

/** The format of the payload a step loads (`pe` when it cannot be resolved). */
export function stepPayloadFormat(step, state) {
  return payloadByName(state, stepPayloadName(step, state))?.format ?? 'pe';
}

/**
 * A step that does not return control to the loader, so it must be last.
 * Mirrors `plan::validate::terminal_technique`.
 */
export function isTerminal(step, state) {
  if (step.id === 'dotnet_hosting') return true;
  if (step.id === 'reflective_loading' || step.id === 'process_ghosting') {
    return stepPayloadFormat(step, state) === 'pe';
  }
  return false;
}

/** The step's params as the plan emits them (ordered, payload first). */
export function buildParams(step, state, TECH) {
  const out = {};
  // The payload a step loads, for readability. An Execution step names it only
  // when the plan declares more than one — with a single payload,
  // `plan::steps::resolve` treats it as implicit; the stager must always name it.
  if (takesPayload(step.id, TECH)) {
    if (step.id === 'network_stager' || state.payloads.length > 1) {
      out.payload = stepPayloadName(step, state);
    }
  }
  for (const f of fieldsOf(TECH[step.id])) {
    if (f.type === 'fixed') {
      out[f.key] = f.def;
      continue;
    }
    const v = step.params[f.key];
    if (v === '' || v == null) continue;
    if (f.type === 'bool') {
      if (v) out[f.key] = true;
      continue;
    }
    if (f.type === 'number') {
      const n = Number(v);
      if (Number.isFinite(n)) out[f.key] = n;
      continue;
    }
    if (f.type === 'list') {
      const parts = String(v).split(',').map((x) => x.trim()).filter(Boolean);
      if (parts.length) out[f.key] = parts;
      continue;
    }
    out[f.key] = v;
  }
  return out;
}

/** The full plan document for `state` as a schema-6 YAML string. */
export function emitYaml(state, TECH) {
  const lines = [
    'schema: 6',
    `name: ${yamlEscape(state.name || 'plan')}`,
    '',
    'build:',
    indent(1, 'payloads:'),
  ];
  if (!state.payloads.length) lines.push(indent(2, '# add a payload'));
  for (const p of state.payloads) {
    lines.push(indent(2, `${yamlKey(p.name)}:`));
    lines.push(indent(3, `source: ${yamlEscape(p.source || './payload.exe')}`));
    if (p.format && p.format !== 'pe') lines.push(indent(3, `format: ${p.format}`));
    const args = splitArgs(p.args);
    if (args.length) {
      lines.push(indent(3, 'args:'));
      for (const a of args) lines.push(indent(4, `- ${yamlEscape(a)}`));
    }
  }

  const stub = [];
  if (state.stubPath && state.stubPath.trim()) {
    stub.push(indent(2, `path: ${yamlEscape(state.stubPath.trim())}`));
  }
  if (state.strings) {
    stub.push(indent(2, 'strings:'), indent(3, 'strategy: xor'), indent(3, 'key: random'));
  }
  if (state.syscalls === 'indirect') {
    stub.push(indent(2, 'syscalls:'), indent(3, 'mode: indirect'), indent(3, `resolver: ${state.resolver}`));
  }
  if (state.proxy) {
    stub.push(indent(2, 'api_resolution:'), indent(3, 'mode: proxy'), indent(3, 'apis: all'), indent(3, 'unmatched: forward'));
  }
  if (state.debug) stub.push(indent(2, 'debug: true'));
  if (stub.length) lines.push(indent(1, 'stub:'), ...stub);

  lines.push(indent(1, 'output:'), indent(2, `path: ${yamlEscape(state.out || './dist/packed.exe')}`));
  if (state.kind === 'dll') lines.push(indent(2, 'kind: dll'), indent(2, 'entry: auto'));
  if (state.arch && state.arch !== 'x64') lines.push(indent(2, `arch: ${state.arch}`));
  if (state.identity) {
    lines.push(indent(2, 'resources:'), indent(3, 'version_info:'), indent(4, 'randomize: true'));
  }
  if (state.signLab) lines.push(indent(2, 'sign:'), indent(3, 'mode: lab'));

  lines.push('', 'runtime:');
  if (!state.steps.length) lines.push(indent(1, '# add a technique'));
  for (const step of state.steps) {
    lines.push(indent(1, `- technique: ${step.id}`));
    const params = buildParams(step, state, TECH);
    const keys = Object.keys(params);
    if (!keys.length) continue;
    lines.push(indent(2, 'params:'));
    for (const k of keys) {
      const v = params[k];
      if (Array.isArray(v)) lines.push(indent(3, `${k}: [${v.map(yamlEscape).join(', ')}]`));
      else if (typeof v === 'boolean' || typeof v === 'number') lines.push(indent(3, `${k}: ${v}`));
      else lines.push(indent(3, `${k}: ${yamlEscape(v)}`));
    }
  }
  return `${lines.join('\n')}\n`;
}

/**
 * Everything the plan would fail (or warn) on, phrased for the person building
 * it. The levels are `err` (a `plan::validate` rejection), `warn` (a build
 * advisory) and `info` (a behavior worth knowing).
 */
export function advisories(state, TECH) {
  const notes = [];
  const add = (level, text) => notes.push({ level, text });

  if (!state.payloads.length) add('err', 'The plan needs at least one payload.');

  const seen = new Set();
  for (const p of state.payloads) {
    const name = (p.name || '').trim();
    if (!name) {
      add('err', 'A payload has an empty name.');
      continue;
    }
    if (seen.has(name)) add('err', `Two payloads are both named '${name}'.`);
    seen.add(name);
    if (!String(p.source || '').trim()) add('err', `Payload '${name}' has an empty source.`);
  }

  const execs = state.steps.filter((s) => TECH[s.id]?.category === 'execution');
  const stagers = state.steps.filter((s) => s.id === 'network_stager');
  const hasHollow = state.steps.some((s) => s.id === 'process_hollowing');
  const names = state.payloads.map((p) => (p.name || '').trim());

  if (!execs.length) add('err', 'The chain needs an execution technique.');

  // A step that names a payload must name one that exists.
  for (const step of state.steps) {
    if (!takesPayload(step.id, TECH)) continue;
    const own = step.params?.payload;
    if (typeof own === 'string' && own && !names.includes(own)) {
      add('err', `Step '${step.id}' targets payload '${own}', which does not exist.`);
    }
  }

  // .NET hosting and a managed payload imply each other.
  for (const step of execs) {
    if (step.id === 'dotnet_hosting' && stepPayloadFormat(step, state) !== 'dotnet') {
      add('err', `${TECH.dotnet_hosting.label} requires a payload with format 'dotnet'.`);
    }
  }
  for (const p of state.payloads) {
    if (p.format !== 'dotnet') continue;
    const hosted = execs.some((s) => s.id === 'dotnet_hosting' && stepPayloadName(s, state) === p.name);
    if (!hosted) add('warn', `Payload '${p.name}' is managed (.NET); load it with .NET hosting.`);
  }

  // A terminal technique hands the process to the payload, so it must be last.
  state.steps.forEach((step, i) => {
    if (i === state.steps.length - 1) return;
    if (isTerminal(step, state)) {
      add('err', `'${step.id}' does not return control to the loader, so it must be the last step.`);
    }
  });

  // network_stager rules (mirror plan::validate::validate_stager).
  if (stagers.length > 1) add('err', 'Only one network_stager step is allowed per plan.');
  if (stagers.length === 1) {
    const stager = stagers[0];
    const name = stepPayloadName(stager, state);
    if (!names.includes(name)) {
      add('err', `network_stager stages payload '${name}', which does not exist.`);
    } else {
      const consumers = execs.filter((s) => stepPayloadName(s, state) === name);
      if (consumers.length !== 1) {
        add('err', `network_stager's payload '${name}' must be loaded by exactly one execution step (found ${consumers.length}).`);
      } else if (state.steps.indexOf(consumers[0]) < state.steps.indexOf(stager)) {
        add('err', `The execution step that runs network_stager's payload must come after the stager.`);
      }
      add('info', `network_stager fetches '${name}' at run time; its 'source' is ignored.`);
    }
  }

  // API proxy catalogue.
  if (state.proxy) {
    if (state.syscalls !== 'indirect') add('err', 'API proxy needs indirect syscalls.');
    if (execs.length !== 1 || hasHollow) {
      add('err', 'API proxy needs exactly one reflective execution, not hollowing.');
    }
  }

  if (state.arch === 'x86' && state.syscalls === 'indirect') {
    add('err', 'Indirect syscalls are x64-only.');
  }

  // Order-sensitive preparations.
  const etw = state.steps.findIndex((s) => s.id === 'patch_etw');
  const unhook = state.steps.findIndex((s) => s.id === 'unhook_ntdll');
  if (unhook >= 0 && etw >= 0 && unhook > etw) {
    add('warn', 'Unhook ntdll after the ETW patch restores the bytes the patch changed.');
  }

  if (state.kind === 'dll'
    && state.steps.some((s) => ['self_deletion', 'sleep_obfuscation', 'stack_spoofing'].includes(s.id))) {
    add('err', 'Self-deletion, sleep obfuscation and stack spoofing are rejected for a DLL.');
  }

  return notes;
}

/** The note shown on a single step's card, or `null`. */
export function stepWarning(step, state, TECH) {
  const def = TECH[step.id];
  if (!def) return null;
  if (takesPayload(step.id, TECH) && def.formats?.length) {
    const format = stepPayloadFormat(step, state);
    if (!def.formats.includes(format)) {
      return { level: 'err', text: `Does not accept format '${format}'; needs ${def.formats.join(' / ')}.` };
    }
  }
  if (step.id === 'stack_spoofing' && state.syscalls !== 'indirect') {
    return { level: 'warn', text: 'Only changes indirect syscalls.' };
  }
  return null;
}

/** The stub a build uses: the custom template's basename, or `Built-in stub`. */
export function stubLabel(state) {
  const path = (state.stubPath || '').trim();
  if (!path) return 'Built-in stub';
  return path.split(/[\\/]/).pop() || path;
}

/** `comma, list` → `['comma', 'list']`. */
export function splitArgs(value) {
  return String(value ?? '').split(',').map((x) => x.trim()).filter(Boolean);
}

function yamlEscape(s) {
  if (s === '' || s == null) return '""';
  if (/^[\w./\\:$+-]+$/.test(s) && !/^(true|false|null|yes|no)$/i.test(s)) return s;
  return JSON.stringify(String(s));
}

/** A mapping key: a bare word where possible, quoted otherwise. */
function yamlKey(name) {
  const s = String(name ?? '').trim();
  if (!s) return 'payload';
  return /^[\w.-]+$/.test(s) ? s : JSON.stringify(s);
}

function indent(n, line) {
  return `${'  '.repeat(n)}${line}`;
}
