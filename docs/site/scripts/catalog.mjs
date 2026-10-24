/**
 * Build the plan-builder catalogue and the docs registry from the Rust metadata
 * under `src/techniques/<name>/` and `src/features/<name>/`.
 *
 * Reads `TechniqueDef` / `FeatureDef` fields (name, category/scope, stability,
 * params, formats, …) plus the README title / one-line summary, so a new
 * technique or feature shows up in the builder and the docs after the next
 * assemble — no hand-maintained JS list.
 */

import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import yaml from 'js-yaml';

/** Keys that always map to a closed set of choices in the builder UI. */
const SELECT_OPTIONS = {
  mode: ['all', 'any', 'rename_ads', 'helper'],
  on_fail: ['silent', 'exit'],
  action: ['abort', 'continue'],
  variant: ['ekko'],
  window: ['hidden', 'normal'],
  downloader: ['auto', 'winhttp', 'curl', 'certutil', 'powershell', 'bitsadmin'],
};

/** Payload formats a technique accepts, read from `TechniqueDef::formats`. */
const FORMAT_LABEL = { Pe: 'pe', Shellcode: 'shellcode', Dll: 'dll', Dotnet: 'dotnet', Powershell: 'powershell' };

const CAPABILITY_LABEL = {
  WindowsX64: 'windows-x64',
  WindowsX86: 'windows-x86',
  KernelAccess: 'kernel-access',
  AdminRequired: 'admin-required',
};

/**
 * Scan `src/techniques` once and return the plan-builder catalogue plus the
 * registry document written as `/techniques.json`.
 */
export function loadTechniques(root) {
  const loaded = scanTechniques(root);
  const features = scanFeatures(root).map(toFeatureRegistry);
  const resolvers = scanResolvers(root);
  return {
    catalog: {
      generated_at: loaded.generated_at,
      techniques: loaded.techniques.map(toCatalog),
    },
    registry: {
      generated_at: loaded.generated_at,
      techniques: loaded.techniques.map(toRegistry),
    },
    features,
    resolvers,
  };
}

/** Plan-builder catalogue (`/plan-catalog.json`). */
export function buildTechniqueCatalog(root) {
  return loadTechniques(root).catalog;
}

function scanTechniques(root) {
  const techRoot = join(root, 'src', 'techniques');
  if (!existsSync(techRoot)) {
    return { generated_at: new Date().toISOString(), techniques: [] };
  }

  const techniques = [];
  for (const entry of readdirSync(techRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith('_') || entry.name === 'mod.rs') continue;
    const modPath = join(techRoot, entry.name, 'mod.rs');
    const readmePath = join(techRoot, entry.name, 'README.md');
    if (!existsSync(modPath)) continue;

    const mod = readFileSync(modPath, 'utf8');
    const def = extractDef(mod);
    if (!def || !def.name) continue;

    const readme = existsSync(readmePath) ? readFileSync(readmePath, 'utf8') : '';
    const { label, blurb } = readmeMeta(readme, def.name);
    const params = fieldsFromExample(def.paramsExample);
    const paramDocs = paramsFromStruct(mod, def.paramsExample, params);

    techniques.push({
      id: def.name,
      label,
      blurb,
      category: def.category,
      stability: def.stability,
      attck: def.attck,
      requires: def.requires.map((cap) => CAPABILITY_LABEL[cap] ?? cap),
      conflicts: def.conflicts,
      syscalls: def.syscalls,
      resolves_imports: def.resolvesImports,
      doc_path: def.docPath,
      params_example: def.paramsExample,
      formats: def.formats,
      fields: params,
      paramDocs,
      // Whether the technique's `Params` struct takes a `payload` (an Execution
      // technique, or the control-plane `network_stager`). The builder renders a
      // payload picker for it instead of a free-text field.
      takes_payload: paramDocs.some((field) => field.key === 'payload'),
      needs_indirect: def.requiresIndirect,
      doc: `/techniques/ref/${def.name}/`,
    });
  }

  techniques.sort((a, b) => {
    const order = { preparation: 0, execution: 1, control: 2 };
    const ca = order[a.category] ?? 9;
    const cb = order[b.category] ?? 9;
    if (ca !== cb) return ca - cb;
    return a.id.localeCompare(b.id);
  });

  return {
    generated_at: new Date().toISOString(),
    techniques,
  };
}

/** Fields the plan builder reads. The registry document is a separate file. */
function toCatalog(tech) {
  return {
    id: tech.id,
    label: tech.label,
    blurb: tech.blurb,
    category: tech.category,
    stability: tech.stability,
    formats: tech.formats,
    // `fields` is the curated shape from `params_example` (a fallback for a
    // technique without a `Params` struct); `paramDocs` is the full struct with
    // types, defaults and allowed values. The builder prefers the latter.
    fields: tech.fields,
    paramDocs: tech.paramDocs,
    takes_payload: tech.takes_payload,
    needs_indirect: tech.needs_indirect,
    doc: tech.doc,
  };
}

/** Everything `TechniqueDef` records, plus the parsed params and the README summary. */
function toRegistry(tech) {
  return {
    kind: 'technique',
    name: tech.id,
    label: tech.label,
    summary: tech.blurb,
    category: tech.category,
    stability: tech.stability,
    attck: tech.attck,
    requires: tech.requires,
    conflicts: tech.conflicts,
    syscalls: tech.syscalls,
    resolves_imports: tech.resolves_imports,
    doc_path: tech.doc_path,
    params_example: tech.params_example,
    params: tech.paramDocs,
    page: tech.doc,
  };
}

/** Pull the `const DEF: TechniqueDef = TechniqueDef { … };` block fields. */
function extractDef(src) {
  const block = src.match(
    /pub\s+const\s+DEF\s*:\s*TechniqueDef\s*=\s*TechniqueDef\s*\{([\s\S]*?)\n\};/,
  );
  if (!block) return null;
  const body = block[1];

  const name = matchStringField(body, 'name');
  const category = matchEnumField(body, 'category', 'Category');
  const stability = matchEnumField(body, 'stability', 'Stability');
  const paramsExample = matchParamsExample(body);
  const attck = matchStringList(body, 'attck');
  const requires = matchEnumList(body, 'requires', 'Capability');
  const conflicts = matchStringList(body, 'conflicts');
  const syscalls = matchStringList(body, 'syscalls');
  const docPath = matchStringField(body, 'doc_path');
  const resolvesImports = matchBoolField(body, 'resolves_imports');
  const formats = matchPayloadFormats(body);
  const requiresIndirect = /requires_indirect_syscalls\s*:\s*true/.test(body);

  return {
    name,
    category: category ? category.toLowerCase() : 'preparation',
    stability: stability ? camelToSnake(stability) : 'experimental',
    paramsExample: paramsExample ?? `technique: ${name}\n`,
    attck,
    requires,
    conflicts,
    syscalls,
    formats,
    requiresIndirect,
    docPath,
    resolvesImports,
  };
}

function matchBoolField(body, field) {
  const match = body.match(new RegExp(`${field}\\s*:\\s*(true|false)`));
  return match ? match[1] === 'true' : false;
}

function matchStringField(body, field) {
  const m = body.match(new RegExp(`${field}\\s*:\\s*"([^"]*)"`));
  return m ? m[1] : null;
}

function matchEnumField(body, field, enumName) {
  const m = body.match(new RegExp(`${field}\\s*:\\s*${enumName}::(\\w+)`));
  return m ? m[1] : null;
}

/** `"T1055.012"` entries inside `field: &["…", "…"]`. */
function matchStringList(body, field) {
  const m = body.match(new RegExp(`${field}\\s*:\\s*&\\[([^\\]]*)]`));
  if (!m) return [];
  return [...m[1].matchAll(/"([^"]*)"/g)].map((hit) => hit[1]);
}

/** `Capability::WindowsX64` entries inside `field: &[Capability::…]`. */
function matchEnumList(body, field, enumName) {
  const m = body.match(new RegExp(`${field}\\s*:\\s*&\\[([^\\]]*)]`));
  if (!m) return [];
  return [...m[1].matchAll(new RegExp(`${enumName}::(\\w+)`, 'g'))].map((hit) => hit[1]);
}

/**
 * `params_example` is written several ways in the crate (`"…"`, `r#"…"`,
 * or a bare string on the next line). Accept all three.
 */
function matchParamsExample(body) {
  const raw = body.match(/params_example\s*:\s*r#"([\s\S]*?)"#/);
  if (raw) return raw[1];

  const same = body.match(/params_example\s*:\s*"((?:\\.|[^"\\])*)"/);
  if (same) return unescapeRustString(same[1]);

  const next = body.match(/params_example\s*:\s*\n\s*"((?:\\.|[^"\\])*)"/);
  if (next) return unescapeRustString(next[1]);

  return null;
}

function unescapeRustString(s) {
  return s
    .replace(/\\n/g, '\n')
    .replace(/\\t/g, '\t')
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, '\\');
}

function camelToSnake(s) {
  return s.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase();
}

function readmeMeta(readme, fallbackId) {
  // Technique READMEs may be checked out with CRLF on Windows.
  const text = readme.replace(/\r\n/g, '\n');
  const title = text.match(/^#\s+(.+)$/m);
  const label = title ? title[1].trim() : humanize(fallbackId);

  // Prefer the italic one-liner that follows the H1 in technique READMEs.
  const italic = text.match(/^#\s+.+\n\n\*([^*]+)\*/m);
  if (italic) return { label, blurb: italic[1].replace(/\s+/g, ' ').trim() };

  const para = text.match(/^#\s+.+\n\n+([^#|*][^\n]+)/m);
  if (para) return { label, blurb: para[1].trim() };

  return { label, blurb: humanize(fallbackId) };
}

function humanize(id) {
  return id
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

/** `formats: &[super::PayloadFormat::Pe, …]` → `['pe', …]`. */
function matchPayloadFormats(body) {
  const block = body.match(/formats\s*:\s*&\[([\s\S]*?)\]/);
  if (!block) return [];
  return [...block[1].matchAll(/PayloadFormat::(\w+)/g)].map(
    (hit) => FORMAT_LABEL[hit[1]] ?? hit[1].toLowerCase(),
  );
}

/**
 * Turn a `params_example` YAML snippet into builder field descriptors.
 * Skips `payload` — the builder uses a single named payload.
 */
function fieldsFromExample(example) {
  let doc;
  try {
    doc = yaml.load(example);
  } catch {
    return [];
  }
  if (!doc || typeof doc !== 'object') return [];
  const params = doc.params;
  if (!params || typeof params !== 'object') return [];

  const fields = [];
  for (const [key, value] of Object.entries(params)) {
    if (key === 'payload') continue;
    fields.push(fieldFromValue(key, value));
  }
  return fields;
}

/**
 * A param value the scalar widgets cannot edit: a group or a list of groups
 * (for example `bouncer.require`, whose entries are single-key maps, or
 * `bouncer.on_reject`). The builder edits these as JSON.
 */
function isStructured(value) {
  if (Array.isArray(value)) {
    return value.some((item) => item !== null && typeof item === 'object');
  }
  return value !== null && typeof value === 'object';
}

function fieldFromValue(key, value) {
  const label = humanize(key);

  if (typeof value === 'boolean') {
    return { key, label, type: 'bool', def: value };
  }
  if (typeof value === 'number') {
    return { key, label, type: 'number', def: value };
  }
  if (isStructured(value)) {
    return { key, label: `${label} (JSON)`, type: 'json', def: JSON.stringify(value) };
  }
  if (Array.isArray(value)) {
    if (key === 'encrypt_regions') {
      return { key, label, type: 'fixed', def: value };
    }
    return {
      key,
      label: `${label} (comma-separated)`,
      type: 'list',
      def: value.map(String).join(','),
    };
  }
  if (SELECT_OPTIONS[key]) {
    // Prefer options that include the example value; for `mode` the set is
    // shared across techniques with different enums, so filter to a sensible
    // subset when the example value is known.
    let options = SELECT_OPTIONS[key];
    if (key === 'mode') {
      if (['rename_ads', 'helper'].includes(value)) {
        options = ['rename_ads', 'helper'];
      } else if (['all', 'any'].includes(value)) {
        options = ['all', 'any'];
      }
    }
    return {
      key,
      label,
      type: 'select',
      options,
      def: String(value),
    };
  }
  return { key, label, type: 'text', def: value == null ? '' : String(value) };
}

/* ------------------------------------------------------------------------- */
/* Parameter docs, read from Rust                                            */
/* ------------------------------------------------------------------------- */
/*
 * The docs Parameter table (with descriptions, requiredness and the YAML type)
 * is derived from the technique's `pub struct Params` at assemble time — the
 * doc comment above each field is the description, `Option<…>`/`#[serde(default)]`
 * decide requiredness, and an enum field's variants become its allowed values.
 * Nothing is written twice: the Rust source is the single source of truth, and
 * the page is generated from it when the docs are built.
 */

/** The text inside the first `{ … }` beginning at `open`, brace-balanced. */
function bracedBody(text, open) {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === '{') depth += 1;
    else if (text[i] === '}') {
      depth -= 1;
      if (depth === 0) return text.slice(open + 1, i);
    }
  }
  return null;
}

/** The text inside the `[ … ]` beginning at `open`, bracket-balanced. */
function bracketedBody(text, open) {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === '[') depth += 1;
    else if (text[i] === ']') {
      depth -= 1;
      if (depth === 0) return text.slice(open + 1, i);
    }
  }
  return null;
}

/** The first sentence of `text` (falls back to the whole string). */
function firstSentence(text) {
  const trimmed = text.replace(/\s+/g, ' ').trim();
  // A sentence ends at `.`/`!`/`?` only when it is followed by a space and an
  // uppercase letter (or ends the string), so `e.g.\` and `T1055.012` survive.
  const match = /^(.*?[.!?])(?=\s+[A-Z(]|$)/.exec(trimmed);
  return match ? match[1] : trimmed;
}

/** A value from the example YAML as one line of text. */
function itemToText(value) {
  if (Array.isArray(value)) return value.map(String).join(', ');
  return String(value);
}

/** The Rust type `rustType` as the YAML type a reader expects. */
function yamlType(rustType) {
  const base = rustType.replace(/^Option\s*<\s*/, '').replace(/\s*>$/, '').trim();
  if (base === 'bool') return 'boolean';
  if (/^(u8|u16|u32|u64|usize|i8|i16|i32|i64|isize)$/.test(base)) return 'integer';
  if (/^Vec\s*</.test(base)) return 'list';
  return 'string';
}

/** `RenameAds` + `snake_case` → `rename_ads`. */
function renameVariant(name, style) {
  if (style === 'snake_case') {
    return name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
  }
  if (style === 'kebab-case') return name.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();
  if (style === 'lowercase') return name.toLowerCase();
  return name;
}

/** The YAML values an enum field accepts, from its `pub enum` variants. */
function enumValues(mod, rustType) {
  const base = rustType.replace(/^Option\s*<\s*/, '').replace(/\s*>$/, '').trim();
  if (!/^[A-Z]\w*$/.test(base)) return [];
  const start = mod.indexOf(`pub enum ${base}`);
  if (start < 0) return [];
  const open = mod.indexOf('{', start);
  const body = open < 0 ? null : bracedBody(mod, open);
  if (!body) return [];

  // `#[serde(rename_all = …)]` sits just above the `pub enum` line.
  const renameAll = /rename_all\s*=\s*"([\w-]+)"/.exec(
    mod.slice(Math.max(0, start - 300), open),
  )?.[1] ?? null;

  const values = [];
  let pending = null;
  for (const raw of body.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const renamed = /rename\s*=\s*"([^"]+)"/.exec(line);
    if (renamed) {
      pending = renamed[1];
      continue;
    }
    const variant = /^([A-Z]\w*)\s*(?:\([^)]*\))?\s*,?$/.exec(line);
    if (variant) {
      values.push(pending ?? renameVariant(variant[1], renameAll));
      pending = null;
    }
  }
  return values;
}

/** The `pub struct <name>` fields with their doc comment, requiredness and type. */
function structFields(mod, structName) {
  const start = mod.indexOf(`pub struct ${structName}`);
  if (start < 0) return [];
  const open = mod.indexOf('{', start);
  const body = open < 0 ? null : bracedBody(mod, open);
  if (!body) return [];

  const fields = [];
  let docs = [];
  let attrs = '';
  for (const raw of body.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('///')) {
      docs.push(line.slice(3).trim());
      continue;
    }
    if (!/^pub\s/.test(line)) {
      // An attribute or its continuation line(s).
      attrs += ` ${line}`;
      continue;
    }
    const match = /^pub\s+(\w+)\s*:\s*(.+?),?$/.exec(line);
    if (!match) {
      docs = [];
      attrs = '';
      continue;
    }
    const [, key, rustType] = match;
    fields.push({
      key,
      // `[`Mode`]` is a rustdoc link; the docs table only needs the code span.
      description: firstSentence(docs.join(' ')).replace(/\[`([^`]+)`\]/g, '`$1`'),
      required: !/default/.test(attrs) && !/^\s*Option\s*</.test(rustType),
      type: yamlType(rustType),
      options: enumValues(mod, rustType),
    });
    docs = [];
    attrs = '';
  }
  return fields;
}

/**
 * The registry's `params` for one technique: every field of its `Params` struct
 * (description, YAML type, requiredness, allowed values) plus the value the
 * `params_example` shows as the default. Falls back to the example-derived
 * fields when the technique has no `Params` struct.
 */
function paramsFromStruct(mod, exampleText, fallbackFields) {
  const fields = structFields(mod, 'Params');
  if (!fields.length) {
    return (fallbackFields ?? []).map((field) => ({
      key: field.key,
      type: field.type === 'number' ? 'integer'
        : field.type === 'bool' ? 'boolean'
          : field.type === 'list' ? 'list'
            : 'string',
      required: null,
      default: field.def === undefined || field.def === '' ? null : String(field.def),
      description: null,
      options: field.options ?? [],
    }));
  }

  let exampleParams = {};
  try {
    const doc = yaml.load(exampleText);
    if (doc && typeof doc === 'object' && doc.params && typeof doc.params === 'object') {
      exampleParams = doc.params;
    }
  } catch {
    exampleParams = {};
  }

  return fields.map((field) => {
    const example = exampleParams[field.key];
    const structured = isStructured(example);
    return {
      key: field.key,
      type: structured ? 'json' : field.type,
      required: field.required,
      // A required field has no default; the example value is only a sample.
      default:
        field.required || example === undefined
          ? null
          : structured
            ? JSON.stringify(example)
            : itemToText(example),
      description: field.description || null,
      // An enum defined outside the technique's module (for example `window`, a
      // `WindowMode` from the plan schema) has no local variants to read; fall back
      // to the curated option set the builder would otherwise use.
      options: field.options.length ? field.options : (SELECT_OPTIONS[field.key] ?? []),
    };
  });
}

/* ------------------------------------------------------------------------- */
/* Loader features                                                           */
/* ------------------------------------------------------------------------- */
/*
 * Loader features are the second half of the catalogue. They are not `runtime:`
 * steps, so they carry scope instead of a pipeline category, but everything else
 * (nav, overview, the metadata panel, the JSON) is generated from them the same
 * way, from `src/features/<name>/mod.rs`.
 */

/** `ParamKind::List` / anything else → the YAML type label. */
function kindToType(kind) {
  return kind === 'List' ? 'list' : 'string';
}

/** `params: &[ ParamDef { … } ]` → registry parameter entries. */
function parseParamDefs(body) {
  const found = /params\s*:\s*&\[/.exec(body);
  if (!found) return [];
  const inside = bracketedBody(body, body.indexOf('[', found.index));
  if (!inside) return [];
  return [...inside.matchAll(/ParamDef\s*\{([^{}]*)\}/g)].map((entry) => {
    const text = entry[1];
    const description = (/description\s*:\s*"((?:\\.|[^"])*)"/.exec(text)?.[1] ?? '')
      .replace(/\\\s*\n\s*/g, ' ') // Rust string line continuation
      .replace(/\\"/g, '"')
      .replace(/\s+/g, ' ')
      .trim();
    const kind = /kind\s*:\s*ParamKind::(\w+)(?:\s*\(\s*&\[([^\]]*)\]\s*\))?/.exec(text);
    return {
      key: /key\s*:\s*"([^"]*)"/.exec(text)?.[1] ?? '',
      description: description || null,
      required: /required\s*:\s*true/.test(text),
      default: /default\s*:\s*Some\(\s*"(?:\\.|[^"])*"\s*\)/.exec(text)
        ? (/default\s*:\s*Some\(\s*"((?:\\.|[^"])*)"\s*\)/.exec(text)?.[1] ?? null)
        : null,
      type: kindToType(kind?.[1] ?? 'Str'),
      options: kind?.[2] ? [...kind[2].matchAll(/"([^"]*)"/g)].map((hit) => hit[1]) : [],
    };
  });
}

/** Pull the `const DEF: FeatureDef = FeatureDef { … }` fields. */
function extractFeatureDef(src) {
  const block = src.match(
    /pub\s+const\s+DEF\s*:\s*FeatureDef\s*=\s*FeatureDef\s*\{([\s\S]*?)\n\};/,
  );
  if (!block) return null;
  const body = block[1];
  return {
    name: matchStringField(body, 'name'),
    attck: matchStringList(body, 'attck'),
    stability: camelToSnake(matchEnumField(body, 'stability', 'Stability') ?? 'Experimental'),
    requires: matchEnumList(body, 'requires', 'Capability'),
    conflicts: matchStringList(body, 'conflicts'),
    scope: (matchEnumField(body, 'scope', 'FeatureScope') ?? 'Loader').toLowerCase(),
    yaml: matchStringField(body, 'yaml'),
    docPath: matchStringField(body, 'doc_path'),
    paramsExample: matchParamsExample(body) ?? '',
    params: parseParamDefs(body),
  };
}

/** Every loader feature under `src/features/<name>/mod.rs`. */
function scanFeatures(root) {
  const featuresRoot = join(root, 'src', 'features');
  if (!existsSync(featuresRoot)) return [];
  const features = [];
  for (const entry of readdirSync(featuresRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const modPath = join(featuresRoot, entry.name, 'mod.rs');
    const readmePath = join(featuresRoot, entry.name, 'README.md');
    if (!existsSync(modPath)) continue;

    const def = extractFeatureDef(readFileSync(modPath, 'utf8'));
    if (!def || !def.name) continue;
    const readme = existsSync(readmePath) ? readFileSync(readmePath, 'utf8') : '';
    const { label, blurb } = readmeMeta(readme, def.name);

    features.push({
      id: def.name,
      label,
      blurb,
      scope: def.scope,
      stability: def.stability,
      attck: def.attck,
      requires: def.requires.map((cap) => CAPABILITY_LABEL[cap] ?? cap),
      conflicts: def.conflicts,
      yaml: def.yaml,
      doc_path: def.docPath,
      params_example: def.paramsExample,
      params: def.params,
      doc: `/features/ref/${def.name}/`,
    });
  }
  features.sort((a, b) => a.scope.localeCompare(b.scope) || a.id.localeCompare(b.id));
  return features;
}

/** The registry entry for one loader feature. */
function toFeatureRegistry(feature) {
  return {
    kind: 'feature',
    name: feature.id,
    label: feature.label,
    summary: feature.blurb,
    scope: feature.scope,
    stability: feature.stability,
    attck: feature.attck,
    requires: feature.requires,
    conflicts: feature.conflicts,
    yaml: feature.yaml,
    doc_path: feature.doc_path,
    params_example: feature.params_example,
    params: feature.params,
    page: feature.doc,
  };
}

/** Parse a `pub const DEF: ResolverDef = ResolverDef { … };` block. */
function extractResolverDef(src) {
  const block = src.match(
    /pub\s+const\s+DEF\s*:\s*ResolverDef\s*=\s*ResolverDef\s*\{([\s\S]*?)\n\};/,
  );
  if (!block) return null;
  const body = block[1];
  return {
    name: matchStringField(body, 'name'),
    phase: matchStringField(body, 'phase'),
    attck: matchStringList(body, 'attck'),
    stability: camelToSnake(matchEnumField(body, 'stability', 'Stability') ?? 'Stable'),
    docPath: matchStringField(body, 'doc_path'),
  };
}

/** Every SSN resolver under `src/engine/syscalls/resolvers/<name>/mod.rs`. */
function scanResolvers(root) {
  const dir = join(root, 'src', 'engine', 'syscalls', 'resolvers');
  if (!existsSync(dir)) return [];
  const resolvers = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const modPath = join(dir, entry.name, 'mod.rs');
    const readmePath = join(dir, entry.name, 'README.md');
    if (!existsSync(modPath)) continue;

    const def = extractResolverDef(readFileSync(modPath, 'utf8'));
    if (!def || !def.name) continue;
    const readme = existsSync(readmePath) ? readFileSync(readmePath, 'utf8') : '';
    const { label, blurb } = readmeMeta(readme, def.name);

    resolvers.push({
      id: def.name,
      label,
      blurb,
      phase: def.phase,
      stability: def.stability,
      attck: def.attck,
      parent: 'syscalls',
      doc_path: def.docPath,
      doc: `/features/ref/syscalls/${def.name}/`,
    });
  }
  resolvers.sort((a, b) => a.id.localeCompare(b.id));
  return resolvers;
}
