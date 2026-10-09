/**
 * Build the plan-builder catalogue from each technique's mod.rs under
 * src/techniques/<name>/.
 *
 * Reads TechniqueDef fields (name, category, stability, params_example) plus
 * the README title / one-line summary, so a new technique directory shows up
 * in the builder after the next assemble — no hand-maintained JS list.
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
  downloader: ['curl', 'certutil'],
};

/** Payload formats a technique accepts when the README does not say. */
const FORMAT_FALLBACK = {
  reflective_loading: ['pe', 'dll', 'shellcode'],
  process_hollowing: ['pe'],
  process_ghosting: ['pe'],
  pe_injection: ['pe'],
  early_bird: ['shellcode'],
  thread_hijacking: ['shellcode'],
  module_stomping: ['shellcode'],
  dll_hollowing: ['shellcode'],
  fibers: ['shellcode'],
  execution_callbacks: ['shellcode'],
  dotnet_hosting: ['dotnet'],
};

/**
 * Scan `src/techniques` under the repository root and return the catalogue
 * object the plan builder fetches as `/plan-catalog.json`.
 */
export function buildTechniqueCatalog(root) {
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
    const formats = formatsFor(def.name, readme, def.category);

    techniques.push({
      id: def.name,
      label,
      blurb,
      category: def.category,
      stability: def.stability,
      formats,
      fields: params,
      needs_indirect: def.name === 'stack_spoofing',
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

  return {
    name,
    category: category ? category.toLowerCase() : 'preparation',
    stability: stability ? camelToSnake(stability) : 'experimental',
    paramsExample: paramsExample ?? `technique: ${name}\n`,
  };
}

function matchStringField(body, field) {
  const m = body.match(new RegExp(`${field}\\s*:\\s*"([^"]*)"`));
  return m ? m[1] : null;
}

function matchEnumField(body, field, enumName) {
  const m = body.match(new RegExp(`${field}\\s*:\\s*${enumName}::(\\w+)`));
  return m ? m[1] : null;
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

function formatsFor(name, readme, category) {
  if (category !== 'execution') return null;
  if (FORMAT_FALLBACK[name]) return FORMAT_FALLBACK[name];

  const table = readme.match(/\|\s*\*\*Payload format\*\*\s*\|\s*([^|]+)\|/i);
  if (table) {
    const cell = table[1].toLowerCase();
    if (cell.includes('shellcode')) return ['shellcode'];
    if (cell.includes('dotnet')) return ['dotnet'];
    if (cell.includes('pe')) return ['pe'];
  }
  if (/format:\s*shellcode.*only|shellcode[`'"]?\s+only/i.test(readme)) {
    return ['shellcode'];
  }
  if (/format:\s*dotnet/i.test(readme)) return ['dotnet'];
  return ['pe'];
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

function fieldFromValue(key, value) {
  const label = humanize(key);

  if (typeof value === 'boolean') {
    return { key, label, type: 'bool', def: value };
  }
  if (typeof value === 'number') {
    return { key, label, type: 'number', def: value };
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
