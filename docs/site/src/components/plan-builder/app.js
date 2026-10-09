/**
 * Plan builder client logic.
 *
 * Catalogue: /plan-catalog.json, assembled from TechniqueDef.
 * Techniques are added from a modal whose sidebar switches section
 * (preparation / execution / control).
 */

const SECTIONS = [
  ['preparation', 'Preparation'],
  ['execution', 'Execution'],
  ['control', 'Control'],
];

function baseState() {
  return {
    name: 'plan',
    source: './payload.exe',
    format: 'pe',
    args: '',
    out: './dist/packed.exe',
    kind: 'exe',
    arch: 'x64',
    strings: false,
    syscalls: 'none',
    resolver: 'hells_gate',
    proxy: false,
    signLab: false,
    identity: false,
    debug: false,
    steps: [],
  };
}

export async function mount(root) {
  const TECH = Object.create(null);
  let catalogMeta = '';
  try {
    const res = await fetch('/plan-catalog.json');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const catalog = await res.json();
    for (const t of catalog.techniques) TECH[t.id] = t;
    catalogMeta = `${catalog.techniques.length} techniques · assembled ${catalog.generated_at?.slice(0, 19) ?? '?'}`;
  } catch (err) {
    root.innerHTML = `<p class="pb-error">Could not load <code>/plan-catalog.json</code> (${esc(err.message)}). Run <code>python scripts/docs.py</code> so assemble generates it.</p>`;
    return;
  }

  let uidSeq = 0;
  function stepOf(id, params = {}) {
    const def = TECH[id];
    if (!def) return null;
    const p = {};
    for (const f of def.fields || []) {
      if (f.type === 'fixed') continue;
      p[f.key] = params[f.key] !== undefined ? params[f.key] : f.def;
    }
    return { uid: ++uidSeq, id, params: p, open: false };
  }

  const state = baseState();
  let pickerQuery = '';
  let pickerSection = 'preparation';

  const ui = {
    payload: root.querySelector('[data-payload]'),
    chain: root.querySelector('[data-chain]'),
    count: root.querySelector('[data-count]'),
    notes: root.querySelector('[data-notes]'),
    settings: root.querySelector('[data-settings]'),
    yaml: root.querySelector('[data-yaml]'),
    toast: root.querySelector('[data-toast]'),
    picker: root.querySelector('[data-picker]'),
    pickerSearch: root.querySelector('[data-picker-search]'),
    pickerNav: root.querySelector('[data-picker-nav]'),
    pickerList: root.querySelector('[data-picker-list]'),
  };
  const metaEl = root.querySelector('[data-meta]');
  if (metaEl) metaEl.textContent = catalogMeta;

  function toast(msg) {
    ui.toast.textContent = msg;
    ui.toast.classList.add('is-on');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => ui.toast.classList.remove('is-on'), 1400);
  }

  function yamlEscape(s) {
    if (s === '' || s == null) return '""';
    if (/^[\w./\\:$+-]+$/.test(s) && !/^(true|false|null|yes|no)$/i.test(s)) return s;
    return JSON.stringify(String(s));
  }
  const indent = (n, line) => `${'  '.repeat(n)}${line}`;

  function buildParams(step) {
    const def = TECH[step.id];
    const out = {};
    for (const f of def.fields || []) {
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
    if (step.id === 'network_stager') out.payload = 'payload';
    return out;
  }

  function emitYaml() {
    const lines = ['schema: 6', `name: ${yamlEscape(state.name || 'plan')}`, '', 'build:', indent(1, 'payloads:'), indent(2, 'payload:'), indent(3, `source: ${yamlEscape(state.source || './payload.exe')}`)];
    if (state.format && state.format !== 'pe') lines.push(indent(3, `format: ${state.format}`));
    if (state.args.trim()) {
      lines.push(indent(3, 'args:'));
      for (const a of state.args.split(',').map((x) => x.trim()).filter(Boolean)) {
        lines.push(indent(4, `- ${yamlEscape(a)}`));
      }
    }
    const stub = [];
    if (state.strings) stub.push(indent(2, 'strings:'), indent(3, 'strategy: xor'), indent(3, 'key: random'));
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
    if (state.identity) lines.push(indent(2, 'resources:'), indent(3, 'version_info:'), indent(4, 'randomize: true'));
    if (state.signLab) lines.push(indent(2, 'sign:'), indent(3, 'mode: lab'));
    lines.push('', 'runtime:');
    if (!state.steps.length) lines.push(indent(1, '# add a technique'));
    for (const step of state.steps) {
      lines.push(indent(1, `- technique: ${step.id}`));
      const params = buildParams(step);
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

  function advisories() {
    const notes = [];
    const execs = state.steps.filter((s) => TECH[s.id]?.category === 'execution');
    const hasHollow = state.steps.some((s) => s.id === 'process_hollowing');
    const etw = state.steps.findIndex((s) => s.id === 'patch_etw');
    const unhook = state.steps.findIndex((s) => s.id === 'unhook_ntdll');
    if (!execs.length) notes.push({ level: 'err', text: 'The chain needs an execution technique.' });
    if (state.proxy && state.syscalls !== 'indirect') notes.push({ level: 'err', text: 'API proxy needs indirect syscalls.' });
    if (state.proxy && (execs.length !== 1 || hasHollow)) {
      notes.push({ level: 'err', text: 'API proxy needs exactly one reflective execution, not hollowing.' });
    }
    if (state.arch === 'x86' && state.syscalls === 'indirect') notes.push({ level: 'err', text: 'Indirect syscalls are x64-only.' });
    if (state.format === 'dotnet' && !state.steps.some((s) => s.id === 'dotnet_hosting')) {
      notes.push({ level: 'warn', text: 'A dotnet payload usually runs with .NET hosting.' });
    }
    if (state.format !== 'dotnet' && state.steps.some((s) => s.id === 'dotnet_hosting')) {
      notes.push({ level: 'err', text: '.NET hosting requires format: dotnet.' });
    }
    for (const s of execs) {
      const allowed = TECH[s.id].formats;
      if (allowed && !allowed.includes(state.format)) {
        notes.push({ level: 'err', text: `${TECH[s.id].label} does not accept format: ${state.format}.` });
      }
    }
    if (unhook >= 0 && etw >= 0 && unhook > etw) {
      notes.push({ level: 'warn', text: 'Unhook ntdll after the ETW patch restores the bytes the patch changed.' });
    }
    if (state.kind === 'dll' && state.steps.some((s) => ['self_deletion', 'sleep_obfuscation', 'stack_spoofing'].includes(s.id))) {
      notes.push({ level: 'err', text: 'Self-deletion, sleep obfuscation and stack spoofing are rejected for a DLL.' });
    }
    return notes;
  }

  function stepWarning(step) {
    const def = TECH[step.id];
    if (def?.formats && !def.formats.includes(state.format)) return { level: 'err', text: `Needs format: ${def.formats.join(' / ')}` };
    if (step.id === 'stack_spoofing' && state.syscalls !== 'indirect') return { level: 'warn', text: 'Only changes indirect syscalls.' };
    return null;
  }

  function highlight(src) {
    return src.replace(/^(.*)$/gm, (line) => {
      if (/^\s*#/.test(line)) return `<span class="tok-cmt">${esc(line)}</span>`;
      const m = line.match(/^(\s*-?\s*)([\w]+):(.*)$/);
      if (!m) return esc(line);
      return `${esc(m[1])}<span class="tok-key">${esc(m[2])}</span>:${colorValue(m[3])}`;
    });
  }
  function colorValue(rest) {
    const t = rest.trim();
    if (!t) return esc(rest);
    const i = rest.indexOf(t);
    const lead = esc(rest.slice(0, i));
    if (t === 'true' || t === 'false') return `${lead}<span class="tok-bool">${t}</span>`;
    if (/^-?\d+(\.\d+)?$/.test(t)) return `${lead}<span class="tok-num">${t}</span>`;
    return `${lead}<span class="tok-str">${esc(t)}</span>`;
  }

  function opts(list, current) {
    return list.map((v) => `<option value="${escAttr(v)}" ${v === current ? 'selected' : ''}>${esc(v)}</option>`).join('');
  }

  function fieldHtml(f, value, attrs) {
    if (f.type === 'bool') {
      return `<label class="pb-toggle"><input type="checkbox" ${attrs} ${value ? 'checked' : ''} /> ${esc(f.label)}</label>`;
    }
    if (f.type === 'select') {
      return `<label class="pb-field"><span>${esc(f.label)}</span><select ${attrs}>${opts(f.options, value)}</select></label>`;
    }
    const type = f.type === 'number' ? 'number' : 'text';
    return `<label class="pb-field"><span>${esc(f.label)}</span><input type="${type}" ${attrs} value="${escAttr(value ?? '')}" /></label>`;
  }

  function refreshYaml() {
    const text = emitYaml();
    ui.yaml.innerHTML = highlight(text);
    ui.yaml.dataset.raw = text;
  }

  function refreshNotes() {
    ui.notes.innerHTML = advisories()
      .map((n) => `<p class="pb-note ${n.level === 'err' ? 'is-err' : ''}">${esc(n.text)}</p>`)
      .join('');
  }

  function catLabel(cat) {
    if (cat === 'preparation') return 'prep';
    if (cat === 'control') return 'control';
    return 'exec';
  }

  function renderPayload() {
    ui.payload.innerHTML = `
      <div class="pb-grid">
        <label class="pb-field pb-span-2"><span>Source</span>
          <input type="text" data-k="source" value="${escAttr(state.source)}" placeholder="./payload.exe · https://… · $arg.0$" />
        </label>
        <label class="pb-field"><span>Format</span>
          <select data-k="format">${opts(['pe', 'dll', 'shellcode', 'dotnet'], state.format)}</select>
        </label>
        <label class="pb-field"><span>Name</span>
          <input type="text" data-k="name" value="${escAttr(state.name)}" />
        </label>
        <label class="pb-field pb-span-3"><span>Args</span>
          <input type="text" data-k="args" value="${escAttr(state.args)}" placeholder="comma-separated, passed to the payload" />
        </label>
      </div>`;
    bindKeys(ui.payload);
  }

  function renderChain() {
    const n = state.steps.length;
    ui.count.textContent = n === 1 ? '1 step' : `${n} steps`;
    if (!n) {
      ui.chain.innerHTML = `<li class="pb-empty">No steps yet. Add a technique to start the chain.</li>`;
      return;
    }
    ui.chain.innerHTML = state.steps.map((step, i) => {
      const def = TECH[step.id];
      if (!def) return '';
      const fields = (def.fields || []).filter((f) => f.type !== 'fixed');
      const warn = stepWarning(step);
      const params = step.open && fields.length
        ? `<div class="pb-params">${fields.map((f) => fieldHtml(f, step.params[f.key], `data-uid="${step.uid}" data-pk="${f.key}"`)).join('')}</div>`
        : '';
      return `
        <li class="pb-step">
          <article class="pb-step-card">
            <div class="pb-step-top">
              <div class="pb-step-title">
                <strong>${esc(def.label)}</strong>
                <span class="pb-badge">${catLabel(def.category)}</span>
                <code class="pb-id">${esc(step.id)}</code>
                ${def.doc ? `<a class="pb-doc" href="${escAttr(def.doc)}">docs</a>` : ''}
              </div>
              <div class="pb-step-tools">
                ${fields.length ? `<button type="button" class="pb-icon" data-toggle="${step.uid}" title="${step.open ? 'Hide parameters' : 'Edit parameters'}" aria-expanded="${step.open}">${step.open ? '–' : '+'}</button>` : ''}
                <button type="button" class="pb-icon" data-move="-1" data-i="${i}" aria-label="Move up" ${i === 0 ? 'disabled' : ''}>↑</button>
                <button type="button" class="pb-icon" data-move="1" data-i="${i}" aria-label="Move down" ${i === n - 1 ? 'disabled' : ''}>↓</button>
                <button type="button" class="pb-icon is-danger" data-del="${i}" aria-label="Remove">×</button>
              </div>
            </div>
            <p class="pb-blurb">${esc(def.blurb)}</p>
            ${warn ? `<p class="pb-step-note ${warn.level === 'err' ? 'is-err' : ''}">${esc(warn.text)}</p>` : ''}
            ${params}
          </article>
        </li>`;
    }).join('');

    ui.chain.querySelectorAll('[data-move]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const i = Number(btn.dataset.i);
        const j = i + Number(btn.dataset.move);
        if (j < 0 || j >= state.steps.length) return;
        [state.steps[i], state.steps[j]] = [state.steps[j], state.steps[i]];
        paint();
      });
    });
    ui.chain.querySelectorAll('[data-del]').forEach((btn) => {
      btn.addEventListener('click', () => {
        state.steps.splice(Number(btn.dataset.del), 1);
        paint();
      });
    });
    ui.chain.querySelectorAll('[data-toggle]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const step = state.steps.find((s) => s.uid === Number(btn.dataset.toggle));
        if (step) step.open = !step.open;
        paint();
      });
    });
    ui.chain.querySelectorAll('[data-uid]').forEach((node) => {
      const step = state.steps.find((s) => s.uid === Number(node.dataset.uid));
      const f = TECH[step.id].fields.find((x) => x.key === node.dataset.pk);
      const sync = () => {
        if (f.type === 'bool') step.params[f.key] = node.checked;
        else if (f.type === 'number') step.params[f.key] = node.value === '' ? '' : Number(node.value);
        else step.params[f.key] = node.value;
        refreshYaml();
        refreshNotes();
      };
      node.addEventListener(node.type === 'checkbox' || node.tagName === 'SELECT' ? 'change' : 'input', sync);
    });
  }

  function renderSettings() {
    ui.settings.innerHTML = `
      <div class="pb-settings-grid">
        <div>
          <h3>Output</h3>
          <div class="pb-grid" style="padding:0">
            <label class="pb-field pb-span-2"><span>Path</span><input type="text" data-k="out" value="${escAttr(state.out)}" /></label>
            <label class="pb-field"><span>Kind</span><select data-k="kind">${opts(['exe', 'dll'], state.kind)}</select></label>
            <label class="pb-field"><span>Arch</span><select data-k="arch">${opts(['x64', 'x86'], state.arch)}</select></label>
            <div class="pb-toggles pb-span-2">
              <label class="pb-toggle"><input type="checkbox" data-k="signLab" ${state.signLab ? 'checked' : ''} /> Lab sign</label>
              <label class="pb-toggle"><input type="checkbox" data-k="identity" ${state.identity ? 'checked' : ''} /> Random identity</label>
              <label class="pb-toggle"><input type="checkbox" data-k="debug" ${state.debug ? 'checked' : ''} /> Stub debug</label>
            </div>
          </div>
        </div>
        <div>
          <h3>Loader</h3>
          <div class="pb-grid" style="padding:0">
            <label class="pb-field"><span>Strings</span>
              <select data-k="strings">
                <option value="off" ${!state.strings ? 'selected' : ''}>off</option>
                <option value="xor" ${state.strings ? 'selected' : ''}>xor · random key</option>
              </select>
            </label>
            <label class="pb-field"><span>Syscalls</span>
              <select data-k="syscalls">
                <option value="none" ${state.syscalls === 'none' ? 'selected' : ''}>Win32</option>
                <option value="indirect" ${state.syscalls === 'indirect' ? 'selected' : ''}>indirect</option>
              </select>
            </label>
            <label class="pb-field pb-span-2"><span>Resolver</span>
              <select data-k="resolver" ${state.syscalls !== 'indirect' ? 'disabled' : ''}>${opts(['hells_gate', 'tartarus_gate', 'api_hash'], state.resolver)}</select>
            </label>
            <div class="pb-span-2">
              <label class="pb-toggle"><input type="checkbox" data-k="proxy" ${state.proxy ? 'checked' : ''} /> Proxy catalogue APIs</label>
              <p class="pb-hint">Serves a few payload imports from the syscall layer. Needs indirect syscalls and one reflective execution.</p>
            </div>
          </div>
        </div>
      </div>`;
    bindKeys(ui.settings);
  }

  function applyKey(node) {
    const key = node.dataset.k;
    if (node.type === 'checkbox') state[key] = node.checked;
    else if (key === 'strings') state.strings = node.value === 'xor';
    else state[key] = node.value;

    if (key === 'format' && node.value === 'dotnet' && TECH.dotnet_hosting && !state.steps.some((s) => s.id === 'dotnet_hosting')) {
      state.steps = [...state.steps.filter((s) => TECH[s.id]?.category !== 'execution'), stepOf('dotnet_hosting')];
    }
    if (key === 'kind' && node.value === 'dll' && !/\.dll$/i.test(state.out)) {
      state.out = state.out.replace(/\.exe$/i, '') + '.dll';
    }
  }

  function bindKeys(scope) {
    scope.querySelectorAll('[data-k]').forEach((node) => {
      const live = node.tagName === 'INPUT' && node.type === 'text';
      node.addEventListener(live ? 'input' : 'change', () => {
        applyKey(node);
        if (live) {
          refreshYaml();
          refreshNotes();
        } else {
          paint();
        }
      });
    });
  }

  function matches(t) {
    const q = pickerQuery.trim().toLowerCase();
    if (!q) return true;
    return t.label.toLowerCase().includes(q) || t.id.includes(q) || (t.blurb || '').toLowerCase().includes(q);
  }

  function inSection(t, cat) {
    return t.category === cat && matches(t);
  }

  function renderPicker() {
    ui.pickerNav.innerHTML = SECTIONS.map(([cat, label]) => {
      const n = Object.values(TECH).filter((t) => inSection(t, cat)).length;
      return `<button type="button" class="pb-sec ${pickerSection === cat ? 'is-on' : ''}" data-section="${cat}">
        <span>${label}</span><span class="pb-sec-count">${n}</span>
      </button>`;
    }).join('');
    ui.pickerNav.querySelectorAll('[data-section]').forEach((btn) => {
      btn.addEventListener('click', () => {
        pickerSection = btn.dataset.section;
        renderPicker();
      });
    });

    const items = Object.values(TECH).filter((t) => inSection(t, pickerSection));
    ui.pickerList.innerHTML = items.length
      ? items.map((t) => `<button type="button" class="pb-tech" data-pick="${escAttr(t.id)}">
          <strong>${esc(t.label)}</strong>
          <code>${esc(t.id)}</code>
          <small>${esc(t.blurb)}</small>
        </button>`).join('')
      : `<p class="pb-none">Nothing in this section${pickerQuery.trim() ? ' matches the filter' : ''}.</p>`;
    ui.pickerList.querySelectorAll('[data-pick]').forEach((btn) => {
      btn.addEventListener('click', () => addTechnique(btn.dataset.pick));
    });
  }

  function addTechnique(id) {
    const step = stepOf(id);
    if (!step) return;
    if ((TECH[id].fields || []).some((f) => f.type !== 'fixed')) step.open = true;
    state.steps.push(step);
    ui.picker.close();
    pickerQuery = '';
    ui.pickerSearch.value = '';
    paint();
  }

  function paint() {
    renderPayload();
    renderChain();
    renderSettings();
    refreshNotes();
    refreshYaml();
  }

  root.querySelector('[data-open-picker]').addEventListener('click', () => {
    pickerQuery = '';
    pickerSection = 'preparation';
    ui.pickerSearch.value = '';
    renderPicker();
    ui.picker.showModal();
    ui.pickerSearch.focus();
  });
  ui.pickerSearch.addEventListener('input', () => {
    pickerQuery = ui.pickerSearch.value;
    renderPicker();
  });

  async function copyYaml() {
    const text = ui.yaml.dataset.raw || emitYaml();
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    toast('Copied');
  }
  root.querySelector('[data-copy]').addEventListener('click', copyYaml);
  root.querySelector('[data-download]').addEventListener('click', () => {
    const text = ui.yaml.dataset.raw || emitYaml();
    const blob = new Blob([text], { type: 'text/yaml;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${state.name || 'plan'}.yaml`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast('Downloaded');
  });

  paint();
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function escAttr(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}
