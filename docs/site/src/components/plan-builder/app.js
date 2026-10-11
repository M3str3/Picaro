/**
 * Plan builder client logic.
 *
 * Catalogue: /plan-catalog.json, assembled from TechniqueDef.
 * The pure plan model — payloads, YAML emission, validation — lives in
 * ./plan.js; this file only renders it and wires events.
 */

import {
  SECTIONS,
  PAYLOAD_FORMATS,
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
} from './plan.js';

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
  const addUid = (obj) => Object.assign(obj, { uid: ++uidSeq });

  const state = baseState();
  for (const p of state.payloads) addUid(p);

  let pickerQuery = '';
  let pickerSection = 'preparation';
  let dragFrom = -1;

  const ui = {
    payload: root.querySelector('[data-payload]'),
    payloadCount: root.querySelector('[data-payload-count]'),
    loader: root.querySelector('[data-loader]'),
    stub: root.querySelector('[data-stub]'),
    chain: root.querySelector('[data-chain]'),
    count: root.querySelector('[data-count]'),
    notes: root.querySelector('[data-notes]'),
    output: root.querySelector('[data-output]'),
    status: root.querySelector('[data-status]'),
    yaml: root.querySelector('[data-yaml]'),
    yamlDialog: root.querySelector('[data-yaml-dialog]'),
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

  /* ---- state mutations -------------------------------------------------- */

  function addStep(id) {
    if (!TECH[id]) return null;
    const step = addUid(makeStep(id, TECH));
    const editable = fieldsOf(TECH[id]).filter((f) => f.type !== 'fixed');
    if (editable.length || takesPayload(id, TECH)) step.open = true;
    state.steps.push(step);
    return step;
  }

  function addPayload() {
    const name = `payload${state.payloads.length + 1}`;
    state.payloads.push(addUid(newPayload({ name })));
  }

  function removePayload(uid) {
    if (state.payloads.length <= 1) return;
    const index = state.payloads.findIndex((p) => p.uid === uid);
    if (index < 0) return;
    const [removed] = state.payloads.splice(index, 1);
    const fallback = state.payloads[0]?.name ?? '';
    for (const step of state.steps) {
      if (step.params && step.params.payload === removed.name) step.params.payload = fallback;
    }
  }

  /** Keep every step that named `old` pointing at the payload's new name. */
  function renamePayload(oldName, newName) {
    for (const step of state.steps) {
      if (step.params && step.params.payload === oldName) step.params.payload = newName;
    }
  }

  function ensureDotnetHosting(name) {
    const hosted = state.steps.some((s) => s.id === 'dotnet_hosting' && stepPayloadName(s, state) === name);
    if (hosted) return;
    const step = addStep('dotnet_hosting');
    if (step) step.params.payload = name;
  }

  function removeDotnetHosting(name) {
    state.steps = state.steps.filter((s) => !(s.id === 'dotnet_hosting'
      && ((s.params.payload || '') === name || !s.params.payload)));
  }

  function ensurePowershellHosting(name) {
    const hosted = state.steps.some((s) => s.id === 'powershell_hosting' && stepPayloadName(s, state) === name);
    if (hosted) return;
    const step = addStep('powershell_hosting');
    if (step) step.params.payload = name;
  }

  function removePowershellHosting(name) {
    state.steps = state.steps.filter((s) => !(s.id === 'powershell_hosting'
      && ((s.params.payload || '') === name || !s.params.payload)));
  }

  /* ---- YAML + status ---------------------------------------------------- */

  function refreshYaml() {
    const text = emitYaml(state, TECH);
    ui.yaml.innerHTML = highlight(text);
    ui.yaml.dataset.raw = text;
  }

  function refreshNotes() {
    ui.notes.innerHTML = advisories(state, TECH)
      .map((n) => `<p class="pb-note ${n.level === 'err' ? 'is-err' : n.level === 'info' ? 'is-info' : ''}">${esc(n.text)}</p>`)
      .join('');
  }

  function refreshStatus() {
    const notes = advisories(state, TECH);
    const errs = notes.filter((n) => n.level === 'err').length;
    const warns = notes.filter((n) => n.level === 'warn').length;
    ui.status.className = 'pb-status';
    if (errs) {
      ui.status.classList.add('is-err');
      ui.status.textContent = errs === 1 ? '1 error' : `${errs} errors`;
    } else if (warns) {
      ui.status.classList.add('is-warn');
      ui.status.textContent = warns === 1 ? '1 warning' : `${warns} warnings`;
    } else {
      ui.status.classList.add('is-ok');
      ui.status.textContent = 'Valid';
    }
  }

  /* ---- payloads --------------------------------------------------------- */

  function renderPayload() {
    ui.payloadCount.textContent = state.payloads.length === 1 ? '1 payload' : `${state.payloads.length} payloads`;
    const rows = state.payloads.map((p, i) => `
      <div class="pb-payload" data-puid="${p.uid}">
        <div class="pb-payload-head">
          <span class="pb-payload-n">Payload ${i + 1}</span>
          <button type="button" class="pb-icon is-danger" data-remove-payload="${p.uid}" aria-label="Remove payload" ${state.payloads.length <= 1 ? 'disabled' : ''}>×</button>
        </div>
        <div class="pb-grid">
          <label class="pb-field pb-span-2"><span>Source</span>
            <input type="text" data-pk="source" value="${escAttr(p.source)}" placeholder="./payload.exe · https://… · $arg.0$" />
          </label>
          <label class="pb-field"><span>Format</span>
            <select data-pk="format">${opts(PAYLOAD_FORMATS, p.format)}</select>
          </label>
          <label class="pb-field"><span>Name</span>
            <input type="text" data-pk="name" value="${escAttr(p.name)}" />
          </label>
          <label class="pb-field pb-span-3"><span>Args</span>
            <input type="text" data-pk="args" value="${escAttr(p.args)}" placeholder="comma-separated, passed to the payload" />
          </label>
        </div>
      </div>`).join('');
    ui.payload.innerHTML = `${rows}<button type="button" class="pb-add pb-add-payload" data-add-payload>Add payload</button>`;

    ui.payload.querySelector('[data-add-payload]').addEventListener('click', () => {
      addPayload();
      paint();
    });
    ui.payload.querySelectorAll('[data-remove-payload]').forEach((btn) => {
      btn.addEventListener('click', () => {
        removePayload(Number(btn.dataset.removePayload));
        paint();
      });
    });
    ui.payload.querySelectorAll('[data-pk]').forEach((node) => {
      const uid = Number(node.closest('[data-puid]').dataset.puid);
      const key = node.dataset.pk;
      const live = node.tagName === 'INPUT';
      node.addEventListener(live ? 'input' : 'change', () => {
        const p = state.payloads.find((x) => x.uid === uid);
        if (!p) return;
        if (key === 'format') {
          const previous = p.format;
          p.format = node.value;
          if (p.format === 'dotnet') ensureDotnetHosting(p.name);
          else if (previous === 'dotnet') removeDotnetHosting(p.name);
          if (p.format === 'powershell' && state.kind !== 'psmodule') ensurePowershellHosting(p.name);
          else if (previous === 'powershell' && state.kind !== 'psmodule') removePowershellHosting(p.name);
          paint();
          return;
        }
        if (key === 'name') {
          const previous = p.name;
          p.name = node.value;
          renamePayload(previous, node.value);
          refreshYaml();
          refreshNotes();
          refreshStatus();
          renderChain();
          return;
        }
        p[key] = node.value;
        refreshYaml();
        refreshNotes();
        refreshStatus();
      });
    });
  }

  /* ---- loader ----------------------------------------------------------- */

  function renderLoader() {
    const custom = state.stubPath.trim();
    ui.loader.innerHTML = `
      <div class="pb-grid">
        <label class="pb-field pb-span-3"><span>Stub template</span>
          <input type="text" data-k="stubPath" value="${escAttr(state.stubPath)}" placeholder="blank = built-in stub · ./stubs/custom.rs" />
        </label>
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
        <label class="pb-field"><span>Resolver</span>
          <select data-k="resolver" ${state.syscalls !== 'indirect' ? 'disabled' : ''}>${opts(['hells_gate', 'tartarus_gate', 'api_hash'], state.resolver)}</select>
        </label>
        <div class="pb-toggles pb-span-3">
          <label class="pb-toggle"><input type="checkbox" data-k="proxy" ${state.proxy ? 'checked' : ''} /> Proxy catalogue APIs</label>
          <label class="pb-toggle"><input type="checkbox" data-k="debug" ${state.debug ? 'checked' : ''} /> Stub debug</label>
        </div>
        <p class="pb-hint pb-span-3">${custom
          ? 'Custom stub — it must keep the step blocks (<code>$STUB_HELPERS$</code>, <code>$STEP_MODULES$</code>, <code>$STEP_RUNNER_BODY$</code>); see <code>docs/custom-stubs.md</code>.'
          : 'Built-in stub. The syscall layer and payload import resolution are wired from the techniques you add.'}</p>
      </div>`;
    if (ui.stub) ui.stub.textContent = stubLabel(state);
    bindKeys(ui.loader);
  }

  /* ---- runtime ---------------------------------------------------------- */

  function payloadSelect(step) {
    if (!takesPayload(step.id, TECH)) return '';
    const current = stepPayloadName(step, state);
    const options = state.payloads
      .map((p) => `<option value="${escAttr(p.name)}" ${p.name === current ? 'selected' : ''}>${esc(p.name || '(unnamed)')}</option>`)
      .join('');
    return `<label class="pb-field"><span>Payload</span><select data-uid="${step.uid}" data-pk="payload">${options}</select></label>`;
  }

  function renderChain() {
    const n = state.steps.length;
    ui.count.textContent = n === 1 ? '1 step' : `${n} steps`;
    if (!n) {
      ui.chain.innerHTML = '<li class="pb-empty">No steps yet. Add a technique to start the chain.</li>';
      return;
    }
    ui.chain.innerHTML = state.steps.map((step, i) => {
      const def = TECH[step.id];
      if (!def) return '';
      const fields = fieldsOf(def).filter((f) => f.type !== 'fixed');
      const hasParams = fields.length > 0 || takesPayload(step.id, TECH);
      const warn = stepWarning(step, state, TECH);
      const params = step.open && hasParams
        ? `<div class="pb-params">${payloadSelect(step)}${fields.map((f) => fieldHtml(f, step.params[f.key], `data-uid="${step.uid}" data-pk="${f.key}"`)).join('')}</div>`
        : '';
      return `
        <li class="pb-step" data-step="${i}">
          <article class="pb-step-card">
            <div class="pb-step-top">
              <div class="pb-step-title" draggable="true" data-drag title="Drag to reorder">
                <span class="pb-icon pb-drag" aria-hidden="true">⠿</span>
                <strong>${esc(def.label)}</strong>
                <span class="pb-badge">${catLabel(def.category)}</span>
                <code class="pb-id">${esc(step.id)}</code>
                ${def.doc ? `<a class="pb-doc" href="${escAttr(def.doc)}">docs</a>` : ''}
              </div>
              <div class="pb-step-tools">
                ${hasParams ? `<button type="button" class="pb-icon" data-toggle="${step.uid}" title="${step.open ? 'Hide parameters' : 'Edit parameters'}" aria-expanded="${step.open}">${step.open ? '–' : '+'}</button>` : ''}
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
      if (!step) return;
      const key = node.dataset.pk;
      const f = fieldsOf(TECH[step.id]).find((x) => x.key === key);
      const sync = () => {
        if (key === 'payload') step.params.payload = node.value;
        else if (f.type === 'bool') step.params[key] = node.checked;
        else if (f.type === 'number') step.params[key] = node.value === '' ? '' : Number(node.value);
        else step.params[key] = node.value;
        refreshYaml();
        refreshNotes();
        refreshStatus();
      };
      node.addEventListener(node.type === 'checkbox' || node.tagName === 'SELECT' ? 'change' : 'input', sync);
    });

    bindDrag();
  }

  /** Reorder `state.steps` by dragging a step's header onto another. Only the
   *  header (`.pb-step-title`) is a drag source, so the params never move by
   *  accident; any part of a step is a drop target. */
  function bindDrag() {
    const clear = () => ui.chain.querySelectorAll('.pb-step').forEach((n) => n.classList.remove('is-dragging', 'drop-above', 'drop-below'));
    ui.chain.querySelectorAll('[data-drag]').forEach((handle) => {
      const li = handle.closest('.pb-step');
      handle.addEventListener('dragstart', (e) => {
        // Keep the docs link clickable and never start a drag from it.
        if (e.target.closest('a')) {
          e.preventDefault();
          return;
        }
        dragFrom = Number(li.dataset.step);
        li.classList.add('is-dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', String(dragFrom));
        const card = li.querySelector('.pb-step-card');
        if (card) e.dataTransfer.setDragImage(card, 16, 16);
      });
      handle.addEventListener('dragend', () => {
        dragFrom = -1;
        clear();
      });
    });
    ui.chain.querySelectorAll('.pb-step').forEach((li) => {
      li.addEventListener('dragover', (e) => {
        if (dragFrom < 0) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        const rect = li.getBoundingClientRect();
        const above = e.clientY < rect.top + rect.height / 2;
        li.classList.toggle('drop-above', above);
        li.classList.toggle('drop-below', !above);
      });
      li.addEventListener('dragleave', () => li.classList.remove('drop-above', 'drop-below'));
      li.addEventListener('drop', (e) => {
        if (dragFrom < 0) return;
        e.preventDefault();
        e.stopPropagation();
        const over = Number(li.dataset.step);
        const rect = li.getBoundingClientRect();
        const above = e.clientY < rect.top + rect.height / 2;
        let to = above ? over : over + 1;
        if (dragFrom < to) to -= 1;
        if (to !== dragFrom) {
          const [moved] = state.steps.splice(dragFrom, 1);
          state.steps.splice(to, 0, moved);
        }
        dragFrom = -1;
        paint();
      });
    });
  }

  /* ---- output ----------------------------------------------------------- */

  function renderOutput() {
    ui.output.innerHTML = `
      <div class="pb-grid">
        <label class="pb-field pb-span-3"><span>Path</span>
          <input type="text" data-k="out" value="${escAttr(state.out)}" />
        </label>
        <label class="pb-field"><span>Kind</span><select data-k="kind">${opts(['exe', 'dll', 'psmodule'], state.kind)}</select></label>
        <label class="pb-field"><span>Arch</span><select data-k="arch">${opts(['x64', 'x86'], state.arch)}</select></label>
        <div class="pb-toggles pb-span-3">
          <label class="pb-toggle"><input type="checkbox" data-k="signLab" ${state.signLab ? 'checked' : ''} /> Lab sign</label>
          <label class="pb-toggle"><input type="checkbox" data-k="identity" ${state.identity ? 'checked' : ''} /> Random identity</label>
        </div>
      </div>`;
    bindKeys(ui.output);
  }

  function applyKey(node) {
    const key = node.dataset.k;
    if (node.type === 'checkbox') state[key] = node.checked;
    else if (key === 'strings') state.strings = node.value === 'xor';
    else state[key] = node.value;

    if (key === 'kind' && (node.value === 'dll' || node.value === 'psmodule')
        && !/\.dll$/i.test(state.out)) {
      state.out = state.out.replace(/\.exe$/i, '') + '.dll';
    }
    if (key === 'stubPath') ui.stub.textContent = stubLabel(state);
  }

  function bindKeys(scope) {
    scope.querySelectorAll('[data-k]').forEach((node) => {
      const live = node.tagName === 'INPUT' && node.type === 'text';
      node.addEventListener(live ? 'input' : 'change', () => {
        applyKey(node);
        if (live) {
          refreshYaml();
          refreshNotes();
          refreshStatus();
        } else {
          paint();
        }
      });
    });
  }

  /* ---- picker ----------------------------------------------------------- */

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
    const step = addStep(id);
    if (!step) return;
    ui.picker.close();
    pickerQuery = '';
    ui.pickerSearch.value = '';
    paint();
  }

  /* ---- render ----------------------------------------------------------- */

  function paint() {
    renderPayload();
    renderLoader();
    renderChain();
    renderOutput();
    refreshNotes();
    refreshStatus();
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

  root.querySelector('[data-open-yaml]').addEventListener('click', () => {
    refreshYaml();
    ui.yamlDialog.showModal();
  });
  root.querySelector('[data-close-yaml]').addEventListener('click', () => ui.yamlDialog.close());
  // Click on the backdrop (the dialog element itself) closes it.
  ui.yamlDialog.addEventListener('click', (e) => {
    if (e.target === ui.yamlDialog) ui.yamlDialog.close();
  });

  async function copyYaml() {
    const text = ui.yaml.dataset.raw || emitYaml(state, TECH);
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
    const text = ui.yaml.dataset.raw || emitYaml(state, TECH);
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

/* ---- small render helpers ---------------------------------------------- */

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
  const help = f.help ? ` title="${escAttr(f.help)}"` : '';
  if (f.type === 'bool') {
    return `<label class="pb-toggle"${help}><input type="checkbox" ${attrs} ${value ? 'checked' : ''} /> ${esc(f.label)}</label>`;
  }
  if (f.type === 'select') {
    return `<label class="pb-field"${help}><span>${esc(f.label)}</span><select ${attrs}>${opts(f.options, value)}</select></label>`;
  }
  const type = f.type === 'number' ? 'number' : 'text';
  return `<label class="pb-field"${help}><span>${esc(f.label)}</span><input type="${type}" ${attrs} value="${escAttr(value ?? '')}" /></label>`;
}

function catLabel(cat) {
  if (cat === 'preparation') return 'prep';
  if (cat === 'control') return 'control';
  return 'exec';
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function escAttr(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}
