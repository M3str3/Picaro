#!/usr/bin/env node
/**
 * Assemble the Starlight docs from the repository's single source of truth.
 *
 * Three things happen here:
 *   1. The navigation in `docs/nav.yml` (which the Rust test suite also reads) is
 *      turned into a Starlight `sidebar` and written to `src/sidebar.mjs`.
 *      Technique pages are then split by category and badged with stability.
 *   2. Every Markdown page under `docs/` is copied into Starlight's content
 *      directory. A page that is only `--8<-- "src/…/README.md"` is that README
 *      copied across, with a `title` taken from its first heading and local
 *      `.md` links rewritten to Starlight slugs (`foo.md` -> `/foo/`).
 *   3. Each technique's `mod.rs` is scanned into `/techniques.json` (the
 *      registry: params, stability, ATT&CK, syscalls, …). The README is not
 *      rewritten from that data; it is the other artifact.
 *
 * The script is editor-agnostic: it never writes to the repository, only to the
 * output directories passed on the command line (in the container those live
 * under /app, outside the bind mount).
 */

import {
  readFileSync,
  readdirSync,
  writeFileSync,
  mkdirSync,
  rmSync,
  watch,
  existsSync,
} from 'node:fs';
import { dirname, join, posix, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';
import { loadTechniques } from './catalog.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

const STABILITY_RANK = { stable: 0, experimental: 1, unimplemented: 2, deprecated: 3 };

const STABILITY_BADGE = {
  stable: { text: 'stable', variant: 'success', class: 'stab' },
  experimental: { text: 'experimental', variant: 'caution', class: 'stab' },
  unimplemented: { text: 'unimplemented', variant: 'danger', class: 'stab' },
  deprecated: { text: 'deprecated', variant: 'danger', class: 'stab' },
};

const CATEGORY_LABEL = {
  preparation: 'Preparation',
  execution: 'Execution',
  control: 'Control',
};

/**
 * The nav lists only the Techniques overview and the guide; the technique entries
 * are generated from the registry. The sidebar splits them by
 * `TechniqueDef.category` and badges each one with its stability, both read
 * from the registry (`techniques.json`).
 */
function groupTechniqueSidebar(sidebar, byName) {
  return sidebar.map((item) => {
    if (item.label !== 'Techniques' || !Array.isArray(item.items)) return item;

    // The nav keeps only the overview and the guide; the technique entries come
    // from the registry (label, link and stability badge), grouped by category
    // and ordered by maturity, so adding a technique needs no nav edit.
    const head = item.items.filter((child) => !child.link?.includes('adding-a-technique'));
    const tail = item.items.filter((child) => child.link?.includes('adding-a-technique'));

    const buckets = new Map(Object.keys(CATEGORY_LABEL).map((key) => [key, []]));
    for (const tech of byName.values()) {
      const list = buckets.get(tech.category) ?? buckets.get('preparation');
      list.push({
        label: tech.label,
        link: tech.page,
        badge: STABILITY_BADGE[tech.stability] ?? {
          text: tech.stability,
          variant: 'default',
          class: 'stab',
        },
        rank: STABILITY_RANK[tech.stability] ?? 9,
      });
    }

    for (const list of buckets.values()) {
      list.sort((a, b) => a.rank - b.rank || a.label.localeCompare(b.label));
      for (const entry of list) delete entry.rank;
    }

    const groups = Object.entries(CATEGORY_LABEL)
      .filter(([key]) => buckets.get(key).length > 0)
      .map(([key, label]) => ({ label, items: buckets.get(key) }));

    return { label: item.label, items: [...head, ...groups, ...tail] };
  });
}

/**
 * The "Registered techniques" overview table, generated from the registry so
 * `docs/techniques/index.md` keeps only its prose. The page carries a
 * `<!-- techniques-table -->` marker that this replaces; the links are relative
 * (`ref/<name>.md`) and the page processor rewrites them to slugs.
 */
function techniquesTable(registry) {
  const order = { preparation: 0, execution: 1, control: 2 };
  const rows = [...registry.techniques].sort(
    (a, b) =>
      (order[a.category] ?? 9) - (order[b.category] ?? 9) || a.name.localeCompare(b.name),
  );
  const lines = [
    '| Technique | Category | ATT&CK | Stability | Summary |',
    '| --- | --- | --- | --- | --- |',
  ];
  for (const tech of rows) {
    const summary = tech.summary.replace(/\|/g, '\\|');
    lines.push(
      `| [${tech.name}](ref/${tech.name}.md) | ${tech.category} | ${tech.attck.join(', ')} | `
        + `${tech.stability} | ${summary} |`,
    );
  }
  return lines.join('\n');
}

/**
 * The loader-features sidebar group, generated from the feature registry (label,
 * link, stability badge), ordered by maturity then name. A feature with
 * children in `resolversByParent` (currently `syscalls`, which owns the SSN
 * resolvers) becomes an expanded sub-tree: an `Overview` link to the feature
 * page plus one child per resolver. The nav keeps only the overview and the
 * guide.
 */
function groupFeatureSidebar(sidebar, byFeature, resolversByParent) {
  const badgeFor = (stability) =>
    STABILITY_BADGE[stability] ?? { text: stability, variant: 'default', class: 'stab' };
  const rank = (stability) => STABILITY_RANK[stability] ?? 9;

  return sidebar.map((item) => {
    if (item.label !== 'Loader features' || !Array.isArray(item.items)) return item;

    const head = item.items.filter((child) => !child.link?.includes('adding-a-feature'));
    const tail = item.items.filter((child) => child.link?.includes('adding-a-feature'));

    const list = [...byFeature.values()]
      .sort((a, b) => rank(a.stability) - rank(b.stability) || a.label.localeCompare(b.label))
      .map((feature) => {
        const children = (resolversByParent.get(feature.name) ?? []).sort(
          (a, b) => rank(a.stability) - rank(b.stability) || a.label.localeCompare(b.label),
        );
        if (children.length === 0) {
          return { label: feature.label, link: feature.page, badge: badgeFor(feature.stability) };
        }
        return {
          label: feature.label,
          collapsed: false,
          items: [
            { label: 'Overview', link: feature.page, badge: badgeFor(feature.stability) },
            ...children.map((child) => ({
              label: child.label,
              link: child.doc,
              badge: badgeFor(child.stability),
            })),
          ],
        };
      });

    return { label: item.label, items: [...head, ...list, ...tail] };
  });
}

/** The "Registered features" overview table, generated from the feature registry. */
function featuresTable(features) {
  const lines = [
    '| Feature | Scope | ATT&CK | Stability | Summary |',
    '| --- | --- | --- | --- | --- |',
  ];
  for (const feature of features) {
    const summary = feature.summary.replace(/\|/g, '\\|');
    lines.push(
      `| [${feature.name}](ref/${feature.name}.md) | ${feature.scope} | `
        + `${feature.attck.join(', ')} | ${feature.stability} | ${summary} |`,
    );
  }
  return lines.join('\n');
}

/** Parse `--name value` / `--flag` arguments into a plain object. */
function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const eq = token.indexOf('=');
    if (eq !== -1) {
      out[token.slice(2, eq)] = token.slice(eq + 1);
    } else {
      const name = token.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        out[name] = next;
        i++;
      } else {
        out[name] = true;
      }
    }
  }
  return out;
}

/* ------------------------------------------------------------------------- */
/* Navigation                                                                */
/* ------------------------------------------------------------------------- */

/** Convert a `.md` path (as written in `docs/nav.yml`) to a Starlight slug. */
function toLink(path) {
  let p = path.replace(/\.mdx?$/, '');
  if (p === 'index' || p.endsWith('/index')) {
    p = p.replace(/\/?index$/, '');
  }
  return p ? `/${p}/` : '/';
}

/**
 * A `docs/nav.yml` nav entry is a single-key mapping whose value is either a
 * string (a leaf page) or an array (a group of further entries).
 */
function toSidebarItem(item) {
  const entries = Object.entries(item);
  if (entries.length !== 1) {
    throw new Error(`Invalid nav entry: ${JSON.stringify(item)}`);
  }
  const [label, value] = entries[0];
  if (typeof value === 'string') {
    // Absolute paths (e.g. `/plan-builder/`) are custom Astro routes, not
    // Markdown pages under docs/.
    if (value.startsWith('/')) {
      const link = value.endsWith('/') ? value : `${value}/`;
      return { label, link };
    }
    return { label, link: toLink(value) };
  }
  if (Array.isArray(value)) {
    return { label, items: value.map(toSidebarItem) };
  }
  throw new Error(`Invalid nav value for "${label}": ${JSON.stringify(value)}`);
}

/** Turn the `nav:` list into a Starlight sidebar array. */
function buildSidebar(nav) {
  if (!Array.isArray(nav)) {
    throw new Error('docs/nav.yml: expected a top-level `nav:` list');
  }
  return nav.map(toSidebarItem);
}

/* ------------------------------------------------------------------------- */
/* Snippet inlining                                                          */
/* ------------------------------------------------------------------------- */

const SNIPPET_LINE = /^\s*--8<--\s+"([^"]+)"\s*$/;
const SECTION_START = /<!--\s*--8<--\s*\[start:([\w-]+)\]\s*-->/;
const SECTION_END = /<!--\s*--8<--\s*\[end:([\w-]+)\]\s*-->/;

/** Read a file and, for a `path:section` directive, extract just that section. */
function readSnippet(root, directive) {
  const [path, section] = directive.split(':');
  const file = join(root, path);
  const text = readFileSync(file, 'utf8').replace(/\r\n/g, '\n');

  if (!section) return text;

  const lines = text.split('\n');
  let start = -1;
  let end = -1;
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(SECTION_START);
    if (m && m[1] === section) start = i;
    const e = lines[i].match(SECTION_END);
    if (e && e[1] === section) {
      end = i;
      break;
    }
  }
  if (start === -1 || end === -1) {
    throw new Error(
      `Snippet section "${section}" not found in ${path} (need [start:${section}] ... [end:${section}])`,
    );
  }
  return lines.slice(start + 1, end).join('\n');
}

/** Shift every ATX heading in a block down one level (`#` -> `##`, ...). */
function demoteHeadings(text) {
  return text
    .split('\n')
    .map((line) => (line.startsWith('#') ? `#${line}` : line))
    .join('\n');
}

/**
 * Inline the `--8<-- "path"` / `--8<-- "path:section"` directives in `text`.
 * `demoteWhole` shifts whole-file includes' headings down one level (used when a
 * page already has its own H1, so an included README's `# Title` becomes a
 * subsection instead of a second page title).
 */
function inlineSnippets(text, root, demoteWhole) {
  const lines = text.split('\n');
  const out = [];
  for (const line of lines) {
    const m = line.match(SNIPPET_LINE);
    if (!m) {
      out.push(line);
      continue;
    }
    const directive = m[1];
    const snippetPath = directive.split(':')[0];
    const isSection = directive.includes(':');
    let included = readSnippet(root, directive).replace(/\n$/, '');
    // Links inside an included README resolve against that file's directory.
    included = rewriteMdLinks(included, posix.dirname(snippetPath));
    if (!isSection && demoteWhole) {
      included = demoteHeadings(included);
    }
    out.push(included);
  }
  return out.join('\n');
}

/* ------------------------------------------------------------------------- */
/* Frontmatter + titles                                                      */
/* ------------------------------------------------------------------------- */

/** Split a leading `---` frontmatter block from the body. */
function splitFrontmatter(raw) {
  if (raw.startsWith('---\n')) {
    const end = raw.indexOf('\n---', 4);
    if (end !== -1) {
      return {
        frontmatter: raw.slice(0, end + 4),
        body: raw.slice(end + 4).replace(/^\n+/, ''),
      };
    }
  }
  return { frontmatter: null, body: raw };
}

/** Pull the first `# Heading` out of `content`, returning title + remainder. */
function extractTitle(content) {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^#\s+(.+?)\s*$/);
    if (m) {
      const title = m[1];
      // Drop the heading and one following blank line.
      if (lines[i + 1] === '') lines.splice(i, 2);
      else lines.splice(i, 1);
      return { title, rest: lines.join('\n') };
    }
  }
  return { title: null, rest: content };
}

/** Map a repository-relative `.md` path to the Starlight slug it is built at.
 *  Returns `null` for anything outside `docs/` (a README may also link to
 *  `AGENTS.md`, `src/…`, …) so those links are left untouched. */
function docSlug(repoPath) {
  if (!repoPath.startsWith('docs/')) return null;
  let p = repoPath.slice('docs/'.length).replace(/\.mdx?$/, '');
  if (p === 'index') p = '';
  else if (p.endsWith('/index')) p = p.slice(0, -'/index'.length);
  return p ? `/${p}/` : '/';
}

const MD_LINK = /\]\(([^)\s]+)(\s+"[^"]*")?\)/g;

/**
 * Rewrite every local `.md` link in `content` to its Starlight slug. `base` is
 * the directory (repository-relative, forward slashes) the links resolve
 * against — the page's own directory, or the included README's directory when
 * `content` came from a `--8<--` snippet.
 *
 * External URLs, bare anchors, site-absolute paths and non-`.md` links are left
 * as they are; anchors and link titles are preserved.
 */
function rewriteMdLinks(content, base) {
  return content.replace(MD_LINK, (whole, target, title) => {
    if (/^[a-z][a-z0-9+.-]*:/i.test(target)) return whole; // http:, mailto:, …
    if (target.startsWith('/') || target.startsWith('#')) return whole;

    const hash = target.indexOf('#');
    const path = hash === -1 ? target : target.slice(0, hash);
    const anchor = hash === -1 ? '' : target.slice(hash);
    if (!/\.mdx?$/i.test(path)) return whole;

    const slug = docSlug(posix.normalize(posix.join(base, path)));
    if (slug === null) return whole;
    return `](${slug}${anchor}${title ?? ''})`;
  });
}

/** Turn a ```mermaid …``` fence into a `<pre class="mermaid">` block that the
 *  client-side Mermaid bundle renders. Keeps the READMEs free of HTML; the
 *  source is escaped so its `-->` arrows survive the markdown → HTML step. */
function transformMermaid(content) {
  return content.replace(/```mermaid\s*\n([\s\S]*?)```/g, (_, src) => {
    const escaped = src.trim()
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    return `<pre class="mermaid">${escaped}</pre>`;
  });
}

/* ------------------------------------------------------------------------- */
/* Page processing                                                           */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* Registry data for the technique panel                                     */
/* ------------------------------------------------------------------------- */

/**
 * Write the registry to a module the site imports.
 *
 * The metadata panel above a technique page ("Metadata", "Example", …) is a
 * real Starlight component (`src/components/TechniqueMeta.astro`), so it cannot
 * be inlined into the generated Markdown. It imports the registry from this
 * module instead, written next to `sidebar.mjs` (both live under Starlight's
 * `src/`).
 */
function writeTechniquesModule(sidebarOut, registry, features) {
  const dest = join(dirname(sidebarOut), 'techniques.generated.mjs');
  const text =
    '// Generated by scripts/assemble-docs.mjs from src/techniques/*/mod.rs and '
    + 'src/features/*/mod.rs. Do not edit.\n'
    + `export const techniques = ${JSON.stringify(registry.techniques, null, 2)};\n`
    + `export const features = ${JSON.stringify(features, null, 2)};\n`;
  const wrote = writeIfChanged(dest, text);
  if (wrote) {
    // eslint-disable-next-line no-console
    console.log(
      `${registry.techniques.length} techniques, ${features.length} features → ${dest}`,
    );
  }
  return wrote;
}

function processPage(raw, root, fallbackTitle, rel, generated) {
  // Normalise Windows CRLF line endings so frontmatter detection and heading
  // extraction work regardless of how the source file was saved.
  raw = raw.replace(/\r\n/g, '\n');

  const { frontmatter, body } = splitFrontmatter(raw);

  // A page "has its own content" when something other than a snippet directive
  // is present — in that case a whole-file include's H1 becomes a subsection.
  const hasOwnContent = body
    .split('\n')
    .some((line) => line.trim() !== '' && !SNIPPET_LINE.test(line));

  let content = inlineSnippets(body, root, hasOwnContent);
  // A generated block (the registry overview table) replaces its marker in the
  // page source, before links are rewritten.
  if (generated) content = content.replace('<!-- registry-table -->', generated);
  // The page's own links resolve against the page's directory under docs/.
  // `rel` comes from `docs/nav.yml` with forward slashes, so resolve with posix.
  content = rewriteMdLinks(content, posix.dirname(posix.join('docs', rel)));
  content = transformMermaid(content);

  if (frontmatter !== null) {
    return `${frontmatter}\n\n${content}`;
  }

  const { title, rest } = extractTitle(content);
  const safeTitle = title ?? fallbackTitle ?? 'Untitled';
  return `---\ntitle: ${JSON.stringify(safeTitle)}\n---\n\n${rest}`;
}

/** Collect every leaf `.md` path referenced by the navigation, with its label. */
function collectPages(nav) {
  const pages = new Map();
  const visit = (items) => {
    for (const item of items) {
      const entries = Object.entries(item);
      if (entries.length !== 1) continue;
      const [label, value] = entries[0];
      // Skip absolute routes (custom Astro pages such as `/plan-builder/`).
      if (typeof value === 'string' && !value.startsWith('/')) {
        pages.set(value, label);
      } else if (Array.isArray(value)) {
        visit(value);
      }
    }
  };
  visit(nav);
  return pages;
}

/** Write `text` only when the file differs, so a no-op assemble does not touch mtimes. */
function writeIfChanged(dest, text) {
  if (existsSync(dest) && readFileSync(dest, 'utf8') === text) return false;
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, text);
  return true;
}

/** Write a JSON document under the site's public dir. */
function writePublicJson(publicOut, name, data) {
  const dest = join(publicOut, name);
  const wrote = writeIfChanged(dest, `${JSON.stringify(data, null, 2)}\n`);
  if (wrote) {
    // eslint-disable-next-line no-console
    console.log(`${data.techniques.length} techniques → ${dest}`);
  }
  return wrote;
}

/** Every `.md` path under `dir`, relative and using forward slashes. */
function markdownFiles(dir) {
  const found = [];
  const walk = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.name.endsWith('.md')) found.push(relative(dir, path).replaceAll('\\', '/'));
    }
  };
  if (existsSync(dir)) walk(dir);
  return found;
}

/**
 * Copy exactly the pages the navigation references.
 *
 * Files are updated in place. Wiping the content directory makes Starlight's
 * dev loader drop `getStaticPaths()` and every route 404s until the server
 * restarts — which is what a second assemble did a few seconds after startup.
 */
function copyDocs(root, outDir, pages, generatedByRel) {
  mkdirSync(outDir, { recursive: true });
  const keep = new Set();
  let wrote = 0;
  for (const [rel, label] of pages) {
    const src = join(root, 'docs', rel);
    if (!existsSync(src)) {
      // eslint-disable-next-line no-console
      console.warn(`nav references a missing page: docs/${rel}`);
      continue;
    }
    keep.add(rel);
    const raw = readFileSync(src, 'utf8');
    const generated = generatedByRel[rel] ?? null;
    if (writeIfChanged(join(outDir, rel), processPage(raw, root, label, rel, generated))) {
      wrote += 1;
    }
  }
  for (const rel of markdownFiles(outDir)) {
    if (!keep.has(rel)) rmSync(join(outDir, rel));
  }
  return wrote;
}

/* ------------------------------------------------------------------------- */
/* Entry point                                                               */
/* ------------------------------------------------------------------------- */

function assemble(root, outDir, sidebarOut, publicOut) {
  const nav = yaml.load(readFileSync(join(root, 'docs', 'nav.yml'), 'utf8'));
  const { registry, catalog, features, resolvers } = loadTechniques(root);
  const byName = new Map(registry.techniques.map((tech) => [tech.name, tech]));
  const byFeature = new Map(features.map((feature) => [feature.name, feature]));
  const resolversByParent = new Map();
  for (const resolver of resolvers) {
    if (!resolversByParent.has(resolver.parent)) resolversByParent.set(resolver.parent, []);
    resolversByParent.get(resolver.parent).push(resolver);
  }
  let sidebar = buildSidebar(nav.nav);
  sidebar = groupTechniqueSidebar(sidebar, byName);
  sidebar = groupFeatureSidebar(sidebar, byFeature, resolversByParent);

  const sidebarText =
    `// Generated by scripts/assemble-docs.mjs from docs/nav.yml and the registries. Do not edit.\nexport default ${JSON.stringify(
      sidebar,
      null,
      2,
    )};\n`;
  const sidebarChanged = writeIfChanged(sidebarOut, sidebarText);
  const dataChanged = writeTechniquesModule(sidebarOut, registry, features);
  const pages = collectPages(nav.nav);
  // Technique and feature pages are not in the nav; add them from the registries.
  for (const tech of registry.techniques) {
    pages.set(`techniques/ref/${tech.name}.md`, tech.label);
  }
  for (const feature of features) {
    pages.set(`features/ref/${feature.name}.md`, feature.label);
  }
  for (const resolver of resolvers) {
    pages.set(`features/ref/syscalls/${resolver.id}.md`, resolver.label);
  }
  const generated = {
    'techniques/index.md': techniquesTable(registry),
    'features/index.md': featuresTable(features),
  };
  const pagesChanged = copyDocs(root, outDir, pages, generated);
  const registryChanged = writePublicJson(publicOut, 'techniques.json', registry);
  const catalogChanged = writePublicJson(publicOut, 'plan-catalog.json', catalog);
  if (sidebarChanged || dataChanged || pagesChanged || registryChanged || catalogChanged) {
    // eslint-disable-next-line no-console
    console.log(`assembled ${sidebar.length} sidebar groups into ${outDir}`);
  }
}

const args = parseArgs(process.argv.slice(2));
const root = resolve(args.root ?? process.cwd());
const outDir = resolve(args.out ?? join(root, 'docs/site/src/content/docs'));
const sidebarOut = resolve(args['sidebar-out'] ?? join(root, 'docs/site/src/sidebar.mjs'));
const publicOut = resolve(args['public-out'] ?? join(root, 'docs/site/public'));

if (args.watch) {
  let timer = null;
  const schedule = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      try {
        assemble(root, outDir, sidebarOut, publicOut);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`assemble failed: ${err.message}`);
      }
    }, 200);
  };
  const watched = [
    join(root, 'docs'),
    join(root, 'docs', 'nav.yml'),
    join(root, 'README.md'),
    join(root, 'examples/README.md'),
    join(root, 'src/techniques'),
    join(root, 'src/features'),
    join(root, 'src/engine/syscalls/resolvers'),
  ].filter((p) => existsSync(p));
  for (const path of watched) {
    watch(path, { recursive: true }, schedule);
  }
  // The serve command already assembled once. Re-running here deletes and
  // rewrites the content tree while Astro is starting, and Starlight then
  // serves 404s for routes it just had.
  // eslint-disable-next-line no-console
  console.log('watching for changes…');
} else {
  assemble(root, outDir, sidebarOut, publicOut);
}
