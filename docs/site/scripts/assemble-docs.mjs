#!/usr/bin/env node
/**
 * Assemble the Starlight docs from the repository's single source of truth.
 *
 * Two things happen here:
 *   1. The navigation in `docs/nav.yml` (which the Rust test suite also reads) is
 *      turned into a Starlight `sidebar` and written to `src/sidebar.mjs`.
 *   2. Every Markdown page under `docs/` is copied into Starlight's content
 *      directory, with the `--8<--` snippet directives inlined from the
 *      READMEs (the same single-source-of-truth trick MkDocs used), a `title`
 *      frontmatter injected from the first heading, and every local `.md`
 *      link rewritten to the Starlight slug it maps to (`foo.md` -> `/foo/`,
 *      `ref/bar.md` -> `/<dir>/ref/bar/`). Links resolve relative to the file
 *      that writes them — the including page for its own links, the snippet's
 *      own directory for links inside an included README.
 *
 * The script is editor-agnostic: it never writes to the repository, only to the
 * output directories passed on the command line (in the container those live
 * under /app, outside the bind mount).
 */

import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  rmSync,
  watch,
  existsSync,
} from 'node:fs';
import { dirname, join, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));

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

function processPage(raw, root, fallbackTitle, rel) {
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
      if (typeof value === 'string') pages.set(value, label);
      else if (Array.isArray(value)) visit(value);
    }
  };
  visit(nav);
  return pages;
}

/** Copy exactly the pages the navigation references (orphans are not built). */
function copyDocs(root, outDir, pages) {
  rmSync(outDir, { recursive: true, force: true });
  for (const [rel, label] of pages) {
    const src = join(root, 'docs', rel);
    if (!existsSync(src)) {
      // eslint-disable-next-line no-console
      console.warn(`nav references a missing page: docs/${rel}`);
      continue;
    }
    const dest = join(outDir, rel);
    mkdirSync(dirname(dest), { recursive: true });
    const raw = readFileSync(src, 'utf8');
    writeFileSync(dest, processPage(raw, root, label, rel));
  }
}

/* ------------------------------------------------------------------------- */
/* Entry point                                                               */
/* ------------------------------------------------------------------------- */

function assemble(root, outDir, sidebarOut) {
  const nav = yaml.load(readFileSync(join(root, 'docs', 'nav.yml'), 'utf8'));
  const sidebar = buildSidebar(nav.nav);

  mkdirSync(dirname(sidebarOut), { recursive: true });
  writeFileSync(
    sidebarOut,
    `// Generated by scripts/assemble-docs.mjs from docs/nav.yml. Do not edit.\nexport default ${JSON.stringify(
      sidebar,
      null,
      2,
    )};\n`,
  );

  copyDocs(root, outDir, collectPages(nav.nav));
  // eslint-disable-next-line no-console
  console.log(
    `assembled ${sidebar.length} sidebar groups into ${outDir}`,
  );
}

const args = parseArgs(process.argv.slice(2));
const root = resolve(args.root ?? process.cwd());
const outDir = resolve(args.out ?? join(root, 'docs/site/src/content/docs'));
const sidebarOut = resolve(args['sidebar-out'] ?? join(root, 'docs/site/src/sidebar.mjs'));

if (args.watch) {
  let timer = null;
  const schedule = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      try {
        assemble(root, outDir, sidebarOut);
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
  ].filter((p) => existsSync(p));
  for (const path of watched) {
    watch(path, { recursive: true }, schedule);
  }
  // eslint-disable-next-line no-console
  console.log('watching for changes…');
  schedule();
} else {
  assemble(root, outDir, sidebarOut);
}
