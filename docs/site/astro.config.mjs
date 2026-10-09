// picaro documentation site configuration.
//
// The sidebar is not written by hand: it is generated from `docs/nav.yml` (the
// single source of navigation truth, which the Rust test suite also reads) by
// `scripts/assemble-docs.mjs`. That script writes `src/sidebar.mjs` before
// Astro starts, so the import below always resolves at run time.

import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import sidebar from './src/sidebar.mjs';

export default defineConfig({
  site: 'https://picaro.dev',
  integrations: [
    starlight({
      title: 'picaro',
      logo: {
        src: './src/assets/picaro_logo.png',
        replacesTitle: false,
      },
      favicon: '/picaro_logo.png',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/M3str3/Picaro' },
      ],
      customCss: ['./src/styles/custom.css'],
      head: [
        {
          tag: 'script',
          attrs: { src: 'https://cdn.jsdelivr.net/npm/mermaid@12/dist/mermaid.min.js', defer: true },
        },
        { tag: 'script', attrs: { src: '/mermaid-init.js', defer: true } },
      ],
      sidebar,
      components: {
        // The technique metadata panel is a real Starlight component; this
        // override places it just under the title, above the page body.
        MarkdownContent: './src/components/MarkdownContent.astro',
      },
    }),
  ],
});
