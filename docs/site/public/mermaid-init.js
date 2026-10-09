// Picaro — client-side Mermaid initialization (theme-aware, brand colors).
//
// `rehype` (via `scripts/assemble-docs.mjs`) turns each ```mermaid fence into a
// `<pre class="mermaid">` block; this script tells Mermaid to render them on
// load with a palette that matches the site's violet/cyan theme. The colors
// are re-read once at load from the `data-theme` attribute Starlight sets.

(function () {
  'use strict';

  function palette(dark) {
    return dark
      ? {
          primaryColor: '#2b2350',
          primaryTextColor: '#ece9f7',
          primaryBorderColor: '#a78bfa',
          lineColor: '#a78bfa',
          secondaryColor: '#173338',
          tertiaryColor: '#15121e',
          background: '#15121e',
          mainBkg: '#15121e',
          textColor: '#ece9f7',
        }
      : {
          primaryColor: '#ede9fe',
          primaryTextColor: '#1a1625',
          primaryBorderColor: '#6d55e0',
          lineColor: '#6d55e0',
          secondaryColor: '#e0f4f7',
          tertiaryColor: '#f7f6fc',
          background: '#f7f6fc',
          mainBkg: '#ffffff',
          textColor: '#1a1625',
        };
  }

  const dark = document.documentElement.getAttribute('data-theme') === 'dark';
  window.mermaid.initialize({
    startOnLoad: true,
    theme: 'base',
    themeVariables: palette(dark),
  });
})();
