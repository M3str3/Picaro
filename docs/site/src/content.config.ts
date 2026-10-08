// Starlight (Astro 5) content layer configuration.
//
// Defines the `docs` collection that Starlight renders, and the `i18n` loader
// for its built-in UI strings. The `docsSchema()` is what makes Starlight treat
// a page without a `draft` frontmatter as published — without it the production
// build filters every page out, because the schema default is what sets
// `draft: false`.

import { defineCollection } from 'astro:content';
import { docsLoader, i18nLoader } from '@astrojs/starlight/loaders';
import { docsSchema, i18nSchema } from '@astrojs/starlight/schema';

export const collections = {
  docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),
  i18n: defineCollection({ loader: i18nLoader(), schema: i18nSchema() }),
};
