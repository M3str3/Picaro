# Picaro documentation site — Astro + Starlight.
#
# Build context is the repository root, and the image is invoked by
# `scripts/docs.py`, which bind-mounts the repository at /docs. Content and the
# sidebar are generated at run time by `scripts/assemble-docs.mjs` from that
# mount, so editing a page (or adding a technique) does not require rebuilding
# this image.

FROM node:20-slim

WORKDIR /app

# Dependencies first, so this layer is cached until package.json changes.
# `npm ci` uses the committed lockfile for a reproducible install.
COPY docs/site/package.json docs/site/package-lock.json ./
RUN npm ci --no-audit --no-fund

# The Starlight project: config, styles, assets and the assembler script.
# `src/content` and `src/sidebar.mjs` are generated at run time and deliberately
# not copied.
COPY docs/site/astro.config.mjs docs/site/tsconfig.json ./
COPY docs/site/src ./src
COPY docs/site/public ./public
COPY docs/site/scripts ./scripts

EXPOSE 4321

CMD ["npm", "run", "dev", "--", "--port", "4321", "--host", "0.0.0.0"]
