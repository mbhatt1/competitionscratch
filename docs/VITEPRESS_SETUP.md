# VitePress Documentation Setup

This directory contains the VitePress site for the repository docs.

## Current Tooling

- package file: [`package.json`](package.json)
- site config: [`.vitepress/config.ts`](.vitepress/config.ts)
- framework: VitePress `^1.0.0`

Current npm scripts:

```bash
npm run docs:dev
npm run docs:build
npm run docs:preview
```

## Prerequisites

- Node.js `18+` locally
- npm

CI currently uses Node `20`.

## Install

```bash
cd docs
npm install
```

## Local Development

Start the dev server:

```bash
cd docs
npm run docs:dev
```

By default, VitePress serves locally on `http://localhost:5173`.

## Production Build

```bash
cd docs
npm run docs:build
```

Current build output:

```text
docs/.vitepress/dist/
```

Preview the production build:

```bash
cd docs
npm run docs:preview
```

## Current Site Configuration

The current config in `.vitepress/config.ts` sets:

- `base: "/competitionscratch/"`
- local search
- a docs sidebar and top navigation
- GitHub edit links
- line numbers in Markdown code blocks
- GitHub Pages-friendly deployment settings

The config also sets `ignoreDeadLinks: true`, so broken local links may not fail the site build even though they are still worth fixing.

## Deployment

The current deployment workflow is:

- workflow file: [`../.github/workflows/deploy-docs.yml`](../.github/workflows/deploy-docs.yml)
- trigger: pushes to `master` that touch `docs/**` or the workflow file
- build command: `cd docs && npm install && npm run docs:build`
- publish target: GitHub Pages

## Common Tasks

### Add a new page

1. create a new `.md` file under `docs/`
2. add it to `.vitepress/config.ts` if it should appear in nav or sidebar
3. add links from related pages

### Update the homepage

Edit [`index.md`](index.md), which uses VitePress frontmatter plus Markdown content.

### Update navigation

Edit:

- `themeConfig.nav`
- `themeConfig.sidebar`

in [`.vitepress/config.ts`](.vitepress/config.ts).

## Troubleshooting

### Port in use

Run VitePress on a different port:

```bash
npx vitepress dev --port 5174
```

### Clean rebuild

```bash
rm -rf docs/.vitepress/dist docs/.vitepress/cache
cd docs
npm run docs:build
```

### Broken links not caught by VitePress

The site config currently ignores dead links. Use the repository Markdown link checks or inspect changed pages manually when you edit docs.
