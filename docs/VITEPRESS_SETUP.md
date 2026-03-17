# VitePress Documentation Setup

Use this page when you are maintaining the VitePress site under `docs/`.

This page covers site maintenance only. For package documentation structure and content routing, use [`README.md`](README.md) and [`index.md`](index.md).

## Run the Site Locally

Prerequisites:

- Node.js `18+` locally
- npm

CI uses Node `20`.

Install dependencies:

```bash
cd docs
npm install
```

Start the local dev server:

```bash
cd docs
npm run docs:dev
```

VitePress serves locally on `http://localhost:5173` by default.

## Build and Preview Production Output

Build the site:

```bash
cd docs
npm run docs:build
```

Build output goes to:

```text
docs/.vitepress/dist/
```

Preview the production build locally:

```bash
cd docs
npm run docs:preview
```

## Update Documentation Content

### Update the homepage

Edit [`index.md`](index.md). This file uses VitePress home-page frontmatter plus Markdown content.

### Add a new page

1. create a new `.md` file under `docs/`
2. add it to [`.vitepress/config.ts`](.vitepress/config.ts) if it should appear in navigation
3. add links from related pages so the new page is discoverable

### Update navigation

Edit `themeConfig.nav` and `themeConfig.sidebar` in [`.vitepress/config.ts`](.vitepress/config.ts).

## Current Site Implementation Notes

The documentation site is currently defined by:

- package file: [`package.json`](package.json)
- site config: [`.vitepress/config.ts`](.vitepress/config.ts)
- framework: VitePress `^1.0.0`

The site config currently sets:

- `base: "/competitionscratch/"`
- local search
- top navigation and sidebar entries
- GitHub edit links
- line numbers in Markdown code blocks
- GitHub Pages deployment settings

The config also sets `ignoreDeadLinks: true`. A VitePress build can still succeed when local links are broken, so changed links should be checked manually or through the repository link-check workflow.

## Deployment

GitHub Pages deployment is defined in [`../.github/workflows/deploy-docs.yml`](../.github/workflows/deploy-docs.yml).

Current behavior:

- trigger: pushes to `master` that touch `docs/**` or the workflow file
- build command: `cd docs && npm install && npm run docs:build`
- publish target: GitHub Pages

## Troubleshooting

### Port already in use

Run VitePress on a different port:

```bash
npx vitepress dev --port 5174
```

### Clean rebuild

Remove cached output, then rebuild:

```bash
rm -rf docs/.vitepress/dist docs/.vitepress/cache
cd docs
npm run docs:build
```

### Broken links not caught by VitePress

Because `ignoreDeadLinks: true` is enabled, the site build is not a complete link validator. When you change docs substantially, also verify:

- relative page links
- example file links
- nav and sidebar targets
- references to commands, filenames, and docs pages
