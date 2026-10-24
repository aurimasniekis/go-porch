import { defineConfig } from 'vitepress';
import { withMermaid } from 'vitepress-plugin-mermaid';

const repo = 'https://github.com/aurimasniekis/go-porch';

// Engineering docs in ../docs link to each other as FOO.md; on the site they are included into these pages.
const docPages: Record<string, string> = {
  IMPLEMENTATION_MATRIX: '/guide/status',
  ARCHITECTURE: '/reference/architecture',
  FLOWS: '/reference/flows',
  SCHEMA: '/reference/schema',
  API: '/reference/api',
  THREAT_MODEL: '/security/threat-model',
  DECISIONS: '/security/decisions',
  PLAN: repo + '/blob/main/docs/PLAN.md',
  BACKLOG: repo + '/blob/main/docs/BACKLOG.md',
  REFERENCES: repo + '/blob/main/docs/REFERENCES.md',
};

export default withMermaid(
  defineConfig({
    title: 'Porch',
    description:
      'Self-hosted identity and single sign-on for families, friend groups and homelabs: OIDC provider, Google federation, RBAC + ABAC, Terraform, encrypted backups.',
    lang: 'en-US',
    // GitHub Pages project site: https://aurimasniekis.github.io/go-porch/
    base: '/go-porch/',
    cleanUrls: true,
    lastUpdated: false,
    srcExclude: ['README.md'],
    head: [['link', { rel: 'icon', type: 'image/svg+xml', href: '/go-porch/logo.svg' }]],
    markdown: {
      theme: { light: 'github-light', dark: 'github-dark' },
      config: (md) => {
        const original = md.renderer.rules.link_open!;
        md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
          const href = tokens[idx].attrGet('href');
          const m = href?.match(/^(?:\.\/)?([A-Z_]+)\.md(#.*)?$/);
          if (m && docPages[m[1]]) {
            const target = docPages[m[1]];
            tokens[idx].attrSet('href', target.startsWith('http') ? target + (m[2] ?? '') : target + (m[2] ?? ''));
          }
          return original(tokens, idx, options, env, self);
        };
      },
    },
    mermaid: {},
    themeConfig: {
      logo: '/logo.svg',
      nav: [
        { text: 'Guide', link: '/guide/what-is-porch' },
        { text: 'Operators', link: '/operators/' },
        { text: 'Security', link: '/security/' },
        { text: 'Reference', link: '/reference/flows' },
      ],
      sidebar: [
        {
          text: 'Guide',
          items: [
            { text: 'What is Porch?', link: '/guide/what-is-porch' },
            { text: 'Concepts', link: '/guide/concepts' },
            { text: 'Signing in', link: '/guide/signing-in' },
            { text: 'Connect an application', link: '/guide/connect-an-app' },
            { text: 'Project status', link: '/guide/status' },
          ],
        },
        {
          text: 'Operators',
          items: [
            { text: 'Overview', link: '/operators/' },
            { text: 'Quickstart', link: '/operators/quickstart' },
            { text: 'Identity providers & domains', link: '/operators/identity-providers' },
            { text: 'Backup login & recovery', link: '/operators/recovery' },
            { text: 'Forward-auth (proxies)', link: '/operators/forward-auth' },
          ],
        },
        {
          text: 'Security',
          items: [
            { text: 'Overview', link: '/security/' },
            { text: 'Threat model', link: '/security/threat-model' },
            { text: 'Decisions (ADRs)', link: '/security/decisions' },
          ],
        },
        {
          text: 'Reference',
          items: [
            { text: 'Flows', link: '/reference/flows' },
            { text: 'Architecture', link: '/reference/architecture' },
            { text: 'Database schema', link: '/reference/schema' },
            { text: 'API boundaries', link: '/reference/api' },
          ],
        },
      ],
      socialLinks: [{ icon: 'github', link: repo }],
      search: { provider: 'local' },
      footer: { message: 'Apache-2.0', copyright: '© 2026 Aurimas Niekis' },
    },
  }),
);
