// Adapted from Pulse site/.vitepress/theme/index.ts (Apache-2.0, same author).
import DefaultTheme from 'vitepress/theme';
import type { Theme } from 'vitepress';
import { h } from 'vue';

import HeroBackground from './HeroBackground.vue';
import Shot from './Shot.vue';
import './custom.css';

export default {
  extends: DefaultTheme,
  Layout: () => h(DefaultTheme.Layout, null, { 'home-hero-before': () => h(HeroBackground) }),
  enhanceApp({ app }) {
    app.component('Shot', Shot);
  },
} satisfies Theme;
