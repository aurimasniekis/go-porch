<script setup lang="ts">
// Adapted from Pulse site/.vitepress/theme/Shot.vue (Apache-2.0, same author).
import { withBase } from 'vitepress';

// A screenshot from public/screenshots (scripts/screenshots.sh): a -light and a -dark capture that follow the site
// theme.
defineProps<{ name: string; alt: string; caption?: string }>();
</script>

<template>
  <figure class="pc-shot">
    <img class="pc-light" :src="withBase(`/screenshots/${name}-light.png`)" :alt="alt" loading="lazy" />
    <img class="pc-dark" :src="withBase(`/screenshots/${name}-dark.png`)" :alt="alt" loading="lazy" />
    <figcaption v-if="caption">{{ caption }}</figcaption>
  </figure>
</template>
