<script setup lang="ts">
// A random landscape from Wikimedia Commons ("Featured pictures of landscapes", openly licensed) behind the home
// hero, with its credit. The same source Porch offers for its sign-in page (ADR-0045). Nothing is shown if the API
// is unreachable.
import { onMounted, ref } from 'vue';

interface Background {
  url: string;
  title: string;
  author: string;
  license: string;
  page: string;
}

const API = 'https://commons.wikimedia.org/w/api.php?origin=*&format=json&action=query';
const CATEGORY = 'Category:Featured pictures of landscapes';
const bg = ref<Background | null>(null);

function text(html: string | undefined): string {
  return new DOMParser().parseFromString(html ?? '', 'text/html').body.textContent?.replace(/\s+/g, ' ').trim() ?? '';
}

onMounted(async () => {
  try {
    const list = await (
      await fetch(`${API}&list=categorymembers&cmtype=file&cmlimit=500&cmtitle=${encodeURIComponent(CATEGORY)}`)
    ).json();
    const files: string[] = (list?.query?.categorymembers ?? [])
      .map((m: { title: string }) => m.title)
      .filter((t: string) => /\.jpe?g$/i.test(t));
    for (let i = files.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [files[i], files[j]] = [files[j], files[i]];
    }
    const info = await (
      await fetch(
        `${API}&prop=imageinfo&iiprop=url|size|extmetadata&iiurlwidth=1920&titles=${encodeURIComponent(files.slice(0, 12).join('|'))}`,
      )
    ).json();
    for (const page of Object.values(info?.query?.pages ?? {}) as any[]) {
      const ii = page.imageinfo?.[0];
      const meta = ii?.extmetadata ?? {};
      const license = text(meta.LicenseShortName?.value);
      if (!ii?.thumburl || ii.width < ii.height || !license) continue;
      bg.value = {
        url: ii.thumburl,
        title: text(meta.ObjectName?.value) || page.title.replace(/^File:/, '').replace(/\.jpe?g$/i, ''),
        author: text(meta.Artist?.value),
        license,
        page: ii.descriptionurl,
      };
      return;
    }
  } catch {
    // No background: the page looks as before.
  }
});
</script>

<template>
  <div v-if="bg" class="pc-hero-bg" :style="{ backgroundImage: `url(${JSON.stringify(bg.url)})` }">
    <a class="pc-hero-credit" :href="bg.page" target="_blank" rel="noopener">
      {{ bg.title }}<template v-if="bg.author"> · {{ bg.author }}</template> · {{ bg.license }}
    </a>
  </div>
</template>
