# Appearance

The pages people see (sign-in, the launcher and their account) can show a landscape behind the sign-in card, a title
of your choice, and a logo for every application. Configure them in the admin UI under **Installation → Appearance**
and on each application's page, or through the API.

## Backgrounds

Backgrounds are off until you add an image provider. Each provider contributes an equal share of one pool of images;
if a provider is unavailable, the others fill its share.

| Provider | What you choose | Credit shown |
| --- | --- | --- |
| **Wikimedia Commons** | a category (default *Featured pictures of landscapes*; also mountains, forests, …) or exact file names | title, author and licence, linked to the file page |
| **Lorem Picsum** | random photos, or photo IDs from [picsum.photos](https://picsum.photos) | photographer, Unsplash License |
| **Your own URLs** | https image URLs | none (make sure you may use the images) |

- **How many and how often:** Porch keeps 1–24 images and picks a new random selection daily, weekly or never.
  **Fetch new images now** refreshes on demand.
- **Rotation:** a random image on every visit, or the same image for everybody all day.
- Portrait images and panoramas wider than 2.6:1 are skipped.

```http
PUT /api/v1/installation/appearance
Content-Type: application/json

{
  "title": "Smith family",
  "background": {
    "providers": [
      { "source": "wikimedia", "category": "Featured pictures of landscapes", "files": [] },
      { "source": "wikimedia", "category": "Featured pictures of mountains", "files": [] },
      { "source": "picsum", "files": [] }
    ],
    "rotation": "visit",
    "count": 9,
    "refresh": "weekly"
  }
}
```

<Shot name="appearance" alt="Appearance settings: image providers and the current background images with credits" caption="Installation → Appearance" />

## Application icons and groups

On an application's page (or in the API: `group` and `icon`), choose:

- **theSVG**: a brand logo from [theSVG](https://thesvg.org), by name (`grafana`) or name and variant (`github/mono`).
- **dashboard-icons**: an icon from the [dashboard-icons](https://dashboardicons.com) set for self-hosted apps
  (`jellyfin`, `immich`, `paperless-ngx`).
- **Image URL**: any https image.
- **Upload**: SVG, PNG, JPEG, GIF or WebP up to 512 KiB.

Without an icon the launcher shows a coloured letter. The **group** (for example *Media* or *Infrastructure*) puts the
application in a launcher section.

Logos are trademarks of their owners; theSVG and dashboard-icons list each logo's licence.

## How images are handled

Porch downloads every image itself, through the same outbound guard as identity providers (public addresses only).
It checks size and dimensions before decoding, and re-encodes photos and raster icons. SVG icons are rewritten from
an allowlist that keeps shapes, colours, gradients and text and drops scripts, event handlers and external
references. Images are stored in the database (so they are part of backups) and served by Porch itself from
`/media/…`. Visitors' browsers never contact Wikimedia, Picsum or the icon sites, and Porch's Content-Security-Policy
does not need any third-party origin. See ADR-0045 in [Decisions](../security/decisions).
