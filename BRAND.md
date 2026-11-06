# OpenMikroRout — visual identity

OpenMikroRout is a lightweight Linux router with a compact, WinBox-inspired web console.
Write the product name exactly **OpenMikroRout**: capital O, M and R; no spaces.
The interface uses the supporting label “OPEN NETWORK ROUTER”.

## Selected application mark

The selected symbol is **Folded Route**: a continuous metallic-blue ribbon that
folds into an open angular loop, crosses its centre and exits towards the upper
right. It represents an open network and packet forwarding. The near-black navy
background, silver-blue faces and deep-blue folded planes retain the application
palette. The user-selected PNG is copied unchanged into the project; it is not
traced, redrawn, cropped or regenerated during integration.

The original concept was made with the built-in imagegen tool. Its final prompt is
preserved in [FOLDED-ROUTE-PROMPT.md](app/static/brand-options/FOLDED-ROUTE-PROMPT.md). The selected
attachment is the application master; it is a raster asset, not an SVG master.

| Asset                                                     | Purpose                                                                         |
| --------------------------------------------------------- | ------------------------------------------------------------------------------- |
| [app/static/logo.png](app/static/logo.png)                | User-selected Folded Route; shared by sidebar, overview, login and browser icon |
| `brandMarkup()` in [app/static/app.js](app/static/app.js) | HTML wordmark and supporting label                                              |
| [app/static/style.css](app/static/style.css)              | Matte navy navigation with a light workspace and readable controls              |

Images use an accessible OpenMikroRout name. Preserve the PNG's square proportions
and internal spacing. The displayed logo uses a 30% corner radius at every size,
matching the user's rounded-square reference. Use the full wordmark where space allows and the symbol alone
for the browser icon. All runtime image references point to the same local PNG,
so the browser can reuse the downloaded image. Versioned asset URLs refresh the
previous logo after an application reload. The current image URL is `/logo.png?v=5`.

The older [logo.svg](app/static/logo.svg) and [favicon.svg](app/static/favicon.svg)
remain as historical routing-hub artwork; the application uses the selected PNG.

## Palette

| Role                 | Colours in the source artwork                         |
| -------------------- | ----------------------------------------------------- |
| Sidebar              | Matte navy `#162D43`, selected blue `#294D70`         |
| Workspace and panels | Almost white `#F5F7F9`, white `#FFFFFF`               |
| Workspace actions    | Green `#237D69`, darker hover `#1A6958`               |
| Workspace text       | Dark `#21343D`, secondary `#3E5660`, muted `#52656D`  |
| Sidebar text         | Cool silver-blue and pale blue highlights             |
| Semantic status      | Separate green success, amber warnings and red errors |

The final user choice keeps blue on the logo and left navigation. The right
workspace, tables, forms, WinBox-style tabs, dialogs and login use matte light
surfaces with stronger dark text and the familiar green actions. Decorative
gradients and glossy card shadows are removed. Dense tables and editor layout
retain their existing WinBox-inspired structure. Network graphs distinguish RX
with green and TX with a steel-coloured dashed line.

UI typography uses native system fonts. No external font or image service is required
for normal application use.

The login screen uses a matte navy brand panel and a light form with the same green
primary action as the workspace. On narrow screens the brand becomes a compact
header. Username, password and optional 2FA/recovery-code fields remain available;
password visibility, keyboard focus, loading feedback and authentication errors
have explicit accessible states. Decorative network lines remain static.

## Additional logo directions

The initial six SVG directions were rejected during visual review. They remain
available in [the first-round gallery](app/static/brand-options/round-1.html),
including their 16, 24 and 32 pixel sizes. These remain exploration assets.

| Option            | SVG                                                                 | Concept                                        |
| ----------------- | ------------------------------------------------------------------- | ---------------------------------------------- |
| 01 · Open Route   | [01-open-route.svg](app/static/brand-options/01-open-route.svg)     | Open network loop with an outgoing route       |
| 02 · Route Switch | [02-route-switch.svg](app/static/brand-options/02-route-switch.svg) | Two traffic directions and packet forwarding   |
| 03 · Network M    | [03-network-m.svg](app/static/brand-options/03-network-m.svg)       | An M formed by connected interface paths       |
| 04 · Router Wave  | [04-router-wave.svg](app/static/brand-options/04-router-wave.svg)   | Router ports and wireless coverage             |
| 05 · Open Gateway | [05-open-gateway.svg](app/static/brand-options/05-open-gateway.svg) | Open gateway with a route passing through it   |
| 06 · Link Fabric  | [06-link-fabric.svg](app/static/brand-options/06-link-fabric.svg)   | Interconnected links forming a compact network |

The alternatives continue the cyan/mint palette and dark rounded surface. All are
native vector artwork with accessible titles and no external assets or scripts.

### Dark-blue abstract G concepts

An exploration round used **dark navy blue** as the main colour, followed by
abstract interpretations of the letter G. The
[archived G gallery](app/static/brand-options/index.html) at `/brand-options/` shows:

- [11 · G Fold](app/static/brand-options/navy/11-g-fold.png): folded planes and
  negative space suggesting G.
- [12 · G Flow](app/static/brand-options/navy/12-g-flow.png): three independent
  flowing planes with a looser hint of G.

Both are 1254 × 1254 raster PNG concepts created with the built-in imagegen tool,
with 32 and 64 pixel previews in the gallery. They are not vector masters. Their
style reference was the generated [literal G study](app/static/brand-options/navy/10-navy-g.png).
The full final prompts and generation method are saved in
[ABSTRACT-G-PROMPTS.md](app/static/brand-options/navy/ABSTRACT-G-PROMPTS.md).

Earlier dark-blue routing concepts 07–09 are preserved in
[the navy gallery](app/static/brand-options/navy/index.html), with their
[prompts](app/static/brand-options/navy/PROMPTS.md). The literal G study also has
[its own prompt](app/static/brand-options/navy/G-PROMPT.md).

The blue direction was informed by the user's MikroTik/WinBox colour reference
and the [official WinBox page](https://mikrotik.com/winbox). The palette
`#07111F`, `#17375E`, `#244C78`, `#4779AC` and `#B9D2EC` is our interpretation,
not an official MikroTik brand specification. These are original OpenMikroRout
concepts; the official MikroTik logo is not used.

## Public references inspected

Only public repository material was used for visual direction:

- [27G-StorageS3 brand mark](https://github.com/gadmin2151/27G-StorageS3/blob/master/web/brand-mark.png).
- [Finora brand description](https://github.com/gadmin2151/Finora/blob/main/BRAND.md)
  and [public application icon](https://github.com/gadmin2151/Finora/blob/main/web/public/finora-icon.png).
- [AmberGate SVG logo](https://github.com/gadmin2151/ambergate/blob/main/docs/logo.svg).

These references informed the polished dark-surface, geometric product-identity direction.
The selected OpenMikroRout mark uses the Folded Route ribbon silhouette. No private repositories were
accessed for this branding work, and none of the referenced artwork is bundled as
an OpenMikroRout application asset.
