---
version: 1
slug: "frontend-src"
primary_target: "frontend/src"
related_targets: []
---

# Surface: ThreatWeaver app (all screens under frontend/src)

Mode: Operate. Code-led (app screens; no image generation available).

Audience and job: researchers first, technical home users second, triaging Windows executables: see what needs attention, understand why, act (quarantine, label), and check model evidence.

Constraints: offline only (bundled fonts and icons); real numbers only; never imply real-time protection; preserve every existing page, chart and data source; both themes; reduced motion and reduced transparency respected.

History: replaces the earlier cyan "security console" direction (user judged it not right; asked for Apple minimalism in black and white and a threat web that does not feel static).

## Direction contract

THESIS: Apple-style minimalism in pure black and white: the interface recedes so the few things that matter (a red, orange or violet verdict; a score crossing a threshold) are the only colour on screen. Refuses the security-dashboard default of neon accents, glows and colour-coded everything.

OWN-WORLD: Monochrome. Dark: true black ground, #1c1c1e surfaces, white ink and controls. Light: #f5f5f7 ground, white surfaces, #1d1d1f ink and controls. Pill buttons, 20px card radii, hairlines, soft shadows in light; frosted translucent chrome (sidebar, top bar, palette, drawer) with content scrolling beneath. Colour only for attention verdicts (system red, orange, violet); benign and trusted are greys distinguished by glyph shape. Mona Sans at normal width with size-specific tracking; JetBrains Mono for hashes, paths and numbers. Lucide icons, 1.75 stroke.

STORY: The visitor sees at a glance how many files need attention, opens one, reads score, reason, attribution and indicators together, acts, and explores the latest scan as a living map.

FIRST VIEWPORT: Translucent sidebar left (collapsible to icons), translucent top bar with the Ctrl+K palette trigger and scan status. Overview: large quiet heading with the attention count, verdict tally, the score field over grey threshold zones beside scan activity, then flagged files with a full-width gauge per row. Start a scan as a black/white pill top right.

FORM: Pinned by the user ("make it in apple minimalism and also use black and white theme and make the threat web much more better"); position 1 of 1. Signature interaction: the living threat web: a force-directed graph that blooms out from its folders, can be grabbed, flung, zoomed and focused, with springs and momentum, and neighbourhoods that light up on hover. seed:5c74e452b9396bf9 (rolled after the fact; the user-pinned direction stands and the roll was not followed)

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
