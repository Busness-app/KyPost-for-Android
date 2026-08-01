# KyPost for Android

KyPost for Android is an Android email client backed by a self-hosted KyPost relay, with keyword-based inbox tabs and two-way contact sync authenticated through native-push pairing. See [app/AGENTS.md](app/AGENTS.md).

For any UI/theming/visual work, read [STYLE_GUIDE.md](STYLE_GUIDE.md) first — it defines
how this app's look should align with the sibling web app (`../llama labels/frontend`)
while staying native Android, and is binding for colors, shape, typography, and
component patterns.

# Ponytail, lazy senior dev mode

Use the smallest correct change.

1. Reuse what already exists.
2. Prefer stdlib and native platform APIs.
3. Add dependencies only when they remove meaningful code.
4. Fix shared root causes, not one caller.
5. If a shortcut has a limit, mark it with `ponytail:` and name the upgrade path.

Non-trivial logic must include one runnable check (unit test or minimal self-check).

# DOX framework

## Core Contract

- AGENTS.md files are binding contracts for their subtree.
- Read from root to nearest AGENTS.md before editing.
- The nearest AGENTS.md controls local details; parent docs keep global rules.

## Update After Editing

- Run a DOX pass for every meaningful change.
- Update nearest owning AGENTS.md when behavior, responsibilities, or verification changes.
- Keep Child DOX Index entries current and delete stale rules.

## User Preferences

- Best-effort 90-second keyword refresh policy (foreground cadence; background catch-up on resume).
- DOX hierarchy scope is app-only.

## Child DOX Index

- `app/` — Android application module, runtime code, resources, tests, and app-level verification contracts. See [app/AGENTS.md](app/AGENTS.md).
