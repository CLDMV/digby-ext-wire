/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /rummage.manifest.mjs
 */

/*
 * THE manifest — rummage discovers this package by this file's PRESENCE and reads
 * its default export. Almost everything is derived, so this stays small:
 *
 *   id / slug     from the package name        version   from package.json
 *   main          from package.json `main`     browser   the "./view" exports subpath
 *   activationEvents  defaults to ["onStartup"]
 *   contributes   auto-loaded from rummage.manifest.jsonv when that file exists
 *   displayName / description  from <i18n.prefix>.displayName / .description
 *
 * THE SECTIONAL LAYOUT (every extension, and any separable core section, uses it):
 *   src/api/wire/    node slothlet leaves — the ext-host mounts them at
 *                       ext.<app>.wire.*; siblings reach each other via `self`
 *   src/lib/            internal shared code (the codec itself — plain modules)
 *
 * Declare only what rummage cannot know:
 *   protocol.version   which extension protocol this targets (absent FAILS CLOSED)
 *   i18n.prefix        your app's i18n namespace; {slug} is expanded
 *   required           true if the user must not be able to disable it
 *   platforms          ["desktop"] etc. — omit to activate everywhere
 *   requires           EXTENSION package names the loader mounts and activates BEFORE this one
 */

export default {
	protocol: { version: "1.0" },
	i18n: { prefix: "wire" }
};
