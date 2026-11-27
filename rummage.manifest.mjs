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
 *   public             mount-relative leaf paths other extensions may call (rummage composes
 *                      default-deny: without an entry a peer's self.<mount>.<leaf> call is refused)
 */

// The whole codec surface is public — wire is a pure library extension with no state, no settings and no
// lifecycle a peer could disturb, so every leaf a consumer (zones, server) may reach is published here, and
// nothing else is: the root's activate/deactivate stay the host's. A peer reaching an unpublished leaf is
// refused with PERMISSION_DENIED; an entry that does not resolve on the composed tree is a load error, so the
// list cannot silently drift from the api tree (tests/compose.test.vitest.mjs asserts both halves).
export default {
	protocol: { version: "1.0" },
	i18n: { prefix: "wire" },
	public: [
		// messages
		"decode",
		"encode",
		"encodeCapped",
		// transports
		"transport.encode",
		"transport.limit",
		"transport.udp.min",
		"transport.udp.cap",
		"tcp.frame",
		"tcp.max",
		// framer
		"framer.create",
		// records, ttl, rdata
		"record.parse",
		"record.format",
		"ttl.parse",
		"rdata.parse",
		"rdata.format",
		"rdata.encode",
		"rdata.decode",
		"rdata.generic",
		// names
		"domain.parse",
		"domain.format",
		"domain.canonical",
		"domain.key",
		"domain.equal",
		"domain.count",
		// mnemonics
		"type.mnemonic",
		"type.parse",
		"class.mnemonic",
		"class.parse",
		// tsig
		"tsig.append",
		"tsig.size",
		// constants, limits, errors — the data leaves are zero-arg functions
		"constants.type",
		"constants.class",
		"constants.rcode",
		"constants.opcode",
		"constants.edns.option",
		"constants.svc.key",
		"limits.message",
		"limits.label",
		"limits.name",
		"limits.name.octets",
		"errors.WireError",
		"errors.codes"
	]
};
