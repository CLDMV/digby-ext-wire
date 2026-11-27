/*
 * @cldmv/digby-ext-wire — the NODE half's root leaf. The ext-host mounts this package's
 * src/api tree at ext.<app>.wire (filename-matches-folder flatten: this file's exports
 * land on the mount root). Sibling leaves reach each other through slothlet's `self` —
 * never by raw import (a raw import is a SECOND module instance outside composition).
 *
 * Storage: none. The wire extension is the DNS wire codec — a pure surface over the plain
 * modules under src/lib (no I/O, no network, node: built-ins only) — so there is no sql/
 * directory, no settings declaration and no setupSettings call.
 */

export const name = "wire";

export function activate(context) {
	// Nothing to capture: the codec has no state, no storage and no commands. activate()
	// exists as the mount point — consumers reach this surface as self.wire.* (captured at
	// entry by the consuming extension's own activate(), since slothlet's `self` is
	// in-call-only). See the leaves under src/api/wire/.
}

export function deactivate() {
	// Nothing auto-disposed; the codec owns no resources.
}
