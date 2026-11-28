/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /src/api/wire/errors/is.mjs
 *	@Date: 2026-11-27T00:00:00-08:00
 *	@Author: Nate Corcoran <CLDMV>
 *	@Email: <Shinrai@users.noreply.github.com>
 *	-----
 *	@Last modified by: Nate Corcoran <CLDMV> (Shinrai@users.noreply.github.com)
 *	@Last modified time: 2026-11-27T00:00:00-08:00
 *	-----
 *	@Copyright: Copyright (c) 2013-2026 Catalyzed Motivation Inc. All rights reserved.
 *
 */

/**
 * @fileoverview Slothlet leaf — exposed at self.wire.errors.is; answers whether an error is the codec's WireError. The
 * class itself stays lib-internal: rummage's own-leaf check sanitizes WireError.mjs to `wireError` while slothlet
 * composes it as `WireError`, so a class leaf cannot be published at all (CLDMV/rummage#1100 — wire refused to load in
 * any rummage host), and `instanceof` is false across the composed boundary anyway (a composed instance is a separate
 * module copy — CLDMV/digby#42 D). The predicate compares by the error's own identity instead: the real brand when the
 * caller is inside this module graph, the name-plus-code shape otherwise — an error another module copy re-threw
 * (zones' master-file decorator) included. The leaf's named export matches its filename, so slothlet's single-export
 * flatten places the codec's own export at the api path (CLDMV/digby#42).
 */

import { WireError } from "../../../lib/errors.mjs";

/**
 * Is this a {@link WireError} — the codec's own, or a re-thrown one carrying its shape?
 * @param {unknown} err
 * @returns {boolean}
 */
export function is(err) {
	return err instanceof WireError || (err?.name === "WireError" && typeof err?.code === "string");
}
