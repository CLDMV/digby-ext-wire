/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /tests/fixtures/compose/peer/src/api/zones/probe.mjs
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
 * @fileoverview A minimal second extension's public-reaching leaf for the compose suite's cross-extension test
 * (CLDMV/digby#42 A2): composed alongside wire under rummage's default-deny policy (rules derived from wire's
 * manifest `public` list), it reaches wire only through `self` — exactly how a consumer (zones, server) calls the
 * codec. One leaf per file, the api leaf's named export matching its filename.
 */

import { self } from "@cldmv/rummage/runtime";

/** Call the public wire.decode through the composed api, as a peer would. */
export function probe(bytes) {
	return self.ext.digby.wire.decode(bytes);
}
