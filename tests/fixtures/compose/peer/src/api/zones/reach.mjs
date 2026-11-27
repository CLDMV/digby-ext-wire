/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /tests/fixtures/compose/peer/src/api/zones/reach.mjs
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
 * @fileoverview The refusal half of the compose suite's cross-extension test (CLDMV/digby#42 A2): it reaches
 * wire.activate — a lifecycle leaf wire never publishes (the lifecycle is the host's) — which rummage's
 * default-deny policy must refuse even though the caller is a composed extension.
 */

import { self } from "@cldmv/rummage/runtime";

/** Reach wire.activate — never public — which the policy must refuse. */
export function reach() {
	return self.ext.digby.wire.activate();
}
