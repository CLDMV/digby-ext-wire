/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /src/api/wire/limits/name.mjs
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
 * @fileoverview Slothlet leaf — exposed at self.wire.limits.name; answers the codec's MAX_NAME from src/lib/names.mjs. Cross-extension callers reach the codec only through this leaf — never a deep import of another extension's lib. The leaf's named export matches its filename, so slothlet's single-export flatten places the codec's own export at the api path (CLDMV/digby#42). Data composes as a zero-arg leaf function returning the frozen table or constant (CLDMV/digby#42 A1: an object export composes as a namespace wrapper — the table itself is not what a caller reads back).
 */

import { MAX_NAME } from "../../../lib/names.mjs";

export function name() {
	return MAX_NAME;
}
