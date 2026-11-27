/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /src/api/wire/errors/WireError.mjs
 *	@Date: 2026-11-26T00:00:00-08:00
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
 * @fileoverview Slothlet leaf — exposed at self.wire.errors.WireError; re-exports the codec's WireError from src/lib/errors.mjs. Callers construct it for their own refusals and catch the codec's by `code` (a composed instance is a separate module copy, so instanceof across the boundary is not the contract). The leaf's named export matches its filename, so slothlet's single-export flatten places the codec's own export at the api path — that is what the ext-host's api.add mount needs, where a top-level default export would become the mount node itself (CLDMV/digby#42).
 */

export { WireError } from "../../../lib/errors.mjs";
