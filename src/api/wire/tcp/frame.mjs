/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /src/api/wire/tcp/frame.mjs
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
 * @fileoverview Slothlet leaf — exposed at self.wire.tcp.frame; re-exports the codec's frameTcp from src/lib/limits.mjs. Cross-extension callers reach the codec only through this leaf — never a deep import of another extension's lib. The leaf's named export matches its filename, so slothlet's single-export flatten places the codec's own export at the api path (CLDMV/digby#42).
 */

import { frameTcp } from "../../../lib/limits.mjs";

export { frameTcp as frame };