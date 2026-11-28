/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /src/api/wire/domain/format.mjs
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
 * @fileoverview Slothlet leaf — exposed at self.wire.domain.format; re-exports the codec's formatName from src/lib/names.mjs. Cross-extension callers reach the codec only through this leaf — never a deep import of another extension's lib. The leaf's named export matches its filename, so slothlet's single-export flatten places the codec's own export at the api path — that is what the ext-host's api.add mount needs, where a top-level default export would become the mount node itself (CLDMV/digby#42).
 */

import { formatName } from "../../../lib/names.mjs";

export { formatName as format };
