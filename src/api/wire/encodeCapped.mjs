/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /src/api/wire/encodeCapped.mjs
 *	@Date: 2026-11-26T00:00:00-08:00
 *	@Author: Nate Corcoran <CLDMV>
 *	@Email: <Shinrai@users.noreply.github.com>
 *	-----
 *	@Last modified by: Nate Corcoran <CLDMV> (Shinrai@users.noreply.github.com)
 *	@Last modified time: 2026-11-26T00:00:00-08:00
 *	-----
 *	@Copyright: Copyright (c) 2013-2026 Catalyzed Motivation Inc. All rights reserved.
 *
 */

/**
 * @fileoverview Slothlet leaf — exposed at self.wire.encodeCapped; re-exports the codec's encodeCapped from
 * src/lib/message.mjs. Cross-extension callers reach the codec only through this leaf — never a
 * deep import of another extension's lib.
 */

import { encodeCapped } from "../../lib/message.mjs";

export default encodeCapped;
