/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /src/api/wire/class/mnemonic.mjs
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
 * @fileoverview Slothlet leaf — exposed at self.wire.class.mnemonic; re-exports the codec's classToString from
 * src/lib/constants.mjs. Cross-extension callers reach the codec only through this leaf — never a
 * deep import of another extension's lib.
 */

import { classToString } from "../../../lib/constants.mjs";

export default classToString;
