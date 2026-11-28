/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /src/api/wire/framer/create.mjs
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
 * @fileoverview Slothlet leaf — exposed at self.wire.framer.create; a FACTORY over the codec's TcpFramer
 * (src/lib/limits.mjs). TcpFramer is stateful — it buffers a partial length prefix and the frame being filled across
 * pushes — so callers never share one instance: they call this factory per stream and feed each connection's octets to
 * its own framer. The leaf's named export matches its filename, so slothlet's single-export flatten places the factory
 * at the api path (CLDMV/digby#42).
 */

import { TcpFramer } from "../../../lib/limits.mjs";

/** @returns {TcpFramer} a fresh, empty framer for one TCP stream. */
export function create() {
	return new TcpFramer();
}
