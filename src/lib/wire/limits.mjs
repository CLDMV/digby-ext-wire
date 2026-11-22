/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/limits.mjs
 */

/**
 * @fileoverview Per-transport size caps and TCP framing.
 *
 * UDP: a response fits in 512 octets unless the query carried EDNS, in which case it fits in the query's advertised UDP size,
 * capped by our own buffer size (plan §5.4: 1232 by default, the DNS flag day 2020 value), and never below 512 (RFC 6891
 * 6.2.3, 6.2.5). TCP: 65535 octets, each message prefixed with a 2-octet length (RFC 1035 4.2.2, RFC 7766 8).
 */

import { MAX_MESSAGE, asBytes, checkInt } from "./buffer.mjs";
import { WireErrorCode, fail } from "./errors.mjs";
import { encodeCapped } from "./message.mjs";

/** The UDP limit without EDNS (RFC 1035 4.2.1). */
export const UDP_MIN = 512;
/** The default EDNS buffer size we advertise and accept (plan §5.4). */
export const DEFAULT_UDP_CAP = 1232;
/** The TCP limit: the length prefix is 16 bits. */
export const TCP_MAX = MAX_MESSAGE;

/**
 * The size a UDP response to `query` may take.
 *
 * @param {{ edns?: { udpSize: number } | null } | null} query - the decoded query (only its `edns` is read)
 * @param {object} [options]
 * @param {number} [options.cap=1232] - our own EDNS buffer size; values below 512 are raised to 512
 * @returns {number}
 */
export function udpLimit(query, { cap = DEFAULT_UDP_CAP } = {}) {
	checkInt(cap, MAX_MESSAGE, "UDP cap");
	const ours = Math.max(UDP_MIN, cap);
	const theirs = query?.edns ? query.edns.udpSize : UDP_MIN;
	return Math.min(ours, Math.max(UDP_MIN, theirs));
}

/**
 * Encode a response for a transport, truncating to its limit (see {@link encodeCapped} for the rules).
 *
 * @param {object} message - the response
 * @param {object} options
 * @param {"udp"|"tcp"} options.transport
 * @param {object} [options.query] - the query being answered (UDP: its EDNS size sets the limit)
 * @param {number} [options.cap=1232] - UDP: our EDNS buffer size
 * @param {number} [options.limit] - override the computed limit
 * @param {boolean} [options.compress=true]
 * @returns {{ bytes: Uint8Array, truncated: boolean, limit: number }}
 */
export function encodeForTransport(message, { transport, query = null, cap = DEFAULT_UDP_CAP, limit, compress = true }) {
	let max;
	if (limit !== undefined) max = limit;
	else if (transport === "udp") max = udpLimit(query, { cap });
	else if (transport === "tcp") max = TCP_MAX;
	else fail(WireErrorCode.VALUE_OUT_OF_RANGE, `unknown transport "${String(transport)}"`);
	const { bytes, truncated } = encodeCapped(message, { limit: max, compress });
	return { bytes, truncated, limit: max };
}

/**
 * Prefix a message with its 2-octet TCP length.
 * @param {Uint8Array} message
 * @returns {Uint8Array}
 */
export function frameTcp(message) {
	const b = asBytes(message);
	if (b.length > TCP_MAX) fail(WireErrorCode.MESSAGE_TOO_LARGE, `a TCP message is at most ${TCP_MAX} octets`);
	const out = new Uint8Array(b.length + 2);
	out[0] = b.length >>> 8;
	out[1] = b.length & 0xff;
	out.set(b, 2);
	return out;
}

/**
 * Split a TCP byte stream into length-prefixed messages. Incomplete data stays buffered until more arrives; the buffer never
 * holds more than one partial frame (at most 65537 octets) between calls.
 *
 * @example
 * const frames = new TcpFramer();
 * socket.on("data", (chunk) => { for (const msg of frames.push(chunk)) handle(msg); });
 */
export class TcpFramer {
	constructor() {
		/** @type {Uint8Array} */
		this.pending = new Uint8Array(0);
	}

	/**
	 * Add received octets; return every message they complete.
	 * @param {Uint8Array} chunk
	 * @returns {Uint8Array[]}
	 */
	push(chunk) {
		const add = asBytes(chunk);
		let buf;
		if (this.pending.length === 0) buf = add;
		else {
			buf = new Uint8Array(this.pending.length + add.length);
			buf.set(this.pending);
			buf.set(add, this.pending.length);
		}
		const out = [];
		let pos = 0;
		while (buf.length - pos >= 2) {
			const len = (buf[pos] << 8) | buf[pos + 1];
			if (buf.length - pos - 2 < len) break;
			out.push(buf.slice(pos + 2, pos + 2 + len));
			pos += 2 + len;
		}
		this.pending = buf.slice(pos);
		return out;
	}

	/** Octets held for an incomplete frame. */
	get buffered() {
		return this.pending.length;
	}
}
