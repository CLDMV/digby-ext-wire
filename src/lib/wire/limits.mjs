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

import { MAX_MESSAGE, asBytes, checkInt, cloneOptions } from "./buffer.mjs";
import { WireErrorCode, describe, fail } from "./errors.mjs";
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
export function udpLimit(query, options) {
	// the options are guarded like every other argument (CLDMV/digby#39)
	const o = cloneOptions(options, "the udpLimit options");
	checkInt(o.cap ?? DEFAULT_UDP_CAP, MAX_MESSAGE, "UDP cap");
	const ours = Math.max(UDP_MIN, o.cap ?? DEFAULT_UDP_CAP);
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
 * @throws {WireError} TSIG_PRESENT when the message already carries a TSIG record: truncating it would invalidate the MAC —
 *   encode unsigned (see {@link encodeCapped}'s `reserveTsig`), sign, then appendTsig (CLDMV/digby#39);
 *   TRUNCATION_REFUSED when truncating would corrupt the message's meaning (an UPDATE, or a question of type AXFR/IXFR —
 *   CLDMV/digby#43)
 */
export function encodeForTransport(message, options) {
	// the options are guarded like every other argument (CLDMV/digby#39): null and undefined mean "no options", and the
	// copy — the query included — is read exactly once
	const o = cloneOptions(options, "the encodeForTransport options");
	const transport = o.transport;
	const query = o.query ?? null;
	const cap = o.cap ?? DEFAULT_UDP_CAP;
	const limit = o.limit;
	const compress = o.compress ?? true;
	let max;
	if (limit !== undefined) max = limit;
	else if (transport === "udp") max = udpLimit(query, { cap });
	else if (transport === "tcp") max = TCP_MAX;
	// described, never String()ed — a hostile transport must not break the refusal itself (CLDMV/digby#39)
	else fail(WireErrorCode.VALUE_OUT_OF_RANGE, `unknown transport ${describe(transport)}`);
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
 * holds more than one partial frame (at most 65537 octets) between calls. Once a frame's length prefix is known, a buffer is
 * started at the size of what has actually arrived (a small floor) and doubles up to the frame's declared length as the rest
 * arrives — so a frame delivered one octet at a time stays amortised-linear (one copy per octet, plus the doubling copies),
 * and a stalled frame pins kilobytes, not its full 64 KB. Completed frames are always a fresh buffer: a copy of the caller's
 * chunk, never a view into it, and never framer state a later push would overwrite.
 *
 * @example
 * const frames = new TcpFramer();
 * socket.on("data", (chunk) => { for (const msg of frames.push(chunk)) handle(msg); });
 */
export class TcpFramer {
	constructor() {
		/** Prefix octets of the next frame held so far (0 or 1 of the 2 the length needs). @type {Uint8Array} */
		this.prefix = new Uint8Array(0);
		/** The frame being filled, once its length prefix is known; null until then. @type {Uint8Array|null} */
		this.frame = null;
		/** The frame's declared length from its prefix. */
		this.len = 0;
		/** Payload octets already copied into {@link TcpFramer#frame}. */
		this.filled = 0;
		/** Allocated size of {@link TcpFramer#frame}; grows by doubling up to {@link TcpFramer#len}. */
		this.cap = 0;
	}

	/**
	 * Add received octets; return every message they complete.
	 * @param {Uint8Array} chunk
	 * @returns {Uint8Array[]}
	 */
	push(chunk) {
		const add = asBytes(chunk);
		const out = [];
		let pos = 0;
		// A frame whose length is known continues with whatever this chunk starts with.
		if (this.frame !== null) {
			pos = this.#fill(add, 0, out);
		} else if (this.prefix.length === 1 && add.length > 0) {
			// one held prefix octet plus the chunk's first octet complete the length prefix
			this.#begin((this.prefix[0] << 8) | add[0], add.length + 1);
			pos = this.#fill(add, 1, out);
		}
		// Whole frames contained in the rest of the chunk: one exact-size copy each.
		while (add.length - pos >= 2) {
			const len = (add[pos] << 8) | add[pos + 1];
			if (add.length - pos - 2 < len) break;
			out.push(add.slice(pos + 2, pos + 2 + len));
			pos += 2 + len;
		}
		// Whatever remains is the start of one frame: either a lone prefix octet, or a known length to start filling.
		const rest = add.length - pos;
		if (rest > 0) {
			if (rest === 1) this.prefix = add.slice(pos, pos + 1);
			else {
				this.#begin((add[pos] << 8) | add[pos + 1], rest);
				this.#fill(add, pos + 2, out);
			}
		}
		return out;
	}

	/**
	 * Start a frame of `len` octets, `received` of which (prefix included) have already arrived. The buffer holds only what
	 * has arrived — a small floor at first — and doubles up to `len` as the rest arrives, so a stalled frame pins kilobytes,
	 * not its full 64 KB (segment sizes are client-controlled; 2,000 connections each stalling after the prefix would
	 * otherwise pin ~131 MB).
	 * @param {number} len - the frame's declared length
	 * @param {number} received - frame octets (prefix included) received so far
	 */
	#begin(len, received) {
		this.len = len;
		this.cap = Math.min(len, Math.max(4096, received));
		this.frame = new Uint8Array(this.cap);
		this.filled = 0;
		this.prefix = new Uint8Array(0);
	}

	/**
	 * Copy `add[start..]` into the frame being filled, doubling the buffer when it runs out of room, and completing and
	 * emitting the frame when full.
	 * @param {Uint8Array} add - the chunk being pushed
	 * @param {number} start - the offset in `add` where the frame's next payload octet sits
	 * @param {Uint8Array[]} out - completed frames are pushed here
	 * @returns {number} the offset in `add` after the octets consumed
	 */
	#fill(add, start, out) {
		let pos = start;
		while (this.frame !== null && pos < add.length && this.filled < this.len) {
			if (this.filled === this.cap) {
				this.cap = Math.min(this.len, this.cap * 2);
				const grown = new Uint8Array(this.cap);
				grown.set(this.frame.subarray(0, this.filled));
				this.frame = grown;
			}
			const take = Math.min(this.cap - this.filled, add.length - pos);
			this.frame.set(add.subarray(pos, pos + take), this.filled);
			this.filled += take;
			pos += take;
		}
		if (this.frame !== null && this.filled === this.len) {
			out.push(this.frame);
			this.frame = null;
			this.filled = 0;
			this.cap = 0;
		}
		return pos;
	}

	/** Octets held for an incomplete frame. */
	get buffered() {
		return this.prefix.length + (this.frame !== null ? 2 + this.filled : 0);
	}

	/**
	 * Diagnostic: octets currently allocated for the frame being filled (0 when no frame is in flight). Starts at a small
	 * floor regardless of the declared length and doubles up to that length as payload arrives, so a stalled connection does
	 * not pin the full frame size.
	 */
	get capacity() {
		return this.cap;
	}
}
