/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/header.mjs
 */

/**
 * @fileoverview The 12-octet message header (RFC 1035 4.1.1, with AD and CD from RFC 4035 3.2).
 */

import { checkInt } from "./buffer.mjs";
import { WireErrorCode, fail } from "./errors.mjs";

/** The header's size in octets. */
export const HEADER_SIZE = 12;

/**
 * The header flags.
 * @typedef {object} Flags
 * @property {boolean} qr - a response
 * @property {number} opcode - 4 bits
 * @property {boolean} aa - authoritative answer
 * @property {boolean} tc - truncated
 * @property {boolean} rd - recursion desired
 * @property {boolean} ra - recursion available
 * @property {boolean} z - the reserved bit (must be zero; kept so a decode round-trips)
 * @property {boolean} ad - authentic data
 * @property {boolean} cd - checking disabled
 */

/**
 * Unpack the 16-bit flags word.
 * @param {number} word
 * @returns {{ flags: Flags, rcode: number }}
 */
export function unpackFlags(word) {
	return {
		flags: {
			qr: (word & 0x8000) !== 0,
			opcode: (word >>> 11) & 0xf,
			aa: (word & 0x0400) !== 0,
			tc: (word & 0x0200) !== 0,
			rd: (word & 0x0100) !== 0,
			ra: (word & 0x0080) !== 0,
			z: (word & 0x0040) !== 0,
			ad: (word & 0x0020) !== 0,
			cd: (word & 0x0010) !== 0
		},
		rcode: word & 0xf
	};
}

/**
 * Pack flags and the low 4 rcode bits into the flags word. Missing flags are false, a missing opcode is QUERY.
 * @param {Partial<Flags>} [flags]
 * @param {number} [rcodeLow=0]
 * @returns {number}
 */
export function packFlags(flags = {}, rcodeLow = 0) {
	if (flags === null || typeof flags !== "object") fail(WireErrorCode.VALUE_OUT_OF_RANGE, "flags must be an object");
	const opcode = flags.opcode ?? 0;
	checkInt(opcode, 0xf, "opcode");
	checkInt(rcodeLow, 0xf, "rcode");
	return (
		(flags.qr ? 0x8000 : 0) |
		(opcode << 11) |
		(flags.aa ? 0x0400 : 0) |
		(flags.tc ? 0x0200 : 0) |
		(flags.rd ? 0x0100 : 0) |
		(flags.ra ? 0x0080 : 0) |
		(flags.z ? 0x0040 : 0) |
		(flags.ad ? 0x0020 : 0) |
		(flags.cd ? 0x0010 : 0) |
		rcodeLow
	);
}

/** The TC bit in the flags word, for setting it after the fact. */
export const TC_BIT = 0x0200;
