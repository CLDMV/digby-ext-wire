/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/edns.mjs
 */

/**
 * @fileoverview EDNS(0) (RFC 6891): the OPT pseudo-record's fields and its options. Typed options: cookie (RFC 7873),
 * tcp-keepalive (RFC 7828), padding (RFC 7830) and extended DNS error (RFC 8914). Any other option passes through raw.
 *
 * Option shapes:
 * - cookie `{ code: 10, client: Uint8Array(8), server: Uint8Array(8..32) | null }`
 * - tcp-keepalive `{ code: 11, timeout: number | null }` (units of 100 ms; null when absent, as in a query)
 * - padding `{ code: 12, length }` (the content is not kept: padding octets are zero on encode and ignored on decode)
 * - extended-error `{ code: 15, infoCode, extraText }` (extraText decoded as UTF-8, invalid sequences replaced)
 * - anything else `{ code, data: Uint8Array }`; `data` also forces a raw encoding for a typed code
 */

import { checkInt } from "./buffer.mjs";
import { EDNS_OPTION } from "./constants.mjs";
import { WireErrorCode, fail } from "./errors.mjs";
import { array, bytes, obj, string } from "./rdata/common.mjs";

const badOption = (msg, offset) => fail(WireErrorCode.BAD_OPTION, msg, offset);
const utf8Lossy = new TextDecoder("utf-8");
const utf8 = new TextEncoder();

/**
 * Read the options to the end of the reader (the OPT rdata).
 * @param {import("./buffer.mjs").Reader} r
 * @returns {object[]}
 */
export function readOptions(r) {
	const options = [];
	while (r.remaining > 0) {
		const at = r.pos;
		const code = r.u16();
		const len = r.u16();
		if (len > r.remaining) fail(WireErrorCode.TRUNCATED, `option ${code} claims ${len} octets, ${r.remaining} left`, at);
		options.push(r.limit(len, () => readOption(code, len, r, at), WireErrorCode.BAD_OPTION));
	}
	return options;
}

function readOption(code, len, r, at) {
	switch (code) {
		case EDNS_OPTION.COOKIE:
			if (len === 8) return { code, client: r.take(8), server: null };
			if (len >= 16 && len <= 40) return { code, client: r.take(8), server: r.rest() };
			return badOption(`a cookie option is 8 or 16 to 40 octets, got ${len}`, at);
		case EDNS_OPTION.TCP_KEEPALIVE:
			if (len === 0) return { code, timeout: null };
			if (len === 2) return { code, timeout: r.u16() };
			return badOption(`a tcp-keepalive option is 0 or 2 octets, got ${len}`, at);
		case EDNS_OPTION.PADDING:
			r.pos = r.end;
			return { code, length: len };
		case EDNS_OPTION.EXTENDED_ERROR: {
			if (len < 2) return badOption(`an extended-error option is at least 2 octets, got ${len}`, at);
			const infoCode = r.u16();
			return { code, infoCode, extraText: utf8Lossy.decode(r.rest()) };
		}
		default:
			return { code, data: r.rest() };
	}
}

/**
 * Write options.
 * @param {import("./buffer.mjs").Writer} w
 * @param {object[]} options
 */
export function writeOptions(w, options) {
	for (const o of array(options, "EDNS options")) {
		obj(o, "an EDNS option");
		checkInt(o.code, 0xffff, "option code");
		w.u16(o.code);
		const lenAt = w.length;
		w.u16(0);
		writeOption(w, o);
		w.patch16(lenAt, w.length - lenAt - 2);
	}
}

function writeOption(w, o) {
	if (o.data !== undefined) {
		w.raw(bytes(o.data, "option data"));
		return;
	}
	switch (o.code) {
		case EDNS_OPTION.COOKIE: {
			if (bytes(o.client, "cookie client").length !== 8) badOption("a client cookie is 8 octets");
			w.raw(o.client);
			if (o.server !== null && o.server !== undefined) {
				const n = bytes(o.server, "cookie server").length;
				if (n < 8 || n > 32) badOption(`a server cookie is 8 to 32 octets, got ${n}`);
				w.raw(o.server);
			}
			return;
		}
		case EDNS_OPTION.TCP_KEEPALIVE:
			if (o.timeout !== null && o.timeout !== undefined) w.u16(o.timeout);
			return;
		case EDNS_OPTION.PADDING:
			checkInt(o.length, 0xffff, "padding length");
			w.raw(new Uint8Array(o.length));
			return;
		case EDNS_OPTION.EXTENDED_ERROR:
			w.u16(o.infoCode);
			w.raw(utf8.encode(string(o.extraText ?? "", "extended-error text")));
			return;
		default:
			return badOption(`option ${o.code} has no typed form; give it as { code, data }`);
	}
}

/**
 * The EDNS fields carried in an OPT record's class and TTL.
 * @typedef {object} Edns
 * @property {number} udpSize - the sender's UDP payload size (the OPT class)
 * @property {number} version - EDNS version (0)
 * @property {boolean} dnssecOk - the DO bit
 * @property {number} z - the other 15 flag bits, normally 0
 * @property {object[]} options
 */

/**
 * Split an OPT record's TTL into the extended rcode bits and the flags.
 * @param {number} ttl
 * @returns {{ extendedRcode: number, version: number, dnssecOk: boolean, z: number }}
 */
export function splitOptTtl(ttl) {
	return { extendedRcode: ttl >>> 24, version: (ttl >>> 16) & 0xff, dnssecOk: (ttl & 0x8000) !== 0, z: ttl & 0x7fff };
}

/**
 * Build an OPT record's TTL.
 * @param {number} extendedRcode - the upper 8 bits of the 12-bit rcode
 * @param {Edns} edns
 * @returns {number}
 */
export function joinOptTtl(extendedRcode, edns) {
	checkInt(edns.version ?? 0, 0xff, "EDNS version");
	checkInt(edns.z ?? 0, 0x7fff, "EDNS z flags");
	return ((extendedRcode << 24) | ((edns.version ?? 0) << 16) | (edns.dnssecOk ? 0x8000 : 0) | (edns.z ?? 0)) >>> 0;
}
