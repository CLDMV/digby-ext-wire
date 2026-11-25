/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/rdata/common.mjs
 */

/**
 * @fileoverview Shared pieces of the rdata codecs: the codec shape and the field checks every encoder runs on its input, so
 * a malformed value is a `WireError` (VALUE_OUT_OF_RANGE) rather than a TypeError.
 */

import { TYPED_ARRAY_TAG, intrinsicBuffer, isSharedBuffer } from "../buffer.mjs";
import { WireErrorCode, fail } from "../errors.mjs";

/**
 * One RR type's codec.
 * @typedef {object} RdataCodec
 * @property {string} name - the type mnemonic
 * @property {(r: import("../buffer.mjs").Reader) => object} decode - read the rdata; the reader is limited to rdlength
 * @property {(w: import("../buffer.mjs").Writer, data: object) => void} encode - write the rdata (without rdlength)
 * @property {(t: import("../text.mjs").Tokens, origin?: string) => object} parse - parse the presentation form
 * @property {(data: object) => string} format - format the presentation form
 */

/**
 * Require a plain object for `data`.
 * @param {unknown} data
 * @param {string} type
 * @returns {Record<string, any>}
 */
export function obj(data, type) {
	if (data === null || typeof data !== "object" || Array.isArray(data)) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${type} rdata must be an object`);
	return data;
}

/**
 * Require a Uint8Array.
 * @param {unknown} v
 * @param {string} what
 * @returns {Uint8Array}
 */
export function bytes(v, what) {
	// every SharedArrayBuffer form first (CLDMV/digby#39, round 9): the brand checks run no caller code, so a bare
	// SharedArrayBuffer and a view over one — from any realm, under any prototype swap — are the NOT_CLONEABLE refusal;
	// the old `instanceof Uint8Array`-first order reported them VALUE_OUT_OF_RANGE, the wrong-type refusal, because a
	// bare or cross-realm SAB fails `instanceof` and a DataView over one is not a Uint8Array at all
	if (isSharedBuffer(intrinsicBuffer(v)) || isSharedBuffer(v))
		fail(WireErrorCode.NOT_CLONEABLE, `${what} is a SharedArrayBuffer or a view over one; it would be read, not copied (CLDMV/digby#39, round 9)`);
	// the type check runs no caller code until the brand getter (CLDMV/digby#39, round 9): ArrayBuffer.isView is an
	// internal-slot read, so a plain object — or a Proxy, which carries no slot of its own — is refused as the wrong
	// type without firing a trap; a real view's Uint8Array-ness comes off the intrinsic TypedArray
	// `Symbol.toStringTag` getter, which verifies the TypedArray slot from any realm and under any prototype swap — a
	// cross-realm Uint8Array is accepted here exactly as decodeMessage and formatGeneric accept its octets, and a
	// DataView wearing Uint8Array.prototype is refused (a DataView slot, not a TypedArray one)
	if (!ArrayBuffer.isView(v)) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} must be a Uint8Array`);
	let tag = null;
	try {
		tag = TYPED_ARRAY_TAG.call(v);
	} catch {}
	if (tag !== "Uint8Array") fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} must be a Uint8Array`);
	return v;
}

/**
 * Require an array.
 * @param {unknown} v
 * @param {string} what
 * @returns {any[]}
 */
export function array(v, what) {
	if (!Array.isArray(v)) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} must be an array`);
	return v;
}

/**
 * Require a string.
 * @param {unknown} v
 * @param {string} what
 * @returns {string}
 */
export function string(v, what) {
	if (typeof v !== "string") fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} must be a string`);
	return v;
}

/**
 * Raise BAD_RDATA.
 * @param {string} msg
 * @param {number} [offset]
 * @returns {never}
 */
export function badRdata(msg, offset) {
	return fail(WireErrorCode.BAD_RDATA, msg, offset);
}
