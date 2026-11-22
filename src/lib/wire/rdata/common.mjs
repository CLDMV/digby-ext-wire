/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/rdata/common.mjs
 */

/**
 * @fileoverview Shared pieces of the rdata codecs: the codec shape and the field checks every encoder runs on its input, so
 * a malformed value is a `WireError` (VALUE_OUT_OF_RANGE) rather than a TypeError.
 */

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
	if (!(v instanceof Uint8Array)) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} must be a Uint8Array`);
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
