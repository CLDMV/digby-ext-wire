/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/errors.mjs
 */

/**
 * @fileoverview The codec's one error type. Every failure the codec reports, on decode, encode or presentation parsing, is a
 * `WireError` with a stable `code`; nothing else (no RangeError from a DataView, no TypeError from a bad field) escapes the
 * public functions. Callers map the code to an answer: a decode failure of a query is FORMERR, an encode failure is SERVFAIL.
 */

/**
 * The error codes, grouped by where they arise.
 * @readonly
 * @enum {string}
 */
export const WireErrorCode = Object.freeze({
	// Decode: framing and bounds
	TRUNCATED: "TRUNCATED", // the input ends before a field it declares
	INPUT_TOO_LARGE: "INPUT_TOO_LARGE", // a message over 65535 octets
	TRAILING_DATA: "TRAILING_DATA", // octets left after the last section
	RDLENGTH_MISMATCH: "RDLENGTH_MISMATCH", // the rdata did not consume exactly rdlength octets
	// Decode: names
	BAD_LABEL_TYPE: "BAD_LABEL_TYPE", // a label type of 0b01 or 0b10 (extended / reserved)
	POINTER_FORWARD: "POINTER_FORWARD", // a compression pointer to its own position or later (loops and forward references)
	POINTER_OUT_OF_RANGE: "POINTER_OUT_OF_RANGE", // a pointer past the end of the message
	POINTER_LIMIT: "POINTER_LIMIT", // more pointer hops in one name than any valid name needs
	LABEL_TOO_LONG: "LABEL_TOO_LONG", // a label over 63 octets
	NAME_TOO_LONG: "NAME_TOO_LONG", // a name over 255 octets in wire form
	NAME_LIMIT: "NAME_LIMIT", // the message decodes more name octets than its cap allows (pointer fan-out amplification)
	// Decode: message structure
	QUESTION_LIMIT: "QUESTION_LIMIT", // a larger qdcount than the decode's maxQuestions allows
	OPT_MISPLACED: "OPT_MISPLACED", // OPT outside the additional section, or with a non-root owner
	MULTIPLE_OPT: "MULTIPLE_OPT", // more than one OPT record
	TSIG_MISPLACED: "TSIG_MISPLACED", // TSIG not the last record of the additional section
	// Decode and encode: field contents
	BAD_RDATA: "BAD_RDATA", // rdata that is malformed for its type
	BAD_OPTION: "BAD_OPTION", // an EDNS option whose length or content is wrong for its code
	BAD_SVCPARAM: "BAD_SVCPARAM", // a SVCB/HTTPS SvcParam that is malformed, out of order or inconsistent
	// Encode
	VALUE_OUT_OF_RANGE: "VALUE_OUT_OF_RANGE", // a number that does not fit its field, or a field of the wrong kind
	MESSAGE_TOO_LARGE: "MESSAGE_TOO_LARGE", // the encoding exceeds the size cap and cannot be truncated to fit
	TSIG_PRESENT: "TSIG_PRESENT", // a capped encode was given a message that already carries a TSIG record; truncating it would invalidate the MAC (CLDMV/digby#39)
	TRUNCATION_REFUSED: "TRUNCATION_REFUSED", // a capped encode was asked to truncate a message whose meaning truncation would destroy — an UPDATE, or a question of type AXFR or IXFR (CLDMV/digby#43)
	// Presentation format
	BAD_PRESENTATION: "BAD_PRESENTATION", // text that does not parse as the type's presentation form
	RELATIVE_NAME: "RELATIVE_NAME", // a relative name with no origin to complete it
	UNKNOWN_MNEMONIC: "UNKNOWN_MNEMONIC" // a type or class mnemonic the codec does not know (use TYPEnnn / CLASSnnn)
});

/**
 * An error raised by the wire codec.
 *
 * @example
 * try { decodeMessage(bytes); } catch (err) { if (err instanceof WireError && err.code === "TRUNCATED") ... }
 */
export class WireError extends Error {
	/**
	 * @param {string} code - one of {@link WireErrorCode}
	 * @param {string} message - a human-readable description
	 * @param {number} [offset] - the octet offset in the input where the problem was found, when there is one
	 */
	constructor(code, message, offset) {
		super(offset === undefined ? message : `${message} (at offset ${offset})`);
		this.name = "WireError";
		/** @type {string} */
		this.code = code;
		/** @type {number|undefined} */
		this.offset = offset;
	}
}

/**
 * Throw a {@link WireError}. A small helper so the hot paths stay one line.
 * @param {string} code
 * @param {string} message
 * @param {number} [offset]
 * @returns {never}
 */
export function fail(code, message, offset) {
	throw new WireError(code, message, offset);
}
