/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/errors.mjs
 */

/**
 * @fileoverview The codec's one error type. Every failure the codec reports, on decode, encode or presentation parsing, is a
 * `WireError` with a stable `code`; nothing else (no RangeError from a DataView, no TypeError from a bad field) escapes the
 * public functions. Callers map the code to an answer: a decode failure of a query is FORMERR, an encode failure is SERVFAIL.
 */

import { intrinsicBuffer, isSharedBuffer } from "./buffer.mjs";

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
	NOT_CLONEABLE: "NOT_CLONEABLE", // the input is not structured-clone data — a function, a Proxy, a symbol — so the one-copy rule cannot hold (CLDMV/digby#39)
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

/**
 * Describe a caller value for an error message without running caller code and without ever throwing (CLDMV/digby#39).
 * `String()` — and a template literal's `${v}` — invokes the value's `toString`/`valueOf`: a plain object with
 * `toString: 1` (which clones fine — it is data) makes the stringification itself throw a TypeError, an
 * `Object.create(null)` cannot be converted at all, and a revoked Proxy throws even for `typeof`. Error messages
 * therefore never stringify a caller value through them: a primitive is shown directly, anything else only by its
 * `typeof` tag.
 * @param {unknown} v
 * @returns {string}
 */
export function describe(v) {
	let tag;
	try {
		tag = typeof v;
	} catch {
		return "an uninspectable value"; // a revoked Proxy: even `typeof` throws
	}
	if (tag === "string") return JSON.stringify(v);
	if (tag === "number" || tag === "boolean" || tag === "bigint") return String(v); // primitives: String() never throws
	if (tag === "object") return v === null ? "null" : "an object";
	if (tag === "undefined") return "undefined";
	if (tag === "function") return "a function";
	if (tag === "symbol") return "a symbol";
	return `a ${tag}`;
}

/**
 * The most entries any list the input may hold (CLDMV/digby#39): the largest count the wire form can carry (a 16-bit
 * section count, RFC 1035 4.1). A list this long already costs its own octets on the wire, so anything a caller hands
 * the codec beyond it is either a sparse array (refused below, before anything walks it) or a dense one a truncating
 * encode legitimately takes and drops whole RRsets from (CLDMV/digby#43's 320,000-record bound).
 */
const MAX_LIST = 0xffff;

/**
 * Copy the caller's input once with structuredClone, then cap and density-check the copy's lists (CLDMV/digby#39, codec
 * fix round 4). The public entries take this copy and never touch the original again: V8's serializer reads each own
 * enumerable property exactly once, so a getter cannot show the checks one value and the writer another; no caller
 * method, iterator or `Symbol.species` runs; a typed-array subclass arrives as a plain Uint8Array of its real octets; a
 * faked brand (`Object.setPrototypeOf({}, Uint8Array.prototype)`) arrives as a plain object the field checks refuse; an
 * own `__proto__` key stays a data key.
 *
 * The input contract is structured-clone data: plain objects — own enumerable properties only, so prototype getters are
 * not read and a record built on a class with prototype getters encodes as absent — plus arrays, primitives and typed
 * arrays. Anything else the serializer refuses (a function, a Proxy, a symbol, extreme nesting) is NOT_CLONEABLE; a list
 * over {@link MAX_LIST} entries that is not dense, or a list with a hole, is VALUE_OUT_OF_RANGE. In both cases a
 * `WireError`, never a TypeError, a raw RangeError, or a hang. A self-referential value is not refused: the copy
 * preserves the cycle, both walks bound themselves with a visited set, and the codecs read only the fields they know —
 * the same observable behaviour as round 3's depth-bounded copy.
 *
 * The size bound runs BEFORE the copy ({@link boundClone}) as well as after it ({@link checkClone}): V8's serializer
 * walks a fast-holey array by index, so a sparse list of 2**32-1 entries would exhaust the heap inside the copy itself.
 * The bound reads the original only through own enumerable DATA properties — reading a data property runs no caller
 * code, so a getter is still read exactly once, by the serializer; a getter's value is the serializer's to read and its
 * cost is the caller's.
 *
 * @param {unknown} value
 * @param {string} what - what the value is, for the refusal message ("a message", "TSIG record", ...)
 * @returns {unknown} the copy
 * @throws {WireError} NOT_CLONEABLE when structuredClone refuses the value; VALUE_OUT_OF_RANGE for a list longer than
 *   {@link MAX_LIST} that is not dense, or a list with a hole
 */
export function cloneInput(value, what) {
	try {
		boundClone(value, what);
	} catch (err) {
		if (err instanceof WireError) throw err;
		// the walk reads the original through `typeof`, `Array.isArray`, `Object.getPrototypeOf`, `Object.keys` and
		// `Object.getOwnPropertyDescriptor` — on a Proxy these fire the caller's traps, and on a revoked Proxy even
		// `typeof` throws. Any such throw means the input is not structured-clone data either, so it is mapped to the
		// documented refusal here, before it can escape as a raw TypeError or RangeError (CLDMV/digby#39)
		fail(WireErrorCode.NOT_CLONEABLE, `${what} is not structured-clone data`);
	}
	let clone;
	try {
		clone = structuredClone(value);
	} catch {
		// structuredClone refuses functions, Proxies and symbols with DataCloneError (cycles it takes), and its
		// serializer is recursive, so extreme nesting surfaces as a RangeError — both mean the input is not
		// structured-clone data. The thrown value is whatever the caller's getter threw (a null, a Symbol, an object)
		// and is never read: it has no `.message` to read, or its message is itself hostile to stringify — either way
		// the refusal is the fixed one (CLDMV/digby#39).
		fail(WireErrorCode.NOT_CLONEABLE, `${what} is not structured-clone data`);
	}
	checkClone(clone, what);
	return clone;
}

/**
 * Refuse, before the copy, every list too big for the serializer to take in bounded time (CLDMV/digby#39): a list over
 * {@link MAX_LIST} entries that is not dense. The walk reads the original only through own enumerable DATA properties
 * (accessors are skipped — the serializer reads those), so it costs the input's own keys and elements and runs no caller
 * code. Typed arrays carry fixed octets, and anything else exotic (a Map, a Date) is refused where a codec reads it.
 * @param {unknown} root
 * @param {string} what
 */
function boundClone(root, what) {
	const seen = new Set(); // a self-referential value is walked once, never in circles
	const stack = [[root, what]];
	// a view over a SharedArrayBuffer (a growable one included) is cloned by SHARING the buffer, not copying it: the
	// copy would alias memory the caller can still change while the encode reads it, so the one-copy rule cannot hold.
	// Checked both in this walk (fail before paying the copy) and in checkClone (the copy — which also catches a view
	// an accessor returned, which this walk skips) (CLDMV/digby#39).
	const refuseShared = (v, where) => {
		// the buffer is read through the intrinsic getter (CLDMV/digby#39): an own `buffer` property on the view would
		// otherwise shadow the SharedArrayBuffer and the copy would share it after all. The buffer is brand-checked
		// with the intrinsic getter, never `instanceof` (CLDMV/digby#39, round 8): a SharedArrayBuffer wearing
		// `ArrayBuffer.prototype` passed the old check and the copy shared it, and a cross-realm one failed
		// `instanceof SharedArrayBuffer` from this realm outright.
		if (isSharedBuffer(intrinsicBuffer(v)))
			fail(WireErrorCode.NOT_CLONEABLE, `${where} is a view over a SharedArrayBuffer; the copy would share it, not copy it (CLDMV/digby#39)`);
	};
	while (stack.length > 0) {
		const [v, where] = stack.pop();
		if (v === null || typeof v !== "object") continue;
		if (ArrayBuffer.isView(v)) {
			refuseShared(v, where);
			continue;
		}
		if (isSharedBuffer(v)) fail(WireErrorCode.NOT_CLONEABLE, `${where} is a SharedArrayBuffer; the copy would share it, not copy it (CLDMV/digby#39)`);
		if (seen.has(v)) continue;
		seen.add(v);
		if (Array.isArray(v) && v.length > MAX_LIST) {
			// longer than any list the wire can carry: only a dense list costs bounded time to copy — a sparse one (the
			// 2**32-1 repro) is refused here, before the serializer walks it by index. Denseness is checked over the
			// list's own keys, which costs their count, never the length.
			const keys = Object.keys(v);
			if (keys.length !== v.length || keys.some((k) => `${k >>> 0}` !== k))
				fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${where} holds ${v.length} entries; a list is at most ${MAX_LIST} dense entries (CLDMV/digby#39)`);
		} else if (!Array.isArray(v)) {
			const proto = Object.getPrototypeOf(v);
			if (proto !== Object.prototype && proto !== null) continue; // a Map, a Set, a Date, ...: refused where a codec reads it
		}
		for (const k of Object.keys(v)) {
			const d = Object.getOwnPropertyDescriptor(v, k);
			if (d === undefined || !("value" in d)) continue; // an accessor: the serializer reads it; this guard does not
			const e = d.value;
			if (e !== null && typeof e === "object") {
				// a view is checked here and never descended into: its contents are octets, not structure
				if (ArrayBuffer.isView(e)) refuseShared(e, `${where}.${k}`);
				else stack.push([e, `${where}.${k}`]);
			}
		}
	}
}

/**
 * Walk a {@link cloneInput} copy and refuse every list that is longer than {@link MAX_LIST} without being dense, and
 * every hole, before the encode iterates anything (CLDMV/digby#39). Only arrays and plain objects are descended: typed
 * arrays carry fixed octets with a real length, and anything else that survived the copy (a Map, a Date) is refused
 * where a codec reads it as a field. A visited set bounds the walk on a copy that preserved a cycle.
 * @param {unknown} root
 * @param {string} what
 */
function checkClone(root, what) {
	const seen = new Set();
	const stack = [[root, what]];
	// the SharedArrayBuffer refusal on the copy: this walk also catches a view an accessor returned, which boundClone
	// skips — the serializer read it, and the copy shares its buffer (CLDMV/digby#39)
	const refuseShared = (v, where) => {
		// the buffer is read through the intrinsic getter (CLDMV/digby#39): an own `buffer` property on the view would
		// otherwise shadow the SharedArrayBuffer and the copy would share it after all. The buffer is brand-checked
		// with the intrinsic getter, never `instanceof` (CLDMV/digby#39, round 8): a SharedArrayBuffer wearing
		// `ArrayBuffer.prototype` passed the old check and the copy shared it, and a cross-realm one failed
		// `instanceof SharedArrayBuffer` from this realm outright.
		if (isSharedBuffer(intrinsicBuffer(v)))
			fail(WireErrorCode.NOT_CLONEABLE, `${where} is a view over a SharedArrayBuffer; the copy would share it, not copy it (CLDMV/digby#39)`);
	};
	while (stack.length > 0) {
		const [v, where] = stack.pop();
		if (v === null || typeof v !== "object") continue;
		if (ArrayBuffer.isView(v)) {
			refuseShared(v, where);
			continue;
		}
		if (isSharedBuffer(v)) fail(WireErrorCode.NOT_CLONEABLE, `${where} is a SharedArrayBuffer; the copy would share it, not copy it (CLDMV/digby#39)`);
		if (seen.has(v)) continue;
		seen.add(v);
		if (Array.isArray(v)) {
			if (v.length > MAX_LIST) {
				// longer than any list the wire can carry: only a dense list costs bounded time to walk — a sparse one
				// (the 2**32-1 repro) is refused here, before anything iterates it. Denseness is checked over the copy's
				// own keys, which costs their count, never the length.
				const keys = Object.keys(v);
				if (keys.length !== v.length || keys.some((k) => `${k >>> 0}` !== k))
					fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${where} holds ${v.length} entries; a list is at most ${MAX_LIST} dense entries (CLDMV/digby#39)`);
			} else {
				for (let i = 0; i < v.length; i++)
					if (!(i in v)) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${where} has a hole at index ${i}; lists are dense (CLDMV/digby#39)`);
			}
			for (let i = 0; i < v.length; i++) {
				const e = v[i];
				if (e !== null && typeof e === "object") {
					// a view is checked here and never descended into: its contents are octets, not structure
					if (ArrayBuffer.isView(e)) refuseShared(e, `${where}[${i}]`);
					else stack.push([e, `${where}[${i}]`]);
				}
			}
		} else {
			const proto = Object.getPrototypeOf(v);
			if (proto !== Object.prototype && proto !== null) continue; // a Map, a Set, a Date, ...: refused where a codec reads it
			for (const k of Object.keys(v)) {
				const e = v[k];
				if (e !== null && typeof e === "object") {
					if (ArrayBuffer.isView(e)) refuseShared(e, `${where}.${k}`);
					else stack.push([e, `${where}.${k}`]);
				}
			}
		}
	}
}
