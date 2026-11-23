/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/buffer.mjs
 */

/**
 * @fileoverview The bounded reader and the capped writer every other wire module goes through.
 *
 * The reader never reads past its current `end`, and every out-of-bounds read is a `WireError` (`TRUNCATED`), never a RangeError
 * from the DataView. `limit()` narrows `end` to one record's rdata and checks the rdata consumed exactly what it declared.
 *
 * The writer grows on demand up to a hard maximum (65535 by default, the largest DNS message) and refuses to grow past it, so
 * an encode can never allocate without bound. It also carries the name-compression table, with checkpoints so the truncation
 * logic can roll back a record set that did not fit.
 */

import { WireError, WireErrorCode, cloneInput, describe, fail } from "./errors.mjs";

/** The largest DNS message: the TCP length prefix is 16 bits. */
export const MAX_MESSAGE = 65535;

/** The `buffer` getter off the view prototype, so the read can go through the intrinsic, never a shadowing own property (CLDMV/digby#39). */
const VIEW_BUFFER = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), "buffer").get;
/** The same, for DataViews. */
const DATAVIEW_BUFFER = Object.getOwnPropertyDescriptor(DataView.prototype, "buffer").get;
/** The typed-array `byteOffset` getter. */
const VIEW_BYTE_OFFSET = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), "byteOffset").get;
/** The typed-array `byteLength` getter. */
const VIEW_BYTE_LENGTH = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), "byteLength").get;
/** The same two, for DataViews. */
const DATAVIEW_BYTE_OFFSET = Object.getOwnPropertyDescriptor(DataView.prototype, "byteOffset").get;
const DATAVIEW_BYTE_LENGTH = Object.getOwnPropertyDescriptor(DataView.prototype, "byteLength").get;

/**
 * A view's buffer, byteOffset and byteLength, read through the intrinsic getters so no own `buffer`, `byteOffset` or
 * `byteLength` property can shadow them (CLDMV/digby#39): an own `buffer` data property or getter on a Uint8Array would
 * otherwise hand the caller a SharedArrayBuffer to read instead of refusing it, and a shadowed `byteOffset` or
 * `byteLength` would make the view construction itself throw a raw RangeError. The pick is brand-checked, not
 * `instanceof`-picked: every getter verifies its receiver's internal slot, so a prototype swap cannot make the DataView
 * getter run on a typed array or the other way round — the reader tries the DataView one and falls back to the
 * typed-array one. Returns null when `v` is not a view or the reads throw (a Proxy's traps, a revoked Proxy) — every
 * caller treats null as "not a SharedArrayBuffer"; the type checks refuse those values anyway.
 * @param {unknown} v
 * @returns {{ buffer: ArrayBuffer | SharedArrayBuffer, byteOffset: number, byteLength: number } | null}
 */
export function intrinsicView(v) {
	try {
		return { buffer: DATAVIEW_BUFFER.call(v), byteOffset: DATAVIEW_BYTE_OFFSET.call(v), byteLength: DATAVIEW_BYTE_LENGTH.call(v) };
	} catch {}
	try {
		return { buffer: VIEW_BUFFER.call(v), byteOffset: VIEW_BYTE_OFFSET.call(v), byteLength: VIEW_BYTE_LENGTH.call(v) };
	} catch {}
	return null;
}

/**
 * A view's buffer, read through the intrinsic getters (see {@link intrinsicView}) so an own `buffer` property cannot
 * shadow it (CLDMV/digby#39). Returns null when `v` is not a view or the read throws (a Proxy's trap, a revoked Proxy) —
 * every caller treats null as "not a SharedArrayBuffer"; the type checks refuse those values anyway.
 * @param {unknown} v
 * @returns {ArrayBuffer | SharedArrayBuffer | null}
 */
export function intrinsicBuffer(v) {
	const view = intrinsicView(v);
	return view === null ? null : view.buffer;
}

/**
 * View any byte source as a plain Uint8Array without copying.
 * @param {Uint8Array|ArrayBuffer|ArrayBufferView} bytes
 * @returns {Uint8Array}
 */
export function asBytes(bytes) {
	// `instanceof` and the intrinsic reads can fire a Proxy's traps (a revoked Proxy throws for `instanceof`'s
	// getPrototypeOf) — any such throw means the input cannot be read as octets, which is the VALUE_OUT_OF_RANGE refusal
	// (CLDMV/digby#39). The view is built only from the intrinsic buffer, byteOffset and byteLength (CLDMV/digby#39):
	// every byte-taking entry — decodeMessage, frameTcp, TcpFramer.push, formatGeneric — refuses every SAB form here,
	// bare SABs included, and no own `buffer`, `byteOffset` or `byteLength` property can shadow any of the three reads.
	try {
		const view = intrinsicView(bytes);
		if (view !== null) {
			if (view.buffer instanceof SharedArrayBuffer)
				fail(WireErrorCode.NOT_CLONEABLE, "byte input is a view over a SharedArrayBuffer; it would be read, not copied (CLDMV/digby#39)");
			return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
		}
		if (bytes instanceof SharedArrayBuffer)
			fail(WireErrorCode.NOT_CLONEABLE, "byte input is a SharedArrayBuffer; it would be read, not copied (CLDMV/digby#39)");
		if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes);
	} catch (err) {
		if (err instanceof WireError) throw err;
		// fall through to the refusal
	}
	return fail(WireErrorCode.VALUE_OUT_OF_RANGE, "expected a Uint8Array, an ArrayBuffer or an ArrayBufferView");
}

/**
 * Guard a public entry's options argument (CLDMV/digby#39): `null` and `undefined` mean "no options"; any other
 * non-object is refused VALUE_OUT_OF_RANGE; and the options are copied once with structuredClone — a getter that
 * throws, a Proxy (a revoked one included) or a function option value is the NOT_CLONEABLE refusal, never a raw
 * TypeError, and every option is read exactly once.
 * @param {unknown} options
 * @param {string} what
 * @returns {object}
 */
export function cloneOptions(options, what) {
	if (options === null || options === undefined) return {};
	// `typeof` runs no caller code, but the walk and the copy below can (a revoked Proxy's Object.keys throws) — both
	// sit inside the refusal they feed
	let tag;
	try {
		tag = typeof options;
	} catch {
		fail(WireErrorCode.NOT_CLONEABLE, `${what} are not structured-clone data (CLDMV/digby#39)`);
	}
	if (tag !== "object") fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} must be an object, got ${describe(options)}`);
	return cloneInput(options, what);
}

/**
 * Read one field of a caller object without ever throwing (CLDMV/digby#39): a getter that throws, a Proxy whose traps
 * throw, and a revoked Proxy are the NOT_CLONEABLE refusal; a missing property reads as undefined. Each call reads the
 * field exactly once, so a getter cannot show the check one value and the use another.
 * @param {unknown} o
 * @param {string} key
 * @returns {unknown}
 */
export function readField(o, key) {
	try {
		return o?.[key];
	} catch (err) {
		if (err instanceof WireError) throw err;
		fail(WireErrorCode.NOT_CLONEABLE, "the input is not structured-clone data (CLDMV/digby#39)");
	}
}

/** A forward-only reader over a message, bounded by `end`. */
export class Reader {
	/**
	 * @param {Uint8Array} bytes - the whole message (compression pointers resolve against it)
	 * @param {number} [pos=0]
	 * @param {number} [end=bytes.length]
	 */
	constructor(bytes, pos = 0, end = bytes.length) {
		/** @type {Uint8Array} */
		this.bytes = bytes;
		this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
		this.pos = pos;
		this.end = end;
	}

	/** Octets left before `end`. */
	get remaining() {
		return this.end - this.pos;
	}

	/**
	 * Require `n` more octets before `end`.
	 * @param {number} n
	 */
	need(n) {
		if (this.pos + n > this.end) fail(WireErrorCode.TRUNCATED, `need ${n} octet(s), ${this.end - this.pos} left`, this.pos);
	}

	/** @returns {number} */
	u8() {
		this.need(1);
		return this.bytes[this.pos++];
	}

	/** @returns {number} */
	u16() {
		this.need(2);
		const v = this.view.getUint16(this.pos);
		this.pos += 2;
		return v;
	}

	/** @returns {number} */
	u32() {
		this.need(4);
		const v = this.view.getUint32(this.pos);
		this.pos += 4;
		return v;
	}

	/** A 48-bit unsigned integer (TSIG time signed). @returns {number} */
	u48() {
		this.need(6);
		const hi = this.view.getUint16(this.pos);
		const lo = this.view.getUint32(this.pos + 2);
		this.pos += 6;
		return hi * 0x100000000 + lo;
	}

	/**
	 * Copy `n` octets out (a fresh Uint8Array, so decoded values never alias the input).
	 * @param {number} n
	 * @returns {Uint8Array}
	 */
	take(n) {
		this.need(n);
		const out = this.bytes.slice(this.pos, this.pos + n);
		this.pos += n;
		return out;
	}

	/** Copy every octet up to `end`. @returns {Uint8Array} */
	rest() {
		return this.take(this.end - this.pos);
	}

	/** A length-prefixed character-string (RFC 1035 3.3). @returns {Uint8Array} */
	charString() {
		return this.take(this.u8());
	}

	/**
	 * Run `fn` with `end` narrowed to the next `n` octets, and require that `fn` consumed exactly those octets.
	 * @template T
	 * @param {number} n
	 * @param {() => T} fn
	 * @param {string} [code=RDLENGTH_MISMATCH]
	 * @returns {T}
	 */
	limit(n, fn, code = WireErrorCode.RDLENGTH_MISMATCH) {
		this.need(n);
		const outer = this.end;
		const stop = this.pos + n;
		this.end = stop;
		try {
			const value = fn();
			if (this.pos !== stop) fail(code, `${stop - this.pos} octet(s) left over in a ${n}-octet field`, this.pos);
			return value;
		} finally {
			this.end = outer;
		}
	}
}

/** A growable writer with a hard size cap and the name-compression table. */
export class Writer {
	/**
	 * @param {object} [options]
	 * @param {number} [options.max=65535] - the hard cap; growing past it throws MESSAGE_TOO_LARGE
	 * @param {boolean} [options.compress=true] - whether names marked compressible use pointers
	 */
	constructor({ max = MAX_MESSAGE, compress = true } = {}) {
		this.max = max;
		this.compress = compress;
		this.bytes = new Uint8Array(Math.min(512, max));
		this.length = 0;
		/** suffix key → offset of a name suffix already written; only offsets < 0x4000 are usable as pointers */
		this.names = new Map();
		/** the keys added to `names`, in order, so a checkpoint can roll them back */
		this.added = [];
	}

	/** @param {number} n */
	reserve(n) {
		const want = this.length + n;
		if (want > this.max) fail(WireErrorCode.MESSAGE_TOO_LARGE, `the encoding exceeds ${this.max} octets`);
		if (want <= this.bytes.length) return;
		let size = this.bytes.length * 2;
		while (size < want) size *= 2;
		const grown = new Uint8Array(Math.min(size, Math.max(want, this.max)));
		grown.set(this.bytes.subarray(0, this.length));
		this.bytes = grown;
	}

	/** @param {number} v */
	u8(v) {
		checkInt(v, 0xff, "u8");
		this.reserve(1);
		this.bytes[this.length++] = v;
	}

	/** @param {number} v */
	u16(v) {
		checkInt(v, 0xffff, "u16");
		this.reserve(2);
		this.bytes[this.length++] = v >>> 8;
		this.bytes[this.length++] = v & 0xff;
	}

	/** @param {number} v */
	u32(v) {
		checkInt(v, 0xffffffff, "u32");
		this.reserve(4);
		this.bytes[this.length++] = v >>> 24;
		this.bytes[this.length++] = (v >>> 16) & 0xff;
		this.bytes[this.length++] = (v >>> 8) & 0xff;
		this.bytes[this.length++] = v & 0xff;
	}

	/** @param {number} v - a 48-bit unsigned integer */
	u48(v) {
		checkInt(v, 0xffffffffffff, "u48");
		this.u16(Math.floor(v / 0x100000000));
		this.u32(v % 0x100000000);
	}

	/** @param {Uint8Array} b */
	raw(b) {
		if (!(b instanceof Uint8Array)) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "expected a Uint8Array");
		this.reserve(b.length);
		this.bytes.set(b, this.length);
		this.length += b.length;
	}

	/** A length-prefixed character-string (at most 255 octets). @param {Uint8Array} b */
	charString(b) {
		if (!(b instanceof Uint8Array)) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "a character-string must be a Uint8Array");
		if (b.length > 255) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `a character-string is at most 255 octets, got ${b.length}`);
		this.u8(b.length);
		this.raw(b);
	}

	/**
	 * Overwrite a 16-bit value already written (counts, rdlength).
	 * @param {number} at
	 * @param {number} v
	 */
	patch16(at, v) {
		checkInt(v, 0xffff, "u16");
		this.bytes[at] = v >>> 8;
		this.bytes[at + 1] = v & 0xff;
	}

	/** Remember the current state, for {@link Writer#rollback}. @returns {{ length: number, added: number }} */
	checkpoint() {
		return { length: this.length, added: this.added.length };
	}

	/**
	 * Undo everything written since `mark`, including compression targets it registered.
	 * @param {{ length: number, added: number }} mark
	 */
	rollback(mark) {
		this.length = mark.length;
		while (this.added.length > mark.added) this.names.delete(this.added.pop());
	}

	/** The encoded bytes (a copy sized to the content). @returns {Uint8Array} */
	finish() {
		return this.bytes.slice(0, this.length);
	}
}

/**
 * Throw VALUE_OUT_OF_RANGE unless `v` is an integer in [0, max].
 * @param {unknown} v
 * @param {number} max
 * @param {string} what
 */
export function checkInt(v, max, what) {
	// the value is described, never String()ed: a caller value with a hostile toString/valueOf must not be able to
	// break the refusal itself (CLDMV/digby#39)
	if (!Number.isInteger(v) || v < 0 || v > max) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} out of range: ${describe(v)}`);
}
