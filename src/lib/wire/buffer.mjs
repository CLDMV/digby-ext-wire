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
/** The getter sets per view kind: a typed array's (off the %TypedArray% prototype) and a DataView's. */
const VIEW_GETTERS = [VIEW_BUFFER, VIEW_BYTE_OFFSET, VIEW_BYTE_LENGTH];
const DATAVIEW_GETTERS = [DATAVIEW_BUFFER, DATAVIEW_BYTE_OFFSET, DATAVIEW_BYTE_LENGTH];
/** The `byteLength` getter off `SharedArrayBuffer.prototype`: it succeeds only on a buffer carrying the SharedArrayBuffer internal slot, from any realm (CLDMV/digby#39). */
const SAB_BYTE_LENGTH = Object.getOwnPropertyDescriptor(SharedArrayBuffer.prototype, "byteLength").get;
/** The `byteLength` getter off `ArrayBuffer.prototype`: it throws on a SharedArrayBuffer, so it never accepts one (CLDMV/digby#39). */
const AB_BYTE_LENGTH = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;
/** The typed-array `Symbol.toStringTag` getter, off `%TypedArray%.prototype`: it succeeds only on an object carrying the TypedArray internal slot — from any realm, under any prototype swap — and answers with that array's tag, so a Uint8Array is recognised by brand, never by `instanceof` (CLDMV/digby#39, round 9). */
export const TYPED_ARRAY_TAG = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), Symbol.toStringTag).get;

/**
 * A view's buffer, byteOffset and byteLength, read through the intrinsic getters so no own `buffer`, `byteOffset` or
 * `byteLength` property can shadow them (CLDMV/digby#39): an own `buffer` data property or getter on a Uint8Array would
 * otherwise hand the caller a SharedArrayBuffer to read instead of refusing it, and a shadowed `byteOffset` or
 * `byteLength` would make the view construction itself throw a raw RangeError. `instanceof` only picks which getter set
 * to try first — it is a hint, never the check: every getter verifies its receiver's internal slot, so a prototype swap
 * that fakes the hint merely costs the other set one try, and the brand check cannot be faked (CLDMV/digby#39). Returns
 * null when `v` is not a view or the reads throw (a Proxy's traps, a revoked Proxy) — every caller treats null as "not a
 * SharedArrayBuffer"; the type checks refuse those values anyway.
 * @param {unknown} v
 * @returns {{ buffer: ArrayBuffer | SharedArrayBuffer, byteOffset: number, byteLength: number } | null}
 */
export function intrinsicView(v) {
	const first = v instanceof DataView ? DATAVIEW_GETTERS : VIEW_GETTERS;
	try {
		return { buffer: first[0].call(v), byteOffset: first[1].call(v), byteLength: first[2].call(v) };
	} catch {}
	const second = first === DATAVIEW_GETTERS ? VIEW_GETTERS : DATAVIEW_GETTERS;
	try {
		return { buffer: second[0].call(v), byteOffset: second[1].call(v), byteLength: second[2].call(v) };
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
 * Whether `b` is a SharedArrayBuffer, by brand (CLDMV/digby#39, round 8): the intrinsic `SharedArrayBuffer.prototype.byteLength`
 * getter succeeds only on a buffer carrying the SharedArrayBuffer internal slot, from any realm and under any prototype swap —
 * `instanceof` tests the prototype chain, which `Object.setPrototypeOf(sab, ArrayBuffer.prototype)` fakes, and a cross-realm
 * SharedArrayBuffer fails `instanceof SharedArrayBuffer` from this realm outright. The getter runs no caller code.
 * @param {unknown} b
 * @returns {boolean}
 */
export function isSharedBuffer(b) {
	try {
		SAB_BYTE_LENGTH.call(b);
		return true;
	} catch {}
	return false;
}

/**
 * Every option key any public entry reads (CLDMV/digby#39, round 9): decodeMessage's (`allowTrailing`, `maxQuestions`,
 * `maxNameOctets`), encodeMessage's (`maxSize`, `compress`), encodeCapped's (`limit`, `reserveTsig`, `truncate`),
 * parseRecord's (`origin`, `ttl`, `class`), the transport entries' (`cap`, `transport`, `query`) and the query's own
 * fields (`edns`, `udpSize`). A key from this set that an options object — or a nested option object, or the query —
 * carries only on its prototype is refused, however it got there: enumerable (the copy would silently drop it) or
 * non-enumerable, a class getter among them, which the enumerable check cannot see.
 */
const OPTION_KEYS = Object.freeze([
	"allowTrailing", "cap", "class", "compress", "edns", "limit", "maxNameOctets", "maxQuestions", "maxSize", "origin", "query", "reserveTsig", "transport", "truncate", "ttl", "udpSize"
]);

/**
 * The refusal for an option that lives on the prototype: the snapshot and the copy behind it read own enumerable
 * properties only, so the bound would silently vanish (CLDMV/digby#39, round 9).
 * @param {string} where
 * @param {string} k
 * @returns {never}
 */
function hiddenOption(where, k) {
	return fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${where} carry the "${k}" option on the prototype; the copy would silently drop it (CLDMV/digby#39, round 9)`);
}

/**
 * Build a plain-data snapshot of a caller value, reading every own enumerable property exactly once and refusing
 * everything the copy would silently drop or that could split a check from its use (CLDMV/digby#39, round 9). The
 * rules, at every depth:
 *
 * - every SharedArrayBuffer form is refused NOT_CLONEABLE first, by brand — a SharedArrayBuffer is not a shape
 *   question, and the old plain-shape refusal reported it VALUE_OUT_OF_RANGE;
 * - a shape read that throws — a Proxy whose traps throw, a revoked Proxy — is the NOT_CLONEABLE refusal, never a raw
 *   TypeError;
 * - only plain objects and arrays are copied; anything else is refused VALUE_OUT_OF_RANGE by the
 *   `Object.prototype.toString` tag, whose read runs no caller code but a `Symbol.toStringTag` getter;
 * - an own non-enumerable key, a symbol-keyed own key and an inherited key — enumerable, or a known option key however
 *   hidden ({@link OPTION_KEYS}) — are all refused: the copy reads own enumerable properties only, so every one of
 *   them would silently vanish;
 * - an array keeps its length and its holes, so the copy's density checks see what the caller gave, and an own
 *   non-index property is refused, which the copy would drop;
 * - an accessor is read exactly once, here — the snapshot holds the value the checks saw, so a getter cannot show the
 *   guard one value and the copy another.
 *
 * The snapshot is caller-independent: every plain object and array in it is freshly built, so what {@link cloneInput}
 * then copies is already the guarded data, and no caller method, iterator or `Symbol.species` runs.
 *
 * @param {unknown} v
 * @param {string} where - what the value is, for the refusal messages
 * @param {Map<object, unknown>} memo - source object → its snapshot, so a cycle is walked once and preserved
 * @returns {unknown}
 */
function snapshotValue(v, where, memo) {
	if (v === null || typeof v !== "object") return v; // primitives; a function is the copy's NOT_CLONEABLE refusal
	// every SharedArrayBuffer form, before any shape check (CLDMV/digby#39, round 9): the buffer read through the
	// intrinsic getter, so an own `buffer` property cannot shadow it
	if (ArrayBuffer.isView(v) ? isSharedBuffer(intrinsicBuffer(v)) : isSharedBuffer(v))
		fail(WireErrorCode.NOT_CLONEABLE, `${where} is ${ArrayBuffer.isView(v) ? "a view over " : ""}a SharedArrayBuffer; the copy would share it, not copy it (CLDMV/digby#39)`);
	// the shape reads below run caller code on a Proxy (a revoked Proxy included) — any such throw is the
	// NOT_CLONEABLE refusal, never a raw TypeError (CLDMV/digby#39, round 9)
	let tag;
	try {
		tag = Object.prototype.toString.call(v);
	} catch {
		fail(WireErrorCode.NOT_CLONEABLE, `${where} is not structured-clone data (CLDMV/digby#39)`);
	}
	const isArray = tag === "[object Array]";
	if (tag !== "[object Object]" && !isArray)
		fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${where} must be plain data, got a ${tag.slice(8, -1)} (CLDMV/digby#39)`);
	if (memo.has(v)) return memo.get(v);
	const out = isArray ? [] : {};
	memo.set(v, out);
	// own enumerable string keys only, each read exactly once. On a plain object the reads run no caller code; on a
	// Proxy they fire its traps, and any throw is NOT_CLONEABLE.
	let descs;
	try {
		descs = Object.getOwnPropertyDescriptors(v);
		if (Object.getOwnPropertySymbols(v).length > 0)
			fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${where} carry a symbol-keyed option; the copy would silently drop it (CLDMV/digby#39, round 8)`);
		// an inherited enumerable key is dropped by the copy; so is an inherited KNOWN option key however hidden — a
		// class getter is non-enumerable, and only the known-key check can see it (CLDMV/digby#39, round 9)
		for (const k in v) if (!Object.hasOwn(v, k)) hiddenOption(where, k);
		for (const k of OPTION_KEYS) if (k in v && !Object.hasOwn(v, k)) hiddenOption(where, k);
	} catch (err) {
		if (err instanceof WireError) throw err;
		fail(WireErrorCode.NOT_CLONEABLE, `${where} is not structured-clone data (CLDMV/digby#39)`);
	}
	for (const [k, d] of Object.entries(descs)) {
		if (isArray && k === "length") {
			// the list's length — and with it its holes — is preserved, so the copy's density checks see what the
			// caller gave (CLDMV/digby#39)
			out.length = "value" in d ? d.value : v.length;
			continue;
		}
		if (!d.enumerable)
			fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${where} hide the "${k}" option behind a non-enumerable own property; the copy would silently drop it (CLDMV/digby#39, round 8)`);
		if (isArray && `${k >>> 0}` !== k)
			fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${where} carry the "${k}" property; a list holds indices only, and the copy would silently drop it (CLDMV/digby#39, round 9)`);
		let value;
		if ("value" in d) value = d.value; // the descriptor's value: read once, never a second get
		else
			try {
				value = v[k]; // an accessor: the one read, here — the snapshot holds the value the checks saw
			} catch {
				fail(WireErrorCode.NOT_CLONEABLE, `${where} is not structured-clone data (CLDMV/digby#39)`);
			}
		out[k] = snapshotValue(value, `${where}.${k}`, memo);
	}
	return out;
}

/**
 * {@link snapshotValue} behind a catch-all: any throw it does not itself recognise as a {@link WireError} — an internal
 * slot read on a revoked Proxy, a trap it does not wrap, deep recursion — is the NOT_CLONEABLE refusal, never a raw
 * error (CLDMV/digby#39).
 * @param {unknown} v
 * @param {string} where
 * @returns {unknown}
 */
function snapshotGuarded(v, where) {
	try {
		return snapshotValue(v, where, new Map());
	} catch (err) {
		if (err instanceof WireError) throw err;
		fail(WireErrorCode.NOT_CLONEABLE, `${where} is not structured-clone data (CLDMV/digby#39)`);
	}
}

/**
 * Guard and copy the query the two transport entries read (CLDMV/digby#39, round 9): the one guarded reader both
 * {@link udpLimit} and encodeForTransport go through — encodeForTransport passes its copy's query back through it — so
 * the two entries cannot disagree. `null` and `undefined` mean "no query"; any other non-object is refused
 * VALUE_OUT_OF_RANGE (udpLimit("x") used to return 512); an array is refused (its non-index properties would be
 * silently dropped by the copy); and the shape rules are {@link snapshotValue}'s, at every depth — prototype-borne,
 * hidden, symbol-keyed and non-index keys refused, a SharedArrayBuffer form refused NOT_CLONEABLE, a Proxy whose traps
 * throw or a revoked Proxy NOT_CLONEABLE — and only the snapshot is read afterwards: a getter is read once, by the
 * snapshot, so an object-then-undefined flip cannot split the check from the use.
 * @param {unknown} query
 * @param {string} what
 * @returns {object | null}
 */
export function snapshotQuery(query, what) {
	if (query === null || query === undefined) return null;
	if (typeof query !== "object") fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} must be a plain object, got ${describe(query)}`);
	let isArray;
	try {
		isArray = Array.isArray(query);
	} catch {
		fail(WireErrorCode.NOT_CLONEABLE, `${what} is not structured-clone data (CLDMV/digby#39)`);
	}
	if (isArray) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} must be a plain object, not an array`);
	return cloneInput(snapshotGuarded(query, what), what);
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
	// The buffer itself is brand-checked with the intrinsic getters, never `instanceof` (CLDMV/digby#39, round 8): a
	// SharedArrayBuffer wearing `ArrayBuffer.prototype` passed the old `instanceof` check and was copied, and a
	// cross-realm one failed `instanceof SharedArrayBuffer` from this realm outright.
	try {
		const view = intrinsicView(bytes);
		if (view !== null) {
			if (isSharedBuffer(view.buffer))
				fail(WireErrorCode.NOT_CLONEABLE, "byte input is a view over a SharedArrayBuffer; it would be read, not copied (CLDMV/digby#39)");
			return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
		}
		if (isSharedBuffer(bytes)) fail(WireErrorCode.NOT_CLONEABLE, "byte input is a SharedArrayBuffer; it would be read, not copied (CLDMV/digby#39)");
		// only a real ArrayBuffer carries the ArrayBuffer internal slot: a pod wearing `ArrayBuffer.prototype` with a
		// hostile `length` (2e8 used to allocate 200 MB inside `new Uint8Array` before failing INPUT_TOO_LARGE, and at
		// 2**32 the pod was OOM-killed) or an iterator over a SharedArrayBuffer view is refused here, before any
		// allocation or iteration (CLDMV/digby#39, round 8)
		try {
			AB_BYTE_LENGTH.call(bytes);
		} catch {
			return fail(WireErrorCode.VALUE_OUT_OF_RANGE, "expected a Uint8Array, an ArrayBuffer or an ArrayBufferView");
		}
		return new Uint8Array(bytes);
	} catch (err) {
		if (err instanceof WireError) throw err;
		// fall through to the refusal
	}
	return fail(WireErrorCode.VALUE_OUT_OF_RANGE, "expected a Uint8Array, an ArrayBuffer or an ArrayBufferView");
}

/**
 * Guard a public entry's options argument (CLDMV/digby#39): `null` and `undefined` mean "no options"; any other
 * non-object is refused VALUE_OUT_OF_RANGE; and the options are snapshotted once ({@link snapshotGuarded}) — every own
 * enumerable property read exactly once, a getter that throws, a Proxy whose traps throw and a revoked Proxy the
 * NOT_CLONEABLE refusal, never a raw TypeError, and every option the copy would silently drop — a prototype-borne,
 * hidden, symbol-keyed or non-index one — refused before the copy runs.
 * @param {unknown} options
 * @param {string} what
 * @returns {object}
 */
export function cloneOptions(options, what) {
	// `typeof` runs no caller code on any value — not even on a revoked Proxy, which does not throw for it (round 9
	// corrects the old comment, which claimed it does). `Array.isArray` can throw on one (its IsArray walks to the
	// revoked target), so it sits inside the refusal it feeds, like the snapshot below — which CAN run caller code (a
	// Proxy's traps, a throwing getter) (CLDMV/digby#39).
	if (options === null || options === undefined) return {};
	if (typeof options !== "object") fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} must be an object, got ${describe(options)}`);
	let isArray;
	try {
		isArray = Array.isArray(options);
	} catch {
		fail(WireErrorCode.NOT_CLONEABLE, `${what} are not structured-clone data (CLDMV/digby#39)`);
	}
	if (isArray) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} must be a plain object, not an array`);
	// The options are snapshotted, not handed to structuredClone directly (CLDMV/digby#39, round 9): the snapshot
	// carries only own enumerable data, so the copy reads the snapshot, never the caller's objects — a getter cannot
	// show the guard one value and the copy another. Round 8's prototype-shape check is gone: it was forgeable — any
	// prototype whose own `constructor` is a function named "Object" with `.prototype ===` that prototype passed it,
	// and its bound was silently dropped — and once only own keys are read, the realm of the prototype does not
	// matter: plain options from another realm, JSON-parsed, frozen, structuredClone'd or null-prototype ones all work.
	return cloneInput(snapshotGuarded(options, what), what);
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
