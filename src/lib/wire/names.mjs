/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/names.mjs
 */

/**
 * @fileoverview Domain names: the presentation form (RFC 1035 5.1 escapes) and the wire form (RFC 1035 3.1, 4.1.4 compression).
 *
 * Decoded names are strings in a canonical presentation form: absolute (trailing dot, the root is "."), case preserved,
 * printable ASCII as itself, the characters with a meaning in master files (`.` `\` `"` `(` `)` `;` `@` `$`) escaped as `\X`,
 * and every other octet (space, control, non-ASCII) as `\DDD`. Encoding accepts any valid presentation form, so
 * `formatName(parseName(x))` canonicalises.
 *
 * Decode guards: a pointer must point strictly before the start of the segment being read (which rules out loops and forward
 * references), inside the message, with at most {@link MAX_POINTER_HOPS} hops; label types 0b01 and 0b10 are refused; the
 * name's wire length is at most 255 octets.
 */

import { WireErrorCode, fail } from "./errors.mjs";

/** The longest label (RFC 1035 2.3.4). */
export const MAX_LABEL = 63;
/** The longest name in wire form, including the root label (RFC 1035 2.3.4). */
export const MAX_NAME = 255;
/** More pointer hops than any valid name needs (a 255-octet name has at most 127 labels). */
export const MAX_POINTER_HOPS = 128;

const DOT = 0x2e;
const BACKSLASH = 0x5c;
// Characters escaped as \X in names: . \ " ( ) ; @ $
const SPECIAL = new Set([0x2e, 0x5c, 0x22, 0x28, 0x29, 0x3b, 0x40, 0x24]);

/**
 * Format one label's octets in presentation form.
 * @param {Uint8Array} bytes
 * @param {number} [start=0]
 * @param {number} [end=bytes.length]
 * @returns {string}
 */
export function formatLabel(bytes, start = 0, end = bytes.length) {
	let out = "";
	for (let i = start; i < end; i++) {
		const c = bytes[i];
		if (SPECIAL.has(c)) out += "\\" + String.fromCharCode(c);
		else if (c > 0x20 && c < 0x7f) out += String.fromCharCode(c);
		else out += "\\" + String(c).padStart(3, "0");
	}
	return out;
}

/**
 * Parse a presentation-form name into its labels.
 *
 * @param {string} text - absolute (`www.example.`), relative (`www`, completed with `origin`), `@` (the origin) or `.` (the root)
 * @param {string} [origin] - an absolute name for relative names and `@`
 * @returns {Uint8Array[]} the labels, without the empty root label
 * @throws {import("./errors.mjs").WireError} BAD_PRESENTATION, RELATIVE_NAME, LABEL_TOO_LONG, NAME_TOO_LONG
 */
export function parseName(text, origin) {
	if (typeof text !== "string" || text.length === 0) fail(WireErrorCode.BAD_PRESENTATION, "a name must be a non-empty string");
	if (text === ".") return [];
	if (text === "@") {
		if (origin === undefined) fail(WireErrorCode.RELATIVE_NAME, `"@" with no origin`);
		return parseName(origin);
	}
	const labels = [];
	let label = [];
	let absolute = false;
	for (let i = 0; i < text.length; i++) {
		const ch = text.charCodeAt(i);
		if (ch > 0x7e || ch < 0x20) fail(WireErrorCode.BAD_PRESENTATION, `a name may hold only printable ASCII; escape other octets as \\DDD`);
		if (ch === BACKSLASH) {
			const next = text.charCodeAt(i + 1);
			if (Number.isNaN(next)) fail(WireErrorCode.BAD_PRESENTATION, `a name ends in a lone backslash: ${text}`);
			if (next >= 0x30 && next <= 0x39) {
				const digits = text.slice(i + 1, i + 4);
				if (!/^\d{3}$/.test(digits)) fail(WireErrorCode.BAD_PRESENTATION, `\\DDD needs three digits: ${text}`);
				const v = Number(digits);
				if (v > 255) fail(WireErrorCode.BAD_PRESENTATION, `\\${digits} is over 255`);
				label.push(v);
				i += 3;
			} else {
				label.push(next);
				i += 1;
			}
		} else if (ch === DOT) {
			if (label.length === 0) fail(WireErrorCode.BAD_PRESENTATION, `empty label in "${text}"`);
			labels.push(finishLabel(label));
			label = [];
			if (i === text.length - 1) absolute = true;
		} else {
			label.push(ch);
		}
	}
	if (!absolute) {
		labels.push(finishLabel(label)); // never empty: an empty text was refused above
		if (origin === undefined) fail(WireErrorCode.RELATIVE_NAME, `relative name "${text}" with no origin`);
		labels.push(...parseName(origin));
	}
	checkLength(labels);
	return labels;
}

function finishLabel(octets) {
	if (octets.length > MAX_LABEL) fail(WireErrorCode.LABEL_TOO_LONG, `a label is at most ${MAX_LABEL} octets, got ${octets.length}`);
	return Uint8Array.from(octets);
}

function checkLength(labels) {
	let n = 1;
	for (const l of labels) n += l.length + 1;
	if (n > MAX_NAME) fail(WireErrorCode.NAME_TOO_LONG, `a name is at most ${MAX_NAME} octets in wire form, got ${n}`);
	return n;
}

/**
 * Format labels as a canonical absolute name.
 * @param {Uint8Array[]} labels
 * @returns {string}
 */
export function formatName(labels) {
	if (labels.length === 0) return ".";
	let out = "";
	for (const l of labels) out += formatLabel(l) + ".";
	return out;
}

/**
 * Canonicalise a presentation-form name (escapes normalised, made absolute against `origin`).
 * @param {string} text
 * @param {string} [origin]
 * @returns {string}
 */
export function canonicalName(text, origin) {
	return formatName(parseName(text, origin));
}

/**
 * Compare two names the DNS way: ASCII case-insensitive, after escape normalisation.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function namesEqual(a, b) {
	return lowerKey(parseName(a)) === lowerKey(parseName(b));
}

/**
 * A key that is equal for two names exactly when {@link namesEqual} says they are.
 * @param {string} name
 * @returns {string}
 */
export function nameKey(name) {
	return lowerKey(parseName(name));
}

function lowerKey(labels) {
	let s = "";
	for (const l of labels) {
		s += String.fromCharCode(l.length);
		for (const c of l) s += String.fromCharCode(c >= 0x41 && c <= 0x5a ? c + 0x20 : c);
	}
	return s;
}

/**
 * The number of labels in a name, not counting the root (RRSIG's Labels field counts this way, minus a leading `*`).
 * @param {string} name
 * @returns {number}
 */
export function labelCount(name) {
	return parseName(name).length;
}

/**
 * Write a name. With `compress`, a suffix already written earlier in the message becomes a pointer (RFC 1035 4.1.4); every
 * suffix written is registered as a pointer target either way. Matching is octet-exact, so the decoded case is what was given.
 *
 * @param {import("./buffer.mjs").Writer} w
 * @param {string} name - presentation form; must be absolute
 * @param {boolean} [compress=false] - whether this name may be compressed (only owner names, questions and the rdata of the
 *   RFC 1035 types NS, CNAME, SOA, PTR and MX, per RFC 3597 4)
 */
export function writeName(w, name, compress = false) {
	const labels = parseName(name);
	// suffix keys, longest first: keys[i] identifies labels[i..]
	const keys = new Array(labels.length);
	let key = "";
	for (let i = labels.length - 1; i >= 0; i--) {
		const l = labels[i];
		let part = String.fromCharCode(l.length);
		for (const c of l) part += String.fromCharCode(c);
		key = part + key;
		keys[i] = key;
	}
	for (let i = 0; i < labels.length; i++) {
		if (compress && w.compress) {
			const at = w.names.get(keys[i]);
			if (at !== undefined) {
				w.u16(0xc000 | at);
				return;
			}
		}
		if (w.length < 0x4000 && !w.names.has(keys[i])) {
			w.names.set(keys[i], w.length);
			w.added.push(keys[i]);
		}
		w.u8(labels[i].length);
		w.raw(labels[i]);
	}
	w.u8(0);
}

/**
 * Read a name, following compression pointers under the guards above.
 *
 * @param {import("./buffer.mjs").Reader} r
 * @returns {string} the canonical presentation form
 * @throws {import("./errors.mjs").WireError} TRUNCATED, BAD_LABEL_TYPE, POINTER_FORWARD, POINTER_OUT_OF_RANGE, POINTER_LIMIT,
 *   NAME_TOO_LONG
 */
export function readName(r) {
	const bytes = r.bytes;
	let cur = r.pos;
	// Before the first pointer, reads are bounded by the reader's end (the rdata); after it, by the message.
	let limit = r.end;
	let floor = r.pos;
	let jumped = false;
	let hops = 0;
	let wire = 1;
	let out = "";
	for (;;) {
		if (cur >= limit) fail(WireErrorCode.TRUNCATED, "a name runs past the end of its field", cur);
		const len = bytes[cur];
		if (len === 0) {
			cur += 1;
			break;
		}
		const kind = len & 0xc0;
		if (kind === 0xc0) {
			if (cur + 1 >= limit) fail(WireErrorCode.TRUNCATED, "a compression pointer is cut short", cur);
			const target = ((len & 0x3f) << 8) | bytes[cur + 1];
			if (target >= bytes.length) fail(WireErrorCode.POINTER_OUT_OF_RANGE, `a compression pointer to ${target} is past the end`, cur);
			if (target >= floor) fail(WireErrorCode.POINTER_FORWARD, `a compression pointer to ${target} does not point backwards`, cur);
			if (++hops > MAX_POINTER_HOPS) fail(WireErrorCode.POINTER_LIMIT, `more than ${MAX_POINTER_HOPS} compression pointers in one name`, cur);
			if (!jumped) {
				r.pos = cur + 2;
				jumped = true;
				limit = bytes.length;
			}
			cur = target;
			floor = target;
			continue;
		}
		if (kind !== 0) fail(WireErrorCode.BAD_LABEL_TYPE, `label type 0x${kind.toString(16)} is not supported`, cur);
		if (cur + 1 + len > limit) fail(WireErrorCode.TRUNCATED, "a label runs past the end of its field", cur);
		wire += len + 1;
		if (wire > MAX_NAME) fail(WireErrorCode.NAME_TOO_LONG, `a name is longer than ${MAX_NAME} octets`, cur);
		out += formatLabel(bytes, cur + 1, cur + 1 + len) + ".";
		cur += 1 + len;
	}
	if (!jumped) r.pos = cur;
	return out === "" ? "." : out;
}
