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
 * name's wire length is at most 255 octets. When the reader carries per-message name state (set up by `decodeMessage`), the
 * decode memoises the name and every suffix of it — by start offset, at every label offset and every pointer target — so any
 * later name at a decoded offset, or pointer into one, reuses the cached string instead of re-expanding it; a memo hit carries
 * the wire length and pointer-hop count of a fresh decode at that offset, so the guards hold for hits exactly as for walks.
 * Only the label octets a decode formats for the first time are charged against {@link MAX_NAME_OCTETS}, so a message full of
 * compressed repeats cannot expand without bound.
 */

import { MAX_MESSAGE } from "./buffer.mjs";
import { WireErrorCode, fail } from "./errors.mjs";

/** The longest label (RFC 1035 2.3.4). */
export const MAX_LABEL = 63;
/** The longest name in wire form, including the root label (RFC 1035 2.3.4). */
export const MAX_NAME = 255;
/** More pointer hops than any valid name needs (a 255-octet name has at most 127 labels). */
export const MAX_POINTER_HOPS = 128;
/**
 * The default per-message cap on decoded name octets: the largest possible message. The cap counts the label octets a
 * decode formats for the first time; the memo records every label offset and pointer target (see {@link readName}), so
 * within one message each octet is charged at most once and a decode whose pointers land on label boundaries can never
 * exceed its own size. Going over means pointers into the interiors of labels — bytes no encoder produces, re-parsed as
 * new labels — or a change that breaks the memo's coverage, which is exactly what the cap exists to stop.
 */
export const MAX_NAME_OCTETS = MAX_MESSAGE;

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
	const chars = [];
	for (let i = start; i < end; i++) {
		const c = bytes[i];
		if (SPECIAL.has(c)) chars.push(0x5c, c);
		else if (c > 0x20 && c < 0x7f) chars.push(c);
		else chars.push(0x5c, 0x30 + ((c / 100) | 0), 0x30 + (((c / 10) | 0) % 10), 0x30 + (c % 10));
	}
	return String.fromCharCode(...chars);
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
 * Read a name, following compression pointers under the guards above. When the reader carries per-message name state
 * (see the file overview), a name is looked up in the memo by its start offset, a pointer to an already-decoded offset
 * — the start of a name, or any label offset or pointer target within one — reuses the cached suffix, a hit carries the
 * wire length and hop count of a fresh decode at that offset, and only the label octets the decode formats for the
 * first time are charged against the reader's cap.
 *
 * @param {import("./buffer.mjs").Reader} r
 * @returns {string} the canonical presentation form
 * @throws {import("./errors.mjs").WireError} TRUNCATED, BAD_LABEL_TYPE, POINTER_FORWARD, POINTER_OUT_OF_RANGE, POINTER_LIMIT,
 *   NAME_TOO_LONG, NAME_LIMIT
 */
export function readName(r) {
	const bytes = r.bytes;
	const memo = r.nameMemo;
	const start = r.pos;
	if (memo !== undefined) {
		const hit = memo.get(start);
		if (hit !== undefined) {
			r.pos = hit.end;
			return hit.text;
		}
	}
	let cur = start;
	// Before the first pointer, reads are bounded by the reader's end (the rdata); after it, by the message.
	let limit = r.end;
	let floor = start;
	let jumped = false;
	let hops = 0;
	let wire = 1;
	/** @type {string[]} */
	const parts = [];
	/** @type {{ text: string, wire: number, hops: number } | null} - a cached suffix reused at a pointer target */
	let suffix = null;
	// Suffixes of this name to memoise at completion: every label offset and pointer target the walk touches, so any
	// later pointer into the name is a hit. `parts` is where the name's text starts from that offset, `wire`/`hops`
	// the walk state before it, `after` whether a pointer was already taken (such offsets end at the walk's terminal
	// octet rather than at the first pointer).
	const offsets = [];
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
			if (memo !== undefined) {
				const hit = memo.get(target);
				if (hit !== undefined) {
					// A hit must decode exactly as a fresh walk from the target would: the name's combined wire length
					// and combined pointer-hop count both stay within their limits.
					const total = wire - 1 + hit.wire;
					if (total > MAX_NAME) fail(WireErrorCode.NAME_TOO_LONG, `a name is longer than ${MAX_NAME} octets`, cur);
					if (hops + hit.hops > MAX_POINTER_HOPS) fail(WireErrorCode.POINTER_LIMIT, `more than ${MAX_POINTER_HOPS} compression pointers in one name`, cur);
					if (parts.length === 0) {
						// The name is exactly this pointer: the whole name is the cached one, nothing new is materialised.
						for (const o of offsets) memo.set(o.at, { text: hit.text, wire: hit.wire - o.wire + 1, hops: hops + hit.hops - o.hops, end: cur + 2 });
						memo.set(start, { text: hit.text, wire: total, hops: hops + hit.hops, end: r.pos });
						return hit.text;
					}
					suffix = hit;
					break;
				}
				offsets.push({ at: target, parts: parts.length, wire, hops, after: true });
			}
			cur = target;
			floor = target;
			continue;
		}
		if (kind !== 0) fail(WireErrorCode.BAD_LABEL_TYPE, `label type 0x${kind.toString(16)} is not supported`, cur);
		if (cur + 1 + len > limit) fail(WireErrorCode.TRUNCATED, "a label runs past the end of its field", cur);
		wire += len + 1;
		if (wire > MAX_NAME) fail(WireErrorCode.NAME_TOO_LONG, `a name is longer than ${MAX_NAME} octets`, cur);
		if (memo !== undefined) offsets.push({ at: cur, parts: parts.length, wire: wire - len - 1, hops, after: hops > 0 });
		parts.push(formatLabel(bytes, cur + 1, cur + 1 + len));
		cur += 1 + len;
	}
	if (!jumped) r.pos = cur;
	const total = suffix === null ? wire : wire - 1 + suffix.wire;
	const totalHops = suffix === null ? hops : hops + suffix.hops;
	// The root as a reused suffix adds only the final dot; every other suffix's text already ends with one. A reused
	// suffix always has labels of its own in front of it: a name that is exactly one pointer returned the cached
	// string at the pointer above.
	const text =
		suffix === null
			? parts.length === 0
				? "."
				: parts.join(".") + "."
			: parts.join(".") + "." + (suffix.text === "." ? "" : suffix.text);
	if (memo !== undefined) {
		// Only the label octets this decode formats for the first time are charged: repeated names and suffixes come
		// from the memo, so a message full of compressed repeats charges no more than its own size.
		chargeName(r, wire - 1, start);
		// Memoise the whole name and every suffix of it, so any later pointer into it is a hit.
		const terminalEnd = suffix === null ? cur : cur + 2;
		for (const o of offsets) {
			const from =
				o.parts === parts.length
					? suffix === null
						? "."
						: suffix.text
					: parts.slice(o.parts).join(".") + "." + (suffix === null || suffix.text === "." ? "" : suffix.text);
			memo.set(o.at, { text: from, wire: total - o.wire + 1, hops: totalHops - o.hops, end: o.after ? terminalEnd : r.pos });
		}
		memo.set(start, { text, wire: total, hops: totalHops, end: r.pos });
	}
	return text;
}

/**
 * Charge freshly materialised name octets against the reader's per-message cap.
 * @param {import("./buffer.mjs").Reader} r
 * @param {number} octets
 * @param {number} at
 */
function chargeName(r, octets, at) {
	const cap = r.maxNameOctets;
	if (cap === undefined) return;
	r.nameOctets = (r.nameOctets ?? 0) + octets;
	if (r.nameOctets > cap) fail(WireErrorCode.NAME_LIMIT, `the message decodes more than ${cap} name octets`, at);
}
