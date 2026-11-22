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
 * `formatName(parseName(x))` canonicalises. On the encode side the writer's compression targets live in a label index (see
 * {@link writeName}): one node per registered suffix, chained from the suffix's last label, so a name costs one lookup per
 * label and the table holds every distinct label once.
 *
 * Decode guards: a pointer must point strictly before the start of the segment being read (which rules out loops and forward
 * references), inside the message, with at most {@link MAX_POINTER_HOPS} hops; label types 0b01 and 0b10 are refused; the
 * name's wire length is at most 255 octets. When the reader carries per-message name state (set up by `decodeMessage`), the
 * decode memoises every suffix of every name it decodes — by offset, at every label offset and every pointer target — so any
 * later pointer into one reuses the cached suffix instead of re-expanding it; a hit carries the wire length and pointer-hop
 * count of a fresh decode at that offset, so the guards hold for hits exactly as for walks. A memo entry stores its suffix's
 * own labels and where the reused suffix behind it starts, and builds the suffix's presentation string only when a pointer
 * actually reuses the entry (caching it then) — a message full of uncompressed names never materialises a string per suffix.
 * Only the label octets a decode walks for the first time are charged against {@link MAX_NAME_OCTETS}: the cap bounds the
 * decode's walk, not the characters it materialises — see the cap's note.
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
 * decode walks for the first time; the memo records every label offset and pointer target (see {@link readName}), so
 * within one message each octet is charged at most once and a decode whose pointers land on label boundaries never
 * charges more than its own size. Going over means pointers into the interiors of labels — bytes no encoder produces,
 * re-parsed as new labels — or a change that breaks the memo's coverage, which is exactly what the cap exists to stop.
 * The cap bounds the walked octets, not the characters a decode materialises: materialisation is kept in check by the
 * memo itself — a name's own text is built once, and a suffix's string only when a pointer reuses that entry, at most
 * once per message (see {@link readName}) — not by this cap.
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
 * One registered name suffix in the writer's compression index. `children` holds the deeper suffixes — each one
 * label longer, attached one label earlier. `at` is the offset the suffix was registered at, a usable pointer
 * target and so below 0x4000, or -1 for a connector: a suffix that was first registered past 0x3fff can never be
 * a pointer target but still carries the chain down to the registered suffixes behind it. `parent` and `key` let
 * the root's `delete` detach the node when {@link import("./buffer.mjs").Writer#rollback} runs.
 *
 * @typedef {object} TargetNode
 * @property {Map<string, TargetNode>} children
 * @property {number} at
 * @property {TargetNode|null} parent
 * @property {string} key
 */

/**
 * The root of a writer's compression index, installed on `Writer#names` by {@link writeName} (the writer
 * constructs that field as a flat Map; the index replaces it on the first name). The root is not a suffix; it
 * carries the walk's resume cache and `delete`, which `Writer#rollback` calls with the nodes `writeName` pushed
 * onto `Writer#added` — children are pushed after their parents, so a pop detaches a node whose own children are
 * already gone, and any rollback drops the cache, since it describes nodes the rollback may have detached.
 *
 * @returns {TargetNode & { delete: (node: TargetNode) => void, prevLabels: Uint8Array[]|undefined, prevSteps: number, pathNodes: (TargetNode|undefined)[], pathHits: (TargetNode|null)[], pathDepths: number[] }}
 */
function newTargets() {
	const root = { children: new Map(), at: -1, parent: null, key: "" };
	root.prevLabels = undefined;
	root.prevSteps = 0;
	root.pathNodes = undefined;
	root.pathHits = undefined;
	root.pathDepths = undefined;
	root.delete = (node) => {
		root.prevLabels = undefined;
		root.prevSteps = 0;
		node.parent.children.delete(node.key);
	};
	return root;
}

/**
 * Write a name. With `compress`, a suffix already written earlier in the message becomes a pointer (RFC 1035 4.1.4); every
 * suffix written is registered as a pointer target either way. Matching is octet-exact, so the decoded case is what was
 * given.
 *
 * The compression targets live in a label index on the writer ({@link newTargets}): one node per registered suffix, its
 * chain running from the suffix's last label at the root to its first. The walk from the last label backwards follows the
 * registered chain, and the deepest node with an offset on it is the longest matching suffix — the target the flat
 * suffix-key table this replaced found with its first hit — and each not-yet-present suffix is registered as a single new
 * node, so the table holds every distinct label once instead of one full copy of every suffix key of every name. That
 * retained text is what made large messages slow to encode: the flat table held O(name) characters per registered suffix
 * (~210 per record on a long-apex response, ~630 KB on 2,900 records, CLDMV/digby#40); the index holds the shared labels
 * once. The walk costs one lookup per label it newly crosses: names in one message share their trailing labels (an apex
 * under every owner), so the walk resumes from the previous name's path through the shared part — one byte comparison per
 * shared label instead of a lookup — and only probes labels from where the names diverge.
 *
 * @param {import("./buffer.mjs").Writer} w
 * @param {string} name - presentation form; must be absolute
 * @param {boolean} [compress=false] - whether this name may be compressed (only owner names, questions and the rdata of the
 *   RFC 1035 types NS, CNAME, SOA, PTR and MX, per RFC 3597 4)
 */
export function writeName(w, name, compress = false) {
	const labels = parseName(name);
	const last = labels.length - 1;
	// Edge keys, built lazily: a label's octets as a string — injective, and the boundary between labels is the
	// edge itself, so no length octet is needed (the flat suffix keys carried one). Only the labels the walk probes
	// or registers need one; the shared trailing labels are compared byte-wise against the previous name's.
	const keys = new Array(labels.length);
	// The walk state: `node` is where the walk stands, `hit` the deepest registered target on the chain so far and
	// `hitDepth` how many labels of this name its suffix is (a node at depth d is the name's last d labels), so the
	// pointer goes after label `last - hitDepth`.
	let node = null;
	let hit = null;
	let hitDepth = 0;
	let broken = -1;
	let taken = 0;
	if (last >= 0) {
		if (w.names instanceof Map) w.names = newTargets();
		const targets = w.names;
		// Resume the previous walk through this name's shared trailing labels: the chain through them is the same,
		// so the cached node and cached hit state apply. `t` is the number of shared trailing labels, compared
		// byte-wise and capped at what the previous walk actually followed; the labels beyond that are probed one
		// lookup each.
		let t = 0;
		const prevLabels = targets.prevLabels;
		if (prevLabels !== undefined) {
			const pl = prevLabels.length - 1;
			const maxT = Math.min(last, pl, targets.prevSteps);
			while (t < maxT) {
				const a = labels[last - t];
				const b = prevLabels[pl - t];
				if (a.length !== b.length) break;
				let same = true;
				for (let x = 0; x < a.length; x++) {
					if (a[x] !== b[x]) {
						same = false;
						break;
					}
				}
				if (!same) break;
				t++;
			}
		}
		// The cached path, grown as needed; entries 0..t carry over from the previous walk, because the shared
		// trailing labels select the same nodes for this name.
		let pathNodes = targets.pathNodes;
		let pathHits = targets.pathHits;
		let pathDepths = targets.pathDepths;
		if (pathNodes === undefined || pathNodes.length < last + 2) {
			const cap = last + 2;
			const nodes = new Array(cap);
			const hits = new Array(cap);
			const depths = new Array(cap);
			if (pathNodes !== undefined) {
				for (let i = 0; i <= t; i++) {
					nodes[i] = pathNodes[i];
					hits[i] = targets.pathHits[i];
					depths[i] = targets.pathDepths[i];
				}
			} else {
				nodes[0] = targets;
				hits[0] = null;
				depths[0] = 0;
			}
			targets.pathNodes = pathNodes = nodes;
			targets.pathHits = pathHits = hits;
			targets.pathDepths = pathDepths = depths;
		}
		node = t === 0 ? targets : pathNodes[t];
		hit = t === 0 ? null : pathHits[t];
		hitDepth = t === 0 ? 0 : pathDepths[t];
		taken = t;
		for (let j = last - t; j >= 0; j--) {
			const key = keys[j] ?? (keys[j] = String.fromCharCode(...labels[j]));
			const child = node.children.get(key);
			if (child === undefined) {
				broken = j;
				break;
			}
			node = child;
			taken++;
			if (child.at >= 0) {
				hit = child;
				hitDepth = taken;
			}
			pathNodes[taken] = node;
			pathHits[taken] = hit;
			pathDepths[taken] = hitDepth;
		}
		targets.prevLabels = labels;
		targets.prevSteps = taken;
	}
	// Where each suffix of this name starts on the wire: suffix j starts at label j's length octet, which is where
	// the flat table recorded its offsets.
	const starts = new Array(labels.length);
	let at = w.length;
	for (let i = 0; i <= last; i++) {
		starts[i] = at;
		at += 1 + labels[i].length;
	}
	// Register the suffixes the walk did not find, deepest first, so each node's parent exists when it attaches. A
	// suffix whose start has passed 0x3fff is registered without an offset: it can never be a pointer target (the
	// flat table never stored one either), but the registered suffixes behind it hang off the chain through it.
	for (let j = broken; j >= 0; j--) {
		const child = {
			children: new Map(),
			at: starts[j] < 0x4000 ? starts[j] : -1,
			parent: node,
			key: keys[j] ?? (keys[j] = String.fromCharCode(...labels[j]))
		};
		node.children.set(keys[j], child);
		node = child;
		w.added.push(child);
	}
	if (compress && w.compress && hit !== null) {
		// the labels in front of the matching suffix, then the pointer to it
		const hitStart = last - hitDepth + 1;
		for (let i = 0; i < hitStart; i++) {
			w.u8(labels[i].length);
			w.raw(labels[i]);
		}
		w.u16(0xc000 | hit.at);
		return;
	}
	for (let i = 0; i <= last; i++) {
		w.u8(labels[i].length);
		w.raw(labels[i]);
	}
	w.u8(0);
}

/**
 * Read a name, following compression pointers under the guards above. When the reader carries per-message name state
 * (see the file overview), a pointer to an already-decoded offset — the start of a name, or any label offset or pointer
 * target within one — reuses the cached suffix, a hit carries the wire length and hop count of a fresh decode at that
 * offset, and only the label octets the decode walks for the first time are charged against the reader's cap.
 *
 * @param {import("./buffer.mjs").Reader} r
 * @returns {string} the canonical presentation form
 * @throws {import("./errors.mjs").WireError} TRUNCATED, BAD_LABEL_TYPE, BAD_RDATA (a compression pointer in standalone rdata,
 *   CLDMV/digby#38), POINTER_FORWARD, POINTER_OUT_OF_RANGE, POINTER_LIMIT, NAME_TOO_LONG, NAME_LIMIT
 */
export function readName(r) {
	const bytes = r.bytes;
	const memo = r.nameMemo;
	const start = r.pos;
	let cur = start;
	// Before the first pointer, reads are bounded by the reader's end (the rdata); after it, by the message.
	let limit = r.end;
	let floor = start;
	let jumped = false;
	let hops = 0;
	let wire = 1;
	/** @type {string[]} */
	const parts = [];
	/** @type {MemoEntry | null} - a cached suffix reused at a pointer target */
	let suffix = null;
	// Suffixes of this name to memoise at completion: every label offset and pointer target the walk touches, so any
	// later pointer into the name is a hit. `index` is where the name's own labels start from that offset (an index
	// into `parts`), `wire`/`hops` the walk state before it.
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
			// standalone rdata (decodeRdataBytes) carries no compression: there is no message for a pointer to resolve
			// against, so one is refused wherever the codec reads a name (CLDMV/digby#38)
			if (r.standalone) fail(WireErrorCode.BAD_RDATA, "standalone rdata must not carry compression pointers", cur);
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
						for (const o of offsets) memo.set(o.at, { rec: hit.rec, index: hit.index, wire: hit.wire - o.wire + 1, hops: hops + hit.hops - o.hops });
						memo.set(start, { rec: hit.rec, index: hit.index, wire: total, hops: hops + hit.hops });
						return entryText(hit);
					}
					suffix = hit;
					break;
				}
				offsets.push({ at: target, index: parts.length, wire, hops });
			}
			cur = target;
			floor = target;
			continue;
		}
		if (kind !== 0) fail(WireErrorCode.BAD_LABEL_TYPE, `label type 0x${kind.toString(16)} is not supported`, cur);
		if (cur + 1 + len > limit) fail(WireErrorCode.TRUNCATED, "a label runs past the end of its field", cur);
		wire += len + 1;
		if (wire > MAX_NAME) fail(WireErrorCode.NAME_TOO_LONG, `a name is longer than ${MAX_NAME} octets`, cur);
		if (memo !== undefined) offsets.push({ at: cur, index: parts.length, wire: wire - len - 1, hops });
		parts.push(formatLabel(bytes, cur + 1, cur + 1 + len));
		cur += 1 + len;
	}
	if (!jumped) r.pos = cur;
	const total = suffix === null ? wire : wire - 1 + suffix.wire;
	const totalHops = suffix === null ? hops : hops + suffix.hops;
	// The root as a reused suffix adds only the final dot; every other suffix's text already ends with one. A reused
	// suffix always has labels of its own in front of it: a name that is exactly one pointer returned the cached
	// string at the pointer above. The reuse builds (and caches) the suffix's string now, if it was not built before.
	const suffixText = suffix === null ? "" : entryText(suffix);
	const tail = suffixText === "." ? "" : suffixText;
	const text = parts.length === 0 ? "." : parts.join(".") + "." + tail;
	if (memo !== undefined) {
		// Only the label octets this decode walks for the first time are charged: repeated names and suffixes come
		// from the memo, so a message full of compressed repeats charges no more than its own size.
		chargeName(r, wire - 1, start);
		// Memoise the whole name and every suffix of it, so any later pointer into it is a hit. An entry holds the
		// name's own labels and where its suffix starts among them; entryText builds the string only when a pointer
		// actually reuses the entry, so a message of uncompressed names never materialises a string per suffix.
		const rec = { labels: parts, tail, text };
		for (const o of offsets) memo.set(o.at, { rec, index: o.index, wire: total - o.wire + 1, hops: totalHops - o.hops });
		memo.set(start, { rec, index: 0, wire: total, hops: totalHops });
	}
	return text;
}

/**
 * A memo entry: one decoded name suffix, keyed by its offset. `rec` is the decoded name the suffix belongs to — its
 * own labels in presentation form and `tail`, the text of the reused suffix behind them (empty for the root or a name
 * with no pointer). `index` is where the suffix starts among those labels (0 at the name's start; `labels.length` at an
 * offset whose suffix is exactly the reused one). `wire`/`hops` are what a fresh decode at the offset would charge, so
 * a hit can check the combined limits; `text` is the suffix's presentation string, built by {@link entryText} on first
 * use and cached. An entry no pointer ever reuses never holds a string.
 *
 * @typedef {object} MemoEntry
 * @property {{ labels: string[], tail: string, text: string }} rec
 * @property {number} index
 * @property {number} wire
 * @property {number} hops
 * @property {string} [text]
 */

/**
 * The presentation text of a memo entry: the record's own labels from the entry's index on, plus the record's tail.
 * Built on first use and cached on the entry. The record's full text (index 0) is built at completion — it is the
 * decode's return value — so that case only reads it.
 * @param {MemoEntry} entry
 * @returns {string}
 */
function entryText(entry) {
	if (entry.text !== undefined) return entry.text;
	const { labels, tail, text } = entry.rec;
	if (entry.index === 0) return (entry.text = text);
	// An index at the end of the record's own labels is an offset whose suffix is exactly the reused one: the tail,
	// or the root when there is none.
	entry.text = entry.index === labels.length ? (tail === "" ? "." : tail) : labels.slice(entry.index).join(".") + "." + tail;
	return entry.text;
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
