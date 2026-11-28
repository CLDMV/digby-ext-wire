/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/helpers/wire-gen.mjs
 */

/**
 * @fileoverview A seeded PRNG and generators of valid, canonical codec values (names, rdata for every typed RR type, generic
 * rdata, EDNS options, whole messages) for the property and fuzz tests. Everything a generator returns is in the form the
 * decoder produces, so `decode(encode(x))` must deep-equal `x`.
 */

import { expect } from "vitest";
import { formatIPv4, formatIPv6 } from "../../src/lib/text.mjs";
import { formatName, nameKey } from "../../src/lib/names.mjs";
import { CLASS, EDNS_OPTION, SVC_KEY, TYPE } from "../../src/lib/constants.mjs";
import { TYPED } from "../../src/lib/rdata/index.mjs";

/**
 * mulberry32: small, fast, good enough for test data.
 * @param {number} seed - a 32-bit integer
 */
export function prng(seed) {
	let a = seed >>> 0;
	const next = () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
	const int = (lo, hi) => lo + Math.floor(next() * (hi - lo + 1));
	const chance = (p) => next() < p;
	const pick = (list) => list[Math.floor(next() * list.length)];
	const bytes = (lo, hi) => {
		const out = new Uint8Array(int(lo, hi));
		for (let i = 0; i < out.length; i++) out[i] = int(0, 255);
		return out;
	};
	return { next, int, chance, pick, bytes };
}

/** A seed: from DIGBY_FUZZ_SEED when set, otherwise random. */
export function seedFromEnv(name = "DIGBY_FUZZ_SEED") {
	const env = process.env[name];
	if (env !== undefined && env !== "") return Number(env) >>> 0;
	return Math.floor(Math.random() * 0x100000000) >>> 0;
}

const LDH = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

/** @param {ReturnType<typeof prng>} g */
export function genLabel(g, max = 12) {
	const len = g.chance(0.05) ? g.int(1, 63) : g.int(1, max);
	const out = new Uint8Array(len);
	const wild = g.chance(0.1);
	for (let i = 0; i < len; i++) out[i] = wild && g.chance(0.3) ? g.int(0, 255) : LDH.charCodeAt(g.int(0, LDH.length - 1));
	return out;
}

/**
 * A canonical absolute name within the 255-octet limit.
 * @param {ReturnType<typeof prng>} g
 * @param {string[]} [pool] - names to reuse sometimes, so compression has suffixes to share
 */
export function genName(g, pool) {
	if (pool?.length && g.chance(0.4)) {
		const base = g.pick(pool);
		if (g.chance(0.5) || base === ".") return base;
		const label = genLabel(g, 8);
		const candidate = formatName([label]) + base;
		return wireLength(candidate) <= 255 ? (candidate.endsWith("..") ? base : candidate) : base;
	}
	const labels = [];
	let size = 1;
	const n = g.int(0, 4);
	for (let i = 0; i < n; i++) {
		const l = genLabel(g);
		if (size + l.length + 1 > 255) break;
		labels.push(l);
		size += l.length + 1;
	}
	const name = formatName(labels);
	pool?.push(name);
	return name;
}

function wireLength(name) {
	if (name === ".") return 1;
	// count unescaped dots and octets: approximate via the codec is avoided here; recompute from labels
	let n = 1;
	let i = 0;
	let label = 0;
	while (i < name.length) {
		if (name[i] === "\\") {
			i += /\d/.test(name[i + 1]) ? 4 : 2;
			label++;
		} else if (name[i] === ".") {
			n += label + 1;
			label = 0;
			i++;
		} else {
			label++;
			i++;
		}
	}
	return n;
}

// 65535 is reserved, so no generated bitmap or RRSIG type covered may include it (CLDMV/digby#38)
const someTypes = [1, 2, 5, 6, 12, 15, 16, 28, 33, 43, 46, 47, 48, 50, 51, 52, 64, 65, 99, 257, 1234, 32768, 65000];

/** @param {ReturnType<typeof prng>} g */
function genTypes(g) {
	const set = new Set();
	const n = g.int(0, 6);
	for (let i = 0; i < n; i++) set.add(g.chance(0.7) ? g.pick(someTypes) : g.int(1, 65534));
	return [...set].sort((a, b) => a - b);
}

/** @param {ReturnType<typeof prng>} g */
export function genIPv6(g) {
	const b = new Uint8Array(16);
	for (let i = 0; i < 16; i += 2) {
		if (g.chance(0.4)) continue;
		b[i] = g.int(0, 255);
		b[i + 1] = g.int(0, 255);
	}
	return formatIPv6(b);
}

const genIPv4 = (g) => formatIPv4(g.bytes(4, 4));

/** A valid string with some non-ASCII code points (no lone surrogates). @param {ReturnType<typeof prng>} g */
function genText(g, max = 20) {
	const n = g.int(0, max);
	let s = "";
	for (let i = 0; i < n; i++) {
		const r = g.next();
		if (r < 0.8) s += String.fromCharCode(g.int(0x20, 0x7e));
		else if (r < 0.95) s += String.fromCodePoint(g.int(0xa0, 0xd7ff));
		else s += String.fromCodePoint(g.int(0x10000, 0x10ffff));
	}
	return s;
}

/** @param {ReturnType<typeof prng>} g */
function genSvcParams(g) {
	const params = [];
	const keys = [SVC_KEY.alpn, SVC_KEY["no-default-alpn"], SVC_KEY.port, SVC_KEY.ipv4hint, SVC_KEY.ech, SVC_KEY.ipv6hint, SVC_KEY.dohpath, SVC_KEY.ohttp];
	for (const key of keys) {
		if (!g.chance(0.3)) continue;
		switch (key) {
			case SVC_KEY.alpn: {
				const ids = [];
				const n = g.int(1, 3);
				for (let i = 0; i < n; i++) ids.push(g.chance(0.7) ? Uint8Array.from(g.pick(["h2", "h3", "http/1.1", "dot", "a,b", "x\\y"]), (c) => c.charCodeAt(0)) : g.bytes(1, 10));
				params.push({ key, value: ids });
				break;
			}
			case SVC_KEY.port:
				params.push({ key, value: g.int(0, 65535) });
				break;
			case SVC_KEY.ipv4hint:
				params.push({ key, value: Array.from({ length: g.int(1, 3) }, () => genIPv4(g)) });
				break;
			case SVC_KEY.ipv6hint:
				params.push({ key, value: Array.from({ length: g.int(1, 2) }, () => genIPv6(g)) });
				break;
			case SVC_KEY.ech:
				params.push({ key, value: g.bytes(1, 30) });
				break;
			case SVC_KEY.dohpath:
				params.push({ key, value: "/dns-query{?dns}" + genText(g, 5) });
				break;
			default:
				params.push({ key, value: null });
		}
	}
	if (g.chance(0.3)) params.push({ key: g.int(9, 65534), value: g.bytes(0, 12) });
	params.sort((a, b) => a.key - b.key);
	// drop a duplicate unknown key, if the random one collided
	const unique = params.filter((p, i) => i === 0 || p.key !== params[i - 1].key);
	if (unique.length && g.chance(0.3)) {
		const listed = unique.filter(() => g.chance(0.5)).map((p) => p.key);
		if (listed.length) unique.unshift({ key: SVC_KEY.mandatory, value: listed });
	}
	return unique;
}

/**
 * Typed rdata for `type`, in decoded (canonical) form.
 * @param {ReturnType<typeof prng>} g
 * @param {number} type
 * @param {string[]} [pool]
 */
export function genRdata(g, type, pool) {
	const name = () => genName(g, pool);
	const u8 = () => g.int(0, 255);
	const u16 = () => g.int(0, 65535);
	const u32 = () => g.int(0, 0xffffffff);
	switch (type) {
		case TYPE.A:
			return { address: genIPv4(g) };
		case TYPE.AAAA:
			return { address: genIPv6(g) };
		case TYPE.NS:
		case TYPE.CNAME:
		case TYPE.PTR:
			return { target: name() };
		case TYPE.MX:
			return { preference: u16(), exchange: name() };
		case TYPE.SOA:
			return { mname: name(), rname: name(), serial: u32(), refresh: u32(), retry: u32(), expire: u32(), minimum: u32() };
		case TYPE.TXT:
			return { strings: Array.from({ length: g.int(1, 3) }, () => g.bytes(0, 40)) };
		case TYPE.SRV:
			return { priority: u16(), weight: u16(), port: u16(), target: name() };
		case TYPE.NAPTR:
			return { order: u16(), preference: u16(), flags: g.bytes(0, 3), services: g.bytes(0, 12), regexp: g.bytes(0, 20), replacement: name() };
		case TYPE.CAA: {
			const tag = Array.from({ length: g.int(1, 15) }, () => g.pick([..."abcdefghijklmnopqrstuvwxyz0123456789"])).join("");
			return { flags: u8(), tag, value: g.bytes(0, 30) };
		}
		case TYPE.TLSA:
			return { usage: u8(), selector: u8(), matchingType: u8(), data: g.bytes(1, 40) };
		case TYPE.SSHFP:
			return { algorithm: u8(), fpType: u8(), fingerprint: g.bytes(1, 32) };
		case TYPE.DS:
		case TYPE.CDS:
			return { keyTag: u16(), algorithm: u8(), digestType: u8(), digest: g.bytes(1, 48) };
		case TYPE.DNSKEY:
		case TYPE.CDNSKEY:
			return { flags: u16(), protocol: u8(), algorithm: u8(), publicKey: g.bytes(1, 64) };
		case TYPE.RRSIG:
			return {
				typeCovered: g.pick(someTypes),
				algorithm: u8(),
				labels: u8(),
				originalTtl: u32(),
				expiration: u32(),
				inception: u32(),
				keyTag: u16(),
				signerName: name(),
				signature: g.bytes(1, 64)
			};
		case TYPE.NSEC:
			return { next: name(), types: genTypes(g) };
		case TYPE.NSEC3:
			return { hashAlgorithm: u8(), flags: u8(), iterations: u16(), salt: g.bytes(0, 8), nextHashed: g.bytes(1, 20), types: genTypes(g) };
		case TYPE.NSEC3PARAM:
			return { hashAlgorithm: u8(), flags: u8(), iterations: u16(), salt: g.bytes(0, 8) };
		case TYPE.TSIG:
			return {
				algorithm: g.pick(["hmac-sha256.", "hmac-sha512.", "hmac-md5.sig-alg.reg.int."]),
				timeSigned: g.int(0, 2 ** 48 - 1),
				fudge: u16(),
				mac: g.bytes(0, 32),
				originalId: u16(),
				error: g.pick([0, 16, 17, 18, 22]),
				otherData: g.bytes(0, 6)
			};
		case TYPE.SVCB:
		case TYPE.HTTPS:
			return { priority: u16(), target: name(), params: g.chance(0.2) ? [] : genSvcParams(g) };
		case TYPE.OPT:
			return { options: genOptions(g) };
		default:
			return { data: g.bytes(0, 30) };
	}
}

/** @param {ReturnType<typeof prng>} g */
export function genOptions(g) {
	const out = [];
	const n = g.int(0, 4);
	for (let i = 0; i < n; i++) {
		switch (g.int(0, 4)) {
			case 0:
				out.push({ code: EDNS_OPTION.COOKIE, client: g.bytes(8, 8), server: g.chance(0.5) ? g.bytes(8, 32) : null });
				break;
			case 1:
				out.push({ code: EDNS_OPTION.TCP_KEEPALIVE, timeout: g.chance(0.5) ? g.int(0, 65535) : null });
				break;
			case 2:
				out.push({ code: EDNS_OPTION.PADDING, length: g.int(0, 64) });
				break;
			case 3:
				out.push({ code: EDNS_OPTION.EXTENDED_ERROR, infoCode: g.int(0, 30), extraText: genText(g) });
				break;
			default:
				out.push({ code: g.pick([3, 8, 9, 13, 65001]), data: g.bytes(0, 16) });
		}
	}
	return out;
}

/** A type for a generated record: a typed one most of the time, otherwise a type with no codec. */
export function genType(g) {
	const typed = TYPED.filter((t) => t !== TYPE.OPT && t !== TYPE.TSIG);
	if (g.chance(0.8)) return g.pick(typed);
	for (;;) {
		// 0 and 65535 are reserved and no record may use them (RFC 6895, CLDMV/digby#38)
		const t = g.int(1, 65534);
		if (!TYPED.includes(t)) return t;
	}
}

/**
 * The types the codec refuses the RFC 2136 empty-rdata update form for (mirrors `RDATA_REQUIRED` in message.mjs,
 * CLDMV/digby#38 — SIG(0) is class ANY with mandatory rdata).
 */
const NO_EMPTY_RDATA = new Set([TYPE.TSIG, TYPE.TKEY, TYPE.SIG, TYPE.IXFR, TYPE.AXFR, TYPE.MAILA, TYPE.MAILB]);

/**
 * A record, sometimes of an update form (class ANY / NONE with empty rdata).
 * @param {ReturnType<typeof prng>} g
 * @param {string[]} pool
 */
export function genRecord(g, pool, type = genType(g)) {
	const cls = g.chance(0.85) ? CLASS.IN : g.pick([CLASS.CH, CLASS.HS, CLASS.NONE, CLASS.ANY, 1000]);
	const data = (cls === CLASS.ANY || cls === CLASS.NONE) && g.chance(0.5) && !NO_EMPTY_RDATA.has(type) ? null : fitData(cls, genRdata(g, type, pool));
	return { name: genName(g, pool), type, class: cls, ttl: g.int(0, 0x7fffffff), data };
}

/** In class ANY / NONE a zero-length generic rdata IS the RFC 2136 update form: it reads back as `data: null` (CLDMV/digby#37). */
export function fitData(cls, data) {
	if ((cls === CLASS.ANY || cls === CLASS.NONE) && data?.data instanceof Uint8Array && data.data.length === 0) return null;
	return data;
}

/** @param {ReturnType<typeof prng>} g */
export function genMessage(g, { maxRecords = 4 } = {}) {
	const pool = [];
	const edns = g.chance(0.6)
		? { udpSize: g.chance(0.5) ? 1232 : g.int(0, 65535), version: g.chance(0.9) ? 0 : g.int(0, 255), dnssecOk: g.chance(0.5), z: g.chance(0.9) ? 0 : g.int(0, 0x7fff), options: genOptions(g) }
		: null;
	const section = (max) => {
		const out = [];
		const n = g.int(0, max);
		while (out.length < n) {
			// sometimes a multi-record RRset
			const first = genRecord(g, pool);
			out.push(first);
			if (g.chance(0.3) && first.data !== null) {
				for (let k = g.int(1, 3); k > 0 && out.length < n + 3; k--) {
					out.push({ ...first, data: fitData(first.class, genRdata(g, first.type, pool)) });
				}
			}
		}
		// half the time, shuffle the section so RRsets interleave: the encoder must keep record order — record order is
		// meaning (CLDMV/digby#36) — so the round-trip target is the input itself, and a truncating encode must still never
		// send part of an interleaved RRset
		return g.chance(0.5) ? shuffled(out, g) : out;
	};
	const additionals = section(Math.max(1, maxRecords - 1));
	if (g.chance(0.15)) additionals.push({ name: genName(g, pool), type: TYPE.TSIG, class: CLASS.ANY, ttl: 0, data: genRdata(g, TYPE.TSIG, pool) });
	return {
		id: g.int(0, 65535),
		flags: {
			qr: g.chance(0.5),
			opcode: g.chance(0.8) ? 0 : g.int(0, 15),
			aa: g.chance(0.5),
			tc: g.chance(0.1),
			rd: g.chance(0.5),
			ra: g.chance(0.5),
			z: g.chance(0.05),
			ad: g.chance(0.3),
			cd: g.chance(0.2)
		},
		rcode: edns ? g.int(0, 4095) : g.int(0, 15),
		// the question type is 1..65534: 0 and 65535 are reserved and the codec refuses them (CLDMV/digby#38)
		questions: Array.from({ length: g.int(0, 2) }, () => ({ name: genName(g, pool), type: g.int(1, 65534), class: g.chance(0.9) ? 1 : g.int(0, 65535) })),
		answers: section(maxRecords),
		authorities: section(Math.max(1, maxRecords - 1)),
		additionals,
		edns
	};
}

/** Fisher-Yates with the generator, so a section's records end up in any order and multi-record RRsets can be split apart. */
export function shuffled(list, g) {
	const out = [...list];
	for (let i = out.length - 1; i > 0; i--) {
		const j = g.int(0, i);
		[out[i], out[j]] = [out[j], out[i]];
	}
	return out;
}

/**
 * The codec's RRset key: same owner (case-insensitive), type and class; an RRSIG also by the type it covers. Mirrors
 * `rrsets` in src/lib/wire/message.mjs so tests can state which records form one RRset (CLDMV/digby#36).
 * @param {object} rec
 * @returns {string}
 */
export function rrsetKey(rec) {
	return `${nameKey(rec.name)}|${rec.type}|${rec.class ?? CLASS.IN}|${rec.type === TYPE.RRSIG ? rec.data?.typeCovered : ""}`;
}

/**
 * Whether `kept` is what a truncating encode may leave of `all` (CLDMV/digby#36, RFC 2181 9): the kept records sit at their
 * original positions (a subsequence of `all` in its order), they are exactly some whole RRsets — each set wholly present or
 * wholly absent — and the surviving sets come in first-seen order, so nothing was dropped ahead of something kept. Records
 * are compared with `expect(...).toEqual`, so a mismatch asserts with a diff rather than returning false quietly.
 * @param {object[]} kept - the decoded survivors
 * @param {object[]} all - the section's records as they went in
 * @returns {boolean}
 */
export function wholeSetPrefix(kept, all) {
	const firstSeen = [];
	const seen = new Map();
	for (const rec of all) {
		const k = rrsetKey(rec);
		if (!seen.has(k)) {
			seen.set(k, true);
			firstSeen.push(k);
		}
	}
	const keptKeys = [];
	const keptSeen = new Map();
	for (const rec of kept) {
		const k = rrsetKey(rec);
		if (!keptSeen.has(k)) {
			keptSeen.set(k, true);
			keptKeys.push(k);
		}
	}
	if (keptKeys.length > firstSeen.length) return false;
	for (let i = 0; i < keptKeys.length; i++) if (keptKeys[i] !== firstSeen[i]) return false;
	const counts = new Map();
	for (const rec of all) counts.set(rrsetKey(rec), (counts.get(rrsetKey(rec)) ?? 0) + 1);
	const keptCounts = new Map();
	for (const rec of kept) keptCounts.set(rrsetKey(rec), (keptCounts.get(rrsetKey(rec)) ?? 0) + 1);
	for (const [k, n] of keptCounts) if (counts.get(k) !== n) return false;
	// the survivors, in order, must be exactly the kept sets' records at their original positions
	const expected = all.filter((rec) => keptCounts.has(rrsetKey(rec)));
	if (expected.length !== kept.length) return false;
	for (let i = 0; i < kept.length; i++) expect(kept[i]).toEqual(expected[i]);
	return true;
}

/** Hex helpers for fixtures and regression bytes. */
export const hex = {
	/** @param {string} s - hex digits, whitespace and `;` comments to end of line ignored */
	from(s) {
		const clean = s.replace(/;[^\n]*/g, "").replace(/\s+/g, "");
		const out = new Uint8Array(clean.length / 2);
		for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
		return out;
	},
	/** @param {Uint8Array} b */
	to(b) {
		return Buffer.from(b).toString("hex");
	}
};
