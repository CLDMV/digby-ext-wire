/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/property.test.vitest.mjs
 */

/**
 * Property tests over generated values: decode(encode(x)) deep-equals x for messages, rdata of every type and names;
 * parse(format(x)) deep-equals x in presentation form; a capped encode never exceeds its cap and truncates at RRset
 * boundaries. The seed comes from DIGBY_PROPERTY_SEED (or is random) and is printed so a failure replays exactly.
 */

import { describe, expect, it } from "vitest";
import { Reader, Writer } from "../../src/lib/wire/buffer.mjs";
import { TYPE } from "../../src/lib/wire/constants.mjs";
import { WireError } from "../../src/lib/wire/errors.mjs";
import { decodeMessage, encodeCapped, encodeMessage } from "../../src/lib/wire/message.mjs";
import { parseName, formatName, readName, writeName } from "../../src/lib/wire/names.mjs";
import { formatRecord, parseRecord } from "../../src/lib/wire/presentation.mjs";
import { TYPED, decodeRdataBytes, encodeRdataBytes, formatRdata, parseRdata } from "../../src/lib/wire/rdata/index.mjs";
import { genMessage, genName, genRdata, genRecord, prng, regroup, regroupMessage, rrsetKey, seedFromEnv } from "../helpers/wire-gen.mjs";

const SEED = seedFromEnv("DIGBY_PROPERTY_SEED");
const MESSAGES = Number(process.env.DIGBY_PROPERTY_MESSAGES || 400);
const PER_TYPE = Number(process.env.DIGBY_PROPERTY_PER_TYPE || 60);
console.log(`wire property tests: DIGBY_PROPERTY_SEED=${SEED} messages=${MESSAGES} perType=${PER_TYPE}`);

/**
 * Whether `kept` is a prefix of `regroup(all)` that ends on an RRset boundary. The encoder emits a section in canonical
 * (grouped) order — a set's records travel together even when the message interleaved them (CLDMV/digby#36) — so what
 * survives truncation is a whole-set prefix of the grouped section, not of the input order.
 */
function isGroupedPrefix(kept, all) {
	const grouped = regroup(all);
	if (kept.length > grouped.length) return false;
	for (let i = 0; i < kept.length; i++) expect(kept[i]).toEqual(grouped[i]);
	return kept.length === 0 || kept.length === grouped.length || rrsetKey(grouped[kept.length]) !== rrsetKey(grouped[kept.length - 1]);
}

describe(`wire properties (seed ${SEED})`, () => {
	it("decode(encode(message)) deep-equals the message, compressed or not, and stays within 65535 octets", () => {
		const g = prng(SEED);
		for (let i = 0; i < MESSAGES; i++) {
			const m = genMessage(g);
			const bytes = encodeMessage(m);
			expect(bytes.length).toBeLessThanOrEqual(65535);
			// genMessage emits up to two questions; the decode default is one (the server path), so say so. genMessage may
			// interleave a section's RRsets, and the encoder emits them regrouped (whole sets, first-seen order), so the
			// round-trip target is the regrouped message (CLDMV/digby#36).
			const canonical = regroupMessage(m);
			expect(decodeMessage(bytes, { maxQuestions: 2 })).toEqual(canonical);
			const plain = encodeMessage(m, { compress: false });
			expect(plain.length).toBeGreaterThanOrEqual(bytes.length);
			expect(decodeMessage(plain, { maxQuestions: 2 })).toEqual(canonical);
		}
	});

	it("a capped encode never exceeds the cap and truncates whole RRsets", () => {
		const g = prng(SEED ^ 0x5bd1e995);
		for (let i = 0; i < MESSAGES; i++) {
			const m = genMessage(g, { maxRecords: 8 });
			// the capped encode refuses a message that already carries a TSIG record (CLDMV/digby#39): the generator sometimes
			// adds one, so drop it here — the capped encode is unsigned, and the reserve/append flow is covered in
			// tsig.test.vitest.mjs
			const unsigned = { ...m, additionals: m.additionals.filter((r) => r.type !== TYPE.TSIG) };
			const full = encodeMessage(unsigned).length;
			const minimal = encodeMessage({ ...unsigned, answers: [], authorities: [], additionals: [] }).length;
			const limit = g.int(12, full + 16);
			if (limit < minimal) {
				expect(() => encodeCapped(unsigned, { limit })).toThrow(WireError);
				continue;
			}
			const { bytes, truncated } = encodeCapped(unsigned, { limit });
			expect(bytes.length).toBeLessThanOrEqual(limit);
			const d = decodeMessage(bytes, { maxQuestions: 2 });
			expect(d.flags.tc).toBe(unsigned.flags.tc || truncated);
			expect(d.edns).toEqual(unsigned.edns);
			expect(isGroupedPrefix(d.answers, unsigned.answers)).toBe(true);
			expect(isGroupedPrefix(d.authorities, unsigned.authorities)).toBe(true);
			expect(isGroupedPrefix(d.additionals, unsigned.additionals)).toBe(true);
			// TC exactly when an answer or authority RRset was dropped
			const droppedPrimary = d.answers.length < unsigned.answers.length || d.authorities.length < unsigned.authorities.length;
			expect(truncated).toBe(droppedPrimary);
			if (droppedPrimary) expect(d.additionals).toEqual([]);
			if (d.answers.length < unsigned.answers.length) expect(d.authorities).toEqual([]);
			if (limit >= full) expect(truncated).toBe(false);
		}
	});

	it("every typed RR type round-trips on the wire and in presentation form", () => {
		const g = prng(SEED ^ 0x1b873593);
		for (const type of TYPED) {
			for (let i = 0; i < PER_TYPE; i++) {
				const data = genRdata(g, type, []);
				const wire = encodeRdataBytes(type, data);
				expect(decodeRdataBytes(type, wire)).toEqual(data);
				expect(parseRdata(type, formatRdata(type, data))).toEqual(data);
			}
		}
	});

	it("types without a codec round-trip as TYPEnnn / \\# octets", () => {
		const g = prng(SEED ^ 0xcc9e2d51);
		for (let i = 0; i < PER_TYPE * 4; i++) {
			let type;
			do type = g.int(0, 65535);
			while (TYPED.includes(type));
			const data = genRdata(g, type, []);
			expect(decodeRdataBytes(type, encodeRdataBytes(type, data))).toEqual(data);
			expect(parseRdata(type, formatRdata(type, data))).toEqual(data);
			const rec = { ...genRecord(g, [], type), data };
			expect(parseRecord(formatRecord(rec))).toEqual(rec);
		}
	});

	it("whole records round-trip through the presentation form", () => {
		const g = prng(SEED ^ 0xe6546b64);
		for (let i = 0; i < PER_TYPE * 10; i++) {
			const rec = genRecord(g, []);
			if (rec.data === null || rec.type === TYPE.OPT) continue;
			expect(parseRecord(formatRecord(rec))).toEqual(rec);
		}
	});

	it("names round-trip through wire and presentation", () => {
		const g = prng(SEED ^ 0x85ebca6b);
		const pool = [];
		const names = Array.from({ length: 300 }, () => genName(g, pool));
		const w = new Writer();
		for (const n of names) writeName(w, n, g.chance(0.7));
		const r = new Reader(w.finish());
		for (const n of names) {
			expect(readName(r)).toBe(n);
			expect(formatName(parseName(n))).toBe(n);
		}
		expect(r.remaining).toBe(0);
	});
});
