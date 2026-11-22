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
import { nameKey, parseName, formatName, readName, writeName } from "../../src/lib/wire/names.mjs";
import { formatRecord, parseRecord } from "../../src/lib/wire/presentation.mjs";
import { TYPED, decodeRdataBytes, encodeRdataBytes, formatRdata, parseRdata } from "../../src/lib/wire/rdata/index.mjs";
import { genMessage, genName, genRdata, genRecord, prng, seedFromEnv } from "../helpers/wire-gen.mjs";

const SEED = seedFromEnv("DIGBY_PROPERTY_SEED");
const MESSAGES = Number(process.env.DIGBY_PROPERTY_MESSAGES || 400);
const PER_TYPE = Number(process.env.DIGBY_PROPERTY_PER_TYPE || 60);
console.log(`wire property tests: DIGBY_PROPERTY_SEED=${SEED} messages=${MESSAGES} perType=${PER_TYPE}`);

const keyOf = (r) => `${nameKey(r.name)}|${r.type}|${r.class}|${r.type === TYPE.RRSIG ? r.data?.typeCovered : ""}`;

/** Whether `kept` is a prefix of `all` that ends on an RRset boundary. */
function isRrsetPrefix(kept, all) {
	if (kept.length > all.length) return false;
	for (let i = 0; i < kept.length; i++) expect(kept[i]).toEqual(all[i]);
	return kept.length === 0 || kept.length === all.length || keyOf(all[kept.length]) !== keyOf(all[kept.length - 1]);
}

describe(`wire properties (seed ${SEED})`, () => {
	it("decode(encode(message)) deep-equals the message, compressed or not, and stays within 65535 octets", () => {
		const g = prng(SEED);
		for (let i = 0; i < MESSAGES; i++) {
			const m = genMessage(g);
			const bytes = encodeMessage(m);
			expect(bytes.length).toBeLessThanOrEqual(65535);
			// genMessage emits up to two questions; the decode default is one (the server path), so say so
			expect(decodeMessage(bytes, { maxQuestions: 2 })).toEqual(m);
			const plain = encodeMessage(m, { compress: false });
			expect(plain.length).toBeGreaterThanOrEqual(bytes.length);
			expect(decodeMessage(plain, { maxQuestions: 2 })).toEqual(m);
		}
	});

	it("a capped encode never exceeds the cap and truncates whole RRsets", () => {
		const g = prng(SEED ^ 0x5bd1e995);
		for (let i = 0; i < MESSAGES; i++) {
			const m = genMessage(g, { maxRecords: 8 });
			const full = encodeMessage(m).length;
			const tsig = m.additionals.filter((r) => r.type === TYPE.TSIG);
			const minimal = encodeMessage({ ...m, answers: [], authorities: [], additionals: tsig }).length;
			const limit = g.int(12, full + 16);
			if (limit < minimal) {
				expect(() => encodeCapped(m, { limit })).toThrow(WireError);
				continue;
			}
			const { bytes, truncated } = encodeCapped(m, { limit });
			expect(bytes.length).toBeLessThanOrEqual(limit);
			const d = decodeMessage(bytes, { maxQuestions: 2 });
			expect(d.flags.tc).toBe(m.flags.tc || truncated);
			expect(d.edns).toEqual(m.edns);
			expect(isRrsetPrefix(d.answers, m.answers)).toBe(true);
			expect(isRrsetPrefix(d.authorities, m.authorities)).toBe(true);
			const addKept = d.additionals.filter((r) => r.type !== TYPE.TSIG);
			const addAll = m.additionals.filter((r) => r.type !== TYPE.TSIG);
			expect(isRrsetPrefix(addKept, addAll)).toBe(true);
			expect(d.additionals.filter((r) => r.type === TYPE.TSIG)).toEqual(tsig);
			// TC exactly when an answer or authority RRset was dropped
			const droppedPrimary = d.answers.length < m.answers.length || d.authorities.length < m.authorities.length;
			expect(truncated).toBe(droppedPrimary);
			if (droppedPrimary) expect(addKept).toEqual([]);
			if (d.answers.length < m.answers.length) expect(d.authorities).toEqual([]);
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
