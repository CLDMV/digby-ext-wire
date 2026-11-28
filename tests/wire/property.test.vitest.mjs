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
import { Reader, Writer } from "../../src/lib/buffer.mjs";
import { CLASS, TYPE } from "../../src/lib/constants.mjs";
import { WireError } from "../../src/lib/errors.mjs";
import { appendTsig, decodeMessage, encodeCapped, encodeMessage, tsigRecordSize } from "../../src/lib/message.mjs";
import { parseName, formatName, readName, writeName } from "../../src/lib/names.mjs";
import { formatRecord, parseRecord } from "../../src/lib/presentation.mjs";
import { TYPED, decodeRdataBytes, encodeRdataBytes, formatRdata, parseRdata } from "../../src/lib/rdata/index.mjs";
import { fitData, genMessage, genName, genRdata, genRecord, prng, seedFromEnv, wholeSetPrefix } from "../helpers/wire-gen.mjs";

const SEED = seedFromEnv("DIGBY_PROPERTY_SEED");
const MESSAGES = Number(process.env.DIGBY_PROPERTY_MESSAGES || 400);
const PER_TYPE = Number(process.env.DIGBY_PROPERTY_PER_TYPE || 60);
console.log(`wire property tests: DIGBY_PROPERTY_SEED=${SEED} messages=${MESSAGES} perType=${PER_TYPE}`);

describe(`wire properties (seed ${SEED})`, () => {
	it("decode(encode(message)) deep-equals the message, compressed or not, and stays within 65535 octets", () => {
		const g = prng(SEED);
		for (let i = 0; i < MESSAGES; i++) {
			const m = genMessage(g);
			// genMessage sometimes adds a TSIG record; the encode refuses any message that carries one (CLDMV/digby#39 —
			// re-encoding a signed message cannot keep the MAC valid), so the round-trip target is the unsigned form
			const unsigned = { ...m, additionals: m.additionals.filter((r) => r.type !== TYPE.TSIG) };
			const bytes = encodeMessage(unsigned);
			expect(bytes.length).toBeLessThanOrEqual(65535);
			// genMessage emits up to two questions; the decode default is one (the server path), so say so. The encoder keeps
			// record order — record order is meaning, even when a section's RRsets interleave (CLDMV/digby#36) — so the
			// round-trip target is the message itself.
			expect(decodeMessage(bytes, { maxQuestions: 2 })).toEqual(unsigned);
			const plain = encodeMessage(unsigned, { compress: false });
			expect(plain.length).toBeGreaterThanOrEqual(bytes.length);
			expect(decodeMessage(plain, { maxQuestions: 2 })).toEqual(unsigned);
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
			let capped;
			try {
				capped = encodeCapped(unsigned, { limit });
			} catch (err) {
				// the capped encode refuses to truncate an UPDATE or a transfer — dropping RRsets would corrupt what the
				// message means (CLDMV/digby#43) — and the generator emits those opcodes and question types at random, so
				// a generated message that would truncate at this limit surfaces the refusal here
				expect(err).toBeInstanceOf(WireError);
				expect(err.code).toBe("TRUNCATION_REFUSED");
				continue;
			}
			const { bytes, truncated } = capped;
			expect(bytes.length).toBeLessThanOrEqual(limit);
			const d = decodeMessage(bytes, { maxQuestions: 2 });
			expect(d.flags.tc).toBe(unsigned.flags.tc || truncated);
			expect(d.edns).toEqual(unsigned.edns);
			expect(wholeSetPrefix(d.answers, unsigned.answers)).toBe(true);
			expect(wholeSetPrefix(d.authorities, unsigned.authorities)).toBe(true);
			expect(wholeSetPrefix(d.additionals, unsigned.additionals)).toBe(true);
			// TC exactly when an answer or authority RRset was dropped
			const droppedPrimary = d.answers.length < unsigned.answers.length || d.authorities.length < unsigned.authorities.length;
			expect(truncated).toBe(droppedPrimary);
			if (droppedPrimary) expect(d.additionals).toEqual([]);
			if (d.answers.length < unsigned.answers.length) expect(d.authorities).toEqual([]);
			if (limit >= full) expect(truncated).toBe(false);
		}
	});

	it("a random reserve/append round signs the capped encode (CLDMV/digby#39)", () => {
		const g = prng(SEED ^ 0x9e3779b9);
		for (let i = 0; i < MESSAGES; i++) {
			const m = genMessage(g, { maxRecords: 6 });
			// genMessage sometimes adds a TSIG itself; the capped encode refuses one, so sign after truncation
			const unsigned = { ...m, additionals: m.additionals.filter((r) => r.type !== TYPE.TSIG) };
			const tsig = { name: genName(g, []), type: TYPE.TSIG, class: CLASS.ANY, ttl: 0, data: { ...genRdata(g, TYPE.TSIG, []), originalId: unsigned.id } };
			const need = tsigRecordSize(tsig);
			const limit = g.int(12, encodeMessage(unsigned).length + 16);
			let capped;
			try {
				capped = encodeCapped(unsigned, { limit, reserveTsig: need });
			} catch (err) {
				expect(err).toBeInstanceOf(WireError); // the header, questions and OPT alone exceed limit - need
				continue;
			}
			expect(capped.bytes.length + need, `i ${i}`).toBeLessThanOrEqual(limit);
			const signed = appendTsig(capped, tsig);
			expect(signed.length, `i ${i}`).toBeLessThanOrEqual(limit);
			const d = decodeMessage(signed, { maxQuestions: 2 });
			expect(d.additionals.at(-1), `i ${i}`).toEqual(tsig);
			expect(d.additionals.at(-1).data.originalId, `i ${i}`).toBe(d.id);
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
			// 0 and 65535 are reserved at the record layer and the assertions below format and re-parse whole records
			do type = g.int(1, 65534);
			while (TYPED.includes(type));
			const data = genRdata(g, type, []);
			expect(decodeRdataBytes(type, encodeRdataBytes(type, data))).toEqual(data);
			expect(parseRdata(type, formatRdata(type, data))).toEqual(data);
			const base = genRecord(g, [], type);
			// fitData, because in class ANY / NONE a zero-length generic rdata IS the update form (CLDMV/digby#37)
			const rec = { ...base, data: fitData(base.class, data) };
			expect(parseRecord(formatRecord(rec))).toEqual(rec);
		}
	});

	it("whole records round-trip through the presentation form, including the update form's data: null", () => {
		const g = prng(SEED ^ 0xe6546b64);
		for (let i = 0; i < PER_TYPE * 10; i++) {
			const rec = genRecord(g, []);
			if (rec.type === TYPE.OPT) continue;
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
