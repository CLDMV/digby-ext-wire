/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/capped-scaling.test.vitest.mjs
 */

/**
 * @fileoverview CLDMV/digby#43: encodeCapped's truncation trials must not get slower per RRset as a message grows. The bound
 * is a COUNT of record writes — `wireCounters.recordWrites`, incremented once per record any encode touches — not wall-clock:
 * the incremental encode measures each set's octet contribution once, writes an over-the-limit trial once, and writes the
 * survivors once for good, so the count stays a small constant multiple of the records. The round-2 trials re-encoded the
 * kept tail of every set and scanned to the end of the section on every trial, which grew quadratically on exactly these
 * two shapes.
 */

import { describe, expect, it } from "vitest";
import { CLASS, TYPE } from "../../src/lib/wire/constants.mjs";
import { decodeMessage, encodeCapped, wireCounters } from "../../src/lib/wire/message.mjs";

// A 100-label apex of one-octet labels: 201 wire octets, the "long apex" shape of CLDMV/digby#40.
const apex = Array.from({ length: 100 }, (_, i) => String.fromCharCode(0x61 + (i % 26))).join(".") + ".";

/** `sets` RRsets of `perSet` A records each, interleaved round-robin: set j's records sit at positions j, j+sets, j+2*sets, ... */
const interleaved = (sets, perSet) => ({
	id: 0x0201,
	flags: { qr: true, ra: true },
	questions: [{ name: apex, type: TYPE.A, class: CLASS.IN }],
	answers: Array.from({ length: sets * perSet }, (_, i) => ({
		name: `n${i % sets}.` + apex,
		type: TYPE.A,
		class: CLASS.IN,
		ttl: 0,
		data: { address: "127.0.0.1" }
	}))
});

/** Every record its own RRset: `n` distinct owners sharing the question's suffix — the shape where the trials used to scan to the end. */
const distinct = (n) => ({
	id: 0x0201,
	flags: { qr: true, ra: true },
	questions: [{ name: "example.", type: TYPE.A, class: CLASS.IN }],
	answers: Array.from({ length: n }, (_, i) => ({ name: `h${i}.example.`, type: TYPE.A, class: CLASS.IN, ttl: 0, data: { address: "127.0.0.1" } }))
});

/** The decoded records are whole RRsets only, in first-seen order, each complete: `sets` sets named n0..n{sets-1}. */
function expectWholeSets(records, perSet, sets) {
	const names = [];
	const counts = new Map();
	for (const rec of records) {
		if (!counts.has(rec.name)) names.push(rec.name);
		counts.set(rec.name, (counts.get(rec.name) ?? 0) + 1);
	}
	expect(names, "the surviving sets, in first-seen order").toEqual(Array.from({ length: sets }, (_, j) => `n${j}.` + apex));
	for (const name of names) expect(counts.get(name), `${name} complete`).toBe(perSet);
}

describe("encodeCapped scaling (CLDMV/digby#43)", () => {
	it("keeps the trials' record writes flat across interleaved RRsets", () => {
		const sets = 100;
		const perSet = 29;
		const n = sets * perSet;
		const m = interleaved(sets, perSet);
		// everything fits: the round-2 trials re-encoded the kept tail once per set (~146,000 record writes here); the
		// incremental trials measure each set once and write the survivors once for good
		wireCounters.recordWrites = 0;
		const full = encodeCapped(m, { limit: 65535 });
		const fullWrites = wireCounters.recordWrites;
		expect(full.truncated).toBe(false);
		const d = decodeMessage(full.bytes);
		expect(d.flags.tc).toBe(false);
		expectWholeSets(d.answers, perSet, sets);
		expect(fullWrites, `${fullWrites} record writes for ${n} records`).toBeLessThan(4 * n);
		// and under a limit that truncates mid-section: the count stays proportional and only whole sets go
		wireCounters.recordWrites = 0;
		const tight = encodeCapped(m, { limit: 20000 });
		const tightWrites = wireCounters.recordWrites;
		expect(tight.truncated).toBe(true);
		const t = decodeMessage(tight.bytes);
		expect(t.flags.tc).toBe(true);
		const keptSets = new Set(t.answers.map((r) => r.name)).size;
		expect(keptSets, "the limit dropped sets").toBeLessThan(sets);
		expectWholeSets(t.answers, perSet, keptSets);
		expect(tightWrites, `${tightWrites} record writes for ${n} records`).toBeLessThan(4 * n);
	}, 120_000);

	it("keeps the trials' record writes flat on a huge input with a small output", () => {
		const n = 320000;
		const m = distinct(n);
		wireCounters.recordWrites = 0;
		const { bytes, truncated } = encodeCapped(m, { limit: 65535 });
		const writes = wireCounters.recordWrites;
		expect(truncated).toBe(true);
		expect(bytes.length).toBeLessThanOrEqual(65535);
		const d = decodeMessage(bytes);
		expect(d.flags.tc).toBe(true);
		const kept = d.answers.length;
		expect(kept, "the 65,535-octet output keeps a fraction of the 320,000 records").toBeGreaterThan(1000);
		// every kept record is its own whole set, in first-seen order: h0..h{kept-1}
		expect(d.answers[0].name).toBe("h0.example.");
		expect(d.answers[kept - 1].name).toBe(`h${kept - 1}.example.`);
		expect(writes, `${writes} record writes for ${n} records`).toBeLessThan(n / 10);
	}, 120_000);

	// The suffix these shapes share lives only in the section's names — the question does not carry it — so a probe
	// that measures a set against nothing but the targets written before the section pays the full 60-octet suffix
	// for every record, and the over-the-bound trials re-encode the kept tail (CLDMV/digby#43).
	const sectionSuffix = `${"abc".repeat(20)}.`; // 60 octets
	const sectionSuffixShape = (n, type, data) => ({
		id: 0x0201,
		flags: { qr: true, ra: true },
		questions: [{ name: "example.", type: TYPE.A, class: CLASS.IN }],
		answers: Array.from({ length: n }, (_, i) => ({ name: `h${i}.${sectionSuffix}`, type, class: CLASS.IN, ttl: 0, data: data(i) }))
	});
	const aRecord = () => ({ address: "127.0.0.1" });
	const mxRecord = (i) => ({ preference: 10, exchange: `m${i}.${sectionSuffix}` });

	it("bounds the trials' writes by the kept records when the shared suffix is only in the section (CLDMV/digby#43)", () => {
		const n = 5000;
		for (const [tag, type, data] of [
			["distinct A owners", TYPE.A, aRecord],
			["MX with the suffix in both owner and rdata", TYPE.MX, mxRecord]
		]) {
			const m = sectionSuffixShape(n, type, data);
			wireCounters.recordWrites = 0;
			const r = encodeCapped(m, { limit: 65535 });
			const writes = wireCounters.recordWrites;
			expect(r.truncated, `${tag}: the limit truncates`).toBe(true);
			const d = decodeMessage(r.bytes);
			const kept = d.answers.length;
			expect(kept, `${tag}: keeps a fraction of the records`).toBeGreaterThan(1000);
			// the survivors are whole sets in first-seen order
			expect(d.answers[0].name).toBe(`h0.${sectionSuffix}`);
			expect(d.answers[kept - 1].name).toBe(`h${kept - 1}.${sectionSuffix}`);
			// one probe measurement per kept set plus one write of the survivors: a small constant per kept
			// record — the probe used to pay ~61 per kept record here (CLDMV/digby#44 holds the single-pass
			// fast path for fitting messages)
			expect(writes, `${tag}: ${writes} record writes for ${kept} kept records`).toBeLessThanOrEqual(5 * kept);
		}
	}, 120_000);

	it("keeps the truncating encode's record writes flat from 5,000 to 320,000 records (CLDMV/digby#43)", () => {
		const count = (n) => {
			const m = distinct(n);
			wireCounters.recordWrites = 0;
			encodeCapped(m, { limit: 65535 });
			return wireCounters.recordWrites;
		};
		const small = count(5000);
		const large = count(320000);
		// the work is bounded by the output (the kept records), not the input: past the limit, more input records
		// cost grouping only, no record writes
		expect(large, `${large} writes at 320k records vs ${small} at 5k`).toBeLessThanOrEqual(2 * small + 1000);
	}, 120_000);
});
