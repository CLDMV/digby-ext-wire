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
import { WireError } from "../../src/lib/wire/errors.mjs";
import { decodeMessage, encodeCapped, encodeMessage, wireCounters } from "../../src/lib/wire/message.mjs";

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
		// the scratch encodes are part of the counted work: the counter must exist on the codec's counters surface,
		// not be conjured by this test's own reset assignment
		expect("scratchEncodes" in wireCounters, "wireCounters counts scratch encodes").toBe(true);
		const count = (n) => {
			const m = distinct(n);
			wireCounters.recordWrites = 0;
			wireCounters.scratchEncodes = 0;
			encodeCapped(m, { limit: 65535 });
			// every encode the truncation does is counted: record writes through writeRecord, and the scratch
			// encodes (the tail's uncompressed size measurement, the near-boundary tail probes) through
			// scratchEncodes — the round-4 shift table measured every record of the section uncounted
			return wireCounters.recordWrites + wireCounters.scratchEncodes;
		};
		const small = count(5000);
		const large = count(320000);
		// the work is bounded by the output (the kept records), not the input: past the limit, more input records
		// cost grouping only, no record writes
		expect(large, `${large} writes at 320k records vs ${small} at 5k`).toBeLessThanOrEqual(2 * small + 1000);
	}, 120_000);

	// The shape the round-4 exact trial goes quadratic on: M two-record NS sets whose first records all come first
	// (rdata `x.example.`, compressing against the question) and whose second records all come last, sharing a long
	// rdata suffix no other record carries. Every set's shift-gate measurement is flagged (the pending first records
	// between each set's own two records bound the shift far past the registration boundary), so every set falls to
	// the exact trial — and each trial re-encodes the kept second records sitting between the candidate's two, which
	// grows with the set index: quadratic record writes on a linear message (CLDMV/digby#43).
	const pairSuffix = "abc".repeat(20); // a 60-octet label only the second records' rdata carries
	const paired = (M) => ({
		id: 0x0201,
		flags: { qr: true, ra: true },
		questions: [{ name: "example.", type: TYPE.NS, class: CLASS.IN }],
		answers: [
			...Array.from({ length: M }, (_, j) => ({ name: `n${j}.example.`, type: TYPE.NS, class: CLASS.IN, ttl: 0, data: { target: "x.example." } })),
			...Array.from({ length: M }, (_, j) => ({ name: `n${j}.example.`, type: TYPE.NS, class: CLASS.IN, ttl: 0, data: { target: `m${j}.${pairSuffix}.` } }))
		]
	});

	it("bounds the work on interleaved pending sets whose second records share a suffix (CLDMV/digby#43)", () => {
		// the peak of the r8 shape (M = 900..1250, 1,800..2,500 records — where the model scan crosses the pointer
		// boundary and one registration's crossing unseats every set's second record) is sampled alongside 800 and
		// 1,600 records (CLDMV/digby#43, round 9)
		for (const M of [100, 200, 400, 800, 900, 1000, 1250, 1600]) {
			const records = 2 * M;
			const m = paired(M);
			// "full" is the whole encode when it fits the largest message, and the largest message itself when the
			// paired shape does not (M=1600 overflows 65,535 — the size that failed round 4)
			let full;
			let fullTruncates = false;
			try {
				full = encodeMessage(m).length;
			} catch (err) {
				if (!(err instanceof WireError) || err.code !== "MESSAGE_TOO_LARGE") throw err;
				full = 65535;
				fullTruncates = true;
			}
			for (const [tag, limit] of [
				["full", full],
				["one under full", full - 1],
				["90%", Math.floor((full * 9) / 10)]
			]) {
				wireCounters.recordWrites = 0;
				wireCounters.scratchEncodes = 0;
				wireCounters.modelWork = 0;
				const r = encodeCapped(m, { limit });
				// every unit of counted work: record writes, the scratch encodes, and the model's own work — the
				// round-4 bound counted only recordWrites, and the model scans it did not see are real work
				const writes = wireCounters.recordWrites + wireCounters.scratchEncodes + wireCounters.modelWork;
				const d = decodeMessage(r.bytes);
				expect(d.flags.tc, `M=${M} ${tag}: the truncation flag`).toBe(limit < full || fullTruncates);
				// the survivors are whole RRsets in first-seen order, each complete
				const counts = new Map();
				for (const rec of d.answers) counts.set(rec.name, (counts.get(rec.name) ?? 0) + 1);
				for (const [name, c] of counts) expect(c, `M=${M} ${tag}: ${name} complete`).toBe(2);
				expect(r.bytes.length, `M=${M} ${tag}: within the limit`).toBeLessThanOrEqual(limit);
				// every record is written a small constant number of times: the round-4 trials wrote each record
				// ~24-200 times on this shape (a fresh exact trial per set, each re-encoding the kept second
				// records sitting between the candidate's two), growing with M. The constant is recalibrated for
				// round 9 (CLDMV/digby#43): the round-8 code spent one cascade round — one probe setup, one drain
				// cycle — per re-measured set, and the drain's global cumPos pop re-keyed every near-boundary
				// registration once per round, so the model work saturated at ~92,600 units and the peak (M=900,
				// 1,800 records) measured 54.9 per record. The round-9 cascade re-measures every queued set's
				// affected records in one merged probe pass per wave, so the per-set overhead and the drain churn
				// collapse: measured (the harness is tmp/agents/r9/measure3.mjs, run inside a test pod) 12.5 per
				// record at M<=400 (the stream never reaches 0x4000 there — pure base machinery), 22.0 at M=800,
				// 30.1 at the peak M=900 and 21.8 at M=1250, limit full or one under — flat across the crossing
				// regime's M, the same work per record everywhere. The bound stays a constant multiple, which is
				// what any quadratic regression blows through: a quadratic regression would blow straight through
				// 40 x at every sampled M.
				expect(writes, `M=${M} ${tag}: ${writes} units of work for ${records} records`).toBeLessThanOrEqual(40 * records);
			}
		}
	}, 120_000);

	// The shape the round-5 cascade goes quadratic on: a filler TXT parks the stream just under 0x4000, then one
	// NS RRset's records interleave with many small distinct TXT sets. Every TXT keep inserts octets that push part
	// of the NS set's registrations across the pointer range, and the round-5 flip scan re-measured ALL of the NS
	// set's records for every flip — 49.6/97.6/190.9/191.6 writes per record at 301/601/1201/2401 records. The fix
	// re-measures only the records the flip touches, and every unit of model work — the scans included — is counted
	// in wireCounters.modelWork, so the bound below is on recordWrites + scratchEncodes + modelWork together.
	// Round 7 (CLDMV/digby#43): modelWork now counts the Fenwick operations the JSDoc always claimed (one unit per
	// set/prefix call, not per tree step), and recordWrites counts the plain attempt's full pass (C1), so the round-6
	// absolute figures are not comparable — flatness in n is the invariant. What each counter counts, what it does
	// not, and the reproducible harness: tmp/agents/r7-capped/measure-capped.mjs (gitignored scratch, run inside a
	// test pod).
	const boundaryShape = (n) => {
		// 16,000 octets of filler as 63 character-strings (a character-string is at most 255 octets): the stream
		// sits just under 0x4000 before the first keep, so the keeps cross the registration boundary immediately
		const filler = [];
		for (let left = 16000; left > 0; left -= 255) filler.push(new Uint8Array(Math.min(255, left)).fill(0x66));
		const answers = [
			{ name: "f.t.", type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: { strings: filler } },
			{ name: "e.t.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: "u.s0.example." } }
		];
		// the rest: alternating distinct TXT sets (~44 octets each) and the e.t. NS set's remaining records
		const rest = n - 2;
		for (let i = 0; i < rest; i++) {
			if (i % 2 === 0) answers.push({ name: `x${i / 2}.t.`, type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: { strings: [new Uint8Array(28).fill(0x78)] } });
			else answers.push({ name: "e.t.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: `u.s${(i + 1) / 2}.example.` } });
		}
		return { id: 1, flags: { qr: true }, questions: [{ name: "example.", type: TYPE.A, class: CLASS.IN }], answers };
	};

	it("keeps the model's work linear when keeps shift registrations across 0x4000 (CLDMV/digby#43)", () => {
		const work = () => {
			expect("modelWork" in wireCounters, "wireCounters counts model work").toBe(true);
			return wireCounters.recordWrites + wireCounters.scratchEncodes + wireCounters.modelWork;
		};
		for (const n of [301, 1201, 2401]) {
			const m = boundaryShape(n);
			// "full" is the whole encode when it fits the largest message and the largest message itself when the
			// 2,401-record shape does not (the filler alone is 16 KB, so 2,401 records overflow 65,535)
			let full;
			let fullTruncates = false;
			try {
				full = encodeMessage(m).length;
			} catch (err) {
				if (!(err instanceof WireError) || err.code !== "MESSAGE_TOO_LARGE") throw err;
				full = 65535;
				fullTruncates = true;
			}
			const nsRecords = 1 + Math.floor((n - 2) / 2);
			for (const [tag, limit] of [
				["full", full],
				["one under full", full - 1],
				["90%", Math.floor((full * 9) / 10)]
			]) {
				wireCounters.recordWrites = 0;
				wireCounters.scratchEncodes = 0;
				wireCounters.modelWork = 0;
				const r = encodeCapped(m, { limit });
				const w = work();
				const d = decodeMessage(r.bytes);
				expect(d.flags.tc, `n=${n} ${tag}: the truncation flag`).toBe(limit < full || fullTruncates);
				// the survivors are whole RRsets in first-seen order, each complete
				const counts = new Map();
				for (const rec of d.answers) counts.set(rec.name, (counts.get(rec.name) ?? 0) + 1);
				for (const [name, c] of counts) expect(c, `n=${n} ${tag}: ${name} complete`).toBe(name === "e.t." ? nsRecords : 1);
				expect(r.bytes.length, `n=${n} ${tag}: within the limit`).toBeLessThanOrEqual(limit);
				// linear: the same small constant multiple of the records at every size and limit — the round-5
				// cascade spent ~50-192 record writes per record here and grew with n. Recalibrated for round 8
				// (CLDMV/digby#43): the largest-fit scan folds past where round 7's greedy stopped, so the
				// crossing-driven re-measures cover more of the message — measured 18.6 per record at n=301 (limit
				// one under full), 18.1 at n=1201, 9.8 at n=2401 (the frozen point cuts the fold there), flat
				// across n. 24 x records keeps the round-7 margin over the measured bump.
				expect(w, `n=${n} ${tag}: ${w} units of work for ${n} records`).toBeLessThanOrEqual(24 * n);
			}
		}
	}, 120_000);
});
