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
import { c1Shape } from "../helpers/capped-oracle.mjs";

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

	// CLDMV/digby#44: a message that already fits must cost exactly one plain encode — the per-set trial
	// machinery never runs — and a message that fits EXACTLY at its limit takes that same single pass. The
	// count is of writes (`wireCounters.recordWrites`), not time.
	it("costs one plain encode when the message fits: record writes equal the record count (CLDMV/digby#44)", () => {
		const sets = 50;
		const perSet = 20;
		const m = interleaved(sets, perSet);
		// a fitting encode: the plain attempt IS the output, so each record is written exactly once
		wireCounters.recordWrites = 0;
		const r = encodeCapped(m, { limit: 65535 });
		expect(r.truncated).toBe(false);
		expect(wireCounters.recordWrites, `${wireCounters.recordWrites} writes for ${sets * perSet} records`).toBe(sets * perSet);
		// the fitting output is byte-identical to the plain encode (nothing drops, so nothing can differ)
		expect(r.bytes).toEqual(encodeMessage(m));
		// a message that fits EXACTLY at its limit still takes the single-pass path
		const full = encodeMessage(m).length;
		wireCounters.recordWrites = 0;
		const exact = encodeCapped(m, { limit: full });
		expect(exact.truncated).toBe(false);
		expect(wireCounters.recordWrites, `exactly at the limit: ${wireCounters.recordWrites} writes for ${sets * perSet} records`).toBe(sets * perSet);
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

	// The drift-window shapes with the counted work bounded from BOTH sides (round 10, CLDMV/digby#43). The
	// output differential cannot see the boundary mutants whose lie self-corrects through the exact trials —
	// an understated total only adds candidates the trial rejects — so these mutants are killed by the model's
	// own counted work instead, on the shapes where their site fires:
	// - the UPPER bound kills the classification mutant (an adoption landing exactly on 0x4000 classified
	//   in-range): its misrouted entry costs an extra drain re-key and re-measure cycle — measured 89 units on
	//   the golden shape against the clean 63 (the mutant run is tmp/agents/r10/logs/calib.log).
	// - the LOWER bound kills the range-check mutant (a target at exactly 0x4000 visible to the probe): the
	//   phantom compression understates the tree, the drain pops fewer registrations, and the re-measure churn
	//   it skips is real counted work — measured 18,505 on the sweep against the clean 18,761; the sweep here
	//   is 21 fillers wide, so the mutant's shortfall scales with it.
	it("keeps the model's counted work exact at the 0x4000 boundary on the drift-window shapes (CLDMV/digby#43)", () => {
		const golden = () => {
			const filler = [];
			for (let left = 16000; left > 0; left -= 255) filler.push(new Uint8Array(Math.min(255, left)).fill(0x78));
			return {
				id: 1,
				flags: { qr: true },
				questions: [{ name: "example.", type: TYPE.A, class: CLASS.IN }],
				answers: [
					{ name: "a.test.", type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: { strings: filler } },
					{ name: "b.test.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: "n0.example." } },
					{ name: "a.test.", type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: { strings: [new Uint8Array(231).fill(0x78)] } },
					{ name: "b.test.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: `n1.${"x".repeat(63)}.example.` } },
					{ name: "b.test.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: `n2.${"x".repeat(63)}.example.` } }
				]
			};
		};
		const m = golden();
		const full = encodeMessage(m).length;
		wireCounters.recordWrites = 0;
		wireCounters.scratchEncodes = 0;
		wireCounters.modelWork = 0;
		const capped = encodeCapped(m, { limit: full - 30 });
		const goldenWork = wireCounters.recordWrites + wireCounters.scratchEncodes + wireCounters.modelWork;
		expect(capped.truncated, "the golden shape truncates").toBe(true);
		expect(goldenWork, `golden: ${goldenWork} units of counted work (clean 63, classification mutant 89)`).toBeLessThanOrEqual(75);
		// the m2 drift-family sweep, 21 fillers wide around the centred landing: the same shapes the drift-window
		// test compares against the best-fit reference, run here for their counted work
		const nLen = 20, kLen = 20;
		const N = `${"n".repeat(nLen)}.example.`, K = `${"k".repeat(kLen)}.kk.`;
		const m2Shape = (filler, variant = 0) => {
			const answers = [
				{ name: "f.t.", type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: { strings: (() => { const s = []; let left = filler; while (left > 255) { s.push(new Uint8Array(255).fill(0x78)); left -= 255; } s.push(new Uint8Array(left).fill(0x78)); return s; })() } },
				{ name: "l.t.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: "s.q." } },
				{ name: "y.t.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: N } },
				{ name: "l.t.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: `a.${N}` } },
				{ name: "y.t.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: K } },
				{ name: "l.t.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: `c.${K}` } }
			];
			if (variant === 1) answers.push({ name: "l.t.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: `d.${K}` } });
			// z.t. is the same 3,000-octet TXT the review harness builds: 12 character-strings of at most 255 octets
			// — a single 3,000-octet string is not a legal character-string and the encode refuses it, which used
			// to zero out most of this section's counted work
			answers.push({ name: "z.t.", type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: { strings: (() => { const s = []; let left = 3000; while (left > 255) { s.push(new Uint8Array(255).fill(0x78)); left -= 255; } s.push(new Uint8Array(left).fill(0x78)); return s; })() } });
			return { id: 1, flags: { qr: true }, questions: [{ name: "q.", type: TYPE.A, class: CLASS.IN }], answers };
		};
		const kOffsetOf = (bytes, kl) => {
			for (let i = 0; i < bytes.length - kl; i++) if (bytes[i] === kl && bytes[i + 1] === 0x6b && bytes[i + kl] === 0x6b) return i;
			return -1;
		};
		let center = 15000;
		for (let it = 0; it < 20; it++) {
			const p2 = { ...m2Shape(center), answers: m2Shape(center).answers.filter((r) => r.name !== "z.t.") };
			const d = 0x4000 - (nLen + 1 + 8 + 1 - 2) - kOffsetOf(encodeMessage(p2), kLen);
			if (d === 0) break;
			center += d > 0 ? Math.max(1, d - Math.floor(d / 256)) : Math.min(-1, d - Math.ceil(d / 256));
		}
		wireCounters.recordWrites = 0;
		wireCounters.scratchEncodes = 0;
		wireCounters.modelWork = 0;
		for (let filler = center - 40; filler <= center + 40; filler += 4) {
			const m2 = m2Shape(filler);
			const size2 = encodeMessage({ ...m2, answers: m2.answers.filter((r) => r.name !== "z.t.") }).length;
			for (let limit = size2 - 3; limit <= size2 + 12; limit++) {
				try { encodeCapped(m2, { limit }); } catch {}
			}
		}
		const sweepWork = wireCounters.recordWrites + wireCounters.scratchEncodes + wireCounters.modelWork;
		expect(sweepWork, `sweep: ${sweepWork} units of counted work (clean 77,975, range-check mutant 77,719, pop-condition mutant 77,927)`).toBeGreaterThanOrEqual(77850);
		// and the c1x centre filler, where a registration's drift-up lands its drain pop exactly on the boundary:
		// the crossing-test mutant (off < 0x4000 -> <= in the drain) routes that pop back into the in-range heap
		// instead of queuing its examiners, and the re-measure cycle it delays is counted work — measured 486
		// against the clean 792 on this shape (tmp/agents/r10/logs/calib2.log holds the mutant run)
		const c1 = c1Shape(8, 16236);
		const c1Full = encodeMessage(c1).length;
		wireCounters.recordWrites = 0;
		wireCounters.scratchEncodes = 0;
		wireCounters.modelWork = 0;
		for (const limit of [c1Full - 1, c1Full, Math.floor((c1Full * 9) / 10)]) {
			try { encodeCapped(c1, { limit }); } catch {}
		}
		const c1Work = wireCounters.recordWrites + wireCounters.scratchEncodes + wireCounters.modelWork;
		expect(c1Work, `c1x centre: ${c1Work} units of counted work (clean 792, crossing-test mutant 486)`).toBeGreaterThanOrEqual(640);
		// and the pop-condition mutant (the drain's crossing threshold <= -> <): a registration whose slack is
		// consumed EXACTLY by the growth since its re-key pops one increment late and its examiner queue is
		// delayed — the heals-later path costs one skipped heap pop per exact-consumption crossing. The
		// committed slice runs both variants of the drift family over the m2kill limit window, where the
		// instrumented clean code takes 4,849 such pops (tmp/agents/r10/logs/exact-hunt.log); measured clean
		// 297,019 against the mutant 296,767 — the floor sits at the midpoint, a ~0.04% margin either side,
		// tight because the mutant's whole effect is one unit of model work per crossing.
		let sweep3 = 0;
		for (const variant of [0, 1]) {
			for (let f = center - 40; f <= center + 40; f += 4) {
				const m3 = m2Shape(f, variant);
				const size2 = encodeMessage({ ...m3, answers: m3.answers.filter((r) => r.name !== "z.t.") }).length;
				for (let limit = size2 - 3; limit <= size2 + kLen + 4; limit++) {
					wireCounters.recordWrites = 0;
					wireCounters.scratchEncodes = 0;
					wireCounters.modelWork = 0;
					try { encodeCapped(m3, { limit }); } catch {}
					sweep3 += wireCounters.recordWrites + wireCounters.scratchEncodes + wireCounters.modelWork;
				}
			}
		}
		expect(sweep3, `drift slice: ${sweep3} units of counted work (clean 297,019, pop-condition mutant 296,767)`).toBeGreaterThanOrEqual(296893);
	}, 120_000);

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
