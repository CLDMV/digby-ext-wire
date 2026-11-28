/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/capped-boundary.test.vitest.mjs
 */

/**
 * @fileoverview The encodeCapped best-fit differential over the 0x4000 boundary families (CLDMV/digby#43): interleaved
 * shapes whose streams straddle the compression-pointer boundary, compared byte for byte against the best-fit oracle
 * (tests/helpers/capped-oracle.mjs). Round 10 trimmed the sweeps to fixed case counts so no single test runs long enough
 * to stall a default-stall pod run: every limit is a decision boundary (a prefix size and its neighbours — between two
 * prefix sizes the kept prefix cannot change) plus a fixed stride across the 800-octet window below the full encode, and
 * the long families print a heartbeat at most every 45 s.
 */

import { describe, expect, it } from "vitest";
import { CLASS, TYPE } from "../../src/lib/constants.mjs";
import { encodeCapped, encodeMessage } from "../../src/lib/message.mjs";
import { beat, bigTxt, boundaryLimits, c1Shape, compareWithReference, landingOf, ns, oracleCapped, srv, txt, x63 } from "../helpers/capped-oracle.mjs";
import { hex } from "../helpers/wire-gen.mjs";

describe("encodeCapped best-fit differential: the 0x4000 boundary families (CLDMV/digby#43)", () => {
	// The four 0x4000 boundary sites, re-derived for the largest-fit contract (R8-2; each mutant applied alone to
	// this suite ran 394/394 — tmp/agents/r8/mut-m{1,2,3,4}.log). The model's only output-bearing role is candidate
	// selection: the winning prefix is verified by an exact trial, so a model lie matters only when it HIDES a
	// fitting prefix. An understated total cannot: a prefix whose real stream fits always passes the fit check
	// (stored octets <= real octets, and the tail bound is the OPT record's exact size — writeOpt writes the root as
	// a raw octet, never a name), so every fitting prefix stays a candidate and the first trial that fits is the
	// largest one whatever the totals said. An overstated total can hide one, and that is the direction the drift-in
	// heap watches. Per site:
	// - m1, the model lookup's range check (r < 0x4000 -> <=): a target at exactly 0x4000 compresses in the
	//   measurement where the real writeName writes it in full (its own guard is w.length < 0x4000; a 14-bit
	//   pointer cannot reach 0x4000). Stored octets go stale-LOW — undercount — self-correcting.
	// - m3, the validity drain's crossing test (off < 0x4000 -> <=, round 7's slack > 0 -> >= 0): a registration
	//   whose offset reaches exactly 0x4000 stays heap-valid, so its examiners are not re-measured and their stored
	//   octets go stale-LOW (they compressed; a fresh measurement writes in full) — undercount — self-correcting.
	//   Round 7 killed it through the greedy fit check; the greedy is gone and the trials arbitrate now.
	// - m4, the lookup's earlier-target scoping (r < curReal + ... -> <=): compresses against a target at exactly
	//   the in-flight write position, which the real stream has not written yet — stale-LOW — self-correcting.
	// - m2, the registration classification (off < 0x4000 -> <= in adopt; the probe registration's own check is
	//   gone — every registration is recorded now and this is where the boundary rule lives): a registration
	//   landing exactly on 0x4000 is classified in-range, into the drift-OUT heap instead of the drift-IN one. At
	//   adoption the examiners' octets are still correct (the real stream also refuses the pointer), and the lie
	//   heals through four independent paths: any positive tree delta pops the entry and the drain's crossed branch
	//   re-checks it, queues its examiners and migrates it to the drift-IN heap — clean behaviour from then on; a
	//   re-registration of the key replaces the entry outright; the cascade seed queues the new key's examiners
	//   regardless; and within one measurement offsets only increase, so a shrink source cannot sit after a phantom
	//   registration. The residual window is a pure-negative shift (no positive delta, no re-registration) pulling
	//   the phantom below 0x4000 after its examiners were already re-measured — their staleness would then be
	//   permanent and could hide a fitting prefix. Neither the round-7 sweep (215,863 cases) nor this suite's
	//   differential cases (the c1x landing sweep puts registrations exactly on 0x4000 and the keeps shift them both
	//   ways) produced it; a shape threading that needle would keep fewer sets than the best-fit oracle — output
	//   within the limit, whole RRsets, correct TC, only the truncation point different.
	//
	// The c1x family (round 8): the C1 shape with the filler swept so the y.t. record's registration of N lands on
	// every offset around the pointer boundary — including exactly 0x4000, where the boundary rules differ — and the
	// keeps around it shift and shrink the stream (l.t.'s records compress against N once it is registered, and
	// their own a60<i>.N registrations drift as a result), so crossings out of the range and drifts back in both
	// fire. This is the family that reaches the divergence channel round 7's sweep called unreached. Chunked its so
	// progress streams and a failure names its filler window.

	// The repro family of round 3/8: a big first TXT record parks the stream just below the registration bound and
	// the same-owner NS set interleaves its records around the distinct owner, so a set's probe measurement (its
	// records written consecutively) registers suffixes at offsets the real stream never reaches.
	const answers = (F) => [bigTxt("t.test.", F), ns("z.test.", "n1.aaaa.example."), txt("b.test.", 200), ns("z.test.", `n2.${x63}.example.`), ns("z.test.", `n3.${x63}.example.`)];
	// the filler swept at a fixed stride across the straddle (the round-9 file walked every 32; the differential's
	// fixed case count keeps 6 fillers per question variant, each at every decision boundary)
	for (let F = 15400; F <= 16400; F += 200) {
		for (const q of [null, "z.test."]) {
			it(`matches the best-fit reference at every decision boundary, filler=${F} q=${q ?? "none"} (CLDMV/digby#43)`, () => {
				const m = { id: 1, flags: { qr: true }, questions: q ? [{ name: q, type: TYPE.A, class: CLASS.IN }] : [], answers: answers(F) };
				const limits = boundaryLimits(m);
				for (let i = 0; i < limits.length; i++) {
					beat(`boundary F=${F} q=${q}`, i, limits.length);
					compareWithReference(m, limits[i], `F=${F} q=${q} limit=${limits[i]}`);
				}
			}, 300_000);
		}
	}

	// Pseudo-random interleavings straddling 0x4000, seeded and bounded by a fixed case count. Without a question any
	// drop is refused (CLDMV/digby#43), so these seeds exercise the refusal path and the fit-or-refuse boundary; the
	// one-question seeds below compare the truncated keeps byte for byte.
	const randomShape = (seed, question) => {
		const rand = (n) => ((seed * 1103515245 + 12345 + n * 69069) >>> 8) % 997;
		const F = 15300 + (rand(1) % 1100); // the filler parks the stream on both sides of 0x4000
		const recs = [bigTxt("big.test.", F)];
		const names = ["z.test.", "b.test.", "c.test.", "d.test."];
		const sig = new Uint8Array(24).fill(0x5a);
		for (let i = 0; i < 8; i++) {
			const n = names[rand(2 + i) % names.length];
			const target = `t${i}.${x63}.example.`;
			switch (rand(3 + i) % 7) {
				case 0:
					recs.push(txt(n, 40 + (rand(i) % 220)));
					break;
				case 1:
					recs.push(ns(n, target));
					break;
				case 2:
					recs.push({ name: n, type: TYPE.SRV, class: CLASS.IN, ttl: 60, data: { priority: 1, weight: 2, port: 3, target } });
					break;
				case 3:
					recs.push({ name: n, type: TYPE.NAPTR, class: CLASS.IN, ttl: 60, data: { order: 1, preference: 2, flags: new Uint8Array(2).fill(0x73), services: new Uint8Array(3).fill(0x74), regexp: new Uint8Array(4).fill(0x75), replacement: target } });
					break;
				case 4:
					recs.push({ name: n, type: TYPE.RRSIG, class: CLASS.IN, ttl: 60, data: { typeCovered: TYPE.A, algorithm: 8, labels: 2, originalTtl: 3600, expiration: 1700000000, inception: 1600000000, keyTag: 1234, signerName: target, signature: sig } });
					break;
				case 5:
					recs.push({ name: n, type: TYPE.NSEC, class: CLASS.IN, ttl: 60, data: { next: target, types: [TYPE.A, TYPE.NS, TYPE.TXT] } });
					break;
				default:
					recs.push({ name: n, type: TYPE.SVCB, class: CLASS.IN, ttl: 60, data: { priority: 3, target, params: [{ key: 65001, value: new Uint8Array(6).fill(0x71) }] } });
					break;
			}
		}
		return { id: 1, flags: { qr: true }, questions: question ? [{ name: "q.", type: TYPE.A, class: CLASS.IN }] : [], answers: recs };
	};
	for (let chunk = 0; chunk < 4; chunk++) {
		const from = chunk * 10;
		it(`matches the best-fit reference on pseudo-random interleavings, seeds ${from}..${from + 9} (CLDMV/digby#43)`, () => {
			for (let seed = from; seed < from + 10; seed++) {
				const m = randomShape(seed, false);
				const limits = boundaryLimits(m);
				for (let i = 0; i < limits.length; i++) {
					beat(`random ${from}..${from + 9}`, (seed - from) * limits.length + i, 10 * limits.length);
					compareWithReference(m, limits[i], `seed=${seed} limit=${limits[i]}`);
				}
			}
		}, 300_000);
	}
	it("matches the best-fit reference on one-question pseudo-random interleavings, seeds 0..9 (CLDMV/digby#43)", () => {
		for (let seed = 0; seed < 10; seed++) {
			const m = randomShape(seed, true);
			const limits = boundaryLimits(m);
			for (let i = 0; i < limits.length; i++) {
				beat("random q 0..9", seed * limits.length + i, 10 * limits.length);
				compareWithReference(m, limits[i], `seed=${seed} q limit=${limits[i]}`);
			}
		}
	}, 300_000);
	// and the EDNS variant on a slice: the OPT tail rides every fit check
	it("matches the best-fit reference on EDNS pseudo-random interleavings, seeds 0..7 (CLDMV/digby#43)", () => {
		for (let seed = 0; seed < 8; seed++) {
			const m = { ...randomShape(seed, true), edns: { udpSize: 1232, version: 0, dnssecOk: false, z: 0, options: [] } };
			const limits = boundaryLimits(m);
			for (let i = 0; i < limits.length; i++) {
				beat("random edns 0..7", seed * limits.length + i, 8 * limits.length);
				compareWithReference(m, limits[i], `seed=${seed} edns limit=${limits[i]}`);
			}
		}
	}, 300_000);

	// The C1 family: every trailing count, at every decision boundary, byte for byte against the best-fit reference.
	// Under the largest-fit rule the interesting window is exactly where the greedy scan used to stop early.
	for (let trailing = 1; trailing <= 10; trailing++) {
		it(`matches the best-fit reference across the C1 family, trailing=${trailing} (CLDMV/digby#43)`, () => {
			const m = c1Shape(trailing);
			const limits = boundaryLimits(m);
			for (let i = 0; i < limits.length; i++) {
				beat(`C1 trailing=${trailing}`, i, limits.length);
				compareWithReference(m, limits[i], `trailing=${trailing} limit=${limits[i]}`);
			}
		}, 300_000);
	}
	// The EDNS variant: the OPT tail is never dropped, so every fit check carries it; the differential holds with
	// one in the message (the reference encodes the same tail the same way).
	it("matches the best-fit reference across the C1 family with EDNS in the message (CLDMV/digby#43)", () => {
		for (const trailing of [3, 8]) {
			const m = { ...c1Shape(trailing), edns: { udpSize: 1232, version: 0, dnssecOk: true, z: 0, options: [] } };
			const limits = boundaryLimits(m);
			for (let i = 0; i < limits.length; i++) {
				beat(`C1 edns trailing=${trailing}`, i, limits.length);
				compareWithReference(m, limits[i], `edns trailing=${trailing} limit=${limits[i]}`);
			}
		}
	}, 300_000);
	// The reserveTsig variant: the codec reduces its limit by the reservation internally; the reference compares
	// against the reduced limit directly.
	it("matches the best-fit reference across the C1 family with a TSIG reservation (CLDMV/digby#43)", () => {
		const m = c1Shape(8);
		const limits = boundaryLimits(m);
		for (let i = 0; i < limits.length; i++) {
			beat("C1 reserve", i, limits.length);
			compareWithReference(m, limits[i], `reserve limit=${limits[i]}`, { reserveTsig: 84 });
		}
	}, 300_000);

	// The c1x shift-landing family: the C1 shape with the filler swept so the y.t. record's registration of N lands on
	// every offset around the pointer boundary — including exactly 0x4000 — and the keeps around it shift and shrink
	// the stream, so crossings out of the range and drifts back in both fire.
	const c1xCenter = 16236 + (0x4000 - landingOf(16236));
	for (const trailing of [2, 8]) {
		for (let chunk = 0; chunk < 4; chunk++) {
			const lo = c1xCenter - 56 + chunk * 28;
			const hi = lo + 27;
			it(`matches the best-fit reference across the c1x shift-landing family, trailing=${trailing}, filler ${lo}..${hi} (CLDMV/digby#43)`, () => {
				for (let filler = lo; filler <= hi; filler++) {
					const m = c1Shape(trailing, filler);
					const limits = boundaryLimits(m);
					for (let i = 0; i < limits.length; i++) {
						beat(`c1x trailing=${trailing} ${lo}..${hi}`, (filler - lo) * limits.length + i, 28 * limits.length);
						compareWithReference(m, limits[i], `c1x trailing=${trailing} filler=${filler} limit=${limits[i]}`);
					}
				}
			}, 300_000);
		}
	}
	it("the c1x sweep's centre lands the y.t. registration exactly on 0x4000 (CLDMV/digby#43)", () => {
		expect(landingOf(c1xCenter)).toBe(0x4000);
	});
});

describe("encodeCapped: in-flight registrations and the 0x4000 drift window (CLDMV/digby#43, round 9)", () => {
	const compare = (m, limit, tag) => {
		const capped = encodeCapped(m, { limit });
		expect(capped.bytes.length, `${tag}: within the limit`).toBeLessThanOrEqual(limit);
		const reference = oracleCapped(m, { limit });
		expect(capped.truncated, `${tag}: the truncation flag matches the best-fit reference`).toBe(reference.truncated);
		expect(hex.to(capped.bytes), `${tag}: the bytes match the best-fit reference`).toBe(hex.to(reference.bytes));
	};

	// R9-1 (CLDMV/digby#43): the model's scoping check placed a registration by its offset in the tree as it stands —
	// but the set being measured is not in the tree yet, so a later record's registration lands before the in-flight
	// write position and the probe sees a target the real stream does not have yet. An SRV target (written
	// uncompressed but registering) then never records its registration, the examiner's stored octets stay
	// stale-high, the model overcounts ~12 octets, and a fitting prefix is hidden. The shape: an SRV whose target a
	// LATER record of an EARLIER set repeats, so the registering write comes after the examiner in the section.
	const r9Shape = (i) => {
		const T = `t${i}.${"l".repeat(60)}.example.`;
		const U = `u${i}.${"l".repeat(60)}.example.`;
		return {
			id: 1,
			flags: { qr: true },
			questions: [{ name: "q.", type: TYPE.A, class: CLASS.IN }],
			answers: [
				bigTxt("f.t.", 16040 + (i % 4) * 60),
				ns("a.t.", "s.q."),
				srv("b.t.", T),
				ns("a.t.", T),
				ns("c.t.", U),
				srv("d.t.", U),
				ns("c.t.", U),
				bigTxt("z.t.", 700 + (i % 5) * 60)
			]
		};
	};
	it("matches the best-fit reference when an uncompressed-but-registering name precedes a later record of an earlier set (CLDMV/digby#43)", () => {
		for (let i = 0; i < 12; i++) {
			const m = r9Shape(i);
			// every first-appearance set boundary of the answers, ± 1: the windows the scoping lie opens
			const keys = [];
			const setOf = m.answers.map((r) => {
				const k = `${r.name.toLowerCase()}|${r.type}|${r.class}`;
				if (!keys.includes(k)) keys.push(k);
				return keys.indexOf(k);
			});
			for (let k = 0; k < keys.length; k++) {
				const size = encodeMessage({ ...m, answers: m.answers.filter((_, j) => setOf[j] <= k) }).length;
				for (const limit of [size - 1, size, size + 1]) {
					beat(`r9 seed=${i}`, k, keys.length);
					compare(m, limit, `r9 seed=${i} k=${k} limit=${limit}`);
				}
			}
		}
	}, 600_000);

	// R9-2 (CLDMV/digby#43): the probe measured a registration with its own write position as the gate, but the real
	// stream's gate is the registration's real offset — the two differ by the kept octets between the measured
	// records. A re-measured record that wrote a key in full (its real offset sat exactly on 0x4000 at that instant)
	// registered a phantom the real stream never makes, and the adopt replaced the true registration — the one whose
	// drift back under 0x4000 (a pure-negative shift from a shrink in the same re-measure batch) the drift-in heap
	// exists to catch. The phantom never drifts, the examiners keep stale-high octets, the model overcounts, and the
	// frozen point — which trusts its totals — hides the fitting prefix outright (no trial ever runs). The family:
	// the filler centres Y2's K registration exactly on 0x4000 in the transient state right after its set folds,
	// X1's shrink (compressing against Y1's N) pulls it under, and C — which measured K absent — is its examiner.
	const m2Shape = (filler, nLen, kLen, zSize = 3000, variant = 0) => {
		const N = `${"n".repeat(nLen)}.example.`;
		const K = `${"k".repeat(kLen)}.kk.`;
		const answers = [
			bigTxt("f.t.", filler),
			ns("l.t.", "s.q."),
			ns("y.t.", N),
			ns("l.t.", `a.${N}`),
			ns("y.t.", K),
			ns("l.t.", `c.${K}`)
		];
		if (variant === 1) answers.push(ns("l.t.", `d.${K}`));
		answers.push(bigTxt("z.t.", zSize));
		return { id: 1, flags: { qr: true }, questions: [{ name: "q.", type: TYPE.A, class: CLASS.IN }], answers };
	};
	const m2Prefix2 = (filler, nLen, kLen, variant) => ({ ...m2Shape(filler, nLen, kLen, 3000, variant), answers: m2Shape(filler, nLen, kLen, 3000, variant).answers.filter((r) => r.name !== "z.t.") });
	const kOffsetOf = (bytes, kLen) => {
		for (let i = 0; i < bytes.length - kLen; i++) if (bytes[i] === kLen && bytes[i + 1] === 0x6b && bytes[i + kLen] === 0x6b) return i;
		return -1;
	};
	// the filler that puts K's final offset at 0x4000 - (wire octets of N - 2): transiently, before X1's shrink, K
	// sits exactly on 0x4000 (the harness that found the residual, tmp/agents/r8-capped/m2kill.mjs, centres the same
	// way — S = the octets X1 loses when it compresses against Y1's N)
	const m2Center = (nLen, kLen) => {
		let center = 15000;
		for (let it = 0; it < 20; it++) {
			const d = 0x4000 - (nLen + 1 + 8 + 1 - 2) - kOffsetOf(encodeMessage(m2Prefix2(center, nLen, kLen, 0)), kLen);
			if (d === 0) break;
			center += d > 0 ? Math.max(1, d - Math.floor(d / 256)) : Math.min(-1, d - Math.ceil(d / 256));
		}
		return center;
	};
	it("matches the best-fit reference when a registration lands exactly on 0x4000 and drifts back under (CLDMV/digby#43)", () => {
		// both variants, and the filler swept +-40 around the centred landing the way the review harness sweeps it
		// (tmp/agents/r10/m2kill.mjs stands for the sweep; the harness centres the same way) — the round-9 test
		// passed 3000 in the variant slot, so variant 1 (the second l.t. examiner of K) never ran
		let done = 0;
		for (const [nLen, kLen] of [
			[20, 20],
			[20, 63],
			[63, 20],
			[63, 63]
		]) {
			const center = m2Center(nLen, kLen);
			for (const variant of [0, 1]) {
				for (const filler of [center - 40, center - 8, center, center + 8, center + 40]) {
					const m = m2Shape(filler, nLen, kLen, 3000, variant);
					const size2 = encodeMessage(m2Prefix2(filler, nLen, kLen, variant)).length;
					for (let limit = size2 - 3; limit <= size2 + 12; limit++) {
						beat("m2 family", done, 40 * 16);
						compare(m, limit, `m2 n=${nLen} k=${kLen} variant=${variant} filler=${filler} limit=${limit}`);
					}
					done++;
				}
			}
		}
	}, 600_000);
});
