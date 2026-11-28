/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/scaling.test.vitest.mjs
 */

/**
 * @fileoverview CLDMV/digby#40: encode must not get slower per record as a message grows, and the compression
 * table's registered targets follow the flat-table rules the encoder has always had. The golden-bytes test pins
 * the exact output of every compression site (owner names, questions, the NS/CNAME/SOA/PTR/MX rdata names, case
 * variants, the truncating encode's rollback, and the 0x3fff registration edge) — captured from the encoder. The
 * scaling tests hold, from 150 records to 2,900, the per-record encode time on both long-apex shapes.
 */

import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import { Writer } from "../../src/lib/buffer.mjs";
import { CLASS, TYPE } from "../../src/lib/constants.mjs";
import { encodeCapped, encodeMessage } from "../../src/lib/message.mjs";
import { writeName } from "../../src/lib/names.mjs";
import { hex } from "../helpers/wire-gen.mjs";

// A 100-label apex of one-octet labels: 201 wire octets, the "long apex" shape of CLDMV/digby#40.
const apex = Array.from({ length: 100 }, (_, i) => String.fromCharCode(0x61 + (i % 26))).join(".") + ".";

/** The long-apex response shape: a question at the apex and `n` A records whose owners share it as a suffix. */
const apexMessage = (n) => ({
	id: 0x0201,
	flags: { qr: true, ra: true },
	questions: [{ name: apex, type: TYPE.A, class: CLASS.IN }],
	answers: Array.from({ length: n }, (_, i) => ({
		name: `n${i}.` + apex,
		type: TYPE.A,
		class: CLASS.IN,
		ttl: 0,
		data: { address: [127, 0, 0, 1].join(".") }
	}))
});

/** Every record's owner IS the apex: the shape where a name's own suffixes are all compression targets. */
const apexOwnedMessage = (n) => ({
	id: 0x0201,
	flags: { qr: true, ra: true },
	questions: [{ name: apex, type: TYPE.A, class: CLASS.IN }],
	answers: Array.from({ length: n }, () => ({ name: apex, type: TYPE.A, class: CLASS.IN, ttl: 0, data: { address: [127, 0, 0, 1].join(".") } }))
});

describe("encode scaling (CLDMV/digby#40)", () => {
	it("encodes the compression sites byte-for-byte as the encoder always has", () => {
		const sites = {
			id: 0x1234,
			flags: { qr: true, aa: true, rd: true, ra: true },
			questions: [{ name: "www.example.", type: TYPE.A, class: CLASS.IN }],
			answers: [
				{ name: "www.example.", type: TYPE.A, class: CLASS.IN, ttl: 300, data: { address: "93.184.216.34" } },
				{ name: "a.example.", type: TYPE.NS, class: CLASS.IN, ttl: 3600, data: { target: "ns1.example." } },
				{ name: "b.example.", type: TYPE.CNAME, class: CLASS.IN, ttl: 60, data: { target: "www.example." } },
				{
					name: "example.",
					type: TYPE.SOA,
					class: CLASS.IN,
					ttl: 3600,
					data: { mname: "ns1.example.", rname: "hostmaster.example.", serial: 2024010101, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 }
				},
				{ name: "1.0.0.127.in-addr.arpa.", type: TYPE.PTR, class: CLASS.IN, ttl: 300, data: { target: "www.example." } },
				{ name: "example.", type: TYPE.MX, class: CLASS.IN, ttl: 300, data: { preference: 10, exchange: "mail.example." } }
			],
			authorities: [{ name: "example.", type: TYPE.NS, class: CLASS.IN, ttl: 3600, data: { target: "ns2.example." } }],
			additionals: [{ name: "ns1.example.", type: TYPE.A, class: CLASS.IN, ttl: 3600, data: { address: "192.0.2.1" } }],
			edns: null
		};
		// owner names, the question, NS/CNAME/SOA/PTR/MX rdata: pointers at several depths, the root-suffix hit,
		// a full-name hit, names registered as targets by rdata and pointed at later
		expect(hex.to(encodeMessage(sites)), "owner names, questions and rdata names").toBe("12348580000100060001000103777777076578616d706c650000010001c00c000100010000012c00045db8d8220161c0100002000100000e100006036e7331c0100162c010000500010000003c0002c00cc0100006000100000e100023c03b0a686f73746d6173746572c01078a3f17500001c2000000e100012750000000e100131013001300331323707696e2d61646472046172706100000c00010000012c0002c00cc010000f00010000012c0009000a046d61696cc010c0100002000100000e100006036e7332c010c03b0001000100000e100004c0000201");
		// case variants: matching is octet-exact, so a case-differing label is written in full while the shared
		// case-equal suffix behind it still compresses
		const cases = {
			id: 0,
			flags: { qr: true },
			questions: [{ name: "a.B.", type: TYPE.A, class: CLASS.IN }],
			answers: [
				{ name: "A.b.", type: TYPE.NS, class: CLASS.IN, ttl: 0, data: { target: "a.B." } },
				{ name: "x.A.b.", type: TYPE.NS, class: CLASS.IN, ttl: 0, data: { target: "A.B." } },
				{ name: "a.b.", type: TYPE.CNAME, class: CLASS.IN, ttl: 0, data: { target: "a.b." } }
			]
		};
		expect(hex.to(encodeMessage(cases)), "case variants").toBe("000080000001000300000000016101420000010001014101620000020001000000000002c00c0178c015000200010000000000040141c00e0161c01700050001000000000002c038");
		// the long-apex shape itself, small: the apex's every suffix is a target and each record's owner
		// compresses at its second label
		expect(hex.to(encodeMessage(apexMessage(5))), "long apex, compressed").toBe("020180800001000500000000016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f01700171017201730174017501760000010001026e30c00c000100010000000000047f000001026e31c00c000100010000000000047f000001026e32c00c000100010000000000047f000001026e33c00c000100010000000000047f000001026e34c00c000100010000000000047f000001");
		expect(hex.to(encodeMessage(apexMessage(5), { compress: false })), "long apex, uncompressed").toBe("020180800001000500000000016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f01700171017201730174017501760000010001026e30016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f017001710172017301740175017600000100010000000000047f000001026e31016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f017001710172017301740175017600000100010000000000047f000001026e32016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f017001710172017301740175017600000100010000000000047f000001026e33016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f017001710172017301740175017600000100010000000000047f000001026e34016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f017001710172017301740175017600000100010000000000047f000001");
		// the truncating encode: limit 128 cuts the sites message exactly after the SOA set (the MX and the
		// additional do not fit); whole RRsets drop, TC sets, and the targets the dropped bytes registered roll
		// back with them
		const cappedSites = encodeCapped(sites, { limit: 128 });
		expect(cappedSites.truncated, "the sites message truncates at 128 octets").toBe(true);
		expect(hex.to(cappedSites.bytes), "truncation rolls the compression table back").toBe("12348780000100040000000003777777076578616d706c650000010001c00c000100010000012c00045db8d8220161c0100002000100000e100006036e7331c0100162c010000500010000003c0002c00cc0100006000100000e100023c03b0a686f73746d6173746572c01078a3f17500001c2000000e100012750000000e10");
		// the apex message through the truncating encode with room for everything: every RRset's trial write runs
		// and nothing is dropped
		const cappedApex = encodeCapped(apexMessage(5), { limit: 400 });
		expect(cappedApex.truncated, "the apex message fits 400 octets").toBe(false);
		expect(hex.to(cappedApex.bytes), "trial writes leave the bytes untouched").toBe("020180800001000500000000016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f01700171017201730174017501760000010001026e30c00c000100010000000000047f000001026e31c00c000100010000000000047f000001026e32c00c000100010000000000047f000001026e33c00c000100010000000000047f000001026e34c00c000100010000000000047f000001");
		// and through a limit that drops the last apex record set off mid-message (12 + 209 + 5 * 21 = 326 octets)
		const cappedApexTight = encodeCapped(apexMessage(5), { limit: 310 });
		expect(cappedApexTight.truncated, "the apex message truncates at 310 octets").toBe(true);
		expect(hex.to(cappedApexTight.bytes), "a dropped apex record rolls its targets back").toBe("020182800001000400000000016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f0170017101720173017401750176017701780179017a016101620163016401650166016701680169016a016b016c016d016e016f01700171017201730174017501760000010001026e30c00c000100010000000000047f000001026e31c00c000100010000000000047f000001026e32c00c000100010000000000047f000001026e33c00c000100010000000000047f000001");
	});

	it("keeps the per-record encode time roughly flat from 150 records to 2,900", () => {
		const measure = (n) => {
			const message = apexMessage(n);
			encodeMessage(message); // warm-up, so the timed runs measure steady-state rather than JIT
			let best = Infinity;
			for (let i = 0; i < 3; i++) {
				const t0 = performance.now();
				encodeMessage(message);
				best = Math.min(best, performance.now() - t0);
			}
			return (best * 1000) / n; // µs per record, best of 3
		};
		const small = measure(150);
		const large = measure(2900);
		// The bound is a ratio, so the test is machine-independent: both sides scale with the machine. Coverage
		// instrumentation and pod contention inflate both measurements together; the indexed encoder sits near 1
		// (the same work per record).
		const RATIO_BOUND = 2.5;
		expect(
			large / small,
			`per-record encode: ${small.toFixed(2)} µs at 150 records, ${large.toFixed(2)} µs at 2,900`
		).toBeLessThan(RATIO_BOUND);
	});

	it("keeps the per-record encode time of the apex-owned shape roughly flat from 150 records to 2,900", () => {
		const measure = (n) => {
			const message = apexOwnedMessage(n);
			encodeMessage(message); // warm-up
			let best = Infinity;
			for (let i = 0; i < 3; i++) {
				const t0 = performance.now();
				encodeMessage(message);
				best = Math.min(best, performance.now() - t0);
			}
			return (best * 1000) / n;
		};
		const small = measure(150);
		const large = measure(2900);
		const RATIO_BOUND = 2.5;
		expect(
			large / small,
			`per-record encode: ${small.toFixed(2)} µs at 150 records, ${large.toFixed(2)} µs at 2,900`
		).toBeLessThan(RATIO_BOUND);
	});

	it("never registers a suffix first written past 0x3fff, while a shorter suffix registered below still compresses", () => {
		// The registration guard (only offsets below 0x4000 become compression targets) at its edge: `a.b.` written
		// first registers `b.` at offset 2; filler pushes the writer past 0x3fff; `c.b.` and `d.c.b.` are then
		// written entirely past it — their longer suffixes (c.b., d.c.b.) are never registered, and both names
		// compress at the below-registered `b.` (captured from the encoder, and through encodeMessage on the
		// full-message shape: the last two records of a 16,766-octet answer section come out `0163c00e` and
		// `01640163c00e`).
		const w = new Writer();
		writeName(w, "a.b.", true);
		w.raw(new Uint8Array(0x4000));
		const at = w.length; // past 0x3fff
		writeName(w, "c.b.", true);
		writeName(w, "d.c.b.", true);
		expect(hex.to(w.bytes.subarray(at, w.length)), "past-0x3fff suffixes are not targets").toBe("0163c00201640163c002");
	});

	it("registers a name written at exactly 0x3fff but not at exactly 0x4000", () => {
		// The guard is `w.length < 0x4000` (a pointer's offset is 14 bits, so 0x3fff is the largest target): a
		// name whose first label lands at exactly 0x3fff registers — the pointer to it is 0xffff — and a name at
		// exactly 0x4000 does not.
		const w = new Writer();
		writeName(w, "a.b.", true); // registers b. at offset 2
		w.raw(new Uint8Array(0x3fff - 5)); // the writer is at exactly 0x3fff
		writeName(w, "c.b.", true); // c.b. registers at 0x3fff; b. compresses to c002
		writeName(w, "e.c.b.", true); // e is past 0x3fff; c.b. is a target: the pointer is 0xffff
		expect(hex.to(w.bytes.subarray(0x3fff, w.length)), "a name registered at 0x3fff is a target").toBe("0163c0020165ffff");
		const w2 = new Writer();
		writeName(w2, "a.b.", true);
		w2.raw(new Uint8Array(0x4000 - 5)); // the writer is at exactly 0x4000
		writeName(w2, "c.b.", true); // c.b. does NOT register at 0x4000; b. still compresses to c002
		writeName(w2, "e.c.b.", true); // e and c are both unregistered: c is written in full
		expect(hex.to(w2.bytes.subarray(0x4000, w2.length)), "a name at 0x4000 is not a target").toBe("0163c00201650163c002");
	});
});
