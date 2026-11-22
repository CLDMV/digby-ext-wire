/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/scaling.test.vitest.mjs
 */

/**
 * @fileoverview CLDMV/digby#40: the encoder's compression table must carry a shared-label index, not every written
 * name's full suffix text, and encode must not get slower per record as a message grows. The golden-bytes test pins
 * the exact output of every compression site (owner names, questions, the NS/CNAME/SOA/PTR/MX rdata names, case
 * variants, the truncating encode's rollback) — captured from the encoder as it stood before the index. The scaling
 * tests hold, from 150 records to 2,900, both the per-record encode time and the per-record size of what the
 * compression table retains.
 */

import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import { Writer } from "../../src/lib/wire/buffer.mjs";
import { CLASS, TYPE } from "../../src/lib/wire/constants.mjs";
import { encodeCapped, encodeMessage } from "../../src/lib/wire/message.mjs";
import { writeName } from "../../src/lib/wire/names.mjs";
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

	it("retains a shared-label index in the compression table, not every name's full suffix text", () => {
		// The characters the compression table holds after writing the apex and `n` record owners. An index keyed
		// by label holds each distinct label once: ~5 characters per record here (one short owner label per
		// record; the apex's own 201 characters are held once). The flat suffix-key table the encoder carried
		// before the index retained every written name's full suffix text — ~210 characters per record on this
		// shape, ~630 KB on the 2,900-record response — the pressure that made the large encode slow
		// (CLDMV/digby#40). The bound sits far above the index's cost and far below the flat table's.
		const CHARS_PER_RECORD_BOUND = 64;
		const measure = (n) => {
			const w = new Writer();
			writeName(w, apex, true);
			for (let i = 0; i < n; i++) writeName(w, `n${i}.` + apex, true);
			return retainedChars(w.names) / n;
		};
		const small = measure(150);
		const large = measure(2900);
		expect(small, `${small.toFixed(1)} table characters per record at 150`).toBeLessThan(CHARS_PER_RECORD_BOUND);
		expect(large, `${large.toFixed(1)} table characters per record at 2,900`).toBeLessThan(CHARS_PER_RECORD_BOUND);
	});
});

/**
 * The characters of name text the writer's compression table retains, whatever its shape: the flat suffix-key
 * table (a Map of full suffix keys) sums its keys; the label index sums one edge key per node.
 * @param {Map<string, number>|object} table
 * @returns {number}
 */
function retainedChars(table) {
	if (table instanceof Map) {
		let n = 0;
		for (const key of table.keys()) n += key.length;
		return n;
	}
	let n = 0;
	const stack = [table];
	while (stack.length > 0) {
		const node = stack.pop();
		n += node.key.length;
		for (const child of node.children.values()) stack.push(child);
	}
	return n;
}
