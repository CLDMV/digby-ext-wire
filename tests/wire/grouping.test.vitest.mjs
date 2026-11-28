/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/grouping.test.vitest.mjs
 */

/**
 * Record order and RRset grouping (CLDMV/digby#36, RFC 2181 9): an encode keeps the section's record order, always — record
 * order is meaning (a transfer's SOA bookends, an IXFR's SOA-diff structure, an update's interleaved adds and deletes). The
 * RRset grouping is consulted only by a truncating encode, to decide what it keeps: whole RRsets survive or drop, never part
 * of one; the survivors keep their original positions, so the surviving sets still come in first-seen order; and TC follows
 * the section rules.
 */

import { describe, expect, it } from "vitest";
import { CLASS, TYPE } from "../../src/lib/constants.mjs";
import { decodeMessage, encodeCapped, encodeMessage } from "../../src/lib/message.mjs";
import { wholeSetPrefix } from "../helpers/wire-gen.mjs";

const SECTIONS = ["answers", "authorities", "additionals"];
const A = (i) => ({ name: "ns.example.", type: TYPE.A, class: 1, ttl: 60, data: { address: `10.0.0.${i}` } });
// n octets of TXT rdata, split into character-strings of at most 255 octets each
const TXT = (name, n) => ({
	name,
	type: TYPE.TXT,
	class: 1,
	ttl: 60,
	data: { strings: Array.from({ length: Math.ceil(n / 255) }, (_, i) => Uint8Array.from({ length: Math.min(255, n - i * 255) }, () => 0x78)) }
});
const SOA = (serial) => ({
	name: "example.",
	type: TYPE.SOA,
	class: 1,
	ttl: 60,
	data: { mname: "ns.example.", rname: "host.example.", serial, refresh: 0, retry: 0, expire: 0, minimum: 0 }
});
const NS = { name: "example.", type: TYPE.NS, class: 1, ttl: 60, data: { target: "ns.example." } };
// the RFC 2136 delete-RRset form: class ANY (or NONE) with empty rdata
const DEL = (cls) => ({ name: "x.example.", type: TYPE.A, class: cls, ttl: 0, data: null });
// flags and edns materialised the way the decoder returns them, so a whole-message round-trip can be compared with toEqual
const message = (sections) => ({
	id: 1,
	flags: { qr: true, opcode: 0, aa: false, tc: false, rd: false, ra: false, z: false, ad: false, cd: false },
	rcode: 0,
	// one question: a truncating encode of a message without exactly one question is refused (CLDMV/digby#43).
	// q.test. shares no suffix with the shapes below except the root, so it costs each packet exactly 13 octets:
	// 12 of head, plus the first name's root label becoming a pointer to the question's root registration.
	questions: [{ name: "q.test.", type: TYPE.A, class: 1 }],
	answers: [],
	authorities: [],
	additionals: [],
	edns: null,
	...sections
});

describe("record order is kept; grouping only decides truncation (CLDMV/digby#36)", () => {
	it("never sends part of the interleaved ns.example A set (the issue's packet)", () => {
		const m = message({ additionals: [A(1), TXT("p1.example.", 200), A(2), TXT("p2.example.", 10)] });
		for (let limit = 270; limit <= 400; limit++) {
			const { bytes, truncated } = encodeCapped(m, { limit });
			const d = decodeMessage(bytes);
			// only optional data is cut here: TC stays clear and no truncation is reported
			expect(d.flags.tc, `limit ${limit}`).toBe(false);
			expect(truncated, `limit ${limit}`).toBe(false);
			// whole sets only, at their original positions
			expect(wholeSetPrefix(d.additionals, m.additionals), `limit ${limit}`).toBe(true);
			const ns = d.additionals.filter((r) => r.type === TYPE.A);
			expect(ns.length % 2, `limit ${limit}: the ns.example set went out partly`).toBe(0);
		}
		// the issue's window: the later piece of the split set is the one that does not fit, so the whole set goes and the
		// small trailing TXT with it — while the records that survive keep their positions. Owner-name compression shrinks
		// this packet (the p1/p2 owners share ns.example.'s suffix): with the question's 13 octets, [A, TXT p1, A] is 285
		// octets and the whole packet 313, so the window where the first three fit but p2 does not is caps 285..312 — 293
		// sits in it
		const { bytes } = encodeCapped(m, { limit: 293 });
		expect(decodeMessage(bytes).additionals).toEqual([A(1), TXT("p1.example.", 200), A(2)]);
	});

	it.each(SECTIONS)("keeps the %s's record order through a full encode", (section) => {
		const m = message({ [section]: [A(1), TXT("p1.example.", 400), A(2)] });
		const d = decodeMessage(encodeMessage(m));
		// the interleaved ns.example records stay where they are: an encode never regroups (record order is meaning)
		expect(d[section]).toEqual([A(1), TXT("p1.example.", 400), A(2)]);
	});

	it("keeps an AXFR's record order: the SOA bookends stay at the ends", () => {
		const answers = [SOA(3), NS, A(1), SOA(3)];
		// the two SOAs share one RRset key, so regrouping would send [SOA, SOA, NS, A] and end the transfer after the first
		// record
		expect(decodeMessage(encodeMessage(message({ answers })))).toEqual(message({ answers }));
	});

	it("keeps an IXFR's SOA-diff structure", () => {
		const answers = [SOA(3), SOA(1), A(7), SOA(2), A(8), SOA(2), SOA(3)];
		// the five SOAs share one RRset key, so regrouping sends every SOA first and destroys the diff
		expect(decodeMessage(encodeMessage(message({ answers })))).toEqual(message({ answers }));
	});

	it.each([CLASS.ANY, CLASS.NONE])("keeps an UPDATE's record order: add, delete-RRset (class %s), add", (cls) => {
		const additionals = [A(1), DEL(cls), A(2)];
		// the two adds share one RRset key, so regrouping sends [add, add, delete] and the update's end state comes out empty
		expect(decodeMessage(encodeMessage(message({ additionals })))).toEqual(message({ additionals }));
	});

	it.each(SECTIONS)("drops the whole split set under a cap in the %s, keeping first-seen order", (section) => {
		const m = message({ [section]: [A(1), TXT("p1.example.", 400), A(2)] });
		const { bytes, truncated } = encodeCapped(m, { limit: 100 });
		const d = decodeMessage(bytes);
		// the ns.example set fits whole in first-seen position; the big TXT set does not, so it and everything after it go
		expect(d[section]).toEqual([A(1), A(2)]);
		expect(truncated).toBe(section !== "additionals");
		expect(d.flags.tc).toBe(section !== "additionals");
		// and nothing after the truncation point survives into the later sections
		for (const later of SECTIONS.slice(SECTIONS.indexOf(section) + 1)) expect(d[later]).toEqual([]);
	});

	it("drops an interleaved RRset whole and keeps the other records at their positions", () => {
		const m = message({ additionals: [A(1), TXT("p1.example.", 10), A(2), TXT("p2.example.", 400)] });
		// [A, small TXT, A] is 82 octets, the big TXT set 419 more: at 100 the p2 set goes whole and the rest keep order
		const { bytes, truncated } = encodeCapped(m, { limit: 100 });
		const d = decodeMessage(bytes);
		expect(d.additionals).toEqual([A(1), TXT("p1.example.", 10), A(2)]);
		// only optional data was cut
		expect(truncated).toBe(false);
		expect(d.flags.tc).toBe(false);
	});
});
