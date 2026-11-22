/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/grouping.test.vitest.mjs
 */

/**
 * RRset grouping across a whole section (CLDMV/digby#36, RFC 2181 9): records with the same owner, type and class form one
 * RRset even when they are not adjacent in the section, so a capped encode never sends part of an RRset. The sets come out
 * in first-seen order with their records in section order; truncation drops whole sets and sets TC per the section.
 */

import { describe, expect, it } from "vitest";
import { TYPE } from "../../src/lib/wire/constants.mjs";
import { decodeMessage, encodeCapped, encodeMessage } from "../../src/lib/wire/message.mjs";
import { regroup, rrsetKey } from "../helpers/wire-gen.mjs";

const A = (i) => ({ name: "ns.example.", type: TYPE.A, class: 1, ttl: 60, data: { address: `10.0.0.${i}` } });
const TXT = (name, n) => ({ name, type: TYPE.TXT, class: 1, ttl: 60, data: { strings: [Uint8Array.from({ length: n }, () => 0x78)] } });
const message = (sections) => ({ id: 1, flags: { qr: true }, rcode: 0, questions: [], answers: [], authorities: [], additionals: [], ...sections });

/** Whether `kept` is a prefix of `regroup(all)` that ends on an RRset boundary (a whole number of sets). */
function isGroupedPrefix(kept, all) {
	const grouped = regroup(all);
	if (kept.length > grouped.length) return false;
	for (let i = 0; i < kept.length; i++) expect(kept[i]).toEqual(grouped[i]);
	return kept.length === 0 || kept.length === grouped.length || rrsetKey(grouped[kept.length]) !== rrsetKey(grouped[kept.length - 1]);
}

describe("RRsets group across a whole section (CLDMV/digby#36)", () => {
	it("never sends part of the interleaved ns.example A set (the issue's packet)", () => {
		const m = message({ additionals: [A(1), TXT("p1.example.", 200), A(2), TXT("p2.example.", 10)] });
		// first-seen order: the ns.example set, then p1, then p2
		const grouped = [A(1), A(2), TXT("p1.example.", 200), TXT("p2.example.", 10)];
		for (let limit = 270; limit <= 400; limit++) {
			const { bytes, truncated } = encodeCapped(m, { limit });
			const d = decodeMessage(bytes);
			// only optional data is cut here: TC stays clear and no truncation is reported
			expect(d.flags.tc, `limit ${limit}`).toBe(false);
			expect(truncated, `limit ${limit}`).toBe(false);
			// whole sets only, in first-seen order
			expect(isGroupedPrefix(d.additionals, m.additionals), `limit ${limit}`).toBe(true);
			const ns = d.additionals.filter((r) => r.type === TYPE.A);
			expect(ns.length % 2, `limit ${limit}: the ns.example set went out partly`).toBe(0);
		}
		// the issue's window: the later piece of the split set is the one that does not fit, so the whole set goes and the
		// small trailing TXT with it
		const { bytes } = encodeCapped(m, { limit: 300 });
		expect(decodeMessage(bytes).additionals).toEqual([A(1), A(2), TXT("p1.example.", 200)]);
	});

	it.each(["answers", "authorities", "additionals"])("rejoins a set split across the %s and keeps first-seen order", (section) => {
		const m = message({ [section]: [A(1), TXT("p1.example.", 400), A(2)] });
		const d = decodeMessage(encodeMessage(m));
		// the interleaved ns.example records travel together, ahead of the set first seen after them
		expect(d[section]).toEqual([A(1), A(2), TXT("p1.example.", 400)]);
	});

	it.each(["answers", "authorities", "additionals"])("drops the whole split set under a cap in the %s, keeping first-seen order", (section) => {
		const m = message({ [section]: [A(1), TXT("p1.example.", 400), A(2)] });
		const { bytes, truncated } = encodeCapped(m, { limit: 100 });
		const d = decodeMessage(bytes);
		// the ns.example set fits whole in first-seen position; the big TXT set does not, so it and everything after it go
		expect(d[section]).toEqual([A(1), A(2)]);
		expect(truncated).toBe(section !== "additionals");
		expect(d.flags.tc).toBe(section !== "additionals");
		if (section !== "additionals") {
			expect(d.authorities).toEqual([]);
			expect(d.additionals).toEqual([]);
		}
	});
});
