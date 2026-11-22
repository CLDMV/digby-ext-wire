/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/amplification.test.vitest.mjs
 */

/**
 * @fileoverview Regression tests for the decode amplification of CLDMV/digby#34: one 64 KB packet whose compression
 * pointers all resolve to the same name must not re-expand that name per pointer, and the pointer fan-outs the fuzzer
 * cannot reach (a fresh label before every pointer, in owner names or in NS rdata) must be stopped by the per-message
 * name-octets cap.
 */

import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import { Reader } from "../../src/lib/wire/buffer.mjs";
import { WireError, WireErrorCode } from "../../src/lib/wire/errors.mjs";
import { decodeMessage } from "../../src/lib/wire/message.mjs";
import { readName } from "../../src/lib/wire/names.mjs";
import { hex } from "../helpers/wire-gen.mjs";

const code = (fn) => {
	try {
		fn();
	} catch (err) {
		if (!(err instanceof WireError)) throw err;
		return err.code;
	}
	return "no error";
};

// The reproduction packet from CLDMV/digby#34: qdcount 10878; the first question is a 255-octet name of zero-byte
// labels (127 labels of one 0x00 octet each, 254 + 1 root octets); the other 10,877 questions are C0 0C 00 01 00 01
// (a pointer to offset 12, the first question's name); 65,533 octets in total.
function amplificationPacket() {
	const b = [0, 0, 0x01, 0x00, 0x2a, 0x7e, 0, 0, 0, 0, 0, 0]; // id 0, RD, qdcount 10878
	for (let i = 0; i < 127; i++) b.push(1, 0);
	b.push(0, 0x00, 0x01, 0x00, 0x01); // root, type A, class IN
	for (let i = 0; i < 10877; i++) b.push(0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01);
	return Uint8Array.from(b); // 12 + 255 + 4 + 10877 * 6 = 65533 octets
}

const ZERO_LABEL_NAME = "\\000.".repeat(127);

// A maximal pointer fan-out over a repeated suffix: the question is a 253-octet zero-label name (126 labels, held
// just under MAX_NAME) and every answer's owner is one fresh label plus a pointer to it — 4,661 14-octet records
// (class NONE with empty rdata keeps them minimal). Every pointer is a memo hit, so the decode is linear and charges
// only each owner's own label octet; the materialised characters are the names' inherent content.
function ownerFanoutPacket() {
	const records = Math.floor((65535 - 12 - 257) / 14); // the question is 257 octets, each record 14
	const b = [0, 0, 0x01, 0x00, 0, 1, records >> 8, records & 0xff, 0, 0, 0, 0]; // qdcount 1, ancount = records
	for (let i = 0; i < 126; i++) b.push(1, 0);
	b.push(0, 0x00, 0x01, 0x00, 0x01);
	for (let i = 0; i < records; i++) {
		// owner: label "a" + pointer to 12; type NS, class NONE, ttl 0, rdlength 0 (the RFC 2136 empty-rdata form)
		b.push(1, 0x61, 0xc0, 0x0c, 0, 2, 0, 254, 0, 0, 0, 0, 0, 0);
	}
	return Uint8Array.from(b);
}

// The rdata variant of the same fan-out: NS records whose owner is a bare pointer (free) and whose rdata name is one
// fresh label plus a pointer to the 253-octet question name — again all memo hits, linear in the record count.
function rdataFanoutPacket() {
	const records = Math.floor((65535 - 12 - 257) / 16); // the question is 257 octets, each record 16
	const b = [0, 0, 0x01, 0x00, 0, 1, records >> 8, records & 0xff, 0, 0, 0, 0]; // qdcount 1, ancount = records
	for (let i = 0; i < 126; i++) b.push(1, 0);
	b.push(0, 0x00, 0x01, 0x00, 0x01);
	for (let i = 0; i < records; i++) {
		// owner: pointer to 12; type NS, class IN, ttl 0, rdlength 4; rdata: label "a" + pointer to 12
		b.push(0xc0, 0x0c, 0, 2, 0, 1, 0, 0, 0, 0, 0, 4, 1, 0x61, 0xc0, 0x0c);
	}
	return Uint8Array.from(b);
}

describe("decode amplification (CLDMV/digby#34)", () => {
	it("the reproduction packet decodes correctly, quickly and small, with an explicit maxQuestions", () => {
		const packet = amplificationPacket();
		expect(packet.length).toBe(65533);
		// Bounds, chosen with headroom on both sides: the pre-fix decoder took ~180 ms and grew the heap ~145 MB on
		// this packet (6.9 M name characters: 635 per name, 127 one-octet zero labels, x 10,878 questions); the
		// fixed decoder retains one cached 635-character name string plus
		// 10,878 small question objects (~1-3 MB) and decodes in single-digit milliseconds. 50 ms and 8 MB leave
		// several-fold headroom over the fixed cost — enough to absorb coverage instrumentation and CI noise — while
		// staying far below the broken behaviour, so the regression cannot pass silently.
		const TIME_BUDGET_MS = 50;
		const HEAP_BUDGET_BYTES = 8 * 1024 * 1024;
		const decode = () => decodeMessage(packet, { maxQuestions: 0xffff });
		decode(); // warm-up, so the timed run measures steady-state rather than JIT
		const t0 = performance.now();
		const m = decode();
		const ms = performance.now() - t0;
		expect(ms).toBeLessThan(TIME_BUDGET_MS);
		// Heap: decode several times and take the smallest heapUsed delta, so one noisy GC pass does not dominate
		// the measurement (globalThis.gc is not exposed under the vitest runner). Each iteration's result is alive
		// when its delta is taken, so every delta is at least the decode's retained size.
		let heap = Infinity;
		for (let i = 0; i < 5; i++) {
			const before = process.memoryUsage().heapUsed;
			const kept = decode();
			heap = Math.min(heap, process.memoryUsage().heapUsed - before);
			if (kept.questions.length !== 10878) throw new Error("the kept decode was discarded early");
		}
		expect(heap).toBeLessThan(HEAP_BUDGET_BYTES);
		expect(m.questions).toHaveLength(10878);
		for (const q of m.questions) {
			expect(q.name).toBe(ZERO_LABEL_NAME);
			expect(q.type).toBe(1);
			expect(q.class).toBe(1);
		}
	});

	it("the default decode rejects the packet instead of allocating it", () => {
		const err = code(() => decodeMessage(amplificationPacket()));
		expect(err).toBe(WireErrorCode.QUESTION_LIMIT);
	});

	it("maxQuestions allows exactly that many questions and rejects one more", () => {
		const two = hex.from(`0000 0000 0002 0000 0000 0000 03 777777 07 6578616d706c65 00 0001 0001 03 777777 07 6578616d706c65 00 0001 0001`);
		expect(decodeMessage(two, { maxQuestions: 2 }).questions).toHaveLength(2);
		expect(code(() => decodeMessage(two, { maxQuestions: 1 }))).toBe(WireErrorCode.QUESTION_LIMIT);
		expect(code(() => decodeMessage(two))).toBe(WireErrorCode.QUESTION_LIMIT);
	});

	it("a maximal owner-name pointer fan-out decodes through the memo", () => {
		const packet = ownerFanoutPacket();
		expect(packet.length).toBeLessThanOrEqual(65535);
		const m = decodeMessage(packet);
		expect(m.answers).toHaveLength(4661);
		const name = `a.${"\\000.".repeat(126)}`;
		expect(m.answers[0].name).toBe(name);
		expect(m.answers[m.answers.length - 1].name).toBe(name);
	});

	it("NS rdata amplification decodes through the memo as well", () => {
		const packet = rdataFanoutPacket();
		expect(packet.length).toBeLessThanOrEqual(65535);
		const m = decodeMessage(packet);
		expect(m.answers).toHaveLength(4079);
		const target = `a.${"\\000.".repeat(126)}`;
		for (const a of m.answers) expect(a.data.target).toBe(target);
	});

	it("a memoised suffix reused behind long own labels still respects MAX_NAME", () => {
		// The first question's name is 199 wire octets; the second is a 62-octet label plus a pointer to it, which
		// walks to 262 octets. The memo path skips walking the suffix, so the combined-length check at the reuse is
		// what must keep the per-name limit (a naive memo would return the 262-octet name).
		const b = [0, 0, 0x01, 0x00, 0, 2, 0, 0, 0, 0, 0, 0];
		for (let i = 0; i < 99; i++) b.push(1, 0);
		b.push(0, 0x00, 0x01, 0x00, 0x01);
		b.push(62, ...Array(62).fill(0x61), 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01);
		expect(code(() => decodeMessage(Uint8Array.from(b), { maxQuestions: 2 }))).toBe(WireErrorCode.NAME_TOO_LONG);
	});

	it("a pointer to the root adds only the final dot behind its own labels", () => {
		// The question's name is the root; the answer's owner is one label plus a pointer back to it, so the reused
		// suffix is "." itself — the result is "a.", not "a..".
		const b = [0, 0, 0x01, 0x00, 0, 1, 0, 1, 0, 0, 0, 0];
		b.push(0, 0x00, 0x01, 0x00, 0x01); // question: root name, type A, class IN
		b.push(1, 0x61, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 1, 0, 4, 0x7f, 0, 0, 1);
		const m = decodeMessage(Uint8Array.from(b));
		expect(m.questions[0].name).toBe(".");
		expect(m.answers[0].name).toBe("a.");
	});

	// Review finding 1: pointers into the MIDDLE of a name must be memo hits too. The question is the 255-octet
	// zero-label name; every answer's owner is a bare pointer to its second label (offset 14). Without middle-offset
	// memoisation each 12-octet answer re-walks 253 wire octets and re-formats 630 characters — 2,000 answers
	// materialise ~1.26 M characters from a 24 KB packet (~50x its size). With the memo recording every label offset,
	// the packet charges only the question's own 254 label octets, so a cap of twice the packet size — which the
	// broken decoder blows through — must decode.
	function middlePointerPacket() {
		const answers = 2000;
		const b = [0, 0, 0x01, 0x00, 0, 1, answers >> 8, answers & 0xff, 0, 0, 0, 0];
		for (let i = 0; i < 127; i++) b.push(1, 0);
		b.push(0, 0x00, 0x01, 0x00, 0x01); // root, type A, class IN
		for (let i = 0; i < answers; i++) {
			// owner: pointer to offset 14 (the second label); type NS, class NONE, ttl 0, rdlength 0
			b.push(0xc0, 0x0e, 0, 2, 0, 254, 0, 0, 0, 0, 0, 0);
		}
		return Uint8Array.from(b); // 12 + 255 + 4 + 2000 * 12 = 24271 octets
	}

	it("a pointer into the middle of a name reuses the memo and charges nothing", () => {
		const packet = middlePointerPacket();
		expect(packet.length).toBe(24271);
		const suffix = "\\000.".repeat(126);
		const m = decodeMessage(packet, { maxNameOctets: 2 * packet.length });
		expect(m.questions[0].name).toBe("\\000.".repeat(127));
		expect(m.answers).toHaveLength(2000);
		for (const a of m.answers) expect(a.name).toBe(suffix);
		expect(decodeMessage(packet).answers).toHaveLength(2000); // the default cap leaves room, too
	});

	// Review finding 2: a memo hit must equal a fresh decode at that offset, including its pointer-hop count. 200
	// answers chain their owners backwards (each a bare pointer to the previous owner's field start, the first to the
	// root question at offset 12), so a fresh decode of the Nth owner takes N hops and refuses at POINTER_LIMIT past
	// MAX_POINTER_HOPS; a memo that drops the hop count accepts the whole chain.
	function pointerChainPacket() {
		const answers = 200;
		const b = [0, 0, 0x01, 0x00, 0, 1, answers >> 8, answers & 0xff, 0, 0, 0, 0];
		b.push(0, 0x00, 0x01, 0x00, 0x01); // the question's name is the root, at offset 12
		for (let i = 0; i < answers; i++) {
			const target = i === 0 ? 12 : 17 + 12 * (i - 1); // the previous answer's owner field start
			b.push(0xc0 | (target >> 8), target & 0xff, 0, 2, 0, 254, 0, 0, 0, 0, 0, 0);
		}
		return Uint8Array.from(b); // 12 + 5 + 200 * 12 = 2417 octets
	}

	it("a memo hit carries the pointer-hop count of a fresh decode", () => {
		const packet = pointerChainPacket();
		expect(packet.length).toBe(2417);
		expect(code(() => decodeMessage(packet))).toBe(WireErrorCode.POINTER_LIMIT);
	});

	// Review finding 3: a legitimate large response must decode. 2,900 A records over a 201-octet apex (100
	// one-octet labels), each owner a fresh 4-octet label plus a pointer to the apex: 61,117 octets. The repeated
	// apex is memoised, so the decode charges only each owner's own label octets (~14.7 K); a cap that charges the
	// reused suffix per record (~597 K) wrongly refuses it.
	function apexResponsePacket() {
		const answers = 2900;
		const c = (n) => 0x61 + (n % 26);
		const b = [0, 0, 0x01, 0x00, 0, 1, answers >> 8, answers & 0xff, 0, 0, 0, 0];
		for (let i = 0; i < 100; i++) b.push(1, c(i)); // the apex: 100 one-octet labels, 201 wire octets
		b.push(0, 0x00, 0x01, 0x00, 0x01);
		for (let i = 0; i < answers; i++) {
			// owner: fresh 4-octet label + pointer to the apex; type A, class IN, ttl 0, rdlength 4, rdata 127.0.0.1
			b.push(4, c(i), c(i >> 1), c(i >> 2), c(i >> 3), 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 0x7f, 0, 0, 1);
		}
		return Uint8Array.from(b); // 12 + 201 + 4 + 2900 * 21 = 61117 octets
	}

	it("a large response with a repeated compressed apex decodes", () => {
		const packet = apexResponsePacket();
		expect(packet.length).toBe(61117);
		const apex = Array.from({ length: 100 }, (_, i) => String.fromCharCode(0x61 + (i % 26))).join(".") + ".";
		const m = decodeMessage(packet);
		expect(m.questions[0].name).toBe(apex);
		expect(m.answers).toHaveLength(2900);
		for (const a of m.answers) expect(a.name.endsWith(apex)).toBe(true);
	});

	it("maxNameOctets is tunable: a cap below a name's own label octets rejects it, one at or above it allows it", () => {
		const one = hex.from(`0000 0000 0001 0000 0000 0000 03 777777 07 6578616d706c65 00 0001 0001`);
		// the name's own labels are 12 wire octets (13 with the root); the charge counts own labels only
		expect(decodeMessage(one, { maxNameOctets: 12 }).questions[0].name).toBe("www.example.");
		expect(code(() => decodeMessage(one, { maxNameOctets: 11 }))).toBe(WireErrorCode.NAME_LIMIT);
	});

	// Review finding 5: the memo's guard branches, exercised through readName directly (it is exported) with a
	// hand-constructed Reader — no decodeMessage path reaches them.
	it("readName returns a pre-seeded memo entry at its start offset", () => {
		const r = new Reader(hex.from(`03 616263 00 0001 0001`), 12);
		r.nameMemo = new Map([[12, { text: "cached.", wire: 5, hops: 2, end: 16 }]]);
		expect(readName(r)).toBe("cached.");
		expect(r.pos).toBe(16);
	});

	it("readName with a memo but no cap decodes and charges nothing", () => {
		const r = new Reader(hex.from(`03 616263 00`));
		r.nameMemo = new Map();
		expect(readName(r)).toBe("abc.");
		expect(r.maxNameOctets).toBeUndefined();
		expect(r.nameOctets).toBeUndefined(); // chargeName returned at the cap guard
	});

	it("readName with a cap but no counter initialises it from zero", () => {
		const r = new Reader(hex.from(`03 616263 00`));
		r.nameMemo = new Map();
		r.maxNameOctets = 100;
		expect(readName(r)).toBe("abc.");
		expect(r.nameOctets).toBe(4); // (r.nameOctets ?? 0) + the name's 4 own label octets
	});
});

