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
import { WireError, WireErrorCode } from "../../src/lib/wire/errors.mjs";
import { decodeMessage } from "../../src/lib/wire/message.mjs";
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

// The worst pointer fan-out constructible in one 64 KB message: the question is a 253-octet zero-label name (126
// labels, held just under MAX_NAME on purpose) and every answer's owner is one fresh label plus a pointer to it, so
// each 14-octet record (class NONE with empty rdata keeps it minimal) expands to a 255-octet name. Every name stays
// within MAX_NAME, so the per-name guard never fires and the per-message name-octets cap is what stops the fan-out —
// 4,661 records would otherwise materialise ~1.19 M name octets. The fuzzer's mutations cannot build this shape.
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

// The rdata variant the issue describes: NS records whose owner is a bare pointer (free) and whose rdata name is one
// fresh label plus a pointer to the 253-octet question name — 16 octets of record expand to a 255-octet name, again
// held within MAX_NAME so the name-octets cap is what catches it.
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

	it("a maximal owner-name pointer fan-out is stopped by the name-octets cap", () => {
		const packet = ownerFanoutPacket();
		expect(packet.length).toBeLessThanOrEqual(65535);
		const err = code(() => decodeMessage(packet));
		expect(err).toBe(WireErrorCode.NAME_LIMIT);
	});

	it("NS rdata amplifies the same way and is stopped by the name-octets cap", () => {
		const packet = rdataFanoutPacket();
		expect(packet.length).toBeLessThanOrEqual(65535);
		const err = code(() => decodeMessage(packet));
		expect(err).toBe(WireErrorCode.NAME_LIMIT);
	});

	it("maxNameOctets is tunable: a cap below a name's wire size rejects it, one at or above it allows it", () => {
		const one = hex.from(`0000 0000 0001 0000 0000 0000 03 777777 07 6578616d706c65 00 0001 0001`);
		expect(decodeMessage(one, { maxNameOctets: 13 }).questions[0].name).toBe("www.example."); // the name is 13 wire octets
		expect(code(() => decodeMessage(one, { maxNameOctets: 12 }))).toBe(WireErrorCode.NAME_LIMIT);
	});
});

