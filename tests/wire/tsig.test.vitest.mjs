/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/tsig.test.vitest.mjs
 */

/**
 * Signing around the capped encode (CLDMV/digby#39): `encodeCapped` may truncate, and truncating a message that already
 * carries a TSIG record invalidates its MAC (RFC 8945 5) — so the capped encode refuses pre-signed input, reserves space for
 * a TSIG with `reserveTsig`, and {@link appendTsig} puts the caller-signed record on the wire. Signing is outside the codec:
 * the codec holds no keys, so it binds the two calls instead (a private brand of the `encodeCapped` return object, a copy of
 * its bytes to catch mutation, the original-ID match, the reserved-size fit).
 */

import { describe, expect, it } from "vitest";
import { CLASS, TYPE } from "../../src/lib/wire/constants.mjs";
import { WireError } from "../../src/lib/wire/errors.mjs";
import { appendTsig, decodeMessage, encodeCapped, encodeMessage, tsigRecordSize } from "../../src/lib/wire/message.mjs";
import { genMessage, genName, genRdata, prng, seedFromEnv } from "../helpers/wire-gen.mjs";

const SEED = seedFromEnv("DIGBY_TSIG_SEED");
console.log(`wire tsig tests: DIGBY_TSIG_SEED=${SEED}`);

const code = (fn) => {
	try {
		fn();
	} catch (err) {
		if (!(err instanceof WireError)) throw err;
		return err.code;
	}
	return "no error";
};

const A = (i) => ({ name: "ns.example.", type: TYPE.A, class: 1, ttl: 60, data: { address: `10.0.0.${i}` } });
const TXT = (name, n) => ({ name, type: TYPE.TXT, class: 1, ttl: 60, data: { strings: Array.from({ length: Math.ceil(n / 255) }, (_, i) => Uint8Array.from({ length: Math.min(255, n - i * 255) }, () => 0x78)) } });
// one question: a truncating encode of a message without exactly one question is refused (CLDMV/digby#43)
const message = (sections) => ({ id: 1, flags: { qr: true }, rcode: 0, questions: [{ name: "example.", type: TYPE.A, class: 1 }], answers: [], authorities: [], additionals: [], ...sections });

/** A TSIG record a signer would produce for message id `originalId`; `macLen` sets its size. */
const tsigRecord = (originalId, macLen = 32) => ({
	name: "key.example.",
	type: TYPE.TSIG,
	class: CLASS.ANY,
	ttl: 0,
	data: { algorithm: "hmac-sha256.", timeSigned: 1, fudge: 300, mac: new Uint8Array(macLen), originalId, error: 0, otherData: new Uint8Array(0) }
});

describe(`TSIG around the capped encode (CLDMV/digby#39, seed ${SEED})`, () => {
	it("appendTsig appends the signed record as the last additional record and keeps the cap", () => {
		const tsig = tsigRecord(1);
		const need = tsigRecordSize(tsig);
		const capped = encodeCapped(message({ additionals: [A(1), TXT("p1.example.", 200), A(2), TXT("p2.example.", 10)] }), { limit: 280, reserveTsig: need });
		expect(capped.reserved).toBe(need);
		expect(capped.bytes.length + need).toBeLessThanOrEqual(280);
		const signed = appendTsig(capped, tsig);
		expect(signed.length).toBeLessThanOrEqual(280);
		expect(signed.length).toBe(capped.bytes.length + need);
		const d = decodeMessage(signed);
		// arcount bumped, TSIG last, and it is the record the signer handed over — original ID matching the message ID
		expect(d.additionals.length).toBe(decodeMessage(capped.bytes).additionals.length + 1);
		expect(d.additionals.at(-1)).toEqual(tsig);
		expect(d.additionals.at(-1).data.originalId).toBe(d.id);
	});

	it("appendTsig refuses everything but a fresh, untouched, matching reservation", () => {
		const tsig = tsigRecord(1);
		const need = tsigRecordSize(tsig);
		const capped = encodeCapped(message({ additionals: [A(1)] }), { limit: 280, reserveTsig: need });
		// not the object encodeCapped returned: bare bytes, or a result with no space reserved
		expect(code(() => appendTsig(capped.bytes, tsig))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => appendTsig(encodeCapped(message({ additionals: [A(1)] }), { limit: 280 }), tsig))).toBe("VALUE_OUT_OF_RANGE");
		// the bytes were changed after encodeCapped returned
		const mutated = encodeCapped(message({ additionals: [A(1)] }), { limit: 280, reserveTsig: need });
		mutated.bytes[12] ^= 0xff;
		expect(code(() => appendTsig(mutated, tsig))).toBe("VALUE_OUT_OF_RANGE");
		// signed for another message: the original ID is not this message's ID
		expect(code(() => appendTsig(capped, tsigRecord(2)))).toBe("VALUE_OUT_OF_RANGE");
		// larger than the space reserved for it
		expect(code(() => appendTsig(capped, tsigRecord(1, 64)))).toBe("VALUE_OUT_OF_RANGE");
		// and not a TSIG record at all
		expect(code(() => appendTsig(capped, { ...tsig, type: TYPE.A, data: { address: "10.0.0.1", originalId: 1 } }))).toBe("VALUE_OUT_OF_RANGE");
		// rdata that cannot encode: the codec's own error propagates untouched
		expect(code(() => appendTsig(capped, { ...tsig, data: { ...tsig.data, mac: "not octets" } }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("refuses a TSIG record whose class is not ANY or whose TTL is not 0 (RFC 8945 4.1.1, CLDMV/digby#39)", () => {
		const capped = encodeCapped(message({ additionals: [A(1)] }), { limit: 280, reserveTsig: tsigRecordSize(tsigRecord(1)) });
		expect(code(() => appendTsig(capped, { ...tsigRecord(1), class: CLASS.IN }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => appendTsig(capped, { ...tsigRecord(1), class: 1 }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => appendTsig(capped, { ...tsigRecord(1), ttl: 300 }))).toBe("VALUE_OUT_OF_RANGE");
		// the RFC 8945 form itself is accepted: class ANY, TTL 0
		expect(appendTsig(capped, tsigRecord(1)).length).toBe(capped.bytes.length + tsigRecordSize(tsigRecord(1)));
	});

	it("names the type of a non-numeric original ID in the refusal (CLDMV/digby#39)", () => {
		const capped = encodeCapped(message({ id: 4660, additionals: [A(1)] }), { limit: 280, reserveTsig: tsigRecordSize(tsigRecord(4660)) });
		let err;
		try {
			appendTsig(capped, { ...tsigRecord(4660), data: { ...tsigRecord(4660).data, originalId: "4660" } });
		} catch (e) {
			err = e;
		}
		// a string "4660" reads as the message's own ID in the old message; the type must be named
		expect(err).toBeInstanceOf(WireError);
		expect(err.message).toMatch(/original ID of type string/);
	});

	it("an overridden map on a section list cannot resurrect the caller's records (CLDMV/digby#39)", () => {
		class L extends Array {
			map() {
				return this;
			}
		}
		let reads = 0;
		const sneaky = {
			name: "key.example.",
			class: CLASS.ANY,
			ttl: 0,
			data: tsigRecord(1).data,
			get type() {
				return ++reads === 1 ? TYPE.A : TYPE.TSIG;
			}
		};
		// round 3 copied each section with the caller's own .map(), whose override returned the original array: the
		// TSIG-present check read the A type and the encode read it again as TSIG — the record went out as a TSIG with no
		// TSIG_PRESENT refusal, a regression against the one-copy rule. The copy is a structuredClone: the subclass and its
		// map do not survive it, the type is read the once, and the TSIG never reaches the wire — the A rdata cannot carry
		// TSIG data, so the encode refuses.
		const additionals = L.from([A(1), sneaky]);
		expect(code(() => encodeCapped(message({ additionals }), { limit: 400 }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("a reservation is single-use: appendTsig spends it (CLDMV/digby#39)", () => {
		const tsig = tsigRecord(1);
		const need = tsigRecordSize(tsig);
		const capped = encodeCapped(message({ additionals: [A(1)] }), { limit: 280, reserveTsig: need });
		const signed = appendTsig(capped, tsig);
		expect(signed.length).toBe(capped.bytes.length + need);
		// a second append against the same encodeCapped result is refused: one reservation cannot carry two TSIG records
		// (two records over the same unsigned bytes would each claim the MAC)
		expect(code(() => appendTsig(capped, tsig))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("encodeMessage refuses a TSIG record: signing happens only via appendTsig (CLDMV/digby#39)", () => {
		// re-encoding a signed message cannot keep the MAC valid (RFC 8945 5), so passing a TSIG through the encode
		// is never useful — encodeMessage refuses it with TSIG_PRESENT, the same as encodeCapped
		const tsig = tsigRecord(1);
		expect(code(() => encodeMessage(message({ additionals: [A(1), tsig] })))).toBe("TSIG_PRESENT");
		expect(code(() => encodeMessage(message({ additionals: [tsig] })))).toBe("TSIG_PRESENT");
		expect(code(() => encodeMessage(message({ answers: [tsig] })))).toBe("TSIG_PRESENT");
		expect(code(() => encodeMessage(message({ authorities: [tsig] })))).toBe("TSIG_PRESENT");
		// a misplaced TSIG gets the same refusal — the encode never examines placement for a record it refuses
		expect(code(() => encodeMessage(message({ additionals: [tsig, A(1)] })))).toBe("TSIG_PRESENT");
		// without the TSIG the same message encodes
		expect(encodeMessage(message({ additionals: [A(1)] })).length).toBeGreaterThan(0);
	});

	it("the property holds across generated messages and TSIG records", () => {
		const g = prng(SEED);
		for (let i = 0; i < 200; i++) {
			const m = genMessage(g, { maxRecords: 6 });
			// genMessage sometimes adds a TSIG itself; the capped encode refuses one (CLDMV/digby#39), so sign after truncation
			const unsigned = { ...m, additionals: m.additionals.filter((r) => r.type !== TYPE.TSIG) };
			const tsig = { name: genName(g, []), type: TYPE.TSIG, class: CLASS.ANY, ttl: 0, data: { ...genRdata(g, TYPE.TSIG, []), originalId: unsigned.id } };
			const need = tsigRecordSize(tsig);
			const limit = g.int(12, encodeMessage(unsigned).length + 16);
			let capped;
			try {
				capped = encodeCapped(unsigned, { limit, reserveTsig: need });
			} catch (err) {
				expect(err).toBeInstanceOf(WireError); // the header, questions and OPT alone exceed limit - need
				continue;
			}
			expect(capped.bytes.length + need, `i ${i}`).toBeLessThanOrEqual(limit);
			const signed = appendTsig(capped, tsig);
			expect(signed.length, `i ${i}`).toBeLessThanOrEqual(limit);
			const d = decodeMessage(signed, { maxQuestions: 2 });
			expect(d.additionals.at(-1), `i ${i}`).toEqual(tsig);
			expect(d.additionals.at(-1).data.originalId, `i ${i}`).toBe(d.id);
		}
	});
});
