/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/snapshot.test.vitest.mjs
 */

/**
 * One copy of the caller's input (CLDMV/digby#39): the encode paths read caller objects more than once, so a getter can show
 * the checks one value and the writer another — a TSIG can get past the TSIG_PRESENT refusal, a flipping type can split an
 * RRset under truncation, appendTsig can write a record unlike the one it checked, and the caller's bytes can be swapped
 * after the comparison.
 *
 * Round 4 (CLDMV/digby#39): every public encode entry (encodeMessage, encodeCapped, appendTsig, tsigRecordSize, formatRecord,
 * formatRdata, encodeRdataBytes) copies its input once with structuredClone and validates and writes only the clone. V8's
 * serializer reads each own enumerable property exactly once, so the getter-count form still holds (a field whose getter
 * counts its reads is read exactly once across a full encode); no caller method, iterator or `Symbol.species` runs; a
 * typed-array subclass arrives as a plain Uint8Array of its real octets; a faked brand arrives as a plain object the field
 * checks refuse. The round-3 hand-written snapshot (snapshotRdata and the per-field copy helpers) is gone. Anything the
 * serializer refuses — a function, a Proxy, a symbol — is refused NOT_CLONEABLE, and so is a list longer than 65,535
 * entries that is not dense, or a list with a hole; a self-referential value is walked once (visited set) and encodes as
 * round 3's depth-bounded copy did.
 */

import { describe, expect, it } from "vitest";
import { Writer } from "../../src/lib/wire/buffer.mjs";
import { CLASS, TYPE } from "../../src/lib/wire/constants.mjs";
import { writeTypeBitmap } from "../../src/lib/wire/rdata/dnssec.mjs";
import { decodeRdataBytes, encodeRdataBytes, formatRdata } from "../../src/lib/wire/rdata/index.mjs";
import { appendTsig, decodeMessage, encodeCapped, encodeMessage, tsigRecordSize } from "../../src/lib/wire/message.mjs";
import { canonicalName, namesEqual, parseName } from "../../src/lib/wire/names.mjs";
import { formatRecord, parseRdata, parseRecord, parseTtl } from "../../src/lib/wire/presentation.mjs";
import { WireError } from "../../src/lib/wire/errors.mjs";

const code = (fn) => {
	try {
		fn();
	} catch (err) {
		if (!(err instanceof WireError)) throw err;
		return err.code;
	}
	return "no error";
};

/**
 * An object whose own enumerable fields are getters that count their reads into `counts`, so a test can assert the codec
 * reads each field exactly once (CLDMV/digby#39).
 * @param {Record<string, unknown>} fields
 * @param {Record<string, number>} counts
 * @returns {object}
 */
const counting = (fields, counts) => {
	const out = {};
	for (const [k, v] of Object.entries(fields))
		Object.defineProperty(out, k, { get: () => ((counts[k] = (counts[k] ?? 0) + 1), v), enumerable: true });
	return out;
};

const A = (i) => ({ name: "ns.example.", type: TYPE.A, class: 1, ttl: 60, data: { address: `10.0.0.${i}` } });
const TXT = (name, n) => ({
	name,
	type: TYPE.TXT,
	class: 1,
	ttl: 60,
	data: { strings: Array.from({ length: Math.ceil(n / 255) }, (_, i) => Uint8Array.from({ length: Math.min(255, n - i * 255) }, () => 0x78)) }
});
// flags, sections and edns materialised the way the decoder returns them
const message = (sections) => ({ id: 1, flags: { qr: true, opcode: 0, aa: false, tc: false, rd: false, ra: false, z: false, ad: false, cd: false }, rcode: 0, questions: [], answers: [], authorities: [], additionals: [], edns: null, ...sections });
/** A TSIG record's rdata for message id `originalId`. */
const tsigData = (originalId) => ({ algorithm: "hmac-sha256.", timeSigned: 1, fudge: 300, mac: new Uint8Array(32), originalId, error: 0, otherData: new Uint8Array(0) });
const tsigRecord = (originalId) => ({ name: "key.example.", type: TYPE.TSIG, class: CLASS.ANY, ttl: 0, data: tsigData(originalId) });

describe("one snapshot of the caller's input (CLDMV/digby#39)", () => {
	it("encodeMessage reads each field of the message, its questions and its records exactly once", () => {
		const mc = {};
		const fc = {};
		const qc = {};
		const rc = {};
		const dc = {};
		const ec = {};
		const q = counting({ name: "q.example.", type: TYPE.A, class: 1 }, qc);
		const data = counting({ address: "10.0.0.1" }, dc);
		const rec = counting({ name: "a.example.", type: TYPE.A, class: 1, ttl: 60, data }, rc);
		const m = counting(
			{
				id: 1,
				flags: counting({ qr: true }, fc),
				rcode: 0,
				questions: [q],
				answers: [rec],
				authorities: [],
				additionals: [],
				edns: counting({ udpSize: 1232, options: [{ code: 12, length: 10 }] }, ec)
			},
			mc
		);
		encodeMessage(m);
		expect(mc).toEqual({ id: 1, flags: 1, rcode: 1, questions: 1, answers: 1, authorities: 1, additionals: 1, edns: 1 });
		expect(fc).toEqual({ qr: 1 });
		expect(qc).toEqual({ name: 1, type: 1, class: 1 });
		expect(rc).toEqual({ name: 1, type: 1, class: 1, ttl: 1, data: 1 });
		expect(dc).toEqual({ address: 1 });
		expect(ec).toEqual({ udpSize: 1, options: 1 });
	});

	it("encodeCapped reads each field exactly once across a truncating encode", () => {
		const mc = {};
		const rc = {};
		const dc = {};
		const data = counting({ address: "1.2.3.4" }, dc);
		const rec = counting({ name: "x.example.", type: TYPE.A, class: 1, ttl: 60, data }, rc);
		const m = counting(
			{
				id: 1,
				flags: { qr: true },
				rcode: 0,
				// one question: a truncating encode of a message without exactly one question is refused (CLDMV/digby#43).
				// q.test. shares no suffix with the records below, so it costs the packet exactly 11 octets
				questions: [{ name: "q.test.", type: TYPE.A, class: 1 }],
				answers: [rec, TXT("big.example.", 400), A(2)],
				authorities: [],
				additionals: [],
				edns: null
			},
			mc
		);
		// the truncation path is where the re-reads lived: the RRset grouping and the probe, trial and final writes all
		// touched the caller's records again
		const { truncated } = encodeCapped(m, { limit: 60 });
		expect(truncated).toBe(true);
		expect(mc).toEqual({ id: 1, flags: 1, rcode: 1, questions: 1, answers: 1, authorities: 1, additionals: 1, edns: 1 });
		expect(rc).toEqual({ name: 1, type: 1, class: 1, ttl: 1, data: 1 });
		expect(dc).toEqual({ address: 1 });
	});

	it("a type that is not an integer is refused at the copy — no fallback read can send a TSIG (CLDMV/digby#39)", () => {
		// a getter that hides the TSIG behind a missing type on the one read the copy takes: today the TSIG-present check
		// sees nothing and the encode's `type ?? rec.type` fallback reads the TSIG out of the same object
		let cappedReads = 0;
		const cappedSneaky = {
			name: "key.example.",
			class: CLASS.ANY,
			ttl: 0,
			data: tsigData(1),
			get type() {
				return ++cappedReads === 1 ? undefined : TYPE.TSIG;
			}
		};
		expect(code(() => encodeCapped(message({ additionals: [A(1), cappedSneaky] }), { limit: 400 }))).toBe("VALUE_OUT_OF_RANGE");
		let plainReads = 0;
		const plainSneaky = {
			name: "key.example.",
			class: CLASS.ANY,
			ttl: 0,
			data: tsigData(1),
			get type() {
				return ++plainReads === 1 ? null : TYPE.TSIG;
			}
		};
		expect(code(() => encodeMessage({ id: 1, additionals: [plainSneaky] }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("a flipping type getter cannot split an RRset under truncation (CLDMV/digby#39)", () => {
		let reads = 0;
		const flip = {
			name: "x.example.",
			class: 1,
			ttl: 60,
			data: { address: "1.2.3.4" },
			get type() {
				return ++reads === 1 ? TYPE.A : TYPE.TXT;
			}
		};
		const a5 = { name: "x.example.", type: TYPE.A, class: 1, ttl: 60, data: { address: "1.2.3.5" } };
		// the grouping must see the type the one read produced: the two x. A records share one RRset and go out together —
		// never the split pair a second read produces, where only the first record leaves and the set travels partly
		// one question: a truncating encode of a message without exactly one question is refused (CLDMV/digby#43).
		// q.test. shares no suffix with the records below, so it costs the packet exactly 11 octets and the kept set
		// (12 head + 11 question + 24 flip + 16 for a5's compressed owner) is 63 — the window moves 60..483 to 63..486
		const { bytes, truncated } = encodeCapped(message({ questions: [{ name: "q.test.", type: TYPE.A, class: 1 }], answers: [flip, TXT("big.example.", 400), a5] }), { limit: 63 });
		const d = decodeMessage(bytes);
		expect(d.answers).toEqual([{ name: "x.example.", type: TYPE.A, class: 1, ttl: 60, data: { address: "1.2.3.4" } }, a5]);
		expect(truncated).toBe(true);
		expect(d.flags.tc).toBe(true);
	});

	it("a question's type is written as the value the reserved check saw (CLDMV/digby#39)", () => {
		let reads = 0;
		const q = {
			name: "q.example.",
			class: 1,
			get type() {
				return ++reads === 1 ? TYPE.A : 0;
			}
		};
		// today the reserved check reads A and the write reads 0, putting a reserved type on the wire
		const d = decodeMessage(encodeMessage({ id: 0, questions: [q] }));
		expect(d.questions[0].type).toBe(TYPE.A);
	});

	it("an RRSIG's typeCovered is written as the value the reserved check saw (CLDMV/digby#39)", () => {
		let reads = 0;
		const data = {
			algorithm: 13,
			labels: 2,
			originalTtl: 3600,
			expiration: 0,
			inception: 0,
			keyTag: 1,
			signerName: "example.",
			signature: new Uint8Array([1, 2, 3]),
			get typeCovered() {
				return ++reads === 1 ? TYPE.A : 0;
			}
		};
		const d = decodeMessage(encodeMessage({ id: 0, answers: [{ name: "x.example.", type: TYPE.RRSIG, class: 1, ttl: 60, data }] }));
		expect(d.answers[0].data.typeCovered).toBe(TYPE.A);
	});

	it("formatRecord reads each field exactly once", () => {
		const rc = {};
		const dc = {};
		const data = counting({ address: "10.0.0.1" }, dc);
		const rec = counting({ name: "a.example.", ttl: 60, class: 1, type: TYPE.A, data }, rc);
		expect(formatRecord(rec)).toBe("a.example. 60 IN A 10.0.0.1");
		expect(rc).toEqual({ name: 1, ttl: 1, class: 1, type: 1, data: 1 });
		expect(dc).toEqual({ address: 1 });
	});

	it("formatRdata reads each rdata field exactly once", () => {
		const dc = {};
		const data = counting(
			{ typeCovered: TYPE.A, algorithm: 13, labels: 2, originalTtl: 3600, expiration: 0, inception: 0, keyTag: 1, signerName: "example.", signature: new Uint8Array([1, 2, 3]) },
			dc
		);
		expect(formatRdata(TYPE.RRSIG, data)).toBe("A 13 2 3600 19700101000000 19700101000000 1 example. AQID");
		expect(dc).toEqual({ typeCovered: 1, algorithm: 1, labels: 1, originalTtl: 1, expiration: 1, inception: 1, keyTag: 1, signerName: 1, signature: 1 });
	});

	it("writeTypeBitmap reads each type once", () => {
		const types = [];
		const reads = [];
		[TYPE.A, TYPE.TXT, TYPE.AAAA].forEach((t, i) => {
			let n = 0;
			Object.defineProperty(types, i, { get: () => (n++, t), enumerable: true });
			reads.push(() => n);
		});
		const w = new Writer({ compress: false });
		writeTypeBitmap(w, types);
		// the validation loop and the dedupe must not each walk the caller's list
		expect(reads.map((r) => r())).toEqual([1, 1, 1]);
	});

	it("appendTsig and tsigRecordSize read each TSIG-record field exactly once", () => {
		const need = tsigRecordSize(tsigRecord(1));
		const capped = encodeCapped(message({ additionals: [A(1)] }), { limit: 280, reserveTsig: need });
		const sizeCounts = {};
		const sizeData = {};
		const sized = counting(
			{ name: "key.example.", type: TYPE.TSIG, class: CLASS.ANY, ttl: 0, data: counting({ ...tsigData(1), mac: new Uint8Array(4) }, sizeData) },
			sizeCounts
		);
		tsigRecordSize(sized);
		expect(sizeCounts).toEqual({ name: 1, type: 1, class: 1, ttl: 1, data: 1 });
		expect(sizeData).toEqual({ algorithm: 1, timeSigned: 1, fudge: 1, mac: 1, originalId: 1, error: 1, otherData: 1 });
		const appCounts = {};
		const appData = {};
		const appended = counting(
			{ name: "key.example.", type: TYPE.TSIG, class: CLASS.ANY, ttl: 0, data: counting({ ...tsigData(1), mac: new Uint8Array(4) }, appData) },
			appCounts
		);
		appendTsig(capped, appended);
		expect(appCounts).toEqual({ name: 1, type: 1, class: 1, ttl: 1, data: 1 });
		expect(appData).toEqual({ algorithm: 1, timeSigned: 1, fudge: 1, mac: 1, originalId: 1, error: 1, otherData: 1 });
	});

	it("appendTsig writes the record it checked: flipping class, TTL or original ID cannot diverge (CLDMV/digby#39)", () => {
		const need = tsigRecordSize(tsigRecord(1));
		const capped = encodeCapped(message({ additionals: [A(1)] }), { limit: 280, reserveTsig: need });
		let classReads = 0;
		let ttlReads = 0;
		let idReads = 0;
		const rec = {
			name: "key.example.",
			type: TYPE.TSIG,
			get class() {
				return ++classReads === 1 ? CLASS.ANY : CLASS.IN;
			},
			get ttl() {
				return ++ttlReads === 1 ? 0 : 300;
			},
			data: {
				...tsigData(1),
				mac: new Uint8Array(4),
				get originalId() {
					return ++idReads === 1 ? 1 : 4660;
				}
			}
		};
		const signed = appendTsig(capped, rec);
		const d = decodeMessage(signed);
		const last = d.additionals.at(-1);
		// the record on the wire is the one the checks saw: class ANY, TTL 0, this message's ID (RFC 8945 4.1.1 and 5)
		expect(last.class).toBe(CLASS.ANY);
		expect(last.ttl).toBe(0);
		expect(last.data.originalId).toBe(d.id);
	});

	it("appendTsig writes the bytes it compared: a getter cannot swap the message after the comparison (CLDMV/digby#39)", () => {
		const need = tsigRecordSize(tsigRecord(1));
		const build = () => {
			const capped = encodeCapped(message({ additionals: [A(1)] }), { limit: 280, reserveTsig: need });
			const real = capped.bytes;
			const other = real.slice();
			other[0] = 0;
			other[1] = 2; // the same length, a different message: ID 2
			let reads = 0;
			Object.defineProperty(capped, "bytes", {
				get: () => (++reads <= 3 ? real : other) // the real bytes to the comparison, the other message to the write
			});
			return capped;
		};
		// a record signed for the message encodeCapped returned: the swapped bytes are never written, so it signs the real one
		const signed = appendTsig(build(), tsigRecord(1));
		expect(decodeMessage(signed).id).toBe(1);
		// a record signed for the swapped message: the codec binds the append to the bytes it reserved for, so it is refused
		expect(code(() => appendTsig(build(), tsigRecord(2)))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("appendTsig compares the bytes element by element: a .some() override cannot fake the comparison (CLDMV/digby#39)", () => {
		const need = tsigRecordSize(tsigRecord(1));
		const capped = encodeCapped(message({ additionals: [A(1)] }), { limit: 280, reserveTsig: need });
		class Sneaky extends Uint8Array {
			some() {
				return false; // claims every element matches the snapshot
			}
		}
		const lying = new Sneaky(capped.bytes);
		lying[12] ^= 0xff;
		Object.defineProperty(capped, "bytes", { value: lying });
		// the comparison must not call a method the caller's array can override: the changed octet is caught element by element
		expect(code(() => appendTsig(capped, tsigRecord(1)))).toBe("VALUE_OUT_OF_RANGE");
	});
});

describe("one structuredClone of the caller's input (CLDMV/digby#39, round 4)", () => {
	it("Symbol.species is never consulted: a section subclass with a broken species encodes its records (CLDMV/digby#39)", () => {
		class Broken extends Array {
			static get [Symbol.species]() {
				return function () {
					return {};
				};
			}
		}
		// round 3 copied each section with the caller's own .map(), whose ArraySpeciesCreate consulted the species: the
		// species returned a plain object, the copies landed on it as keys, and the encode iterated a non-array — a raw
		// TypeError escaped. The copy is a structuredClone: the subclass and its species do not survive it.
		const additionals = Broken.from([A(1), A(2), A(3)]);
		const d = decodeMessage(encodeMessage({ id: 1, additionals }));
		expect(d.additionals).toEqual([A(1), A(2), A(3)]);
	});

	it("a faked Uint8Array brand is refused: the clone is a plain object, not octets (CLDMV/digby#39)", () => {
		const fake = Object.setPrototypeOf({}, Uint8Array.prototype);
		// today: the instance-of check passes the prototype chain, the writer reserves fake.length (undefined) and poisons
		// its length with NaN — a raw RangeError out of the grow path
		expect(code(() => encodeMessage({ id: 1, answers: [{ name: "x.example.", type: 999, class: 1, ttl: 0, data: { data: fake } }] }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("a Proxy is refused NOT_CLONEABLE: with a faked prototype, around real octets, or around a whole record (CLDMV/digby#39)", () => {
		const fake = new Proxy(Object.setPrototypeOf({}, Uint8Array.prototype), {});
		expect(code(() => encodeMessage({ id: 1, answers: [{ name: "x.example.", type: 999, class: 1, ttl: 0, data: { data: fake } }] }))).toBe("NOT_CLONEABLE");
		const wrapped = new Proxy(new Uint8Array([1, 2, 3]), {});
		// today the instance-of check forwards through the proxy and the octets encode
		expect(code(() => encodeMessage({ id: 1, answers: [{ name: "x.example.", type: 999, class: 1, ttl: 0, data: { data: wrapped } }] }))).toBe("NOT_CLONEABLE");
		const rec = new Proxy(A(1), {});
		expect(code(() => encodeMessage({ id: 1, answers: [rec] }))).toBe("NOT_CLONEABLE");
	});

	it("a function is refused NOT_CLONEABLE and a self-referential value encodes without hanging (CLDMV/digby#39)", () => {
		expect(code(() => encodeMessage({ id: 1, answers: [{ name: "x.example.", type: 999, class: 1, ttl: 0, data: { data: () => {} } }] }))).toBe("NOT_CLONEABLE");
		const cyclic = { data: new Uint8Array([1]) };
		cyclic.self = cyclic;
		// the copy preserves the cycle and both walks bound themselves with a visited set; the codecs read only the fields
		// they know, so the value encodes exactly as round 3's depth-bounded copy did — never a hang, never an OOM
		expect(encodeRdataBytes(999, cyclic)).toEqual(new Uint8Array([1]));
	});

	it("a MAC whose length lies is written from its real octets (CLDMV/digby#39)", () => {
		class LyingMac extends Uint8Array {
			get length() {
				return 16;
			}
		}
		const mac = new LyingMac(32); // 32 real octets, reports 16
		const rec = { name: "key.example.", type: TYPE.TSIG, class: CLASS.ANY, ttl: 0, data: { ...tsigData(1), mac } };
		// today: the length field says 16 octets, .set() copies all 32, and the record on the wire does not round-trip —
		// the decode misreads everything after the MAC (its originalId is not the message's ID). A TSIG record travels
		// only through appendTsig now — encodeMessage refuses one (CLDMV/digby#39) — so the record is appended to a
		// reservation sized for the record the copy actually produces (the copy erases the length getter)
		const reserve = tsigRecordSize({ ...rec, data: { ...tsigData(1), mac: new Uint8Array(32) } });
		const capped = encodeCapped(message({ additionals: [A(1)] }), { limit: 280, reserveTsig: reserve });
		const d = decodeMessage(appendTsig(capped, rec));
		expect(d.additionals.at(-1).data.mac).toEqual(new Uint8Array(32));
		expect(d.additionals.at(-1).data.originalId).toBe(1);
	});

	it("a MAC reporting length 0 on 2,000 octets does not escape a raw RangeError (CLDMV/digby#39)", () => {
		class Zero extends Uint8Array {
			get length() {
				return 0;
			}
		}
		const mac = new Zero(2000);
		const rec = { name: "key.example.", type: TYPE.TSIG, class: CLASS.ANY, ttl: 0, data: { ...tsigData(1), mac } };
		// today: the writer reserves 0 octets and .set() copies the 2,000 real ones — RangeError, out of bounds.
		// encodeMessage refuses a TSIG record (CLDMV/digby#39), so the record goes through appendTsig, whose
		// reservation is sized for the record the copy produces (2,000 real octets)
		const reserve = tsigRecordSize({ ...rec, data: { ...tsigData(1), mac: new Uint8Array(2000) } });
		const capped = encodeCapped(message({ additionals: [A(1)] }), { limit: reserve + 320, reserveTsig: reserve });
		const d = decodeMessage(appendTsig(capped, rec));
		expect(d.additionals.at(-1).data.mac).toEqual(new Uint8Array(2000));
	});

	it("appendTsig indexes the copy: a length getter cannot pad the caller's bytes past the comparison (CLDMV/digby#39)", () => {
		const need = tsigRecordSize(tsigRecord(1));
		const capped = encodeCapped(message({ additionals: [A(1)] }), { limit: 280, reserveTsig: need });
		class Padded extends Uint8Array {
			get length() {
				return capped.bytes.length;
			}
		}
		const padded = new Padded(capped.bytes.length + 50);
		padded.set(capped.bytes);
		Object.defineProperty(capped, "bytes", { value: padded });
		// today: the comparison reads the length getter (the snapshot's length) and compares the first octets — the 50 extra
		// octets the caller's array really holds are never compared, and the signed bytes are not the bytes verified
		expect(code(() => appendTsig(capped, tsigRecord(1)))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("a 2**32-1 sparse list is refused in bounded time, wherever it sits (CLDMV/digby#39)", () => {
		const sparse = new Array(2 ** 32 - 1);
		sparse[0] = new Uint8Array([1]);
		// today: the section copy walks the caller's list with .map(), which visits every index of a sparse array — the
		// encode hangs for a minute or more before anything is refused
		expect(code(() => encodeMessage({ id: 1, answers: [{ name: "x.example.", type: TYPE.TXT, class: 1, ttl: 60, data: { strings: sparse } }] }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ id: 1, edns: { udpSize: 1232, options: sparse } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ id: 1, answers: sparse }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("a hole in a list is a refusal, never a TypeError or a hang (CLDMV/digby#39)", () => {
		// today: `[,]` survives the section copy (.map() preserves holes), and encodeCapped's TSIG-present scan reads
		// rec.type of the hole — a raw TypeError
		expect(code(() => encodeCapped(message({ answers: [,] }), { limit: 512 }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ id: 1, answers: [{ name: "x.example.", type: TYPE.TXT, class: 1, ttl: 60, data: { strings: [new Uint8Array([1]), , new Uint8Array([2])] } }] }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("an own __proto__ key is data, not the prototype (CLDMV/digby#39)", () => {
		const sneaky = JSON.parse('{"__proto__":{"address":"10.0.0.7"}}');
		// today: the hand-written copy's out[k] = v assignment hits the __proto__ setter — the copy's prototype becomes the
		// injected object and the A record encodes 10.0.0.7
		expect(code(() => encodeMessage({ id: 1, answers: [{ name: "x.example.", type: TYPE.A, class: 1, ttl: 60, data: sneaky }] }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("error messages stringify only cloned values: a throwing toString cannot hijack a refusal (CLDMV/digby#39)", () => {
		const evil = { toString() { throw new Error("boom"); } };
		// today: checkType's message interpolates String(t) on the caller's object — the raw Error("boom") escapes
		expect(code(() => encodeMessage({ id: 1, questions: [{ name: "q.example.", type: evil }] }))).toBe("NOT_CLONEABLE");
		// a plain object's String() is inert — the refusal names the value without running caller code
		expect(code(() => encodeMessage({ id: 1, questions: [{ name: "q.example.", type: {} }] }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("prototype getters are not read: a class-built record encodes as plain data (CLDMV/digby#39)", () => {
		class Rec {
			get name() {
				return "x.example.";
			}
			get type() {
				return TYPE.A;
			}
		}
		// the input contract: own enumerable properties only — prototype getters are not read, so this record has neither a
		// name nor a type and is refused
		expect(code(() => encodeMessage({ id: 1, answers: [new Rec()] }))).toBe("VALUE_OUT_OF_RANGE");
	});
});

describe("caller traps fire inside the NOT_CLONEABLE mapping, never before it (CLDMV/digby#39, round 5)", () => {
	it("a revoked Proxy is refused wherever the pre-clone walk or a pre-check touches it", () => {
		const { proxy, revoke } = Proxy.revocable({}, {});
		revoke();
		// today: boundClone's `typeof` on the revoked Proxy throws a raw TypeError, before NOT_CLONEABLE can map the failure
		expect(code(() => encodeMessage(proxy))).toBe("NOT_CLONEABLE");
		expect(code(() => encodeMessage({ id: 1, answers: [proxy] }))).toBe("NOT_CLONEABLE");
		// today: formatRecord's shape check reads the caller's object before the clone can refuse it
		expect(code(() => formatRecord(proxy))).toBe("NOT_CLONEABLE");
		// today: appendTsig reads `typeof capped` before its refusal can map the failure
		expect(code(() => appendTsig(proxy, tsigRecord(1)))).toBe("VALUE_OUT_OF_RANGE");
		// a genuine result with a throwing `bytes` getter: today the raw RangeError escapes the read
		const need = tsigRecordSize(tsigRecord(1));
		const capped = encodeCapped(message({ additionals: [A(1)] }), { limit: 280, reserveTsig: need });
		Object.defineProperty(capped, "bytes", { get() { throw new RangeError("bytes"); } });
		expect(code(() => appendTsig(capped, tsigRecord(1)))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("a Proxy trap that throws is mapped to NOT_CLONEABLE", () => {
		// today: the pre-clone walk calls Object.getPrototypeOf on the caller's object — the raw RangeError escapes
		const proto = new Proxy({ id: 1 }, { getPrototypeOf() { throw new RangeError("getPrototypeOf"); } });
		expect(code(() => encodeMessage(proto))).toBe("NOT_CLONEABLE");
		// today: the walk reads property descriptors over the record's own keys — the raw RangeError escapes
		const gopd = new Proxy(A(1), { getOwnPropertyDescriptor() { throw new RangeError("getOwnPropertyDescriptor"); } });
		expect(code(() => encodeMessage({ id: 1, answers: [gopd] }))).toBe("NOT_CLONEABLE");
		// today: the walk reads the section list's own keys — the raw RangeError escapes
		const ownKeys = new Proxy([A(1)], { ownKeys() { throw new RangeError("ownKeys"); } });
		expect(code(() => encodeMessage({ id: 1, answers: ownKeys }))).toBe("NOT_CLONEABLE");
	});
});

describe("the NOT_CLONEABLE refusal never reads the thrown value (CLDMV/digby#39, round 5)", () => {
	const rec = (data) => ({ name: "x.example.", type: 999, class: 1, ttl: 0, data });
	it("a getter that throws null has no .message to read", () => {
		// today: the catch interpolates `${err.message}` — err is the caller's thrown null, and reading .message off it
		// throws a raw TypeError
		expect(code(() => encodeMessage({ id: 1, answers: [rec({ get data() { throw null; } })] }))).toBe("NOT_CLONEABLE");
	});
	it("a getter that throws a Symbol cannot be stringified", () => {
		// today: `${err.message}` on a Symbol throws "Cannot convert a Symbol value to a string"
		expect(code(() => encodeMessage({ id: 1, answers: [rec({ get data() { throw Symbol("boom"); } })] }))).toBe("NOT_CLONEABLE");
	});
	it("a getter that throws an object with a hostile message is never stringified", () => {
		// today: `${err.message}` invokes the thrown value's message's toString — the raw Error("boom") escapes
		expect(code(() => encodeMessage({ id: 1, answers: [rec({ get data() { throw { message: { toString() { throw new Error("boom"); } } }; } })] }))).toBe("NOT_CLONEABLE");
	});
});

describe("a public entry throws only WireError, for any input (CLDMV/digby#39, round 5)", () => {
	// every value a caller can hand an entry that is not plain data, or that breaks a naive String()/template of it
	const revokedProxy = (() => {
		const { proxy, revoke } = Proxy.revocable({}, {});
		revoke();
		return proxy;
	})();
	const throwingGet = new Proxy({}, { get() { throw new RangeError("get trap"); } });
	const throwingProto = new Proxy({}, { getPrototypeOf() { throw new RangeError("getPrototypeOf trap"); } });
	const throwingView = new Proxy(new Uint8Array([1, 2, 3, 4]), { get() { throw new RangeError("get trap"); } });
	const throwingNull = Object.defineProperty({}, "x", { get() { throw null; }, enumerable: true });
	const throwingSymbol = Object.defineProperty({}, "x", { get() { throw Symbol("boom"); }, enumerable: true });
	const throwingObject = Object.defineProperty({}, "x", { get() { throw { message: { toString() { throw new Error("boom"); } } }; }, enumerable: true });
	const toStringOne = { toString: 1, valueOf: 1 };
	const toStringNull = { toString: null };
	const nullProto = Object.create(null);
	const hostiles = [
		["a revoked Proxy", revokedProxy],
		["a Proxy whose get trap throws", throwingGet],
		["a Proxy whose getPrototypeOf trap throws", throwingProto],
		["a Proxy over a Uint8Array whose get trap throws", throwingView],
		["a getter that throws null", throwingNull],
		["a getter that throws a Symbol", throwingSymbol],
		["a getter that throws an unstringifiable object", throwingObject],
		["{ toString: 1, valueOf: 1 }", toStringOne],
		["{ toString: null }", toStringNull],
		["Object.create(null)", nullProto],
		["a Symbol", Symbol("nope")],
		["a function", () => {}]
	];

	const question = (over) => ({ name: "q.example.", type: TYPE.A, class: 1, ...over });
	const arec = (over) => ({ name: "a.example.", type: TYPE.A, class: 1, ttl: 60, data: { address: "10.0.0.1" }, ...over });
	const envelope = (over) => ({ id: 1, flags: { qr: true }, rcode: 0, questions: [], answers: [], authorities: [], additionals: [], edns: null, ...over });
	const rrsigData = (over) => ({ typeCovered: TYPE.A, algorithm: 13, labels: 2, originalTtl: 3600, expiration: 0, inception: 0, keyTag: 1, signerName: "example.", signature: new Uint8Array([1, 2, 3]), ...over });
	const tsigRdata = (over) => ({ ...tsigData(1), mac: new Uint8Array(4), ...over });
	const tsig = (over) => ({ name: "key.example.", type: TYPE.TSIG, class: CLASS.ANY, ttl: 0, data: tsigRdata(), ...over });
	const makeCapped = () => encodeCapped(envelope({ additionals: [arec()] }), { limit: 280, reserveTsig: tsigRecordSize(tsig()) });

	// every input position of every public entry the snapshot round covers; each shape receives one hostile value.
	// (decodeRdataBytes' octets position is the octet-copy round's; the names, mnemonic and transport helpers are
	// outside this slice.)
	const shapes = [
		["decodeMessage: the bytes", (hv) => () => decodeMessage(hv)],
		["encodeMessage: the message", (hv) => () => encodeMessage(hv)],
		["encodeMessage: id", (hv) => () => encodeMessage(envelope({ id: hv }))],
		["encodeMessage: flags", (hv) => () => encodeMessage(envelope({ flags: hv }))],
		["encodeMessage: rcode", (hv) => () => encodeMessage(envelope({ rcode: hv }))],
		["encodeMessage: question name", (hv) => () => encodeMessage(envelope({ questions: [question({ name: hv })] }))],
		["encodeMessage: question type", (hv) => () => encodeMessage(envelope({ questions: [question({ type: hv })] }))],
		["encodeMessage: question class", (hv) => () => encodeMessage(envelope({ questions: [question({ class: hv })] }))],
		["encodeMessage: record name", (hv) => () => encodeMessage(envelope({ answers: [arec({ name: hv })] }))],
		["encodeMessage: record type", (hv) => () => encodeMessage(envelope({ answers: [arec({ type: hv })] }))],
		["encodeMessage: record class", (hv) => () => encodeMessage(envelope({ answers: [arec({ class: hv })] }))],
		["encodeMessage: record ttl", (hv) => () => encodeMessage(envelope({ answers: [arec({ ttl: hv })] }))],
		["encodeMessage: record data", (hv) => () => encodeMessage(envelope({ answers: [arec({ data: hv })] }))],
		["encodeMessage: rdata field", (hv) => () => encodeMessage(envelope({ answers: [arec({ data: { address: hv } })] }))],
		["encodeMessage: RRSIG typeCovered", (hv) => () => encodeMessage(envelope({ answers: [arec({ type: TYPE.RRSIG, data: rrsigData({ typeCovered: hv }) })] }))],
		["encodeMessage: edns", (hv) => () => encodeMessage(envelope({ edns: hv }))],
		["encodeMessage: edns udpSize", (hv) => () => encodeMessage(envelope({ edns: { udpSize: hv, options: [] } }))],
		["encodeMessage: an EDNS option", (hv) => () => encodeMessage(envelope({ edns: { options: [hv] } }))],
		["encodeMessage: EDNS option code", (hv) => () => encodeMessage(envelope({ edns: { options: [{ code: hv, data: new Uint8Array([1]) }] } }))],
		["encodeMessage: maxSize", (hv) => () => encodeMessage(envelope(), { maxSize: hv })],
		["encodeCapped: RRset class in the grouping key", (hv) => () => encodeCapped(envelope({ answers: [arec({ class: hv }), arec()] }), { limit: 60 })],
		["encodeCapped: RRSIG typeCovered in the grouping key", (hv) => () => encodeCapped(envelope({ answers: [arec({ type: TYPE.RRSIG, data: rrsigData({ typeCovered: hv }) }), arec(), arec()] }), { limit: 60 })],
		["encodeCapped: limit", (hv) => () => encodeCapped(envelope(), { limit: hv })],
		["encodeCapped: reserveTsig", (hv) => () => encodeCapped(envelope(), { limit: 512, reserveTsig: hv })],
		["appendTsig: the capped result", (hv) => () => appendTsig(hv, tsig())],
		["appendTsig: the record", (hv) => () => appendTsig(makeCapped(), hv)],
		["appendTsig: record name", (hv) => () => appendTsig(makeCapped(), tsig({ name: hv }))],
		["appendTsig: record type", (hv) => () => appendTsig(makeCapped(), tsig({ type: hv }))],
		["appendTsig: record class", (hv) => () => appendTsig(makeCapped(), tsig({ class: hv }))],
		["appendTsig: record ttl", (hv) => () => appendTsig(makeCapped(), tsig({ ttl: hv }))],
		["appendTsig: originalId", (hv) => () => appendTsig(makeCapped(), tsig({ data: tsigRdata({ originalId: hv }) }))],
		["tsigRecordSize: the record", (hv) => () => tsigRecordSize(hv)],
		["tsigRecordSize: record type", (hv) => () => tsigRecordSize(tsig({ type: hv }))],
		["tsigRecordSize: record class", (hv) => () => tsigRecordSize(tsig({ class: hv }))],
		["tsigRecordSize: record ttl", (hv) => () => tsigRecordSize(tsig({ ttl: hv }))],
		["tsigRecordSize: originalId", (hv) => () => tsigRecordSize(tsig({ data: tsigRdata({ originalId: hv }) }))],
		["formatRecord: the record", (hv) => () => formatRecord(hv)],
		["formatRecord: name", (hv) => () => formatRecord(arec({ name: hv }))],
		["formatRecord: ttl", (hv) => () => formatRecord(arec({ ttl: hv }))],
		["formatRecord: class", (hv) => () => formatRecord(arec({ class: hv }))],
		["formatRecord: type", (hv) => () => formatRecord(arec({ type: hv }))],
		["formatRecord: data", (hv) => () => formatRecord(arec({ data: hv }))],
		["formatRdata: type", (hv) => () => formatRdata(hv, { address: "10.0.0.1" })],
		["formatRdata: data", (hv) => () => formatRdata(TYPE.A, hv)],
		["formatRdata: RRSIG typeCovered", (hv) => () => formatRdata(TYPE.RRSIG, rrsigData({ typeCovered: hv }))],
		["encodeRdataBytes: type", (hv) => () => encodeRdataBytes(hv, { address: "10.0.0.1" })],
		["encodeRdataBytes: data", (hv) => () => encodeRdataBytes(TYPE.A, hv)],
		["encodeRdataBytes: RRSIG typeCovered", (hv) => () => encodeRdataBytes(TYPE.RRSIG, rrsigData({ typeCovered: hv }))],
		["decodeRdataBytes: type", (hv) => () => decodeRdataBytes(hv, new Uint8Array(4))],
		["parseRecord: text", (hv) => () => parseRecord(hv)],
		["parseRecord: origin", (hv) => () => parseRecord("@ IN A 10.0.0.1", { origin: hv })],
		["parseRecord: default ttl", (hv) => () => parseRecord("a.example. IN A 10.0.0.1", { ttl: hv })],
		["parseRecord: default class", (hv) => () => parseRecord("a.example. 60 IN A 10.0.0.1", { class: hv })],
		["parseRdata: type", (hv) => () => parseRdata(hv, "10.0.0.1")],
		["parseRdata: text", (hv) => () => parseRdata(TYPE.A, hv)],
		["parseRdata: origin", (hv) => () => parseRdata(TYPE.MX, "10 mail", hv)],
		["parseTtl: text", (hv) => () => parseTtl(hv)],
		["parseName: text", (hv) => () => parseName(hv)],
		["canonicalName: text", (hv) => () => canonicalName(hv)],
		["namesEqual: a name", (hv) => () => namesEqual(hv, "a.example.")]
	];

	it("every hostile value at every input position returns or throws WireError, never anything else", () => {
		const escapes = [];
		for (const [what, shape] of shapes) {
			for (const [hvName, hv] of hostiles) {
				let outcome;
				try {
					shape(hv)();
					outcome = "returned";
				} catch (err) {
					outcome = err;
				}
				if (outcome !== "returned" && !(outcome instanceof WireError)) {
					const shown = outcome instanceof Error ? outcome.constructor.name : String(outcome);
					escapes.push(`${what} with ${hvName} escaped as ${shown}: ${outcome instanceof Error ? outcome.message : ""}`);
				}
			}
		}
		// every escape at once, so one run lists all the positions that still leak
		expect(escapes).toEqual([]);
	});
});

describe("error messages never stringify caller values (CLDMV/digby#39, round 5)", () => {
	const toStringOne = { toString: 1, valueOf: 1 };
	it("checkType and checkInt describe a cloned hostile value instead of String()ing it", () => {
		// today: `String(t)` on the cloned { toString: 1 } throws "is not a function" — a TypeError, not a WireError
		expect(code(() => encodeMessage({ id: 1, questions: [{ name: "q.example.", type: toStringOne }] }))).toBe("VALUE_OUT_OF_RANGE");
		// today: checkedId's String(id) throws
		expect(code(() => encodeMessage({ id: toStringOne, questions: [] }))).toBe("VALUE_OUT_OF_RANGE");
		// today: checkInt's String(v) on the ttl throws
		expect(code(() => encodeMessage({ id: 1, answers: [{ name: "a.example.", type: TYPE.A, class: 1, ttl: toStringOne, data: { address: "1.2.3.4" } }] }))).toBe("VALUE_OUT_OF_RANGE");
		// today: checkInt's String(maxSize) throws
		expect(code(() => encodeMessage({ id: 1 }, { maxSize: toStringOne }))).toBe("VALUE_OUT_OF_RANGE");
		// today: checkInt's String(limit) and String(reserveTsig) throw
		expect(code(() => encodeCapped({ id: 1 }, { limit: toStringOne }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeCapped({ id: 1 }, { limit: 512, reserveTsig: toStringOne }))).toBe("VALUE_OUT_OF_RANGE");
	});
	it("appendTsig and tsigRecordSize describe cloned hostile values", () => {
		const need = tsigRecordSize(tsigRecord(1));
		const build = () => encodeCapped(message({ additionals: [A(1)] }), { limit: 280, reserveTsig: need });
		// today: String(rec.type) throws
		expect(code(() => appendTsig(build(), { ...tsigRecord(1), type: toStringOne }))).toBe("VALUE_OUT_OF_RANGE");
		// today: classToString(rec.class) converts through a property key — the TypeError escapes
		expect(code(() => appendTsig(build(), { ...tsigRecord(1), class: toStringOne }))).toBe("VALUE_OUT_OF_RANGE");
		// today: String(rec.ttl) throws
		expect(code(() => appendTsig(build(), { ...tsigRecord(1), ttl: toStringOne }))).toBe("VALUE_OUT_OF_RANGE");
		// today: String(originalId) in the shown branch throws
		expect(code(() => appendTsig(build(), { ...tsigRecord(1), data: { ...tsigData(1), mac: new Uint8Array(4), originalId: toStringOne } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => tsigRecordSize({ ...tsigRecord(1), type: toStringOne }))).toBe("VALUE_OUT_OF_RANGE");
		// a string "4660" reads as the message's own ID in a bare String(); the description still names the type
		expect(code(() => appendTsig(build(), { ...tsigRecord(1), data: { ...tsigData(1), mac: new Uint8Array(4), originalId: "4660" } }))).toBe("VALUE_OUT_OF_RANGE");
	});
});

describe("a SharedArrayBuffer-backed view is refused, not shared (CLDMV/digby#39, round 5)", () => {
	it("a view over a SharedArrayBuffer is refused NOT_CLONEABLE wherever an encode copies it", () => {
		const view = new Uint8Array(new SharedArrayBuffer(8));
		view.set([1, 2, 3, 4]);
		// today: structuredClone shares the buffer with the copy — the caller can change the octets the encode is
		// reading while it reads them, so the one-copy rule cannot hold
		expect(code(() => encodeMessage({ id: 1, answers: [{ name: "x.example.", type: 999, class: 1, ttl: 0, data: { data: view } }] }))).toBe("NOT_CLONEABLE");
		expect(code(() => encodeMessage({ id: 1, answers: [{ name: "x.example.", type: TYPE.TXT, class: 1, ttl: 60, data: { strings: [view] } }] }))).toBe("NOT_CLONEABLE");
		// a getter-hidden view too: the walk skips accessors, so the copy itself is checked
		const hidden = { get data() { return view; } };
		expect(code(() => encodeMessage({ id: 1, answers: [{ name: "x.example.", type: 999, class: 1, ttl: 0, data: hidden }] }))).toBe("NOT_CLONEABLE");
	});
	it("a bare SharedArrayBuffer is refused too", () => {
		const sab = new SharedArrayBuffer(8);
		expect(code(() => encodeMessage({ id: 1, answers: [{ name: "x.example.", type: 999, class: 1, ttl: 0, data: { data: sab } }] }))).toBe("NOT_CLONEABLE");
	});
});
