/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/message.test.vitest.mjs
 */

import { describe, expect, it } from "vitest";
import { CLASS, OPCODE, TYPE } from "../../src/lib/wire/constants.mjs";
import { WireError } from "../../src/lib/wire/errors.mjs";
import { packFlags, unpackFlags } from "../../src/lib/wire/header.mjs";
import { decodeMessage, encodeCapped, encodeMessage, tsigRecordSize } from "../../src/lib/wire/message.mjs";
import { parseRecord } from "../../src/lib/wire/presentation.mjs";
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

const QUESTION = "07 6578616d706c65 03 636f6d 00 0001 0001"; // example.com. A IN
// example.com. A 3600 93.184.216.34, owner compressed to the question at offset 12
const ANSWER = "c00c 0001 0001 00000e10 0004 5db8d822";
// a record with no rdata: root owner, type SIG (24), class ANY, ttl 0, rdlength 0
const EMPTY_SIG = "00 0018 00ff 00000000 0000";
const FLAGS = { qr: false, opcode: 0, aa: false, tc: false, rd: false, ra: false, z: false, ad: false, cd: false };

describe("header", () => {
	it("packs and unpacks every flag", () => {
		const all = { qr: true, opcode: 15, aa: true, tc: true, rd: true, ra: true, z: true, ad: true, cd: true };
		expect(packFlags(all, 15)).toBe(0xffff);
		expect(unpackFlags(0xffff)).toEqual({ flags: all, rcode: 15 });
		expect(unpackFlags(0)).toEqual({ flags: FLAGS, rcode: 0 });
		expect(packFlags({ rd: true })).toBe(0x0100);
		expect(packFlags({ opcode: OPCODE.UPDATE })).toBe(0x2800);
		expect(packFlags()).toBe(0);
		expect(code(() => packFlags({ opcode: 16 }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => packFlags(null))).toBe("VALUE_OUT_OF_RANGE");
	});
});

describe("messages", () => {
	it("decodes a query and re-encodes it byte for byte", () => {
		const q = hex.from(`abcd 0100 0001 0000 0000 0000 ${QUESTION}`);
		const m = decodeMessage(q);
		expect(m).toEqual({
			id: 0xabcd,
			flags: { ...FLAGS, rd: true },
			rcode: 0,
			questions: [{ name: "example.com.", type: 1, class: 1 }],
			answers: [],
			authorities: [],
			additionals: [],
			edns: null
		});
		expect(hex.to(encodeMessage(m))).toBe(hex.to(q));
	});

	it("decodes a response with a compressed answer and compresses the same way", () => {
		const r = hex.from(`abcd 8180 0001 0001 0000 0000 ${QUESTION} ${ANSWER}`);
		const m = decodeMessage(r);
		expect(m.answers).toEqual([{ name: "example.com.", type: 1, class: 1, ttl: 3600, data: { address: "93.184.216.34" } }]);
		expect(hex.to(encodeMessage(m))).toBe(hex.to(r));
		expect(encodeMessage(m, { compress: false }).length).toBe(r.length + 11);
	});

	it("accepts an ArrayBuffer and a Buffer view", () => {
		const r = hex.from(`abcd 8180 0001 0001 0000 0000 ${QUESTION} ${ANSWER}`);
		expect(decodeMessage(r.buffer)).toEqual(decodeMessage(r));
		const padded = Buffer.concat([Buffer.from([9, 9]), Buffer.from(r)]).subarray(2);
		expect(decodeMessage(padded)).toEqual(decodeMessage(r));
		expect(code(() => decodeMessage("x"))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("does not alias the input: decoded octets are copies", () => {
		const b = hex.from(`0000 0000 0000 0001 0000 0000 00 0010 0001 00000000 0002 0161`);
		const m = decodeMessage(b);
		b[b.length - 1] = 0x62;
		expect(m.answers[0].data.strings[0]).toEqual(Uint8Array.of(0x61));
	});

	it("reads a TTL with the top bit set as 0 (RFC 2181 8)", () => {
		const b = hex.from(`0000 8000 0000 0001 0000 0000 00 0001 0001 80000000 0004 01020304`);
		expect(decodeMessage(b).answers[0].ttl).toBe(0);
		expect(code(() => encodeMessage({ id: 0, answers: [{ name: ".", type: 1, ttl: 0x80000000, data: { address: "1.2.3.4" } }] }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("keeps the update forms: class ANY / NONE with empty rdata as data: null", () => {
		const b = hex.from(`0000 2800 0000 0000 0001 0000 00 0001 00ff 00000000 0000`);
		const m = decodeMessage(b);
		expect(m.flags.opcode).toBe(OPCODE.UPDATE);
		expect(m.authorities).toEqual([{ name: ".", type: 1, class: CLASS.ANY, ttl: 0, data: null }]);
		expect(hex.to(encodeMessage(m))).toBe(hex.to(b));
		// the same in class IN is malformed A rdata
		expect(code(() => decodeMessage(hex.from(`0000 2800 0000 0000 0001 0000 00 0001 0001 00000000 0000`)))).toBe("BAD_RDATA");
		expect(code(() => encodeMessage({ id: 0, answers: [{ name: ".", type: 1, ttl: 0, data: null }] }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("refuses the empty-rdata update form for types that never carry zone data (CLDMV/digby#38)", () => {
		const empty = (type) => `00 ${type.toString(16).padStart(4, "0")} 00ff 00000000 0000`; // root owner, class ANY, no rdata
		// TSIG, TKEY, IXFR, AXFR, MAILA, MAILB: a TSIG verifier reading data.mac on a data: null record would throw a TypeError
		for (const type of [TYPE.TSIG, 249, 251, 252, 253, 254]) {
			expect(code(() => decodeMessage(hex.from(`0000 2800 0000 0000 0000 0001 ${empty(type)}`)))).toBe("BAD_RDATA");
		}
		// a real RR type keeps the RFC 2136 form
		const b = hex.from(`0000 2800 0000 0000 0001 0000 00 0001 00ff 00000000 0000`);
		expect(decodeMessage(b).authorities[0]).toEqual({ name: ".", type: 1, class: CLASS.ANY, ttl: 0, data: null });
		// and the encode side refuses the same types
		expect(code(() => encodeMessage({ id: 0, additionals: [{ name: ".", type: TYPE.TSIG, class: CLASS.ANY, ttl: 0, data: null }] }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("refuses an empty SIG record: SIG(0) is class ANY and its rdata is mandatory (CLDMV/digby#38)", () => {
		// SIG is type 24 and SIG(0) travels as class ANY, so the empty-rdata update form reached it and data read back null
		expect(code(() => decodeMessage(hex.from(`0000 2800 0000 0000 0000 0001 ${EMPTY_SIG}`)))).toBe("BAD_RDATA");
		expect(code(() => encodeMessage({ id: 0, additionals: [{ name: ".", type: TYPE.SIG, class: CLASS.ANY, ttl: 0, data: null }] }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("refuses records of the reserved type 65535 (CLDMV/digby#38)", () => {
		expect(code(() => decodeMessage(hex.from(`0000 0000 0000 0001 0000 0000 00 ffff 0001 00000000 0000`)))).toBe("BAD_RDATA");
		expect(code(() => encodeMessage({ id: 0, answers: [{ name: ".", type: 65535, ttl: 0, data: { data: new Uint8Array(0) } }] }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => parseRecord("a. 3600 IN TYPE65535 \\# 0"))).toBe("BAD_PRESENTATION");
	});

	it("refuses records of the reserved type 0 (RFC 6895; CLDMV/digby#38)", () => {
		// the questions, the type bitmaps and RRSIG's typeCovered already refuse it; the record envelope does too now
		expect(code(() => decodeMessage(hex.from(`0000 0000 0000 0001 0000 0000 00 0000 0001 00000000 0000`)))).toBe("BAD_RDATA");
		expect(code(() => encodeMessage({ id: 0, answers: [{ name: ".", type: 0, ttl: 0, data: { data: new Uint8Array(0) } }] }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("keeps a SIG(0) record: typeCovered 0 stays unchecked (RFC 2931; CLDMV/digby#38)", () => {
		// SIG rdata is RFC 3597 octets to the codec and its first field is the typeCovered, which a SIG(0) transaction
		// signature sets to 0 (RFC 2931) — the codec must never start checking it
		const b = hex.from(`0000 0000 0000 0001 0000 0000 00 0018 00ff 00000000 0016 0000 03 00 0000000a 0000000a 0000000a 0000 0161 0062`);
		const m = decodeMessage(b);
		expect(m.answers[0].type).toBe(TYPE.SIG);
		expect(hex.to(encodeMessage(m))).toBe(hex.to(b));
	});

	it("refuses a question of a reserved type: 0 and 65535 (CLDMV/digby#38)", () => {
		// one question of type 0 / 65535, class IN
		expect(code(() => decodeMessage(hex.from("0000 0000 0001 0000 0000 0000 00 0000 0001")))).toBe("BAD_RDATA");
		expect(code(() => decodeMessage(hex.from("0000 0000 0001 0000 0000 0000 00 ffff 0001")))).toBe("BAD_RDATA");
		expect(code(() => encodeMessage({ id: 0, questions: [{ name: ".", type: 0 }] }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ id: 0, questions: [{ name: ".", type: 65535 }] }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("keeps unknown types and classes as RFC 3597 octets", () => {
		const b = hex.from(`0000 8000 0000 0001 0000 0000 00 04d2 03e8 00000001 0003 aabbcc`);
		expect(decodeMessage(b).answers).toEqual([{ name: ".", type: 1234, class: 1000, ttl: 1, data: { data: hex.from("aabbcc") } }]);
		expect(hex.to(encodeMessage(decodeMessage(b)))).toBe(hex.to(b));
	});

	it("defaults omitted fields on encode", () => {
		expect(hex.to(encodeMessage({}))).toBe("000000000000000000000000");
		expect(hex.to(encodeMessage({ id: 7, questions: [{ name: ".", type: TYPE.NS }] }))).toBe("000700000001000000000000 00 0002 0001".replace(/ /g, ""));
	});

	it("refuses malformed messages with the codec's error", () => {
		expect(code(() => decodeMessage(new Uint8Array(11)))).toBe("TRUNCATED");
		expect(code(() => decodeMessage(new Uint8Array(65536)))).toBe("INPUT_TOO_LARGE");
		// claims 65535 questions with none present: no allocation, just TRUNCATED
		expect(code(() => decodeMessage(hex.from("0000 0000 ffff ffff ffff ffff")))).toBe("TRUNCATED");
		expect(code(() => decodeMessage(hex.from(`0000 0000 0001 0000 0000 0000 ${QUESTION} 00`)))).toBe("TRAILING_DATA");
		expect(decodeMessage(hex.from(`0000 0000 0001 0000 0000 0000 ${QUESTION} 00`), { allowTrailing: true }).questions).toHaveLength(1);
		// rdlength past the end
		expect(code(() => decodeMessage(hex.from(`0000 8000 0001 0001 0000 0000 ${QUESTION} c00c 0001 0001 00000e10 0005 5db8d822`)))).toBe("TRUNCATED");
		// rdlength longer than the rdata the type parses: the A codec sees 5 octets
		expect(code(() => decodeMessage(hex.from(`0000 8000 0001 0001 0000 0000 ${QUESTION} c00c 0001 0001 00000e10 0005 5db8d82200`)))).toBe("BAD_RDATA");
		// an MX whose name ends before its rdlength
		expect(code(() => decodeMessage(hex.from(`0000 8000 0001 0001 0000 0000 ${QUESTION} c00c 000f 0001 00000e10 0004 000a 00 ff`)))).toBe("RDLENGTH_MISMATCH");
		// an MX whose name runs past its rdlength
		expect(code(() => decodeMessage(hex.from(`0000 8000 0001 0001 0000 0000 ${QUESTION} c00c 000f 0001 00000e10 0003 000a 01 61 00`)))).toBe("TRUNCATED");
	});

	it("resolves compression pointers inside rdata against the whole message", () => {
		// an MX pointing at the question name
		const b = hex.from(`0000 8000 0001 0001 0000 0000 ${QUESTION} c00c 000f 0001 00000e10 0004 000a c00c`);
		expect(decodeMessage(b).answers[0].data).toEqual({ preference: 10, exchange: "example.com." });
		expect(hex.to(encodeMessage(decodeMessage(b)))).toBe(hex.to(b));
		// SRV targets are decompressed on decode (RFC 3597 4) but never compressed on encode
		const srv = hex.from(`0000 8000 0001 0001 0000 0000 ${QUESTION} c00c 0021 0001 00000e10 0008 0000 0000 0035 c00c`);
		const m = decodeMessage(srv);
		expect(m.answers[0].data.target).toBe("example.com.");
		expect(encodeMessage(m).length).toBe(srv.length + 11);
	});

	it("TSIG must be the last record", () => {
		const tsig = "00 00fa 00ff 00000000 0011 00 000000000000 012c 0000 0000 0000 0000";
		const a = "00 0001 0001 00000000 0004 01020304";
		expect(decodeMessage(hex.from(`0000 0000 0000 0000 0000 0001 ${tsig}`)).additionals[0].type).toBe(TYPE.TSIG);
		expect(code(() => decodeMessage(hex.from(`0000 0000 0000 0000 0000 0002 ${tsig} ${a}`)))).toBe("TSIG_MISPLACED");
		expect(code(() => decodeMessage(hex.from(`0000 0000 0000 0001 0000 0000 ${tsig}`)))).toBe("TSIG_MISPLACED");
		const t = decodeMessage(hex.from(`0000 0000 0000 0000 0000 0001 ${tsig}`)).additionals[0];
		const rec = { name: ".", type: 1, class: 1, ttl: 0, data: { address: "1.2.3.4" } };
		expect(code(() => encodeMessage({ id: 0, additionals: [t, rec] }))).toBe("TSIG_MISPLACED");
		expect(code(() => encodeMessage({ id: 0, answers: [t] }))).toBe("TSIG_MISPLACED");
	});

	it("refuses malformed message objects with WireError", () => {
		expect(code(() => encodeMessage(null))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ id: 65536 }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ questions: "x" }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ questions: [null] }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ questions: [{ name: 5, type: 1 }] }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ answers: [null] }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ answers: [{ name: ".", type: 1, ttl: 1 }] }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ answers: [{ name: 1, type: 1, ttl: 1, data: { address: "1.2.3.4" } }] }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({}, { maxSize: 70000 }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("refuses an encoding over maxSize", () => {
		const big = { id: 0, answers: Array.from({ length: 40 }, (_, i) => ({ name: `h${i}.example.`, type: 1, ttl: 1, data: { address: "1.2.3.4" } })) };
		expect(code(() => encodeMessage(big, { maxSize: 512 }))).toBe("MESSAGE_TOO_LARGE");
		expect(encodeMessage(big).length).toBeGreaterThan(512);
		expect(code(() => encodeMessage({ questions: [{ name: "example.com.", type: 1 }] }, { maxSize: 20 }))).toBe("MESSAGE_TOO_LARGE");
	});
});

describe("encodeCapped and TSIG (CLDMV/digby#39)", () => {
	const A = (i) => ({ name: "ns.example.", type: 1, class: 1, ttl: 60, data: { address: `10.0.0.${i}` } });
	const TXT = (name, n) => ({ name, type: TYPE.TXT, class: 1, ttl: 60, data: { strings: [Uint8Array.from({ length: n }, () => 0x78)] } });
	const message = (sections) => ({ id: 1, flags: { qr: true }, rcode: 0, questions: [], answers: [], authorities: [], additionals: [], ...sections });

	it("refuses a message that already carries a TSIG record", () => {
		const tsig = decodeMessage(hex.from(`0000 0000 0000 0000 0000 0001 00 00fa 00ff 00000000 0011 00 000000000000 012c 0000 0000 0000 0000`)).additionals[0];
		const rec = { name: ".", type: 1, class: 1, ttl: 0, data: { address: "1.2.3.4" } };
		// even well-formed and last: truncating a signed message invalidates its MAC (RFC 8945 5)
		expect(code(() => encodeCapped(message({ additionals: [rec, tsig] }), { limit: 512 }))).toBe("TSIG_PRESENT");
		expect(code(() => encodeCapped(message({ answers: [tsig] }), { limit: 512 }))).toBe("TSIG_PRESENT");
		// the refusal points at the issue, so a caller passing pre-signed input learns the flow instead of a bare code
		try {
			encodeCapped(message({ additionals: [tsig] }), { limit: 512 });
			expect.unreachable("encodeCapped accepted a pre-signed message");
		} catch (err) {
			expect(err).toBeInstanceOf(WireError);
			expect(err.message).toContain("CLDMV/digby#39");
		}
		// encodeMessage never truncates, so a signed message still encodes
		expect(decodeMessage(encodeMessage(message({ additionals: [tsig] }))).additionals).toEqual([tsig]);
	});

	it("reserves octets: the result plus the reservation fits the cap", () => {
		const m = message({ answers: [TXT("p1.example.", 200), A(1)], additionals: [A(2)] });
		const full = encodeMessage(m).length;
		// the default stays exactly what it was: bytes and truncated, nothing reserved
		const base = encodeCapped(m, { limit: full });
		expect(base.truncated).toBe(false);
		expect(base.reserved).toBe(0);
		expect(decodeMessage(base.bytes).answers).toEqual([TXT("p1.example.", 200), A(1)]);
		const need = 84; // a hmac-sha256 TSIG record is about this size; any nonzero reserve must shrink the budget
		const capped = encodeCapped(m, { limit: full, reserveTsig: need });
		expect(capped.reserved).toBe(need);
		expect(capped.bytes.length + need).toBeLessThanOrEqual(full);
		// the shrunken budget dropped an answer RRset, so TC sets exactly as it would for a kept TSIG record
		expect(capped.truncated).toBe(true);
		const d = decodeMessage(capped.bytes);
		expect(d.flags.tc).toBe(true);
		expect(d.answers).toEqual([]);
		expect(d.additionals).toEqual([]);
		// with room for both the message and the reservation nothing is dropped
		const roomy = encodeCapped(m, { limit: full + need, reserveTsig: need });
		expect(roomy.truncated).toBe(false);
		expect(roomy.bytes.length).toBe(full);
	});

	it("tsigRecordSize measures a TSIG record only (CLDMV/digby#39)", () => {
		// an A record is 26 octets on the wire, but the reservation is for a TSIG record: measuring anything else would
		// have appendTsig refuse it later anyway, so refuse it here
		expect(code(() => tsigRecordSize({ name: ".", type: 1, class: 1, ttl: 0, data: { address: "1.2.3.4" } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => tsigRecordSize(null))).toBe("VALUE_OUT_OF_RANGE");
	});
});

describe("truncation refuses messages whose meaning it would destroy (CLDMV/digby#43)", () => {
	const SOA = (serial) => ({
		name: "example.",
		type: TYPE.SOA,
		class: 1,
		ttl: 60,
		data: { mname: "ns.example.", rname: "host.example.", serial, refresh: 0, retry: 0, expire: 0, minimum: 0 }
	});
	const A = (i) => ({ name: `h${i}.example.`, type: TYPE.A, class: 1, ttl: 60, data: { address: "10.0.0.1" } });
	// the records between the SOAs make the message need truncation at a 512-octet limit
	const transfer = (type) => ({
		id: 1,
		flags: { qr: true },
		questions: [{ name: "example.", type, class: 1 }],
		answers: [SOA(3), ...Array.from({ length: 40 }, (_, i) => A(i)), SOA(3)]
	});
	const update = {
		id: 1,
		flags: { opcode: OPCODE.UPDATE },
		questions: [],
		authorities: [SOA(3), ...Array.from({ length: 40 }, (_, i) => A(i)), SOA(3)]
	};

	it("refuses to truncate an UPDATE (TRUNCATION_REFUSED)", () => {
		// dropping whole RRsets out of an update section changes the update it describes
		expect(code(() => encodeCapped(update, { limit: 512 }))).toBe("TRUNCATION_REFUSED");
		// when the message fits it still encodes normally
		const capped = encodeCapped(update, { limit: 65535 });
		expect(capped.truncated).toBe(false);
		expect(decodeMessage(capped.bytes).authorities).toHaveLength(42);
	});

	it.each([TYPE.AXFR, TYPE.IXFR])("refuses to truncate a transfer with a type-%s question (TRUNCATION_REFUSED)", (type) => {
		// an AXFR's SOA bookends and an IXFR's SOA-diff structure break when whole RRsets drop
		expect(code(() => encodeCapped(transfer(type), { limit: 512 }))).toBe("TRUNCATION_REFUSED");
		const capped = encodeCapped(transfer(type), { limit: 65535 });
		expect(capped.truncated).toBe(false);
		expect(decodeMessage(capped.bytes).answers).toHaveLength(42);
	});
});
