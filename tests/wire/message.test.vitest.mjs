/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/message.test.vitest.mjs
 */

import { describe, expect, it } from "vitest";
import { Writer } from "../../src/lib/wire/buffer.mjs";
import { CLASS, OPCODE, TYPE } from "../../src/lib/wire/constants.mjs";
import { WireError, WireErrorCode } from "../../src/lib/wire/errors.mjs";
import { TC_BIT, packFlags, unpackFlags } from "../../src/lib/wire/header.mjs";
import { decodeMessage, encodeCapped, encodeMessage, tsigRecordSize } from "../../src/lib/wire/message.mjs";
import { nameKey, writeName } from "../../src/lib/wire/names.mjs";
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
		// and the encode side refuses the same types — a TSIG record meets the TSIG_PRESENT refusal first (CLDMV/digby#39
		// refuses any TSIG through an encode), so the empty-rdata rule shows on the decode side and for non-TSIG types
		expect(code(() => encodeMessage({ id: 0, additionals: [{ name: ".", type: TYPE.TSIG, class: CLASS.ANY, ttl: 0, data: null }] }))).toBe("TSIG_PRESENT");
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
		// the encode refuses any TSIG (CLDMV/digby#39, round 5): re-encoding a signed message cannot keep the MAC
		// valid, so a TSIG never passes through encodeMessage — signing happens only via appendTsig
		expect(code(() => encodeMessage({ id: 0, additionals: [t, rec] }))).toBe("TSIG_PRESENT");
		expect(code(() => encodeMessage({ id: 0, answers: [t] }))).toBe("TSIG_PRESENT");
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
		// and encodeMessage refuses it too (CLDMV/digby#39, round 5): re-encoding a signed message cannot keep the
		// MAC valid, so a TSIG never passes through any encode — sign the capped result with appendTsig instead
		expect(code(() => encodeMessage(message({ additionals: [tsig] })))).toBe("TSIG_PRESENT");
	});

	it("reserves octets: the result plus the reservation fits the cap", () => {
		// one question: a truncating encode of a message without exactly one question is refused (CLDMV/digby#43)
		const m = message({ questions: [{ name: "example.", type: TYPE.A, class: 1 }], answers: [TXT("p1.example.", 200), A(1)], additionals: [A(2)] });
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

	it("refuses to truncate an UPDATE whose additionals alone drop (CLDMV/digby#43)", () => {
		// dropping additionals never sets TC (RFC 2181 9: they are optional data), but it still changes the update
		// the message describes — the refusal keys on any drop, not on TC
		const small = {
			id: 1,
			flags: { opcode: OPCODE.UPDATE },
			questions: [],
			answers: [A(0), A(1)],
			additionals: Array.from({ length: 60 }, (_, i) => A(2 + i))
		};
		expect(code(() => encodeCapped(small, { limit: 200 }))).toBe("TRUNCATION_REFUSED");
		// when everything fits it still encodes normally
		const capped = encodeCapped(small, { limit: 65535 });
		expect(capped.truncated).toBe(false);
		expect(decodeMessage(capped.bytes).additionals).toHaveLength(60);
	});

	it.each([TYPE.AXFR, TYPE.IXFR])("refuses to truncate a type-%s transfer whose additionals alone drop (CLDMV/digby#43)", (type) => {
		// the transfer refusal used to key on truncation actually happening (TC), which additionals-only drops
		// never set — the answers fit, the additionals do not, and the SOA bookends are still broken
		const small = {
			id: 1,
			flags: { qr: true },
			questions: [{ name: "example.", type, class: 1 }],
			answers: [SOA(3), A(0), A(1), SOA(3)],
			additionals: Array.from({ length: 60 }, (_, i) => A(2 + i))
		};
		expect(code(() => encodeCapped(small, { limit: 220 }))).toBe("TRUNCATION_REFUSED");
		const capped = encodeCapped(small, { limit: 65535 });
		expect(capped.truncated).toBe(false);
		expect(decodeMessage(capped.bytes).additionals).toHaveLength(60);
	});

	it("refuses to truncate unless there is exactly one question (CLDMV/digby#43)", () => {
		// an AXFR continuation may carry no question at all (RFC 5936 2.2.1), and other messages may carry more than
		// one; without exactly one question the encode cannot tell what the message is, so a drop is refused — the
		// 40 A records plus a trailing SOA at a 200-octet limit used to truncate to ~190 octets with the SOA dropped
		const noQuestion = {
			id: 1,
			flags: { qr: true, aa: true },
			questions: [],
			answers: [...Array.from({ length: 40 }, (_, i) => A(i)), SOA(3)]
		};
		expect(code(() => encodeCapped(noQuestion, { limit: 200 }))).toBe("TRUNCATION_REFUSED");
		// two questions: same refusal
		const two = { ...noQuestion, questions: [{ name: "example.", type: TYPE.A, class: 1 }, { name: "example.", type: TYPE.NS, class: 1 }] };
		expect(code(() => encodeCapped(two, { limit: 200 }))).toBe("TRUNCATION_REFUSED");
		// when nothing drops, no question (or several) still encodes normally
		const capped = encodeCapped(noQuestion, { limit: 65535 });
		expect(capped.truncated).toBe(false);
		expect(decodeMessage(capped.bytes).answers).toHaveLength(41);
	});
});

/**
 * The best-fit reference (CLDMV/digby#43, round 8): the kept sets are the longest prefix of the message's RRsets, in
 * first-appearance order, whose encoding fits `limit` — and the reference finds that k by brute force, newest-first:
 * for k from the last set down it builds the message that keeps exactly the records of sets 0..k at their original
 * positions, encodes it with {@link encodeMessage} — so the bytes, compression included, are exactly what a
 * non-truncating encode of that prefix produces, which is also byte for byte what the codec's winning trial writes
 * (the dropped records sit after the kept ones or between them, and a record's encoding depends only on the records
 * before it, so their absence changes nothing) — and the first k whose encoding fits is the answer. It encodes up to
 * one prefix per set — quadratic — which is fine for a test oracle: it is exact by construction, where the codec's
 * model is only as exact as its machinery.
 *
 * TC follows the rule the codec documents: a prefix that drops an answer or authority set sets TC; one that drops
 * only additionals does not (RFC 2181 9). When no set fits, the kept prefix is empty — the header, questions and tail
 * alone, TC when an answer or authority set exists; if even that exceeds the limit the reference fails the same
 * MESSAGE_TOO_LARGE the codec's head gate raises.
 *
 * @param {object} message
 * @param {{ limit: number, truncate?: boolean, compress?: boolean }} options
 * @returns {{ bytes: Uint8Array, truncated: boolean }}
 */
function oracleCapped(message, { limit, truncate = true, compress = true }) {
	if (!truncate) return { bytes: encodeMessage(message, { compress, maxSize: limit }), truncated: false };
	const sections = [message.answers ?? [], message.authorities ?? [], message.additionals ?? []];
	// the same per-section grouping the codec applies (same owner case-insensitively, type, class; an RRSIG also by
	// the type it covers), numbered per section and then laid end to end in first-appearance order — answers first,
	// then authorities, then additionals
	const grouping = sections.map((list) => {
		const byKey = new Map();
		const owner = new Array(list.length);
		let n = 0;
		for (let i = 0; i < list.length; i++) {
			const rec = list[i];
			const k = `${nameKey(rec.name)}|${rec.type}|${rec.class ?? CLASS.IN}|${rec.type === TYPE.RRSIG ? rec.data?.typeCovered : ""}`;
			let ix = byKey.get(k);
			if (ix === undefined) {
				ix = n++;
				byKey.set(k, ix);
			}
			owner[i] = ix;
		}
		return { owner, n };
	});
	const base = [0, grouping[0].n, grouping[0].n + grouping[1].n];
	const globalOf = (s, i) => base[s] + grouping[s].owner[i];
	const totalSets = grouping[0].n + grouping[1].n + grouping[2].n;
	const answerAuthoritySets = grouping[0].n + grouping[1].n;
	const filterTo = (k) => ({
		...message,
		answers: sections[0].filter((_, i) => globalOf(0, i) <= k),
		authorities: sections[1].filter((_, i) => globalOf(1, i) <= k),
		additionals: sections[2].filter((_, i) => globalOf(2, i) <= k)
	});
	const withTc = (bytes, truncated) => {
		if (truncated) bytes[2] |= TC_BIT >>> 8;
		return { bytes, truncated };
	};
	for (let k = totalSets - 1; k >= 0; k--) {
		try {
			return withTc(encodeMessage(filterTo(k), { compress, maxSize: limit }), k < answerAuthoritySets - 1);
		} catch (err) {
			if (err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE) continue;
			throw err;
		}
	}
	return withTc(encodeMessage({ ...message, answers: [], authorities: [], additionals: [] }, { compress, maxSize: limit }), answerAuthoritySets >= 1);
}

describe("encodeCapped matches the best-fit reference on 0x4000-straddling interleavings (CLDMV/digby#43)", () => {
	// 63 strings of 255 `x` plus a remainder: a TXT record holding n octets of filler
	const txtFiller = (n) => {
		const strings = [];
		let left = n;
		while (left > 255) {
			strings.push(new Uint8Array(255).fill(0x78));
			left -= 255;
		}
		if (left > 0) strings.push(new Uint8Array(left).fill(0x78));
		return { strings };
	};
	const bigTxt = (name, n) => ({ name, type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: txtFiller(n) });
	const ns = (name, target) => ({ name, type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target } });
	const txt = (name, n) => ({ name, type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: txtFiller(n) });
	const x63 = "x".repeat(63);
	// A truncating encode of a message without exactly one question is refused (CLDMV/digby#43), so the shapes
	// without a question can only be compared against the reference where nothing drops; the one-question shapes
	// keep the full comparison across every limit.
	const compareWithReference = (m, limit, tag, options) => {
		let capped;
		try {
			capped = encodeCapped(m, { limit, ...options });
		} catch (err) {
			expect(err, `${tag}: the refusal`).toBeInstanceOf(WireError);
			expect(err.code, `${tag}: the refusal code`).toBe("TRUNCATION_REFUSED");
			expect(m.questions.length, `${tag}: the refusal only fires without exactly one question`).toBe(0);
			return;
		}
		expect(capped.bytes.length, `${tag}: the capped encode stays within the limit`).toBeLessThanOrEqual(limit);
		const reference = oracleCapped(m, { limit: limit - (options?.reserveTsig ?? 0) });
		expect(capped.truncated, `${tag}: the truncation flag matches the best-fit reference`).toBe(reference.truncated);
		expect(hex.to(capped.bytes), `${tag}: the bytes match the best-fit reference`).toBe(hex.to(reference.bytes));
	};

	it("never outputs more than the limit when an insertion pushes a kept registration past 0x4000", () => {
		// The round-3 probe's bound covers only the set being measured: keeping set k shifts every kept record
		// after set k's first position by set k's size, and a name that registered a suffix below 0x4000 can land
		// at or past it — a later record that compressed against it then writes out in full, past the bound. The
		// repro: answers t.test. TXT(filler), z.test. NS n1, b.test. TXT 200, z.test. NS n2.<63x>, z.test. NS
		// n3.<63x> — answers 2, 4 and 5 are ONE RRset (z.test. NS), so keeping it inserts two records between
		// b.test. and the registrations it made.
		for (const filler of [16100, 16107, 16114]) {
			const m = {
				id: 1,
				flags: { qr: true },
				questions: [],
				answers: [bigTxt("t.test.", filler), ns("z.test.", "n1.aaaa.example."), txt("b.test.", 200), ns("z.test.", `n2.${x63}.example.`), ns("z.test.", `n3.${x63}.example.`)]
			};
			compareWithReference(m, 16546, `filler ${filler}`);
		}
	});

	it("matches the best-fit reference at every limit around every decision boundary", () => {
		// The repro family, swept: a big first TXT record parks the stream just below the registration bound and
		// the same-owner NS set interleaves its records around the distinct owner, so a set's probe measurement
		// (its records written consecutively) registers suffixes at offsets the real stream never reaches. Every
		// filler (step 8) × every limit around the full length, with and without a question sharing the section's
		// suffix, compared byte for byte against the best-fit reference.
		const answers = (F) => [bigTxt("t.test.", F), ns("z.test.", "n1.aaaa.example."), txt("b.test.", 200), ns("z.test.", `n2.${x63}.example.`), ns("z.test.", `n3.${x63}.example.`)];
		for (let F = 15400; F <= 16400; F += 32) {
			for (const q of [null, "z.test."]) {
				const m = { id: 1, flags: { qr: true }, questions: q ? [{ name: q, type: TYPE.A, class: CLASS.IN }] : [], answers: answers(F) };
				const full = encodeMessage(m).length;
				for (let limit = full - 800; limit <= full + 2; limit++) {
					compareWithReference(m, limit, `F=${F} q=${q} limit=${limit}`);
				}
			}
		}
	}, 600_000);

	it("never encodes past the limit when a kept set's registration belongs to a later record (CLDMV/digby#43)", () => {
		// The model registered a target by ANY kept record, including one at a LATER stream position: writeName registers
		// targets even for names it never compresses (an SRV target, an RRSIG signer), so the first SRV's set is measured
		// with its second record's target compressing against the registration the b.t. NS record's measurement will make
		// LATER — the real stream writes that name in full, the fit check passed on the 2-octet phantom, and the output
		// went over the limit. Repro: question `q.` A; answers `a.t.` SRV -> s1.example., `b.t.` NS -> <60xl>.example.,
		// `a.t.` SRV -> <60xl>.example. (records 0 and 2 are one RRset; record 1 is its own NS set). Full encode 217
		// octets; at limits 156..216 the buggy encode returned all 217 with truncated:false, the best-fit reference
		// returns 140 with truncated:true. Every limit in the window is compared byte for byte, and the output stays
		// within the limit — the encoder must never return more octets than the limit.
		const l60 = "l".repeat(60);
		const srv = (target) => ({ name: "a.t.", type: TYPE.SRV, class: CLASS.IN, ttl: 60, data: { priority: 1, weight: 2, port: 3, target } });
		const m = {
			id: 1,
			flags: { qr: true },
			questions: [{ name: "q.", type: TYPE.A, class: CLASS.IN }],
			answers: [srv("s1.example."), { name: "b.t.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: `${l60}.example.` } }, srv(`${l60}.example.`)]
		};
		const full = encodeMessage(m).length;
		expect(full, "the repro's full encode").toBe(217);
		for (let limit = 140; limit <= full; limit++) {
			const capped = encodeCapped(m, { limit });
			expect(capped.bytes.length, `limit=${limit}: the encoder never returns more octets than the limit`).toBeLessThanOrEqual(limit);
			const reference = oracleCapped(m, { limit });
			expect(capped.truncated, `limit=${limit}: the truncation flag matches the best-fit reference`).toBe(reference.truncated);
			expect(hex.to(capped.bytes), `limit=${limit}: the bytes match the best-fit reference`).toBe(hex.to(reference.bytes));
		}
		// the window the bug sat in: the best-fit reference truncates to 140 octets well before the full encode, and
		// every limit inside the window gets the 140-octet stream (the phantom pointer saved rec1's 61-octet target
		// suffix, so the window opens at 217 - 61 = 156 — the window the finding reports)
		for (const limit of [156, 180, 200, 216]) {
			const reference = oracleCapped(m, { limit });
			expect(reference.truncated, `limit=${limit}: the reference truncates inside the window`).toBe(true);
			expect(reference.bytes.length, `limit=${limit}: the reference's kept stream`).toBe(140);
		}
	});

	it("matches the best-fit reference on pseudo-random interleavings straddling 0x4000", () => {
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
		// without a question any drop is refused (CLDMV/digby#43), so these seeds exercise the refusal path and the
		// fit-or-refuse boundary; the one-question seeds below compare the truncated keeps byte for byte
		for (let seed = 0; seed < 40; seed++) {
			const m = randomShape(seed, false);
			const full = encodeMessage(m).length;
			for (let limit = full - 800; limit <= full + 2; limit += 1) {
				compareWithReference(m, limit, `seed=${seed} limit=${limit}`);
			}
		}
		for (let seed = 0; seed < 10; seed++) {
			const m = randomShape(seed, true);
			const full = encodeMessage(m).length;
			for (let limit = full - 800; limit <= full + 2; limit += 1) {
				compareWithReference(m, limit, `seed=${seed} q limit=${limit}`);
			}
		}
		// and the EDNS variant on a slice: the OPT tail rides every fit check
		for (let seed = 0; seed < 8; seed++) {
			const m = { ...randomShape(seed, true), edns: { udpSize: 1232, version: 0, dnssecOk: false, z: 0, options: [] } };
			const full = encodeMessage(m).length;
			for (let limit = full - 800; limit <= full + 2; limit += 1) {
				compareWithReference(m, limit, `seed=${seed} edns limit=${limit}`);
			}
		}
	}, 600_000);

	it("treats a registration whose real offset lands exactly on 0x4000 as absent (CLDMV/digby#43)", () => {
		// Set 0 is a two-record TXT RRset (positions 0 and 2); set 1 is a three-record NS RRset (positions 1, 3, 4)
		// whose rdata names share the <63x>.example. suffix. At set 1's measurement set 0 is kept, so a suffix
		// registered while writing the record at position 3 lands at its probe offset plus the kept record at
		// position 2's octets — the shift — which puts it at exactly 16,384. The compression pointer range ends at
		// 0x3fff, so the registration does not exist, and the record at position 4 writes the shared suffix in full.
		// The boundary mutant (`< 0x4000` -> `<= 0x4000` at the three sites that implement the rule: the probe
		// registration, the model lookup and the flip scan) keeps that registration: the record at position 4 then
		// measures 62 octets shorter, the keep decision flips, and the encode goes out over its limit — this golden
		// is the failure evidence for that mutant (tmp/agents/r5-capped/ev-evidence.out in the round-5 work area
		// holds the pod run).
		// g is the filler size at which the registration lands exactly on the boundary, found empirically (the
		// hand arithmetic for a 16 KB stream is not trustworthy — see tmp/agents/r5-capped/findg.out in the round-5
		// work area)
		const g = 231;
		const m = {
			id: 1,
			flags: { qr: true },
			questions: [{ name: "example.", type: TYPE.A, class: CLASS.IN }],
			answers: [bigTxt("a.test.", 16000), ns("b.test.", "n0.example."), bigTxt("a.test.", g), ns("b.test.", `n1.${x63}.example.`), ns("b.test.", `n2.${x63}.example.`)]
		};
		// the limit sits inside the flip window: the whole message does not fit, set 1 does not fit either under the
		// correct boundary (the record at position 4 writes the shared suffix in full), but does under the mutant
		// (it measures 62 octets shorter)
		const full = encodeMessage(m).length;
		const capped = encodeCapped(m, { limit: full - 30 });
		expect(capped.truncated, "the truncation flag").toBe(true);
		expect(capped.bytes.length, "within the limit").toBeLessThanOrEqual(full - 30);
		// the kept stream: header + the whole a.test. TXT set at its positions — all three b.test. NS records are
		// ONE RRset (position 1 among them), so the drop takes b0 with its set, and the kept records sit before every
		// dropped one, so their own whole-message encode is byte for byte what the truncating encode kept
		const kept = [m.answers[0], m.answers[2]];
		expect(capped.bytes.length, "the b.test. NS set dropped whole").toBe(encodeMessage({ ...m, answers: kept }).length);
		const d = decodeMessage(capped.bytes);
		expect(d.flags.tc, "TC set").toBe(true);
		expect(d.answers.map((r) => r.name)).toEqual(["a.test.", "a.test."]);
		expect(d.answers[0].data.strings.reduce((n, s) => n + s.length, 0)).toBe(16000);
		expect(d.answers[1].data.strings.reduce((n, s) => n + s.length, 0)).toBe(g);
	});

	// The C1 repro of round 7 (CLDMV/digby#43), sharpened by round 8: a message whose full encode fits the limit, but
	// whose stop-at-first-miss prefix keep stops early. The y.t. record writes N at an offset just below 0x4000 and
	// registers it, so the l.t. records' targets (a60<i>.N) compress against it — but the l.t. set is decided BEFORE
	// the y.t. set, and the drop-here stream at the l.t. set (the y.t. record absent) writes every a60<i>.N target in
	// full, which does not fit at a limit the whole message fits. Stream size is not monotone in the sets kept. The
	// greedy stop used to truncate there: at limit == full the encode came back TC'd with 3 of 13 answers.
	const c1Shape = (trailing, filler = 16236) => {
		const N = `${"w".repeat(60)}.${"x".repeat(63)}.example.`;
		const a60 = (i) => `${"a".repeat(60)}${i}`;
		return {
			id: 1,
			flags: { qr: true },
			questions: [{ name: "q.", type: TYPE.A, class: CLASS.IN }],
			answers: [
				bigTxt("f.t.", filler),
				ns("e.t.", "s.q."),
				ns("l.t.", "s.q."),
				ns("y.t.", N),
				ns("e.t.", `p63.${N}`),
				...Array.from({ length: trailing }, (_, i) => ns("l.t.", `${a60(i + 1)}.${N}`))
			]
		};
	};

	// The stream offset where writeName registers the y.t. record's N key: the record's rdata start, read off the
	// wire. Names here may be pointers (the owners share the "t." suffix with earlier records), so the walk follows
	// the envelope: a label length of 0xc0 or more is a pointer and ends the name. The landing moves one octet per
	// filler octet (the TXT rdata grows by one string-length octet every 255 filler octets, which the sweep window
	// below stays clear of).
	const landingOf = (filler) => {
		const bytes = encodeMessage(c1Shape(1, filler));
		let at = 12;
		const skipName = () => {
			for (;;) {
				const len = bytes[at];
				if (len >= 0xc0) {
					at += 2;
					return;
				}
				at += 1 + len;
				if (len === 0) return;
			}
		};
		skipName(); // the question
		at += 4;
		for (let i = 0; i < 3; i++) {
			// records 0..2: name, type, class, ttl, rdlength, rdata
			skipName();
			at += 10 + ((bytes[at + 8] << 8) | bytes[at + 9]);
		}
		skipName(); // the y.t. record's owner
		return at + 10; // its rdata start: type, class, ttl, rdlength
	};

	it("returns whole a message whose full encode fits though a prefix's drop-here stream does not (CLDMV/digby#43)", () => {
		for (const [trailing, fullExpected] of [
			[8, 17142],
			[3, 16762]
		]) {
			const m = c1Shape(trailing);
			const full = encodeMessage(m).length;
			for (const limit of [full, full + 1]) {
				const capped = encodeCapped(m, { limit });
				expect(capped.truncated, `trailing=${trailing} limit=${limit}: the whole message fits, no TC`).toBe(false);
				expect(hex.to(capped.bytes), `trailing=${trailing} limit=${limit}: the whole message, byte for byte`).toBe(hex.to(encodeMessage(m)));
				const d = decodeMessage(capped.bytes);
				expect(d.answers, `trailing=${trailing} limit=${limit}: every answer survives`).toHaveLength(m.answers.length);
				expect(d.flags.tc, `trailing=${trailing} limit=${limit}: no TC`).toBe(false);
			}
			// and the differential holds across the window the bug sat in: below the full size the largest-fit
			// truncation applies and must match the best-fit reference byte for byte
			for (let limit = full - 800; limit <= full + 2; limit++) compareWithReference(m, limit, `trailing=${trailing} limit=${limit}`);
			// the repro's size, pinned last so the property above is what a failure reports
			expect(full, `trailing=${trailing}: the repro's full encode (the finding's number)`).toBe(fullExpected);
		}
	}, 300_000);

	// Repro A of round 8 (CLDMV/digby#43): the C1 shape (filler 16,236, the trigger r7 found) with one more RRset at
	// the end. Full size 17,160; at 17,159 the largest fitting prefix drops ONLY the trailing z.t. set — 17,142
	// octets, 13 of 14 answers — while round 7's stop-at-first-miss scan stopped three answers in and returned
	// 16,502 octets (measured on 9e04bed; the finding's figures 17,220/17,202/16,562 are 60 octets higher — filler
	// 16,296 — the anchor here is the filler r7 pinned, and the sizes are measured).
	it("keeps the longest fitting prefix just under the full size: only the trailing set drops (CLDMV/digby#43, repro A)", () => {
		const base = c1Shape(8);
		const m = { ...base, answers: [...base.answers, { name: "z.t.", type: TYPE.A, class: CLASS.IN, ttl: 60, data: { address: "1.2.3.4" } }] };
		const full = encodeMessage(m).length;
		expect(full, "the repro's full encode (the finding's structure: 13 answers + z.t.)").toBe(17160);
		const capped = encodeCapped(m, { limit: full - 1 });
		expect(capped.truncated, "TC set").toBe(true);
		expect(capped.bytes.length, "dropping only z.t. fits, and that is what comes back").toBe(17142);
		const d = decodeMessage(capped.bytes);
		expect(d.answers, "13 of the 14 answers survive").toHaveLength(13);
		expect(d.flags.tc, "TC set").toBe(true);
		// byte for byte the filtered message's own encode, TC patched
		const ref = encodeMessage({ ...m, answers: m.answers.slice(0, 13) });
		ref[2] |= TC_BIT >>> 8;
		expect(hex.to(capped.bytes)).toBe(hex.to(ref));
	}, 60_000);

	// Repro B of round 8 (CLDMV/digby#43): a middle set (z.t. A) is the only one that has to drop. Full size 16,644
	// (the finding's number — which pins the filler at 16,236, the trigger r7 found, not the 16,176 the finding
	// named); at 16,626 the largest fitting prefix keeps everything around it — 7 of 8 answers, 16,626 octets —
	// while round 7's scan stopped at the first miss and returned 16,502 octets with 3 answers. This shape is also
	// the mutant frame of R8-2: the z.t. set's keep is what the drain lie (m3) used to let past the fit check.
	it("keeps the longest fitting prefix when a middle set drops (CLDMV/digby#43, repro B)", () => {
		const N = `${"w".repeat(60)}.${"x".repeat(63)}.example.`;
		const m = {
			id: 1,
			flags: { qr: true },
			questions: [{ name: "q.", type: TYPE.A, class: CLASS.IN }],
			answers: [
				bigTxt("f.t.", 16236),
				ns("e.t.", "s.q."),
				ns("l.t.", "s.q."),
				ns("y.t.", N),
				ns("e.t.", `p63.${N}`),
				ns("l.t.", `${"a".repeat(60)}1.${N}`),
				{ name: "z.t.", type: TYPE.A, class: CLASS.IN, ttl: 60, data: { address: "1.2.3.4" } },
				ns("y.t.", `b.${N}`)
			]
		};
		const full = encodeMessage(m).length;
		expect(full, "the repro's full encode (the finding's number)").toBe(16644);
		const capped = encodeCapped(m, { limit: full - 18 });
		expect(capped.truncated, "TC set").toBe(true);
		expect(capped.bytes.length, "dropping only z.t. fits, and that is what comes back").toBe(16626);
		const d = decodeMessage(capped.bytes);
		expect(d.answers, "7 of the 8 answers survive").toHaveLength(7);
		expect(d.answers.map((r) => r.name)).toEqual(["f.t.", "e.t.", "l.t.", "y.t.", "e.t.", "l.t.", "y.t."]);
		expect(d.flags.tc, "TC set").toBe(true);
	}, 60_000);

	// The C1 family swept (round 8's differential): every trailing count, every limit from full - 800 to full + 2,
	// byte for byte against the best-fit reference. Under the largest-fit rule the interesting window is exactly
	// where the greedy scan used to stop early — every limit in it must keep the longest fitting prefix. One it per
	// trailing, so progress streams and a failure names its trailing.
	for (let trailing = 1; trailing <= 10; trailing++) {
		it(`matches the best-fit reference across the C1 family, trailing=${trailing} (CLDMV/digby#43)`, () => {
			const m = c1Shape(trailing);
			const full = encodeMessage(m).length;
			for (let limit = full - 800; limit <= full + 2; limit++) {
				compareWithReference(m, limit, `trailing=${trailing} limit=${limit}`);
			}
		}, 300_000);
	}

	// The EDNS variant: the OPT tail is never dropped, so every fit check carries it; the differential holds with
	// one in the message (the reference encodes the same tail the same way).
	it("matches the best-fit reference across the C1 family with EDNS in the message (CLDMV/digby#43)", () => {
		for (const trailing of [3, 8]) {
			const m = { ...c1Shape(trailing), edns: { udpSize: 1232, version: 0, dnssecOk: true, z: 0, options: [] } };
			const full = encodeMessage(m).length;
			for (let limit = full - 800; limit <= full + 2; limit++) {
				compareWithReference(m, limit, `edns trailing=${trailing} limit=${limit}`);
			}
		}
	}, 600_000);

	// The reserveTsig variant: the codec reduces its limit by the reservation internally; the reference compares
	// against the reduced limit directly.
	it("matches the best-fit reference across the C1 family with a TSIG reservation (CLDMV/digby#43)", () => {
		const m = c1Shape(8);
		const full = encodeMessage(m).length;
		for (let limit = full - 800; limit <= full + 2; limit++) {
			compareWithReference(m, limit, `reserve limit=${limit}`, { reserveTsig: 84 });
		}
	}, 600_000);

	// The c1x family (round 8): the C1 shape with the filler swept so the y.t. record's registration of N lands on
	// every offset around the pointer boundary — including exactly 0x4000, where the boundary rules differ — and the
	// keeps around it shift and shrink the stream (l.t.'s records compress against N once it is registered, and
	// their own a60<i>.N registrations drift as a result), so crossings out of the range and drifts back in both
	// fire. This is the family that reaches the divergence channel round 7's sweep called unreached. Chunked its so
	// progress streams and a failure names its filler window.
	const c1xCenter = 16236 + (0x4000 - landingOf(16236));
	for (const trailing of [2, 8]) {
		for (let chunk = 0; chunk < 4; chunk++) {
			const lo = c1xCenter - 56 + chunk * 28;
			const hi = lo + 27;
			it(`matches the best-fit reference across the c1x shift-landing family, trailing=${trailing}, filler ${lo}..${hi} (CLDMV/digby#43)`, () => {
				for (let filler = lo; filler <= hi; filler++) {
					const m = c1Shape(trailing, filler);
					const full = encodeMessage(m).length;
					for (let limit = full - 800; limit <= full + 2; limit++) {
						compareWithReference(m, limit, `c1x trailing=${trailing} filler=${filler} limit=${limit}`);
					}
				}
			}, 600_000);
		}
	}
	it("the c1x sweep's centre lands the y.t. registration exactly on 0x4000 (CLDMV/digby#43)", () => {
		expect(landingOf(c1xCenter)).toBe(0x4000);
	});
});
