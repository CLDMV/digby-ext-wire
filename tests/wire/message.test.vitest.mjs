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
 * The exact-trial reference (CLDMV/digby#43): the round-2/3 truncation algorithm, captured from commit 11347f0
 * (`encodeCappedRaw`'s truncation branch) and re-implemented here on the exported primitives — {@link Writer},
 * {@link writeName}, {@link nameKey}, {@link packFlags} — plus local rdata writers for the record types the
 * differential shapes carry (A, NS, CNAME, PTR, MX, TXT). Per set it writes the stream that would actually go out
 * (all kept sets plus this one, at their original positions, with real compression) and keeps it when it fits, so
 * its keep/drop decisions and its bytes are exact by construction. The differential below pins `encodeCapped` to
 * it byte for byte: a fast probe path may only skip the trial when it cannot change what is kept.
 *
 * No EDNS and no TSIG: the differential shapes carry neither, so the reference's `fits` check is
 * `w.length <= limit` (the tail's own fit check is vacuous without one).
 *
 * @param {object} message
 * @param {{ limit: number, truncate?: boolean, compress?: boolean }} options
 * @returns {{ bytes: Uint8Array, truncated: boolean }}
 */
function oracleCapped(message, { limit, truncate = true, compress = true }) {
	/** Local mirrors of the codecs basic.mjs uses for the types the differential shapes carry. */
	const writeRdata = (w, rec) => {
		const d = rec.data;
		if (d === null) return; // the empty-rdata update form: not used by the differential shapes
		switch (rec.type) {
			case TYPE.A: {
				const o = d.address.split(".").map(Number);
				w.u8(o[0]);
				w.u8(o[1]);
				w.u8(o[2]);
				w.u8(o[3]);
				return;
			}
			case TYPE.NS:
			case TYPE.CNAME:
			case TYPE.PTR:
				writeName(w, d.target, true);
				return;
			case TYPE.MX:
				w.u16(d.preference);
				writeName(w, d.exchange, true);
				return;
			case TYPE.TXT:
				for (const s of d.strings) {
					w.u8(s.length);
					w.raw(s);
				}
				return;
			default:
				throw new Error(`the differential reference has no encoder for type ${rec.type}`);
		}
	};
	const writeRecord = (w, rec) => {
		writeName(w, rec.name, true);
		w.u16(rec.type);
		w.u16(rec.class ?? CLASS.IN);
		w.u32(rec.ttl);
		const lenAt = w.length;
		w.u16(0);
		writeRdata(w, rec);
		w.patch16(lenAt, w.length - lenAt - 2);
	};
	const rrsets = (list) => {
		const sets = [];
		const owner = new Array(list.length);
		const byKey = new Map();
		for (let i = 0; i < list.length; i++) {
			const rec = list[i];
			const k = `${nameKey(rec.name)}|${rec.type}|${rec.class ?? CLASS.IN}|${rec.type === TYPE.RRSIG ? rec.data?.typeCovered : ""}`;
			let ix = byKey.get(k);
			if (ix === undefined) {
				ix = sets.length;
				byKey.set(k, ix);
				sets.push([]);
			}
			sets[ix].push(i);
			owner[i] = ix;
		}
		return { sets, owner };
	};

	const w = new Writer({ max: truncate ? 65535 : limit, compress });
	const questions = message.questions ?? [];
	w.u16(message.id ?? 0);
	w.u16(packFlags(message.flags ?? {}, 0));
	w.u16(questions.length);
	const countAt = w.length;
	w.u16(0);
	w.u16(0);
	w.u16(0);
	for (const q of questions) {
		writeName(w, q.name, true);
		w.u16(q.type);
		w.u16(q.class ?? CLASS.IN);
	}
	const sections = [message.answers ?? [], message.authorities ?? [], message.additionals ?? []];
	const written = [0, 0, 0];
	let truncated = false;
	outer: for (let s = 0; s < 3; s++) {
		const list = sections[s];
		const { sets, owner } = rrsets(list);
		let pos = 0; // section positions below this are decided and finally written
		let keptSets = sets.length;
		for (let k = 0; k < sets.length; k++) {
			const first = sets[k][0];
			// records before this set's first record belong to sets already decided as kept: write them for good
			for (let i = pos; i < first; i++) {
				writeRecord(w, list[i]);
				written[s]++;
			}
			pos = first;
			const mark = w.checkpoint();
			let fits = true;
			try {
				// the section from `first` on with this set slotted in at its positions: the final write order
				for (let i = first; i < list.length; i++) if (owner[i] <= k) writeRecord(w, list[i]);
				fits = w.length <= limit;
			} catch (err) {
				if (!(err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE)) throw err;
				fits = false;
			}
			w.rollback(mark);
			if (!fits) {
				keptSets = k;
				if (s < 2) truncated = true;
				break; // the truncation point: this set and everything after it, in every section, is dropped
			}
		}
		for (let i = pos; i < list.length; i++)
			if (owner[i] < keptSets) {
				writeRecord(w, list[i]);
				written[s]++;
			}
		if (keptSets < sets.length) break outer;
	}
	written.forEach((n, i) => w.patch16(countAt + i * 2, n));
	if (truncated) w.patch16(2, ((w.bytes[2] << 8) | w.bytes[3]) | TC_BIT);
	return { bytes: w.finish(), truncated };
}

describe("encodeCapped matches the exact-trial reference on 0x4000-straddling interleavings (CLDMV/digby#43)", () => {
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
			const capped = encodeCapped(m, { limit: 16546 });
			const reference = oracleCapped(m, { limit: 16546 });
			expect(capped.bytes.length, `filler ${filler}: the capped encode stays within the limit`).toBeLessThanOrEqual(16546);
			expect(capped.truncated, `filler ${filler}: the truncation flag matches the exact-trial reference`).toBe(reference.truncated);
			expect(hex.to(capped.bytes), `filler ${filler}: the bytes match the exact-trial reference`).toBe(hex.to(reference.bytes));
		}
	});

	it("matches the exact-trial reference at every limit around every decision boundary", () => {
		// The repro family, swept: a big first TXT record parks the stream just below the registration bound and
		// the same-owner NS set interleaves its records around the distinct owner, so a set's probe measurement
		// (its records written consecutively) registers suffixes at offsets the real stream never reaches. Every
		// filler (step 8) × every limit around the full length, with and without a question sharing the section's
		// suffix, compared byte for byte against the exact-trial reference.
		const answers = (F) => [bigTxt("t.test.", F), ns("z.test.", "n1.aaaa.example."), txt("b.test.", 200), ns("z.test.", `n2.${x63}.example.`), ns("z.test.", `n3.${x63}.example.`)];
		for (let F = 15400; F <= 16400; F += 32) {
			for (const q of [null, "z.test."]) {
				const m = { id: 1, flags: { qr: true }, questions: q ? [{ name: q, type: TYPE.A, class: CLASS.IN }] : [], answers: answers(F) };
				const full = encodeMessage(m).length;
				for (let limit = full - 700; limit <= full; limit++) {
					const capped = encodeCapped(m, { limit });
					const reference = oracleCapped(m, { limit });
					expect(capped.truncated, `F=${F} q=${q} limit=${limit}`).toBe(reference.truncated);
					expect(hex.to(capped.bytes), `F=${F} q=${q} limit=${limit}`).toBe(hex.to(reference.bytes));
				}
			}
		}
	}, 600_000);

	it("matches the exact-trial reference on pseudo-random interleavings straddling 0x4000", () => {
		for (let seed = 0; seed < 40; seed++) {
			const rand = (n) => ((seed * 1103515245 + 12345 + n * 69069) >>> 8) % 997;
			const F = 15300 + (rand(1) % 1100);
			const recs = [bigTxt("big.test.", F)];
			const names = ["z.test.", "b.test.", "c.test.", "d.test."];
			for (let i = 0; i < 8; i++) {
				const n = names[rand(2 + i) % names.length];
				recs.push(rand(3 + i) % 2 ? txt(n, 40 + (rand(i) % 220)) : ns(n, `t${i}.${x63}.example.`));
			}
			const m = { id: 1, flags: { qr: true }, questions: [], answers: recs };
			const full = encodeMessage(m).length;
			for (let limit = full - 900; limit <= full; limit += 1) {
				const capped = encodeCapped(m, { limit });
				const reference = oracleCapped(m, { limit });
				expect(capped.truncated, `seed=${seed} limit=${limit}`).toBe(reference.truncated);
				expect(hex.to(capped.bytes), `seed=${seed} limit=${limit}`).toBe(hex.to(reference.bytes));
			}
		}
	}, 600_000);
});
