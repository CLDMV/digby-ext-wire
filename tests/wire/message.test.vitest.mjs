/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/message.test.vitest.mjs
 */

import { describe, expect, it } from "vitest";
import { CLASS, OPCODE, TYPE } from "../../src/lib/wire/constants.mjs";
import { WireError } from "../../src/lib/wire/errors.mjs";
import { packFlags, unpackFlags } from "../../src/lib/wire/header.mjs";
import { decodeMessage, encodeMessage } from "../../src/lib/wire/message.mjs";
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
