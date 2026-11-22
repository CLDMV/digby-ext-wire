/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/edns.test.vitest.mjs
 */

import { describe, expect, it } from "vitest";
import { EDNS_OPTION, RCODE } from "../../src/lib/wire/constants.mjs";
import { WireError } from "../../src/lib/wire/errors.mjs";
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

// a query header (id 0x1234, RD, 1 question, 1 additional) and the question example. A IN
const HEAD = "1234 0100 0001 0000 0000 0001";
const QUESTION = "07 6578616d706c65 00 0001 0001";
/** an OPT record: udp 1232, the given TTL word, then the rdata */
const opt = (ttl, rdata) => {
	const r = hex.from(rdata);
	return `00 0029 04d0 ${ttl} ${r.length.toString(16).padStart(4, "0")} ${rdata}`;
};
const query = (ttl, rdata) => hex.from(`${HEAD} ${QUESTION} ${opt(ttl, rdata)}`);
const edns = (bytes) => decodeMessage(bytes).edns;
const roundTrip = (bytes) => expect(hex.to(encodeMessage(decodeMessage(bytes)))).toBe(hex.to(bytes));

describe("EDNS(0)", () => {
	it("lifts OPT out of the additional section", () => {
		const m = decodeMessage(query("00000000", ""));
		expect(m.additionals).toEqual([]);
		expect(m.edns).toEqual({ udpSize: 1232, version: 0, dnssecOk: false, z: 0, options: [] });
		roundTrip(query("00000000", ""));
	});

	it("reads DO, the version, the other flag bits and the extended rcode", () => {
		const m = decodeMessage(query("01018001", ""));
		expect(m.edns).toMatchObject({ version: 1, dnssecOk: true, z: 1 });
		// extended rcode 1 in the OPT, 0 in the header: rcode 16 (BADVERS)
		expect(m.rcode).toBe(RCODE.BADVERS);
		roundTrip(query("01018001", ""));
	});

	it("needs EDNS to encode an rcode over 15", () => {
		const m = decodeMessage(query("01000000", ""));
		expect(code(() => encodeMessage({ ...m, edns: null }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ ...m, rcode: 4096 }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("cookie (RFC 7873): client only, and client plus server", () => {
		expect(edns(query("00000000", "000a 0008 0102030405060708")).options).toEqual([{ code: 10, client: hex.from("0102030405060708"), server: null }]);
		const both = query("00000000", "000a 0010 0102030405060708 1112131415161718");
		expect(edns(both).options).toEqual([{ code: 10, client: hex.from("0102030405060708"), server: hex.from("1112131415161718") }]);
		roundTrip(both);
		const longest = query("00000000", `000a 0028 0102030405060708 ${"aa".repeat(32)}`);
		expect(edns(longest).options[0].server).toHaveLength(32);
	});

	it("cookie: refuses the lengths RFC 7873 rules out", () => {
		for (const len of [0, 7, 9, 15, 41]) {
			const rdata = `000a ${len.toString(16).padStart(4, "0")} ${"ab".repeat(len)}`;
			expect(code(() => decodeMessage(query("00000000", rdata)))).toBe("BAD_OPTION");
		}
		const enc = (o) => code(() => encodeMessage({ id: 0, edns: { udpSize: 1232, options: [o] } }));
		expect(enc({ code: 10, client: new Uint8Array(7) })).toBe("BAD_OPTION");
		expect(enc({ code: 10, client: new Uint8Array(8), server: new Uint8Array(7) })).toBe("BAD_OPTION");
		expect(enc({ code: 10, client: new Uint8Array(8), server: new Uint8Array(33) })).toBe("BAD_OPTION");
		expect(enc({ code: 10 })).toBe("VALUE_OUT_OF_RANGE");
	});

	it("tcp-keepalive (RFC 7828): empty in a query, a timeout in a response", () => {
		expect(edns(query("00000000", "000b 0000")).options).toEqual([{ code: 11, timeout: null }]);
		expect(edns(query("00000000", "000b 0002 0064")).options).toEqual([{ code: 11, timeout: 100 }]);
		roundTrip(query("00000000", "000b 0002 0064"));
		roundTrip(query("00000000", "000b 0000"));
		expect(code(() => decodeMessage(query("00000000", "000b 0001 00")))).toBe("BAD_OPTION");
		expect(code(() => decodeMessage(query("00000000", "000b 0004 00000000")))).toBe("BAD_OPTION");
	});

	it("padding (RFC 7830): the length is kept, the content is zeros on encode", () => {
		expect(edns(query("00000000", "000c 0004 00000000")).options).toEqual([{ code: 12, length: 4 }]);
		expect(edns(query("00000000", "000c 0000")).options).toEqual([{ code: 12, length: 0 }]);
		roundTrip(query("00000000", "000c 0004 00000000"));
		// non-zero padding is accepted and normalised
		const m = decodeMessage(query("00000000", "000c 0002 ffff"));
		expect(hex.to(encodeMessage(m))).toBe(hex.to(query("00000000", "000c 0002 0000")));
	});

	it("extended DNS error (RFC 8914)", () => {
		const text = hex.to(new TextEncoder().encode("signature expired"));
		const b = query("00000000", `000f ${(2 + 17).toString(16).padStart(4, "0")} 0007 ${text}`);
		expect(edns(b).options).toEqual([{ code: 15, infoCode: 7, extraText: "signature expired" }]);
		roundTrip(b);
		expect(edns(query("00000000", "000f 0002 0012")).options).toEqual([{ code: 15, infoCode: 18, extraText: "" }]);
		expect(code(() => decodeMessage(query("00000000", "000f 0001 00")))).toBe("BAD_OPTION");
		// invalid UTF-8 in the text is replaced, not refused: the text is informational
		expect(edns(query("00000000", "000f 0003 0000 ff")).options[0].extraText).toBe("�");
	});

	it("passes unknown options through raw, and can force a raw typed option", () => {
		const b = query("00000000", "0003 0004 6e736964 fde9 0000");
		expect(edns(b).options).toEqual([
			{ code: 3, data: hex.from("6e736964") },
			{ code: 65001, data: new Uint8Array(0) }
		]);
		roundTrip(b);
		const raw = encodeMessage({ id: 0, edns: { udpSize: 512, options: [{ code: 10, data: hex.from("01") }] } });
		expect(code(() => decodeMessage(raw))).toBe("BAD_OPTION");
	});

	it("refuses an option longer than the OPT rdata, and options of the wrong shape on encode", () => {
		expect(code(() => decodeMessage(query("00000000", "000a 0010 0102")))).toBe("TRUNCATED");
		expect(code(() => decodeMessage(query("00000000", "000a")))).toBe("TRUNCATED");
		const enc = (options) => code(() => encodeMessage({ id: 0, edns: { udpSize: 512, options } }));
		expect(enc([{ code: 99 }])).toBe("BAD_OPTION");
		expect(enc([{ code: 70000, data: new Uint8Array(0) }])).toBe("VALUE_OUT_OF_RANGE");
		expect(enc(["x"])).toBe("VALUE_OUT_OF_RANGE");
		expect(enc("x")).toBe("VALUE_OUT_OF_RANGE");
		expect(enc([{ code: 12, length: -1 }])).toBe("VALUE_OUT_OF_RANGE");
		expect(enc([{ code: 15, infoCode: 1, extraText: 5 }])).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ id: 0, edns: { udpSize: 512, version: 256 } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ id: 0, edns: { udpSize: 512, z: 0x8000 } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage({ id: 0, edns: "x" }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("refuses a second OPT, an OPT outside the additional section and an OPT with an owner", () => {
		const two = hex.from(`1234 0100 0001 0000 0000 0002 ${QUESTION} ${opt("00000000", "")} ${opt("00000000", "")}`);
		expect(code(() => decodeMessage(two))).toBe("MULTIPLE_OPT");
		const inAnswer = hex.from(`1234 0100 0001 0001 0000 0000 ${QUESTION} ${opt("00000000", "")}`);
		expect(code(() => decodeMessage(inAnswer))).toBe("OPT_MISPLACED");
		const owned = hex.from(`1234 0100 0001 0000 0000 0001 ${QUESTION} c00c 0029 04d0 00000000 0000`);
		expect(code(() => decodeMessage(owned))).toBe("OPT_MISPLACED");
		expect(code(() => encodeMessage({ id: 0, additionals: [{ name: ".", type: 41, class: 512, ttl: 0, data: { options: [] } }] }))).toBe("OPT_MISPLACED");
	});

	it("refuses extended-error text that is not well-formed Unicode: a lone surrogate would encode as U+FFFD (CLDMV/digby#38)", () => {
		expect(code(() => encodeMessage({ id: 0, edns: { udpSize: 1232, options: [{ code: EDNS_OPTION.EXTENDED_ERROR, infoCode: 18, extraText: "oops \uD800" }] } }))).toBe("BAD_OPTION");
	});

	it("exposes the option codes", () => {
		expect(EDNS_OPTION).toEqual({ COOKIE: 10, TCP_KEEPALIVE: 11, PADDING: 12, EXTENDED_ERROR: 15 });
	});
});
