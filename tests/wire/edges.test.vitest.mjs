/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/edges.test.vitest.mjs
 */

import { describe, expect, it } from "vitest";
import * as wire from "../../src/lib/wire/index.mjs";
import { Reader, Writer, asBytes } from "../../src/lib/wire/buffer.mjs";
import { hex } from "../helpers/wire-gen.mjs";

const { TYPE, WireError, decodeMessage, encodeMessage, encodeRdataBytes, parseRdata } = wire;

const code = (fn) => {
	try {
		fn();
	} catch (err) {
		if (!(err instanceof WireError)) throw err;
		return err.code;
	}
	return "no error";
};

describe("the public surface", () => {
	it("exports the codec from one module", () => {
		for (const name of [
			"WireError",
			"WireErrorCode",
			"TYPE",
			"CLASS",
			"RCODE",
			"OPCODE",
			"EDNS_OPTION",
			"SVC_KEY",
			"decodeMessage",
			"encodeMessage",
			"encodeCapped",
			"appendTsig",
			"encodeForTransport",
			"udpLimit",
			"frameTcp",
			"TcpFramer",
			"decodeRdataBytes",
			"encodeRdataBytes",
			"parseRdata",
			"formatRdata",
			"formatGeneric",
			"parseRecord",
			"formatRecord",
			"parseTtl",
			"canonicalName",
			"namesEqual",
			"nameKey",
			"parseName",
			"formatName",
			"labelCount",
			"typeFromString",
			"typeToString",
			"classFromString",
			"classToString",
			"svcKeyFromString",
			"svcKeyToString",
			"isTyped",
			"TYPED"
		])
			expect(wire[name], name).toBeDefined();
		expect(wire.MAX_MESSAGE).toBe(65535);
		expect(wire.MAX_LABEL).toBe(63);
		expect(wire.MAX_NAME).toBe(255);
		expect(wire.UDP_MIN).toBe(512);
		expect(wire.DEFAULT_UDP_CAP).toBe(1232);
		expect(wire.TCP_MAX).toBe(65535);
		expect(new WireError("BAD_RDATA", "x", 3).message).toBe("x (at offset 3)");
		expect(new WireError("BAD_RDATA", "x").offset).toBeUndefined();
	});
});

describe("buffer edges", () => {
	it("views any ArrayBufferView", () => {
		const dv = new DataView(Uint8Array.of(9, 1, 2).buffer, 1);
		expect(asBytes(dv)).toEqual(Uint8Array.of(1, 2));
		expect(asBytes(new Uint16Array([0x0102]))).toHaveLength(2);
	});

	it("refuses non-octet input to raw and charString", () => {
		const w = new Writer();
		expect(code(() => w.raw([1]))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => w.charString("x"))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => w.u8(256))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => w.u32(-1))).toBe("VALUE_OUT_OF_RANGE");
		expect(new Reader(Uint8Array.of(1, 2)).remaining).toBe(2);
	});

	it("never grows past its cap", () => {
		const w = new Writer({ max: 10 });
		w.raw(new Uint8Array(10));
		expect(code(() => w.u8(0))).toBe("MESSAGE_TOO_LARGE");
		const big = new Writer();
		big.raw(new Uint8Array(65535));
		expect(big.finish()).toHaveLength(65535);
	});
});

describe("size caps around the tail", () => {
	it("fails MESSAGE_TOO_LARGE when the OPT does not fit under maxSize", () => {
		const m = { id: 0, questions: [{ name: "example.", type: 1 }], edns: { udpSize: 1232, options: [{ code: 12, length: 100 }] } };
		const size = encodeMessage(m).length;
		expect(code(() => encodeMessage(m, { maxSize: size - 1 }))).toBe("MESSAGE_TOO_LARGE");
		expect(encodeMessage(m, { maxSize: size })).toHaveLength(size);
		const withAnswer = { ...m, answers: [{ name: "example.", type: 1, ttl: 1, data: { address: "1.2.3.4" } }] };
		const full = encodeMessage(withAnswer).length;
		expect(code(() => encodeMessage(withAnswer, { maxSize: full - 1 }))).toBe("MESSAGE_TOO_LARGE");
	});

	it("refuses an OPT that cannot fit in any message", () => {
		const m = { id: 0, edns: { udpSize: 1232, options: [{ code: 12, length: 65530 }] } };
		expect(code(() => encodeMessage(m))).toBe("MESSAGE_TOO_LARGE");
	});
});

describe("rdata edges", () => {
	it("checks the empty trailing fields of TLSA and SSHFP", () => {
		expect(code(() => encodeRdataBytes(TYPE.TLSA, { usage: 3, selector: 1, matchingType: 1, data: new Uint8Array(0) }))).toBe("BAD_RDATA");
		expect(code(() => parseRdata(TYPE.TLSA, "3 1 1"))).toBe("BAD_RDATA");
		expect(code(() => parseRdata(TYPE.SSHFP, "1 1"))).toBe("BAD_RDATA");
	});

	it("bounds NSEC3 salts and hashes in presentation", () => {
		expect(code(() => parseRdata(TYPE.NSEC3, `1 0 0 ${"ab".repeat(256)} 00`))).toBe("BAD_RDATA");
		expect(code(() => parseRdata(TYPE.NSEC3, `1 0 0 - ${"0".repeat(416)}`))).toBe("BAD_RDATA");
		expect(code(() => parseRdata(TYPE.NSEC3PARAM, `1 0 0 ${"ab".repeat(256)}`))).toBe("BAD_RDATA");
	});

	it("refuses an IPv6 address with :: and eight groups", () => {
		expect(code(() => parseRdata(TYPE.AAAA, "1:2:3:4:5:6:7::8"))).toBe("BAD_PRESENTATION");
	});

	it("defaults an extended error's text to empty", () => {
		const b = encodeMessage({ id: 0, edns: { udpSize: 512, options: [{ code: 15, infoCode: 3 }] } });
		expect(decodeMessage(b).edns.options).toEqual([{ code: 15, infoCode: 3, extraText: "" }]);
	});

	it("needs a dohpath value", () => {
		expect(code(() => parseRdata(TYPE.SVCB, "1 . dohpath"))).toBe("BAD_SVCPARAM");
		expect(code(() => parseRdata(TYPE.SVCB, '1 . dohpath=""'))).toBe("BAD_SVCPARAM");
	});

	it("keeps a relative name's escaped last label", () => {
		expect(wire.canonicalName("a\\.", "example.")).toBe("a\\..example.");
	});

	it("decodes the same message from a fresh copy and a view", () => {
		const b = hex.from("0000 0000 0000 0000 0000 0000");
		expect(decodeMessage(new DataView(b.buffer))).toEqual(decodeMessage(b));
	});
});
