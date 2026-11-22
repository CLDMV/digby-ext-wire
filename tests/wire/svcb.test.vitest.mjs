/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/svcb.test.vitest.mjs
 */

import { describe, expect, it } from "vitest";
import { TYPE } from "../../src/lib/wire/constants.mjs";
import { WireError } from "../../src/lib/wire/errors.mjs";
import { decodeRdataBytes, encodeRdataBytes, formatRdata, parseRdata } from "../../src/lib/wire/rdata/index.mjs";
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
const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const FOO_COM = "03 666f6f 07 6578616d706c65 03 636f6d 00";
const FOO_ORG = "03 666f6f 07 6578616d706c65 03 6f7267 00";

// RFC 9460 Appendix D (the wire is the RFC's, the canonical form is how this codec prints it)
const VECTORS = [
	[TYPE.HTTPS, "0 foo.example.com.", "0 foo.example.com.", `0000 ${FOO_COM}`],
	[TYPE.SVCB, "1 .", "1 .", "0001 00"],
	[TYPE.SVCB, "16 foo.example.com. port=53", "16 foo.example.com. port=53", `0010 ${FOO_COM} 0003 0002 0035`],
	[TYPE.SVCB, "1 foo.example.com. key667=hello", '1 foo.example.com. key667="hello"', `0001 ${FOO_COM} 029b 0005 68656c6c6f`],
	[TYPE.SVCB, String.raw`1 foo.example.com. key667="hello\210qoo"`, String.raw`1 foo.example.com. key667="hello\210qoo"`, `0001 ${FOO_COM} 029b 0009 68656c6c6f d2 716f6f`],
	[
		TYPE.SVCB,
		'1 foo.example.com. ipv6hint="2001:db8::1,2001:db8::53:1"',
		"1 foo.example.com. ipv6hint=2001:db8::1,2001:db8::53:1",
		`0001 ${FOO_COM} 0006 0020 20010db8000000000000000000000001 20010db8000000000000000000530001`
	],
	[
		TYPE.SVCB,
		'1 example.com. ipv6hint="2001:db8:122:344::192.0.2.33"',
		"1 example.com. ipv6hint=2001:db8:122:344::c000:221",
		"0001 07 6578616d706c65 03 636f6d 00 0006 0010 20010db8 01220344 00000000 c0000221"
	],
	[
		TYPE.SVCB,
		"16 foo.example.org. (alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1)",
		'16 foo.example.org. mandatory=alpn,ipv4hint alpn="h2,h3-19" ipv4hint=192.0.2.1',
		`0010 ${FOO_ORG} 0000 0004 0001 0004 0001 0009 02 6832 05 68332d3139 0004 0004 c0000201`
	],
	[TYPE.SVCB, String.raw`16 foo.example.org. alpn="f\\\\oo\\,bar,h2"`, String.raw`16 foo.example.org. alpn="f\\\\oo\\,bar,h2"`, `0010 ${FOO_ORG} 0001 000c 08 665c6f6f2c626172 02 6832`],
	[TYPE.SVCB, String.raw`16 foo.example.org. alpn=f\\\092oo\092,bar,h2`, String.raw`16 foo.example.org. alpn="f\\\\oo\\,bar,h2"`, `0010 ${FOO_ORG} 0001 000c 08 665c6f6f2c626172 02 6832`]
];

describe("SVCB and HTTPS: the RFC 9460 test vectors", () => {
	for (const [type, text, canonical, wire] of VECTORS) {
		it(text, () => {
			const data = parseRdata(type, text);
			expect(hex.to(encodeRdataBytes(type, data))).toBe(hex.to(hex.from(wire)));
			expect(decodeRdataBytes(type, hex.from(wire))).toEqual(data);
			expect(formatRdata(type, data)).toBe(canonical);
			expect(parseRdata(type, canonical)).toEqual(data);
		});
	}

	it("decodes the alpn escapes to the right ids", () => {
		const data = parseRdata(TYPE.SVCB, String.raw`16 foo.example.org. alpn="f\\\\oo\\,bar,h2"`);
		expect(data.params).toEqual([{ key: 1, value: [ascii("f\\oo,bar"), ascii("h2")] }]);
	});

	it("handles every typed key", () => {
		const text = '1 svc.example. mandatory=port alpn=h2 no-default-alpn port=8443 ipv4hint=192.0.2.1,192.0.2.2 ech=AQID ipv6hint=::1 dohpath="/dns-query{?dns}" ohttp key65000';
		const data = parseRdata(TYPE.HTTPS, text);
		expect(data).toEqual({
			priority: 1,
			target: "svc.example.",
			params: [
				{ key: 0, value: [3] },
				{ key: 1, value: [ascii("h2")] },
				{ key: 2, value: null },
				{ key: 3, value: 8443 },
				{ key: 4, value: ["192.0.2.1", "192.0.2.2"] },
				{ key: 5, value: hex.from("010203") },
				{ key: 6, value: ["::1"] },
				{ key: 7, value: "/dns-query{?dns}" },
				{ key: 8, value: null },
				{ key: 65000, value: new Uint8Array(0) }
			]
		});
		expect(decodeRdataBytes(TYPE.HTTPS, encodeRdataBytes(TYPE.HTTPS, data))).toEqual(data);
		expect(parseRdata(TYPE.HTTPS, formatRdata(TYPE.HTTPS, data))).toEqual(data);
		expect(formatRdata(TYPE.HTTPS, data)).toBe(
			'1 svc.example. mandatory=port alpn="h2" no-default-alpn port=8443 ipv4hint=192.0.2.1,192.0.2.2 ech=AQID ipv6hint=::1 dohpath="/dns-query{?dns}" ohttp key65000'
		);
	});

	it("keeps a non-ASCII dohpath as UTF-8", () => {
		const data = { priority: 1, target: ".", params: [{ key: 7, value: "/q/ü{?dns}" }] };
		const wire = encodeRdataBytes(TYPE.SVCB, data);
		expect(hex.to(wire)).toBe("0001" + "00" + "0007" + "000b" + hex.to(new TextEncoder().encode("/q/ü{?dns}")));
		expect(decodeRdataBytes(TYPE.SVCB, wire)).toEqual(data);
		expect(formatRdata(TYPE.SVCB, data)).toBe(String.raw`1 . dohpath="/q/\195\188{?dns}"`);
		expect(parseRdata(TYPE.SVCB, formatRdata(TYPE.SVCB, data))).toEqual(data);
	});
});

describe("SVCB failure cases", () => {
	const p = (text) => code(() => parseRdata(TYPE.SVCB, text));
	const d = (wire) => code(() => decodeRdataBytes(TYPE.SVCB, hex.from(wire)));
	const e = (params) => code(() => encodeRdataBytes(TYPE.SVCB, { priority: 1, target: ".", params }));

	it("refuses the RFC 9460 D.3 presentation failures", () => {
		expect(p("1 foo.example.com. key123=abc key123=def")).toBe("BAD_SVCPARAM");
		expect(p("1 foo.example.com. mandatory")).toBe("BAD_SVCPARAM");
		expect(p("1 foo.example.com. alpn")).toBe("BAD_SVCPARAM");
		expect(p("1 foo.example.com. port")).toBe("BAD_SVCPARAM");
		expect(p("1 foo.example.com. ipv4hint")).toBe("BAD_SVCPARAM");
		expect(p("1 foo.example.com. ipv6hint")).toBe("BAD_SVCPARAM");
		expect(p("1 foo.example.com. no-default-alpn=abc")).toBe("BAD_SVCPARAM");
		expect(p("1 foo.example.com. mandatory=key123")).toBe("BAD_SVCPARAM");
		expect(p("1 foo.example.com. mandatory=mandatory")).toBe("BAD_SVCPARAM");
	});

	it("refuses other malformed presentation", () => {
		expect(p("1 . key65535=x")).toBe("BAD_SVCPARAM");
		expect(p("1 . bogus=1")).toBe("BAD_SVCPARAM");
		expect(p("1 . port=65536")).toBe("BAD_SVCPARAM");
		expect(p("1 . port=x")).toBe("BAD_SVCPARAM");
		expect(p("1 . ipv4hint=1.2.3")).toBe("BAD_PRESENTATION");
		expect(p("1 . ech=***")).toBe("BAD_PRESENTATION");
		expect(p('1 . alpn=","')).toBe("BAD_SVCPARAM");
		expect(p("1 . ohttp=1")).toBe("BAD_SVCPARAM");
		expect(p(String.raw`1 . dohpath="\255"`)).toBe("BAD_SVCPARAM");
		expect(p("1 . mandatory=port,port port=1")).toBe("BAD_SVCPARAM");
	});

	it("refuses malformed wire", () => {
		expect(d("0001 00 0003 0002 0035 0001 0003 02 6832")).toBe("BAD_SVCPARAM"); // keys out of order
		expect(d("0001 00 0003 0002 0035 0003 0002 0035")).toBe("BAD_SVCPARAM"); // a repeated key
		expect(d("0001 00 ffff 0000")).toBe("BAD_SVCPARAM"); // key 65535
		expect(d("0001 00 0003 0003 003500")).toBe("BAD_SVCPARAM"); // port of 3 octets
		expect(d("0001 00 0002 0001 00")).toBe("BAD_SVCPARAM"); // no-default-alpn with a value
		expect(d("0001 00 0001 0000")).toBe("BAD_SVCPARAM"); // empty alpn
		expect(d("0001 00 0001 0001 00")).toBe("BAD_SVCPARAM"); // an empty alpn id
		expect(d("0001 00 0001 0002 0568")).toBe("TRUNCATED"); // an alpn id longer than its param
		expect(d("0001 00 0000 0003 000300")).toBe("BAD_SVCPARAM"); // mandatory of odd length
		expect(d("0001 00 0000 0002 0000")).toBe("BAD_SVCPARAM"); // mandatory listing itself
		expect(d("0001 00 0000 0002 0003")).toBe("BAD_SVCPARAM"); // mandatory listing an absent key
		expect(d("0001 00 0000 0004 0003 0003 0003 0002 0035")).toBe("BAD_SVCPARAM"); // mandatory with a repeat
		expect(d("0001 00 0004 0003 c00002")).toBe("BAD_SVCPARAM"); // ipv4hint not a multiple of 4
		expect(d("0001 00 0006 0004 00000000")).toBe("BAD_SVCPARAM");
		expect(d("0001 00 0005 0000")).toBe("BAD_SVCPARAM"); // empty ech
		expect(d("0001 00 0007 0001 ff")).toBe("BAD_SVCPARAM"); // dohpath not UTF-8
		expect(d("0001 00 0003 0004 0035")).toBe("TRUNCATED"); // value longer than the rdata
		expect(d("0001 00 0003")).toBe("TRUNCATED");
	});

	it("refuses malformed values on encode", () => {
		expect(e([{ key: 3, value: 1 }, { key: 1, value: [ascii("h2")] }])).toBe("BAD_SVCPARAM");
		expect(e([{ key: 65535, value: new Uint8Array(0) }])).toBe("BAD_SVCPARAM");
		expect(e([null])).toBe("BAD_SVCPARAM");
		expect(e([{ key: 0, value: [] }])).toBe("BAD_SVCPARAM");
		expect(e([{ key: 0, value: [3] }])).toBe("BAD_SVCPARAM");
		expect(e([{ key: 0, value: ["x"] }, { key: 3, value: 1 }])).toBe("BAD_SVCPARAM");
		expect(e([{ key: 1, value: [] }])).toBe("BAD_SVCPARAM");
		expect(e([{ key: 1, value: [new Uint8Array(0)] }])).toBe("BAD_SVCPARAM");
		expect(e([{ key: 2, value: 1 }])).toBe("BAD_SVCPARAM");
		expect(e([{ key: 3, value: 70000 }])).toBe("VALUE_OUT_OF_RANGE");
		expect(e([{ key: 4, value: [] }])).toBe("BAD_SVCPARAM");
		expect(e([{ key: 6, value: [] }])).toBe("BAD_SVCPARAM");
		expect(e([{ key: 5, value: new Uint8Array(0) }])).toBe("BAD_SVCPARAM");
		expect(e([{ key: 7, value: 5 }])).toBe("VALUE_OUT_OF_RANGE");
		expect(e([{ key: 99, value: "x" }])).toBe("VALUE_OUT_OF_RANGE");
		expect(e("x")).toBe("VALUE_OUT_OF_RANGE");
	});
});
