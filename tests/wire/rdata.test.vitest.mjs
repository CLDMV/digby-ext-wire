/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/rdata.test.vitest.mjs
 */

import { describe, expect, it } from "vitest";
import { TYPE, typeFromString } from "../../src/lib/wire/constants.mjs";
import { WireError } from "../../src/lib/wire/errors.mjs";
import { TYPED, decodeRdataBytes, encodeRdataBytes, formatRdata, isTyped, parseRdata } from "../../src/lib/wire/rdata/index.mjs";
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
const EXAMPLE = "07 65 78 61 6d 70 6c 65 00"; // example.
const seconds = (y, m, d) => Date.UTC(y, m - 1, d) / 1000;

/**
 * [type, presentation in, canonical presentation out, decoded data, rdata hex]
 * The hex is worked out by hand from the RFCs' field layouts (or copied from the RFC where noted), not produced by the codec.
 */
const CASES = [
	["A", "192.0.2.1", "192.0.2.1", { address: "192.0.2.1" }, "c0 00 02 01"],
	["AAAA", "2001:DB8::1", "2001:db8::1", { address: "2001:db8::1" }, "2001 0db8 0000 0000 0000 0000 0000 0001"],
	["AAAA", "::ffff:192.0.2.1", "::ffff:c000:201", { address: "::ffff:c000:201" }, "0000 0000 0000 0000 0000 ffff c000 0201"],
	["NS", "ns1.example.", "ns1.example.", { target: "ns1.example." }, `03 6e 73 31 ${EXAMPLE}`],
	["CNAME", "@", "example.", { target: "example." }, EXAMPLE],
	["PTR", "host", "host.example.", { target: "host.example." }, `04 68 6f 73 74 ${EXAMPLE}`],
	["MX", "10 mail", "10 mail.example.", { preference: 10, exchange: "mail.example." }, `00 0a 04 6d 61 69 6c ${EXAMPLE}`],
	[
		"SOA",
		"ns admin ( 1 7200 3600 ; comment\n 1209600 300 )",
		"ns.example. admin.example. 1 7200 3600 1209600 300",
		{ mname: "ns.example.", rname: "admin.example.", serial: 1, refresh: 7200, retry: 3600, expire: 1209600, minimum: 300 },
		`02 6e 73 ${EXAMPLE} 05 61 64 6d 69 6e ${EXAMPLE} 00000001 00001c20 00000e10 00127500 0000012c`
	],
	[
		"TXT",
		'"hello world" "a\\"b" \\065 ""',
		'"hello world" "a\\"b" "A" ""',
		{ strings: [ascii("hello world"), ascii('a"b'), ascii("A"), new Uint8Array(0)] },
		"0b 68656c6c6f20776f726c64 03 612262 01 41 00"
	],
	["TXT", '"\\000\\255\\009"', '"\\000\\255\\009"', { strings: [Uint8Array.of(0, 255, 9)] }, "03 00 ff 09"],
	["TXT", '"café"', '"caf\\195\\169"', { strings: [Uint8Array.of(0x63, 0x61, 0x66, 0xc3, 0xa9)] }, "05 636166c3a9"],
	["SRV", "0 5 5060 sip", "0 5 5060 sip.example.", { priority: 0, weight: 5, port: 5060, target: "sip.example." }, `0000 0005 13c4 03 736970 ${EXAMPLE}`],
	[
		"NAPTR",
		'100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .',
		'100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .',
		{ order: 100, preference: 10, flags: ascii("U"), services: ascii("E2U+sip"), regexp: ascii("!^.*$!sip:info@example.com!"), replacement: "." },
		"0064 000a 01 55 07 4532552b736970 1b 215e2e2a242173 69703a696e666f406578616d706c652e636f6d21 00"
	],
	["CAA", '0 issue "letsencrypt.org"', '0 issue "letsencrypt.org"', { flags: 0, tag: "issue", value: ascii("letsencrypt.org") }, "00 05 6973737565 6c657473656e63727970742e6f7267"],
	["CAA", "128 tbs Unknown", '128 tbs "Unknown"', { flags: 128, tag: "tbs", value: ascii("Unknown") }, "80 03 746273 556e6b6e6f776e"],
	["CAA", '0 issue ""', '0 issue ""', { flags: 0, tag: "issue", value: new Uint8Array(0) }, "00 05 6973737565"],
	["TLSA", "3 1 1 0c72ac70 b745ac19", "3 1 1 0C72AC70B745AC19", { usage: 3, selector: 1, matchingType: 1, data: hex.from("0c72ac70b745ac19") }, "03 01 01 0c72ac70b745ac19"],
	["SSHFP", "1 1 abcdef0123", "1 1 ABCDEF0123", { algorithm: 1, fpType: 1, fingerprint: hex.from("abcdef0123") }, "01 01 abcdef0123"],
	// RFC 4034 5.4
	[
		"DS",
		"60485 5 1 ( 2BB183AF5F22588179A53B0A 98631FAD1A292118 )",
		"60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118",
		{ keyTag: 60485, algorithm: 5, digestType: 1, digest: hex.from("2BB183AF5F22588179A53B0A98631FAD1A292118") },
		"ec45 05 01 2BB183AF5F22588179A53B0A98631FAD1A292118"
	],
	// RFC 8078 4: the CDS delete form
	["CDS", "0 0 0 00", "0 0 0 00", { keyTag: 0, algorithm: 0, digestType: 0, digest: Uint8Array.of(0) }, "0000 00 00 00"],
	["DNSKEY", "257 3 13 AwEA AQ==", "257 3 13 AwEAAQ==", { flags: 257, protocol: 3, algorithm: 13, publicKey: hex.from("03010001") }, "0101 03 0d 03010001"],
	// RFC 8078 4: the CDNSKEY delete form
	["CDNSKEY", "0 3 0 AA==", "0 3 0 AA==", { flags: 0, protocol: 3, algorithm: 0, publicKey: Uint8Array.of(0) }, "0000 03 00 00"],
	[
		"RRSIG",
		"A 13 2 3600 20261201000000 20261101000000 12345 example. AQID",
		"A 13 2 3600 20261201000000 20261101000000 12345 example. AQID",
		{
			typeCovered: 1,
			algorithm: 13,
			labels: 2,
			originalTtl: 3600,
			expiration: seconds(2026, 12, 1),
			inception: seconds(2026, 11, 1),
			keyTag: 12345,
			signerName: "example.",
			signature: hex.from("010203")
		},
		`0001 0d 02 00000e10 ${seconds(2026, 12, 1).toString(16).padStart(8, "0")} ${seconds(2026, 11, 1).toString(16).padStart(8, "0")} 3039 ${EXAMPLE} 010203`
	],
	// RFC 4034 4.3: window 0 (A, MX, RRSIG, NSEC) in 6 octets, window 4 (TYPE1234 = 4 * 256 + 210) in 27, 210 being octet 26 bit 2
	[
		"NSEC",
		"host.example.com. ( A MX RRSIG NSEC TYPE1234 )",
		"host.example.com. A MX RRSIG NSEC TYPE1234",
		{ next: "host.example.com.", types: [1, 15, 46, 47, 1234] },
		`04 686f7374 07 6578616d706c65 03 636f6d 00  00 06 40 01 00 00 00 03  04 1b ${"00 ".repeat(26)} 20`
	],
	["NSEC", "next.example.", "next.example.", { next: "next.example.", types: [] }, `04 6e657874 ${EXAMPLE}`],
	// RFC 5155 Appendix A
	[
		"NSEC3",
		"1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA NSEC3PARAM RRSIG",
		"1 1 12 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS SOA MX RRSIG DNSKEY NSEC3PARAM",
		{
			hashAlgorithm: 1,
			flags: 1,
			iterations: 12,
			salt: hex.from("aabbccdd"),
			nextHashed: hex.from("174eb2409fe28bcb4887a1836f957f0a8425e27b"),
			types: [2, 6, 15, 46, 48, 51]
		},
		"01 01 000c 04 aabbccdd 14 174eb2409fe28bcb4887a1836f957f0a8425e27b 00 07 22 01 00 00 00 02 90"
	],
	["NSEC3PARAM", "1 0 12 aabbccdd", "1 0 12 AABBCCDD", { hashAlgorithm: 1, flags: 0, iterations: 12, salt: hex.from("aabbccdd") }, "01 00 000c 04 aabbccdd"],
	["NSEC3PARAM", "1 0 0 -", "1 0 0 -", { hashAlgorithm: 1, flags: 0, iterations: 0, salt: new Uint8Array(0) }, "01 00 0000 00"],
	[
		"TSIG",
		"hmac-sha256. 1700000000 300 4 AQIDBA== 4660 0 0 -",
		"hmac-sha256. 1700000000 300 4 AQIDBA== 4660 0 0 -",
		{ algorithm: "hmac-sha256.", timeSigned: 1700000000, fudge: 300, mac: hex.from("01020304"), originalId: 4660, error: 0, otherData: new Uint8Array(0) },
		"0b 686d61632d736861323536 00 0000 6553f100 012c 0004 01020304 1234 0000 0000"
	],
	["TYPE1234", "\\# 3 abcdef", "\\# 3 ABCDEF", { data: hex.from("abcdef") }, "abcdef"],
	["TYPE65535", "\\# 0", "\\# 0", { data: new Uint8Array(0) }, ""],
	["HINFO", "\\# 4 01410142", "\\# 4 01410142", { data: hex.from("01410142") }, "01410142"]
];

describe("typed rdata: presentation and wire", () => {
	for (const [mnemonic, text, canonical, data, rdataHex] of CASES) {
		const type = typeFromString(mnemonic);
		it(`${mnemonic} ${text}`, () => {
			const parsed = parseRdata(type, text, "example.");
			expect(parsed).toEqual(data);
			expect(formatRdata(type, parsed)).toBe(canonical);
			expect(parseRdata(type, canonical)).toEqual(data);
			const wire = encodeRdataBytes(type, data);
			expect(hex.to(wire)).toBe(hex.to(hex.from(rdataHex)));
			expect(decodeRdataBytes(type, wire)).toEqual(data);
		});
	}

	it("covers every typed type", () => {
		const covered = new Set(CASES.map(([m]) => typeFromString(m)));
		const missing = TYPED.filter((t) => t !== TYPE.OPT && t !== TYPE.SVCB && t !== TYPE.HTTPS && !covered.has(t));
		expect(missing).toEqual([]);
		expect(isTyped(TYPE.A)).toBe(true);
		expect(isTyped(13)).toBe(false);
	});

	it("accepts the RFC 3597 generic form for a typed type and decodes it with the typed codec", () => {
		expect(parseRdata(TYPE.A, "\\# 4 C0000201")).toEqual({ address: "192.0.2.1" });
		expect(parseRdata(TYPE.MX, "\\# 3 000a00")).toEqual({ preference: 10, exchange: "." });
		expect(code(() => parseRdata(TYPE.A, "\\# 3 C00002"))).toBe("BAD_RDATA");
		expect(code(() => parseRdata(TYPE.A, "\\# 4 C00002"))).toBe("BAD_RDATA");
		// a compression pointer cannot resolve in standalone rdata
		expect(code(() => parseRdata(TYPE.NS, "\\# 2 c000"))).toBe("POINTER_FORWARD");
	});

	it("formats OPT rdata (no master-file form) generically", () => {
		const data = { options: [{ code: 12, length: 2 }] };
		expect(formatRdata(TYPE.OPT, data)).toBe("\\# 6 000C00020000");
		expect(parseRdata(TYPE.OPT, "\\# 6 000C00020000")).toEqual(data);
		expect(code(() => parseRdata(TYPE.OPT, "1 2"))).toBe("BAD_RDATA");
		expect(code(() => parseRdata(13, '"cpu" "os"'))).toBe("BAD_RDATA");
	});
});

describe("malformed wire rdata", () => {
	const bad = (mnemonic, rdataHex) => code(() => decodeRdataBytes(typeFromString(mnemonic), hex.from(rdataHex)));

	it("checks fixed lengths and exact consumption", () => {
		expect(bad("A", "c00002")).toBe("BAD_RDATA");
		expect(bad("A", "c0000201ff")).toBe("BAD_RDATA");
		expect(bad("AAAA", "00".repeat(15))).toBe("BAD_RDATA");
		expect(bad("MX", "000a")).toBe("TRUNCATED");
		expect(bad("MX", `000a ${EXAMPLE} ff`)).toBe("RDLENGTH_MISMATCH");
		expect(bad("SOA", `00 00 00000001`)).toBe("TRUNCATED");
		expect(bad("TXT", "")).toBe("BAD_RDATA");
		expect(bad("TXT", "05 6162")).toBe("TRUNCATED");
		expect(bad("SRV", "0000 0000 0000")).toBe("TRUNCATED");
	});

	it("checks CAA, DS, DNSKEY, RRSIG, TLSA and NSEC3 contents", () => {
		expect(bad("CAA", "00 00")).toBe("BAD_RDATA");
		expect(bad("CAA", "00 03 61 2d 62")).toBe("BAD_RDATA");
		expect(bad("CAA", "00 05 6973")).toBe("TRUNCATED");
		expect(bad("DS", "ec45 05 01")).toBe("BAD_RDATA");
		expect(bad("DNSKEY", "0101 03 0d")).toBe("BAD_RDATA");
		expect(bad("RRSIG", `0001 0d 02 00000e10 00000000 00000000 3039 ${EXAMPLE}`)).toBe("BAD_RDATA");
		expect(bad("TLSA", "03 01 01")).toBe("BAD_RDATA");
		expect(bad("SSHFP", "01 01")).toBe("BAD_RDATA");
		expect(bad("NSEC3", "01 00 0000 00 00")).toBe("BAD_RDATA");
		expect(bad("NSEC3PARAM", "01 00 0000 05 aabb")).toBe("TRUNCATED");
	});

	it("checks type bitmaps strictly", () => {
		expect(bad("NSEC", "00 00 01 00")).toBe("BAD_RDATA"); // a 1-octet window holding 0 (trailing zero)
		expect(bad("NSEC", "00 00 01")).toBe("TRUNCATED");
		expect(bad("NSEC", "00 00 00")).toBe("BAD_RDATA"); // length 0
		expect(bad("NSEC", `00 00 21 ${"ff".repeat(33)}`)).toBe("BAD_RDATA"); // 33 octets
		expect(bad("NSEC", "00 01 01 40 00 01 40")).toBe("BAD_RDATA"); // window 1 then window 0
		expect(bad("NSEC", "00 00 01 40 00 01 40")).toBe("BAD_RDATA"); // window 0 twice
		expect(bad("NSEC", "00 00 02 40")).toBe("TRUNCATED");
		expect(bad("NSEC", "00 00")).toBe("TRUNCATED");
		expect(decodeRdataBytes(TYPE.NSEC, hex.from("00 ff 01 80"))).toEqual({ next: ".", types: [65280] });
	});

	it("refuses a type bitmap that sets type 0 (CLDMV/digby#38)", () => {
		expect(bad("NSEC", "00 00 01 80")).toBe("BAD_RDATA"); // window 0, bit 0 = type 0
		expect(bad("NSEC3", "01 00 000c 04 aabbccdd 14 174eb2409fe28bcb4887a1836f957f0a8425e27b 00 00 01 80")).toBe("BAD_RDATA");
	});

	it("TSIG fields are bounded by the rdata", () => {
		expect(bad("TSIG", "00 000000000000 0000 0005 0102")).toBe("TRUNCATED");
		expect(bad("TSIG", "00 000000000000 0000 0000 0000 0000 0003 01")).toBe("TRUNCATED");
	});
});

describe("encoding refuses malformed values with WireError", () => {
	const enc = (mnemonic, data) => code(() => encodeRdataBytes(typeFromString(mnemonic), data));

	it("checks the data's shape and field ranges", () => {
		expect(enc("A", null)).toBe("VALUE_OUT_OF_RANGE");
		expect(enc("A", "1.2.3.4")).toBe("VALUE_OUT_OF_RANGE");
		expect(enc("A", { address: 42 })).toBe("VALUE_OUT_OF_RANGE");
		expect(enc("A", { address: "1.2.3" })).toBe("BAD_PRESENTATION");
		expect(enc("A", { address: "01.2.3.4" })).toBe("BAD_PRESENTATION");
		expect(enc("MX", { preference: 70000, exchange: "a." })).toBe("VALUE_OUT_OF_RANGE");
		expect(enc("MX", { preference: 1.5, exchange: "a." })).toBe("VALUE_OUT_OF_RANGE");
		expect(enc("MX", { preference: 1, exchange: "relative" })).toBe("RELATIVE_NAME");
		expect(enc("TXT", { strings: [] })).toBe("BAD_RDATA");
		expect(enc("TXT", { strings: "x" })).toBe("VALUE_OUT_OF_RANGE");
		expect(enc("TXT", { strings: ["x"] })).toBe("VALUE_OUT_OF_RANGE");
		expect(enc("TXT", { strings: [new Uint8Array(256)] })).toBe("VALUE_OUT_OF_RANGE");
		expect(enc("CAA", { flags: 0, tag: "is-sue", value: new Uint8Array(0) })).toBe("BAD_RDATA");
		expect(enc("DS", { keyTag: 1, algorithm: 1, digestType: 1, digest: new Uint8Array(0) })).toBe("BAD_RDATA");
		expect(enc("NSEC", { next: "a.", types: [70000] })).toBe("BAD_RDATA");
		expect(enc("NSEC", { next: "a.", types: [1, "x"] })).toBe("BAD_RDATA");
		expect(enc("NSEC", { next: "a.", types: null })).toBe("VALUE_OUT_OF_RANGE");
		expect(enc("NSEC3", { hashAlgorithm: 1, flags: 0, iterations: 0, salt: new Uint8Array(0), nextHashed: new Uint8Array(0), types: [] })).toBe("BAD_RDATA");
		expect(enc("TSIG", { algorithm: "a.", timeSigned: 2 ** 48, fudge: 0, mac: new Uint8Array(0), originalId: 0, error: 0, otherData: new Uint8Array(0) })).toBe(
			"VALUE_OUT_OF_RANGE"
		);
		expect(enc("TYPE999", { data: "x" })).toBe("VALUE_OUT_OF_RANGE");
		expect(enc("TYPE999", null)).toBe("VALUE_OUT_OF_RANGE");
	});

	it("refuses a bitmap value that sets type 0 (CLDMV/digby#38)", () => {
		expect(enc("NSEC", { next: "a.", types: [0] })).toBe("BAD_RDATA");
	});

	it("sorts and de-duplicates a bitmap's types", () => {
		expect(decodeRdataBytes(TYPE.NSEC, encodeRdataBytes(TYPE.NSEC, { next: ".", types: [47, 1, 1, 46] }))).toEqual({ next: ".", types: [1, 46, 47] });
	});
});

describe("malformed presentation rdata", () => {
	const p = (mnemonic, text, origin) => code(() => parseRdata(typeFromString(mnemonic), text, origin));

	it("refuses missing, extra and malformed fields", () => {
		expect(p("A", "")).toBe("BAD_PRESENTATION");
		expect(p("A", "1.2.3.4 5")).toBe("BAD_PRESENTATION");
		expect(p("A", "256.1.1.1")).toBe("BAD_PRESENTATION");
		expect(p("A", '"1.2.3.4"')).toBe("BAD_PRESENTATION");
		expect(p("AAAA", "1:2:3:4:5:6:7:8:9")).toBe("BAD_PRESENTATION");
		expect(p("AAAA", "1::2::3")).toBe("BAD_PRESENTATION");
		expect(p("AAAA", "1:2:3:4:5:6:7")).toBe("BAD_PRESENTATION");
		expect(p("AAAA", "1.2.3.4::")).toBe("BAD_PRESENTATION");
		expect(p("AAAA", "12345::")).toBe("BAD_PRESENTATION");
		expect(p("MX", "x mail.")).toBe("BAD_PRESENTATION");
		expect(p("MX", "65536 mail.")).toBe("BAD_PRESENTATION");
		expect(p("MX", "10 mail")).toBe("RELATIVE_NAME");
		expect(p("TXT", "")).toBe("BAD_RDATA");
		expect(p("TXT", `"${"a".repeat(256)}"`)).toBe("BAD_PRESENTATION");
		expect(p("TXT", '"open')).toBe("BAD_PRESENTATION");
		expect(p("TXT", "( a")).toBe("BAD_PRESENTATION");
		expect(p("TXT", "a )")).toBe("BAD_PRESENTATION");
		expect(p("TXT", 'a"b')).toBe("BAD_PRESENTATION");
		expect(p("CAA", "0 bad-tag x")).toBe("BAD_RDATA");
		expect(p("DS", "1 2 3 abc")).toBe("BAD_PRESENTATION");
		expect(p("DS", "1 2 3")).toBe("BAD_RDATA");
		expect(p("DNSKEY", "256 3 8 not*base64")).toBe("BAD_PRESENTATION");
		expect(p("DNSKEY", "256 3 8 AB==")).toBe("BAD_PRESENTATION"); // non-zero trailing bits
		expect(p("DNSKEY", "256 3 8")).toBe("BAD_RDATA");
		expect(p("RRSIG", "A 13 2 3600 20261301000000 20261101000000 1 example. AQID")).toBe("BAD_PRESENTATION");
		expect(p("RRSIG", "A 13 2 3600 21070101000000 20261101000000 1 example. AQID")).toBe("BAD_PRESENTATION");
		expect(p("RRSIG", "A 13 2 3600 1 2 1 example.")).toBe("BAD_RDATA");
		expect(p("RRSIG", "BOGUS 13 2 3600 1 2 1 example. AQID")).toBe("UNKNOWN_MNEMONIC");
		expect(p("NSEC", "a. A BOGUS")).toBe("UNKNOWN_MNEMONIC");
		expect(p("NSEC3", "1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22boj")).toBe("BAD_PRESENTATION");
		expect(p("NSEC3", "1 1 12 aabbccdd 2W")).toBe("BAD_PRESENTATION");
		expect(p("NSEC3", "1 1 12 aabbccdd 01")).toBe("BAD_PRESENTATION"); // non-zero trailing bits
		expect(p("NSEC3PARAM", "1 0 12 -- ")).toBe("BAD_PRESENTATION");
		expect(p("TSIG", "a. 1 300 4 AQID 0 0 0 -")).toBe("BAD_RDATA");
		expect(p("TYPE99", "\\# 2 abcdef")).toBe("BAD_RDATA");
		expect(p("TYPE99", "\\# x ab")).toBe("BAD_PRESENTATION");
		expect(p("TYPE99", "\\# 1 a")).toBe("BAD_PRESENTATION");
	});

	it("refuses rdata that encodes past a record's 65535-octet limit (CLDMV/digby#38)", () => {
		// a 70,000-octet CAA value or a 750 KB DNSKEY used to parse and fail only at encode
		expect(p("CAA", `0 issue "${"a".repeat(70000)}"`)).toBe("BAD_PRESENTATION");
		expect(p("DNSKEY", `257 3 8 ${Buffer.from(new Uint8Array(750 * 1024)).toString("base64")}`)).toBe("BAD_PRESENTATION");
		// exactly 65535 octets still parses; one octet more does not (flags + tag length + "issue" + value)
		expect(parseRdata(TYPE.CAA, `0 issue "${"a".repeat(65528)}"`).value).toHaveLength(65528);
		expect(p("CAA", `0 issue "${"a".repeat(65529)}"`)).toBe("BAD_PRESENTATION");
	});

	it("refuses lone surrogates in character-strings and escapes (CLDMV/digby#38)", () => {
		expect(p("TXT", '"\uD800"')).toBe("BAD_PRESENTATION");
		expect(p("TXT", '"a\uD800b"')).toBe("BAD_PRESENTATION");
		expect(p("CAA", '0 issue "\uD800"')).toBe("BAD_PRESENTATION");
		expect(p("CAA", '0 issue "\\\uD800"')).toBe("BAD_PRESENTATION"); // an escape whose character is a lone surrogate
	});

	it("refuses TYPE0 in a type bitmap (CLDMV/digby#38)", () => {
		expect(p("NSEC", "a. TYPE0")).toBe("BAD_PRESENTATION");
		expect(p("NSEC", "a. A TYPE0")).toBe("BAD_PRESENTATION");
		expect(p("NSEC3", "1 1 12 aabbccdd 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR TYPE0")).toBe("BAD_PRESENTATION");
	});

	it("accepts RRSIG times as decimal seconds", () => {
		expect(parseRdata(TYPE.RRSIG, "A 13 2 3600 4294967295 0 1 example. AQID")).toMatchObject({ expiration: 4294967295, inception: 0 });
		expect(formatRdata(TYPE.RRSIG, parseRdata(TYPE.RRSIG, "A 13 2 3600 4294967295 0 1 example. AQID"))).toContain(" 21060207062815 19700101000000 ");
	});
});

describe("formatRdata validates its input (CLDMV/digby#37)", () => {
	it("refuses malformed rdata shapes with a WireError instead of a TypeError or undefined", () => {
		// the reproducing cases from the issue
		expect(code(() => formatRdata(TYPE.A, {}))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRdata(TYPE.MX, { preference: "x;y", exchange: "a. b" }))).toBe("VALUE_OUT_OF_RANGE");
		// a bad shape in a field the format function reads directly must not throw a TypeError
		expect(code(() => formatRdata(TYPE.TXT, {}))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRdata(TYPE.TXT, { strings: [] }))).toBe("BAD_RDATA");
		expect(code(() => formatRdata(TYPE.SVCB, {}))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRdata(TYPE.SVCB, { priority: 1, target: ".", params: [{}] }))).toBe("BAD_SVCPARAM");
		expect(code(() => formatRdata(TYPE.A, null))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRdata(TYPE.A, { address: 1.2 }))).toBe("VALUE_OUT_OF_RANGE");
		// a relative name has no origin to complete it on the encode path
		expect(code(() => formatRdata(TYPE.MX, { preference: 1, exchange: "a. b" }))).toBe("RELATIVE_NAME");
		expect(code(() => formatRdata(TYPE.MX, { preference: 70000, exchange: "a." }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("formats only what the wire round-trip produced, so nothing unvalidated is echoed", () => {
		// the exchange name is re-canonicalised through decode: a raw `;` would start a comment in the zone text
		expect(formatRdata(TYPE.MX, { preference: 1, exchange: "a;b." })).toBe(String.raw`1 a\;b.`);
		expect(formatRdata(TYPE.A, { address: "1.2.3.4" })).toBe("1.2.3.4");
	});
});
