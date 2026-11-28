/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/presentation.test.vitest.mjs
 */

import { describe, expect, it } from "vitest";
import { CLASS, TYPE, classFromString, classToString, svcKeyFromString, svcKeyToString, typeFromString, typeToString } from "../../src/lib/constants.mjs";
import { WireError } from "../../src/lib/errors.mjs";
import { formatRecord, parseRecord, parseTtl } from "../../src/lib/presentation.mjs";
import { formatIPv6, fromBase32Hex, parseIPv6, toBase32Hex, tokenize, unescapeBytes } from "../../src/lib/text.mjs";
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

describe("the tokenizer", () => {
	it("splits on whitespace, keeps quoted strings whole and drops comments and parentheses", () => {
		expect(tokenize('a  "b c" ( d\n e ) ; f\n g')).toEqual([
			{ value: "a", quoted: false },
			{ value: "b c", quoted: true },
			{ value: "d", quoted: false },
			{ value: "e", quoted: false },
			{ value: "g", quoted: false }
		]);
		expect(tokenize("")).toEqual([]);
		expect(tokenize('""')).toEqual([{ value: "", quoted: true }]);
	});

	it("keeps escapes as written, including escaped whitespace, quotes and parentheses", () => {
		expect(tokenize(String.raw`a\ b \( \; "x\"y"`).map((t) => t.value)).toEqual([String.raw`a\ b`, String.raw`\(`, String.raw`\;`, String.raw`x\"y`]);
	});

	it("refuses unterminated quotes, unbalanced parentheses and a trailing backslash", () => {
		expect(code(() => tokenize('"abc'))).toBe("BAD_PRESENTATION");
		expect(code(() => tokenize("( a"))).toBe("BAD_PRESENTATION");
		expect(code(() => tokenize(") a"))).toBe("BAD_PRESENTATION");
		expect(code(() => tokenize("a\\"))).toBe("BAD_PRESENTATION");
		expect(code(() => tokenize('"a\\'))).toBe("BAD_PRESENTATION");
		expect(code(() => tokenize('k="a\\'))).toBe("BAD_PRESENTATION");
		expect(code(() => tokenize('k="a'))).toBe("BAD_PRESENTATION");
		expect(code(() => tokenize(5))).toBe("BAD_PRESENTATION");
	});

	it("joins a key=\"value\" pair into one token", () => {
		expect(tokenize('alpn="h2,h3" port=1')).toEqual([
			{ value: "alpn=h2,h3", quoted: false },
			{ value: "port=1", quoted: false }
		]);
		expect(unescapeBytes(tokenize('k="a b"')[0].value)).toEqual(ascii("k=a b"));
	});

	it("joins a quote after an escaped backslash before = (CLDMV/digby#38)", () => {
		// `x\\=` is a literal backslash, then `=`: the `=` is not escaped, so the quote joins the token
		expect(tokenize('x\\\\="v"')).toEqual([{ value: "x\\\\=v", quoted: false }]);
		expect(unescapeBytes("x\\\\=v")).toEqual(ascii("x\\=v"));
		// a single backslash escapes the `=` itself: no quote may follow
		expect(code(() => tokenize('x\\="v"'))).toBe("BAD_PRESENTATION");
	});
});

describe("RFC 1035 escapes in character-strings", () => {
	it("decodes \\DDD and \\X, and UTF-8 for non-ASCII text", () => {
		expect(unescapeBytes(String.raw`\065\066\\\"x`)).toEqual(ascii('AB\\"x'));
		expect(unescapeBytes("é")).toEqual(Uint8Array.of(0xc3, 0xa9));
		expect(unescapeBytes("\\é")).toEqual(Uint8Array.of(0xc3, 0xa9));
		expect(unescapeBytes("😀")).toEqual(Uint8Array.of(0xf0, 0x9f, 0x98, 0x80));
		expect(unescapeBytes("\\😀")).toEqual(Uint8Array.of(0xf0, 0x9f, 0x98, 0x80));
		expect(code(() => unescapeBytes("\\25"))).toBe("BAD_PRESENTATION");
		expect(code(() => unescapeBytes("\\300"))).toBe("BAD_PRESENTATION");
		expect(code(() => unescapeBytes("a\\"))).toBe("BAD_PRESENTATION");
	});

	it("refuses lone surrogates (CLDMV/digby#38)", () => {
		expect(code(() => unescapeBytes("\uD800"))).toBe("BAD_PRESENTATION");
		expect(code(() => unescapeBytes("a\uD800b"))).toBe("BAD_PRESENTATION");
		expect(code(() => unescapeBytes("\uDFFF"))).toBe("BAD_PRESENTATION");
		expect(code(() => unescapeBytes("\\\uD800"))).toBe("BAD_PRESENTATION"); // an escape whose character is a lone surrogate
	});
});

describe("mnemonics", () => {
	it("maps types and classes both ways, with RFC 3597 TYPEnnn / CLASSnnn", () => {
		expect(typeFromString("aaaa")).toBe(TYPE.AAAA);
		expect(typeFromString("TYPE28")).toBe(28);
		expect(typeFromString("type65535")).toBe(65535);
		expect(typeToString(28)).toBe("AAAA");
		expect(typeToString(4000)).toBe("TYPE4000");
		expect(code(() => typeFromString("TYPE65536"))).toBe("UNKNOWN_MNEMONIC");
		expect(code(() => typeFromString("BOGUS"))).toBe("UNKNOWN_MNEMONIC");
		expect(code(() => typeFromString("toString"))).toBe("UNKNOWN_MNEMONIC");
		expect(classFromString("in")).toBe(CLASS.IN);
		expect(classFromString("CLASS32")).toBe(32);
		expect(classToString(3)).toBe("CH");
		expect(classToString(32)).toBe("CLASS32");
		expect(code(() => classFromString("XX"))).toBe("UNKNOWN_MNEMONIC");
		expect(svcKeyToString(1)).toBe("alpn");
		expect(svcKeyToString(1234)).toBe("key1234");
		expect(svcKeyFromString("key1")).toBe(1);
		// key65535 round-trips with svcKeyToString (CLDMV/digby#39, round 7): the mnemonic layer is permissive like
		// TYPEnnn / CLASSnnn, and the SvcParam record layer refuses the reserved key on decode, encode and parse
		expect(svcKeyFromString("key65535")).toBe(65535);
		expect(svcKeyToString(svcKeyFromString("key65535"))).toBe("key65535");
		expect(svcKeyFromString(svcKeyToString(65535))).toBe(65535);
		expect(code(() => svcKeyFromString("key65536"))).toBe("BAD_SVCPARAM");
	});
});

describe("field formats", () => {
	it("formats IPv6 the RFC 5952 way", () => {
		const f = (s) => formatIPv6(parseIPv6(s));
		expect(f("2001:0db8:0000:0000:0000:0000:0000:0001")).toBe("2001:db8::1");
		expect(f("2001:db8:0:0:1:0:0:1")).toBe("2001:db8::1:0:0:1"); // the first of two equal runs
		expect(f("2001:db8:0:1:1:1:1:1")).toBe("2001:db8:0:1:1:1:1:1"); // a single zero group is not compressed
		expect(f("2001:0:0:1:0:0:0:1")).toBe("2001:0:0:1::1"); // the longest run wins
		expect(f("::")).toBe("::");
		expect(f("::1")).toBe("::1");
		expect(f("1::")).toBe("1::");
		expect(f("ABCD::EF")).toBe("abcd::ef");
	});

	it("base32hex round-trips without padding", () => {
		for (const n of [1, 2, 3, 4, 5, 6, 20]) {
			const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + 11) & 0xff);
			expect(fromBase32Hex(toBase32Hex(b), "x")).toEqual(b);
		}
		expect(toBase32Hex(ascii("f"))).toBe("CO");
		expect(toBase32Hex(ascii("foobar"))).toBe("CPNMUOJ1E8");
		expect(fromBase32Hex("cpnmuoj1e8", "x")).toEqual(ascii("foobar"));
	});
});

describe("records", () => {
	it("parses owner, TTL and class in either order, with defaults", () => {
		expect(parseRecord("www 3600 IN A 192.0.2.1", { origin: "example." })).toEqual({ name: "www.example.", ttl: 3600, class: 1, type: 1, data: { address: "192.0.2.1" } });
		expect(parseRecord("www IN 3600 A 192.0.2.1", { origin: "example." }).ttl).toBe(3600);
		expect(parseRecord("@ A 192.0.2.1", { origin: "example.", ttl: 300 })).toMatchObject({ name: "example.", ttl: 300, class: 1 });
		expect(parseRecord("a. CH 0 TXT x").class).toBe(CLASS.CH);
		expect(parseRecord("a. 1h30m CLASS99 TYPE1234 \\# 1 ff")).toEqual({ name: "a.", ttl: 5400, class: 99, type: 1234, data: { data: hex.from("ff") } });
		expect(code(() => parseRecord("a. A 1.2.3.4"))).toBe("BAD_PRESENTATION");
		expect(code(() => parseRecord("a. 1 IN"))).toBe("BAD_PRESENTATION");
		expect(code(() => parseRecord("a. 1 IN BOGUS x"))).toBe("UNKNOWN_MNEMONIC");
		expect(code(() => parseRecord('"a." 1 IN A 1.2.3.4'))).toBe("BAD_PRESENTATION");
		expect(code(() => parseRecord("a 1 IN A 1.2.3.4"))).toBe("RELATIVE_NAME");
	});

	it("refuses a non-ASCII escape in a record's owner name (CLDMV/digby#38)", () => {
		// the owner name reaches parseName, which truncated \\Ł to A: "ex\\Łmple." parsed as "exAmple."
		expect(code(() => parseRecord("ex\\Łmple. 60 IN A 192.0.2.1"))).toBe("BAD_PRESENTATION");
	});

	it("parses multi-line records with comments", () => {
		const text = `example. 86400 IN SOA ns.example. hostmaster.example. (
			2026112101 ; serial
			7200       ; refresh
			3600       ; retry
			1209600    ; expire
			300 )      ; minimum`;
		expect(parseRecord(text).data).toEqual({ mname: "ns.example.", rname: "hostmaster.example.", serial: 2026112101, refresh: 7200, retry: 3600, expire: 1209600, minimum: 300 });
	});

	it("parses TTLs", () => {
		expect(parseTtl("0")).toBe(0);
		expect(parseTtl("1W2d3H4m5S")).toBe(604800 + 2 * 86400 + 3 * 3600 + 4 * 60 + 5);
		expect(parseTtl("2147483647")).toBe(2147483647);
		expect(code(() => parseTtl("2147483648"))).toBe("BAD_PRESENTATION");
		expect(code(() => parseTtl("1y"))).toBe("BAD_PRESENTATION");
		expect(code(() => parseTtl("h"))).toBe("BAD_PRESENTATION");
	});

	it("formats one canonical line", () => {
		expect(formatRecord({ name: "Www.Example.", ttl: 60, class: 1, type: 28, data: { address: "2001:db8::1" } })).toBe("Www.Example. 60 IN AAAA 2001:db8::1");
		expect(formatRecord({ name: "a.", ttl: 0, type: 999, data: { data: new Uint8Array(0) } })).toBe("a. 0 IN TYPE999 \\# 0");
		expect(formatRecord({ name: "a.", ttl: 0, class: 255, type: 1, data: null })).toBe("a. 0 ANY A");
		expect(formatRecord({ name: "x\\ y.", ttl: 1, class: 1, type: 16, data: { strings: [ascii('say "hi"')] } })).toBe('x\\032y. 1 IN TXT "say \\"hi\\""');
	});

	it("parses what it formats", () => {
		const recs = [
			{ name: "a\\.b.example.", ttl: 1, class: 1, type: 16, data: { strings: [Uint8Array.of(0, 34, 92, 255, 32)] } },
			{ name: "\\(paren\\).example.", ttl: 2, class: 1, type: 15, data: { preference: 1, exchange: "\\;semi.example." } },
			{ name: "example.", ttl: 3, class: 1, type: 257, data: { flags: 0, tag: "iodef", value: ascii('mailto:"x"@example.') } }
		];
		for (const r of recs) expect(parseRecord(formatRecord(r))).toEqual(r);
	});

	it("refuses record type 0: reserved like 65535, as the wire's record layer refuses it (CLDMV/digby#38)", () => {
		// both would otherwise carry a TYPE0 record through parse and format — the generic zero-length form even parses
		expect(code(() => parseRecord("a.example. 0 IN TYPE0 \\# 0"))).toBe("BAD_PRESENTATION");
		expect(code(() => parseRecord("a.example. 0 ANY TYPE0 \\# 0"))).toBe("BAD_PRESENTATION");
		expect(code(() => formatRecord({ name: "a.", ttl: 0, type: 0, data: { data: new Uint8Array(0) } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: 0, class: 255, type: 0, data: null }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("parses the RFC 2136 update form: class ANY or NONE with no rdata text is data: null (CLDMV/digby#37)", () => {
		expect(parseRecord("a.example. 0 ANY A")).toEqual({ name: "a.example.", ttl: 0, class: CLASS.ANY, type: 1, data: null });
		expect(parseRecord("a.example. 0 NONE A")).toEqual({ name: "a.example.", ttl: 0, class: CLASS.NONE, type: 1, data: null });
		// the generic zero-length form is the update form too, the way the wire reader maps rdlength 0 under ANY / NONE
		expect(parseRecord("a.example. 0 ANY TYPE999 \\# 0")).toEqual({ name: "a.example.", ttl: 0, class: CLASS.ANY, type: 999, data: null });
		expect(parseRecord("a.example. 0 NONE TYPE999 \\# 0")).toEqual({ name: "a.example.", ttl: 0, class: CLASS.NONE, type: 999, data: null });
		expect(parseRecord("a.example. 0 ANY ANY \\# 0")).toEqual({ name: "a.example.", ttl: 0, class: CLASS.ANY, type: 255, data: null });
		// every other class with no rdata stays refused, with or without a class token
		expect(code(() => parseRecord("a.example. 0 IN A"))).toBe("BAD_PRESENTATION");
		expect(code(() => parseRecord("a.example. 0 A"))).toBe("BAD_PRESENTATION");
		expect(code(() => parseRecord("a.example. 0 CH A"))).toBe("BAD_PRESENTATION");
		// a type that must carry rdata never takes the update form
		expect(code(() => parseRecord("a.example. 0 ANY TSIG"))).toBe("BAD_PRESENTATION");
		expect(code(() => parseRecord("a.example. 0 NONE TSIG \\# 0"))).toBe("BAD_PRESENTATION");
		// class IN keeps the zero-length generic form as ordinary zero-length octets
		expect(parseRecord("a.example. 0 IN TYPE999 \\# 0")).toEqual({ name: "a.example.", ttl: 0, class: 1, type: 999, data: { data: new Uint8Array(0) } });
		// an update that does carry rdata still parses normally
		expect(parseRecord("a.example. 0 ANY A 1.2.3.4")).toEqual({ name: "a.example.", ttl: 0, class: CLASS.ANY, type: 1, data: { address: "1.2.3.4" } });
		expect(parseRecord("a.example. 0 NONE TYPE999 \\# 4 01020304")).toEqual({ name: "a.example.", ttl: 0, class: CLASS.NONE, type: 999, data: { data: hex.from("01020304") } });
	});
});

describe("formatRecord validates its input (CLDMV/digby#37)", () => {
	it("refuses a TTL that is not a 32-bit integer instead of injecting its text", () => {
		expect(code(() => formatRecord({ name: "a.", ttl: "1 IN A 9.9.9.9 ;", type: 1, data: { address: "1.2.3.4" } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: -1, type: 1, data: { address: "1.2.3.4" } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: 1.5, type: 1, data: { address: "1.2.3.4" } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: 2 ** 32, type: 1, data: { address: "1.2.3.4" } }))).toBe("VALUE_OUT_OF_RANGE");
		// the codec's TTL domain matches encode's (RFC 2181: at most 2^31 - 1; decode maps more to 0)
		expect(code(() => formatRecord({ name: "a.", ttl: 2 ** 31, type: 1, data: { address: "1.2.3.4" } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: null, type: 1, data: { address: "1.2.3.4" } }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("refuses a class or type that is not an integer in range instead of printing CLASSxx / TYPExx text", () => {
		expect(code(() => formatRecord({ name: "a.", ttl: 0, class: "IN", type: 1, data: { address: "1.2.3.4" } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: 0, class: 70000, type: 1, data: { address: "1.2.3.4" } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: 0, type: "A", data: { address: "1.2.3.4" } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: 0, type: 70000, data: { address: "1.2.3.4" } }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("refuses a malformed owner name and malformed rdata with a WireError", () => {
		expect(code(() => formatRecord({ name: "", ttl: 0, type: 1, data: { address: "1.2.3.4" } }))).toBe("BAD_PRESENTATION");
		// no data field at all: formatRdata must refuse it, not print "undefined" or throw a TypeError
		expect(code(() => formatRecord({ name: "a.", ttl: 0, type: 1 }))).toBe("VALUE_OUT_OF_RANGE");
		// a TXT with no strings field and an SVCB with no fields must be a WireError, not a TypeError
		expect(code(() => formatRecord({ name: "a.", ttl: 0, type: 16, data: {} }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: 0, type: 64, data: {} }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("prints empty rdata only for the RFC 2136 update form: class ANY or NONE (CLDMV/digby#37)", () => {
		// the reproducing case: an IN record with no rdata printed as "a. 1 IN A"
		expect(code(() => formatRecord({ name: "a.", ttl: 1, type: 1, data: null }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: 1, class: 1, type: 1, data: null }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: 1, class: 3, type: 1, data: null }))).toBe("VALUE_OUT_OF_RANGE");
		// the update form itself stays allowed
		expect(formatRecord({ name: "a.", ttl: 0, class: 255, type: 1, data: null })).toBe("a. 0 ANY A");
		expect(formatRecord({ name: "a.", ttl: 0, class: 254, type: 1, data: null })).toBe("a. 0 NONE A");
	});

	it("refuses zero-length generic rdata under class ANY or NONE: that is the update form, so give data: null (CLDMV/digby#37)", () => {
		// the line such a value would print (`\# 0`) parses back as data: null, so no line represents it
		expect(code(() => formatRecord({ name: "a.", ttl: 0, class: 255, type: 999, data: { data: new Uint8Array(0) } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: 0, class: 254, type: 999, data: { data: new Uint8Array(0) } }))).toBe("VALUE_OUT_OF_RANGE");
		// class IN keeps it: there `\# 0` is ordinary zero-length octets and re-parses to itself
		expect(formatRecord({ name: "a.", ttl: 0, type: 999, data: { data: new Uint8Array(0) } })).toBe("a. 0 IN TYPE999 \\# 0");
	});

	it("refuses OPT with zero-length rdata under class ANY or NONE: typed on the wire, generic in text (CLDMV/digby#38)", () => {
		// OPT's rdata is `{ options }`; with no options it encodes to zero octets and would print `\# 0`, which parses back
		// as data: null — the same hole the untyped generic form had, which the old shape-only check did not see
		expect(code(() => formatRecord({ name: "x.", ttl: 0, class: 255, type: TYPE.OPT, data: { options: [] } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "x.", ttl: 0, class: 254, type: TYPE.OPT, data: { options: [] } }))).toBe("VALUE_OUT_OF_RANGE");
		// class IN keeps its line: there `\# 0` is ordinary zero-length octets and re-parses to itself
		expect(formatRecord({ name: "x.", ttl: 0, type: TYPE.OPT, data: { options: [] } })).toBe("x. 0 IN OPT \\# 0");
	});

	it("refuses what parseRecord refuses: record type 65535, and empty rdata for a type that must carry rdata (CLDMV/digby#38)", () => {
		// type 65535 is reserved at the record layer, yet formatRecord printed "a. 1 IN TYPE65535 \# 0"
		expect(code(() => formatRecord({ name: "a.", ttl: 1, type: 65535, data: { data: new Uint8Array(0) } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: 1, type: 65535, data: null }))).toBe("VALUE_OUT_OF_RANGE");
		// TSIG is in the empty-rdata-required set, yet formatRecord printed "a. 0 ANY TSIG"
		expect(code(() => formatRecord({ name: "a.", ttl: 0, class: 255, type: 250, data: null }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.", ttl: 0, class: 254, type: 249, data: null }))).toBe("VALUE_OUT_OF_RANGE");
	});
});

describe("formatRecord and parseTtl never stringify caller values (CLDMV/digby#39, round 5)", () => {
	const toStringOne = { toString: 1, valueOf: 1 };
	it("the ttl, class and type refusals describe a cloned hostile value", () => {
		// today: String(snap.ttl) on the cloned { toString: 1 } throws "is not a function" — a TypeError, not a WireError
		expect(code(() => formatRecord({ name: "a.example.", ttl: toStringOne, type: TYPE.A, data: { address: "10.0.0.1" } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.example.", ttl: 60, class: toStringOne, type: TYPE.A, data: { address: "10.0.0.1" } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => formatRecord({ name: "a.example.", ttl: 60, type: toStringOne, data: { address: "10.0.0.1" } }))).toBe("VALUE_OUT_OF_RANGE");
		// today: String(Object.create(null)) throws "Cannot convert object to primitive value"
		expect(code(() => formatRecord({ name: "a.example.", ttl: 60, type: Object.create(null), data: { address: "10.0.0.1" } }))).toBe("VALUE_OUT_OF_RANGE");
	});
	it("parseTtl refuses a non-string before any coercion", () => {
		// today: /^\d+$/.test(symbol) coerces through ToString — a raw TypeError
		expect(code(() => parseTtl(Symbol("nope")))).toBe("BAD_PRESENTATION");
		expect(code(() => parseTtl(toStringOne))).toBe("BAD_PRESENTATION");
	});
});
