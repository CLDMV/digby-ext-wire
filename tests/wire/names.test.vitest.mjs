/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/names.test.vitest.mjs
 */

import { describe, expect, it } from "vitest";
import { Reader, Writer } from "../../src/lib/buffer.mjs";
import { WireError } from "../../src/lib/errors.mjs";
import { canonicalName, labelCount, nameKey, namesEqual, parseName, readName, writeName } from "../../src/lib/names.mjs";
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

const read = (bytes, pos = 0) => {
	const r = new Reader(bytes, pos);
	return { name: readName(r), pos: r.pos };
};

describe("presentation names", () => {
	it("canonicalises escapes, case and the root", () => {
		expect(canonicalName(".")).toBe(".");
		expect(canonicalName("Example.COM.")).toBe("Example.COM.");
		expect(canonicalName("\\065b\\.c.d.")).toBe("Ab\\.c.d.");
		expect(canonicalName("a\\032b.")).toBe("a\\032b.");
		expect(canonicalName("a\\ b.")).toBe("a\\032b.");
		expect(canonicalName("\\(\\)\\;\\@\\$\\\"\\\\.")).toBe('\\(\\)\\;\\@\\$\\"\\\\.');
		expect(canonicalName("\\000\\255.")).toBe("\\000\\255.");
	});

	it("completes relative names and @ against the origin", () => {
		expect(canonicalName("www", "example.com.")).toBe("www.example.com.");
		expect(canonicalName("@", "example.com.")).toBe("example.com.");
		expect(code(() => canonicalName("www"))).toBe("RELATIVE_NAME");
		expect(code(() => canonicalName("@"))).toBe("RELATIVE_NAME");
	});

	it("refuses empty labels, bad escapes and oversize labels and names", () => {
		expect(code(() => parseName("a..b."))).toBe("BAD_PRESENTATION");
		expect(code(() => parseName(".a."))).toBe("BAD_PRESENTATION");
		expect(code(() => parseName("a\\25."))).toBe("BAD_PRESENTATION");
		expect(code(() => parseName("a\\256."))).toBe("BAD_PRESENTATION");
		expect(code(() => parseName("a\\"))).toBe("BAD_PRESENTATION");
		expect(code(() => parseName(""))).toBe("BAD_PRESENTATION");
		expect(code(() => parseName("é."))).toBe("BAD_PRESENTATION");
		expect(code(() => parseName(`${"a".repeat(64)}.`))).toBe("LABEL_TOO_LONG");
		expect(parseName(`${"a".repeat(63)}.`)[0]).toHaveLength(63);
		// 4 x 63-octet labels: 4 * 64 + 1 = 257 octets
		expect(code(() => parseName(`${"a".repeat(63)}.`.repeat(4)))).toBe("NAME_TOO_LONG");
		// 3 x 63 + one 61: 3 * 64 + 62 + 1 = 255 octets, the maximum
		expect(() => parseName(`${"a".repeat(63)}.`.repeat(3) + `${"b".repeat(61)}.`)).not.toThrow();
	});

	it("refuses a non-ASCII unit after a backslash — the octet copy would truncate it (CLDMV/digby#38)", () => {
		// label.push took the UTF-16 unit after the backslash unchecked and Uint8Array.from truncated it:
		// parseName("a\\Ł.") equalled parseName("aA.") and parseName("a\\\uD800.") gave [97, 0]
		expect(parseName("a\\A.")).toEqual(parseName("aA.")); // the printable-ASCII escape still works
		expect(code(() => parseName("a\\Ł."))).toBe("BAD_PRESENTATION");
		expect(code(() => parseName("a\\\uD800."))).toBe("BAD_PRESENTATION");
	});

	it("compares case-insensitively after escape normalisation", () => {
		expect(namesEqual("WWW.Example.com.", "www.example.COM.")).toBe(true);
		expect(namesEqual("\\065.", "a.")).toBe(true);
		expect(namesEqual("a.", "b.")).toBe(false);
		expect(nameKey("A.b.")).toBe(nameKey("a.B."));
		expect(labelCount(".")).toBe(0);
		expect(labelCount("www.example.com.")).toBe(3);
	});
});

describe("wire names", () => {
	it("reads plain names and the root", () => {
		expect(read(hex.from("00"))).toEqual({ name: ".", pos: 1 });
		expect(read(hex.from("03 77 77 77 07 65 78 61 6d 70 6c 65 00"))).toEqual({ name: "www.example.", pos: 13 });
		expect(read(hex.from("01 2e 01 20 00")).name).toBe("\\..\\032.");
	});

	it("follows a backward pointer and leaves the reader after it", () => {
		// RFC 1035 4.1.4: F.ISI.ARPA at 0, FOO.F.ISI.ARPA at 12 as "FOO" + pointer to 0, ARPA as a pointer to 6
		const b = hex.from("01 46 03 49 53 49 04 41 52 50 41 00  03 46 4f 4f c0 00  c0 06");
		expect(read(b, 0)).toEqual({ name: "F.ISI.ARPA.", pos: 12 });
		expect(read(b, 12)).toEqual({ name: "FOO.F.ISI.ARPA.", pos: 18 });
		expect(read(b, 18)).toEqual({ name: "ARPA.", pos: 20 });
	});

	it("refuses a pointer to itself (the shortest loop)", () => {
		expect(code(() => read(hex.from("c0 00")))).toBe("POINTER_FORWARD");
	});

	it("refuses a two-pointer loop", () => {
		// at 0: label "a" then pointer to 3; at 3: pointer to 0 (backwards, but to the segment it came from)
		expect(code(() => read(hex.from("01 61 c0 03 c0 00"), 4))).toBe("POINTER_FORWARD");
		expect(code(() => read(hex.from("01 61 c0 00")))).toBe("POINTER_FORWARD");
	});

	it("refuses a forward pointer", () => {
		expect(code(() => read(hex.from("c0 02 00")))).toBe("POINTER_FORWARD");
	});

	it("refuses a pointer past the end of the message", () => {
		expect(code(() => read(hex.from("00 c0 10"), 1))).toBe("POINTER_OUT_OF_RANGE");
		expect(code(() => read(hex.from("00 ff ff"), 1))).toBe("POINTER_OUT_OF_RANGE");
	});

	it("refuses the extended and reserved label types", () => {
		expect(code(() => read(hex.from("41 00")))).toBe("BAD_LABEL_TYPE");
		expect(code(() => read(hex.from("80 00")))).toBe("BAD_LABEL_TYPE");
	});

	it("refuses a name over 255 octets, also when assembled from pointers", () => {
		const label = (n) => [n, ...new Array(n).fill(0x61)];
		// a 255-octet name is fine
		const ok = Uint8Array.from([...label(63), ...label(63), ...label(63), ...label(61), 0]);
		expect(read(ok).pos).toBe(255);
		const long = Uint8Array.from([...label(63), ...label(63), ...label(63), ...label(62), 0]);
		expect(code(() => read(long))).toBe("NAME_TOO_LONG");
		// 200 octets at 0, then at 201 a 60-octet label pointing back at it: 261 octets in all
		const base = Uint8Array.from([...label(63), ...label(63), ...label(63), ...label(7), 0]);
		const viaPointer = Uint8Array.from([...base, ...label(60), 0xc0, 0x00]);
		expect(code(() => read(viaPointer, base.length))).toBe("NAME_TOO_LONG");
	});

	it("refuses a name cut short", () => {
		expect(code(() => read(hex.from("03 77 77")))).toBe("TRUNCATED");
		expect(code(() => read(hex.from("03 77 77 77")))).toBe("TRUNCATED");
		expect(code(() => read(hex.from("c0")))).toBe("TRUNCATED");
		expect(code(() => read(new Uint8Array(0)))).toBe("TRUNCATED");
	});

	it("stops at the reader's end before a pointer", () => {
		const r = new Reader(hex.from("03 61 62 63 00"), 0, 3);
		expect(code(() => readName(r))).toBe("TRUNCATED");
	});

	it("caps pointer hops", () => {
		// a chain of 200 pointers, each to the one before it; the first points to a root label at 0
		const bytes = [0x00, 0xc0, 0x00];
		for (let i = 1; i < 200; i++) {
			const target = 1 + (i - 1) * 2;
			bytes.push(0xc0 | (target >> 8), target & 0xff);
		}
		const b = Uint8Array.from(bytes);
		expect(read(b, 1 + 100 * 2).name).toBe(".");
		expect(code(() => read(b, 1 + 199 * 2))).toBe("POINTER_LIMIT");
	});
});

describe("name compression on encode", () => {
	const encode = (names, compress = true) => {
		const w = new Writer();
		for (const n of names) writeName(w, n, compress);
		return hex.to(w.finish());
	};

	it("points at the longest suffix already written", () => {
		expect(encode(["F.ISI.ARPA.", "FOO.F.ISI.ARPA.", "ARPA."])).toBe("0146034953490441525041000346 4f4fc000c006".replace(/ /g, ""));
	});

	it("matches octet-exactly, so the case of what was given survives", () => {
		expect(encode(["a.b.", "A.b."])).toBe("0161016200" + "0141c002");
	});

	it("writes names in full when compression is off for that name, but still registers them", () => {
		expect(encode(["a.b.", "a.b."], false)).toBe("0161016200".repeat(2));
		const w = new Writer();
		writeName(w, "x.b.", false);
		writeName(w, "y.b.", true);
		expect(hex.to(w.finish())).toBe("0178016200" + "0179c002");
	});

	it("never writes a pointer to an offset beyond 0x3fff", () => {
		const w = new Writer();
		w.raw(new Uint8Array(0x4000));
		writeName(w, "far.example.", true);
		writeName(w, "far.example.", true);
		const out = w.finish();
		// the second copy is written in full: no target was registered past 0x3fff
		expect(out.length).toBe(0x4000 + 13 * 2);
	});

	it("rolls back compression targets with the bytes", () => {
		const w = new Writer();
		writeName(w, "a.", true);
		const mark = w.checkpoint();
		writeName(w, "b.a.", true);
		w.rollback(mark);
		writeName(w, "c.b.a.", true);
		// "b.a." was rolled back, so only "a." (at 0) is a target
		expect(hex.to(w.finish())).toBe("016100" + "0163" + "0162" + "c000");
	});

	it("round-trips through the reader", () => {
		const names = ["example.com.", "www.example.com.", "mail.example.com.", "com.", ".", "Other.ORG."];
		const w = new Writer();
		for (const n of names) writeName(w, n, true);
		const r = new Reader(w.finish());
		expect(names.map(() => readName(r))).toEqual(names);
		expect(r.remaining).toBe(0);
	});
});
