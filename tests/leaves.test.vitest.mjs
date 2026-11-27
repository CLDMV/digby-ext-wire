/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /tests/leaves.test.vitest.mjs
 *	@Date: 2026-11-26T00:00:00-08:00
 *	@Author: Nate Corcoran <CLDMV>
 *	@Email: <Shinrai@users.noreply.github.com>
 *	-----
 *	@Last modified by: Nate Corcoran <CLDMV> (Shinrai@users.noreply.github.com)
 *	@Last modified time: 2026-11-26T00:00:00-08:00
 *	-----
 *	@Copyright: Copyright (c) 2013-2026 Catalyzed Motivation Inc. All rights reserved.
 *
 */

/**
 * @fileoverview The api leaves' suite: every leaf under src/api/wire/ is the SAME value the codec module exports —
 * the ext-host composes the leaves onto self.wire.* and callers must never see a wrapper where the codec's function
 * (or frozen table, or error class) belongs. Plus the one factory: framer.create() hands out a working TcpFramer per
 * stream. The leaves import their lib modules directly (relative paths, as slothlet composes them); no other extension
 * is involved.
 */

import { describe, expect, it } from "vitest";

// The leaves, at their api paths:
import decode from "../src/api/wire/decode.mjs";
import encode from "../src/api/wire/encode.mjs";
import encodeCapped from "../src/api/wire/encodeCapped.mjs";
import createFramer from "../src/api/wire/framer/create.mjs";
import recordParse from "../src/api/wire/record/parse.mjs";
import recordFormat from "../src/api/wire/record/format.mjs";
import nameParse from "../src/api/wire/name/parse.mjs";
import nameFormat from "../src/api/wire/name/format.mjs";
import nameCanonical from "../src/api/wire/name/canonical.mjs";
import nameKey from "../src/api/wire/name/key.mjs";
import ttlParse from "../src/api/wire/ttl/parse.mjs";
import rdataParse from "../src/api/wire/rdata/parse.mjs";
import rdataFormat from "../src/api/wire/rdata/format.mjs";
import rdataEncode from "../src/api/wire/rdata/encode.mjs";
import rdataDecode from "../src/api/wire/rdata/decode.mjs";
import typeName from "../src/api/wire/type/name.mjs";
import className from "../src/api/wire/class/name.mjs";
import TYPELeaf from "../src/api/wire/constants/TYPE.mjs";
import CLASSLeaf from "../src/api/wire/constants/CLASS.mjs";
import RCODELeaf from "../src/api/wire/constants/RCODE.mjs";
import WireErrorLeaf from "../src/api/wire/errors/WireError.mjs";
import codesLeaf from "../src/api/wire/errors/codes.mjs";
import tsigAppend from "../src/api/wire/tsig/append.mjs";
import tsigSize from "../src/api/wire/tsig/size.mjs";
import * as root from "../src/api/wire/wire.mjs";

// The codec modules the leaves re-export:
import { decodeMessage, encodeMessage, encodeCapped as libEncodeCapped, appendTsig, tsigRecordSize } from "../src/lib/message.mjs";
import { parseRecord, formatRecord, parseTtl } from "../src/lib/presentation.mjs";
import { parseName, formatName, canonicalName, nameKey as libNameKey } from "../src/lib/names.mjs";
import { parseRdata, formatRdata, encodeRdataBytes, decodeRdataBytes } from "../src/lib/rdata/index.mjs";
import { typeToString, classToString, TYPE, CLASS, RCODE } from "../src/lib/constants.mjs";
import { WireError, WireErrorCode } from "../src/lib/errors.mjs";
import { TcpFramer, frameTcp } from "../src/lib/limits.mjs";

/** A minimal well-formed message, enough for encodeMessage + the framer below. */
const MESSAGE = {
	id: 0x1234,
	qr: 0,
	opcode: 0,
	rcode: 0,
	questions: [{ name: "example.", type: 1, class: 1 }],
	answers: [],
	authority: [],
	additional: []
};

describe("the leaves are the codec's own exports — identity, not wrappers", () => {
	it("the message codec leaves", () => {
		expect(decode).toBe(decodeMessage);
		expect(encode).toBe(encodeMessage);
		expect(encodeCapped).toBe(libEncodeCapped);
	});

	it("the presentation leaves", () => {
		expect(recordParse).toBe(parseRecord);
		expect(recordFormat).toBe(formatRecord);
		expect(ttlParse).toBe(parseTtl);
	});

	it("the name leaves", () => {
		expect(nameParse).toBe(parseName);
		expect(nameFormat).toBe(formatName);
		expect(nameCanonical).toBe(canonicalName);
		expect(nameKey).toBe(libNameKey);
	});

	it("the rdata leaves", () => {
		expect(rdataParse).toBe(parseRdata);
		expect(rdataFormat).toBe(formatRdata);
		expect(rdataEncode).toBe(encodeRdataBytes);
		expect(rdataDecode).toBe(decodeRdataBytes);
	});

	it("the mnemonic leaves", () => {
		expect(typeName).toBe(typeToString);
		expect(className).toBe(classToString);
	});

	it("the constants leaves are the frozen tables", () => {
		expect(TYPELeaf).toBe(TYPE);
		expect(CLASSLeaf).toBe(CLASS);
		expect(RCODELeaf).toBe(RCODE);
	});

	it("the error leaves are the class and its frozen code table", () => {
		expect(WireErrorLeaf).toBe(WireError);
		expect(codesLeaf).toBe(WireErrorCode);
	});
});

describe("framer.create()", () => {
	it("hands out a fresh TcpFramer per call — instances are not shared", () => {
		const a = createFramer();
		const b = createFramer();
		expect(a).toBeInstanceOf(TcpFramer);
		expect(b).toBeInstanceOf(TcpFramer);
		expect(a).not.toBe(b);
		expect(a.prefix.length).toBe(0);
		expect(b.prefix.length).toBe(0);
	});

	it("the factory's framer frames and reassembles a real message", () => {
		const bytes = encodeMessage(MESSAGE);
		const framer = createFramer();
		const [first] = framer.push(frameTcp(bytes));
		expect(first).toEqual(bytes);
		// And it round-trips through the same codec the leaves expose:
		expect(decode(first).questions[0].name).toBe("example.");
	});

	it("the framer survives a split length prefix — the state the factory exists for", () => {
		const bytes = encodeMessage(MESSAGE);
		const framed = frameTcp(bytes);
		const framer = createFramer();
		// One octet now, the rest next push: the framer holds the partial prefix.
		expect(framer.push(framed.subarray(0, 1))).toEqual([]);
		expect(framer.push(framed.subarray(1))).toEqual([bytes]);
	});
});

describe("the root leaf", () => {
	it("is the wire root: named, activate-able, no state to capture", () => {
		expect(root.name).toBe("wire");
		expect(typeof root.activate).toBe("function");
		expect(typeof root.deactivate).toBe("function");
		// A no-op activate: the codec owns nothing disposable.
		expect(() => root.activate({})).not.toThrow();
		expect(() => root.deactivate()).not.toThrow();
	});
});

describe("the composed surface covers the codec's public entry points", () => {
	it("every exported leaf is defined — none silently missing", () => {
		for (const leaf of [decode, encode, encodeCapped, createFramer, recordParse, recordFormat, nameParse, nameFormat, nameCanonical, nameKey, ttlParse, rdataParse, rdataFormat, rdataEncode, rdataDecode, typeName, className, TYPELeaf, CLASSLeaf, RCODELeaf, WireErrorLeaf, codesLeaf, tsigAppend, tsigSize]) {
			expect(leaf).toBeDefined();
		}
	});

	it("the TSIG leaves — tsig.append and tsig.size, composed per the orchestrator's order (20261127T195149Z)", () => {
		// the TSIG helpers joined the leaf set as nested leaves (`tsig.append` / `tsig.size` — multi-word names
		// become nested paths per the slothlet naming rule); the identity pins hold: the leaves ARE the lib exports
		expect(tsigAppend).toBe(appendTsig);
		expect(tsigSize).toBe(tsigRecordSize);
	});
});
