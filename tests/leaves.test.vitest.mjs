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
import domainParse from "../src/api/wire/domain/parse.mjs";
import domainFormat from "../src/api/wire/domain/format.mjs";
import domainCanonical from "../src/api/wire/domain/canonical.mjs";
import domainKey from "../src/api/wire/domain/key.mjs";
import domainEqual from "../src/api/wire/domain/equal.mjs";
import domainCount from "../src/api/wire/domain/count.mjs";
import ttlParse from "../src/api/wire/ttl/parse.mjs";
import rdataParse from "../src/api/wire/rdata/parse.mjs";
import rdataFormat from "../src/api/wire/rdata/format.mjs";
import rdataEncode from "../src/api/wire/rdata/encode.mjs";
import rdataDecode from "../src/api/wire/rdata/decode.mjs";
import rdataGeneric from "../src/api/wire/rdata/generic.mjs";
import typeMnemonic from "../src/api/wire/type/mnemonic.mjs";
import typeParse from "../src/api/wire/type/parse.mjs";
import classMnemonic from "../src/api/wire/class/mnemonic.mjs";
import classParse from "../src/api/wire/class/parse.mjs";
import TYPELeaf from "../src/api/wire/constants/type.mjs";
import CLASSLeaf from "../src/api/wire/constants/class.mjs";
import RCODELeaf from "../src/api/wire/constants/rcode.mjs";
import WireErrorLeaf from "../src/api/wire/errors/WireError.mjs";
import codesLeaf from "../src/api/wire/errors/codes.mjs";
import tsigAppend from "../src/api/wire/tsig/append.mjs";
import tsigSize from "../src/api/wire/tsig/size.mjs";
import transportEncode from "../src/api/wire/transport/encode.mjs";
import transportLimit from "../src/api/wire/transport/limit.mjs";
import udpMin from "../src/api/wire/transport/udp/min.mjs";
import udpCap from "../src/api/wire/transport/udp/cap.mjs";
import tcpFrame from "../src/api/wire/tcp/frame.mjs";
import tcpMax from "../src/api/wire/tcp/max.mjs";
import opcodeLeaf from "../src/api/wire/constants/opcode.mjs";
import ednsOptionLeaf from "../src/api/wire/constants/edns/option.mjs";
import svcKeyLeaf from "../src/api/wire/constants/svc/key.mjs";
import maxMessageLeaf from "../src/api/wire/limits/message.mjs";
import maxLabelLeaf from "../src/api/wire/limits/label.mjs";
import maxNameLeaf from "../src/api/wire/limits/name.mjs";
import maxNameOctetsLeaf from "../src/api/wire/limits/name/octets.mjs";
import * as root from "../src/api/wire/wire.mjs";

// The codec modules the leaves re-export:
import { decodeMessage, encodeMessage, encodeCapped as libEncodeCapped, appendTsig, tsigRecordSize } from "../src/lib/message.mjs";
import { parseRecord, formatRecord, parseTtl } from "../src/lib/presentation.mjs";
import { parseName, formatName, canonicalName, nameKey as libNameKey, namesEqual, labelCount, MAX_LABEL, MAX_NAME, MAX_NAME_OCTETS } from "../src/lib/names.mjs";
import { parseRdata, formatRdata, encodeRdataBytes, decodeRdataBytes } from "../src/lib/rdata/index.mjs";
import { typeToString, typeFromString, classToString, classFromString, TYPE, CLASS, RCODE, OPCODE, EDNS_OPTION, SVC_KEY } from "../src/lib/constants.mjs";
import { WireError, WireErrorCode } from "../src/lib/errors.mjs";
import { TcpFramer, DEFAULT_UDP_CAP, TCP_MAX, UDP_MIN, encodeForTransport, frameTcp, udpLimit } from "../src/lib/limits.mjs";
import { MAX_MESSAGE } from "../src/lib/buffer.mjs";
import { formatGeneric } from "../src/lib/rdata/index.mjs";

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

	it("the domain leaves", () => {
		expect(domainParse).toBe(parseName);
		expect(domainFormat).toBe(formatName);
		expect(domainCanonical).toBe(canonicalName);
		expect(domainKey).toBe(libNameKey);
		expect(domainEqual).toBe(namesEqual);
		expect(domainCount).toBe(labelCount);
	});

	it("the rdata leaves", () => {
		expect(rdataParse).toBe(parseRdata);
		expect(rdataFormat).toBe(formatRdata);
		expect(rdataEncode).toBe(encodeRdataBytes);
		expect(rdataDecode).toBe(decodeRdataBytes);
	});

	it("the mnemonic leaves", () => {
		expect(typeMnemonic).toBe(typeToString);
		expect(classMnemonic).toBe(classToString);
	});

	it("the mnemonic parse leaves", () => {
		expect(typeParse).toBe(typeFromString);
		expect(classParse).toBe(classFromString);
	});

	it("the generic rdata leaf", () => {
		expect(rdataGeneric).toBe(formatGeneric);
	});

	it("the transport and tcp leaves", () => {
		expect(transportEncode).toBe(encodeForTransport);
		expect(transportLimit).toBe(udpLimit);
		expect(tcpFrame).toBe(frameTcp);
	});

	it("the data leaves answer the frozen tables and constants", () => {
		expect(opcodeLeaf()).toBe(OPCODE);
		expect(ednsOptionLeaf()).toBe(EDNS_OPTION);
		expect(svcKeyLeaf()).toBe(SVC_KEY);
		expect(maxMessageLeaf()).toBe(MAX_MESSAGE);
		expect(maxLabelLeaf()).toBe(MAX_LABEL);
		expect(maxNameLeaf()).toBe(MAX_NAME);
		expect(maxNameOctetsLeaf()).toBe(MAX_NAME_OCTETS);
		expect(udpMin()).toBe(UDP_MIN);
		expect(udpCap()).toBe(DEFAULT_UDP_CAP);
		expect(tcpMax()).toBe(TCP_MAX);
	});

	it("the constants leaves answer the frozen tables (A1: data as zero-arg leaf functions)", () => {
		expect(TYPELeaf()).toBe(TYPE);
		expect(CLASSLeaf()).toBe(CLASS);
		expect(RCODELeaf()).toBe(RCODE);
	});

	it("the error leaves are the class and its frozen code table", () => {
		expect(WireErrorLeaf).toBe(WireError);
		expect(codesLeaf()).toBe(WireErrorCode);
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
		for (const leaf of [decode, encode, encodeCapped, createFramer, recordParse, recordFormat, domainParse, domainFormat, domainCanonical, domainKey, domainEqual, domainCount, ttlParse, rdataParse, rdataFormat, rdataEncode, rdataDecode, rdataGeneric, typeMnemonic, typeParse, classMnemonic, classParse, TYPELeaf, CLASSLeaf, RCODELeaf, opcodeLeaf, ednsOptionLeaf, svcKeyLeaf, maxMessageLeaf, maxLabelLeaf, maxNameLeaf, maxNameOctetsLeaf, udpMin, udpCap, tcpFrame, tcpMax, transportEncode, transportLimit, WireErrorLeaf, codesLeaf, tsigAppend, tsigSize]) {
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
