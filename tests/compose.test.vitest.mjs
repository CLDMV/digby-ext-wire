/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /tests/compose.test.vitest.mjs
 *	@Date: 2026-11-27T00:00:00-08:00
 *	@Author: Nate Corcoran <CLDMV>
 *	@Email: <Shinrai@users.noreply.github.com>
 *	-----
 *	@Last modified by: Nate Corcoran <CLDMV> (Shinrai@users.noreply.github.com)
 *	@Last modified time: 2026-11-27T00:00:00-08:00
 *	-----
 *	@Copyright: Copyright (c) 2013-2026 Catalyzed Motivation Inc. All rights reserved.
 *
 */

/**
 * @fileoverview The composed-surface suite: the REAL src/api tree through slothlet itself, in the three shapes that
 * matter — eager {@link slothlet} composition, the rummage-style `api.slothlet.api.add` mount (the ext-host composes
 * eagerly, api-tree.mjs), and lazy. The leaves test imports the leaf files directly, which composes nothing; this
 * suite is what proves the tree survives composition (a Function.prototype-name leaf such as `name` crashes eager
 * compose with `TypeError: Cannot use 'in' operator …`), that every leaf is present under the path the api names, and
 * that every leaf is callable. Slothlet resolves the module exports' own answers, not the file import — the leaves
 * test's identity pins do not transfer here, so every leaf is called and its result compared with the codec's own
 * function on the same input.
 *
 * Plus the two data findings this surface must answer (CLDMV/digby#42 review):
 * - the frozen tables (constants, error codes, limits) are plain data through the composed api — leaf functions
 *   returning the frozen table (CLDMV/slothlet docs, API-RULES Rule 5: an object default export composes as a
 *   namespace wrapper, so a table leaf is a zero-arg function and callers call it);
 * - the manifest's `public` list publishes the composed surface (rummage's default-deny policy refuses every
 *   cross-extension call an extension does not declare — extension-host.md), proven by a second, minimal extension
 *   composed alongside wire under the same rules rummage derives.
 */

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";

// Slothlet resolves through rummage's own dependency (the review-proven pod path: wire does not depend on slothlet
// directly — its ext-host does — so the specifier would not resolve from this package).
const wireReq = createRequire(import.meta.url);
const rummageReq = createRequire(wireReq.resolve("@cldmv/rummage/package.json"));
const slothlet = (await import(rummageReq.resolve("@cldmv/slothlet"))).default;

// The codec modules the leaves re-export — the comparison oracle:
import { appendTsig, decodeMessage, encodeCapped, encodeMessage, tsigRecordSize } from "../src/lib/message.mjs";
import { parseRecord, formatRecord, parseTtl } from "../src/lib/presentation.mjs";
import { MAX_LABEL, MAX_NAME, MAX_NAME_OCTETS, canonicalName, formatName, labelCount, nameKey, namesEqual, parseName } from "../src/lib/names.mjs";
import { decodeRdataBytes, encodeRdataBytes, formatGeneric, formatRdata, parseRdata } from "../src/lib/rdata/index.mjs";
import { CLASS, EDNS_OPTION, OPCODE, RCODE, SVC_KEY, TYPE, classFromString, classToString, typeFromString, typeToString } from "../src/lib/constants.mjs";
import { WireError, WireErrorCode } from "../src/lib/errors.mjs";
import { DEFAULT_UDP_CAP, TCP_MAX, UDP_MIN, encodeForTransport, frameTcp, udpLimit } from "../src/lib/limits.mjs";
import { MAX_MESSAGE } from "../src/lib/buffer.mjs";
import manifest from "../rummage.manifest.mjs";

const API_DIR = fileURLToPath(new URL("../src/api/wire/", import.meta.url));
const API_BASE = fileURLToPath(new URL("../src/api/", import.meta.url));

/** Resolve a dotted api path, `undefined` when a segment is missing. */
const at = (node, p) => p.split(".").reduce((v, s) => (v == null ? v : v[s]), node);

/**
 * The composed surface: every leaf path under the mount, with the kind a caller must see. The data leaves are
 * FUNCTIONS (calling returns the frozen table or constant) — see the fileoverview.
 * @type {Array<[string, "function"]>}
 */
const SURFACE = [
	["decode", "function"],
	["encode", "function"],
	["encodeCapped", "function"],
	["framer.create", "function"],
	["record.parse", "function"],
	["record.format", "function"],
	["ttl.parse", "function"],
	["rdata.parse", "function"],
	["rdata.format", "function"],
	["rdata.encode", "function"],
	["rdata.decode", "function"],
	["rdata.generic", "function"],
	["domain.parse", "function"],
	["domain.format", "function"],
	["domain.canonical", "function"],
	["domain.key", "function"],
	["domain.equal", "function"],
	["domain.count", "function"],
	["type.mnemonic", "function"],
	["type.parse", "function"],
	["class.mnemonic", "function"],
	["class.parse", "function"],
	["tsig.append", "function"],
	["tsig.size", "function"],
	["transport.encode", "function"],
	["transport.limit", "function"],
	["transport.udp.min", "function"],
	["transport.udp.cap", "function"],
	["tcp.frame", "function"],
	["tcp.max", "function"],
	["constants.type", "function"],
	["constants.class", "function"],
	["constants.rcode", "function"],
	["constants.opcode", "function"],
	["constants.edns.option", "function"],
	["constants.svc.key", "function"],
	["limits.message", "function"],
	["limits.label", "function"],
	["limits.name", "function"],
	["limits.name.octets", "function"],
	["errors.WireError", "function"],
	["errors.codes", "function"]
];

/** One well-formed one-question message — every leaf's valid input comes from it. */
const MESSAGE = {
	id: 0x1234,
	flags: { qr: true },
	rcode: 0,
	questions: [{ name: "example.", type: TYPE.A, class: 1 }],
	answers: [],
	authorities: [],
	additionals: []
};
const BYTES = encodeMessage(MESSAGE);
const RECORD = parseRecord("ns.example. 60 IN A 10.0.0.1");
const TSIG = {
	name: "key.example.",
	type: TYPE.TSIG,
	class: CLASS.ANY,
	ttl: 0,
	data: { algorithm: "hmac-sha256.", timeSigned: 1, fudge: 300, mac: new Uint8Array(32), originalId: 0x1234, error: 0, otherData: new Uint8Array(0) }
};

/**
 * Call every leaf and compare each result with the codec's own function on the same input. This is the part the
 * leaves test cannot do: it proves the composed value BEHAVES like the codec's export, not merely that a file
 * exports something.
 * @param {object} wire - the composed wire node
 */
const callEveryLeaf = (wire) => {
	// message codec
	expect(wire.decode(BYTES)).toEqual(decodeMessage(BYTES));
	expect(wire.encode(MESSAGE)).toEqual(encodeMessage(MESSAGE));
	expect(wire.encodeCapped(MESSAGE, { limit: 4096 })).toEqual(encodeCapped(MESSAGE, { limit: 4096 }));
	// framer (a composed instance is a separate module copy — the leaves test pins instanceof, this suite pins behavior)
	const framer = wire.framer.create();
	expect(framer.push(frameTcp(BYTES))).toEqual([BYTES]);
	expect(wire.framer.create()).not.toBe(framer);
	// records, ttl, rdata
	expect(wire.record.parse("ns.example. 60 IN A 10.0.0.1")).toEqual(parseRecord("ns.example. 60 IN A 10.0.0.1"));
	expect(wire.record.format(RECORD)).toEqual(formatRecord(RECORD));
	expect(wire.ttl.parse("1h")).toEqual(parseTtl("1h"));
	expect(wire.rdata.parse(TYPE.A, "10.0.0.1", "example.")).toEqual(parseRdata(TYPE.A, "10.0.0.1", "example."));
	expect(wire.rdata.format(TYPE.A, RECORD.data)).toEqual(formatRdata(TYPE.A, RECORD.data));
	expect(wire.rdata.encode(TYPE.A, RECORD.data)).toEqual(encodeRdataBytes(TYPE.A, RECORD.data));
	expect(wire.rdata.decode(TYPE.A, encodeRdataBytes(TYPE.A, RECORD.data))).toEqual(decodeRdataBytes(TYPE.A, encodeRdataBytes(TYPE.A, RECORD.data)));
	expect(wire.rdata.generic(new Uint8Array([1, 2, 3]))).toEqual(formatGeneric(new Uint8Array([1, 2, 3])));
	// names
	expect(wire.domain.parse("a.example.")).toEqual(parseName("a.example."));
	expect(wire.domain.format(parseName("a.example."))).toEqual(formatName(parseName("a.example.")));
	expect(wire.domain.canonical("Example.")).toEqual(canonicalName("Example."));
	expect(wire.domain.key("a.example.")).toEqual(nameKey("a.example."));
	expect(wire.domain.equal("A.example.", "a.example.")).toBe(namesEqual("A.example.", "a.example."));
	expect(wire.domain.count("a.b.c.")).toBe(labelCount("a.b.c."));
	// mnemonics
	expect(wire.type.mnemonic(TYPE.A)).toBe(typeToString(TYPE.A));
	expect(wire.type.parse("A")).toBe(typeFromString("A"));
	expect(wire.class.mnemonic(1)).toBe(classToString(1));
	expect(wire.class.parse("IN")).toBe(classFromString("IN"));
	// tsig
	const need = wire.tsig.size(TSIG);
	expect(need).toBe(tsigRecordSize(TSIG));
	const capped = wire.encodeCapped(MESSAGE, { limit: 280, reserveTsig: need });
	const signed = wire.tsig.append(capped, TSIG);
	expect(signed.length).toBe(capped.bytes.length + need);
	// transport
	expect(wire.transport.limit({ edns: { udpSize: 4096 } }, { cap: 4096 })).toBe(udpLimit({ edns: { udpSize: 4096 } }, { cap: 4096 }));
	expect(wire.transport.encode(MESSAGE, { transport: "udp" }).bytes).toEqual(encodeForTransport(MESSAGE, { transport: "udp" }).bytes);
	expect(wire.tcp.frame(BYTES)).toEqual(frameTcp(BYTES));
	// the data leaves: plain data through the composed api (CLDMV/digby#42 A1) — each returns the codec's own
	// frozen table or constant. A composed module is a separate module copy (slothlet loads leaves
	// instance-scoped), so the tables compare by value and frozen-ness, not by reference with this module's import
	const table = ([path, value]) => {
		const got = at(wire, path)();
		expect(got, `wire.${path}() should be the codec's table`).toEqual(value);
		expect(Object.isFrozen(got), `wire.${path}() should be frozen`).toBe(true);
	};
	for (const [p, v] of [["constants.type", TYPE], ["constants.class", CLASS], ["constants.rcode", RCODE], ["constants.opcode", OPCODE], ["constants.edns.option", EDNS_OPTION], ["constants.svc.key", SVC_KEY], ["errors.codes", WireErrorCode]]) table([p, v]);
	expect(wire.limits.message()).toBe(MAX_MESSAGE);
	expect(wire.limits.label()).toBe(MAX_LABEL);
	expect(wire.limits.name()).toBe(MAX_NAME);
	expect(wire.limits.name.octets()).toBe(MAX_NAME_OCTETS);
	expect(wire.transport.udp.min()).toBe(UDP_MIN);
	expect(wire.transport.udp.cap()).toBe(DEFAULT_UDP_CAP);
	expect(wire.tcp.max()).toBe(TCP_MAX);
	// errors: a refusal from a composed leaf carries the codec's own code
	try {
		wire.domain.parse("");
		expect.unreachable("domain.parse('') must refuse");
	} catch (err) {
		expect(err.code).toBe("BAD_PRESENTATION");
	}
	// the WireError leaf constructs
	const err = new wire.errors.WireError("BAD_PRESENTATION", "boom");
	expect(err.message).toBe("boom");
	expect(err.code).toBe("BAD_PRESENTATION");
};

describe("the composed wire surface (CLDMV/digby#42)", () => {
	it("composes the real src/api tree in eager mode — every leaf present and callable", async () => {
		const api = await slothlet({ base: API_BASE, mode: "eager" });
		const wire = api.wire;
		// the root leaf: named, activate-able
		expect(wire.name).toBe("wire");
		expect(typeof wire.activate).toBe("function");
		expect(typeof wire.deactivate).toBe("function");
		const missing = SURFACE.filter(([p, kind]) => typeof at(wire, p) !== kind).map(([p]) => p);
		expect(missing, `leaves missing or the wrong kind: ${missing.join(", ")}`).toEqual([]);
		callEveryLeaf(wire);
	});

	it("composes through api.slothlet.api.add — the rummage-style mount — with the same surface", async () => {
		const api = await slothlet({ mode: "eager" });
		await api.slothlet.api.add(["ext", "digby", "wire"], API_DIR, { moduleID: "wire" });
		const wire = api.ext.digby.wire;
		const missing = SURFACE.filter(([p, kind]) => typeof at(wire, p) !== kind).map(([p]) => p);
		expect(missing, `leaves missing or the wrong kind: ${missing.join(", ")}`).toEqual([]);
		callEveryLeaf(wire);
	});

	it("composes in lazy mode to the same surface once the namespaces materialize", async () => {
		const api = await slothlet({ base: API_BASE, mode: "lazy" });
		const wire = await api.wire;
		// a lazy node answers its own placeholder until its module loads: awaiting each namespace materializes it
		// (the docs' "any other member access, a call, or await self.owner loads it") — and a materialized parent
		// leaves ITS child namespaces lazy, so the nested ones are awaited too
		for (const ns of ["framer", "record", "ttl", "rdata", "domain", "type", "class", "tsig", "transport", "transport.udp", "tcp", "constants", "constants.edns", "constants.svc", "limits", "errors"]) await at(wire, ns);
		const missing = SURFACE.filter(([p, kind]) => typeof at(wire, p) !== kind).map(([p]) => p);
		expect(missing, `leaves missing or the wrong kind: ${missing.join(", ")}`).toEqual([]);
		callEveryLeaf(wire);
	});
});

describe("the manifest's public list gates a peer (CLDMV/digby#42 A2)", () => {
	// rummage's api tree composes with defaultPolicy "deny" and derives, per manifest `public` entry, an allow for
	// the leaf AND its subtree for every caller (src/ext-host/api-tree.mjs deriveRules). The test derives the same
	// rules from wire's own manifest — so the list is proven against the policy it must satisfy.
	it("every manifest public entry resolves on the composed tree", async () => {
		const api = await slothlet({ base: API_BASE, mode: "eager" });
		const missing = manifest.public.filter((leaf) => typeof at(api.wire, leaf) !== "function");
		expect(missing, `public entries that do not resolve: ${missing.join(", ")}`).toEqual([]);
	});

	it("a second extension reaches the public leaves and is refused the rest", async () => {
		const base = "ext.digby.wire";
		const rules = [];
		for (const leaf of manifest.public) {
			rules.push({ caller: "**", target: `${base}.${leaf}`, effect: "allow" });
			rules.push({ caller: "**", target: `${base}.${leaf}.**`, effect: "allow" });
		}
		const api = await slothlet({ mode: "eager", permissions: { defaultPolicy: "deny", rules } });
		await api.slothlet.api.add(["ext", "digby", "wire"], API_DIR, { moduleID: "wire" });
		// a minimal peer extension, composed alongside wire, reaching wire only through `self`
		const peer = fileURLToPath(new URL("./fixtures/compose/peer/src/api/zones/", import.meta.url));
		await api.slothlet.api.add(["ext", "digby", "zones"], peer, { moduleID: "zones" });
		const zones = api.ext.digby.zones;
		// public: the peer's leaf calls wire.decode through self and answers
		expect(zones.probe(BYTES)).toEqual(decodeMessage(BYTES));
		// not public: the lifecycle leaves are the host's, never a peer's
		expect(() => zones.reach()).toThrow(/denied|PERMISSION/i);
	});
});
