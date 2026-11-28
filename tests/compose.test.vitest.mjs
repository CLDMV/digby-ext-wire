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
 * eagerly, api-tree.mjs), and lazy — plus the real production host, rummage's `composeTestHost` (@cldmv/rummage/testing:
 * the in-process ext-host under the tree's defaultPolicy "deny"), which is what actually loads wire in a rummage app.
 * The leaves test imports the leaf files directly, which composes nothing; this suite is what proves the tree survives
 * composition and that every leaf is callable. Slothlet resolves the module exports' own answers, not the file import —
 * the leaves test's identity pins do not transfer here, so every leaf is called and its result compared with the codec's
 * own function on the same input.
 *
 * The surface itself is never a fixed list: each mode walks the composed tree and asserts the leaf set against an eager
 * reference compose of the same tree, that no leaf path runs through a `Function.prototype` key (a leaf named `name` —
 * or `length`, `bind`, … — answers the placeholder's own property instead of itself: `wire.limits.name` came back as the
 * string "wire_waitingProxy" in lazy mode, CLDMV/digby#42 B1), and that the walk and the manifest's `public` list agree
 * in both directions — rummage refuses to LOAD a manifest entry that does not resolve on the composed tree
 * (CLDMV/rummage#193), so drift is a load failure, not a silent gap.
 *
 * Plus the two data findings this surface must answer (CLDMV/digby#42 review):
 * - the frozen tables (constants, error codes, limits) are plain data through the composed api — leaf functions
 *   returning the frozen table (CLDMV/slothlet docs, API-RULES Rule 5: an object default export composes as a
 *   namespace wrapper, so a table leaf is a zero-arg function and callers call it);
 * - the error surface is a predicate, not the class: rummage's own-leaf check sanitizes WireError.mjs to `wireError`
 *   while slothlet composes it as `WireError`, so a `errors.WireError` manifest entry is refused and wire does not load
 *   in any rummage host (CLDMV/rummage#1100), and `instanceof` is false across the composed boundary anyway (a composed
 *   instance is a separate module copy) — callers ask `errors.is(err)`.
 */

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { composeTestHost } from "@cldmv/rummage/testing";
import { self } from "@cldmv/rummage/runtime";
// the error predicate leaf, imported directly — the leaves test's shape; the composed assertions below go through
// the api, this one pins the leaf's own logic against a lookalike (r4-5)
import { is as isLeaf } from "../src/api/wire/errors/is.mjs";

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

const API_BASE = fileURLToPath(new URL("../src/api/", import.meta.url));
const API_DIR = fileURLToPath(new URL("../src/api/wire/", import.meta.url));

/** Resolve a dotted api path, `undefined` when a segment is missing. */
const at = (node, p) => p.split(".").reduce((v, s) => (v == null ? v : v[s]), node);

// ---------------------------------------------------------------- the walk

/** Every own property name `Function.prototype` carries — a leaf may not sit behind one of them (CLDMV/digby#42 B1). */
const FN_SEGMENT = new Set(Object.getOwnPropertyNames(Function.prototype));

/**
 * Walk a composed subtree depth-first, collecting every reachable `[path, value]`. A `seen` set bounds it on a tree
 * that closes over itself.
 */
const walkTree = (node, pre, seen, out) => {
	if (node == null || (typeof node !== "function" && typeof node !== "object") || seen.has(node)) return out;
	seen.add(node);
	for (const k of Object.keys(node)) {
		const p = pre ? `${pre}.${k}` : k;
		out.push([p, node[k]]);
		walkTree(node[k], p, seen, out);
	}
	return out;
};

/** The composed leaf paths — the walk's function entries (every leaf is a function; namespaces are plain objects). */
const leafPathsOf = (wire) =>
	walkTree(wire, "", new Set(), [])
		.filter(([, v]) => typeof v === "function")
		.map(([p]) => p);

/**
 * The namespace paths a leaf set implies — every PROPER prefix of every leaf path, built PER PATH from the tree
 * being checked (in lazy mode a materialized namespace is still a function node, so the walk's function filter
 * picks namespaces up too, and they are exempt from the leaf-set and publication checks). The r3 shape was the
 * whole-list `.slice(0, -1)` (r4-1): it trims ONE element off the flattened prefix list and leaves every leaf
 * path counted as its own namespace — 43 of the 44 leaf paths exempt themselves, so the publication check was
 * vacuous (a dropped manifest entry and a new unpublished leaf both waved through). Proper prefixes leave exactly
 * one leaf exempt: `limits.domain`, a leaf that is a prefix of another leaf (`limits.domain.octets`).
 * @param {string[]} leafPaths - the leaf paths of the tree being checked
 * @returns {Set<string>}
 */
const namespacePathsOf = (leafPaths) => new Set(leafPaths.flatMap((p) => p.split(".").slice(0, -1).map((_, i, a) => a.slice(0, i + 1).join("."))));

/**
 * The composed leaf paths the manifest does not publish — the host's own lifecycle (`activate`, `deactivate`) and
 * namespace paths excepted. Shared by the surface check and the r4-1 mutant tests, so the mutants exercise the
 * same logic the real check runs.
 * @param {string[]} paths - the tree's leaf paths
 * @param {Set<string>} pub - the manifest's `public` list
 * @returns {string[]}
 */
const unpublishedLeavesOf = (paths, pub) =>
	paths.filter((p) => !pub.has(p) && p !== "activate" && p !== "deactivate" && !namespacePathsOf(paths).has(p));

// The reference surface, derived once from an eager compose of the real tree — no fixed list anywhere in this suite.
// The composed surface is 44 leaves: the 42 the manifest publishes, plus the host's own activate and deactivate
// (never published). The manifest's `public` list has exactly 42 entries (r4-4: the count, pinned by a test below —
// the r3 handback's "45 leaves" was wrong).
const reference = await slothlet({ base: API_BASE, mode: "eager" });
const LEAF_PATHS = leafPathsOf(reference.wire);

/**
 * Assert a composed tree carries exactly the reference leaf set, that no leaf path runs through a
 * `Function.prototype` key, and that the manifest's `public` list agrees with the walk in both directions:
 * every composed leaf (but the host's own activate/deactivate) is published, and every published entry resolves.
 * @param {object} wire - the composed wire node
 */
const checkSurface = (wire) => {
	const paths = leafPathsOf(wire);
	const missing = LEAF_PATHS.filter((p) => !paths.includes(p));
	expect(missing, `leaves missing from the composed tree: ${missing.join(", ")}`).toEqual([]);
	// a namespace that is a prefix of a leaf is not itself a leaf — and in lazy mode a materialized namespace is
	// still a function node (the lazy callable), so the walk's function filter picks it up; only prefix paths are
	// tolerated, anything else in the walk that the eager reference lacks is an unexpected leaf. The prefixes are
	// derived from the tree BEING CHECKED (the mutant-faithful shape — a new leaf exempts itself as its own prefix,
	// which is exactly what the publication check must refuse)
	const namespacePaths = namespacePathsOf(paths);
	const extra = paths.filter((p) => !LEAF_PATHS.includes(p) && !namespacePaths.has(p));
	expect(extra, `composed leaves the eager reference does not have: ${extra.join(", ")}`).toEqual([]);
	const fnSegment = paths.filter((p) => p.split(".").some((s) => FN_SEGMENT.has(s)));
	expect(fnSegment, `leaf paths through a Function.prototype key (CLDMV/digby#42 B1): ${fnSegment.join(", ")}`).toEqual([]);
	const pub = new Set(manifest.public);
	const unpublished = unpublishedLeavesOf(paths, pub);
	expect(unpublished, `composed leaves the manifest does not publish: ${unpublished.join(", ")}`).toEqual([]);
	const uncomposed = manifest.public.filter((p) => !paths.includes(p));
	expect(uncomposed, `public entries that do not resolve on the composed tree: ${uncomposed.join(", ")}`).toEqual([]);
};

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
	expect(wire.messages.encode.capped(MESSAGE, { limit: 4096 })).toEqual(encodeCapped(MESSAGE, { limit: 4096 }));
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
	const capped = wire.messages.encode.capped(MESSAGE, { limit: 280, reserveTsig: need });
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
	expect(wire.limits.domain()).toBe(MAX_NAME);
	expect(wire.limits.domain.octets()).toBe(MAX_NAME_OCTETS);
	expect(wire.transport.udp.min()).toBe(UDP_MIN);
	expect(wire.transport.udp.cap()).toBe(DEFAULT_UDP_CAP);
	expect(wire.tcp.max()).toBe(TCP_MAX);
	// errors: a refusal from a composed leaf carries the codec's own code, and errors.is answers it — through the
	// composed api, where `instanceof` is false for errors wire's own leaves threw (CLDMV/digby#42 D)
	try {
		wire.domain.parse("");
		expect.unreachable("domain.parse('') must refuse");
	} catch (err) {
		expect(err.code).toBe("BAD_PRESENTATION");
		expect(wire.errors.is(err)).toBe(true);
	}
	expect(wire.errors.is(new WireError("TRUNCATED", "boom"))).toBe(true);
	// name-plus-code also answers a WireError-shaped error another module copy re-threw (zones' master-file
	// decorator): the class is lib-internal, the shape is the contract
	expect(wire.errors.is(Object.assign(new Error("boom"), { name: "WireError", code: "TRUNCATED" }))).toBe(true);
	expect(wire.errors.is(new Error("plain"))).toBe(false);
	expect(wire.errors.is(null)).toBe(false);
	expect(wire.errors.is({ name: "WireError" })).toBe(false);
};

describe("the composed wire surface (CLDMV/digby#42)", () => {
	it("composes the real src/api tree in eager mode — every leaf present and callable", async () => {
		const api = await slothlet({ base: API_BASE, mode: "eager" });
		const wire = api.wire;
		// the root leaf: activate-able (the host's lifecycle; no state to capture)
		expect(typeof wire.activate).toBe("function");
		expect(typeof wire.deactivate).toBe("function");
		checkSurface(wire);
		callEveryLeaf(wire);
	});

	it("composes through api.slothlet.api.add — the rummage-style mount — with the same surface", async () => {
		const api = await slothlet({ mode: "eager" });
		await api.slothlet.api.add(["ext", "digby", "wire"], API_DIR, { moduleID: "wire" });
		checkSurface(api.ext.digby.wire);
		callEveryLeaf(api.ext.digby.wire);
	});
});

describe("the lazy compose answers without any namespace awaited first (CLDMV/digby#42 B1)", () => {
	it("every leaf answers a function on fresh access — nothing awaited", async () => {
		const api = await slothlet({ base: API_BASE, mode: "lazy" });
		const wire = api.wire;
		// fresh, nothing awaited: a leaf path must answer the leaf. A leaf behind a Function.prototype key — the
		// old `limits.name` — answered the lazy placeholder's own property instead: the string "wire_waitingProxy"
		for (const p of LEAF_PATHS) expect(typeof at(wire, p), `wire.${p} fresh in lazy mode`).toBe("function");
		// the nested data leaf too, fresh: await the call, never the namespaces
		await expect(wire.limits.domain.octets()).resolves.toBe(MAX_NAME_OCTETS);
	});

	it("composes in lazy mode to the same surface once the namespaces materialize", async () => {
		const api = await slothlet({ base: API_BASE, mode: "lazy" });
		const wire = api.wire;
		// a lazy node answers its own placeholder until its module loads: awaiting each namespace materializes it
		// (the docs' "any other member access, a call, or await self.owner loads it") — and a materialized parent
		// leaves ITS child namespaces lazy, so the nested ones are awaited too
		for (const ns of ["framer", "record", "ttl", "rdata", "domain", "type", "class", "tsig", "transport", "transport.udp", "tcp", "constants", "constants.edns", "constants.svc", "limits", "errors", "messages", "messages.encode"]) await at(wire, ns);
		checkSurface(wire);
		callEveryLeaf(wire);
	});
});

describe("the leaf-publication check is not vacuous (CLDMV/digby#42 r4-1, red on fa65b3d)", () => {
	it("M1 — a leaf the manifest drops is flagged unpublished (rdata.generic)", () => {
		// the r3 reviewer's M1: remove the manifest's rdata.generic entry — a composed leaf left unpublished
		const pub = new Set(manifest.public.filter((p) => p !== "rdata.generic"));
		const offenders = unpublishedLeavesOf(LEAF_PATHS, pub);
		expect(offenders, "the dropped leaf must be flagged, and nothing else").toEqual(["rdata.generic"]);
	});

	it("M2 — a new leaf the manifest does not know is flagged unpublished (rdata.extra)", () => {
		// the r3 reviewer's M2: a new leaf file appears and is composed but the manifest does not publish it. The
		// mutant-faithful simulation inserts the leaf path MID-WALK, where a new rdata sibling really lands — not
		// at the end of the list, where the r3 bug's whole-list `.slice(0, -1)` would drop it by accident and let
		// it through. (The real M2 run is scripted pod-side in the r4 evidence; this committed form exercises the
		// same check logic on the same shape.)
		const at = LEAF_PATHS.indexOf("rdata.parse");
		const paths = [...LEAF_PATHS.slice(0, at), "rdata.extra", ...LEAF_PATHS.slice(at)];
		const offenders = unpublishedLeavesOf(paths, new Set(manifest.public));
		expect(offenders, "the unpublished new leaf must be flagged, and nothing else").toEqual(["rdata.extra"]);
	});

	it("the composed surface counts 44 leaves — 42 published plus activate and deactivate (r4-4)", () => {
		// the count, pinned: 44 composed leaves, of which the 42 the manifest publishes are eligible for peers and
		// the host's own activate/deactivate are not (r4-4 — the r3 statements said 45)
		expect(LEAF_PATHS.length, "the composed leaf count").toBe(44);
		expect(LEAF_PATHS.filter((p) => p !== "activate" && p !== "deactivate").length, "the published-eligible leaves").toBe(42);
		expect(manifest.public.length, "the manifest's public entries").toBe(42);
	});
});

describe("errors.is refuses a lookalike whose code is not a WireErrorCode (CLDMV/digby#42 r4-5, red on fa65b3d)", () => {
	it("a WireError-named error with an unknown code is not the codec's error", () => {
		expect(isLeaf(Object.assign(new Error("boom"), { name: "WireError", code: "NOT_A_WIRE_CODE" })), "the shape alone is not enough — the code must be a WireErrorCode").toBe(false);
		// a known code keeps answering (the name-plus-code re-throw contract, unchanged)
		expect(isLeaf(Object.assign(new Error("boom"), { name: "WireError", code: "TRUNCATED" }))).toBe(true);
	});
});

describe("the real ext-host composes wire — the manifest's public list (CLDMV/digby#42 A2)", () => {
	let t;
	beforeAll(async () => {
		// the production web path: a real in-process ext-host composing wire under the tree's defaultPolicy "deny",
		// exactly as a rummage app loads it — a manifest entry rummage cannot resolve is a load failure here
		t = await composeTestHost({ ext: new URL("..", import.meta.url), store: null, app: "digby" });
	}, 300_000);
	afterAll(() => t?.close());

	/** Where the host composed wire — first-party (`wire`) or third-party (`ext.digby.wire`). */
	const mount = () => ["wire", "ext.digby.wire", "ext.wire"].find((p) => { try { return t.leaf(`${p}.decode`) !== undefined; } catch { return false; } });

	it("boots wire — the manifest's public list is accepted", () => {
		expect(mount(), "the host composed wire somewhere").toBeTruthy();
	});

	it("a peer reaches the public leaves and is refused the rest — through the real host", async () => {
		const p = mount();
		const node = () => p.split(".").reduce((v, s) => v[s], self);
		// public: the peer's extent calls wire.decode through self and answers
		expect(await t.run(() => node().decode(BYTES).questions.length)).toBe(1);
		// the error predicate through the composed api, on an error wire's own decode threw
		const caught = await t.run(() => {
			try {
				node().decode(new Uint8Array([1]));
			} catch (e) {
				return [e.code, node().errors.is(e)];
			}
		});
		expect(caught[0]).toBe("TRUNCATED");
		expect(caught[1]).toBe(true);
		// not public: the lifecycle leaves are the host's, never a peer's
		await expect(t.run(() => node().activate({}))).rejects.toThrow(/denied|permission/i);
		await expect(t.run(() => node().deactivate())).rejects.toThrow(/denied|permission/i);
	});
});
