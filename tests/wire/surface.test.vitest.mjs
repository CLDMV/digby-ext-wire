/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/surface.test.vitest.mjs
 */

/**
 * The argument positions round 5's message-side slices did not cover (CLDMV/digby#39, round 6): the options argument of
 * every entry that takes one, udpLimit's query, the constant converters and the names helpers, and the SharedArrayBuffer
 * forms at every byte-taking entry. The governing rule: every export of src/lib/wire/index.mjs is a public entry and
 * throws only WireError, for any value in any argument position, whole arguments included.
 */

import { Buffer } from "node:buffer";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { CLASS, TYPE, classFromString, classToString, svcKeyFromString, svcKeyToString, typeFromString, typeToString } from "../../src/lib/wire/constants.mjs";
import { WireError } from "../../src/lib/wire/errors.mjs";
import { TcpFramer, UDP_MIN, encodeForTransport, frameTcp, udpLimit } from "../../src/lib/wire/limits.mjs";
import { decodeMessage, encodeCapped, encodeMessage } from "../../src/lib/wire/message.mjs";
import { formatName, parseName } from "../../src/lib/wire/names.mjs";
import { parseRecord } from "../../src/lib/wire/presentation.mjs";
import { decodeRdataBytes, formatGeneric } from "../../src/lib/wire/rdata/index.mjs";

const code = (fn) => {
	try {
		fn();
	} catch (err) {
		if (!(err instanceof WireError)) throw err;
		return err.code;
	}
	return "no error";
};

// every value a caller can hand an entry that is not plain data, or that breaks a naive String()/template of it — the
// round-5 set plus the shapes the round-6 findings name (a BigInt for Math.max's coercion, sparse and deep arrays, a
// getter whose value flips between reads, a throwing Symbol.toPrimitive, a BigInt64Array for formatLabel's indexed reads)
const revokedProxy = (() => {
	const { proxy, revoke } = Proxy.revocable({}, {});
	revoke();
	return proxy;
})();
const throwingGet = new Proxy({}, { get() { throw new RangeError("get trap"); } });
const throwingProto = new Proxy({}, { getPrototypeOf() { throw new RangeError("getPrototypeOf trap"); } });
const throwingView = new Proxy(new Uint8Array([1, 2, 3, 4]), { get() { throw new RangeError("get trap"); } });
const throwingNull = Object.defineProperty({}, "x", { get() { throw null; }, enumerable: true });
const throwingSymbol = Object.defineProperty({}, "x", { get() { throw Symbol("boom"); }, enumerable: true });
const throwingObject = Object.defineProperty({}, "x", { get() { throw { message: { toString() { throw new Error("boom"); } } }; }, enumerable: true });
const toStringOne = { toString: 1, valueOf: 1 };
const toStringNull = { toString: null };
const nullProto = Object.create(null);
const sparse = new Array(100);
sparse[0] = 1;
const deep = [];
{
	let at = deep;
	for (let i = 0; i < 64; i++) {
		at.push([]);
		at = at[0];
	}
}
let flips = 0;
const flipGetter = { get v() { return ++flips % 2 ? { x: 1 } : undefined; } };
const toPrimitiveThrower = { [Symbol.toPrimitive]() { throw null; } };
const hostiles = [
	["a revoked Proxy", revokedProxy],
	["a Proxy whose get trap throws", throwingGet],
	["a Proxy whose getPrototypeOf trap throws", throwingProto],
	["a Proxy over a Uint8Array whose get trap throws", throwingView],
	["a getter that throws null", throwingNull],
	["a getter that throws a Symbol", throwingSymbol],
	["a getter that throws an unstringifiable object", throwingObject],
	["{ toString: 1, valueOf: 1 }", toStringOne],
	["{ toString: null }", toStringNull],
	["Object.create(null)", nullProto],
	["a Symbol", Symbol("nope")],
	["a function", () => {}],
	["a BigInt", 10n],
	["a sparse array", sparse],
	["a deep array", deep],
	["a getter that alternates its value", flipGetter],
	["a Symbol.toPrimitive that throws", toPrimitiveThrower],
	["a BigInt64Array", new BigInt64Array(4)]
];

/** Run `shape` with every hostile value and return a line for each that escapes as something other than a WireError. */
const sweep = (entries) => {
	const escapes = [];
	for (const [what, shape] of entries)
		for (const [hvName, hv] of hostiles) {
			let outcome;
			try {
				shape(hv)();
				outcome = "returned";
			} catch (err) {
				outcome = err;
			}
			if (outcome !== "returned" && !(outcome instanceof WireError)) {
				const shown = outcome instanceof Error ? outcome.constructor.name : String(outcome);
				escapes.push(`${what} with ${hvName} escaped as ${shown}${outcome instanceof Error ? `: ${outcome.message}` : ""}`);
			}
		}
	return escapes;
};

const message = () => ({ id: 1, flags: { qr: true }, rcode: 0, questions: [], answers: [], authorities: [], additionals: [], edns: null });
const bytes = new Uint8Array(12);

describe("the options argument is guarded (CLDMV/digby#39, round 6)", () => {
	const entries = [
		["decodeMessage", (o) => () => decodeMessage(bytes, o)],
		["encodeMessage", (o) => () => encodeMessage(message(), o)],
		["encodeCapped", (o) => () => encodeCapped(message(), o)],
		["parseRecord", (o) => () => parseRecord("a.example. 60 IN A 10.0.0.1", o)],
		["udpLimit", (o) => () => udpLimit(null, o)],
		["encodeForTransport", (o) => () => encodeForTransport(message(), o)]
	];

	it("every hostile value as the whole options argument is a WireError, never anything else", () => {
		expect(sweep(entries)).toEqual([]);
	});

	it('null and undefined mean "no options"', () => {
		expect(() => decodeMessage(bytes, null)).not.toThrow();
		expect(() => decodeMessage(bytes, undefined)).not.toThrow();
		expect(() => encodeMessage(message(), null)).not.toThrow();
		expect(() => parseRecord("a.example. 60 IN A 10.0.0.1", null)).not.toThrow();
		expect(udpLimit(null, null)).toBe(UDP_MIN);
		// the transport is still required — the refusal is the entry's own, not a destructuring TypeError
		expect(code(() => encodeForTransport(message(), null))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("a non-object options value is refused", () => {
		for (const o of [5, "x", 10n, Symbol("s"), true]) {
			expect(code(() => decodeMessage(bytes, o))).toBe("VALUE_OUT_OF_RANGE");
			expect(code(() => encodeMessage(message(), o))).toBe("VALUE_OUT_OF_RANGE");
		}
	});

	it("a getter that throws in the options is a WireError, not a raw null", () => {
		expect(code(() => encodeMessage(message(), { get maxSize() { throw null; } }))).toBe("NOT_CLONEABLE");
	});

	it("options on a prototype or in a Map are refused, never silently dropped (CLDMV/digby#39, round 7)", () => {
		// structuredClone copies own enumerable properties only, so a bound on the prototype would silently vanish:
		// encodeMessage(big, Object.create({ maxSize: 40 })) encoded 189 octets instead of refusing, udpLimit read the
		// default 1232 instead of cap 600, and decodeMessage decoded everything without the name cap
		const big = {
			...message(),
			answers: [
				{ name: "a.example.", type: TYPE.A, class: 1, ttl: 60, data: { address: "10.0.0.1" } },
				{ name: "b.example.", type: TYPE.A, class: 1, ttl: 60, data: { address: "10.0.0.2" } }
			]
		};
		expect(code(() => encodeMessage(big, { maxSize: 40 }))).toBe("MESSAGE_TOO_LARGE");
		expect(code(() => encodeMessage(big, Object.create({ maxSize: 40 })))).toBe("VALUE_OUT_OF_RANGE");
		class Opts {
			get maxSize() {
				return 40;
			}
		}
		expect(code(() => encodeMessage(big, new Opts()))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => udpLimit({ edns: { udpSize: 4096 } }, Object.create({ cap: 600 })))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => decodeMessage(bytes, Object.create({ maxNameOctets: 5 })))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => decodeMessage(bytes, new Map([["maxNameOctets", 5]])))).toBe("VALUE_OUT_OF_RANGE");
		// a null-prototype options object is still plain data and still works
		expect(() => decodeMessage(bytes, Object.assign(Object.create(null), { allowTrailing: true }))).not.toThrow();
	});

	it("a bound on the prototype is refused however it is hidden: by key, not by prototype shape (CLDMV/digby#39, round 9)", () => {
		// round 8's plain-object check was forgeable: any prototype whose own `constructor` is a function named
		// "Object" with `.prototype ===` that prototype passed it, and the bound it carries was silently dropped by
		// the copy — the forged-function, renamed-class and inherited forms below all encoded at 1117 octets with
		// maxSize 40 in force. The check is now by key: an inherited ENUMERABLE key is refused (the copy drops it),
		// and so is an inherited KNOWN option key however hidden — a class getter is non-enumerable and the
		// enumerable check cannot see it.
		const big = {
			...message(),
			answers: [
				{ name: "a.example.", type: TYPE.A, class: 1, ttl: 60, data: { address: "10.0.0.1" } },
				{ name: "b.example.", type: TYPE.A, class: 1, ttl: 60, data: { address: "10.0.0.2" } }
			]
		};
		const F = function Object() {};
		F.prototype.maxSize = 40;
		expect(code(() => encodeMessage(big, new F()))).toBe("VALUE_OUT_OF_RANGE");
		class Object2 {
			get maxSize() {
				return 40;
			}
		}
		Object.defineProperty(Object2, "name", { value: "Object" });
		expect(code(() => encodeMessage(big, new Object2()))).toBe("VALUE_OUT_OF_RANGE");
		const G = function Object() {};
		G.prototype.maxNameOctets = 1;
		expect(code(() => decodeMessage(bytes, new G()))).toBe("VALUE_OUT_OF_RANGE");
		// the same forge against the query: encodeForTransport's options walk refuses the prototype-borne edns before
		// the copy could silently drop it (udpLimit's own reader catches it once its guarded snapshot lands)
		const Q = function Object() {};
		Q.prototype.edns = { udpSize: 4096 };
		expect(code(() => encodeForTransport(message(), { transport: "udp", cap: 4096, query: new Q() }))).toBe("VALUE_OUT_OF_RANGE");
		// plain data of every realm still works: vm, JSON, null-prototype, frozen and structuredClone'd options are
		// all own-keyed, so nothing is dropped and nothing needs the prototype shape
		expect(() => decodeMessage(bytes, structuredClone({ allowTrailing: true }))).not.toThrow();
	});

	it("an own non-enumerable or symbol-keyed option is refused, never silently dropped (CLDMV/digby#39, round 8)", () => {
		// structuredClone copies own enumerable string-keyed properties only: Object.defineProperty({}, "maxSize",
		// { value: 40 }) used to encode the whole message — the bound silently gone. Every known bound hides the same
		// way, and a symbol-keyed option is dropped by the copy too.
		const big = {
			...message(),
			answers: [
				{ name: "a.example.", type: TYPE.A, class: 1, ttl: 60, data: { address: "10.0.0.1" } },
				{ name: "b.example.", type: TYPE.A, class: 1, ttl: 60, data: { address: "10.0.0.2" } }
			]
		};
		expect(code(() => encodeMessage(big, Object.defineProperty({}, "maxSize", { value: 40 })))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeCapped(message(), Object.defineProperty({}, "limit", { value: 20 })))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => udpLimit({ edns: { udpSize: 4096 } }, Object.defineProperty({}, "cap", { value: 70000 })))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => decodeMessage(bytes, Object.defineProperty({}, "maxNameOctets", { value: 5 })))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => decodeMessage(bytes, Object.defineProperty({}, "maxQuestions", { value: 0 })))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage(big, Object.defineProperty({}, Symbol("maxSize"), { value: 40, enumerable: true })))).toBe("VALUE_OUT_OF_RANGE");
		// frozen and JSON-parsed options still work: freezing changes no enumerability
		expect(() => decodeMessage(bytes, Object.freeze({ allowTrailing: true }))).not.toThrow();
		expect(() => decodeMessage(bytes, JSON.parse('{"allowTrailing":true}'))).not.toThrow();
	});

	it("a nested option object's keys must be its own: the query's EDNS cannot live on a prototype (CLDMV/digby#39, round 9)", () => {
		// today: Object.create({ edns: { udpSize: 4096 } }) read its EDNS in udpLimit but lost it in
		// encodeForTransport's copy — 512 there, 4096 here; both entries refuse the prototype-borne shape now
		const q = Object.create({ edns: { udpSize: 4096 } });
		expect(code(() => encodeForTransport(message(), { transport: "udp", cap: 4096, query: q }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => udpLimit(q, { cap: 4096 }))).toBe("VALUE_OUT_OF_RANGE");
		// a plain nested object still works
		expect(udpLimit({ edns: { udpSize: 4096 } }, { cap: 4096 })).toBe(4096);
		expect(encodeForTransport(message(), { transport: "udp", cap: 4096, query: { edns: { udpSize: 4096 } } }).limit).toBe(4096);
	});

	it("both transport entries read the one guarded snapshot of the query (CLDMV/digby#39, round 9)", () => {
		// R8-7 closed only half of the gap: udpLimit still read the query through readField — non-enumerable and
		// inherited fields included — while encodeForTransport read the copy, so the two entries could answer
		// different limits for the same query, or refuse it with different codes. Both now take the one guarded
		// snapshot ({@link snapshotQuery}) and read only it.
		const msg = message();
		const refuse = (make, what) => {
			expect(code(() => udpLimit(make(), { cap: 4096 })), what).toBe("VALUE_OUT_OF_RANGE");
			expect(code(() => encodeForTransport(msg, { transport: "udp", cap: 4096, query: make() })), what).toBe("VALUE_OUT_OF_RANGE");
		};
		// a non-enumerable edns: udpLimit read it (4096) where the copy silently dropped it (512)
		refuse(() => Object.defineProperty({}, "edns", { value: { udpSize: 4096 } }), "non-enumerable edns");
		// depth 2: an inherited udpSize, a non-enumerable udpSize and a class-borne getter — each read here, dropped there
		refuse(() => ({ edns: Object.create({ udpSize: 4096 }) }), "inherited udpSize");
		refuse(() => ({ edns: Object.defineProperty({}, "udpSize", { value: 4096 }) }), "non-enumerable udpSize");
		class UdpSize {
			get udpSize() {
				return 4096;
			}
		}
		refuse(() => ({ edns: new UdpSize() }), "class getter udpSize");
		// the query itself on a custom prototype — 4096 here, silently 512 there; the forge of the round-9 options check
		const Q = function Object() {};
		Q.prototype.edns = { udpSize: 4096 };
		refuse(() => new Q(), "forged-prototype query");
		// and a getter option carrying such a query: the copy lost the prototype and answered 512
		expect(
			code(() => encodeForTransport(msg, { transport: "udp", cap: 4096, get query() { return Object.create({ edns: { udpSize: 4096 } }); } }))
		).toBe("VALUE_OUT_OF_RANGE");
		// a bare SharedArrayBuffer inside the query: accepted by udpLimit (1232), refused by the copy — both refuse
		expect(code(() => udpLimit({ edns: { udpSize: 4096, x: new SharedArrayBuffer(4) } }, { cap: 4096 }))).toBe("NOT_CLONEABLE");
		expect(code(() => encodeForTransport(msg, { transport: "udp", cap: 4096, query: { edns: { udpSize: 4096, x: new SharedArrayBuffer(4) } } }))).toBe("NOT_CLONEABLE");
		// an array is not a query (its non-index properties would be dropped by the copy)
		refuse(() => Object.assign([], { edns: { udpSize: 4096 } }), "array query");
		// a cooperative Proxy query is snapshotted once — its data read through the traps — and reads the same at both
		// entries (512 there was a NOT_CLONEABLE refusal before, a disagreement of a different kind)
		const proxyQuery = new Proxy({ edns: { udpSize: 4096 } }, {});
		expect(udpLimit(proxyQuery, { cap: 4096 })).toBe(4096);
		expect(encodeForTransport(msg, { transport: "udp", cap: 4096, query: proxyQuery }).limit).toBe(4096);
		// plain, getter-edns and vm queries still read the same at both entries
		expect(udpLimit({ edns: { udpSize: 4096 } }, { cap: 4096 })).toBe(4096);
		expect(encodeForTransport(msg, { transport: "udp", cap: 4096, query: { edns: { udpSize: 4096 } } }).limit).toBe(4096);
		const getterQ = { get edns() { return { udpSize: 4096 }; } };
		expect(udpLimit(getterQ, { cap: 4096 })).toBe(4096);
		expect(encodeForTransport(msg, { transport: "udp", cap: 4096, query: getterQ }).limit).toBe(4096);
		expect(udpLimit(runInNewContext("({ edns: { udpSize: 4096 } })"), { cap: 4096 })).toBe(4096);
		expect(encodeForTransport(msg, { transport: "udp", cap: 4096, query: runInNewContext("({ edns: { udpSize: 4096 } })") }).limit).toBe(4096);
	});

	it("options from another realm are plain data too (CLDMV/digby#39, round 8)", () => {
		// round 7's plain-object rule compared the prototype by identity with this realm's Object.prototype: a plain
		// options object built in a vm context failed it. The rule is the shape — a null prototype, or some realm's
		// Object.prototype — and a prototype-borne option from another realm is still refused.
		expect(() => decodeMessage(bytes, runInNewContext("({ allowTrailing: true })"))).not.toThrow();
		expect(code(() => decodeMessage(bytes, runInNewContext("Object.create({ maxNameOctets: 5 })")))).toBe("VALUE_OUT_OF_RANGE");
		expect(() => decodeMessage(bytes, runInNewContext("Object.freeze({ allowTrailing: true })"))).not.toThrow();
	});

	it("the round-9 refusal mappings are pinned: SAB forms and revoked Proxies in the options are NOT_CLONEABLE (CLDMV/digby#39, round 9)", () => {
		// round 8 refused a SharedArrayBuffer form inside the options with VALUE_OUT_OF_RANGE — the plain-shape
		// refusal answered before any SAB check — and a revoked Proxy with VALUE_OUT_OF_RANGE too, because
		// isPlainObject swallowed its throw. Round 9 maps both to NOT_CLONEABLE: a SAB form is not a shape question,
		// and a shape read that throws means the value is not cloneable data. Round 8's unknown-key refusals are kept
		// and pinned: a non-plain value under ANY option key, known or not, is VALUE_OUT_OF_RANGE.
		expect(code(() => decodeMessage(bytes, { x: new SharedArrayBuffer(4) }))).toBe("NOT_CLONEABLE");
		expect(code(() => decodeMessage(bytes, { x: new Uint8Array(new SharedArrayBuffer(4)) }))).toBe("NOT_CLONEABLE");
		expect(code(() => encodeMessage(message(), revokedProxy))).toBe("NOT_CLONEABLE");
		expect(code(() => encodeMessage(message(), { maxSize: 40, extra: new Date() }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeMessage(message(), { maxSize: 40, extra: new Uint8Array(1) }))).toBe("VALUE_OUT_OF_RANGE");
	});
});

describe("udpLimit reads the query's EDNS size once and validates it (CLDMV/digby#39, round 6)", () => {
	const q = (udpSize) => ({ edns: { udpSize } });

	it("every hostile value as the advertised size is a WireError, never anything else", () => {
		// today: Math.max's ToNumber on a BigInt, a Symbol, { toString: 1 }, an Object.create(null) or a throwing
		// Symbol.toPrimitive throws a raw TypeError, and a sparse or deep array coerces to a wrong limit
		expect(sweep([["udpLimit's udpSize", (hv) => () => udpLimit(q(hv))]])).toEqual([]);
	});

	it("a getter is read once: an object then undefined cannot split the check from the use", () => {
		let n = 0;
		const query = { get edns() { return ++n % 2 ? { udpSize: 1232 } : undefined; } };
		expect(udpLimit(query)).toBe(1232);
	});

	it("a missing or out-of-range udpSize is refused, never a NaN limit", () => {
		expect(code(() => udpLimit({ edns: {} }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => udpLimit({ edns: { udpSize: 70000 } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => udpLimit({ edns: { udpSize: -1 } }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => udpLimit({ edns: { udpSize: 1.5 } }))).toBe("VALUE_OUT_OF_RANGE");
	});
});

describe("the constant converters, formatName and formatGeneric refuse hostile input (CLDMV/digby#39, round 6)", () => {
	it("every hostile value at the one argument is a WireError, never anything else", () => {
		expect(
			sweep([
				["typeToString", (hv) => () => typeToString(hv)],
				["typeFromString", (hv) => () => typeFromString(hv)],
				["classToString", (hv) => () => classToString(hv)],
				["classFromString", (hv) => () => classFromString(hv)],
				["svcKeyToString", (hv) => () => svcKeyToString(hv)],
				["svcKeyFromString", (hv) => () => svcKeyFromString(hv)],
				["formatName", (hv) => () => formatName(hv)],
				["formatGeneric", (hv) => () => formatGeneric(hv)]
			])
		).toEqual([]);
	});

	it("valid inputs still round-trip", () => {
		expect(typeToString(TYPE.A)).toBe("A");
		expect(typeToString(65534)).toBe("TYPE65534");
		expect(typeFromString("type12345")).toBe(12345);
		expect(typeFromString("A")).toBe(1);
		expect(classToString(CLASS.IN)).toBe("IN");
		expect(classToString(256)).toBe("CLASS256");
		expect(classFromString("class256")).toBe(256);
		expect(svcKeyToString(8)).toBe("ohttp");
		expect(svcKeyToString(9)).toBe("key9");
		expect(svcKeyFromString("alpn")).toBe(1);
		expect(svcKeyFromString("key9")).toBe(9);
		// the generic form has no leading zeros (RFC 9460): "key00001" is not the presentation form of key 1, and key 0
		// is registered as "mandatory", so its presentation is the mnemonic (CLDMV/digby#39, round 8)
		expect(code(() => svcKeyFromString("key00001"))).toBe("BAD_SVCPARAM");
		expect(code(() => svcKeyFromString("key0"))).toBe("BAD_SVCPARAM");
		expect(svcKeyFromString("key65535")).toBe(0xffff);
		expect(formatName(parseName("www.example."))).toBe("www.example.");
		expect(formatName([])).toBe(".");
		expect(formatGeneric(new Uint8Array([1, 2, 3]))).toBe("\\# 3 010203");
		expect(formatGeneric(new Uint8Array(0))).toBe("\\# 0");
	});

	it("a one-megabyte label builds without overflowing the stack", () => {
		// today: String.fromCharCode(...chars) with a million arguments throws a raw RangeError
		expect(code(() => formatName([new Uint8Array(1024 * 1024)]))).toBe("LABEL_TOO_LONG");
	});

	it("a label's own length property cannot shadow the wire length (CLDMV/digby#39, round 7)", () => {
		// today: a zero-length label with an own length of 5 printed five raw NULs
		const nul = new Uint8Array(0);
		Object.defineProperty(nul, "length", { value: 5 });
		expect(formatName([nul])).toBe(".");
		// today: a 60-octet label with an own length of 3 printed only "aaa."
		const padded = new Uint8Array(60).fill(0x61);
		Object.defineProperty(padded, "length", { value: 3 });
		expect(formatName([padded])).toBe(`${"a".repeat(60)}.`);
		// the over-long check reads the intrinsic length too: the shadow cannot smuggle a 100-octet label past it
		const long = new Uint8Array(100).fill(0x61);
		Object.defineProperty(long, "length", { value: 3 });
		expect(code(() => formatName([long]))).toBe("LABEL_TOO_LONG");
	});

	it("a label over a SharedArrayBuffer is refused like every byte-taking input (CLDMV/digby#39, round 7)", () => {
		// formatName was the only byte-taking export without the SAB rule; with a length-tracking view over a growable
		// SAB the length was checked and then read again
		for (const make of [
			() => new Uint8Array(new SharedArrayBuffer(1)),
			() => new Uint8Array(new SharedArrayBuffer(1, { maxByteLength: 4 })),
			() => Buffer.from(new SharedArrayBuffer(1))
		])
			expect(code(() => formatName([make()]))).toBe("NOT_CLONEABLE");
	});
});

describe("every SharedArrayBuffer form is refused at every byte-taking entry (CLDMV/digby#39, round 6)", () => {
	const sab = () => new SharedArrayBuffer(12);
	const forms = [
		["a bare SharedArrayBuffer", sab],
		["a Uint8Array over a SharedArrayBuffer", () => new Uint8Array(sab())],
		["a growable SharedArrayBuffer view", () => new Uint8Array(new SharedArrayBuffer(12, { maxByteLength: 24 }))],
		["a DataView over a SharedArrayBuffer", () => new DataView(sab())],
		["a Buffer over a SharedArrayBuffer", () => Buffer.from(sab())]
	];
	// decodeRdataBytes takes Uint8Arrays only: a bare SAB and a DataView are refused as the wrong type there, whatever
	// their backing store
	const octetShaped = (form) => form !== "a bare SharedArrayBuffer" && form !== "a DataView over a SharedArrayBuffer";
	const entries = [
		["decodeMessage", (b) => () => decodeMessage(b)],
		["frameTcp", (b) => () => frameTcp(b)],
		["TcpFramer.push", (b) => () => new TcpFramer().push(b)],
		["decodeRdataBytes", (b) => () => decodeRdataBytes(TYPE.A, b)],
		["formatGeneric", (b) => () => formatGeneric(b)]
	];

	it("every form at every entry is a WireError; the octet-shaped ones are NOT_CLONEABLE", () => {
		const escapes = [];
		for (const [entry, shape] of entries)
			for (const [form, make] of forms) {
				let outcome;
				try {
					shape(make())();
					outcome = "returned";
				} catch (err) {
					outcome = err;
				}
				if (!(outcome instanceof WireError)) {
					const shown = outcome instanceof Error ? outcome.constructor.name : String(outcome);
					escapes.push(`${entry} with ${form} escaped as ${shown}`);
				} else if ((entry !== "decodeRdataBytes" || octetShaped(form)) && outcome.code !== "NOT_CLONEABLE")
					escapes.push(`${entry} with ${form} refused as ${outcome.code}, not NOT_CLONEABLE`);
			}
		expect(escapes).toEqual([]);
	});

	it("an own buffer property cannot shadow the intrinsic one", () => {
		const shadow = new Uint8Array(new SharedArrayBuffer(8));
		Object.defineProperty(shadow, "buffer", { value: new ArrayBuffer(8) });
		expect(code(() => decodeMessage(shadow))).toBe("NOT_CLONEABLE");
		expect(code(() => frameTcp(shadow))).toBe("NOT_CLONEABLE");
		expect(code(() => new TcpFramer().push(shadow))).toBe("NOT_CLONEABLE");
		expect(code(() => decodeRdataBytes(TYPE.A, shadow))).toBe("NOT_CLONEABLE");
	});

	it("the clone walk reads the intrinsic buffer too: a shadowed view inside an encode is refused", () => {
		const shadow = new Uint8Array(new SharedArrayBuffer(8));
		Object.defineProperty(shadow, "buffer", { value: new ArrayBuffer(8) });
		expect(code(() => encodeMessage({ id: 1, answers: [{ name: "x.example.", type: TYPE.TXT, class: 1, ttl: 60, data: { strings: [shadow] } }] }))).toBe("NOT_CLONEABLE");
	});

	it("a SharedArrayBuffer wearing ArrayBuffer.prototype is refused by brand, never by prototype (CLDMV/digby#39, round 8)", () => {
		// today: `view.buffer instanceof SharedArrayBuffer` and `bytes instanceof ArrayBuffer` test the prototype chain,
		// so a prototype swap made a SharedArrayBuffer pass as a plain one and its octets were read — and a cross-realm
		// SharedArrayBuffer failed `instanceof SharedArrayBuffer` from this realm outright. The brand check is the
		// intrinsic `SharedArrayBuffer.prototype.byteLength` getter, which verifies the internal slot from any realm.
		const s = new SharedArrayBuffer(3);
		new Uint8Array(s).set([1, 2, 3]);
		Object.setPrototypeOf(s, ArrayBuffer.prototype);
		for (const [what, shape] of [
			["formatGeneric", (b) => () => formatGeneric(b)],
			["decodeMessage", (b) => () => decodeMessage(b)],
			["frameTcp", (b) => () => frameTcp(b)],
			["TcpFramer.push", (b) => () => new TcpFramer().push(b)]
		])
			expect(code(shape(s)), what).toBe("NOT_CLONEABLE");
		// the same for a view whose buffer wears the wrong prototype, and for every cross-realm form
		expect(code(() => formatGeneric(new Uint8Array(s)))).toBe("NOT_CLONEABLE");
		expect(code(() => formatGeneric(runInNewContext("new SharedArrayBuffer(3)")))).toBe("NOT_CLONEABLE");
		expect(code(() => formatGeneric(runInNewContext("new Uint8Array(new SharedArrayBuffer(3))")))).toBe("NOT_CLONEABLE");
		expect(code(() => decodeMessage(runInNewContext("new Uint8Array(new SharedArrayBuffer(12))")))).toBe("NOT_CLONEABLE");
		expect(code(() => frameTcp(runInNewContext("new DataView(new SharedArrayBuffer(12))")))).toBe("NOT_CLONEABLE");
	});

	it("a SAB-backed label is NOT_CLONEABLE whatever its realm or prototype, and a cross-realm label is accepted (CLDMV/digby#39, round 9)", () => {
		// the label check ran `instanceof Uint8Array` BEFORE the SAB brand check, so a bare SharedArrayBuffer and every
		// cross-realm form failed the type check and were reported VALUE_OUT_OF_RANGE — the wrong-type refusal —
		// instead of NOT_CLONEABLE
		for (const make of [
			() => new SharedArrayBuffer(4),
			() => runInNewContext("new SharedArrayBuffer(4)"),
			() => new DataView(new SharedArrayBuffer(4)),
			() => runInNewContext("new DataView(new SharedArrayBuffer(4))"),
			() => runInNewContext("new Uint8Array(new SharedArrayBuffer(4))")
		])
			expect(code(() => formatName([make()]))).toBe("NOT_CLONEABLE");
		// a cross-realm non-SAB Uint8Array label is accepted, exactly as decodeMessage accepts its octets: the type
		// check is the intrinsic TypedArray brand getter, never `instanceof`
		expect(formatName([runInNewContext("new Uint8Array([97])")])).toBe("a.");
	});
});

describe("parseRecord validates its default ttl and class like parsed values (CLDMV/digby#39, round 6)", () => {
	it("a default TTL out of range or of the wrong type is refused (CLDMV/digby#39, round 7: one code with the default class)", () => {
		// the default is a caller-supplied number, not presentation text: VALUE_OUT_OF_RANGE, the same code as the
		// default class and as every other out-of-range numeric argument
		for (const ttl of ["abc", -5, 2 ** 31, 1.5, { x: 1 }]) expect(code(() => parseRecord("a.example. IN A 10.0.0.1", { ttl }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("a default class out of range or of the wrong type is refused", () => {
		for (const cls of [{ x: 1 }, 70000, -1, "IN", 1.5]) expect(code(() => parseRecord("a.example. 60 A 10.0.0.1", { class: cls }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("valid defaults still work", () => {
		// the text carries neither TTL nor class, so both defaults are used
		expect(parseRecord("a.example. A 10.0.0.1", { ttl: 3600, class: 3 })).toEqual({ name: "a.example.", ttl: 3600, class: 3, type: TYPE.A, data: { address: "10.0.0.1" } });
	});
});

describe("only a real ArrayBuffer, TypedArray or DataView is byte input (CLDMV/digby#39, round 8)", () => {
	// today: asBytes' `bytes instanceof ArrayBuffer` accepts any object wearing ArrayBuffer.prototype, and the
	// `new Uint8Array(bytes)` behind it copies it as an array-like or iterable: { length: 2e8 } allocated 200 MB and
	// took 4.2 s before failing INPUT_TOO_LARGE, at 2**32 the pod was OOM-killed (exit 137), and an iterator walking a
	// SharedArrayBuffer view got that shared memory copied
	const fake = (extra) => Object.assign(Object.create(ArrayBuffer.prototype), { length: 3, 0: 1, 1: 2, 2: 3 }, extra);
	const shapes = [
		["decodeMessage", (b) => () => decodeMessage(b)],
		["frameTcp", (b) => () => frameTcp(b)],
		["TcpFramer.push", (b) => () => new TcpFramer().push(b)],
		["formatGeneric", (b) => () => formatGeneric(b)]
	];

	it("a pod wearing ArrayBuffer.prototype is VALUE_OUT_OF_RANGE before any allocation, however large its length claims to be", () => {
		for (const [what, shape] of shapes) expect(code(shape(fake({ length: 2e8 }))), what).toBe("VALUE_OUT_OF_RANGE");
	});

	it("an array-like whose iterator walks a SharedArrayBuffer view is refused before the iterator runs", () => {
		const walker = Object.create(ArrayBuffer.prototype);
		walker.length = 3;
		const shared = new Uint8Array(new SharedArrayBuffer(3));
		shared.set([1, 2, 3]);
		Object.defineProperty(walker, Symbol.iterator, {
			value: function* () {
				yield* shared;
			}
		});
		for (const [what, shape] of shapes) expect(code(shape(walker)), what).toBe("VALUE_OUT_OF_RANGE");
	});
});
