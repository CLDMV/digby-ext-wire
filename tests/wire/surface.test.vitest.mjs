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
		expect(formatName(parseName("www.example."))).toBe("www.example.");
		expect(formatName([])).toBe(".");
		expect(formatGeneric(new Uint8Array([1, 2, 3]))).toBe("\\# 3 010203");
		expect(formatGeneric(new Uint8Array(0))).toBe("\\# 0");
	});

	it("a one-megabyte label builds without overflowing the stack", () => {
		// today: String.fromCharCode(...chars) with a million arguments throws a raw RangeError
		expect(code(() => formatName([new Uint8Array(1024 * 1024)]))).toBe("LABEL_TOO_LONG");
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
});

describe("parseRecord validates its default ttl and class like parsed values (CLDMV/digby#39, round 6)", () => {
	it("a default TTL out of range or of the wrong type is refused", () => {
		for (const ttl of ["abc", -5, 2 ** 31, 1.5, { x: 1 }]) expect(code(() => parseRecord("a.example. IN A 10.0.0.1", { ttl }))).toBe("BAD_PRESENTATION");
	});

	it("a default class out of range or of the wrong type is refused", () => {
		for (const cls of [{ x: 1 }, 70000, -1, "IN", 1.5]) expect(code(() => parseRecord("a.example. 60 A 10.0.0.1", { class: cls }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("valid defaults still work", () => {
		expect(parseRecord("a.example. IN A 10.0.0.1", { ttl: 3600, class: 3 })).toEqual({ name: "a.example.", ttl: 3600, class: 3, type: TYPE.A, data: { address: "10.0.0.1" } });
	});
});
