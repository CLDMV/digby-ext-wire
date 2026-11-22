/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/fuzz.test.vitest.mjs
 */

/**
 * A bounded, seeded fuzz run over the decoder and the presentation parser. Inputs are random octets and mutations of valid
 * encoded messages (bit flips, octet overwrites, inserted compression pointers, inflated counts and lengths, cuts and splices).
 *
 * For each input: decode returns or throws WireError, within a per-input time bound; a successful decode re-encodes (or fails
 * MESSAGE_TOO_LARGE only), the re-encoding decodes to the same message, and every decoded record round-trips through its
 * presentation form. Random text fed to the record parser either parses or throws WireError.
 *
 * The seed is printed on every run. Replay a failure with DIGBY_FUZZ_SEED=<seed>; DIGBY_FUZZ_ITERATIONS sets the count.
 */

import { describe, expect, it } from "vitest";
import { CLASS } from "../../src/lib/wire/constants.mjs";
import { WireError, WireErrorCode } from "../../src/lib/wire/errors.mjs";
import { decodeMessage, encodeMessage } from "../../src/lib/wire/message.mjs";
import { canonicalName } from "../../src/lib/wire/names.mjs";
import { formatRecord, parseRecord } from "../../src/lib/wire/presentation.mjs";
import { TYPED, decodeRdataBytes, encodeRdataBytes, formatRdata, parseRdata } from "../../src/lib/wire/rdata/index.mjs";
import { genMessage, genRdata, genRecord, hex, prng, seedFromEnv } from "../helpers/wire-gen.mjs";

const SEED = seedFromEnv("DIGBY_FUZZ_SEED");
const ITERATIONS = Number(process.env.DIGBY_FUZZ_ITERATIONS || 20000);
const PER_INPUT_MS = 250;
console.log(`wire fuzz: DIGBY_FUZZ_SEED=${SEED} iterations=${ITERATIONS}`);

/** A failure report carrying everything needed to replay it. */
function report(kind, input, err) {
	return new Error(`${kind} (seed ${SEED}) on input ${hex.to(input)}: ${err?.stack ?? err}`);
}

function mutate(g, base) {
	const b = Array.from(base);
	const rounds = g.int(1, 4);
	for (let k = 0; k < rounds; k++) {
		const at = b.length ? g.int(0, b.length - 1) : 0;
		switch (g.int(0, 8)) {
			case 0: // flip a bit
				if (b.length) b[at] ^= 1 << g.int(0, 7);
				break;
			case 1: // overwrite an octet
				if (b.length) b[at] = g.int(0, 255);
				break;
			case 2: // insert a compression pointer to anywhere (including forward and to itself)
				b.splice(at, 0, 0xc0 | g.int(0, 0x3f), g.int(0, 255));
				break;
			case 3: // inflate a header count
				if (b.length >= 12) {
					const c = 4 + 2 * g.int(0, 3);
					b[c] = g.int(0, 255);
					b[c + 1] = g.int(0, 255);
				}
				break;
			case 4: // cut the tail
				b.length = g.int(0, b.length);
				break;
			case 5: // delete a run
				b.splice(at, g.int(1, 8));
				break;
			case 6: // duplicate a run (repeats records, OPTs, labels)
				b.splice(at, 0, ...b.slice(at, at + g.int(1, 40)));
				break;
			case 7: // a large length byte pair somewhere (rdlength, option length, label length)
				b.splice(at, 2, g.int(0, 255), g.int(0, 255));
				break;
			default: // insert random octets
				for (let n = g.int(1, 6); n > 0; n--) b.splice(at, 0, g.int(0, 255));
		}
	}
	return Uint8Array.from(b.slice(0, 65535));
}

function checkInput(input) {
	const t0 = performance.now();
	let m;
	try {
		m = decodeMessage(input, { maxQuestions: 2 });
	} catch (err) {
		if (!(err instanceof WireError)) throw report("decode threw a non-WireError", input, err);
		if (!Object.values(WireErrorCode).includes(err.code)) throw report("decode threw an unknown code", input, err);
		return "rejected";
	} finally {
		const ms = performance.now() - t0;
		if (ms > PER_INPUT_MS) throw report(`decode took ${ms.toFixed(0)} ms`, input, "too slow");
	}
	let again;
	try {
		again = encodeMessage(m);
	} catch (err) {
		if (err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE) return "accepted";
		throw report("re-encoding a decoded message failed", input, err);
	}
	let back;
	try {
		back = decodeMessage(again, { maxQuestions: 2 });
	} catch (err) {
		throw report("the re-encoding did not decode", input, err);
	}
	try {
		// the encoder keeps record order — record order is meaning, even when a section's RRsets interleave
		// (CLDMV/digby#36) — so the re-encoding decodes to exactly what was decoded
		expect(back).toEqual(m);
	} catch (err) {
		throw report("the re-encoding decoded differently", input, err);
	}
	for (const rec of [...m.answers, ...m.authorities, ...m.additionals]) {
		if (rec.data === null) continue;
		let text;
		try {
			text = formatRdata(rec.type, rec.data);
			expect(parseRdata(rec.type, text)).toEqual(rec.data);
			expect(parseRecord(formatRecord(rec))).toEqual(rec);
		} catch (err) {
			throw report(`presentation round-trip of type ${rec.type} failed (${text})`, input, err);
		}
	}
	return "accepted";
}

const TEXT_ALPHABET = ' \t\n()";\\.@$#abcAZ09-=,:/+=';
const TEXT_WORDS = ["A", "AAAA", "TXT", "MX", "SOA", "SVCB", "HTTPS", "NSEC", "RRSIG", "CAA", "IN", "3600", "\\#", "alpn=", "key65000", "TYPE99", "1.2.3.4", "::1", "example."];

describe(`wire fuzz (seed ${SEED}, ${ITERATIONS} iterations)`, () => {
	it("decode returns or throws WireError, and what it returns survives re-encoding and presentation", () => {
		const g = prng(SEED);
		const seeds = Array.from({ length: 64 }, () => encodeMessage(genMessage(g)));
		const tally = { accepted: 0, rejected: 0 };
		const heapBefore = process.memoryUsage().heapUsed;
		const started = performance.now();
		for (let i = 0; i < ITERATIONS; i++) {
			const input = g.chance(0.15) ? g.bytes(0, 600) : mutate(g, g.pick(seeds));
			tally[checkInput(input)]++;
		}
		const elapsed = performance.now() - started;
		const heapGrowth = process.memoryUsage().heapUsed - heapBefore;
		console.log(`wire fuzz: ${tally.accepted} accepted, ${tally.rejected} rejected in ${elapsed.toFixed(0)} ms, heap +${(heapGrowth / 1e6).toFixed(1)} MB`);
		// nothing is retained between inputs: the heap must not grow with the iteration count
		expect(heapGrowth).toBeLessThan(256 * 1024 * 1024);
		// both outcomes are exercised, or the mutator is not doing its job
		expect(tally.accepted).toBeGreaterThan(ITERATIONS / 50);
		expect(tally.rejected).toBeGreaterThan(ITERATIONS / 50);
	});

	it("the record parser parses or throws WireError on random text", () => {
		const g = prng(SEED ^ 0x9e3779b9);
		for (let i = 0; i < ITERATIONS / 4; i++) {
			let text = "";
			for (let n = g.int(0, 12); n > 0; n--) text += g.chance(0.5) ? g.pick(TEXT_WORDS) + " " : TEXT_ALPHABET[g.int(0, TEXT_ALPHABET.length - 1)];
			try {
				const rec = parseRecord(text, { origin: "example.", ttl: 60 });
				expect(parseRecord(formatRecord(rec))).toEqual(rec);
			} catch (err) {
				if (!(err instanceof WireError)) throw new Error(`parseRecord threw a non-WireError (seed ${SEED}) on ${JSON.stringify(text)}: ${err?.stack ?? err}`);
			}
		}
	});

	// Malformed API-supplied shapes must reach the formatters as WireError (or come back as valid text), never a TypeError,
	// undefined or injected record text (CLDMV/digby#37).
	const MANGLE_VALUES = [undefined, null, 0, -1, 1.5, 2 ** 32, true, "", "x;y", "1 IN A 9.9.9.9 ;", "a. b", [], {}, [1, 2, 3], { address: "1.2.3.4" }];

	/** A copy of a valid rdata / record object with one field deleted, mistyped or replaced wholesale. */
	function mangle(g, data) {
		if (data === null || typeof data !== "object") return g.pick(MANGLE_VALUES);
		const out = { ...data };
		const keys = Object.keys(out);
		if (!keys.length || g.chance(0.15)) return g.pick(MANGLE_VALUES);
		const k = g.pick(keys);
		switch (g.int(0, 3)) {
			case 0:
				delete out[k];
				break;
			case 1:
				out[k] = g.pick(MANGLE_VALUES);
				break;
			case 2:
				out[k] = Array.isArray(out[k]) ? [...out[k], g.pick(MANGLE_VALUES)] : [out[k], g.pick(MANGLE_VALUES)];
				break;
			default:
				out[k] = { ...out[k], extra: "1 IN A 9.9.9.9 ;" };
		}
		return out;
	}

	const reportShape = (kind, shape, err) => new Error(`${kind} (seed ${SEED}) on ${JSON.stringify(shape, (_, v) => (v instanceof Uint8Array ? hex.to(v) : String(v)))}: ${err?.stack ?? err}`);

	it("the formatters take malformed shapes only as WireError or valid text", () => {
		const g = prng(SEED ^ 0x811c9dc5);
		const codes = Object.values(WireErrorCode);
		for (let i = 0; i < ITERATIONS / 4; i++) {
			const type = g.chance(0.8) ? g.pick(TYPED) : 1234 + (i % 5000); // typed most of the time, otherwise generic
			const data = mangle(g, genRdata(g, type, []));
			try {
				const text = formatRdata(type, data);
				if (typeof text !== "string") throw reportShape("formatRdata returned a non-string", { type, data }, text);
				let parsed;
				try {
					parsed = parseRdata(type, text);
				} catch (err) {
					if (!(err instanceof WireError)) throw reportShape("the formatted text did not re-parse as WireError-or-value", { type, data }, err);
				}
				// when the text does re-parse, it must be exactly the presentation of the input's wire round-trip — text that parses
				// to anything else is a divergence too (CLDMV/digby#37)
				if (parsed !== undefined) {
					let canonical;
					try {
						canonical = decodeRdataBytes(type, encodeRdataBytes(type, data));
					} catch (err) {
						throw reportShape("the formatted text re-parsed but the input does not survive a wire round-trip", { type, data }, err);
					}
					try {
						expect(parsed).toEqual(canonical);
					} catch (err) {
						throw reportShape("the formatted text re-parsed to a different value than the input's canonical form", { type, data }, err);
					}
				}
			} catch (err) {
				if (!(err instanceof WireError) || !codes.includes(err.code)) throw reportShape("formatRdata threw a non-WireError", { type, data }, err);
			}
			const rec = genRecord(g, []);
			const field = g.pick(["name", "ttl", "class", "type", "data"]);
			const bad =
				field === "name"
					? { ...rec, name: g.pick(["a.", "a;b.", "", 5, "..", "@"]) }
					: field === "data"
						? { ...rec, data: mangle(g, rec.data) }
						: { ...rec, [field]: g.pick(MANGLE_VALUES) };
			try {
				const text = formatRecord(bad);
				if (typeof text !== "string") throw reportShape("formatRecord returned a non-string", bad, text);
				let parsed;
				try {
					parsed = parseRecord(text);
				} catch (err) {
					if (!(err instanceof WireError)) throw reportShape("the formatted record did not re-parse as WireError-or-value", bad, err);
				}
				// the same rule for the whole record line: a line that re-parses must re-parse to the record's canonical form
				// (CLDMV/digby#37)
				if (parsed !== undefined) {
					let canonicalData = null;
					if (bad.data !== null) {
						try {
							canonicalData = decodeRdataBytes(bad.type, encodeRdataBytes(bad.type, bad.data));
						} catch (err) {
							throw reportShape("the formatted record re-parsed but its rdata does not survive a wire round-trip", bad, err);
						}
					}
					try {
						expect(parsed).toEqual({ name: canonicalName(bad.name), ttl: bad.ttl, class: bad.class ?? CLASS.IN, type: bad.type, data: canonicalData });
					} catch (err) {
						throw reportShape("the formatted record re-parsed to a different record than the input's canonical form", bad, err);
					}
				}
			} catch (err) {
				if (!(err instanceof WireError) || !codes.includes(err.code)) throw reportShape("formatRecord threw a non-WireError", bad, err);
			}
		}
	});
});
