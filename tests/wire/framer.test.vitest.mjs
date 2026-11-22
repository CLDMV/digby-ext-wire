/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/framer.test.vitest.mjs
 */

import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import { WireError } from "../../src/lib/wire/errors.mjs";
import { TcpFramer, frameTcp } from "../../src/lib/wire/limits.mjs";

/**
 * Deterministic pseudo-random payload (a plain LCG, so a failure is reproducible).
 * @param {number} n
 * @param {number} seed
 * @returns {Uint8Array}
 */
const payload = (n, seed = 1) => {
	const b = new Uint8Array(n);
	let s = seed >>> 0;
	for (let i = 0; i < n; i++) {
		s = (s * 1103515245 + 12345) >>> 0;
		b[i] = s >>> 16;
	}
	return b;
};

const code = (fn) => {
	try {
		fn();
	} catch (err) {
		if (!(err instanceof WireError)) throw err;
		return err.code;
	}
	return "no error";
};

/** Push `chunk` one octet at a time and collect every completed frame. */
const byteByByte = (framer, chunk) => {
	const out = [];
	for (let i = 0; i < chunk.length; i++) out.push(...framer.push(chunk.subarray(i, i + 1)));
	return out;
};

describe("TcpFramer buffering", () => {
	it("reassembles a frame whose length prefix is split across pushes", () => {
		const f = new TcpFramer();
		const frame = frameTcp(payload(300, 7));
		expect(f.push(frame.subarray(0, 1))).toEqual([]);
		expect(f.buffered).toBe(1);
		expect(f.push(frame.subarray(1, 2))).toEqual([]);
		// the prefix is now known, but no payload octet has arrived yet: both held octets are the prefix
		expect(f.buffered).toBe(2);
		expect(f.push(frame.subarray(2))).toEqual([frame.subarray(2)]);
		expect(f.buffered).toBe(0);
	});

	it("keeps filling a partial frame when further chunks arrive", () => {
		const f = new TcpFramer();
		const body = payload(1000, 2);
		const frame = frameTcp(body);
		expect(f.push(frame.subarray(0, 500))).toEqual([]);
		// 500 octets held: the 2-octet prefix plus 498 payload octets
		expect(f.buffered).toBe(500);
		expect(f.push(frame.subarray(500, 900))).toEqual([]);
		expect(f.buffered).toBe(900);
		expect(f.push(frame.subarray(900))).toEqual([body]);
		expect(f.buffered).toBe(0);
	});

	it("splits several whole frames out of one chunk, each an independent copy of the source", () => {
		const f = new TcpFramer();
		const one = frameTcp(payload(100, 3));
		const two = frameTcp(payload(0, 0));
		const three = frameTcp(payload(40000, 4));
		const chunk = new Uint8Array(one.length + two.length + three.length);
		chunk.set(one, 0);
		chunk.set(two, one.length);
		chunk.set(three, one.length + two.length);
		const out = f.push(chunk);
		expect(out).toHaveLength(3);
		expect(out[0]).toEqual(payload(100, 3));
		expect(out[1]).toEqual(new Uint8Array(0));
		expect(out[2]).toEqual(payload(40000, 4));
		// no aliasing with the caller's chunk: overwrite every source octet, the frames must not change
		chunk.fill(0xaa);
		expect(out[0]).toEqual(payload(100, 3));
		expect(out[1]).toEqual(new Uint8Array(0));
		expect(out[2]).toEqual(payload(40000, 4));
	});

	it("does not hand out state a later push would overwrite", () => {
		const f = new TcpFramer();
		const first = f.push(frameTcp(payload(50, 5)))[0];
		expect(first).toEqual(payload(50, 5));
		// a second frame goes through the same framer; the first extraction must be untouched
		f.push(frameTcp(payload(50, 6)));
		expect(first).toEqual(payload(50, 5));
	});

	it("treats an empty chunk as a no-op, mid-frame or not", () => {
		const f = new TcpFramer();
		expect(f.push(new Uint8Array(0))).toEqual([]);
		expect(f.buffered).toBe(0);
		f.push(Uint8Array.of(0, 4, 1, 2));
		expect(f.buffered).toBe(4);
		expect(f.push(new Uint8Array(0))).toEqual([]);
		expect(f.buffered).toBe(4);
		expect(f.push(Uint8Array.of(3, 4))).toEqual([Uint8Array.of(1, 2, 3, 4)]);
		expect(f.buffered).toBe(0);
	});

	it("accepts the maximum-length frame and reports it whole", () => {
		const f = new TcpFramer();
		const body = payload(65535, 8);
		const frame = frameTcp(body);
		expect(frame.length).toBe(65537);
		expect(f.push(frame)).toEqual([body]);
		// and split across pushes
		const g = new TcpFramer();
		expect(g.push(frame.subarray(0, 30000))).toEqual([]);
		expect(g.push(frame.subarray(30000))).toEqual([body]);
	});

	it("still rejects input that is not bytes", () => {
		const f = new TcpFramer();
		expect(code(() => f.push("nope"))).toBe("VALUE_OUT_OF_RANGE");
	});
});

describe("TcpFramer one-octet segments (CLDMV/digby#35)", () => {
	it("delivers a 64 KB frame pushed one octet at a time, byte-identical, well within the time bound", () => {
		// warm the JIT first, so the bound measures the framer and not first-call interpreter time
		byteByByte(new TcpFramer(), frameTcp(payload(1024, 10)));
		const body = payload(65535, 11);
		const frame = frameTcp(body);
		let out = [];
		let elapsed = Infinity;
		// best of three: a single sample on a shared runner picks up scheduling noise, the fastest of three does not
		for (let run = 0; run < 3; run++) {
			const f = new TcpFramer();
			out = [];
			const start = performance.now();
			for (let i = 0; i < frame.length; i++) out.push(...f.push(frame.subarray(i, i + 1)));
			elapsed = Math.min(elapsed, performance.now() - start);
		}
		expect(out).toHaveLength(1);
		expect(out[0]).toEqual(body);
		// Bound justification: the pre-fix framer re-concatenated `pending + chunk` on every push, which is quadratic in the
		// frame size — measured ~21 ms for one 8 KB frame, ~54 ms at 16 KB and ~371 ms at 64 KB fed one octet per push (and
		// ~707 ms for this exact sequence on the test runner pod). The fixed framer is linear in the frame size — one
		// preallocation, one copy per octet — measuring ~13 ms steady-state on a dev box and 55 ms worst-case (cold, contended
		// runner pod, single sample). Best-of-three plus a 100 ms bound leaves roughly 2x headroom over that worst observed
		// run and about 7x below the quadratic behaviour, so the assertion fails only when the regression is real.
		expect(elapsed).toBeLessThan(100);
	});

	it("delivers several frames back to back, all one octet at a time", () => {
		const bodies = [payload(1000, 21), payload(7, 22), payload(20000, 23), new Uint8Array(0), payload(65535, 24)];
		const stream = new Uint8Array(bodies.reduce((n, b) => n + b.length + 2, 0));
		let at = 0;
		for (const body of bodies) {
			stream[at++] = body.length >>> 8;
			stream[at++] = body.length & 0xff;
			stream.set(body, at);
			at += body.length;
		}
		const f = new TcpFramer();
		const out = byteByByte(f, stream);
		expect(out).toHaveLength(bodies.length);
		bodies.forEach((body, i) => expect(out[i]).toEqual(body));
		expect(f.buffered).toBe(0);
	});
});
