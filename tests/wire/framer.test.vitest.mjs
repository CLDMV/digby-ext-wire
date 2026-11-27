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

	it("does not hand out state a later push would overwrite, for a frame filled across pushes", () => {
		const f = new TcpFramer();
		const body = payload(5000, 5);
		const frame = frameTcp(body);
		f.push(frame.subarray(0, 1000));
		f.push(frame.subarray(1000, 4000));
		const first = f.push(frame.subarray(4000))[0];
		expect(first).toEqual(body);
		// a second frame delivered whole in one chunk
		f.push(frameTcp(payload(5000, 6)));
		expect(first).toEqual(body);
		// and a second frame filled across pushes too
		const body2 = payload(7000, 7);
		const frame2 = frameTcp(body2);
		f.push(frame2.subarray(0, 3000));
		f.push(frame2.subarray(3000));
		expect(first).toEqual(body);
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

describe("TcpFramer buffer growth (review of CLDMV/digby#35)", () => {
	it("holds only a small buffer while a declared 64 KB frame stalls after its prefix", () => {
		const f = new TcpFramer();
		f.push(Uint8Array.of(0xff, 0xff));
		// a 65535-octet frame is declared but only the 2 prefix octets arrived: capacity stays at the small floor, not 65535
		// — segment sizes are client-controlled, and 2,000 stalled connections must not pin ~131 MB
		expect(f.capacity).toBe(4096);
		f.push(new Uint8Array(100));
		expect(f.capacity).toBe(4096);
		expect(f.buffered).toBe(102);
	});

	it("doubles capacity as payload arrives and delivers the frame byte-identical", () => {
		const f = new TcpFramer();
		const body = payload(65535, 31);
		const frame = frameTcp(body);
		f.push(frame.subarray(0, 2));
		expect(f.capacity).toBe(4096);
		f.push(frame.subarray(2, 4098));
		// the buffer filled to capacity but the chunk ended with it: no growth until more octets need room
		expect(f.capacity).toBe(4096);
		const out = f.push(frame.subarray(4098, 4099));
		expect(out).toEqual([]);
		expect(f.capacity).toBe(8192);
		// the rest of the frame walks the doubling ladder up to the declared length and completes
		expect(f.push(frame.subarray(4099))).toEqual([body]);
		// handed out and nothing held: no capacity pinned
		expect(f.capacity).toBe(0);
		expect(f.buffered).toBe(0);
	});

	it("sizes capacity to the octets actually received when one chunk carries most of a frame", () => {
		const f = new TcpFramer();
		const body = payload(60000, 32);
		const frame = frameTcp(body);
		expect(f.push(frame.subarray(0, 50002))).toEqual([]);
		// prefix + 50000 payload received: capacity matches what arrived, no floor-padding and not the full 60000
		expect(f.capacity).toBe(50002);
		expect(f.push(frame.subarray(50002))).toEqual([body]);
	});
});

describe("TcpFramer one-octet segments (CLDMV/digby#35)", () => {
	it("delivers a 64 KB frame pushed one octet at a time, byte-identical, with linear scaling", () => {
		// warm the JIT first, so the bounds measure the framer and not first-call interpreter time
		byteByByte(new TcpFramer(), frameTcp(payload(1024, 10)));
		const runOnce = (n, seed) => {
			const body = payload(n, seed);
			const frame = frameTcp(body);
			let out = [];
			let best = Infinity;
			// best of three: a single sample on a shared runner picks up scheduling noise, the fastest of three does not
			for (let run = 0; run < 3; run++) {
				const f = new TcpFramer();
				out = [];
				const start = performance.now();
				for (let i = 0; i < frame.length; i++) out.push(...f.push(frame.subarray(i, i + 1)));
				best = Math.min(best, performance.now() - start);
			}
			expect(out).toHaveLength(1);
			expect(out[0]).toEqual(body);
			return best;
		};
		const t16 = runOnce(16383, 11);
		const t64 = runOnce(65535, 12);
		// Scaling bound (machine-independent; chosen over a bare absolute bound so the test cannot flake on a slow or loaded
		// runner): the pre-fix framer re-concatenated `pending + chunk` on every push — quadratic in the frame size, so
		// quadrupling 16 KB → 64 KB multiplies the time by ~16 (measured ~592 ms vs ~55 ms here). The fixed framer is linear —
		// one buffer grown by doubling, one copy per octet — so the ratio is ~4. 8 sits 2x above linear and 2x below quadratic,
		// failing only when the re-concatenation returns, regardless of machine speed. This ratio is the test's ONLY timing
		// guard: an absolute backstop (150 ms) stood here until it flaked under coverage instrumentation on shared runner
		// pods four rounds running (150.26 / 154.2 / 160.8 vs 150) while the isolated file passed every time — the ratio,
		// measured in the same run at the same instrumentation, cannot.
		expect(t64 / t16).toBeLessThan(8);
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
