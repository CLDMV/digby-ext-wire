/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/limits.test.vitest.mjs
 */

import { describe, expect, it } from "vitest";
import { TYPE } from "../../src/lib/wire/constants.mjs";
import { WireError } from "../../src/lib/wire/errors.mjs";
import { DEFAULT_UDP_CAP, TCP_MAX, TcpFramer, UDP_MIN, encodeForTransport, frameTcp, udpLimit } from "../../src/lib/wire/limits.mjs";
import { appendTsig, decodeMessage, encodeCapped, tsigRecordSize } from "../../src/lib/wire/message.mjs";

const code = (fn) => {
	try {
		fn();
	} catch (err) {
		if (!(err instanceof WireError)) throw err;
		return err.code;
	}
	return "no error";
};

const Q = { name: "big.example.", type: TYPE.A, class: 1 };
const a = (name, i) => ({ name, type: TYPE.A, class: 1, ttl: 60, data: { address: `10.0.${i >> 8}.${i & 255}` } });
const rrset = (name, n) => Array.from({ length: n }, (_, i) => a(name, i));
const response = (parts = {}) => ({ id: 1, flags: { qr: true, rd: true, ra: true }, rcode: 0, questions: [Q], ...parts });

describe("UDP limits", () => {
	it("is 512 without EDNS, the advertised size capped by ours with it, and never below 512", () => {
		expect(UDP_MIN).toBe(512);
		expect(DEFAULT_UDP_CAP).toBe(1232);
		expect(udpLimit(null)).toBe(512);
		expect(udpLimit({ edns: null })).toBe(512);
		expect(udpLimit({ edns: { udpSize: 4096 } })).toBe(1232);
		expect(udpLimit({ edns: { udpSize: 1000 } })).toBe(1000);
		expect(udpLimit({ edns: { udpSize: 100 } })).toBe(512);
		expect(udpLimit({ edns: { udpSize: 4096 } }, { cap: 4096 })).toBe(4096);
		expect(udpLimit({ edns: { udpSize: 4096 } }, { cap: 100 })).toBe(512);
		expect(code(() => udpLimit(null, { cap: 70000 }))).toBe("VALUE_OUT_OF_RANGE");
	});
});

describe("truncation (RFC 2181 9)", () => {
	it("drops a whole answer RRset that does not fit and sets TC", () => {
		const msg = response({ answers: rrset("big.example.", 40) });
		const { bytes, truncated, limit } = encodeForTransport(msg, { transport: "udp" });
		expect(limit).toBe(512);
		expect(truncated).toBe(true);
		expect(bytes.length).toBeLessThanOrEqual(512);
		const m = decodeMessage(bytes);
		expect(m.flags.tc).toBe(true);
		expect(m.questions).toEqual([Q]);
		expect(m.answers).toEqual([]);
	});

	it("keeps the RRsets before the one that does not fit", () => {
		const cname = { name: "big.example.", type: TYPE.CNAME, class: 1, ttl: 60, data: { target: "real.example." } };
		const msg = response({ answers: [cname, ...rrset("real.example.", 40)], additionals: [a("x.example.", 1)] });
		const { bytes, truncated } = encodeForTransport(msg, { transport: "udp" });
		expect(truncated).toBe(true);
		const m = decodeMessage(bytes);
		expect(m.answers).toEqual([cname]);
		// nothing after the truncation point, even optional data that would fit
		expect(m.additionals).toEqual([]);
	});

	it("drops additional data that does not fit without setting TC", () => {
		const msg = response({ answers: rrset("big.example.", 2), additionals: [...rrset("ns1.example.", 2), ...rrset("ns2.example.", 40)] });
		const { bytes, truncated } = encodeForTransport(msg, { transport: "udp" });
		expect(truncated).toBe(false);
		const m = decodeMessage(bytes);
		expect(m.flags.tc).toBe(false);
		expect(m.answers).toHaveLength(2);
		expect(m.additionals.map((r) => r.name)).toEqual(["ns1.example.", "ns1.example."]);
	});

	it("sets TC when an authority RRset does not fit", () => {
		const msg = response({ authorities: rrset("big.example.", 40) });
		const { bytes, truncated } = encodeForTransport(msg, { transport: "udp" });
		expect(truncated).toBe(true);
		expect(decodeMessage(bytes).authorities).toEqual([]);
	});

	it("always keeps the OPT record, and the limit follows the query's EDNS size", () => {
		const options = [{ code: 15, infoCode: 0, extraText: "x".repeat(100) }];
		const msg = response({ answers: rrset("big.example.", 200), edns: { udpSize: 1232, version: 0, dnssecOk: false, z: 0, options } });
		const query = { edns: { udpSize: 4096 } };
		const { bytes, truncated, limit } = encodeForTransport(msg, { transport: "udp", query });
		expect(limit).toBe(1232);
		expect(truncated).toBe(true);
		expect(bytes.length).toBeLessThanOrEqual(1232);
		expect(decodeMessage(bytes).edns.options).toEqual(options);
		// with room for it, the RRset is sent whole
		const roomy = encodeForTransport(response({ answers: rrset("big.example.", 50) }), { transport: "udp", query, cap: 4096 });
		expect(roomy.truncated).toBe(false);
		expect(decodeMessage(roomy.bytes).answers).toHaveLength(50);
	});

	it("refuses a signed message; truncate first, sign, then append (CLDMV/digby#39)", () => {
		const tsig = {
			name: "key.example.",
			type: TYPE.TSIG,
			class: 255,
			ttl: 0,
			data: { algorithm: "hmac-sha256.", timeSigned: 1, fudge: 300, mac: new Uint8Array(32), originalId: 1, error: 0, otherData: new Uint8Array(0) }
		};
		const msg = response({ answers: rrset("big.example.", 40), additionals: [a("x.example.", 1), tsig] });
		// a transport encode may truncate, which would invalidate the TSIG's MAC
		expect(code(() => encodeForTransport(msg, { transport: "udp" }))).toBe("TSIG_PRESENT");
		// instead: encode unsigned with the record's size reserved, sign the truncated message, append
		const unsigned = { ...msg, additionals: [a("x.example.", 1)] };
		const need = tsigRecordSize(tsig);
		const capped = encodeCapped(unsigned, { limit: 512, reserveTsig: need });
		expect(capped.truncated).toBe(true);
		const signed = appendTsig(capped, tsig);
		expect(signed.length).toBeLessThanOrEqual(512);
		const d = decodeMessage(signed);
		expect(d.flags.tc).toBe(true);
		expect(d.additionals).toEqual([tsig]);
	});

	it("treats records with the same owner (any case), type and class as one RRset; RRSIGs by the type covered", () => {
		const sig = (covered, i) => ({
			name: "big.example.",
			type: TYPE.RRSIG,
			class: 1,
			ttl: 60,
			data: { typeCovered: covered, algorithm: 13, labels: 2, originalTtl: 60, expiration: 2, inception: 1, keyTag: i, signerName: "example.", signature: new Uint8Array(64) }
		});
		const answers = [a("big.example.", 1), a("BIG.example.", 2), sig(TYPE.A, 1), sig(TYPE.A, 2), sig(TYPE.AAAA, 3), sig(TYPE.AAAA, 4), sig(TYPE.AAAA, 5), sig(TYPE.AAAA, 6)];
		const bytes = encodeCapped(response({ answers }), { limit: 512 }).bytes;
		const m = decodeMessage(bytes);
		expect(m.flags.tc).toBe(true);
		// the A set and its two signatures fit; the four AAAA signatures together do not
		expect(m.answers.map((r) => (r.type === TYPE.RRSIG ? `RRSIG/${r.data.typeCovered}` : r.name))).toEqual(["big.example.", "BIG.example.", "RRSIG/1", "RRSIG/1"]);
	});

	it("refuses when even the header and question exceed the limit", () => {
		expect(code(() => encodeForTransport(response(), { transport: "udp", limit: 20 }))).toBe("MESSAGE_TOO_LARGE");
		const withOpt = response({ edns: { udpSize: 512, options: [{ code: 12, length: 600 }] } });
		expect(code(() => encodeForTransport(withOpt, { transport: "udp" }))).toBe("MESSAGE_TOO_LARGE");
		expect(code(() => encodeForTransport(response(), { transport: "sctp" }))).toBe("VALUE_OUT_OF_RANGE");
		expect(code(() => encodeCapped(response(), { limit: 65536 }))).toBe("VALUE_OUT_OF_RANGE");
	});

	it("truncates at the TCP limit of 65535 octets", () => {
		// 4200 records of ~16 octets: about 67 kB untruncated; split into RRsets of 100 so a prefix fits
		const answers = [];
		for (let s = 0; s < 42; s++) answers.push(...rrset(`set${s}.example.`, 100));
		const { bytes, truncated, limit } = encodeForTransport(response({ answers }), { transport: "tcp" });
		expect(limit).toBe(TCP_MAX);
		expect(truncated).toBe(true);
		expect(bytes.length).toBeLessThanOrEqual(65535);
		const m = decodeMessage(bytes);
		expect(m.answers.length % 100).toBe(0);
		expect(m.answers.length).toBeGreaterThan(3000);
		// and fits without truncation when it does fit
		const small = encodeForTransport(response({ answers: answers.slice(0, 1000) }), { transport: "tcp" });
		expect(small.truncated).toBe(false);
	});

	it("leaves the compression table consistent after a rollback", () => {
		// the dropped RRset introduced new suffixes; the OPT and nothing else follow, and the message decodes cleanly
		const msg = response({ answers: [a("keep.example.", 1), ...rrset("drop.longer-name.example.", 60)], edns: { udpSize: 512, options: [] } });
		const { bytes } = encodeForTransport(msg, { transport: "udp" });
		expect(decodeMessage(bytes).answers).toEqual([a("keep.example.", 1)]);
	});
});

describe("TCP framing", () => {
	it("prefixes the 2-octet length", () => {
		expect([...frameTcp(Uint8Array.of(1, 2, 3))]).toEqual([0, 3, 1, 2, 3]);
		expect(frameTcp(new Uint8Array(300)).subarray(0, 2)).toEqual(Uint8Array.of(1, 44));
		expect(code(() => frameTcp(new Uint8Array(65536)))).toBe("MESSAGE_TOO_LARGE");
	});

	it("reassembles frames split across chunks and splits several frames in one chunk", () => {
		const f = new TcpFramer();
		const one = frameTcp(Uint8Array.of(1, 2, 3));
		const two = frameTcp(Uint8Array.of(4));
		expect(f.push(one.subarray(0, 1))).toEqual([]);
		expect(f.buffered).toBe(1);
		expect(f.push(one.subarray(1, 3))).toEqual([]);
		expect(f.push(Uint8Array.from([...one.subarray(3), ...two]))).toEqual([Uint8Array.of(1, 2, 3), Uint8Array.of(4)]);
		expect(f.buffered).toBe(0);
		expect(f.push(Uint8Array.of(0, 0))).toEqual([new Uint8Array(0)]);
	});

	it("holds at most one partial frame", () => {
		const f = new TcpFramer();
		f.push(Uint8Array.of(0xff, 0xff));
		f.push(new Uint8Array(1000));
		expect(f.buffered).toBe(1002);
		expect(f.push(new Uint8Array(65535 - 1000))).toHaveLength(1);
		expect(f.buffered).toBe(0);
	});
});
