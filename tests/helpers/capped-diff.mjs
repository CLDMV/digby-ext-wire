/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/helpers/capped-diff.mjs
 */

/**
 * @fileoverview Seeded generators of truncation-stress messages for the encodeCapped differential tests (CLDMV/digby#43),
 * mirroring the review harness' `diff.mjs`: a mulberry-style PRNG, and two message families — `genMessage` (mixed record
 * types with a filler TXT parking the stream near 0x4000) and `genC1` (the interleaved non-monotone channel: a long target
 * registered mid-stream whose landing is centred on the pointer boundary by construction). Everything is deterministic in
 * the seed, so a committed test pins a fixed case count, never a wall-time budget.
 */

import { CLASS, TYPE } from "../../src/lib/wire/constants.mjs";
import { encodeMessage } from "../../src/lib/wire/message.mjs";

const strs = (n, fillByte = 0x78) => {
	const out = [];
	let left = n;
	while (left > 255) {
		out.push(new Uint8Array(255).fill(fillByte));
		left -= 255;
	}
	out.push(new Uint8Array(Math.max(0, left)).fill(fillByte));
	return { strings: out };
};
const lab = (c, n) => c.repeat(Math.max(1, Math.min(62, n)));

function rng(seed) {
	let s = (seed * 2654435761 + 12345) >>> 0 || 1;
	return () => {
		s ^= s << 13;
		s >>>= 0;
		s ^= s >>> 17;
		s ^= s << 5;
		s >>>= 0;
		return s / 4294967296;
	};
}

const N1 = `${lab("w", 60)}.${lab("x", 63)}.example.`;
export function genMessage(seed) {
	const R = rng(seed);
	const ri = (a, b) => a + Math.floor(R() * (b - a + 1));
	const pick = (arr) => arr[Math.floor(R() * arr.length)];
	const family = seed % 5;
	const bases = [N1, `${lab("k", ri(20, 63))}.${lab("j", ri(1, 63))}.kk.`, `${lab("m", ri(1, 63))}.example.`, `s.q.`, `${lab("p", ri(30, 50))}.${N1}`];
	const target = () => (R() < 0.5 ? pick(bases) : `${lab(String.fromCharCode(97 + ri(0, 25)), ri(1, 63))}${ri(0, 9)}.${pick(bases)}`);
	const owners = ["a.t.", "b.t.", "c.t.", "e.t.", "l.t.", "y.t.", "z.t.", "A.t.", `${lab("o", ri(1, 63))}.t.`];
	const owner = () => pick(owners);
	const rec = () => {
		const t = R();
		const name = owner();
		if (t < 0.4) return { name, type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: target() } };
		if (t < 0.5) return { name, type: TYPE.MX, class: CLASS.IN, ttl: 60, data: { preference: ri(0, 50), exchange: target() } };
		if (t < 0.58) return { name, type: TYPE.SRV, class: CLASS.IN, ttl: 60, data: { priority: 1, weight: 1, port: 53, target: target() } };
		if (t < 0.68) return { name, type: TYPE.SOA, class: CLASS.IN, ttl: 60, data: { mname: target(), rname: target(), serial: 1, refresh: 2, retry: 3, expire: 4, minimum: 5 } };
		if (t < 0.8) return { name, type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: strs(ri(0, family === 3 ? 900 : 300)) };
		if (t < 0.9) return { name, type: TYPE.A, class: CLASS.IN, ttl: 60, data: { address: `1.2.3.${ri(0, 255)}` } };
		return { name, type: TYPE.CNAME, class: CLASS.IN, ttl: 60, data: { target: target() } };
	};
	// filler puts the stream near 0x4000
	const fillerTarget = 0x4000 - ri(-400, 700);
	const answers = [{ name: "f.t.", type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: strs(Math.max(0, fillerTarget - 40 - Math.floor(fillerTarget / 255))) }];
	const nA = ri(2, family === 4 ? 40 : 16);
	for (let i = 0; i < nA; i++) answers.push(rec());
	// sometimes a mid filler to make probe gaps (non-consecutive set records separated by kept octets)
	if (R() < 0.3) answers.splice(ri(1, answers.length), 0, { name: owner(), type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: strs(ri(100, 2000)) });
	const authorities = [];
	const additionals = [];
	if (R() < 0.4) for (let i = ri(1, 6); i > 0; i--) authorities.push(rec());
	if (R() < 0.5) for (let i = ri(1, 8); i > 0; i--) additionals.push(rec());
	// sometimes move the filler into authorities to put the boundary in a later section
	if (family === 2 && authorities.length > 0) {
		authorities.unshift(answers.shift());
		answers.splice(0, answers.length, ...answers.slice(0, 3));
	}
	const m = { id: seed & 0xffff, flags: { qr: true }, questions: [{ name: R() < 0.5 ? "q." : `${lab("q", ri(1, 63))}.t.`, type: TYPE.A, class: CLASS.IN }], answers, authorities, additionals };
	if (R() < 0.25) m.edns = { udpSize: 1232, version: 0, dnssecOk: R() < 0.5, z: 0, options: [] };
	return m;
}

// The c1-family generator, centred so the registrar's suffix lands within +-90 of 0x4000 (the non-monotone channel)
const c1Answers = (R, ri, filler, N, trailing, plan) => {
	const answers = [
		{ name: "f.t.", type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: strs(filler) },
		{ name: "e.t.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: "s.q." } },
		{ name: "l.t.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: "s.q." } },
		plan.reg,
		{ name: "e.t.", type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target: `p63.${N}` } }
	];
	for (const r of plan.tail) answers.push(r);
	return answers;
};
export function genC1(seed) {
	const R = rng(seed ^ 0x5bd1e995);
	const ri = (a, b) => a + Math.floor(R() * (b - a + 1));
	const pick = (arr) => arr[Math.floor(R() * arr.length)];
	const N = `${lab("w", ri(20, 60))}.${lab("x", ri(20, 63))}.example.`;
	const trailing = ri(1, 12);
	const regType = pick([TYPE.NS, TYPE.NS, TYPE.MX, TYPE.CNAME, TYPE.SOA]);
	const nameData = (type, t) => (type === TYPE.MX ? { preference: 1, exchange: t } : type === TYPE.SOA ? { mname: t, rname: `h.${t}`, serial: 1, refresh: 2, retry: 3, expire: 4, minimum: 5 } : type === TYPE.SRV ? { priority: 1, weight: 1, port: 1, target: t } : { target: t });
	const plan = { reg: { name: pick(["y.t.", "y.t.", "g.t."]), type: regType, class: CLASS.IN, ttl: 60, data: nameData(regType, N) }, tail: [] };
	for (let i = 0; i < trailing; i++) {
		const o = R() < 0.7 ? "l.t." : pick(["y.t.", "e.t.", "z.t.", "g.t.", "m.t."]);
		const ty = R() < 0.75 ? TYPE.NS : pick([TYPE.MX, TYPE.SOA, TYPE.SRV, TYPE.CNAME]);
		const t = R() < 0.8 ? `${lab(pick(["a", "b", "c"]), ri(1, 60))}${i}.${N}` : N;
		plan.tail.push({ name: o, type: ty, class: CLASS.IN, ttl: 60, data: nameData(ty, t) });
		if (R() < 0.2) plan.tail.push({ name: pick(["z.t.", "h.t."]), type: TYPE.A, class: CLASS.IN, ttl: 60, data: { address: "1.2.3.4" } });
		if (R() < 0.1) plan.tail.push({ name: "x.t.", type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: strs(ri(0, 400)) });
	}
	if (R() < 0.3) plan.tail.splice(ri(0, plan.tail.length), 0, { name: plan.reg.name, type: regType, class: CLASS.IN, ttl: 60, data: nameData(regType, `b.${N}`) });
	// centre: measure where N's first label lands at a probe filler, shift the filler so it lands near 0x4000
	const f0 = 16000;
	const probe = encodeMessage({ id: 1, flags: { qr: true }, questions: [{ name: "q.", type: TYPE.A, class: CLASS.IN }], answers: c1Answers(R, ri, f0, N, trailing, plan) });
	const first = N.split(".")[0];
	let landing = -1;
	for (let i = f0; i < probe.length - first.length; i++) if (probe[i] === first.length && probe[i + 1] === 0x77 && probe[i + first.length] === 0x77) {
		landing = i;
		break;
	}
	const filler = Math.max(0, f0 + (0x4000 - landing) + ri(-90, 90));
	const m = { id: 1, flags: { qr: true }, questions: [{ name: "q.", type: TYPE.A, class: CLASS.IN }], answers: c1Answers(R, ri, filler, N, trailing, plan), authorities: [], additionals: [] };
	if (R() < 0.25) m.authorities = m.answers.splice(5);
	if (R() < 0.3) m.additionals = [{ name: `n.${N}`, type: TYPE.A, class: CLASS.IN, ttl: 60, data: { address: "9.9.9.9" } }, { name: "s.q.", type: TYPE.A, class: CLASS.IN, ttl: 60, data: { address: "9.9.9.8" } }];
	if (R() < 0.15) m.additionals.push(...m.answers.splice(m.answers.length - ri(1, 3)));
	if (R() < 0.2) m.edns = { udpSize: 4096, version: 0, dnssecOk: true, z: 0, options: [] };
	return m;
}
