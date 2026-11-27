/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/helpers/capped-oracle.mjs
 */

/**
 * @fileoverview The best-fit reference for the encodeCapped differential tests (CLDMV/digby#43, round 8) and the message
 * shapes the boundary families build on. Shared by the encodeCapped test files so the oracle and the shapes stay in one
 * place.
 */

import { expect } from "vitest";
import { CLASS, TYPE } from "../../src/lib/constants.mjs";
import { WireError, WireErrorCode } from "../../src/lib/errors.mjs";
import { TC_BIT } from "../../src/lib/header.mjs";
import { nameKey } from "../../src/lib/names.mjs";
import { encodeCapped, encodeMessage } from "../../src/lib/message.mjs";
import { hex } from "./wire-gen.mjs";

/**
 * The best-fit reference (CLDMV/digby#43, round 8): the kept sets are the longest prefix of the message's RRsets, in
 * first-appearance order, whose encoding fits `limit` — and the reference finds that k by brute force, newest-first:
 * for k from the last set down it builds the message that keeps exactly the records of sets 0..k at their original
 * positions, encodes it with {@link encodeMessage} — so the bytes, compression included, are exactly what a
 * non-truncating encode of that prefix produces, which is also byte for byte what the codec's winning trial writes
 * (the dropped records sit after the kept ones or between them, and a record's encoding depends only on the records
 * before it, so their absence changes nothing) — and the first k whose encoding fits is the answer. It encodes up to
 * one prefix per set — quadratic — which is fine for a test oracle: it is exact by construction, where the codec's
 * model is only as exact as its machinery.
 *
 * TC follows the rule the codec documents: a prefix that drops an answer or authority set sets TC; one that drops
 * only additionals does not (RFC 2181 9). When no set fits, the kept prefix is empty — the header, questions and tail
 * alone, TC when an answer or authority set exists; if even that exceeds the limit the reference fails the same
 * MESSAGE_TOO_LARGE the codec's head gate raises.
 *
 * @param {object} message
 * @param {{ limit: number, truncate?: boolean, compress?: boolean }} options
 * @returns {{ bytes: Uint8Array, truncated: boolean }}
 */
export function oracleCapped(message, { limit, truncate = true, compress = true }) {
	if (!truncate) return { bytes: encodeMessage(message, { compress, maxSize: limit }), truncated: false };
	const sections = [message.answers ?? [], message.authorities ?? [], message.additionals ?? []];
	// the same per-section grouping the codec applies (same owner case-insensitively, type, class; an RRSIG also by
	// the type it covers), numbered per section and then laid end to end in first-appearance order — answers first,
	// then authorities, then additionals
	const grouping = sections.map((list) => {
		const byKey = new Map();
		const owner = new Array(list.length);
		let n = 0;
		for (let i = 0; i < list.length; i++) {
			const rec = list[i];
			const k = `${nameKey(rec.name)}|${rec.type}|${rec.class ?? CLASS.IN}|${rec.type === TYPE.RRSIG ? rec.data?.typeCovered : ""}`;
			let ix = byKey.get(k);
			if (ix === undefined) {
				ix = n++;
				byKey.set(k, ix);
			}
			owner[i] = ix;
		}
		return { owner, n };
	});
	const base = [0, grouping[0].n, grouping[0].n + grouping[1].n];
	const globalOf = (s, i) => base[s] + grouping[s].owner[i];
	const totalSets = grouping[0].n + grouping[1].n + grouping[2].n;
	const answerAuthoritySets = grouping[0].n + grouping[1].n;
	const filterTo = (k) => ({
		...message,
		answers: sections[0].filter((_, i) => globalOf(0, i) <= k),
		authorities: sections[1].filter((_, i) => globalOf(1, i) <= k),
		additionals: sections[2].filter((_, i) => globalOf(2, i) <= k)
	});
	const withTc = (bytes, truncated) => {
		if (truncated) bytes[2] |= TC_BIT >>> 8;
		return { bytes, truncated };
	};
	for (let k = totalSets - 1; k >= 0; k--) {
		try {
			return withTc(encodeMessage(filterTo(k), { compress, maxSize: limit }), k < answerAuthoritySets - 1);
		} catch (err) {
			if (err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE) continue;
			throw err;
		}
	}
	return withTc(encodeMessage({ ...message, answers: [], authorities: [], additionals: [] }, { compress, maxSize: limit }), answerAuthoritySets >= 1);
}

/** 63 strings of 255 `x` plus a remainder: a TXT record holding n octets of filler. */
export const txtFiller = (n) => {
	const strings = [];
	let left = n;
	while (left > 255) {
		strings.push(new Uint8Array(255).fill(0x78));
		left -= 255;
	}
	if (left > 0) strings.push(new Uint8Array(left).fill(0x78));
	return { strings };
};
export const bigTxt = (name, n) => ({ name, type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: txtFiller(n) });
export const txt = (name, n) => ({ name, type: TYPE.TXT, class: CLASS.IN, ttl: 60, data: txtFiller(n) });
export const ns = (name, target) => ({ name, type: TYPE.NS, class: CLASS.IN, ttl: 60, data: { target } });
export const srv = (name, target) => ({ name, type: TYPE.SRV, class: CLASS.IN, ttl: 60, data: { priority: 1, weight: 2, port: 3, target } });
export const x63 = "x".repeat(63);

/**
 * The C1 repro of round 7 (CLDMV/digby#43), sharpened by round 8: a message whose full encode fits the limit, but whose
 * stop-at-first-miss prefix keep stops early. The y.t. record writes N at an offset just below 0x4000 and registers it,
 * so the l.t. records' targets (a60<i>.N) compress against it — but the l.t. set is decided BEFORE the y.t. set, and the
 * drop-here stream at the l.t. set (the y.t. record absent) writes every a60<i>.N target in full, which does not fit at
 * a limit the whole message fits. Stream size is not monotone in the sets kept.
 * @param {number} trailing
 * @param {number} [filler]
 * @returns {object}
 */
export const c1Shape = (trailing, filler = 16236) => {
	const N = `${"w".repeat(60)}.${"x".repeat(63)}.example.`;
	const a60 = (i) => `${"a".repeat(60)}${i}`;
	return {
		id: 1,
		flags: { qr: true },
		questions: [{ name: "q.", type: TYPE.A, class: CLASS.IN }],
		answers: [
			bigTxt("f.t.", filler),
			ns("e.t.", "s.q."),
			ns("l.t.", "s.q."),
			ns("y.t.", N),
			ns("e.t.", `p63.${N}`),
			...Array.from({ length: trailing }, (_, i) => ns("l.t.", `${a60(i + 1)}.${N}`))
		]
	};
};

/**
 * The stream offset where writeName registers the y.t. record's N key: the record's rdata start, read off the wire.
 * Names here may be pointers (the owners share the "t." suffix with earlier records), so the walk follows the envelope:
 * a label length of 0xc0 or more is a pointer and ends the name. The landing moves one octet per filler octet (the TXT
 * rdata grows by one string-length octet every 255 filler octets, which the sweep window stays clear of).
 * @param {number} filler
 * @returns {number}
 */
export const landingOf = (filler) => {
	const bytes = encodeMessage(c1Shape(1, filler));
	let at = 12;
	const skipName = () => {
		for (;;) {
			const len = bytes[at];
			if (len >= 0xc0) {
				at += 2;
				return;
			}
			at += 1 + len;
			if (len === 0) return;
		}
	};
	skipName(); // the question
	at += 4;
	for (let i = 0; i < 3; i++) {
		// records 0..2: name, type, class, ttl, rdlength, rdata
		skipName();
		at += 10 + ((bytes[at + 8] << 8) | bytes[at + 9]);
	}
	skipName(); // the y.t. record's owner
	return at + 10; // its rdata start: type, class, ttl, rdlength
};

/**
 * Compare a capped encode against the best-fit reference, byte for byte. A truncating encode of a message without
 * exactly one question is refused (CLDMV/digby#43), so the shapes without a question can only be compared against the
 * reference where nothing drops; the one-question shapes keep the full comparison across every limit.
 * @param {object} m
 * @param {number} limit
 * @param {string} tag
 * @param {{ reserveTsig?: number }} [options]
 */
export function compareWithReference(m, limit, tag, options) {
	let capped;
	try {
		capped = encodeCapped(m, { limit, ...options });
	} catch (err) {
		expect(err, `${tag}: the refusal`).toBeInstanceOf(WireError);
		expect(err.code, `${tag}: the refusal code`).toBe("TRUNCATION_REFUSED");
		expect(m.questions.length, `${tag}: the refusal only fires without exactly one question`).toBe(0);
		return;
	}
	expect(capped.bytes.length, `${tag}: the capped encode stays within the limit`).toBeLessThanOrEqual(limit);
	const reference = oracleCapped(m, { limit: limit - (options?.reserveTsig ?? 0) });
	expect(capped.truncated, `${tag}: the truncation flag matches the best-fit reference`).toBe(reference.truncated);
	expect(hex.to(capped.bytes), `${tag}: the bytes match the best-fit reference`).toBe(hex.to(reference.bytes));
}

/**
 * The decision-boundary limits of a message: the sizes of every first-appearance set prefix and their neighbours — the
 * only limits where the best-fit answer can change — plus a fixed stride across the 800-octet window below the full
 * encode (repeated-encode coverage at fixed case count) and the full encode itself and its neighbours. The exhaustive
 * sweeps this replaces walked all ~800 limits; between two prefix sizes the kept prefix cannot change, so the
 * boundaries plus the stride cover every distinct output.
 * @param {object} m
 * @returns {number[]}
 */
export function boundaryLimits(m) {
	const sections = [m.answers ?? [], m.authorities ?? [], m.additionals ?? []];
	const grouping = sections.map((list) => {
		const byKey = new Map();
		const owner = new Array(list.length);
		let n = 0;
		for (let i = 0; i < list.length; i++) {
			const rec = list[i];
			const k = `${nameKey(rec.name)}|${rec.type}|${rec.class ?? CLASS.IN}|${rec.type === TYPE.RRSIG ? rec.data?.typeCovered : ""}`;
			let ix = byKey.get(k);
			if (ix === undefined) {
				ix = n++;
				byKey.set(k, ix);
			}
			owner[i] = ix;
		}
		return { owner, n };
	});
	const base = [0, grouping[0].n, grouping[0].n + grouping[1].n];
	const globalOf = (s, i) => base[s] + grouping[s].owner[i];
	const total = grouping[0].n + grouping[1].n + grouping[2].n;
	const sizes = [];
	for (let k = 0; k < total; k++)
		sizes.push(encodeMessage({
			...m,
			answers: sections[0].filter((_, i) => globalOf(0, i) <= k),
			authorities: sections[1].filter((_, i) => globalOf(1, i) <= k),
			additionals: sections[2].filter((_, i) => globalOf(2, i) <= k)
		}).length);
	const full = encodeMessage(m).length;
	const limits = new Set([full - 1, full, full + 1, full + 2]);
	for (const size of sizes) {
		limits.add(size - 1);
		limits.add(size);
		limits.add(size + 1);
	}
	for (let L = Math.max(12, full - 800); L <= full; L += 32) limits.add(L);
	return [...limits].sort((a, b) => a - b);
}

/**
 * Progress heartbeat for the long families: prints a line at most every 45 s so a pod run shows life well inside the
 * 60 s stall budget. The case counts are fixed; the heartbeat only reports position.
 * @param {string} tag
 * @param {number} done
 * @param {number} total
 */
export function beat(tag, done, total) {
	const now = Date.now();
	if (now - beat.last >= 45_000) {
		beat.last = now;
		process.stdout.write(`[${tag}] ${done}/${total}\n`);
	}
}
beat.last = 0;
