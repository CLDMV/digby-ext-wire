/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/message.mjs
 */

/**
 * @fileoverview Whole messages (RFC 1035 4.1): decode and encode, with EDNS(0) lifted out of the additional section and
 * size-capped encoding with RFC 2181 9 truncation.
 *
 * Message shape:
 * ```
 * { id, flags: { qr, opcode, aa, tc, rd, ra, z, ad, cd }, rcode,
 *   questions: [{ name, type, class }],
 *   answers / authorities / additionals: [{ name, type, class, ttl, data }],
 *   edns: null | { udpSize, version, dnssecOk, z, options } }
 * ```
 * `rcode` is the full 12-bit value: its upper 8 bits travel in the OPT record, so a value over 15 needs `edns`. The OPT record
 * never appears in `additionals`; a TSIG record, when present, is the last one there. A record of class ANY or NONE with empty
 * rdata (the RFC 2136 update forms) has `data: null`.
 *
 * Decode never allocates from a claimed count: each section's array grows only as records are actually read from the bytes,
 * and every read is bounded by the input. A TTL with the top bit set reads as 0 (RFC 2181 8).
 */

import { MAX_MESSAGE, Reader, Writer, asBytes, checkInt } from "./buffer.mjs";
import { CLASS, TYPE } from "./constants.mjs";
import { joinOptTtl, readOptions, splitOptTtl, writeOptions } from "./edns.mjs";
import { WireError, WireErrorCode, fail } from "./errors.mjs";
import { HEADER_SIZE, TC_BIT, packFlags, unpackFlags } from "./header.mjs";
import { MAX_NAME_OCTETS, nameKey, readName, writeName } from "./names.mjs";
import { array, obj, string } from "./rdata/common.mjs";
import { decodeRdata, encodeRdata } from "./rdata/index.mjs";

const SECTIONS = ["answers", "authorities", "additionals"];
const MAX_TTL = 0x7fffffff;

/**
 * Decode a message.
 *
 * The decode bounds exist so one packet cannot make the decode allocate without bound: `maxQuestions` caps the question
 * section (a DNS query carries one question, so the server decode path keeps the default), and `maxNameOctets` caps the
 * name octets a decode newly materialises — with names memoised per message (see `readName`), a compression-pointer
 * fan-out that re-expands one name per pointer fails NAME_LIMIT instead of producing megabytes of strings.
 *
 * @param {Uint8Array|ArrayBuffer|ArrayBufferView} input
 * @param {object} [options]
 * @param {boolean} [options.allowTrailing=false] - accept octets after the last section instead of failing TRAILING_DATA
 * @param {number} [options.maxQuestions=1] - the most questions to decode; a larger qdcount fails QUESTION_LIMIT. Raise it
 *   only for a caller that legitimately decodes multi-question messages (round-trip tooling does).
 * @param {number} [options.maxNameOctets=MAX_NAME_OCTETS] - the most name label octets one decode may format for the first
 *   time (repeated names and suffixes come back from the memo for free); going over fails NAME_LIMIT
 * @returns {object} the message (shape above)
 * @throws {WireError} for any malformed input; nothing else
 */
export function decodeMessage(input, { allowTrailing = false, maxQuestions = 1, maxNameOctets = MAX_NAME_OCTETS } = {}) {
	const bytes = asBytes(input);
	if (bytes.length > MAX_MESSAGE) fail(WireErrorCode.INPUT_TOO_LARGE, `a message is at most ${MAX_MESSAGE} octets, got ${bytes.length}`);
	checkInt(maxQuestions, 0xffff, "maxQuestions");
	checkInt(maxNameOctets, Number.MAX_SAFE_INTEGER, "maxNameOctets");
	const r = new Reader(bytes);
	if (bytes.length < HEADER_SIZE) fail(WireErrorCode.TRUNCATED, `a message is at least ${HEADER_SIZE} octets, got ${bytes.length}`, 0);
	const id = r.u16();
	const { flags, rcode: rcodeLow } = unpackFlags(r.u16());
	const qd = r.u16();
	const counts = [r.u16(), r.u16(), r.u16()];

	// Per-decode name state, read by readName (see names.mjs): the start-offset memo of decoded names and the running
	// count of newly materialised name octets against the cap.
	r.nameMemo = new Map();
	r.nameOctets = 0;
	r.maxNameOctets = maxNameOctets;

	const questions = [];
	for (let i = 0; i < qd; i++) {
		if (i >= maxQuestions) fail(WireErrorCode.QUESTION_LIMIT, `the message declares ${qd} questions, more than the ${maxQuestions} the decode allows`, r.pos);
		questions.push({ name: readName(r), type: r.u16(), class: r.u16() });
	}

	const message = { id, flags, rcode: rcodeLow, questions, answers: [], authorities: [], additionals: [], edns: null };
	let extendedRcode = 0;
	for (let s = 0; s < 3; s++) {
		const list = message[SECTIONS[s]];
		for (let i = 0; i < counts[s]; i++) {
			const at = r.pos;
			const rec = readRecord(r);
			if (rec.type === TYPE.OPT) {
				if (s !== 2 || rec.name !== ".") fail(WireErrorCode.OPT_MISPLACED, "OPT must be in the additional section with the root as owner", at);
				if (message.edns) fail(WireErrorCode.MULTIPLE_OPT, "more than one OPT record", at);
				const { extendedRcode: ext, ...rest } = rec.opt;
				extendedRcode = ext;
				message.edns = rest;
				continue;
			}
			if (rec.type === TYPE.TSIG && (s !== 2 || i !== counts[2] - 1))
				fail(WireErrorCode.TSIG_MISPLACED, "TSIG must be the last record of the additional section", at);
			list.push(rec);
		}
	}
	if (r.pos !== bytes.length && !allowTrailing) fail(WireErrorCode.TRAILING_DATA, `${bytes.length - r.pos} octet(s) after the last section`, r.pos);
	message.rcode = (extendedRcode << 4) | rcodeLow;
	return message;
}

/**
 * Read one resource record.
 * @param {Reader} r
 */
function readRecord(r) {
	const name = readName(r);
	const type = r.u16();
	const cls = r.u16();
	const ttl = r.u32();
	const rdlength = r.u16();
	if (type === TYPE.OPT) {
		const options = r.limit(rdlength, () => readOptions(r));
		return { name, type, opt: { ...splitOptTtl(ttl), udpSize: cls, options } };
	}
	let data;
	if (rdlength === 0 && (cls === CLASS.ANY || cls === CLASS.NONE)) data = null;
	else data = r.limit(rdlength, () => decodeRdata(type, r));
	return { name, type, class: cls, ttl: ttl > MAX_TTL ? 0 : ttl, data };
}

/**
 * Encode a message. Names are compressed (owner names, questions, and the rdata of NS, CNAME, SOA, PTR and MX).
 *
 * @param {object} message - shape above; `flags`, the section arrays and `edns` may be omitted
 * @param {object} [options]
 * @param {number} [options.maxSize=65535] - fail MESSAGE_TOO_LARGE rather than produce more octets than this
 * @param {boolean} [options.compress=true]
 * @returns {Uint8Array}
 * @throws {WireError}
 */
export function encodeMessage(message, { maxSize = MAX_MESSAGE, compress = true } = {}) {
	checkInt(maxSize, MAX_MESSAGE, "maxSize");
	return encodeCapped(message, { limit: maxSize, truncate: false, compress }).bytes;
}

/**
 * Encode a message into at most `limit` octets, truncating when it does not fit (RFC 2181 9): whole RRsets are dropped, never
 * part of one. An answer or authority RRset that does not fit sets TC and drops it and everything after it; an additional
 * RRset that does not fit is dropped with the rest of the additional section, without TC (it is optional data). The OPT and
 * TSIG records are always kept: each RRset is only kept when they still fit after it. Each section's records of one RRset
 * travel together even when the message interleaved them with other sets: they come out grouped, in first-seen set order
 * (CLDMV/digby#36), so the surviving sets keep the order they were first seen in.
 *
 * @param {object} message
 * @param {object} options
 * @param {number} options.limit - the size cap in octets (at least 12)
 * @param {boolean} [options.truncate=true]
 * @param {boolean} [options.compress=true]
 * @returns {{ bytes: Uint8Array, truncated: boolean }}
 * @throws {WireError} MESSAGE_TOO_LARGE when even the header, questions, OPT and TSIG exceed the limit
 */
export function encodeCapped(message, { limit, truncate = true, compress = true }) {
	checkInt(limit, MAX_MESSAGE, "limit");
	obj(message, "message");
	const questions = array(message.questions ?? [], "questions");
	const sections = SECTIONS.map((k) => array(message[k] ?? [], k));
	const edns = message.edns ?? null;
	const rcode = message.rcode ?? 0;
	checkInt(rcode, 0xfff, "rcode");
	if (rcode > 0xf && !edns) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `rcode ${rcode} needs EDNS (its upper bits live in the OPT record)`);

	// split off a trailing TSIG; refuse OPT and misplaced TSIG records
	let tsig = null;
	sections.forEach((list, s) =>
		list.forEach((rec, i) => {
			obj(rec, "a record");
			if (rec.type === TYPE.OPT) fail(WireErrorCode.OPT_MISPLACED, "give EDNS as message.edns, not as an OPT record");
			if (rec.type === TYPE.TSIG) {
				if (s !== 2 || i !== list.length - 1) fail(WireErrorCode.TSIG_MISPLACED, "TSIG must be the last record of the additional section");
				tsig = rec;
			}
		})
	);
	if (tsig) sections[2] = sections[2].slice(0, -1);

	const w = new Writer({ max: truncate ? MAX_MESSAGE : limit, compress });
	const writeTail = () => {
		if (edns) writeOpt(w, edns, rcode >>> 4);
		if (tsig) writeRecord(w, tsig);
	};
	// An upper bound on the tail's size: written uncompressed into a scratch writer, once.
	const scratch = new Writer({ compress: false });
	if (edns) writeOpt(scratch, edns, rcode >>> 4);
	if (tsig) writeRecord(scratch, tsig);
	const tailBound = scratch.length;
	// Whether the tail (OPT, TSIG) still fits after what is written now. The bound settles it almost always; near the limit,
	// write the tail for real, measure and roll it back, since the TSIG owner may compress against names written so far.
	const tailFits = () => {
		if (w.length + tailBound <= limit) return true;
		const mark = w.checkpoint();
		try {
			writeTail();
			return w.length <= limit;
		} catch (err) {
			if (err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE) return false;
			throw err;
		} finally {
			w.rollback(mark);
		}
	};
	w.u16(checkedId(message.id));
	w.u16(packFlags(message.flags ?? {}, rcode & 0xf));
	w.u16(questions.length);
	const countAt = w.length;
	w.u16(0);
	w.u16(0);
	w.u16(0);
	for (const q of questions) {
		obj(q, "a question");
		writeName(w, string(q.name, "question name"), true);
		w.u16(q.type);
		w.u16(q.class ?? CLASS.IN);
	}
	if (!tailFits()) fail(WireErrorCode.MESSAGE_TOO_LARGE, `the header, questions, OPT and TSIG alone exceed ${limit} octets`);

	const written = [0, 0, 0];
	let truncated = false;
	outer: for (let s = 0; s < 3; s++) {
		for (const set of rrsets(sections[s])) {
			const mark = w.checkpoint();
			let fits = true;
			try {
				for (const rec of set) writeRecord(w, rec);
				fits = w.length <= limit && tailFits();
			} catch (err) {
				if (!(truncate && err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE)) throw err;
				fits = false;
			}
			if (!fits) {
				if (!truncate) fail(WireErrorCode.MESSAGE_TOO_LARGE, `the encoding exceeds ${limit} octets`);
				w.rollback(mark);
				if (s < 2) truncated = true;
				break outer;
			}
			written[s] += set.length;
		}
	}
	writeTail();
	if (edns) written[2]++;
	if (tsig) written[2]++;
	written.forEach((n, i) => w.patch16(countAt + i * 2, n));
	if (truncated) w.patch16(2, ((w.bytes[2] << 8) | w.bytes[3]) | TC_BIT);
	return { bytes: w.finish(), truncated };
}

function checkedId(id) {
	checkInt(id ?? 0, 0xffff, "id");
	return id ?? 0;
}

/**
 * Group a section's records into RRsets: same owner (case-insensitive), type and class; an RRSIG also by the type it covers.
 * Records with the same key form one RRset wherever they sit in the section (RFC 2181 9: a partial RRset is never sent), so
 * the sets come out in first-seen order, each with its records in section order — a section whose RRsets interleave comes
 * out regrouped.
 * @param {object[]} list
 * @returns {object[][]}
 */
function rrsets(list) {
	const sets = [];
	const byKey = new Map();
	for (const rec of list) {
		const k = `${nameKey(string(rec.name, "record name"))}|${rec.type}|${rec.class ?? CLASS.IN}|${rec.type === TYPE.RRSIG ? rec.data?.typeCovered : ""}`;
		let set = byKey.get(k);
		if (set === undefined) {
			set = [];
			byKey.set(k, set);
			sets.push(set);
		}
		set.push(rec);
	}
	return sets;
}

/**
 * Write one resource record.
 * @param {Writer} w
 * @param {object} rec
 */
function writeRecord(w, rec) {
	const cls = rec.class ?? CLASS.IN;
	writeName(w, string(rec.name, "record name"), true);
	w.u16(rec.type);
	w.u16(cls);
	checkInt(rec.ttl, MAX_TTL, "ttl");
	w.u32(rec.ttl);
	const lenAt = w.length;
	w.u16(0);
	if (rec.data === null) {
		if (cls !== CLASS.ANY && cls !== CLASS.NONE) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "empty rdata (data: null) is only for class ANY or NONE");
	} else {
		encodeRdata(w, rec.type, rec.data);
	}
	w.patch16(lenAt, w.length - lenAt - 2);
}

/**
 * Write the OPT pseudo-record.
 * @param {Writer} w
 * @param {object} edns
 * @param {number} extendedRcode
 */
function writeOpt(w, edns, extendedRcode) {
	obj(edns, "edns");
	w.u8(0); // root owner
	w.u16(TYPE.OPT);
	w.u16(edns.udpSize ?? 512);
	w.u32(joinOptTtl(extendedRcode, edns));
	const lenAt = w.length;
	w.u16(0);
	writeOptions(w, edns.options ?? []);
	w.patch16(lenAt, w.length - lenAt - 2);
}
