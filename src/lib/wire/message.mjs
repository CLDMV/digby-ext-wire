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
import { CLASS, OPCODE, TYPE, classToString, typeToString } from "./constants.mjs";
import { joinOptTtl, readOptions, splitOptTtl, writeOptions } from "./edns.mjs";
import { WireError, WireErrorCode, fail } from "./errors.mjs";
import { HEADER_SIZE, TC_BIT, packFlags, unpackFlags } from "./header.mjs";
import { MAX_NAME_OCTETS, nameKey, readName, writeName } from "./names.mjs";
import { array, obj, string } from "./rdata/common.mjs";
import { decodeRdata, encodeRdata, snapshotRdata } from "./rdata/index.mjs";

const SECTIONS = ["answers", "authorities", "additionals"];
const MAX_TTL = 0x7fffffff;
/**
 * Types that never carry zone data, so the RFC 2136 empty-rdata update form (class ANY or NONE, rdlength 0) never applies to
 * them and their rdata must be present (CLDMV/digby#38). TSIG and TKEY are transaction records whose rdata is mandatory; SIG
 * is the SIG(0) transaction signature, which travels as class ANY with mandatory rdata; the transfer and meta-query types are
 * not records at all. OPT never reaches the empty-rdata branch (it is read as EDNS), and type ANY must stay allowed — type ANY
 * with class ANY is the "delete every RRset" update form.
 *
 * Exported so the presentation formatter applies the same rule to `data: null` (CLDMV/digby#37).
 */
export const RDATA_REQUIRED = new Set([TYPE.TSIG, TYPE.TKEY, TYPE.SIG, TYPE.IXFR, TYPE.AXFR, TYPE.MAILA, TYPE.MAILB]);
/** The top of the type range is reserved (RFC 6895); no record may use it. */
const RESERVED_TYPE = 0xffff;
/**
 * Diagnostic counters for the scaling tests (CLDMV/digby#43): `recordWrites` counts {@link writeRecord} calls — every
 * record any encode touches — so tests bound the work by count rather than wall-clock. Not part of the codec's public
 * surface (index.mjs does not re-export it); a test resets it before the encode it measures.
 * @type {{ recordWrites: number }}
 */
export const wireCounters = { recordWrites: 0 };

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
		const name = readName(r);
		const type = r.u16();
		if (type === 0 || type === RESERVED_TYPE) fail(WireErrorCode.BAD_RDATA, `question type ${type} is reserved`, r.pos - 2); // 0 and 65535 are reserved (CLDMV/digby#38)
		questions.push({ name, type, class: r.u16() });
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
 * Read one resource record. The envelope's class and TTL are decoded as they arrive, with no record-level rules applied: what
 * a record's class and TTL must be is the verifier layer's job, not the codec's — a TSIG record's class ANY and TTL 0
 * (RFC 8945 4.1.1) are judged there, so decode stays lenient and a verifier sees exactly what arrived (CLDMV/digby#39).
 * @param {Reader} r
 */
function readRecord(r) {
	const name = readName(r);
	const type = r.u16();
	// 0 and 65535 are reserved (RFC 6895), matching the questions, the type bitmaps and RRSIG's typeCovered (CLDMV/digby#38);
	// SIG's typeCovered stays unchecked on purpose — SIG(0) needs typeCovered 0 (RFC 2931)
	if (type === 0 || type === RESERVED_TYPE) fail(WireErrorCode.BAD_RDATA, `record type ${type} is reserved`, r.pos - 2);
	const cls = r.u16();
	const ttl = r.u32();
	const rdlength = r.u16();
	if (type === TYPE.OPT) {
		const options = r.limit(rdlength, () => readOptions(r));
		return { name, type, opt: { ...splitOptTtl(ttl), udpSize: cls, options } };
	}
	let data;
	if (rdlength === 0 && (cls === CLASS.ANY || cls === CLASS.NONE)) {
		if (RDATA_REQUIRED.has(type)) fail(WireErrorCode.BAD_RDATA, `${typeToString(type)} rdata must be present; the empty-rdata update form does not apply to it`, r.pos);
		data = null;
	} else data = r.limit(rdlength, () => decodeRdata(type, r));
	return { name, type, class: cls, ttl: ttl > MAX_TTL ? 0 : ttl, data };
}

/**
 * Encode a message. Names are compressed (owner names, questions, and the rdata of NS, CNAME, SOA, PTR and MX). The records
 * are written exactly in the order given: record order is meaning (a transfer's SOA bookends, an IXFR's SOA-diff structure,
 * an update's interleaved adds and deletes), so nothing is regrouped (CLDMV/digby#36).
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
	return encodeCappedRaw(snapshotMessage(message), { limit: maxSize, truncate: false, compress }).bytes;
}

/**
 * Validate a record or question type when the caller's object is copied (CLDMV/digby#39): an integer in 0..0xffff, and
 * neither reserved value (RFC 6895; CLDMV/digby#38). Because the copy is what the encode writes, there is never a
 * `type ?? rec.type` fallback read anywhere.
 * @param {unknown} t
 * @param {string} what
 * @returns {number}
 */
function checkType(t, what) {
	if (!Number.isInteger(t) || t < 0 || t > 0xffff) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} out of range: ${String(t)}`);
	if (t === 0 || t === RESERVED_TYPE) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} ${t} is reserved`);
	return t;
}

/**
 * Copy a question into a plain object, once (CLDMV/digby#39): every field is read exactly once from the caller's object and
 * the encode writes the copy, so a getter cannot show the checks one value and the writer another.
 * @param {object} q
 * @returns {object}
 */
function snapshotQuestion(q) {
	obj(q, "a question");
	return { name: string(q.name, "question name"), type: checkType(q.type, "question type"), class: q.class ?? CLASS.IN };
}

/**
 * Copy a record into a plain object, once (CLDMV/digby#39): every field is read exactly once, the type is validated on the
 * copy, and the rdata value is copied one level past the deepest field the codecs read (see {@link snapshotRdata}). `what`
 * names the record in the refusal ("a record", "TSIG record").
 * @param {object} rec
 * @param {string} [what]
 * @returns {object}
 */
function snapshotRecord(rec, what = "a record") {
	obj(rec, what);
	return {
		name: string(rec.name, "record name"),
		type: checkType(rec.type, "record type"),
		class: rec.class ?? CLASS.IN,
		ttl: rec.ttl,
		data: snapshotRdata(rec.data)
	};
}

/**
 * Copy the EDNS fields into a plain object, once (CLDMV/digby#39). A falsy `edns` stays absent, exactly as the encode skips
 * it. Each option is copied shallowly: its fields are plain values and octets, which the option writers read once.
 * @param {object} edns
 * @returns {object | null}
 */
function snapshotEdns(edns) {
	if (!edns) return null;
	obj(edns, "edns");
	const options = array(edns.options ?? [], "EDNS options").map((o) => {
		obj(o, "an EDNS option");
		return { ...o };
	});
	return { udpSize: edns.udpSize, version: edns.version, dnssecOk: edns.dnssecOk, z: edns.z, options };
}

/**
 * Copy the message envelope into a plain object, once (CLDMV/digby#39): the header fields, EDNS and every question and record
 * of every section are read exactly once from the caller's object, and the encode acts on the copy only — a getter can
 * neither slip a TSIG past the TSIG-present check nor show the writer another value.
 * @param {object} message
 * @returns {object}
 */
function snapshotMessage(message) {
	obj(message, "message");
	const flags = message.flags;
	const edns = message.edns;
	return {
		id: message.id,
		flags: flags !== null && typeof flags === "object" ? { ...flags } : flags,
		rcode: message.rcode,
		questions: array(message.questions ?? [], "questions").map(snapshotQuestion),
		answers: array(message.answers ?? [], "answers").map((rec) => snapshotRecord(rec)),
		authorities: array(message.authorities ?? [], "authorities").map((rec) => snapshotRecord(rec)),
		additionals: array(message.additionals ?? [], "additionals").map((rec) => snapshotRecord(rec)),
		edns: snapshotEdns(edns)
	};
}

/**
 * The objects a reserved {@link encodeCapped} returned, each with a copy of the bytes as they were returned, so
 * {@link appendTsig} accepts only a genuine, unchanged one. The codec has no key, so it cannot check a MAC — it binds the
 * truncating encode and the append instead (CLDMV/digby#39).
 * @type {WeakMap<object, { snapshot: Uint8Array, reserved: number }>}
 */
const reservedEncodes = new WeakMap();

/**
 * Encode a message into at most `limit` octets, truncating when it does not fit (RFC 2181 9): whole RRsets are dropped, never
 * part of one. An answer or authority RRset that does not fit sets TC and drops it and everything after it; an additional
 * RRset that does not fit is dropped with the rest of the additional section, without TC (it is optional data). The grouping
 * decides only what a truncating encode keeps: the surviving records stay at their original positions, so the surviving sets
 * keep the order they were first seen in and nothing ever travels regrouped (CLDMV/digby#36).
 *
 * A message that already carries a TSIG record is refused (CLDMV/digby#39): truncating a signed message invalidates the MAC
 * (RFC 8945 5), which must cover the message actually sent. To send a signed, truncated message, encode the unsigned message
 * with `reserveTsig` set to the TSIG record's size, sign exactly the bytes that come back, then append the signed record with
 * {@link appendTsig}.
 *
 * @param {object} message
 * @param {object} options
 * @param {number} options.limit - the size cap in octets (at least 12)
 * @param {number} [options.reserveTsig=0] - octets to leave free for a TSIG record appended afterwards: the result plus this
 *   many octets fits `limit`
 * @param {boolean} [options.truncate=true]
 * @param {boolean} [options.compress=true]
 * @returns {{ bytes: Uint8Array, truncated: boolean, reserved: number }} `bytes` is the unsigned message when `reserveTsig`
 *   is set (the final message when it is not); `reserved` echoes the option
 * @throws {WireError} TSIG_PRESENT when the message already carries a TSIG record (CLDMV/digby#39); MESSAGE_TOO_LARGE when
 *   even the header, questions and tail exceed the limit; TRUNCATION_REFUSED when truncating would corrupt an UPDATE or a
 *   transfer (CLDMV/digby#43)
 */
export function encodeCapped(message, { limit, truncate = true, compress = true, reserveTsig = 0 } = {}) {
	checkInt(limit, MAX_MESSAGE, "limit");
	checkInt(reserveTsig, MAX_MESSAGE, "reserveTsig");
	if (reserveTsig > limit) fail(WireErrorCode.MESSAGE_TOO_LARGE, `reserving ${reserveTsig} octets of the ${limit}-octet limit leaves no room for a message`);
	// one snapshot of the caller's input (CLDMV/digby#39): the TSIG-present check and the encode act on the same copied
	// records, whose types were validated at the copy — a getter can neither slip a TSIG past the check nor show the encode
	// another type
	const snap = snapshotMessage(message);
	for (const section of [snap.answers, snap.authorities, snap.additionals])
		for (const rec of section)
			if (rec.type === TYPE.TSIG)
				fail(WireErrorCode.TSIG_PRESENT, "the message already carries a TSIG record: truncating it would invalidate the MAC — encode unsigned with reserveTsig, sign, then appendTsig (CLDMV/digby#39)");
	const { bytes, truncated } = encodeCappedRaw(snap, { limit: limit - reserveTsig, truncate, compress });
	const out = { bytes, truncated, reserved: reserveTsig };
	if (reserveTsig > 0) reservedEncodes.set(out, { snapshot: bytes.slice(), reserved: reserveTsig });
	return out;
}

/**
 * Append a signed TSIG record to the unsigned message {@link encodeCapped} returned with `reserveTsig` (CLDMV/digby#39). The
 * codec holds no keys: the caller signs exactly the bytes `encodeCapped` returned (the message the receiver sees up to the
 * TSIG) and hands the signed record here; this adds it as the last record of the additional section and bumps arcount, so the
 * result is the signed message on the wire.
 *
 * Misuse is refused, not merely documented: only the object `encodeCapped` itself returned is accepted (a private WeakMap
 * brands it), its bytes must be unchanged since it was returned (a copy is kept alongside and compared), the record's
 * `data.originalId` must be the message's ID (RFC 8945 5), and the record must fit the space `reserveTsig` reserved.
 *
 * @param {{ bytes: Uint8Array, truncated: boolean, reserved: number }} capped - the object `encodeCapped` returned with
 *   `reserveTsig` set
 * @param {object} tsigRecord - the signed TSIG record (`name`, `type` TYPE.TSIG, `class`, `ttl`, `data` per rdata/tsig.mjs)
 * @returns {Uint8Array} the signed message, still within the limit `encodeCapped` was given
 * @throws {WireError} VALUE_OUT_OF_RANGE for anything that is not a fresh, untouched, matching reservation
 */
export function appendTsig(capped, tsigRecord) {
	const state = typeof capped === "object" && capped !== null ? reservedEncodes.get(capped) : undefined;
	if (state === undefined) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "appendTsig takes the object encodeCapped returned with reserveTsig set (CLDMV/digby#39)");
	const { snapshot: bytes, reserved } = state;
	// The caller's bytes are read once and compared element by element — never through a method the array could override
	// (a Uint8Array subclass's .some() would lie, CLDMV/digby#39) — and the message is written from the codec's own copy, so
	// a getter cannot hand the comparison one message and the write another, and the ID and arcount come from the copy too.
	const given = capped.bytes;
	if (!(given instanceof Uint8Array) || given.length !== bytes.length) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "the unsigned bytes were changed after encodeCapped returned");
	for (let i = 0; i < bytes.length; i++) if (given[i] !== bytes[i]) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "the unsigned bytes were changed after encodeCapped returned");
	const rec = snapshotRecord(tsigRecord, "TSIG record");
	if (rec.type !== TYPE.TSIG) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `appendTsig appends a TSIG record, got type ${String(rec.type)}`);
	// a TSIG record carries class ANY and TTL 0 on the wire (RFC 8945 4.1.1) (CLDMV/digby#39)
	if (rec.class !== CLASS.ANY) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `a TSIG record has class ANY (RFC 8945 4.1.1), got ${classToString(rec.class)}`);
	if (rec.ttl !== 0) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `a TSIG record has TTL 0 (RFC 8945 4.1.1), got ${String(rec.ttl)}`);
	const id = (bytes[0] << 8) | bytes[1];
	const originalId = rec.data?.originalId;
	if (!Number.isInteger(originalId) || originalId !== id) {
		// a non-number's String() can equal the message's ID ("4660"), so name the type (CLDMV/digby#39)
		const shown = typeof originalId === "number" ? String(originalId) : `of type ${typeof originalId} (${String(originalId)})`;
		fail(WireErrorCode.VALUE_OUT_OF_RANGE, `the TSIG's original ID ${shown} is not this message's ID ${id}`);
	}
	// the record must fit the space reserved for it; a Writer capped at exactly the room left turns an oversized record into
	// MESSAGE_TOO_LARGE, which is the oversized refusal here
	const w = new Writer({ max: bytes.length + reserved, compress: false });
	w.raw(bytes);
	try {
		writeRecord(w, rec);
	} catch (err) {
		if (err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE)
			fail(WireErrorCode.VALUE_OUT_OF_RANGE, `the TSIG record needs more than the ${reserved} octets reserved for it`);
		throw err;
	}
	const out = new Uint8Array(w.length);
	out.set(w.bytes.subarray(0, w.length));
	const arcount = ((bytes[10] << 8) | bytes[11]) + 1;
	out[10] = arcount >>> 8;
	out[11] = arcount & 0xff;
	return out;
}

/**
 * The wire size of a TSIG record in octets: what {@link appendTsig} adds to the message for it — the owner name written
 * uncompressed, exactly as the space `encodeCapped`'s `reserveTsig` reserves is filled (CLDMV/digby#39). The record is
 * validated the same way encoding it is, so a record that cannot go on the wire fails here.
 *
 * @param {object} tsigRecord - a TSIG record (`name`, `type` TYPE.TSIG, `class`, `ttl`, `data` per rdata/tsig.mjs)
 * @returns {number}
 * @throws {WireError} VALUE_OUT_OF_RANGE for anything that is not a TSIG record; whatever encoding the record raises
 */
export function tsigRecordSize(tsigRecord) {
	const rec = snapshotRecord(tsigRecord, "TSIG record");
	if (rec.type !== TYPE.TSIG) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `tsigRecordSize measures a TSIG record, got type ${String(rec.type)}`);
	const w = new Writer({ max: MAX_MESSAGE, compress: false });
	writeRecord(w, rec);
	return w.length;
}

/**
 * The capped encode itself, with the OPT record and (for {@link encodeMessage}, which never truncates) a trailing TSIG record
 * as an always-kept tail. `message` is a {@link snapshotMessage} copy (CLDMV/digby#39): plain objects throughout, so reading
 * a field here can never re-run a getter on the caller's input.
 *
 * @param {object} message
 * @param {object} options
 * @param {number} options.limit - the size cap in octets (at least 12); already reduced by any reserved TSIG space
 * @param {boolean} options.truncate
 * @param {boolean} options.compress
 * @returns {{ bytes: Uint8Array, truncated: boolean }}
 * @throws {WireError} MESSAGE_TOO_LARGE when even the header, questions and tail exceed the limit; TRUNCATION_REFUSED when
 *   truncation would corrupt an UPDATE or a transfer (CLDMV/digby#43)
 */
function encodeCappedRaw(message, { limit, truncate, compress }) {
	checkInt(limit, MAX_MESSAGE, "limit");
	const questions = message.questions ?? [];
	const sections = [message.answers ?? [], message.authorities ?? [], message.additionals ?? []];
	const edns = message.edns ?? null;
	const rcode = message.rcode ?? 0;
	checkInt(rcode, 0xfff, "rcode");
	if (rcode > 0xf && !edns) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `rcode ${rcode} needs EDNS (its upper bits live in the OPT record)`);

	// split off a trailing TSIG; refuse OPT and misplaced TSIG records (the types were validated at the copy, CLDMV/digby#39)
	let tsig = null;
	sections.forEach((list, s) =>
		list.forEach((rec, i) => {
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
		writeName(w, q.name, true);
		w.u16(q.type);
		w.u16(q.class);
	}
	if (!tailFits()) fail(WireErrorCode.MESSAGE_TOO_LARGE, `the header, questions and tail records alone exceed ${limit} octets`);

	const written = [0, 0, 0];
	let truncated = false;
	if (!truncate) {
		// a non-truncating encode writes the records exactly as they are: record order is meaning (a transfer's SOA bookends,
		// an IXFR's SOA-diff structure, an update's interleaved adds and deletes), so nothing is regrouped (CLDMV/digby#36)
		for (let s = 0; s < 3; s++)
			for (let i = 0; i < sections[s].length; i++) {
				writeRecord(w, sections[s][i]);
				written[s]++;
			}
	} else {
		// a truncating encode consults the RRset grouping only to decide what it keeps — whole sets, in first-seen order; a
		// partial RRset is never sent (RFC 2181 9). The survivors are then written at their original positions, so record
		// order is kept: only whole sets leave it (CLDMV/digby#36).
		//
		// The trials are measured incrementally (CLDMV/digby#43), so a trial costs O(the new set) and not O(the kept
		// tail): each set's octet contribution is measured once, in a probe writer seeded with the targets known so far
		// (the writer's own — the section's records are not in it yet) and positioned past an upper bound of the kept
		// records' octets. Both seedings can only make the measurement larger than the contribution the set really adds
		// to the final stream: the probe's target set is a subset of the final one (a record encodes no shorter against
		// fewer targets), and the probe's offsets sit at or past the final ones (fewer suffixes clear the 0x4000
		// registration bound), so a running total that includes the measurement is an upper bound on the real stream
		// length. When the bound plus the tail bound fits the limit, the set fits — no trial write. Only when the bound
		// is over the limit is the trial written out for real (all kept sets plus this one, at their original positions —
		// exactly the stream that would be sent), which decides it exactly and, on a keep, replaces the running bound
		// with the exact length. The output is the last trial that fits, whole sets at their original positions, nothing
		// dangles — the round-2 design's exactness, preserved.
		outer: for (let s = 0; s < 3; s++) {
			const list = sections[s];
			const { sets, owner } = rrsets(list);
			let keptSets = sets.length;
			if (sets.length > 0) {
				// the probe: the writer's compression targets copied once (they do not change while the section's fate is
				// undecided — every trial write is rolled back), a length seeded per measurement past the kept records'
				// upper bound. A measurement that runs past MAX_MESSAGE throws MESSAGE_TOO_LARGE, which reads as a
				// bound that is over the limit and falls through to the exact trial.
				const probe = new Writer({ max: MAX_MESSAGE, compress });
				for (const [key, at] of w.names) probe.names.set(key, at);
				let keptBound = 0; // upper bound on the octets the kept sets add to the stream (exact after an exact trial)
				for (let k = 0; k < sets.length; k++) {
					// measure this set's contribution: write its records into the probe past the seeded offset, then roll
					// the probe back (its registered targets with them)
					probe.length = w.length + keptBound;
					const probeMark = probe.checkpoint();
					let contribution;
					try {
						for (const at of sets[k]) writeRecord(probe, list[at]);
						contribution = probe.length - (w.length + keptBound);
					} catch (err) {
						if (!(err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE)) throw err;
						contribution = Infinity;
					} finally {
						probe.rollback(probeMark);
					}
					if (w.length + keptBound + contribution + tailBound <= limit) {
						keptBound += contribution; // an upper bound plus an upper bound stays an upper bound
						continue;
					}
					// the bound is over the limit: decide exactly, by writing the stream that would be sent (all kept sets
					// plus this one, at their original positions) and rolling it back
					const mark = w.checkpoint();
					let fits = true;
					try {
						for (let i = 0; i < list.length; i++) if (owner[i] <= k) writeRecord(w, list[i]);
						fits = w.length <= limit && tailFits();
					} catch (err) {
						if (!(err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE)) throw err;
						fits = false;
					}
					if (fits) {
						keptBound = w.length - mark.length; // exact, so later trials bound tightly again
						w.rollback(mark);
						continue;
					}
					w.rollback(mark);
					keptSets = k;
					if (s < 2) truncated = true;
					break; // the truncation point: this set and everything after it, in every section, is dropped
				}
			}
			// the surviving records: all of them, or — after a drop — only the records of the sets kept so far, at their
			// original positions, written for good once
			for (let i = 0; i < list.length; i++)
				if (owner[i] < keptSets) {
					writeRecord(w, list[i]);
					written[s]++;
				}
			if (keptSets < sets.length) break outer;
		}
	}
	if (truncated) {
		// Truncating must not corrupt a message whose meaning lives in its record structure (CLDMV/digby#43): whole
		// RRsets drop, and out of an UPDATE that changes the update it describes; out of a transfer it breaks the SOA
		// bookends (AXFR) or the SOA-diff structure (IXFR). A message that fits still encodes normally.
		if ((message.flags?.opcode ?? 0) === OPCODE.UPDATE)
			fail(WireErrorCode.TRUNCATION_REFUSED, "an UPDATE cannot be truncated: dropping RRsets would change the update it describes");
		if (questions.some((q) => q.type === TYPE.AXFR || q.type === TYPE.IXFR))
			fail(WireErrorCode.TRUNCATION_REFUSED, "a transfer cannot be truncated: dropping RRsets would break the SOA bookends (AXFR) or the SOA-diff structure (IXFR)");
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
 * Group a section's records into RRsets: same owner (case-insensitive), type and class; an RRSIG also by the type it covers
 * (RFC 2181 9: a partial RRset is never sent). Returns the sets in first-seen order, each an ascending array of its records'
 * positions in the section, plus `owner`, which maps every position of the section to its set's index. Only a truncating
 * encode consults this, to decide which whole sets survive and write them at their original positions; a non-truncating
 * encode never regroups, because record order is meaning (CLDMV/digby#36).
 * @param {object[]} list
 * @returns {{ sets: number[][], owner: number[] }}
 */
function rrsets(list) {
	const sets = [];
	const owner = new Array(list.length);
	const byKey = new Map();
	for (let i = 0; i < list.length; i++) {
		const rec = list[i];
		const k = `${nameKey(string(rec.name, "record name"))}|${rec.type}|${rec.class ?? CLASS.IN}|${rec.type === TYPE.RRSIG ? rec.data?.typeCovered : ""}`;
		let ix = byKey.get(k);
		if (ix === undefined) {
			ix = sets.length;
			byKey.set(k, ix);
			sets.push([]);
		}
		sets[ix].push(i);
		owner[i] = ix;
	}
	return { sets, owner };
}

/**
 * Write one resource record from a {@link snapshotRecord} copy: the type was validated when the copy was taken (CLDMV/digby#39),
 * so there is no fallback read and the record on the wire is exactly the record the checks saw — however many times the
 * truncation logic writes the same record.
 * @param {Writer} w
 * @param {object} snap
 */
function writeRecord(w, snap) {
	wireCounters.recordWrites++;
	writeName(w, snap.name, true);
	w.u16(snap.type);
	w.u16(snap.class);
	checkInt(snap.ttl, MAX_TTL, "ttl");
	w.u32(snap.ttl);
	const lenAt = w.length;
	w.u16(0);
	if (snap.data === null) {
		if (snap.class !== CLASS.ANY && snap.class !== CLASS.NONE) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "empty rdata (data: null) is only for class ANY or NONE");
		if (RDATA_REQUIRED.has(snap.type)) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${typeToString(snap.type)} rdata must be present; the empty-rdata update form does not apply to it`);
	} else {
		encodeRdata(w, snap.type, snap.data);
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
