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
 *
 * Input contract (CLDMV/digby#39): the encode entries copy their input once with structuredClone ({@link cloneInput}) and
 * validate and write only the copy — structured-clone data, own enumerable properties only. Prototype getters are not read
 * (flags built on a class with prototype getters encode as absent); no caller method, iterator or `Symbol.species` runs; a
 * typed-array subclass arrives as a plain Uint8Array of its real octets. Anything the serializer refuses — a function, a
 * Proxy, a cycle — is a `WireError` NOT_CLONEABLE, and so is a list longer than 65,535 entries that is not dense, or a list
 * with a hole.
 */

import { MAX_MESSAGE, Reader, Writer, asBytes, checkInt } from "./buffer.mjs";
import { CLASS, OPCODE, TYPE, typeToString } from "./constants.mjs";
import { joinOptTtl, readOptions, splitOptTtl, writeOptions } from "./edns.mjs";
import { WireError, WireErrorCode, cloneInput, describe, fail } from "./errors.mjs";
import { HEADER_SIZE, TC_BIT, packFlags, unpackFlags } from "./header.mjs";
import { MAX_NAME_OCTETS, nameKey, readName, writeName } from "./names.mjs";
import { array, obj, string } from "./rdata/common.mjs";
import { decodeRdata, encodeRdata } from "./rdata/index.mjs";

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
 * record any encode touches, in the probe measurements, the exact trials, the records written for good and the
 * {@link appendTsig} append — so tests bound the work by count rather than wall-clock. `scratchEncodes` counts the
 * encodes that go through a scratch writer and are thrown away: the tail's uncompressed size measurement and the
 * near-boundary tail probes of {@link tailFitsOn} (a rolled-back OPT encode is not a {@link writeRecord} call, so
 * `recordWrites` alone would hide it). Neither is part of the codec's public surface (index.mjs does not re-export
 * them); a test resets them before the encode it measures.
 * @type {{ recordWrites: number, scratchEncodes: number }}
 */
export const wireCounters = { recordWrites: 0, scratchEncodes: 0 };

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
 * A message that already carries a TSIG record is refused (CLDMV/digby#39): re-encoding a signed message cannot
 * keep the MAC valid (RFC 8945 5), so signing happens only via {@link appendTsig}.
 *
 * @param {object} message - shape above; `flags`, the section arrays and `edns` may be omitted. The input is copied once
 *   with structuredClone and only the copy is validated and written (see the module's input contract, CLDMV/digby#39).
 * @param {object} [options]
 * @param {number} [options.maxSize=65535] - fail MESSAGE_TOO_LARGE rather than produce more octets than this
 * @param {boolean} [options.compress=true]
 * @returns {Uint8Array}
 * @throws {WireError} TSIG_PRESENT when the message already carries a TSIG record (CLDMV/digby#39)
 */
export function encodeMessage(message, { maxSize = MAX_MESSAGE, compress = true } = {}) {
	checkInt(maxSize, MAX_MESSAGE, "maxSize");
	// a TSIG never passes through an encode (CLDMV/digby#39): re-encoding a signed message cannot keep the MAC
	// valid (RFC 8945 5), so passing one through is never useful — signing happens only via appendTsig
	const snap = snapshotMessage(cloneInput(message, "a message"));
	for (const section of [snap.answers, snap.authorities, snap.additionals])
		for (const rec of section)
			if (rec.type === TYPE.TSIG)
				fail(WireErrorCode.TSIG_PRESENT, "the message already carries a TSIG record: re-encoding it cannot keep the MAC valid — encode unsigned with reserveTsig, sign, then appendTsig (CLDMV/digby#39)");
	return encodeCappedRaw(snap, { limit: maxSize, truncate: false, compress }).bytes;
}

/**
 * Validate a record or question type on the copy (CLDMV/digby#39): an integer in 0..0xffff, and neither reserved value
 * (RFC 6895; CLDMV/digby#38). Because the copy is what the encode writes, there is never a `type ?? rec.type` fallback read
 * anywhere, and the message's stringifications see only cloned values.
 * @param {unknown} t
 * @param {string} what
 * @returns {number}
 */
function checkType(t, what) {
	// the value is described, never String()ed: the copy is plain data, but a plain object with `toString: 1` survives
	// the clone and String() on it throws a TypeError (CLDMV/digby#39)
	if (!Number.isInteger(t) || t < 0 || t > 0xffff) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} out of range: ${describe(t)}`);
	if (t === 0 || t === RESERVED_TYPE) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} ${t} is reserved`);
	return t;
}

/**
 * Validate a question of the {@link cloneInput} copy (CLDMV/digby#39): the copy is plain data, so every field is read once
 * and the encode writes the copy — a getter cannot show the checks one value and the writer another.
 * @param {object} q
 * @returns {object}
 */
function snapshotQuestion(q) {
	obj(q, "a question");
	return { name: string(q.name, "question name"), type: checkType(q.type, "question type"), class: q.class ?? CLASS.IN };
}

/**
 * Validate a record of the {@link cloneInput} copy (CLDMV/digby#39): the copy is plain data throughout, so every field is
 * read once, the type is validated on the copy, and the rdata value the codecs write is the copy's. `what` names the record
 * in the refusal ("a record", "TSIG record").
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
		data: rec.data
	};
}

/**
 * Validate the EDNS fields of the {@link cloneInput} copy (CLDMV/digby#39). A falsy `edns` stays absent, exactly as the
 * encode skips it.
 * @param {object} edns
 * @returns {object | null}
 */
function snapshotEdns(edns) {
	if (!edns) return null;
	obj(edns, "edns");
	const options = array(edns.options ?? [], "EDNS options").map((o) => {
		obj(o, "an EDNS option");
		return o;
	});
	return { udpSize: edns.udpSize, version: edns.version, dnssecOk: edns.dnssecOk, z: edns.z, options };
}

/**
 * Validate the message envelope of the {@link cloneInput} copy (CLDMV/digby#39): the header fields, EDNS and every question
 * and record of every section are read once from the copy, and the encode acts on the copy only — a getter can neither slip
 * a TSIG past the TSIG-present check nor show the writer another value.
 * @param {object} message
 * @returns {object}
 */
function snapshotMessage(message) {
	obj(message, "message");
	const flags = message.flags;
	return {
		id: message.id,
		flags: flags !== null && typeof flags === "object" ? { ...flags } : flags,
		rcode: message.rcode,
		questions: array(message.questions ?? [], "questions").map(snapshotQuestion),
		answers: array(message.answers ?? [], "answers").map((rec) => snapshotRecord(rec)),
		authorities: array(message.authorities ?? [], "authorities").map((rec) => snapshotRecord(rec)),
		additionals: array(message.additionals ?? [], "additionals").map((rec) => snapshotRecord(rec)),
		edns: snapshotEdns(message.edns)
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
 * @param {object} message - copied once with structuredClone and only the copy validated and written (CLDMV/digby#39)
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
 *   transfer, or when the message does not carry exactly one question (CLDMV/digby#43)
 */
export function encodeCapped(message, { limit, truncate = true, compress = true, reserveTsig = 0 } = {}) {
	checkInt(limit, MAX_MESSAGE, "limit");
	checkInt(reserveTsig, MAX_MESSAGE, "reserveTsig");
	if (reserveTsig > limit) fail(WireErrorCode.MESSAGE_TOO_LARGE, `reserving ${reserveTsig} octets of the ${limit}-octet limit leaves no room for a message`);
	// one copy of the caller's input (CLDMV/digby#39): the TSIG-present check and the encode act on the same cloned
	// records, whose types were validated on the copy — a getter can neither slip a TSIG past the check nor show the encode
	// another type
	const snap = snapshotMessage(cloneInput(message, "a message"));
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
 * @param {object} tsigRecord - the signed TSIG record (`name`, `type` TYPE.TSIG, `class`, `ttl`, `data` per rdata/tsig.mjs);
 *   copied once with structuredClone and only the copy validated and written (CLDMV/digby#39)
 * @returns {Uint8Array} the signed message, still within the limit `encodeCapped` was given
 * @throws {WireError} VALUE_OUT_OF_RANGE for anything that is not a fresh, untouched, matching reservation
 */
export function appendTsig(capped, tsigRecord) {
	// `typeof capped` and the `capped.bytes` read can fire caller traps — a revoked Proxy throws for `typeof`, a
	// Proxy's `get` trap can throw — so both sit inside the refusal they feed: any throw means the object is not a
	// genuine encodeCapped result (CLDMV/digby#39)
	let state;
	try {
		state = capped !== null && typeof capped === "object" ? reservedEncodes.get(capped) : undefined;
	} catch {
		state = undefined; // a revoked Proxy: not a reserved encode either way
	}
	if (state === undefined) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "appendTsig takes the object encodeCapped returned with reserveTsig set (CLDMV/digby#39)");
	const { snapshot: bytes, reserved } = state;
	let givenBytes;
	try {
		givenBytes = capped.bytes;
	} catch {
		fail(WireErrorCode.VALUE_OUT_OF_RANGE, "appendTsig takes the object encodeCapped returned with reserveTsig set (CLDMV/digby#39)");
	}
	// The caller's bytes are copied once and compared element by element against the codec's own snapshot — the copy's
	// length is the real octet count (a Uint8Array subclass's length getter does not survive the copy), the comparison never
	// goes through a method the array could override, and the message is written from the codec's snapshot, so the bytes
	// written are exactly the bytes compared (CLDMV/digby#39).
	const given = cloneInput(givenBytes, "the unsigned bytes");
	if (!(given instanceof Uint8Array) || given.length !== bytes.length) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "the unsigned bytes were changed after encodeCapped returned");
	for (let i = 0; i < bytes.length; i++) if (given[i] !== bytes[i]) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "the unsigned bytes were changed after encodeCapped returned");
	const rec = snapshotRecord(cloneInput(tsigRecord, "TSIG record"), "TSIG record");
	if (rec.type !== TYPE.TSIG) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `appendTsig appends a TSIG record, got type ${describe(rec.type)}`);
	// a TSIG record carries class ANY and TTL 0 on the wire (RFC 8945 4.1.1) (CLDMV/digby#39)
	if (rec.class !== CLASS.ANY) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `a TSIG record has class ANY (RFC 8945 4.1.1), got ${describe(rec.class)}`);
	if (rec.ttl !== 0) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `a TSIG record has TTL 0 (RFC 8945 4.1.1), got ${describe(rec.ttl)}`);
	const id = (bytes[0] << 8) | bytes[1];
	const originalId = rec.data?.originalId;
	if (!Number.isInteger(originalId) || originalId !== id) {
		// a non-number's String() can equal the message's ID ("4660"), so the type is named — and the value is
		// described, never String()ed: a hostile originalId must not be able to break the refusal itself (CLDMV/digby#39)
		const shown = typeof originalId === "number" ? String(originalId) : `of type ${typeof originalId} (${describe(originalId)})`;
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
	// the reservation is spent: a second appendTsig against the same encodeCapped result is refused, so one reservation
	// cannot carry two TSIG records (CLDMV/digby#39)
	reservedEncodes.delete(capped);
	return out;
}

/**
 * The wire size of a TSIG record in octets: what {@link appendTsig} adds to the message for it — the owner name written
 * uncompressed, exactly as the space `encodeCapped`'s `reserveTsig` reserves is filled (CLDMV/digby#39). The record is
 * validated the same way encoding it is, so a record that cannot go on the wire fails here.
 *
 * @param {object} tsigRecord - a TSIG record (`name`, `type` TYPE.TSIG, `class`, `ttl`, `data` per rdata/tsig.mjs); copied
 *   once with structuredClone and only the copy measured (CLDMV/digby#39)
 * @returns {number}
 * @throws {WireError} VALUE_OUT_OF_RANGE for anything that is not a TSIG record; whatever encoding the record raises
 */
export function tsigRecordSize(tsigRecord) {
	const rec = snapshotRecord(cloneInput(tsigRecord, "TSIG record"), "TSIG record");
	if (rec.type !== TYPE.TSIG) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `tsigRecordSize measures a TSIG record, got type ${describe(rec.type)}`);
	const w = new Writer({ max: MAX_MESSAGE, compress: false });
	writeRecord(w, rec);
	return w.length;
}

/**
 * The capped encode itself, with the OPT record as an always-kept tail. `message` is a {@link snapshotMessage} copy
 * (CLDMV/digby#39): plain objects throughout, so reading a field here can never re-run a getter on the caller's input.
 * No TSIG can reach it: both public entries refuse a message that carries one (CLDMV/digby#39).
 *
 * @param {object} message
 * @param {object} options
 * @param {number} options.limit - the size cap in octets (at least 12); already reduced by any reserved TSIG space
 * @param {boolean} options.truncate
 * @param {boolean} options.compress
 * @returns {{ bytes: Uint8Array, truncated: boolean }}
 * @throws {WireError} MESSAGE_TOO_LARGE when even the header, questions and tail exceed the limit; TRUNCATION_REFUSED when
 *   truncation would corrupt an UPDATE or a transfer, or when the message does not carry exactly one question
 *   (CLDMV/digby#43)
 */
function encodeCappedRaw(message, { limit, truncate, compress }) {
	checkInt(limit, MAX_MESSAGE, "limit");
	const questions = message.questions ?? [];
	const sections = [message.answers ?? [], message.authorities ?? [], message.additionals ?? []];
	const edns = message.edns ?? null;
	const rcode = message.rcode ?? 0;
	checkInt(rcode, 0xfff, "rcode");
	if (rcode > 0xf && !edns) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `rcode ${rcode} needs EDNS (its upper bits live in the OPT record)`);

	// refuse an OPT record (the types were validated at the copy, CLDMV/digby#39); a TSIG cannot reach this
	// encode — both public entries refuse one before it
	sections.forEach((list) =>
		list.forEach((rec) => {
			if (rec.type === TYPE.OPT) fail(WireErrorCode.OPT_MISPLACED, "give EDNS as message.edns, not as an OPT record");
		})
	);

	// The header and questions, written into whichever writer the caller passes: the plain attempt, the
	// non-truncating encode and the trial path all write the same head. Returns where the section counts start.
	const writeHead = (wr) => {
		wr.u16(checkedId(message.id));
		wr.u16(packFlags(message.flags ?? {}, rcode & 0xf));
		wr.u16(questions.length);
		const countAt = wr.length;
		wr.u16(0);
		wr.u16(0);
		wr.u16(0);
		for (const q of questions) {
			writeName(wr, q.name, true);
			wr.u16(q.type);
			wr.u16(q.class);
		}
		return countAt;
	};
	const writeTail = (wr) => {
		if (edns) writeOpt(wr, edns, rcode >>> 4);
	};
	// An upper bound on the tail's size: written uncompressed into a scratch writer, once. The OPT encode is
	// scratch work no other counter sees, so it is counted (CLDMV/digby#43).
	const scratch = new Writer({ compress: false });
	if (edns) {
		wireCounters.scratchEncodes++;
		writeOpt(scratch, edns, rcode >>> 4);
	}
	const tailBound = scratch.length;
	// Whether the OPT record still fits on `wr` after what is written now. The bound settles it almost always; near
	// the limit, write it for real, measure and roll it back.
	const tailFitsOn = (wr) => {
		if (wr.length + tailBound <= limit) return true;
		const mark = wr.checkpoint();
		try {
			wireCounters.scratchEncodes++; // a rolled-back tail probe: counted scratch work (CLDMV/digby#43)
			writeTail(wr);
			return wr.length <= limit;
		} catch (err) {
			if (err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE) return false;
			throw err;
		} finally {
			wr.rollback(mark);
		}
	};
	// The header, questions and tail records alone must fit on `wr`: they are never dropped, so no RRset can make
	// room for them.
	const headAndTail = (wr) => {
		const countAt = writeHead(wr);
		if (!tailFitsOn(wr)) fail(WireErrorCode.MESSAGE_TOO_LARGE, `the header, questions and tail records alone exceed ${limit} octets`);
		return countAt;
	};
	// The plain encode of the whole message: header, questions, every record of every section, then the tail, with
	// the section counts patched.
	const writeAll = (wr, countAt, written) => {
		for (let s = 0; s < 3; s++)
			for (let i = 0; i < sections[s].length; i++) {
				writeRecord(wr, sections[s][i]);
				written[s]++;
			}
		writeTail(wr);
		if (edns) written[2]++;
		written.forEach((n, i) => wr.patch16(countAt + i * 2, n));
	};

	const written = [0, 0, 0];
	if (!truncate) {
		// a non-truncating encode writes the records exactly as they are: record order is meaning (a transfer's SOA bookends,
		// an IXFR's SOA-diff structure, an update's interleaved adds and deletes), so nothing is regrouped (CLDMV/digby#36)
		const w = new Writer({ max: limit, compress });
		writeAll(w, headAndTail(w), written);
		return { bytes: w.finish(), truncated: false };
	}

	// The message does not fit as it stands: whole RRsets drop, never part of one (RFC 2181 9), and the survivors
	// stay at their original positions, so the surviving sets keep the order they were first seen in and nothing ever
	// travels regrouped (CLDMV/digby#36). A truncating encode consults the RRset grouping only to decide what it
	// keeps.
	//
	// The keep decisions are exact, and cheap (CLDMV/digby#43). Deciding set k means asking whether the stream that
	// would go out if sets 0..k were kept and everything after dropped fits the limit — the drop-here stream. Writing
	// it out for every set is quadratic on interleaved shapes (each trial re-encodes the kept records around the
	// candidate), so the encode instead maintains an exact model of the drop-here stream and measures each candidate
	// against it:
	//
	// - `fen` holds the exact wire octets of every kept record at its position. A record's offset in the drop-here
	//   stream is `sectionBase + fen.prefix(position) + (its offset within its record)`; closed records (written for
	//   good below) stay in the tree, so the formula holds for every kept position without bookkeeping.
	// - `model` holds, per compression target, the key and the registration's offset within its record. For a later
	//   record the target is present exactly when the registration's stream offset is below 0x4000 — computed from
	//   the tree on demand, so a later keep that shifts the registration is reflected without touching the entry.
	// - Measuring a candidate writes its records into a probe writer positioned at the candidate's first record's
	//   stream offset, seeded with the model's targets and the closed records' targets, and each registration the
	//   probe makes is corrected by the exact shift — the kept octets between the candidate's records, from the
	//   tree. The probe's lookups therefore hit and miss exactly as the interleaved drop-here stream would, so the
	//   measured contribution is the candidate's exact octets there, not a bound.
	//
	// Keeping a set folds its octets and registrations into the model, which can disturb earlier kept records: the
	// inserted octets shift their registrations (one can cross 0x4000 and vanish, lengthening the records that
	// pointed at it), and the new registrations can shorten records that examined those keys and could not register
	// them. Every kept record therefore leaves the keys it examined in an index; when a key's presence flips — a
	// registration added, removed, or shifted across the boundary — the sets whose records examined it are
	// re-measured against the updated model, and the flips the re-measuring itself produces are processed in turn
	// until the model is consistent. The provisional keep, its cascades and the fit check are all logged, so a check
	// that fails (the stream does not fit) rolls back cleanly before the exact trial decides the set — the trial
	// writes the drop-here stream for real and is exact by construction. A guard bounds the cascade rounds; past it
	// the section falls back to exact trials for every remaining set, which is slower but just as exact.
	//
	// The fit check is the exact stream total plus the uncompressed tail bound, so it can only refuse a set whose
	// stream actually fits when the tail itself compresses; the exact trial settles those.
	const w = new Writer({ max: MAX_MESSAGE, compress });
	const countAt = writeHead(w);
	// the header, questions and tail records alone must fit: they are never dropped, so no RRset can make room for
	// them
	if (!tailFitsOn(w)) fail(WireErrorCode.MESSAGE_TOO_LARGE, `the header, questions and tail records alone exceed ${limit} octets`);
	let truncated = false;
	let dropped = false; // any RRset dropped from any section — an additionals-only drop never sets TC, but it is still a drop (CLDMV/digby#43)
	let modelBroken = false; // the cascade guard tripped: the rest of the section decides by exact trial
	outer: for (let s = 0; s < 3; s++) {
		const list = sections[s];
		const { sets, owner } = rrsets(list);
		let pos = 0; // section positions below this are decided and finally written
		let keptSets = sets.length;
		if (sets.length > 0) {
			// the stream offset this section's records sit at: the header and questions plus every kept record of the
			// sections before it. w.length grows past this as this section's records are written for good, so the
			// section's offsets anchor here, not at headSize.
			const sectionBase = w.length;
			const fen = new Fenwick(list.length); // kept record position -> its exact wire octets
			const model = new Map(); // compression target key -> { rec, rel, valid }
			const setEntries = new Map(); // set index -> { entries: Map<key, entry>, byRec: Map<position, key[]>, open }
			const index = new Map(); // examined key -> Set of set indices whose records examined it
			const probe = new Writer({ max: MAX_MESSAGE, compress });
			const overlay = new Map(); // key -> { rec, rel, real } — the measurement's own registrations
			let recStart = 0; // probe offset where the record being measured starts
			let curRec = 0; // the position of the record being measured
			let curShift = 0; // kept octets between the candidate's first record and it
			const touched = [];
			const realOf = (entry) => sectionBase + fen.prefix(entry.rec) + entry.rel;
			const lookup = (key) => {
				const o = overlay.get(key);
				if (o !== undefined) return o.real;
				const m = model.get(key);
				if (m !== undefined) {
					const r = realOf(m);
					return r < 0x4000 ? r : undefined;
				}
				return w.names.get(key);
			};
			// The probe's compression table: the model's targets at their stream offsets, the measurement's own
			// registrations corrected by the shift (a registration whose real offset reaches 0x4000 does not exist
			// — the real stream's write would be past the pointer range), and every examined key recorded for the
			// disturbance index.
			probe.names = {
				get(key) {
					touched.push(key);
					return lookup(key);
				},
				has(key) {
					touched.push(key);
					return lookup(key) !== undefined;
				},
				set(key, at) {
					const real = at + curShift;
					if (real < 0x4000) overlay.set(key, { rec: curRec, rel: at - recStart, real });
				},
				delete(key) {
					overlay.delete(key);
				}
			};
			const measureSet = (k) => {
				const set = sets[k];
				// the set's open records only: a record below pos is written for good, its octets final in the tree —
				// re-encoding it would see the targets its own closing write registered and undershoot. The open
				// records are a contiguous suffix (positions ascend, closure cuts at pos).
				const i0 = set.findIndex((at) => at >= pos);
				if (i0 === -1) return { recs: [], contribution: 0, overflow: false, examined: new Set() };
				const open = set.slice(i0);
				const p1 = open[0];
				const probeBase = sectionBase + fen.prefix(p1);
				probe.length = probeBase;
				probe.added.length = 0;
				overlay.clear();
				const recs = [];
				const examined = new Set();
				let overflow = false;
				// the shift is the kept octets between the set's own records: the tree's range minus the set's own
				// octets in it (zero for a candidate, whose positions are not in the tree yet; its old octets on a
				// re-measure, which the consecutive probe layout already carries)
				let own = 0;
				for (const at of open) {
					curRec = at;
					curShift = fen.prefix(at) - fen.prefix(p1) - own;
					own += fen.vals[at];
					recStart = probe.length;
					touched.length = 0;
					const start = probe.length;
					try {
						writeRecord(probe, list[at]);
					} catch (err) {
						if (err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE) {
							overflow = true;
							break;
						}
						throw err;
					}
					recs.push({ at, oct: probe.length - start });
					for (const key of touched) examined.add(key);
				}
				return { recs, contribution: overflow ? Infinity : probe.length - probeBase, overflow, examined };
			};
			const keepSet = (k, m, log) => {
				const entries = new Map();
				const byRec = new Map();
				for (const { at, oct } of m.recs) {
					log.push({ t: 0, pos: at, old: fen.vals[at] });
					fen.set(at, oct);
				}
				for (const [key, e] of overlay) {
					log.push({ t: 1, key, old: model.get(key) ?? null });
					const entry = { rec: e.rec, rel: e.rel, valid: true };
					model.set(key, entry);
					entries.set(key, entry);
					let keys = byRec.get(e.rec);
					if (keys === undefined) {
						keys = [];
						byRec.set(e.rec, keys);
					}
					keys.push(key);
				}
				for (const key of m.examined) {
					let ix = index.get(key);
					if (ix === undefined) {
						ix = new Set();
						index.set(key, ix);
					}
					if (!ix.has(k)) {
						log.push({ t: 2, key, idx: k });
						ix.add(k);
					}
				}
				setEntries.set(k, { entries, byRec, open: sets[k].length });
			};
			const remeasure = (j, log, push) => {
				const state = setEntries.get(j);
				// the pre-remeasure per-set state, for the rollback log
				log.push({ t: 3, j, oldEntries: state.entries, oldByRec: state.byRec, oldOpen: state.open });
				// the set's own registrations come out first: a record must not compress against the registration its
				// own previous measurement made — in the stream it is being re-measured for, it writes that name
				// itself
				const removed = new Map();
				for (const [key, entry] of state.entries) {
					log.push({ t: 1, key, old: entry });
					model.delete(key);
					removed.set(key, entry);
				}
				const m = measureSet(j);
				for (const key of removed.keys()) {
					if (!overlay.has(key)) {
						// the registration is gone for good: whoever examined it may now write it in full
						const ix = index.get(key);
						if (ix !== undefined) for (const q of ix) push(q, j);
					}
				}
				const entries = new Map();
				const byRec = new Map();
				for (const [key, e] of overlay) {
					// a key removed above and registered again: the original entry is what the rollback restores
					const prev = removed.get(key) ?? model.get(key) ?? null;
					log.push({ t: 1, key, old: prev });
					const entry = { rec: e.rec, rel: e.rel, valid: true };
					model.set(key, entry);
					entries.set(key, entry);
					if (prev === null) {
						const ix = index.get(key);
						if (ix !== undefined) for (const q of ix) push(q, j);
					}
					let keys = byRec.get(e.rec);
					if (keys === undefined) {
						keys = [];
						byRec.set(e.rec, keys);
					}
					keys.push(key);
				}
				for (const { at, oct } of m.recs) {
					if (fen.vals[at] !== oct) {
						log.push({ t: 0, pos: at, old: fen.vals[at] });
						fen.set(at, oct);
					}
				}
				for (const key of m.examined) {
					let ix = index.get(key);
					if (ix === undefined) {
						ix = new Set();
						index.set(key, ix);
					}
					if (!ix.has(j)) {
						log.push({ t: 2, key, idx: j });
						ix.add(j);
					}
				}
				state.entries = entries;
				state.byRec = byRec;
			};
			// Undo a provisional keep and its cascades, in reverse order.
			const rollback = (log) => {
				for (let i = log.length - 1; i >= 0; i--) {
					const e = log[i];
					if (e.t === 0) fen.set(e.pos, e.old);
					else if (e.t === 1) {
						if (e.old === null) model.delete(e.key);
						else model.set(e.key, e.old);
					} else if (e.t === 3) {
						const st = setEntries.get(e.j);
						if (st !== undefined) {
							st.entries = e.oldEntries;
							st.byRec = e.oldByRec;
							st.open = e.oldOpen;
						}
					} else {
						const ix = index.get(e.key);
						ix.delete(e.idx);
						if (ix.size === 0) index.delete(e.key);
					}
				}
			};
			// Presence flips: re-measure the sets whose records examined the key, until no flip remains. Returns
			// false when the guard trips (the model is abandoned for the rest of the section).
			const cascade = (log, seedKeys, exceptSet) => {
				const queue = [];
				const queued = new Set();
				const push = (j, except) => {
					if (j !== except && setEntries.has(j) && !queued.has(j)) {
						queued.add(j);
						queue.push(j);
					}
				};
				if (seedKeys !== undefined)
					for (const key of seedKeys) {
						const ix = index.get(key);
						if (ix !== undefined) for (const j of ix) push(j, exceptSet);
					}
				let rounds = 0;
				for (;;) {
					for (const [key, entry] of model) {
						const valid = realOf(entry) < 0x4000;
						if (valid !== entry.valid) {
							entry.valid = valid;
							const ix = index.get(key);
							if (ix !== undefined) for (const j of ix) push(j);
						}
					}
					if (queue.length === 0) return true;
					if (++rounds > 64 + sets.length) return false;
					const j = queue.shift();
					queued.delete(j);
					remeasure(j, log, push);
				}
			};
			for (let k = 0; k < sets.length; k++) {
				const first = sets[k][0];
				// records before this set's first record belong to sets already decided as kept: write them for
				// good — their compression targets become final (the real writer's table holds them now) and their
				// model entries retire
				for (let i = pos; i < first; i++) {
					const at = w.length;
					writeRecord(w, list[i]);
					written[s]++;
					if (!modelBroken) fen.set(i, w.length - at); // the tree carries the actual octets from here on
					if (!modelBroken) {
						const state = setEntries.get(owner[i]);
						if (state !== undefined) {
							const keys = state.byRec.get(i);
							if (keys !== undefined) {
								for (const key of keys) {
									model.delete(key);
									state.entries.delete(key);
								}
								state.byRec.delete(i);
							}
							if (--state.open === 0 && state.entries.size === 0) setEntries.delete(owner[i]);
						}
					}
				}
				pos = first;
				if (!modelBroken) {
					const m = measureSet(k);
					if (!m.overflow) {
						const log = [];
						keepSet(k, m, log);
						if (cascade(log, overlay.keys(), k) && sectionBase + fen.total() + tailBound <= limit) {
							continue;
						}
						rollback(log);
					}
				}
				// the stream would not fit (or the model fell back): decide exactly, by writing the stream that
				// would be sent (all kept sets plus this one, at their original positions, from `first` on —
				// records before it are final) and rolling it back
				const mark = w.checkpoint();
				let fits = true;
				try {
					for (let i = first; i < list.length; i++) if (owner[i] <= k) writeRecord(w, list[i]);
					fits = w.length <= limit && tailFitsOn(w);
				} catch (err) {
					if (!(err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE)) throw err;
					fits = false;
				}
				w.rollback(mark);
				if (fits) {
					// the trial decided the keep exactly — fold it into the model (the trial's stream is the
					// drop-here stream, so the model's formulas reproduce its offsets)
					if (!modelBroken) {
						const m2 = measureSet(k);
						if (!m2.overflow) {
							const log2 = [];
							keepSet(k, m2, log2);
							if (!cascade(log2, overlay.keys(), k)) modelBroken = true;
						} else modelBroken = true;
					}
					continue;
				}
				keptSets = k;
				dropped = true;
				if (s < 2) truncated = true;
				break; // the truncation point: this set and everything after it, in every section, is dropped
			}
		}
		// the surviving records from `pos` on: all of them, or — after a drop — only the records of the sets kept
		// so far, at their original positions, written for good once
		for (let i = pos; i < list.length; i++)
			if (owner[i] < keptSets) {
				writeRecord(w, list[i]);
				written[s]++;
			}
		if (keptSets < sets.length) break outer;
	}
	if (dropped) {
		// Truncating must not corrupt a message whose meaning lives in its record structure (CLDMV/digby#43): whole
		// RRsets drop, and out of an UPDATE that changes the update it describes; out of a transfer it breaks the SOA
		// bookends (AXFR) or the SOA-diff structure (IXFR). Any drop from any section counts: an additionals-only
		// drop never sets TC (RFC 2181 9 — additionals are optional data), but it is still a drop. A message that
		// fits still encodes normally.
		if ((message.flags?.opcode ?? 0) === OPCODE.UPDATE)
			fail(WireErrorCode.TRUNCATION_REFUSED, "an UPDATE cannot be truncated: dropping RRsets would change the update it describes");
		// an AXFR continuation may carry no question at all (RFC 5936 2.2.1), and nothing about the message is
		// identifiable without exactly one question — so any drop from a message that does not carry exactly one
		// is refused (CLDMV/digby#43)
		if (questions.length !== 1)
			fail(WireErrorCode.TRUNCATION_REFUSED, `a message with ${questions.length} questions cannot be truncated: without exactly one question the message cannot be identified — encode it within the limit or refuse the drop`);
		if (questions.some((q) => q.type === TYPE.AXFR || q.type === TYPE.IXFR))
			fail(WireErrorCode.TRUNCATION_REFUSED, "a transfer cannot be truncated: dropping RRsets would break the SOA bookends (AXFR) or the SOA-diff structure (IXFR)");
	}
	writeTail(w);
	if (edns) written[2]++;
	written.forEach((n, i) => w.patch16(countAt + i * 2, n));
	if (truncated) w.patch16(2, ((w.bytes[2] << 8) | w.bytes[3]) | TC_BIT);
	return { bytes: w.finish(), truncated };
}

function checkedId(id) {
	checkInt(id ?? 0, 0xffff, "id");
	return id ?? 0;
}

/**
 * A Fenwick tree of per-position octet counts: the kept records' exact wire octets, indexed by section position
 * (CLDMV/digby#43). Point updates as sets are kept and re-measured; prefix sums give any kept record's offset in the
 * drop-here stream and the kept octets between two positions.
 */
class Fenwick {
	constructor(n) {
		this.n = n;
		this.tree = new Float64Array(n + 1);
		this.vals = new Float64Array(n);
	}

	/** Set the octets at position `i`. */
	set(i, v) {
		const d = v - this.vals[i];
		if (d === 0) return;
		this.vals[i] = v;
		for (i++; i <= this.n; i += i & -i) this.tree[i] += d;
	}

	/** Sum of the octets at positions `0..i-1`. */
	prefix(i) {
		let sum = 0;
		for (; i > 0; i -= i & -i) sum += this.tree[i];
		return sum;
	}

	/** Sum over all positions. */
	total() {
		return this.prefix(this.n);
	}
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
		// the class and the covered type are described, never stringified: they are the copy's values, but a plain
		// object with a hostile toString survives the clone and a template literal on it throws a TypeError. Such a
		// class never reaches the wire (writeRecord's checkInt refuses it), so descriptions colliding into one key is
		// harmless (CLDMV/digby#39).
		const k = `${nameKey(string(rec.name, "record name"))}|${rec.type}|${describe(rec.class ?? CLASS.IN)}|${rec.type === TYPE.RRSIG ? describe(rec.data?.typeCovered) : ""}`;
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
