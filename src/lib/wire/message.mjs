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

import { MAX_MESSAGE, Reader, Writer, asBytes, checkInt, cloneOptions } from "./buffer.mjs";
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
 * record any encode touches, in the plain attempt's full pass, the probe measurements, the exact trials, the records
 * written for good and the {@link appendTsig} append — so tests bound the work by count rather than wall-clock. A
 * record written twice is two units; the plain attempt's rolled-back pass counts like any other (CLDMV/digby#43,
 * round 7). `scratchEncodes` counts the encodes that go through a scratch writer and are thrown away: the tail's
 * uncompressed size measurement and the near-boundary tail probes of {@link tailFitsOn} (a rolled-back OPT encode is
 * not a {@link writeRecord} call, so `recordWrites` alone would hide it). `modelWork` counts every unit of the
 * truncation model's own work: each Fenwick operation (every `set` and every `prefix` call, one unit per
 * call, not per tree step), each validity-heap push and pop, each registration, index and queue mutation, and each
 * record the re-measure bookkeeping visits — the round-5 flip scan over the whole model was uncounted work of
 * exactly this kind, and a bound that did not see it could be cheated by moving work out of `recordWrites`
 * (CLDMV/digby#43). None of them is part of the codec's public surface (index.mjs does not re-export them); a test
 * resets them before the encode it measures.
 * @type {{ recordWrites: number, scratchEncodes: number, modelWork: number }}
 */
export const wireCounters = { recordWrites: 0, scratchEncodes: 0, modelWork: 0 };

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
export function decodeMessage(input, options) {
	// the options are guarded like every other argument (CLDMV/digby#39): null and undefined mean "no options", and the
	// copy is read exactly once
	const o = cloneOptions(options, "the decode options");
	const bytes = asBytes(input);
	if (bytes.length > MAX_MESSAGE) fail(WireErrorCode.INPUT_TOO_LARGE, `a message is at most ${MAX_MESSAGE} octets, got ${bytes.length}`);
	const maxQuestions = o.maxQuestions ?? 1;
	checkInt(maxQuestions, 0xffff, "maxQuestions");
	const maxNameOctets = o.maxNameOctets ?? MAX_NAME_OCTETS;
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
	if (r.pos !== bytes.length && !(o.allowTrailing ?? false)) fail(WireErrorCode.TRAILING_DATA, `${bytes.length - r.pos} octet(s) after the last section`, r.pos);
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
export function encodeMessage(message, options) {
	// the options are guarded like every other argument (CLDMV/digby#39): null and undefined mean "no options", and the
	// copy is read exactly once
	const o = cloneOptions(options, "the encodeMessage options");
	checkInt(o.maxSize ?? MAX_MESSAGE, MAX_MESSAGE, "maxSize");
	// a TSIG never passes through an encode (CLDMV/digby#39): re-encoding a signed message cannot keep the MAC
	// valid (RFC 8945 5), so passing one through is never useful — signing happens only via appendTsig
	const snap = snapshotMessage(cloneInput(message, "a message"));
	for (const section of [snap.answers, snap.authorities, snap.additionals])
		for (const rec of section)
			if (rec.type === TYPE.TSIG)
				fail(WireErrorCode.TSIG_PRESENT, "the message already carries a TSIG record: re-encoding it cannot keep the MAC valid — encode unsigned with reserveTsig, sign, then appendTsig (CLDMV/digby#39)");
	return encodeCappedRaw(snap, { limit: o.maxSize ?? MAX_MESSAGE, truncate: false, compress: o.compress ?? true }).bytes;
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
 * part of one. The kept sets are the LONGEST PREFIX of the message's RRsets, in first-appearance order (answers, then
 * authorities, then additionals), that fits the limit — the largest k whose k-set prefix fits, so a truncated message drops
 * only the trailing RRsets of that order it has to, never what a stop-at-first-miss scan finds (CLDMV/digby#43, round 8). A
 * prefix that ends in the answers or the authorities sets TC; one that drops only additionals does not (they are optional
 * data, RFC 2181 9). The grouping decides only what a truncating encode keeps: the surviving records stay at their original
 * positions, so the surviving sets keep the order they were first seen in and nothing ever travels regrouped (CLDMV/digby#36).
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
export function encodeCapped(message, options) {
	// the options are guarded like every other argument (CLDMV/digby#39): null and undefined mean "no options", and the
	// copy is read exactly once
	const o = cloneOptions(options, "the encodeCapped options");
	const limit = o.limit;
	const truncate = o.truncate ?? true;
	const compress = o.compress ?? true;
	const reserveTsig = o.reserveTsig ?? 0;
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
	// The keep rule (CLDMV/digby#43, round 8): the kept sets are the LONGEST PREFIX of the RRsets, in first-appearance
	// order, whose drop-here stream fits the limit — the largest k whose k-set prefix fits; a truncated message drops
	// only the trailing RRsets of that order it has to. {@link selectKept} is the one place the rule lives, so swapping
	// it (the prefix rule for a best-subset rule) stays contained. Because compression makes the stream's size
	// non-monotone in the prefix length — the sets interleave, so a set decided later can register a target below
	// 0x4000 that the already-kept records then compress against, and a smaller prefix that does not fit does not stop
	// the search (round 7's C1) — the rule needs, per section, the largest fitting prefix, not the first fitting one.
	//
	// Per section is enough for the global order: a later section's records all sit at higher stream offsets than
	// every earlier section's record, and compression pointers only reach backwards, so folding a later section's sets
	// can never shorten an earlier section's record — the drop-here stream of a prefix that ends inside a section is a
	// byte-prefix of the drop-here stream of every longer prefix. A longer prefix that fits therefore implies every
	// section boundary below it fits, and the global largest fitting prefix is exactly: the largest fitting prefix of
	// the answers; if all of them fit, the largest fitting prefix of the authorities; and so on.
	//
	// The per-section search is exact and cheap (CLDMV/digby#43). Deciding prefix k means asking whether the stream
	// that would go out if sets 0..k were kept and everything after dropped fits the limit — the drop-here stream.
	// Writing it out for every k is quadratic on interleaved shapes, so the encode maintains an exact model of the
	// drop-here stream and measures every set against it once, in first-appearance order:
	//
	// - `fen` holds the exact wire octets of every measured record at its position, so any record's offset in the
	//   drop-here stream is `sectionBase + fen.prefix(position) + (its offset within its record)`; a running total
	//   gives each prefix's stream size in O(1).
	// - `model` holds, per compression target, the key and the registration's offset within its record. Every
	//   registration the probe's writes make is recorded, in pointer range or not (round 10): an out-of-range one is
	//   not a pointer target yet, but its real offset — the probe gates on the real offset, not on its own write
	//   position, which sits below it by the kept octets between the measured records (CLDMV/digby#43, round 9) — is
	//   watched by the drift-in heap, because a later shrink can pull it back under 0x4000 and make it real. The
	//   entry's validity is still computed on demand (`realOf < 0x4000`), so a later keep that shifts the registration
	//   is reflected without touching the entry, and a registration that crosses out of or drifts back under the
	//   pointer range is detected instead of silently miscounting (see the two heaps below).
	// - Measuring a set writes its records into a probe writer positioned at the set's first record's stream offset,
	//   seeded with the model's targets, and each registration the probe makes is corrected by the exact shift — the
	//   kept octets between the measured records, from the tree. The probe's lookups therefore hit and miss exactly
	//   as the drop-here stream would at the name being written: a target is visible only where the stream already
	//   has it — written by an earlier record, or an earlier name of the same one. A registration a LATER record will
	//   make is not yet on the wire and cannot shorten an earlier name (writeName registers targets even for names it
	//   never compresses — an SRV target, an RRSIG signer — CLDMV/digby#43), so the measured contribution is the
	//   set's exact octets there, not a bound.
	//
	// Keeping a set folds its octets and registrations into the model, which can disturb earlier kept records: the
	// inserted octets shift their registrations (one can cross 0x4000 and vanish, lengthening the records that
	// pointed at it, or drift back under it and reappear, shortening records that wrote it in full), and the new
	// registrations can shorten records that examined those keys and could not register them. Every measured record
	// therefore leaves the keys it examined both in a per-set index (key -> the records that examined it) and in a
	// global one (key -> the sets); a key whose state changed re-measures exactly the records whose stored octets
	// depended on it — the fixed point over the changed keys and the registrations they unseat — not the whole set,
	// and the re-measures the re-measuring itself produces are processed in turn until the model is consistent.
	// Validity is watched off two lazy min-heaps, so no scan of the model is ever needed: the registrations currently
	// valid sit in one keyed by their slack plus the cumulative positive shift at push, and every positive octet the
	// tree gains pops it to the registrations that could have crossed OUT of the pointer range (see drain); the
	// registrations currently out of the range sit in the other keyed by their deficit plus the cumulative negative
	// shift at push, and every negative octet the tree gains pops it to the registrations that could have drifted
	// back IN (see drainInvalid). Without the second heap a drifted-back registration would leave its examiners'
	// stored octets stale-high — an overcount — and an overcounted total can hide a fitting prefix, which is the one
	// model lie the largest-fit search cannot self-correct (see below). A guard bounds the cascade rounds; past it
	// the model is abandoned and the section's prefixes are decided by exact trials, which is slower but just as
	// exact.
	//
	// Searching for the largest k (CLDMV/digby#43, round 8). The scan folds every set until the model breaks or the
	// FROZEN point (below), recording each prefix's exact stream total; {@link selectKept} then probes candidate
	// prefixes newest-first and verifies the winner by an exact trial — the trial writes the candidate's drop-here
	// stream for real against the writer that will carry it, and on success its bytes ARE the output, so the encoder
	// never returns more octets than the limit by construction. The trials are what make the search exact under a
	// model lie in the undercount direction: an understated total can only add candidates (a prefix whose real stream
	// fits always passes the fit check), every candidate is trial-verified, and the first trial that fits is the
	// largest fitting prefix whatever the model said. An overstated total is the dangerous direction: it can hide a
	// fitting prefix from the fit check, and past the frozen point no trial would ever run to correct it — so the
	// overstated direction is the one kept exact, by record-order visibility (a target a later record makes cannot
	// shorten an earlier name), by recording every registration and watching the out-of-range ones in the drift-in
	// heap (a registration that drifts back under 0x4000 re-measures its examiners instead of leaving their stored
	// octets stale-high), and by the no-displacement rule (an out-of-range registration never replaces an in-range
	// one, so a phantom can never make the model lose a target the stream has); the exact trial is the last line of
	// defence in the understated direction and the differential suite is the net (CLDMV/digby#43, rounds 9-10).
	//
	// The frozen point (CLDMV/digby#43, round 8). Once the prefix total is over the budget AND every record a later
	// keep would add sits at a stream offset at or above 0x4000, the search can stop: a record at offset >= 0x4000
	// registers nothing the real writer would accept (writeName's own guard is `w.length < 0x4000`), so folding the
	// later sets can add no compression target — no re-measure fires, no stored octet shrinks — and every longer
	// prefix is this prefix's stream plus positive octets, so it cannot fit either. The sets past the point are never
	// measured; past-limit input costs grouping only. The honest worst case: a shape whose stream oscillates around
	// the limit past 0x4000 keeps the scan folding every set (still linear), and the exact-trial fallback when the
	// model breaks (the cascade guard, or a measurement past the probe's 2 GiB scratch cap) is quadratic within the
	// section — one trial per candidate prefix, each O(prefix) — contained per section and unreached in clean code
	// (round 7's C3, kept).
	const w = new Writer({ max: limit, compress });
	const countAt = writeHead(w);
	// the header, questions and tail records alone must fit: they are never dropped, so no RRset can make room for
	// them
	if (!tailFitsOn(w)) fail(WireErrorCode.MESSAGE_TOO_LARGE, `the header, questions and tail records alone exceed ${limit} octets`);
	// The plain attempt first (CLDMV/digby#43): a message whose full encode fits the limit is returned whole, without
	// TC. That is the largest-fitting-prefix rule's k = every-set case, answered where it is cheapest: the model scan
	// below folds every set to place every prefix's total, so a message that fits whole would pay the full scan only
	// to conclude what one encode already showed. Encoding everything once and returning it when it fits answers
	// fit-or-truncate exactly there; only a message that does not fit whole reaches the model. The attempt's writes
	// are counted work (recordWrites), not free — correctness first (CLDMV/digby#43).
	const plainMark = w.checkpoint();
	try {
		writeAll(w, countAt, written);
		return { bytes: w.finish(), truncated: false };
	} catch (err) {
		if (!(err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE)) throw err;
		// the full encode does not fit: undo it — the compression targets it registered included — and decide by the
		// model below. The head stays: it is the same head every path writes, and the tail gate above already held.
		w.rollback(plainMark);
		written[0] = 0;
		written[1] = 0;
		written[2] = 0;
	}
	let truncated = false;
	let dropped = false; // any RRset dropped from any section — an additionals-only drop never sets TC, but it is still a drop (CLDMV/digby#43)
	outer: for (let s = 0; s < 3; s++) {
		const list = sections[s];
		const { sets, owner } = rrsets(list);
		if (sets.length === 0) continue; // nothing to keep or drop here
		// The model is per section by construction — the tree, the target table, the disturbance index and the heaps
		// are all created fresh below — so the exact-trial fallback is per section too (CLDMV/digby#43): a section
		// whose model fell back decides its own prefixes by exact trials, and the next section gets the model back.
		// Carrying the fallback across sections would cost every later section the trial-per-prefix work — quadratic
		// after a single model lie — with nothing gained: no state a later section reads is broken by an earlier
		// section's lie, and the per-section models compose into the global order because later sections can never
		// shorten earlier sections' records (see the keep-rule comment above).
		let modelBroken = false; // the model is untrusted: every prefix from `brokenFrom` on is decided by exact trial
		let brokenFrom = sets.length; // the set index the model broke at (0 when the cascade guard tripped)
		// the stream offset this section's records sit at: the header and questions plus every kept record of the
		// sections before it. This section's kept stream is materialised only by its winning trial, so the section's
		// offsets anchor here throughout the scan.
		const sectionBase = w.length;
		const fen = new Fenwick(list.length); // measured record position -> its exact wire octets
		const model = new Map(); // compression target key -> { rec, rel, key, score }
		const setEntries = new Map(); // set index -> { byRec: Map<position, key[]>, byKey: Map<key, Set<position>> }
		const index = new Map(); // examined key -> Set of set indices whose records examined it
		// The probe's scratch cap is 2 GiB, not MAX_MESSAGE: the model now folds every set, so the drop-here stream it
		// measures can be arbitrarily larger than the limit (a message whose records carry megabytes of rdata); a
		// measurement past even this cap breaks the model (see `brokenFrom` in the scan below) rather than lying about
		// a total. The buffer grows on demand, so the cap costs nothing until a shape that large actually arrives.
		const probe = new Writer({ max: 0x80000000, compress });
		const overlay = new Map(); // key -> { rec, rel, real } — the measurement's own registrations, in range or not
		const heapV = []; // every in-range registration (the model's entry for its key, or a displaced one still watched), by (slack + the cumulative positive shift at push)
		const heapI = []; // every out-of-range registration, by (deficit + the cumulative negative shift at push)
		let cumPos = 0; // every positive octet the tree ever gained: a registration's slack shrank by at most this since its push
		let cumNeg = 0; // every negative octet the tree ever lost: an out-of-range registration's deficit shrank by at most this since its push
		let runTotal = 0; // fen.total() maintained incrementally: the kept octets of every set folded so far
		const queue = new Map(); // set index -> Set<key> — the re-measure reasons waiting for the set
		let recStart = 0; // probe offset where the record being measured starts
		let curRec = 0; // the position of the record being measured
		let curShift = 0; // kept octets between the candidate's first record and it
		let curReal = 0; // the record's first octet's offset in the drop-here stream
		const touched = [];
		const realOf = (entry) => sectionBase + fen.prefix(entry.rec) + entry.rel;
		// A registration is usable as a pointer target exactly while its stream offset stays below 0x4000, and shifts
		// move registrations both ways — so validity has to be re-checked without scanning the model per round. The
		// registrations currently in the range sit in a lazy min-heap keyed by slack + cumPos at push, the ones out of
		// the range in a second keyed by deficit + cumNeg at push, where deficit = offset - 0x4000 and cumNeg counts
		// every negative octet the tree ever lost. cumPos grows by every positive octet the tree gains, so popping
		// while the key is below cumPos finds every crossing OUT of the range and only those (a negative octet can only
		// delay a crossing, so `positiveSince > slack` is necessary for one — CLDMV/digby#43); symmetrically, cumNeg
		// grows by every negative octet the tree loses, so popping the out-of-range heap while its key is below cumNeg
		// finds every drift back IN and only those (a positive octet can only deepen a deficit). The drift-in heap is
		// what keeps the model's totals from overstating the stream: a registration that crossed out re-measured its
		// examiners with the target absent (their octets grew); if it then drifts back under 0x4000, a fresh
		// measurement would compress against it and their stored octets are stale-high — an overcount, the one model
		// lie the largest-fit search cannot self-correct (an understated total only adds candidates, and every
		// candidate is exact-trial-verified; an overstated one can hide a fitting prefix from the fit check). Round 7
		// left that direction unwatched and settled it by exact-trialling every refused set; the largest-fit search
		// has no refused set to trial, so the drift is watched instead. Round 10 widens it to every out-of-range
		// registration, including ones born out of range: the round-9 gate dropped those outright, so a shrink that
		// pulled one back under 0x4000 went unwatched and its examiners stayed stale-high (CLDMV/digby#43).
		const heapPush = (h, entry) => {
			wireCounters.modelWork++;
			h.push(entry);
			let i = h.length - 1;
			while (i > 0) {
				const p = (i - 1) >> 1;
				if (h[p].score <= h[i].score) break;
				[h[p], h[i]] = [h[i], h[p]];
				i = p;
			}
		};
		const heapPop = (h) => {
			const top = h[0];
			const last = h.pop();
			if (h.length > 0) {
				h[0] = last;
				let i = 0;
				for (;;) {
					const l = 2 * i + 1;
					const r = l + 1;
					let m = i;
					if (l < h.length && h[l].score < h[m].score) m = l;
					if (r < h.length && h[r].score < h[m].score) m = r;
					if (m === i) break;
					[h[m], h[i]] = [h[i], h[m]];
					i = m;
				}
			}
			return top;
		};
		const drain = () => {
			// `<=` so a registration that lands EXACTLY on 0x4000 counts as crossed out — it is out of the pointer
			// range there (writeName's own guard is `w.length < 0x4000`): popped, queued for its examiners and moved
			// to the drift-in heap, where a later shift back under is watched. With `<` it would stay in this heap
			// unwatched, and a later pure-negative shift would resurrect it without anybody re-measuring — stored
			// octets stale-high, the one overcount the largest-fit search cannot self-correct (CLDMV/digby#43,
			// round 9).
			while (heapV.length > 0 && heapV[0].score <= cumPos) {
				const entry = heapPop(heapV);
				wireCounters.modelWork++;
				if (model.get(entry.key) !== entry) {
					// a watched registration that is not the model's entry for its key — displaced by a later
					// adoption (round 10). Its crossing out cannot make the key absent while the primary entry is
					// in range, and if the primary is out of range the drift-in heap watches the comeback — so it
					// is only re-keyed here, never queued.
					const off = realOf(entry);
					if (off < 0x4000) {
						entry.score = 0x4000 - off + cumPos;
						heapPush(heapV, entry);
					} else {
						entry.score = off - 0x4000 + cumNeg;
						heapPush(heapI, entry);
					}
					continue;
				}
				const off = realOf(entry);
				if (off < 0x4000) {
					// still in range: re-key with the fresh slack and wait for the next shift
					entry.score = 0x4000 - off + cumPos;
					heapPush(heapV, entry);
					continue;
				}
				// the registration crossed out of the pointer range: whoever examined it may now write it in full —
				// and the entry moves to the drift-in heap, where a later shift back under the range is caught
				const ix = index.get(entry.key);
				if (ix !== undefined) for (const q of ix) queuePush(q, entry.key, undefined);
				entry.score = off - 0x4000 + cumNeg;
				heapPush(heapI, entry);
			}
		};
		const drainInvalid = () => {
			while (heapI.length > 0 && heapI[0].score < cumNeg) {
				const entry = heapPop(heapI);
				wireCounters.modelWork++;
				if (model.get(entry.key) !== entry) {
					// a watched registration that is not the model's entry for its key (round 10): re-keyed while it
					// stays out of range; when it drifts back under and the primary entry is absent or still out of
					// range, it is ADOPTED as the primary — the real stream's registration is the first write of the
					// key in stream order, so the drifted-in watcher is what the stream compresses against, and the
					// examiners' stored octets are stale-high until they are re-measured
					const off = realOf(entry);
					if (off >= 0x4000) {
						entry.score = off - 0x4000 + cumNeg;
						heapPush(heapI, entry);
						continue;
					}
					const cur = model.get(entry.key);
					if (cur === undefined || realOf(cur) >= 0x4000) {
						model.set(entry.key, entry);
						const ix = index.get(entry.key);
						if (ix !== undefined) for (const q of ix) queuePush(q, entry.key, undefined);
					}
					entry.score = 0x4000 - off + cumPos;
					heapPush(heapV, entry);
					continue;
				}
				const off = realOf(entry);
				if (off >= 0x4000) {
					// still out of range: re-key with the fresh deficit and wait for the next shift
					entry.score = off - 0x4000 + cumNeg;
					heapPush(heapI, entry);
					continue;
				}
				// the registration drifted back under the pointer range: whoever examined it while it was out may
				// now compress against it — their stored octets are stale-high until they are re-measured
				const ix = index.get(entry.key);
				if (ix !== undefined) for (const q of ix) queuePush(q, entry.key, undefined);
				entry.score = 0x4000 - off + cumPos;
				heapPush(heapV, entry);
			}
		};
		const setFen = (i, v) => {
			const d = fen.set(i, v);
			if (d > 0) cumPos += d;
			else if (d < 0) cumNeg -= d;
			runTotal += d; // the running fen.total(): each prefix's stream total, read off in O(1)
			return d;
		};
		const queuePush = (j, key, except) => {
			wireCounters.modelWork++;
			if (j === except || !setEntries.has(j)) return;
			let keys = queue.get(j);
			if (keys === undefined) {
				keys = new Set();
				queue.set(j, keys);
			}
			keys.add(key);
		};
		const lookup = (key) => {
			const o = overlay.get(key);
			// an out-of-range registration is not a pointer target: recorded (round 10, watched by the drift-in
			// heap), but the measurement writes the name in full while its real offset stays at or past 0x4000
			if (o !== undefined) return o.real < 0x4000 ? o.real : undefined;
			const m = model.get(key);
			if (m !== undefined) {
				const r = realOf(m);
				// a target is visible only where the stream already has it: written by an EARLIER record — record
				// order, not an offset read off the tree, because the records being measured are not in the tree yet
				// and an offset check would place a later record's registration before the in-flight write position
				// (the probe then saw a target the real stream did not have yet, an uncompressed-but-registering name
				// never recorded its registration, and the model overcounted — CLDMV/digby#43, round 9) — and inside
				// the pointer range.
				return r < 0x4000 && m.rec < curRec ? r : undefined;
			}
			return w.names.get(key);
		};
		// The probe's compression table: the model's targets at their stream offsets, the measurement's own
		// registrations corrected by the shift, and every examined key recorded for the disturbance index. Every
		// registration is recorded, in pointer range or not (round 10): one whose real offset has reached 0x4000 is
		// not a pointer target yet (the real stream's write would be past the range — writeName's own guard is
		// `w.length < 0x4000`), but it is watched, because a later shrink can pull its real offset back under the
		// boundary and make it real — the round-9 gate dropped it outright and left that comeback unwatched
		// (CLDMV/digby#43). The first write of a key in stream order is the registration the real stream makes: the
		// probe's real offsets grow across a measurement, so a later record's write of the same key never displaces
		// an earlier record's.
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
				const prev = overlay.get(key);
				if (prev !== undefined && prev.real <= real) return;
				overlay.set(key, { rec: curRec, rel: at - recStart, real });
			},
			delete(key) {
				overlay.delete(key);
			}
		};
		// Measure the given open records of this section consecutively into the probe: each record's octets at its
		// own position in the drop-here stream, plus the keys it examined. A candidate set is measured whole; a
		// re-measure measures only the records a disturbance touched (CLDMV/digby#43).
		const measureSet = (positions) => {
			// validity crossings and drift-ins left over from the keeps and re-measures since the last cascade settle
			// before anything is measured against the model
			drain();
			drainInvalid();
			if (positions.length === 0) return { recs: [], contribution: 0, overflow: false };
			const p1 = positions[0];
			const probeBase = sectionBase + fen.prefix(p1);
			probe.length = probeBase;
			probe.added.length = 0;
			overlay.clear();
			const recs = [];
			let overflow = false;
			// the shift is the kept octets between the measured records: the tree's range minus the measured
			// records' own octets in it (zero for a candidate, whose positions are not in the tree yet; their old
			// octets on a re-measure, which the consecutive probe layout already carries)
			let own = 0;
			let ownNew = 0; // probe octets written for the measured records before the one being measured
			for (const at of positions) {
				curRec = at;
				curShift = fen.prefix(at) - fen.prefix(p1) - own;
				// the record's first octet sits at the kept octets before it plus its own measured records as the
				// probe just wrote them (the tree still carries their old values)
				curReal = sectionBase + fen.prefix(at) - own + ownNew;
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
				recs.push({ at, oct: probe.length - start, examined: touched.splice(0) });
				ownNew += probe.length - start;
			}
			return { recs, contribution: overflow ? Infinity : probe.length - probeBase, overflow };
		};
		// Fold one registration of a measurement into the model. The entry replaces whatever was there, and the
		// examiners of a key whose model entry changed go back to the re-measure queue: a brand-new key that is in
		// the pointer range shortens the records that examined it while it was absent; a replaced entry whose
		// offset or validity moved can shorten (the target reappeared earlier in the stream than the record that
		// measured against the old one assumed) or lengthen (it vanished) them. An out-of-range registration that
		// replaces another out-of-range one changes nothing visible — the key is absent to every examiner either
		// way — so its examiners stay put. `except` keeps a set out of its own queue entry — the records a
		// re-measure just re-measured are already done.
		//
		// The no-displacement rule (round 10, CLDMV/digby#43): an out-of-range registration never replaces the
		// model's in-range entry for its key. The real stream's registration of a key is its first write in stream
		// order; a registration recorded out of range is the candidate for that slot, watched by the drift-in heap,
		// and when the in-range entry it could not displace later crosses out, the drifted-in watcher takes the
		// slot (drainInvalid) instead of leaving the model blind to a target the stream compresses against. A
		// displaced entry stays watched in the heap matching its own range, so its later crossings and comebacks
		// still reach the examiners that measured against it.
		const adopt = (key, e, except, prevKnown) => {
			wireCounters.modelWork++;
			// `prevKnown` is what the examiners last measured against when the caller already knows it (a
			// re-measure deletes the record's own registration before re-measuring, so the model no longer holds
			// it); otherwise the model's current entry is the prev.
			const prev = prevKnown !== undefined ? prevKnown : (model.get(key) ?? null);
			const entry = { rec: e.rec, rel: e.rel, key, score: 0 };
			const off = realOf(entry);
			const prevOff = prev === null ? -1 : realOf(prev); // the tree is frozen while a measurement's overlay is adopted
			if (prev !== null && prevOff < 0x4000 && off >= 0x4000) {
				// out of range against an in-range entry: the key stays visible at the in-range entry — a pointer
				// is two octets to either target, so the examiners' stored octets are unchanged and nobody
				// re-measures. The out-of-range registration is still recorded, in the drift-in heap. A `prevKnown`
				// prev was removed from the model before the measurement (a re-measured record's own registration),
				// so it goes back in — and back into the in-range heap, where its own crossings stay watched.
				if (model.get(key) !== prev) {
					model.set(key, prev);
					prev.score = 0x4000 - prevOff + cumPos;
					heapPush(heapV, prev);
				}
				entry.score = off - 0x4000 + cumNeg;
				heapPush(heapI, entry);
				return;
			}
			model.set(key, entry);
			if (prev !== null) {
				// the displaced entry stays watched: its own offset moves with the same shifts, and a later
				// crossing or comeback of it still reaches the examiners that measured against it (round 10)
				if (prevOff < 0x4000) {
					prev.score = 0x4000 - prevOff + cumPos;
					heapPush(heapV, prev);
				} else {
					prev.score = prevOff - 0x4000 + cumNeg;
					heapPush(heapI, prev);
				}
			}
			if (off < 0x4000) {
				entry.score = 0x4000 - off + cumPos;
				heapPush(heapV, entry);
			} else {
				entry.score = off - 0x4000 + cumNeg;
				heapPush(heapI, entry);
			}
			const moved = prev !== null && off !== prevOff;
			if ((prev === null && off < 0x4000) || (moved && (off < 0x4000 || prevOff < 0x4000))) {
				const ix = index.get(key);
				if (ix !== undefined) for (const q of ix) queuePush(q, key, except);
			}
		};
		const keepSet = (k, m) => {
			const byRec = new Map();
			const byKey = new Map();
			for (const { at, oct } of m.recs) setFen(at, oct);
			for (const [key, e] of overlay) {
				adopt(key, e);
				let keys = byRec.get(e.rec);
				if (keys === undefined) {
					keys = [];
					byRec.set(e.rec, keys);
				}
				keys.push(key);
			}
			for (const { at, examined } of m.recs) {
				for (const key of examined) {
					let ps = byKey.get(key);
					if (ps === undefined) {
						ps = new Set();
						byKey.set(key, ps);
					}
					ps.add(at);
					let ix = index.get(key);
					if (ix === undefined) {
						ix = new Set();
						index.set(key, ix);
					}
					ix.add(k);
				}
			}
			setEntries.set(k, { byRec, byKey });
		};
		// Re-measure the records of every queued set that its reason touches (CLDMV/digby#43): the records whose last
		// measurement examined a key whose state changed — a registration added, removed, or shifted across the
		// pointer range — plus, in turn, the records the re-measured ones' own registrations can no longer be
		// trusted for. The wave's sets are collected and their affected records merged into ONE probe pass (round 9):
		// a record's octets depend on the model's targets and on the records written before it — not on the other
		// re-measured records' stored values — the probe corrects every record's position by the exact shift, and
		// the tree stays frozen until every setFen lands, so one pass over the merged positions costs one probe
		// setup and one drain cycle instead of one per set. Re-measuring a record is always safe, so the selection
		// may over-select; it must not under-select, or a stale octet count could understate the stream and keep a
		// prefix that does not fit.
		const remeasureJobs = (jobs) => {
			const affected = new Set(); // every affected record position, across the wave's sets
			const setOfPosition = new Map(); // an affected position -> the index of the set owning it
			for (const [j, reasonKeys] of jobs) {
				const state = setEntries.get(j);
				const pending = [...reasonKeys];
				const seen = new Set(reasonKeys);
				while (pending.length > 0) {
					const key = pending.pop();
					for (const at of state.byKey.get(key) ?? []) {
						if (affected.has(at)) continue;
						affected.add(at);
						setOfPosition.set(at, j);
						for (const k2 of state.byRec.get(at) ?? [])
							if (!seen.has(k2)) {
								seen.add(k2);
								pending.push(k2);
							}
					}
				}
			}
			if (affected.size === 0) return;
			const positions = [...affected].sort((a, b) => a - b);
			// the affected records' own registrations come out first: a record must not compress against the
			// registration its own previous measurement made — in the stream it is being re-measured for, it
			// writes that name itself. Only the record's OWN model entries come out: an entry another record's
			// re-registration replaced is that record's target now, and the re-measure may compress against it
			// (the record-order visibility check in `lookup` keeps a record from compressing against a target
			// registered by a record at or past its own position).
			const removed = new Map();
			for (const at of positions) {
				const state = setEntries.get(setOfPosition.get(at));
				const keys = state.byRec.get(at);
				wireCounters.modelWork++;
				if (keys !== undefined) {
					for (const key of keys) {
						const old = model.get(key);
						if (old !== undefined && old.rec === at) {
							wireCounters.modelWork++;
							model.delete(key);
							removed.set(key, old);
						}
					}
					state.byRec.delete(at);
				}
			}
			const m = measureSet(positions);
			for (const key of removed.keys()) {
				if (!overlay.has(key)) {
					// the registration is gone for good: whoever examined it may now write it in full
					const ix = index.get(key);
					if (ix !== undefined) for (const q of ix) queuePush(q, key, setOfPosition.get(removed.get(key).rec));
				}
			}
			for (const [key, e] of overlay) {
				// a key removed above and registered again: the removed entry is what the examiners last measured
				// against, so it is the `prev` the queue decision compares against — an equivalent re-registration
				// queues nobody, a moved one does
				const j = setOfPosition.get(e.rec);
				const state = setEntries.get(j);
				adopt(key, e, j, removed.has(key) ? (removed.get(key) ?? null) : undefined);
				let keys = state.byRec.get(e.rec);
				if (keys === undefined) {
					keys = [];
					state.byRec.set(e.rec, keys);
				}
				keys.push(key);
			}
			for (const { at, oct } of m.recs) {
				if (fen.vals[at] !== oct) setFen(at, oct);
			}
			for (const { at, examined } of m.recs) {
				const state = setEntries.get(setOfPosition.get(at));
				for (const key of examined) {
					let ps = state.byKey.get(key);
					if (ps === undefined) {
						ps = new Set();
						state.byKey.set(key, ps);
					}
					ps.add(at);
					let ix = index.get(key);
					if (ix === undefined) {
						ix = new Set();
						index.set(key, ix);
					}
					ix.add(setOfPosition.get(at));
				}
			}
		};
		// Presence flips and re-measures until the model is consistent. The flip scan of the earlier rounds is
		// gone: validity crossings come off the in-range heap (drain), drift-ins off the out-of-range one
		// (drainInvalid), record-level disturbances come off the queue, and all three feed the same re-measure.
		// There is no rollback any more: a keep is never provisional under the largest-fit rule (every prefix's
		// total is read off the model, so every set stays folded), and when the guard trips the model is abandoned
		// for the rest of the section outright. Returns false when the guard trips. Each round is a WAVE: every set
		// currently queued re-measures in one merged pass (CLDMV/digby#43, round 9), so a crossing that unseats
		// many examiners costs one pass, not one per examiner.
		const cascade = (seedKeys, exceptSet) => {
			if (seedKeys !== undefined)
				for (const key of seedKeys) {
					const ix = index.get(key);
					if (ix !== undefined) for (const q of ix) queuePush(q, key, exceptSet);
				}
			let rounds = 0;
			for (;;) {
				drain();
				drainInvalid();
				if (queue.size === 0) return true;
				if (++rounds > 64 + sets.length) return false;
				const jobs = [];
				for (const [j, keys] of queue) {
					queue.delete(j);
					if (setEntries.has(j)) jobs.push([j, keys]);
				}
				if (jobs.length > 0) remeasureJobs(jobs);
			}
		};
		// The scan: fold every set into the model, in first-appearance order, recording each prefix's exact
		// stream total. Nothing is written for good during the scan — a set is folded whether or not its prefix
		// fits, because a longer prefix contains it and a longer prefix can fit where a shorter one does not (the
		// non-monotonicity the keep rule exists for) — the winning prefix is materialised once, by its own trial,
		// below.
		const totals = new Float64Array(sets.length); // prefix k's exact drop-here stream octets (kept records only)
		let frozenAt = sets.length; // past the frozen point no prefix fits: see the keep-rule comment
		for (let k = 0; k < sets.length; k++) {
			const m = measureSet(sets[k]);
			if (m.overflow) {
				// the measurement ran past the probe's scratch cap: the model cannot place this set, so its total
				// and every later one are untrusted — the prefixes from here on are decided by exact trial
				modelBroken = true;
				brokenFrom = k;
				break;
			}
			keepSet(k, m);
			if (!cascade(overlay.keys(), k)) {
				// the cascade guard tripped: the model is abandoned outright — every prefix of this section is
				// decided by exact trial (quadratic within the section, contained here, unreached in clean code)
				modelBroken = true;
				brokenFrom = 0;
				break;
			}
			totals[k] = runTotal;
			// The frozen point: the prefix is over budget AND every record a later keep would add sits at a stream
			// offset at or above the pointer range. Folding the later sets can add no compression target — no
			// re-measure fires, no stored octet shrinks — so every longer prefix is this prefix's stream plus
			// positive octets, and it cannot fit either. The sets past this point are never measured.
			if (sectionBase + runTotal + tailBound > limit && k + 1 < sets.length && sectionBase + fen.prefix(sets[k + 1][0]) >= 0x4000) {
				frozenAt = k;
				break;
			}
		}
		// The largest fitting prefix (see selectKept): candidates newest-first off the model's totals, the winner
		// verified — and materialised — by an exact trial. Past the frozen point nothing is a candidate; past a
		// model break every prefix from the break on is one (the trial decides it outright).
		const kept = selectKept({
			count: sets.length,
			isCandidate: (k) => k < frozenAt && (k < brokenFrom ? sectionBase + totals[k] + tailBound <= limit : true),
			firstPos: (k) => (k < sets.length ? sets[k][0] : Number.POSITIVE_INFINITY),
			ownerAt: (pos) => owner[pos],
			trial: (k) => {
				// the candidate's drop-here stream, written for real at its original positions against the state the
				// winner's stream will be sent in — on success the writes stay: they ARE the output. `failPos` is the
				// position of the record whose write hit the limit (-1 when the failure was not a record write, e.g.
				// the tail check) — the fallback's cost bound reads it (round 10, CLDMV/digby#43).
				const mark = w.checkpoint();
				const before = written[s];
				let fits = true;
				let failPos = -1;
				try {
					for (let i = 0; i < list.length; i++) {
						if (owner[i] > k) continue;
						try {
							writeRecord(w, list[i]);
						} catch (err) {
							if (err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE) {
								fits = false;
								failPos = i;
								break;
							}
							throw err;
						}
						written[s]++;
					}
					if (fits) fits = w.length <= limit && tailFitsOn(w);
				} catch (err) {
					if (!(err instanceof WireError && err.code === WireErrorCode.MESSAGE_TOO_LARGE)) throw err;
					fits = false;
				}
				if (!fits) {
					w.rollback(mark);
					written[s] = before;
				}
				return { fits, failPos };
			}
		});
		if (kept < sets.length - 1) {
			// the truncation point: this prefix and everything after it, in every section, is dropped
			dropped = true;
			if (s < 2) truncated = true;
			break outer;
		}
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

/**
 * The keep-selection rule, in one place (CLDMV/digby#43, round 8): the kept sets are the LONGEST PREFIX of the
 * section's RRsets, in first-appearance order, whose drop-here stream fits the limit — the largest k whose k-set
 * prefix fits. The caller supplies the candidate test (which prefixes the model says could fit — the search skips
 * the rest without measuring them further) and the exact trial (which writes a candidate's drop-here stream for
 * real and answers whether it fits; on success its bytes stay written — the trial IS the final write). Candidates
 * are probed newest-first: the largest candidate is tried first, and the first trial that fits is the largest
 * fitting prefix — under a model lie in the undercount direction a fitting prefix is always a candidate, so the
 * trials self-correct whatever the totals said; the empty prefix (k = -1) always fits (the header, questions and
 * tail alone were checked before the scan), so it needs no trial.
 *
 * Swapping the rule (the user is still deciding between prefix and best subset) is contained here: a best-subset
 * rule would change what the scan must place in the model and what a trial verifies, but the shape of this
 * decision — candidates newest-first, exact-trial-verified, largest wins — stays.
 *
 * The failed-trial skip (round 10, CLDMV/digby#43) bounds the exact-trial fallback's cost: after trial(j) failed at
 * record position q, the trials for the candidates below j would rewrite the same stream and fail at the same record
 * for as long as every set between them owns no record before q — a record's bytes depend only on the records before
 * it (pointers reach backwards), so if none of the sets j, j-1, .., k+1 has a record at a position < q, the candidate
 * k's stream up to q is byte for byte trial(j)'s, record q is attempted (it belongs to a set ≤ k) and fails
 * identically. Skipping it costs one comparison instead of a full rewrite — on a message of n independent records
 * whose fitting prefix is a fraction of the input, that is the difference between O(n) failed trials that each write
 * the output-size stream (quadratic) and O(n) one-comparison skips plus O(output) rewrites (linear in the records
 * actually written). A candidate whose sets DO own records before q changes the compression state of everything
 * after them, so its trial runs for real. The chain tracks the smallest first-position of the sets between the
 * candidate and the last run trial; a failure that is not a record write (the tail check) leaves no positional
 * evidence, so the chain resets and the next candidate runs.
 *
 * @param {{ count: number, isCandidate: (k: number) => boolean, firstPos: (k: number) => number, ownerAt: (pos: number) => number, trial: (k: number) => { fits: boolean, failPos: number } }} search
 * @returns {number} the last kept set's index (the largest fitting prefix is sets 0..k), or -1 when no set fits
 */
function selectKept({ count, isCandidate, firstPos, ownerAt, trial }) {
	let failPos = -1; // the record position where the last run trial failed (-1: none yet, or the failure left no positional evidence)
	let minAbove = Number.POSITIVE_INFINITY; // the smallest first-position among the sets between the candidate and the last run trial
	for (let k = count - 1; k >= 0; k--) {
		minAbove = Math.min(minAbove, firstPos(k + 1));
		if (!isCandidate(k)) continue;
		if (failPos >= 0 && minAbove >= failPos && ownerAt(failPos) <= k) continue;
		const r = trial(k);
		if (r.fits) return k;
		failPos = r.failPos;
		minAbove = Number.POSITIVE_INFINITY;
	}
	return -1;
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

	/** Set the octets at position `i`. @returns {number} the delta applied (0 when the value did not change) */
	set(i, v) {
		wireCounters.modelWork++; // a Fenwick operation is a unit of model work (CLDMV/digby#43)
		const d = v - this.vals[i];
		if (d === 0) return 0;
		this.vals[i] = v;
		for (i++; i <= this.n; i += i & -i) this.tree[i] += d;
		return d;
	}

	/** Sum of the octets at positions `0..i-1`. */
	prefix(i) {
		wireCounters.modelWork++; // a Fenwick operation is a unit of model work (CLDMV/digby#43)
		let sum = 0;
		for (; i > 0; i -= i & -i) sum += this.tree[i];
		return sum;
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
