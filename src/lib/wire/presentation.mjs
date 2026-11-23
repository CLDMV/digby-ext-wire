/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/presentation.mjs
 */

/**
 * @fileoverview The presentation (master-file) form of whole records, on top of the per-type rdata parsers in `rdata/`.
 *
 * `parseRecord` reads one record: `owner [ttl] [class] type rdata`, TTL and class in either order (RFC 1035 5.1), the owner
 * relative to `origin` or `@`, the TTL in seconds or with BIND units (`1h30m`). Directives (`$ORIGIN`, `$TTL`, `$INCLUDE`) and
 * owner inheritance across lines are the zone file reader's business, not this module's: `zones` feeds it one record at a
 * time. `formatRecord` writes the canonical one-line form.
 */

import { CLASS, classFromString, classToString, isClassToken, typeFromString, typeToString } from "./constants.mjs";
import { WireErrorCode, cloneInput, fail } from "./errors.mjs";
import { RDATA_REQUIRED } from "./message.mjs";
import { canonicalName } from "./names.mjs";
import { encodeRdataBytes, formatGeneric, formatRdata, isGenericForm, parseRdataTokens } from "./rdata/index.mjs";
import { Tokens, tokenize } from "./text.mjs";

export { formatRdata, parseRdata, formatGeneric } from "./rdata/index.mjs";

const UNIT = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };

/** The largest TTL the codec accepts (RFC 2181 8); encode's wire writer uses the same bound. */
const MAX_TTL = 0x7fffffff;

/** The top of the type range is reserved (RFC 6895); no record may use it (CLDMV/digby#38). */
const RESERVED_TYPE = 0xffff;

/**
 * Parse a TTL: seconds, or BIND-style units (`1w2d3h4m5s`, case-insensitive). At most 2^31 - 1 (RFC 2181 8).
 * @param {string} text
 * @returns {number}
 */
export function parseTtl(text) {
	let v;
	if (/^\d+$/.test(text)) v = Number(text);
	else if (/^(?:\d+[smhdwSMHDW])+$/.test(text)) {
		v = 0;
		for (const [, n, u] of text.matchAll(/(\d+)([smhdwSMHDW])/g)) v += Number(n) * UNIT[u.toLowerCase()];
	} else return fail(WireErrorCode.BAD_PRESENTATION, `"${text}" is not a TTL`);
	if (v > 0x7fffffff) fail(WireErrorCode.BAD_PRESENTATION, `TTL ${text} is over 2^31 - 1`);
	return v;
}

const isTtlToken = (text) => /^\d+$/.test(text) || /^(?:\d+[smhdwSMHDW])+$/.test(text);

/**
 * Parse one record.
 *
 * @param {string} text
 * @param {object} [options]
 * @param {string} [options.origin] - completes relative names (owner and rdata) and `@`
 * @param {number} [options.ttl] - the TTL when the record gives none (a zone's `$TTL`); without it a TTL is required
 * @param {number} [options.class=1] - the class when the record gives none
 * @returns {{ name: string, ttl: number, class: number, type: number, data: object | null }}
 */
export function parseRecord(text, { origin, ttl: defaultTtl, class: defaultClass = CLASS.IN } = {}) {
	const t = new Tokens(tokenize(text));
	const name = canonicalName(t.word("owner name"), origin);
	let ttl;
	let clsTok;
	for (let k = 0; k < 2 && !t.done; k++) {
		const tok = t.list[t.i];
		if (tok.quoted) break;
		if (ttl === undefined && isTtlToken(tok.value)) {
			ttl = parseTtl(tok.value);
			t.i++;
		} else if (clsTok === undefined && isClassToken(tok.value)) {
			clsTok = classFromString(tok.value);
			t.i++;
		} else break;
	}
	const type = typeFromString(t.word("type"));
	// type 0 and the top of the type range are reserved (RFC 6895); no record may use either (CLDMV/digby#38)
	if (type === 0 || type === RESERVED_TYPE) fail(WireErrorCode.BAD_PRESENTATION, `record type ${type} is reserved`);
	ttl ??= defaultTtl;
	if (ttl === undefined) fail(WireErrorCode.BAD_PRESENTATION, "the record has no TTL and no default was given");
	const cls = clsTok ?? defaultClass;
	// No rdata text at all is the RFC 2136 update form, the same rule readRecord and writeRecord apply (CLDMV/digby#37):
	// empty rdata is only a class ANY or NONE record — every other class with no rdata stays refused. The zero-length
	// generic form (`\# 0`) is the update form too under ANY / NONE; parseRdataTokens maps it the way the wire reader
	// maps rdlength 0.
	let data;
	if (t.done) {
		if (cls !== CLASS.ANY && cls !== CLASS.NONE)
			fail(WireErrorCode.BAD_PRESENTATION, "the record has no rdata; empty rdata is only the class ANY or NONE update form");
		data = null;
	} else data = parseRdataTokens(type, t, origin, cls);
	if (data === null && RDATA_REQUIRED.has(type))
		fail(WireErrorCode.BAD_PRESENTATION, `${typeToString(type)} rdata must be present; the empty-rdata update form does not apply to it`);
	return { name, ttl, class: cls, type, data };
}

/**
 * Format one record on one line: `name ttl class type rdata`. Every field is validated first, so a bad shape raises a
 * {@link WireError} — the line can never carry injected record text (CLDMV/digby#37).
 * @param {{ name: string, ttl: number, class?: number, type: number, data: object | null }} rec
 * @returns {string}
 * @throws {import("./errors.mjs").WireError} VALUE_OUT_OF_RANGE, BAD_PRESENTATION, or whatever the rdata encoding raises
 *   (including MESSAGE_TOO_LARGE for rdata past a record's 65,535-octet limit)
 */
export function formatRecord(rec) {
	if (rec === null || typeof rec !== "object" || Array.isArray(rec)) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "a record must be an object");
	// one copy of the caller's record (CLDMV/digby#39): the input is copied once with structuredClone and every field is read
	// exactly once from the copy, so the validation and the line see the same values — a getter cannot show the checks one
	// value and the printed line another
	const snap = cloneInput(rec, "a record");
	const name = canonicalName(snap.name); // parses, so no unvalidated name text reaches the line
	if (!Number.isInteger(snap.ttl) || snap.ttl < 0 || snap.ttl > MAX_TTL) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `TTL out of range: ${String(snap.ttl)}`);
	const cls = snap.class ?? CLASS.IN;
	if (!Number.isInteger(cls) || cls < 0 || cls > 0xffff) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `class out of range: ${String(cls)}`);
	if (!Number.isInteger(snap.type) || snap.type < 0 || snap.type > 0xffff) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `type out of range: ${String(snap.type)}`);
	// the record-layer rules parseRecord and writeRecord apply (CLDMV/digby#38): types 0 and 65535 are reserved, and empty
	// rdata is only the RFC 2136 update form — a type that must carry rdata (RDATA_REQUIRED) never takes it
	if (snap.type === 0 || snap.type === RESERVED_TYPE) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `record type ${snap.type} is reserved`);
	const head = `${name} ${snap.ttl} ${classToString(cls)} ${typeToString(snap.type)}`;
	if (snap.data === null) {
		// the RFC 2136 empty-rdata update form, same rule as writeRecord: empty rdata is only a class ANY or NONE record, so
		// anything else would print a line parseRecord refuses (CLDMV/digby#37)
		if (cls !== CLASS.ANY && cls !== CLASS.NONE) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "empty rdata (data: null) is only for class ANY or NONE");
		if (RDATA_REQUIRED.has(snap.type)) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${typeToString(snap.type)} rdata must be present; the empty-rdata update form does not apply to it`);
		return head;
	}
	// Generic-form rdata: the types with no presentation of their own, and OPT — typed on the wire, generic in text. The
	// octets are encoded here, so the zero-length refusal below and the printed line describe the same rdata (CLDMV/digby#37).
	if (isGenericForm(snap.type)) {
		const octets = encodeRdataBytes(snap.type, snap.data);
		// under class ANY or NONE, zero-length rdata IS the update form — the wire reader maps rdlength 0 to data: null
		// (CLDMV/digby#37) — so `\# 0` has no line of its own: it parses back as data: null. Refuse it and ask for the
		// update form itself. OPT with no options slipped through the shape check that only saw the generic `{ data }` form
		// (CLDMV/digby#38); encoding decides it for every generic-form type alike.
		if ((cls === CLASS.ANY || cls === CLASS.NONE) && octets.length === 0)
			fail(WireErrorCode.VALUE_OUT_OF_RANGE, "zero-length rdata in class ANY or NONE is the empty-rdata update form; give data: null");
		return `${head} ${formatGeneric(octets)}`;
	}
	return `${head} ${formatRdata(snap.type, snap.data)}`;
}
