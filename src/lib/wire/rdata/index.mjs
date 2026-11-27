/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/rdata/index.mjs
 */

/**
 * @fileoverview The rdata registry: type number → codec, and the four entry points every caller uses (decode, encode, parse,
 * format). A type with no typed codec goes through the RFC 3597 generic form: `{ data: Uint8Array }` on the wire side and
 * `\# <length> <hex>` in presentation. A typed type also accepts the generic presentation form (RFC 3597 5), whose octets are
 * then decoded with the typed codec, so a malformed generic rdata is refused the same way as malformed wire.
 */

import { MAX_MESSAGE, Reader, Writer, asBytes, intrinsicView, isSharedBuffer } from "../buffer.mjs";
import { CLASS, TYPE, typeToString } from "../constants.mjs";
import { readOptions, writeOptions } from "../edns.mjs";
import { WireError, WireErrorCode, cloneInput, describe, fail } from "../errors.mjs";
import { Tokens, fromHex, toHex, tokenize } from "../text.mjs";
import { A, AAAA, CAA, CNAME, MX, NAPTR, NS, PTR, SOA, SRV, SSHFP, TLSA, TXT } from "./basic.mjs";
import { badRdata, bytes, obj } from "./common.mjs";
import { CDNSKEY, CDS, DNSKEY, DS, NSEC, NSEC3, NSEC3PARAM, RRSIG } from "./dnssec.mjs";
import { HTTPS, SVCB } from "./svcb.mjs";
import { TSIG } from "./tsig.mjs";

/** OPT as an rdata type: `{ options }`. Its presentation is the generic form only (OPT never appears in master files). */
const OPT = {
	name: "OPT",
	decode: (r) => ({ options: readOptions(r) }),
	encode(w, data) {
		writeOptions(w, obj(data, "OPT").options);
	},
	parse: null,
	format: null
};

/** The top of the type range is reserved (RFC 6895); no record may use it (CLDMV/digby#38). */
const RESERVED_TYPE = 0xffff;

/**
 * Validate a standalone entry's type (CLDMV/digby#38): an integer in 0..0xffff, and neither reserved value — the same rule
 * the record layer applies to record and question types. The RR line parser validates its own type before
 * {@link parseRdataTokens}, so this guards the standalone entries only.
 * @param {number} type
 * @returns {number}
 */
function checkRdataType(type) {
	// the type is described, never String()ed: it is the caller's raw value — no clone has run yet — so an
	// Object.create(null) (which String() cannot convert) or a hostile toString must not be able to break the refusal
	// itself (CLDMV/digby#39)
	if (!Number.isInteger(type) || type < 0 || type > 0xffff) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `type out of range: ${describe(type)}`);
	if (type === 0 || type === RESERVED_TYPE) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `type ${type} is reserved`);
	return type;
}

/** @type {Map<number, import("./common.mjs").RdataCodec>} */
const CODECS = new Map([
	[TYPE.A, A],
	[TYPE.NS, NS],
	[TYPE.CNAME, CNAME],
	[TYPE.SOA, SOA],
	[TYPE.PTR, PTR],
	[TYPE.MX, MX],
	[TYPE.TXT, TXT],
	[TYPE.AAAA, AAAA],
	[TYPE.SRV, SRV],
	[TYPE.NAPTR, NAPTR],
	[TYPE.OPT, OPT],
	[TYPE.DS, DS],
	[TYPE.SSHFP, SSHFP],
	[TYPE.RRSIG, RRSIG],
	[TYPE.NSEC, NSEC],
	[TYPE.DNSKEY, DNSKEY],
	[TYPE.NSEC3, NSEC3],
	[TYPE.NSEC3PARAM, NSEC3PARAM],
	[TYPE.TLSA, TLSA],
	[TYPE.CDS, CDS],
	[TYPE.CDNSKEY, CDNSKEY],
	[TYPE.SVCB, SVCB],
	[TYPE.HTTPS, HTTPS],
	[TYPE.TSIG, TSIG],
	[TYPE.CAA, CAA]
]);

/** The type numbers with a typed rdata codec. */
export const TYPED = Object.freeze([...CODECS.keys()].sort((a, b) => a - b));

/**
 * Whether `type` has a typed rdata codec (otherwise it is handled as RFC 3597 opaque octets).
 * @param {number} type
 * @returns {boolean}
 */
export function isTyped(type) {
	return CODECS.has(type);
}

/**
 * Decode rdata. The reader must already be limited to the rdlength (the message layer does it; a standalone caller can use
 * {@link decodeRdataBytes}).
 * @param {number} type
 * @param {Reader} r
 * @returns {object}
 */
export function decodeRdata(type, r) {
	const codec = CODECS.get(type);
	return codec ? codec.decode(r) : { data: r.rest() };
}

/**
 * Decode standalone rdata octets. Standalone rdata carries no compression pointers (RFC 3597 5): there is no message for one
 * to resolve against, so a pointer inside the octets is refused BAD_RDATA wherever the type's codec reads a name
 * (CLDMV/digby#38).
 * @param {number} type
 * @param {Uint8Array} octets
 * @returns {object}
 */
export function decodeRdataBytes(type, octets) {
	// the standalone type rules, the same ones formatRdata, encodeRdataBytes and parseRdata apply (CLDMV/digby#38):
	// reserved and non-integer types are refused — SIG stays a legal type (SIG(0) needs typeCovered 0, RFC 2931)
	checkRdataType(type);
	// the octets are copied once, before the decode reads them (CLDMV/digby#39): the length comes off the intrinsic
	// view a single time and the decode reads the copy — a Proxy over a typed array (whose traps can throw or lie), a
	// faked brand, or a view over shared memory is never consulted again while decoding. The byteLength comes through
	// {@link intrinsicView}, the same path as every other byte entry (CLDMV/digby#39, round 8): the caller's own
	// `byteLength` property used to be read here — a value of 20 on a 4-octet array decoded 16 phantom empty strings,
	// and a throwing own getter was refused while formatGeneric, going through the intrinsic getters, accepted the
	// same value. The buffer is brand-checked with the intrinsic getter, never `instanceof` (CLDMV/digby#39, round 8):
	// a SharedArrayBuffer wearing `ArrayBuffer.prototype` passed the old check and its octets were read, and a
	// cross-realm one failed `instanceof SharedArrayBuffer` from this realm outright. The instanceof and the
	// buffer/byteLength reads can fire the caller's traps, so they sit inside the refusal they feed.
	let copy;
	try {
		const src = bytes(octets, "rdata");
		const view = intrinsicView(src);
		if (view === null) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "rdata must be a plain Uint8Array of octets");
		// a view over a SharedArrayBuffer is refused like any entry's input: the decode must not read memory the
		// caller can change. The buffer is read through the intrinsic getter, so an own `buffer` property cannot
		// shadow the refusal (CLDMV/digby#39)
		if (isSharedBuffer(view.buffer))
			fail(WireErrorCode.NOT_CLONEABLE, "rdata is a view over a SharedArrayBuffer; it would be read, not copied (CLDMV/digby#39)");
		copy = new Uint8Array(view.byteLength);
		copy.set(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
	} catch (err) {
		if (err instanceof WireError) throw err;
		// a Proxy whose traps throw, or a faked brand whose byteLength lies: the octets cannot be read as data
		fail(WireErrorCode.VALUE_OUT_OF_RANGE, "rdata must be a plain Uint8Array of octets");
	}
	const r = new Reader(copy);
	r.standalone = true; // readName refuses compression pointers on a standalone reader (CLDMV/digby#38)
	return r.limit(copy.length, () => decodeRdata(type, r));
}

/**
 * Encode rdata (without the rdlength prefix).
 * @param {import("../buffer.mjs").Writer} w
 * @param {number} type
 * @param {object} data
 */
export function encodeRdata(w, type, data) {
	const codec = CODECS.get(type);
	if (codec) codec.encode(w, data);
	else w.raw(bytes(obj(data, typeToString(type)).data, `${typeToString(type)} data`));
}

/**
 * Parse rdata presentation text. Relative names complete against `origin`.
 *
 * @param {number} type
 * @param {string} text - the rdata part of a master-file record (it may span parenthesised lines and carry comments)
 * @param {string} [origin]
 * @returns {object}
 * @throws {import("../errors.mjs").WireError} BAD_PRESENTATION, BAD_RDATA, BAD_SVCPARAM, RELATIVE_NAME, ...
 */
export function parseRdata(type, text, origin) {
	checkRdataType(type);
	return parseRdataTokens(type, new Tokens(tokenize(text)), origin);
}

/**
 * Parse rdata from a token cursor (shared with the RR line parser).
 * @param {number} type
 * @param {Tokens} t
 * @param {string} [origin]
 * @param {number} [cls] - the record's class when the caller knows it (the RR line parser passes it): the zero-length
 *   generic form (`\# 0`) in class ANY or NONE is the RFC 2136 update form and reads back as `data: null`, the way the
 *   wire reader maps rdlength 0 (CLDMV/digby#37); without a class, `\# 0` stays ordinary zero-length octets
 * @returns {object | null}
 */
export function parseRdataTokens(type, t, origin, cls) {
	const first = t.list[t.i];
	if (first && !first.quoted && first.value === "\\#") {
		t.i++;
		const len = t.int("generic rdata length", 0xffff);
		if (len === 0 && (cls === CLASS.ANY || cls === CLASS.NONE) && t.done) {
			// the update form; the RDATA_REQUIRED refusal for it is the record layer's, so the error names the record parser
			return null;
		}
		const octets = fromHex(t.joinRest(), "generic rdata");
		if (octets.length !== len) badRdata(`generic rdata says ${len} octets but holds ${octets.length}`);
		return decodeRdataBytes(type, octets);
	}
	const codec = CODECS.get(type);
	if (!codec?.parse) badRdata(`${typeToString(type)} rdata must be given in the generic form "\\# <length> <hex>"`);
	const data = codec.parse(t, origin);
	// The parse must survive a round-trip: encode the result and require it to fit a record's 16-bit rdata length (a
	// 70,000-octet CAA value or a 750 KB DNSKEY used to parse and fail only at encode; CLDMV/digby#38). An encode failure for
	// any other reason surfaces here too. The writer is uncapped so the length check, not the writer's cap, reports it.
	const w = new Writer({ max: Number.MAX_SAFE_INTEGER, compress: false });
	encodeRdata(w, type, data);
	if (w.length > MAX_MESSAGE) fail(WireErrorCode.BAD_PRESENTATION, `${typeToString(type)} rdata encodes to more than ${MAX_MESSAGE} octets`);
	return data;
}

/**
 * Whether a type's presentation form is the RFC 3597 generic `\# <length> <hex>`: the types with no typed codec, and OPT —
 * typed on the wire, generic in text (its codec has no presentation form of its own). presentation.mjs uses it to refuse the
 * zero-length generic form under class ANY or NONE, where it would read back as the RFC 2136 update form (CLDMV/digby#37).
 * @param {number} type
 * @returns {boolean}
 */
export function isGenericForm(type) {
	const codec = CODECS.get(type);
	return !codec || codec.format === null;
}

/**
 * Encode an already-copied rdata value (CLDMV/digby#39): the public entries take the {@link cloneInput} copy once and share
 * this, so a format's encode-plus-round-trip never copies twice.
 * @param {number} type
 * @param {object} data
 * @returns {Uint8Array}
 */
function encodeRdataCopy(type, data) {
	const w = new Writer({ compress: false });
	encodeRdata(w, type, data);
	return w.finish();
}

/**
 * Format rdata in presentation form: the type's own form, or `\# <length> <hex>` for types without one. The data is validated
 * by encoding it first, and the formatted text is produced from what the wire round-trip decoded — the canonical presentation
 * of rdata that actually encodes — so a malformed shape raises the encode's `WireError` and no unvalidated field is ever
 * echoed into zone text (CLDMV/digby#37). The generic path encodes through the capped writer too, so rdata past a record's
 * 65,535-octet limit is refused, not printed (CLDMV/digby#37, the wire bound of CLDMV/digby#38).
 * @param {number} type - an integer in 0..0xffff, neither reserved value (RFC 6895; CLDMV/digby#38)
 * @param {object} data - copied once with structuredClone and only the copy encoded (CLDMV/digby#39)
 * @returns {string}
 * @throws {import("../errors.mjs").WireError} VALUE_OUT_OF_RANGE for a type out of range or reserved (CLDMV/digby#38), or
 *   whatever the type's encoding or decoding raises (BAD_RDATA, BAD_SVCPARAM, BAD_PRESENTATION, MESSAGE_TOO_LARGE, ...)
 */
export function formatRdata(type, data) {
	checkRdataType(type);
	// one copy of the caller's value (CLDMV/digby#39): the encode and the round-trip act on it, never on the original
	const snap = cloneInput(data, `${typeToString(type)} rdata`);
	const codec = CODECS.get(type);
	if (codec?.format) return codec.format(decodeRdataBytes(type, encodeRdataCopy(type, snap)));
	// typed on the wire but generic in text (OPT), and types with no codec: encode, then print the octets
	return formatGeneric(encodeRdataCopy(type, snap));
}

/**
 * Encode rdata into standalone octets.
 * @param {number} type - an integer in 0..0xffff, neither reserved value (RFC 6895; CLDMV/digby#38)
 * @param {object} data - copied once with structuredClone and only the copy encoded (CLDMV/digby#39)
 * @returns {Uint8Array}
 * @throws {import("../errors.mjs").WireError} VALUE_OUT_OF_RANGE for a type out of range or reserved (CLDMV/digby#38), or
 *   whatever the encoding raises
 */
export function encodeRdataBytes(type, data) {
	checkRdataType(type);
	return encodeRdataCopy(type, cloneInput(data, `${typeToString(type)} rdata`));
}

/**
 * The RFC 3597 generic presentation of octets. The octets go through the one guarded byte path (CLDMV/digby#39): every
 * SharedArrayBuffer form is refused NOT_CLONEABLE, and anything that is not octets is VALUE_OUT_OF_RANGE — `.length` on
 * a bare SharedArrayBuffer reads undefined and used to print `\# 0`.
 * @param {Uint8Array} octets
 * @returns {string}
 */
export function formatGeneric(octets) {
	const b = asBytes(octets);
	return b.length ? `\\# ${b.length} ${toHex(b)}` : "\\# 0";
}
