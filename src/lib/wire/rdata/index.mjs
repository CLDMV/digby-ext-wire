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

import { MAX_MESSAGE, Reader, Writer } from "../buffer.mjs";
import { TYPE, typeToString } from "../constants.mjs";
import { readOptions, writeOptions } from "../edns.mjs";
import { WireErrorCode, fail } from "../errors.mjs";
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
	const r = new Reader(bytes(octets, "rdata"));
	r.standalone = true; // readName refuses compression pointers on a standalone reader (CLDMV/digby#38)
	return r.limit(octets.length, () => decodeRdata(type, r));
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
	return parseRdataTokens(type, new Tokens(tokenize(text)), origin);
}

/**
 * Parse rdata from a token cursor (shared with the RR line parser).
 * @param {number} type
 * @param {Tokens} t
 * @param {string} [origin]
 * @returns {object}
 */
export function parseRdataTokens(type, t, origin) {
	const first = t.list[t.i];
	if (first && !first.quoted && first.value === "\\#") {
		t.i++;
		const len = t.int("generic rdata length", 0xffff);
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
 * Format rdata in presentation form: the type's own form, or `\# <length> <hex>` for types without one. The data is validated
 * by encoding it first, and the formatted text is produced from what the wire round-trip decoded — the canonical presentation
 * of rdata that actually encodes — so a malformed shape raises the encode's `WireError` and no unvalidated field is ever
 * echoed into zone text (CLDMV/digby#37). The generic path encodes through the capped writer too, so rdata past a record's
 * 65,535-octet limit is refused, not printed (CLDMV/digby#37, the wire bound of CLDMV/digby#38).
 * @param {number} type
 * @param {object} data
 * @returns {string}
 * @throws {import("../errors.mjs").WireError} whatever the type's encoding or decoding raises (VALUE_OUT_OF_RANGE, BAD_RDATA,
 *   BAD_SVCPARAM, BAD_PRESENTATION, MESSAGE_TOO_LARGE, ...)
 */
export function formatRdata(type, data) {
	const codec = CODECS.get(type);
	if (codec?.format) return codec.format(decodeRdataBytes(type, encodeRdataBytes(type, data)));
	// typed on the wire but generic in text (OPT), and types with no codec: encode, then print the octets
	return formatGeneric(encodeRdataBytes(type, data));
}

/**
 * Encode rdata into standalone octets.
 * @param {number} type
 * @param {object} data
 * @returns {Uint8Array}
 */
export function encodeRdataBytes(type, data) {
	const w = new Writer({ compress: false });
	encodeRdata(w, type, data);
	return w.finish();
}

/**
 * The RFC 3597 generic presentation of octets.
 * @param {Uint8Array} octets
 * @returns {string}
 */
export function formatGeneric(octets) {
	return octets.length ? `\\# ${octets.length} ${toHex(octets)}` : "\\# 0";
}
