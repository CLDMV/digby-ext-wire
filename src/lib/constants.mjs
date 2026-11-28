/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/constants.mjs
 */

/**
 * @fileoverview Numeric constants and mnemonic tables: RR types, classes, opcodes, rcodes, EDNS option codes and SvcParam keys,
 * plus the RFC 3597 `TYPEnnn` / `CLASSnnn` conversions.
 */

import { WireErrorCode, describe, fail } from "./errors.mjs";

/**
 * RR type numbers. Every type with a typed rdata codec is here, plus the mnemonics the presentation format should know by
 * name even though their rdata goes through the RFC 3597 generic form, and the query-only types.
 * @readonly
 */
export const TYPE = Object.freeze({
	A: 1,
	NS: 2,
	MD: 3,
	MF: 4,
	CNAME: 5,
	SOA: 6,
	MB: 7,
	MG: 8,
	MR: 9,
	NULL: 10,
	WKS: 11,
	PTR: 12,
	HINFO: 13,
	MINFO: 14,
	MX: 15,
	TXT: 16,
	RP: 17,
	AFSDB: 18,
	SIG: 24,
	KEY: 25,
	AAAA: 28,
	LOC: 29,
	SRV: 33,
	NAPTR: 35,
	KX: 36,
	CERT: 37,
	DNAME: 39,
	OPT: 41,
	APL: 42,
	DS: 43,
	SSHFP: 44,
	IPSECKEY: 45,
	RRSIG: 46,
	NSEC: 47,
	DNSKEY: 48,
	DHCID: 49,
	NSEC3: 50,
	NSEC3PARAM: 51,
	TLSA: 52,
	SMIMEA: 53,
	HIP: 55,
	CDS: 59,
	CDNSKEY: 60,
	OPENPGPKEY: 61,
	CSYNC: 62,
	ZONEMD: 63,
	SVCB: 64,
	HTTPS: 65,
	SPF: 99,
	EUI48: 108,
	EUI64: 109,
	TKEY: 249,
	TSIG: 250,
	IXFR: 251,
	AXFR: 252,
	MAILB: 253,
	MAILA: 254,
	ANY: 255,
	URI: 256,
	CAA: 257
});

/** RR classes. @readonly */
export const CLASS = Object.freeze({ IN: 1, CH: 3, HS: 4, NONE: 254, ANY: 255 });

/** Header opcodes. @readonly */
export const OPCODE = Object.freeze({ QUERY: 0, IQUERY: 1, STATUS: 2, NOTIFY: 4, UPDATE: 5, DSO: 6 });

/** Response codes; values over 15 need EDNS (the upper 8 bits live in the OPT record). @readonly */
export const RCODE = Object.freeze({
	NOERROR: 0,
	FORMERR: 1,
	SERVFAIL: 2,
	NXDOMAIN: 3,
	NOTIMP: 4,
	REFUSED: 5,
	YXDOMAIN: 6,
	YXRRSET: 7,
	NXRRSET: 8,
	NOTAUTH: 9,
	NOTZONE: 10,
	DSOTYPENI: 11,
	BADVERS: 16,
	BADKEY: 17,
	BADTIME: 18,
	BADMODE: 19,
	BADNAME: 20,
	BADALG: 21,
	BADTRUNC: 22,
	BADCOOKIE: 23
});

/** EDNS(0) option codes with typed codecs (others pass through raw). @readonly */
export const EDNS_OPTION = Object.freeze({
	COOKIE: 10, // RFC 7873
	TCP_KEEPALIVE: 11, // RFC 7828
	PADDING: 12, // RFC 7830
	EXTENDED_ERROR: 15 // RFC 8914
});

/** SVCB/HTTPS SvcParamKeys (RFC 9460, RFC 9461, RFC 9540). @readonly */
export const SVC_KEY = Object.freeze({
	mandatory: 0,
	alpn: 1,
	"no-default-alpn": 2,
	port: 3,
	ipv4hint: 4,
	ech: 5,
	ipv6hint: 6,
	dohpath: 7,
	ohttp: 8
});

const invert = (table) => Object.freeze(Object.fromEntries(Object.entries(table).map(([k, v]) => [v, k])));
const TYPE_NAME = invert(TYPE);
const CLASS_NAME = invert(CLASS);
const SVC_KEY_NAME = invert(SVC_KEY);

/**
 * Require a 16-bit integer for a numeric converter (CLDMV/digby#39): the value is described, never stringified — a
 * template literal of a plain object with `toString: 1` throws a TypeError, so the converters validate first and
 * refuse anything that is not an integer in 0..0xffff.
 * @param {unknown} v
 * @param {string} what
 * @returns {number}
 */
function check16(v, what) {
	if (!Number.isInteger(v) || v < 0 || v > 0xffff) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `${what} out of range: ${describe(v)}`);
	return v;
}

/**
 * A mnemonic argument as a string, without running caller code (CLDMV/digby#39): `String()` on a plain object with
 * `toString: 1` throws a TypeError and cannot convert an Object.create(null) at all, so anything that is not a string
 * or a safe primitive is refused.
 * @param {unknown} text
 * @param {string} what
 * @param {string} [code=UNKNOWN_MNEMONIC]
 * @returns {string}
 */
function mnemonicText(text, what, code = WireErrorCode.UNKNOWN_MNEMONIC) {
	const tag = typeof text; // typeof runs no caller code, even on a revoked Proxy
	if (tag === "string") return text;
	if (tag === "number" || tag === "boolean" || tag === "bigint") return String(text);
	fail(code, `${what} must be a string, got ${describe(text)}`);
}

/**
 * The presentation mnemonic of a type: its name when known, otherwise RFC 3597 `TYPEnnn`.
 * @param {number} type
 * @returns {string}
 */
export function typeToString(type) {
	check16(type, "type");
	return TYPE_NAME[type] ?? `TYPE${type}`;
}

/**
 * Parse a type mnemonic (case-insensitive) or RFC 3597 `TYPEnnn`.
 * @param {string} text
 * @returns {number}
 * @throws {import("./errors.mjs").WireError} UNKNOWN_MNEMONIC
 */
export function typeFromString(text) {
	const upper = mnemonicText(text, "a type mnemonic").toUpperCase();
	if (Object.hasOwn(TYPE, upper)) return TYPE[upper];
	return generic(upper, "TYPE", upper);
}

/**
 * The presentation mnemonic of a class: its name when known, otherwise RFC 3597 `CLASSnnn`.
 * @param {number} cls
 * @returns {string}
 */
export function classToString(cls) {
	check16(cls, "class");
	return CLASS_NAME[cls] ?? `CLASS${cls}`;
}

/**
 * Parse a class mnemonic (case-insensitive) or RFC 3597 `CLASSnnn`.
 * @param {string} text
 * @returns {number}
 * @throws {import("./errors.mjs").WireError} UNKNOWN_MNEMONIC
 */
export function classFromString(text) {
	const upper = mnemonicText(text, "a class mnemonic").toUpperCase();
	if (Object.hasOwn(CLASS, upper)) return CLASS[upper];
	return generic(upper, "CLASS", upper);
}

/**
 * Whether a presentation token is a class mnemonic (used by the RR line parser, where TTL and class may come in either order).
 * @param {string} text
 * @returns {boolean}
 */
export function isClassToken(text) {
	const upper = mnemonicText(text, "a class token").toUpperCase();
	return Object.hasOwn(CLASS, upper) || /^CLASS\d{1,5}$/.test(upper);
}

/**
 * The presentation name of a SvcParamKey: its name when registered, otherwise `keyNNNNN`.
 * @param {number} key
 * @returns {string}
 */
export function svcKeyToString(key) {
	check16(key, "SvcParamKey");
	return SVC_KEY_NAME[key] ?? `key${key}`;
}

/**
 * Parse a SvcParamKey name or `keyNNNNN`. `key65535` round-trips with {@link svcKeyToString}: the mnemonic layer is
 * permissive like TYPEnnn / CLASSnnn (whose generic form accepts the reserved top of the range), and the reserved key
 * stays refused where a key is used — the SvcParam record layer refuses 65535 on decode, encode and parse.
 * @param {string} text
 * @returns {number}
 */
export function svcKeyFromString(text) {
	const s = mnemonicText(text, "a SvcParamKey name", WireErrorCode.BAD_SVCPARAM);
	if (Object.hasOwn(SVC_KEY, s)) return SVC_KEY[s];
	// the generic form has no leading zeros (RFC 9460): "key00001" is not the presentation form of key 1, and key 0 is
	// registered as "mandatory", so its presentation is the mnemonic — both refused here (CLDMV/digby#39, round 8)
	const m = /^key([1-9]\d{0,4})$/.exec(s);
	if (m) {
		const n = Number(m[1]);
		if (n <= 0xffff) return n;
	}
	return fail(WireErrorCode.BAD_SVCPARAM, `unknown SvcParamKey "${s}"`);
}

function generic(upper, prefix, original) {
	const m = new RegExp(`^${prefix}(\\d{1,5})$`).exec(upper);
	if (m) {
		const n = Number(m[1]);
		if (n <= 0xffff) return n;
	}
	return fail(WireErrorCode.UNKNOWN_MNEMONIC, `unknown ${prefix.toLowerCase()} mnemonic "${original}"`);
}
