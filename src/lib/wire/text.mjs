/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/text.mjs
 */

/**
 * @fileoverview Presentation-format building blocks: the master-file tokenizer (RFC 1035 5.1: whitespace, quoted strings,
 * `\X` / `\DDD` escapes, parentheses, `;` comments) and the field formats rdata is written in (decimal integers,
 * character-strings, hex, base64, base32hex, IPv4, IPv6, RRSIG timestamps).
 */

import { WireErrorCode, fail } from "./errors.mjs";

/**
 * One presentation token.
 * @typedef {object} Token
 * @property {string} value - the token's text; escapes are kept as written (quotes are stripped)
 * @property {boolean} quoted - whether it was a quoted string
 */

const bad = (msg) => fail(WireErrorCode.BAD_PRESENTATION, msg);

/**
 * Split presentation text into tokens. Parentheses group lines and are dropped, comments run to the end of the line, and a
 * quoted string is one token even when it holds whitespace.
 *
 * @param {string} text
 * @returns {Token[]}
 * @throws {import("./errors.mjs").WireError} BAD_PRESENTATION for an unterminated quote, unbalanced parentheses or a lone
 *   trailing backslash
 */
export function tokenize(text) {
	if (typeof text !== "string") bad("presentation text must be a string");
	const tokens = [];
	let depth = 0;
	let i = 0;
	const n = text.length;
	while (i < n) {
		const ch = text[i];
		if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
			i++;
		} else if (ch === ";") {
			while (i < n && text[i] !== "\n") i++;
		} else if (ch === "(") {
			depth++;
			i++;
		} else if (ch === ")") {
			if (--depth < 0) bad("unbalanced ')'");
			i++;
		} else if (ch === '"') {
			let value = "";
			i++;
			for (;;) {
				if (i >= n) bad("unterminated quoted string");
				const c = text[i];
				if (c === '"') break;
				if (c === "\\") {
					if (i + 1 >= n) bad("a lone backslash at the end");
					value += c + text[i + 1];
					i += 2;
				} else {
					value += c;
					i++;
				}
			}
			i++;
			tokens.push({ value, quoted: true });
		} else {
			let value = "";
			while (i < n) {
				const c = text[i];
				if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === ";" || c === "(" || c === ")") break;
				if (c === '"') {
					// SvcParams write `key="value"` (RFC 9460 2.1): a quoted part straight after `=` joins the token
					if (!value.endsWith("=") || value.endsWith("\\=")) bad(`a quote inside an unquoted token near "${value}"`);
					i++;
					for (;;) {
						if (i >= n) bad("unterminated quoted string");
						const q = text[i];
						if (q === '"') break;
						if (q === "\\") {
							if (i + 1 >= n) bad("a lone backslash at the end");
							value += q + text[i + 1];
							i += 2;
						} else {
							// a raw space inside the quotes must survive later whitespace-free handling: escape it
							value += q === " " ? "\\032" : q;
							i++;
						}
					}
					i++;
					continue;
				}
				if (c === "\\") {
					if (i + 1 >= n) bad("a lone backslash at the end");
					value += c + text[i + 1];
					i += 2;
				} else {
					value += c;
					i++;
				}
			}
			tokens.push({ value, quoted: false });
		}
	}
	if (depth !== 0) bad("unbalanced '('");
	return tokens;
}

/**
 * A cursor over tokens, with typed takers that raise BAD_PRESENTATION naming the field.
 */
export class Tokens {
	/** @param {Token[]} list */
	constructor(list) {
		this.list = list;
		this.i = 0;
	}

	get done() {
		return this.i >= this.list.length;
	}

	/** @param {string} what @returns {Token} */
	next(what) {
		if (this.i >= this.list.length) bad(`missing ${what}`);
		return this.list[this.i++];
	}

	/** An unquoted token's text. @param {string} what @returns {string} */
	word(what) {
		const t = this.next(what);
		if (t.quoted) bad(`${what} must not be quoted`);
		return t.value;
	}

	/** @param {string} what @param {number} max @returns {number} */
	int(what, max) {
		return parseIntField(this.word(what), max, what);
	}

	/** Every remaining token's text joined (hex and base64 fields may be split by whitespace). @returns {string} */
	joinRest() {
		const parts = [];
		while (!this.done) parts.push(this.word("data"));
		return parts.join("");
	}

	/** Require that nothing is left. */
	end() {
		if (!this.done) bad(`unexpected "${this.list[this.i].value}"`);
	}
}

/**
 * Parse an unsigned decimal field.
 * @param {string} text
 * @param {number} max
 * @param {string} what
 * @returns {number}
 */
export function parseIntField(text, max, what) {
	if (!/^\d{1,15}$/.test(text)) bad(`${what} must be an unsigned decimal integer, got "${text}"`);
	const v = Number(text);
	if (v > max) bad(`${what} is at most ${max}, got ${v}`);
	return v;
}

const utf8 = new TextEncoder();

/**
 * Decode a token's escapes into octets (a character-string's content, or any escaped field).
 * Characters outside ASCII are taken as UTF-8.
 * @param {string} text
 * @returns {Uint8Array}
 */
export function unescapeBytes(text) {
	const out = [];
	for (let i = 0; i < text.length; i++) {
		const ch = text.charCodeAt(i);
		if (ch === 0x5c) {
			const next = text.charCodeAt(i + 1);
			if (Number.isNaN(next)) bad("a lone backslash at the end");
			if (next >= 0x30 && next <= 0x39) {
				const digits = text.slice(i + 1, i + 4);
				if (!/^\d{3}$/.test(digits)) bad(`\\DDD needs three digits near "${text}"`);
				const v = Number(digits);
				if (v > 255) bad(`\\${digits} is over 255`);
				out.push(v);
				i += 3;
			} else {
				const cp = text.codePointAt(i + 1);
				if (cp > 0x7f) {
					for (const b of utf8.encode(String.fromCodePoint(cp))) out.push(b);
					i += cp > 0xffff ? 2 : 1;
				} else {
					out.push(next);
					i += 1;
				}
			}
		} else if (ch > 0x7f) {
			const cp = text.codePointAt(i);
			for (const b of utf8.encode(String.fromCodePoint(cp))) out.push(b);
			if (cp > 0xffff) i++;
		} else {
			out.push(ch);
		}
	}
	return Uint8Array.from(out);
}

/**
 * Parse a character-string token (quoted or not) into at most 255 octets.
 * @param {Token} token
 * @returns {Uint8Array}
 */
export function parseCharString(token) {
	const bytes = unescapeBytes(token.value);
	if (bytes.length > 255) bad(`a character-string is at most 255 octets, got ${bytes.length}`);
	return bytes;
}

/**
 * Format octets as a quoted character-string: `"` and `\` escaped, printable ASCII and space as themselves, the rest `\DDD`.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function formatCharString(bytes) {
	return `"${escapeBytes(bytes, true)}"`;
}

/**
 * Escape octets for presentation. Inside quotes, space stays literal; outside, it is `\032`.
 * @param {Uint8Array} bytes
 * @param {boolean} quoted
 * @param {Set<number>} [extra] - further octets to escape as `\X`
 * @returns {string}
 */
export function escapeBytes(bytes, quoted, extra) {
	let out = "";
	for (const c of bytes) {
		if (c === 0x22 || c === 0x5c || extra?.has(c)) out += "\\" + String.fromCharCode(c);
		else if ((c > 0x20 && c < 0x7f) || (quoted && c === 0x20)) out += String.fromCharCode(c);
		else out += "\\" + String(c).padStart(3, "0");
	}
	return out;
}

/** @param {Uint8Array} bytes @returns {string} uppercase hex */
export function toHex(bytes) {
	let s = "";
	for (const b of bytes) s += b.toString(16).padStart(2, "0");
	return s.toUpperCase();
}

/**
 * @param {string} text
 * @param {string} what
 * @returns {Uint8Array}
 */
export function fromHex(text, what) {
	if (!/^(?:[0-9a-fA-F]{2})*$/.test(text)) bad(`${what} must be hex with an even number of digits`);
	const out = new Uint8Array(text.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
	return out;
}

/** @param {Uint8Array} bytes @returns {string} */
export function toBase64(bytes) {
	return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64");
}

/**
 * Strict base64 (standard alphabet, padded).
 * @param {string} text
 * @param {string} what
 * @returns {Uint8Array}
 */
export function fromBase64(text, what) {
	if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) bad(`${what} must be base64`);
	const buf = Buffer.from(text, "base64");
	const out = new Uint8Array(buf.length);
	out.set(buf);
	if (toBase64(out) !== text) bad(`${what} is not canonical base64 (non-zero trailing bits)`);
	return out;
}

const B32 = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

/** Base32hex without padding (RFC 4648 7; NSEC3's next hashed owner). @param {Uint8Array} bytes @returns {string} */
export function toBase32Hex(bytes) {
	let out = "";
	let acc = 0;
	let bits = 0;
	for (const b of bytes) {
		acc = (acc << 8) | b;
		bits += 8;
		while (bits >= 5) {
			out += B32[(acc >>> (bits - 5)) & 31];
			bits -= 5;
		}
		acc &= (1 << bits) - 1;
	}
	if (bits > 0) out += B32[(acc << (5 - bits)) & 31];
	return out;
}

/**
 * @param {string} text - unpadded, case-insensitive
 * @param {string} what
 * @returns {Uint8Array}
 */
export function fromBase32Hex(text, what) {
	const upper = text.toUpperCase();
	if (!/^[0-9A-V]*$/.test(upper) || [1, 3, 6].includes(upper.length % 8)) bad(`${what} must be unpadded base32hex`);
	const out = [];
	let acc = 0;
	let bits = 0;
	for (const ch of upper) {
		acc = (acc << 5) | B32.indexOf(ch);
		bits += 5;
		if (bits >= 8) {
			out.push((acc >>> (bits - 8)) & 0xff);
			bits -= 8;
		}
		acc &= (1 << bits) - 1;
	}
	if (acc !== 0) bad(`${what} has non-zero trailing bits`);
	return Uint8Array.from(out);
}

/**
 * @param {string} text - dotted quad, no leading zeros
 * @returns {Uint8Array} 4 octets
 */
export function parseIPv4(text) {
	const parts = String(text).split(".");
	if (parts.length !== 4) bad(`"${text}" is not an IPv4 address`);
	const out = new Uint8Array(4);
	parts.forEach((p, i) => {
		if (!/^(?:0|[1-9]\d{0,2})$/.test(p) || Number(p) > 255) bad(`"${text}" is not an IPv4 address`);
		out[i] = Number(p);
	});
	return out;
}

/** @param {Uint8Array} b - 4 octets @returns {string} */
export function formatIPv4(b) {
	return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
}

/**
 * Parse an IPv6 address (RFC 4291 2.2: hex groups, one `::`, an optional dotted-quad tail).
 * @param {string} text
 * @returns {Uint8Array} 16 octets
 */
export function parseIPv6(text) {
	const s = String(text);
	const no = () => bad(`"${s}" is not an IPv6 address`);
	if (!/^[0-9A-Fa-f:.]+$/.test(s)) no();
	const halves = s.split("::");
	if (halves.length > 2) no();
	const groups = (part) => (part === "" ? [] : part.split(":"));
	const head = groups(halves[0]);
	const tail = halves.length === 2 ? groups(halves[1]) : [];
	const words = [];
	const all = [...head, ...tail];
	const last = all[all.length - 1];
	let v4 = null;
	if (last !== undefined && last.includes(".")) {
		// the dotted quad must be the address's last part
		if (halves.length === 2 && tail.length === 0) no();
		v4 = parseIPv4(last);
		(tail.length ? tail : head).pop();
	}
	const toWords = (list) =>
		list.map((g) => {
			if (!/^[0-9A-Fa-f]{1,4}$/.test(g)) no();
			return parseInt(g, 16);
		});
	const h = toWords(head);
	const t = toWords(tail);
	if (v4) t.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
	const total = h.length + t.length;
	if (halves.length === 2) {
		if (total > 7) no();
		words.push(...h, ...new Array(8 - total).fill(0), ...t);
	} else {
		if (total !== 8) no();
		words.push(...h, ...t);
	}
	const out = new Uint8Array(16);
	words.forEach((w, i) => {
		out[i * 2] = w >>> 8;
		out[i * 2 + 1] = w & 0xff;
	});
	return out;
}

/**
 * Format an IPv6 address in the RFC 5952 canonical form (lowercase, no leading zeros, the longest run of two or more zero
 * groups as `::`, the first on a tie). Always hex; IPv4-mapped addresses are not written in dotted form.
 * @param {Uint8Array} b - 16 octets
 * @returns {string}
 */
export function formatIPv6(b) {
	const w = [];
	for (let i = 0; i < 8; i++) w.push((b[i * 2] << 8) | b[i * 2 + 1]);
	let best = -1;
	let bestLen = 1;
	for (let i = 0; i < 8; ) {
		if (w[i] !== 0) {
			i++;
			continue;
		}
		let j = i;
		while (j < 8 && w[j] === 0) j++;
		if (j - i > bestLen) {
			best = i;
			bestLen = j - i;
		}
		i = j;
	}
	const hex = (list) => list.map((x) => x.toString(16)).join(":");
	if (best < 0) return hex(w);
	return `${hex(w.slice(0, best))}::${hex(w.slice(best + bestLen))}`;
}

/**
 * Parse an RRSIG timestamp: `YYYYMMDDHHmmSS` (UTC) or an unsigned decimal of seconds (RFC 4034 3.2).
 * @param {string} text
 * @param {string} what
 * @returns {number}
 */
export function parseTime(text, what) {
	if (/^\d{14}$/.test(text)) {
		const [y, mo, d, h, mi, s] = [text.slice(0, 4), text.slice(4, 6), text.slice(6, 8), text.slice(8, 10), text.slice(10, 12), text.slice(12, 14)].map(
			Number
		);
		const ms = Date.UTC(y, mo - 1, d, h, mi, s);
		const back = new Date(ms);
		if (back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d || back.getUTCHours() !== h || back.getUTCMinutes() !== mi || back.getUTCSeconds() !== s)
			bad(`${what} "${text}" is not a valid date`);
		const v = ms / 1000;
		if (v < 0 || v > 0xffffffff) bad(`${what} "${text}" is outside the 32-bit range`);
		return v;
	}
	return parseIntField(text, 0xffffffff, what);
}

/** @param {number} seconds @returns {string} YYYYMMDDHHmmSS */
export function formatTime(seconds) {
	const d = new Date(seconds * 1000);
	const p = (v, n = 2) => String(v).padStart(n, "0");
	return `${p(d.getUTCFullYear(), 4)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`;
}
