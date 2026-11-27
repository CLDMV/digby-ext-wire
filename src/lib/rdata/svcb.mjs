/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/rdata/svcb.mjs
 */

/**
 * @fileoverview SVCB and HTTPS rdata (RFC 9460) with typed SvcParams: mandatory, alpn, no-default-alpn, port, ipv4hint, ech,
 * ipv6hint, dohpath (RFC 9461) and ohttp (RFC 9540). Any other key passes through as raw octets (`keyNNNNN`).
 *
 * Data shape: `{ priority, target, params: [{ key, value }] }`, params in strictly increasing key order. Values by key:
 * mandatory `number[]` (keys, ascending), alpn `Uint8Array[]`, no-default-alpn and ohttp `null`, port `number`,
 * ipv4hint / ipv6hint `string[]`, ech `Uint8Array`, dohpath `string`, others `Uint8Array`.
 *
 * Checked on decode, encode and parse: keys strictly increasing, key 65535 refused, each value's length and form, mandatory
 * not listing itself and every key it lists present.
 */

import { SVC_KEY, svcKeyFromString, svcKeyToString } from "../constants.mjs";
import { WireErrorCode, describe, fail } from "../errors.mjs";
import { canonicalName, readName, writeName } from "../names.mjs";
import { escapeBytes, formatIPv4, formatIPv6, fromBase64, parseIPv4, parseIPv6, toBase64, unescapeBytes } from "../text.mjs";
import { array, bytes, obj, string } from "./common.mjs";

const badParam = (msg, offset) => fail(WireErrorCode.BAD_SVCPARAM, msg, offset);
const utf8Strict = new TextDecoder("utf-8", { fatal: true });
const utf8 = new TextEncoder();

/**
 * Decode one SvcParam value. The reader is limited to the value.
 * @param {number} key
 * @param {import("../buffer.mjs").Reader} r
 */
function readValue(key, r) {
	const at = r.pos;
	const len = r.remaining;
	switch (key) {
		case SVC_KEY.mandatory: {
			if (len === 0 || len % 2) badParam("mandatory is a non-empty list of 16-bit keys", at);
			const keys = [];
			while (r.remaining) keys.push(r.u16());
			return keys;
		}
		case SVC_KEY.alpn: {
			if (len === 0) badParam("alpn is a non-empty list", at);
			const ids = [];
			while (r.remaining) {
				const id = r.charString();
				if (id.length === 0) badParam("an alpn id is not empty", at);
				ids.push(id);
			}
			return ids;
		}
		case SVC_KEY["no-default-alpn"]:
		case SVC_KEY.ohttp:
			if (len !== 0) badParam(`${svcKeyToString(key)} has no value`, at);
			return null;
		case SVC_KEY.port:
			if (len !== 2) badParam("port is 2 octets", at);
			return r.u16();
		case SVC_KEY.ipv4hint: {
			if (len === 0 || len % 4) badParam("ipv4hint is a non-empty list of 4-octet addresses", at);
			const out = [];
			while (r.remaining) out.push(formatIPv4(r.take(4)));
			return out;
		}
		case SVC_KEY.ipv6hint: {
			if (len === 0 || len % 16) badParam("ipv6hint is a non-empty list of 16-octet addresses", at);
			const out = [];
			while (r.remaining) out.push(formatIPv6(r.take(16)));
			return out;
		}
		case SVC_KEY.ech:
			if (len === 0) badParam("ech is not empty", at);
			return r.rest();
		case SVC_KEY.dohpath:
			try {
				return utf8Strict.decode(r.rest());
			} catch {
				return badParam("dohpath is not valid UTF-8", at);
			}
		default:
			return r.rest();
	}
}

/**
 * Encode one SvcParam value.
 * @param {import("../buffer.mjs").Writer} w
 * @param {number} key
 * @param {unknown} value
 */
function writeValue(w, key, value) {
	const name = svcKeyToString(key);
	switch (key) {
		case SVC_KEY.mandatory:
			if (array(value, name).length === 0) badParam("mandatory is a non-empty list");
			for (const k of value) w.u16(k);
			return;
		case SVC_KEY.alpn:
			if (array(value, name).length === 0) badParam("alpn is a non-empty list");
			for (const id of value) {
				if (bytes(id, "an alpn id").length === 0) badParam("an alpn id is not empty");
				w.charString(id);
			}
			return;
		case SVC_KEY["no-default-alpn"]:
		case SVC_KEY.ohttp:
			if (value !== null && value !== undefined) badParam(`${name} has no value`);
			return;
		case SVC_KEY.port:
			w.u16(value);
			return;
		case SVC_KEY.ipv4hint:
			if (array(value, name).length === 0) badParam("ipv4hint is a non-empty list");
			for (const a of value) w.raw(parseIPv4(string(a, "an ipv4hint address")));
			return;
		case SVC_KEY.ipv6hint:
			if (array(value, name).length === 0) badParam("ipv6hint is a non-empty list");
			for (const a of value) w.raw(parseIPv6(string(a, "an ipv6hint address")));
			return;
		case SVC_KEY.ech:
			if (bytes(value, name).length === 0) badParam("ech is not empty");
			w.raw(value);
			return;
		case SVC_KEY.dohpath: {
			const text = string(value, name);
			// a lone surrogate would silently encode as U+FFFD (CLDMV/digby#38)
			if (!text.isWellFormed()) badParam("dohpath is not well-formed Unicode: a lone surrogate would encode as U+FFFD");
			w.raw(utf8.encode(text));
			return;
		}
		default:
			w.raw(bytes(value, name));
	}
}

/**
 * Check the params as a set: keys valid and strictly increasing, mandatory well formed and satisfied.
 * @param {{ key: number, value: unknown }[]} params
 */
function checkParams(params) {
	let last = -1;
	for (const p of params) {
		if (p === null || typeof p !== "object") badParam("a SvcParam is an object { key, value }");
		// described, never String()ed — the params are the copy's values, but a hostile key must not break the refusal itself (CLDMV/digby#39)
		if (!Number.isInteger(p.key) || p.key < 0 || p.key >= 0xffff) badParam(`SvcParamKey ${describe(p.key)} is invalid`);
		if (p.key <= last) badParam("SvcParamKeys must be strictly increasing");
		last = p.key;
	}
	const mandatory = params.find((p) => p.key === SVC_KEY.mandatory);
	if (!mandatory) return;
	let prev = -1;
	for (const k of array(mandatory.value, "mandatory")) {
		if (!Number.isInteger(k) || k < 0 || k > 0xffff) badParam(`mandatory key ${describe(k)} is invalid`);
		if (k === SVC_KEY.mandatory) badParam("mandatory must not list itself");
		if (k <= prev) badParam("mandatory keys must be strictly increasing");
		prev = k;
		if (!params.some((p) => p.key === k)) badParam(`mandatory lists ${svcKeyToString(k)}, which is absent`);
	}
}

/**
 * Split a value-list (RFC 9460 A.1) on unescaped commas.
 * @param {Uint8Array} b
 * @returns {Uint8Array[]}
 */
function splitList(b) {
	const items = [];
	let cur = [];
	for (let i = 0; i < b.length; i++) {
		if (b[i] === 0x5c && i + 1 < b.length) cur.push(b[++i]);
		else if (b[i] === 0x2c) {
			items.push(Uint8Array.from(cur));
			cur = [];
		} else cur.push(b[i]);
	}
	items.push(Uint8Array.from(cur));
	return items;
}

/**
 * Join ids into a value-list, escaping `,` and `\` inside each with a backslash.
 * @param {Uint8Array[]} ids
 * @returns {Uint8Array}
 */
function joinList(ids) {
	const out = [];
	ids.forEach((id, i) => {
		if (i) out.push(0x2c);
		for (const c of id) {
			if (c === 0x2c || c === 0x5c) out.push(0x5c);
			out.push(c);
		}
	});
	return Uint8Array.from(out);
}

const ascii = (b) => String.fromCharCode(...b);

/**
 * Parse one `key[=value]` token.
 * @param {string} token
 * @returns {{ key: number, value: unknown }}
 */
function parseParam(token) {
	const eq = token.indexOf("=");
	const key = svcKeyFromString(eq < 0 ? token : token.slice(0, eq));
	const has = eq >= 0;
	const raw = has ? unescapeBytes(token.slice(eq + 1)) : null;
	const need = () => {
		if (!has || raw.length === 0) badParam(`${svcKeyToString(key)} needs a value`);
		return raw;
	};
	switch (key) {
		case SVC_KEY.mandatory:
			return { key, value: splitList(need()).map((k) => svcKeyFromString(ascii(k))) };
		case SVC_KEY.alpn: {
			const ids = splitList(need());
			if (ids.some((id) => id.length === 0 || id.length > 255)) badParam("an alpn id is 1 to 255 octets");
			return { key, value: ids };
		}
		case SVC_KEY["no-default-alpn"]:
		case SVC_KEY.ohttp:
			if (has) badParam(`${svcKeyToString(key)} takes no value`);
			return { key, value: null };
		case SVC_KEY.port: {
			const text = ascii(need());
			if (!/^\d{1,5}$/.test(text) || Number(text) > 0xffff) badParam(`port "${text}" is not a 16-bit number`);
			return { key, value: Number(text) };
		}
		case SVC_KEY.ipv4hint:
			return { key, value: ascii(need()).split(",").map((a) => formatIPv4(parseIPv4(a))) };
		case SVC_KEY.ipv6hint:
			return { key, value: ascii(need()).split(",").map((a) => formatIPv6(parseIPv6(a))) };
		case SVC_KEY.ech:
			return { key, value: fromBase64(ascii(need()), "ech") };
		case SVC_KEY.dohpath:
			try {
				return { key, value: utf8Strict.decode(need()) };
			} catch (err) {
				if (err?.name === "WireError") throw err;
				return badParam("dohpath is not valid UTF-8");
			}
		default:
			return { key, value: has ? raw : new Uint8Array(0) };
	}
}

/**
 * Format one param as `key[=value]`.
 * @param {{ key: number, value: any }} p
 * @returns {string}
 */
function formatParam({ key, value }) {
	const name = svcKeyToString(key);
	switch (key) {
		case SVC_KEY.mandatory:
			return `${name}=${value.map(svcKeyToString).join(",")}`;
		case SVC_KEY.alpn:
			// two layers (RFC 9460 A.1): the value-list escapes `,` and `\` in each id, then the char-string escapes the result
			return `${name}="${escapeBytes(joinList(value), true)}"`;
		case SVC_KEY["no-default-alpn"]:
		case SVC_KEY.ohttp:
			return name;
		case SVC_KEY.port:
			return `${name}=${value}`;
		case SVC_KEY.ipv4hint:
		case SVC_KEY.ipv6hint:
			return `${name}=${value.join(",")}`;
		case SVC_KEY.ech:
			return `${name}=${toBase64(value)}`;
		case SVC_KEY.dohpath: {
			const text = string(value, name);
			// a lone surrogate would silently encode as U+FFFD (CLDMV/digby#38)
			if (!text.isWellFormed()) badParam("dohpath is not well-formed Unicode: a lone surrogate would encode as U+FFFD");
			return `${name}="${escapeBytes(utf8.encode(text), true)}"`;
		}
		default:
			return value.length ? `${name}="${escapeBytes(value, true)}"` : name;
	}
}

/**
 * @param {string} type - "SVCB" or "HTTPS"
 * @returns {import("./common.mjs").RdataCodec}
 */
function svcb(type) {
	return {
		name: type,
		decode(r) {
			const priority = r.u16();
			const target = readName(r);
			const params = [];
			let last = -1;
			while (r.remaining > 0) {
				const at = r.pos;
				const key = r.u16();
				const len = r.u16();
				if (key === 0xffff) badParam("SvcParamKey 65535 is reserved", at);
				if (key <= last) badParam("SvcParamKeys must be strictly increasing", at);
				last = key;
				params.push({ key, value: r.limit(len, () => readValue(key, r), WireErrorCode.BAD_SVCPARAM) });
			}
			checkParams(params);
			return { priority, target, params };
		},
		encode(w, data) {
			obj(data, type);
			w.u16(data.priority);
			writeName(w, string(data.target, `${type} target`), false);
			const params = array(data.params, `${type} params`);
			checkParams(params);
			for (const p of params) {
				w.u16(p.key);
				const lenAt = w.length;
				w.u16(0);
				writeValue(w, p.key, p.value);
				w.patch16(lenAt, w.length - lenAt - 2);
			}
		},
		parse(t, origin) {
			const priority = t.int("priority", 0xffff);
			const target = canonicalName(t.word("target"), origin);
			const params = [];
			while (!t.done) params.push(parseParam(t.word("SvcParam")));
			params.sort((a, b) => a.key - b.key);
			for (let i = 1; i < params.length; i++) if (params[i].key === params[i - 1].key) badParam(`${svcKeyToString(params[i].key)} appears twice`);
			if (params.some((p) => p.key === SVC_KEY.mandatory)) {
				const m = params.find((p) => p.key === SVC_KEY.mandatory);
				m.value = [...m.value].sort((a, b) => a - b);
			}
			checkParams(params);
			return { priority, target, params };
		},
		format: (d) => [String(d.priority), d.target, ...d.params.map(formatParam)].join(" ")
	};
}

export const SVCB = svcb("SVCB");
export const HTTPS = svcb("HTTPS");
