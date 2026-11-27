/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/rdata/basic.mjs
 */

/**
 * @fileoverview Address, name and string rdata: A, AAAA, NS, CNAME, PTR, MX, SOA, TXT (RFC 1035, 3596), SRV (RFC 2782), NAPTR
 * (RFC 3403), CAA (RFC 8659), TLSA (RFC 6698) and SSHFP (RFC 4255).
 *
 * Only the RFC 1035 types (NS, CNAME, PTR, MX, SOA) compress the names in their rdata on encode (RFC 3597 4); every type's
 * names are decompressed on decode.
 */

import { canonicalName, readName, writeName } from "../names.mjs";
import {
	escapeBytes,
	formatCharString,
	formatIPv4,
	formatIPv6,
	fromHex,
	parseCharString,
	parseIPv4,
	parseIPv6,
	toHex,
	unescapeBytes
} from "../text.mjs";
import { array, badRdata, bytes, obj, string } from "./common.mjs";

/** @type {import("./common.mjs").RdataCodec} */
export const A = {
	name: "A",
	decode(r) {
		if (r.remaining !== 4) badRdata(`A rdata is 4 octets, got ${r.remaining}`, r.pos);
		return { address: formatIPv4(r.take(4)) };
	},
	encode(w, data) {
		w.raw(parseIPv4(string(obj(data, "A").address, "A address")));
	},
	parse(t) {
		const address = formatIPv4(parseIPv4(t.word("address")));
		t.end();
		return { address };
	},
	format: (d) => d.address
};

/** @type {import("./common.mjs").RdataCodec} */
export const AAAA = {
	name: "AAAA",
	decode(r) {
		if (r.remaining !== 16) badRdata(`AAAA rdata is 16 octets, got ${r.remaining}`, r.pos);
		return { address: formatIPv6(r.take(16)) };
	},
	encode(w, data) {
		w.raw(parseIPv6(string(obj(data, "AAAA").address, "AAAA address")));
	},
	parse(t) {
		const address = formatIPv6(parseIPv6(t.word("address")));
		t.end();
		return { address };
	},
	format: (d) => d.address
};

/**
 * A codec for rdata that is one domain name.
 * @param {string} type
 * @param {boolean} compress
 * @returns {import("./common.mjs").RdataCodec}
 */
function singleName(type, compress) {
	return {
		name: type,
		decode: (r) => ({ target: readName(r) }),
		encode(w, data) {
			writeName(w, string(obj(data, type).target, `${type} target`), compress);
		},
		parse(t, origin) {
			const target = canonicalName(t.word("target"), origin);
			t.end();
			return { target };
		},
		format: (d) => d.target
	};
}

export const NS = singleName("NS", true);
export const CNAME = singleName("CNAME", true);
export const PTR = singleName("PTR", true);

/** @type {import("./common.mjs").RdataCodec} */
export const MX = {
	name: "MX",
	decode: (r) => ({ preference: r.u16(), exchange: readName(r) }),
	encode(w, data) {
		obj(data, "MX");
		w.u16(data.preference);
		writeName(w, string(data.exchange, "MX exchange"), true);
	},
	parse(t, origin) {
		const preference = t.int("preference", 0xffff);
		const exchange = canonicalName(t.word("exchange"), origin);
		t.end();
		return { preference, exchange };
	},
	format: (d) => `${d.preference} ${d.exchange}`
};

const SOA_TIMES = ["serial", "refresh", "retry", "expire", "minimum"];

/** @type {import("./common.mjs").RdataCodec} */
export const SOA = {
	name: "SOA",
	decode(r) {
		const mname = readName(r);
		const rname = readName(r);
		return { mname, rname, serial: r.u32(), refresh: r.u32(), retry: r.u32(), expire: r.u32(), minimum: r.u32() };
	},
	encode(w, data) {
		obj(data, "SOA");
		writeName(w, string(data.mname, "SOA mname"), true);
		writeName(w, string(data.rname, "SOA rname"), true);
		for (const k of SOA_TIMES) w.u32(data[k]);
	},
	parse(t, origin) {
		const mname = canonicalName(t.word("mname"), origin);
		const rname = canonicalName(t.word("rname"), origin);
		const out = { mname, rname };
		for (const k of SOA_TIMES) out[k] = t.int(k, 0xffffffff);
		t.end();
		return out;
	},
	format: (d) => `${d.mname} ${d.rname} ${SOA_TIMES.map((k) => d[k]).join(" ")}`
};

/** @type {import("./common.mjs").RdataCodec} */
export const TXT = {
	name: "TXT",
	decode(r) {
		if (r.remaining === 0) badRdata("TXT rdata holds at least one character-string", r.pos);
		const strings = [];
		while (r.remaining > 0) strings.push(r.charString());
		return { strings };
	},
	encode(w, data) {
		const strings = array(obj(data, "TXT").strings, "TXT strings");
		if (strings.length === 0) badRdata("TXT rdata holds at least one character-string");
		for (const s of strings) w.charString(bytes(s, "a TXT string"));
	},
	parse(t) {
		const strings = [];
		while (!t.done) strings.push(parseCharString(t.next("string")));
		if (strings.length === 0) badRdata("TXT rdata holds at least one character-string");
		return { strings };
	},
	format: (d) => d.strings.map(formatCharString).join(" ")
};

/** @type {import("./common.mjs").RdataCodec} */
export const SRV = {
	name: "SRV",
	decode: (r) => ({ priority: r.u16(), weight: r.u16(), port: r.u16(), target: readName(r) }),
	encode(w, data) {
		obj(data, "SRV");
		w.u16(data.priority);
		w.u16(data.weight);
		w.u16(data.port);
		writeName(w, string(data.target, "SRV target"), false);
	},
	parse(t, origin) {
		const priority = t.int("priority", 0xffff);
		const weight = t.int("weight", 0xffff);
		const port = t.int("port", 0xffff);
		const target = canonicalName(t.word("target"), origin);
		t.end();
		return { priority, weight, port, target };
	},
	format: (d) => `${d.priority} ${d.weight} ${d.port} ${d.target}`
};

/** @type {import("./common.mjs").RdataCodec} */
export const NAPTR = {
	name: "NAPTR",
	decode: (r) => ({
		order: r.u16(),
		preference: r.u16(),
		flags: r.charString(),
		services: r.charString(),
		regexp: r.charString(),
		replacement: readName(r)
	}),
	encode(w, data) {
		obj(data, "NAPTR");
		w.u16(data.order);
		w.u16(data.preference);
		w.charString(bytes(data.flags, "NAPTR flags"));
		w.charString(bytes(data.services, "NAPTR services"));
		w.charString(bytes(data.regexp, "NAPTR regexp"));
		writeName(w, string(data.replacement, "NAPTR replacement"), false);
	},
	parse(t, origin) {
		const order = t.int("order", 0xffff);
		const preference = t.int("preference", 0xffff);
		const flags = parseCharString(t.next("flags"));
		const services = parseCharString(t.next("services"));
		const regexp = parseCharString(t.next("regexp"));
		const replacement = canonicalName(t.word("replacement"), origin);
		t.end();
		return { order, preference, flags, services, regexp, replacement };
	},
	format: (d) =>
		`${d.order} ${d.preference} ${formatCharString(d.flags)} ${formatCharString(d.services)} ${formatCharString(d.regexp)} ${d.replacement}`
};

const CAA_TAG = /^[A-Za-z0-9]{1,15}$/;

/** @type {import("./common.mjs").RdataCodec} */
export const CAA = {
	name: "CAA",
	decode(r) {
		const flags = r.u8();
		const start = r.pos;
		const tagBytes = r.charString();
		const tag = String.fromCharCode(...tagBytes);
		if (!CAA_TAG.test(tag)) badRdata("a CAA tag is 1 to 15 ASCII letters and digits", start);
		return { flags, tag, value: r.rest() };
	},
	encode(w, data) {
		obj(data, "CAA");
		w.u8(data.flags);
		const tag = string(data.tag, "CAA tag");
		if (!CAA_TAG.test(tag)) badRdata("a CAA tag is 1 to 15 ASCII letters and digits");
		w.charString(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
		w.raw(bytes(data.value, "CAA value"));
	},
	parse(t) {
		const flags = t.int("flags", 0xff);
		const tag = t.word("tag");
		if (!CAA_TAG.test(tag)) badRdata("a CAA tag is 1 to 15 ASCII letters and digits");
		// the value is one character-string-like token, but without the 255-octet limit (RFC 8659 4.1.1)
		const tok = t.next("value");
		t.end();
		return { flags, tag, value: unescapeBytes(tok.value) };
	},
	format: (d) => `${d.flags} ${d.tag} "${escapeBytes(d.value, true)}"`
};

/**
 * A codec for "a few small integers, then hex to the end" (TLSA, SSHFP).
 * @param {string} type
 * @param {string[]} ints - u8 field names
 * @param {string} field - the trailing octets field (never empty)
 * @returns {import("./common.mjs").RdataCodec}
 */
function intsThenHex(type, ints, field) {
	return {
		name: type,
		decode(r) {
			const out = {};
			for (const k of ints) out[k] = r.u8();
			if (r.remaining === 0) badRdata(`${type} ${field} is empty`, r.pos);
			out[field] = r.rest();
			return out;
		},
		encode(w, data) {
			obj(data, type);
			for (const k of ints) w.u8(data[k]);
			const b = bytes(data[field], `${type} ${field}`);
			if (b.length === 0) badRdata(`${type} ${field} is empty`);
			w.raw(b);
		},
		parse(t) {
			const out = {};
			for (const k of ints) out[k] = t.int(k, 0xff);
			out[field] = fromHex(t.joinRest(), `${type} ${field}`);
			if (out[field].length === 0) badRdata(`${type} ${field} is empty`);
			return out;
		},
		format: (d) => `${ints.map((k) => d[k]).join(" ")} ${toHex(d[field])}`
	};
}

export const TLSA = intsThenHex("TLSA", ["usage", "selector", "matchingType"], "data");
export const SSHFP = intsThenHex("SSHFP", ["algorithm", "fpType"], "fingerprint");
