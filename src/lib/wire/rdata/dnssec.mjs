/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/rdata/dnssec.mjs
 */

/**
 * @fileoverview DNSSEC rdata: DS and CDS (RFC 4034 5, RFC 7344), DNSKEY and CDNSKEY (RFC 4034 2), RRSIG (RFC 4034 3), NSEC
 * (RFC 4034 4), NSEC3 and NSEC3PARAM (RFC 5155), and the type bitmap they share.
 *
 * The codec is structural only: it does not check signatures, digests or key tags. Names in this rdata are never compressed on
 * encode (RFC 4034 and RFC 3597 forbid it); they are decompressed on decode.
 */

import { typeFromString, typeToString } from "../constants.mjs";
import { WireErrorCode, fail } from "../errors.mjs";
import { canonicalName, readName, writeName } from "../names.mjs";
import { formatTime, fromBase32Hex, fromBase64, fromHex, parseTime, toBase32Hex, toBase64, toHex } from "../text.mjs";
import { array, badRdata, bytes, obj, string } from "./common.mjs";

/**
 * Read a type bitmap (RFC 4034 4.1.2) to the end of the reader. Strict: windows ascending, each 1 to 32 octets, with no
 * trailing zero octet.
 * @param {import("../buffer.mjs").Reader} r
 * @returns {number[]} the types, ascending
 */
export function readTypeBitmap(r) {
	const types = [];
	let last = -1;
	while (r.remaining > 0) {
		const at = r.pos;
		const win = r.u8();
		const len = r.u8();
		if (win <= last) badRdata("type bitmap windows must be in ascending order", at);
		if (len < 1 || len > 32) badRdata(`a type bitmap window is 1 to 32 octets, got ${len}`, at);
		const map = r.take(len);
		if (map[len - 1] === 0) badRdata("a type bitmap window has a trailing zero octet", at);
		if (win === 0 && map[0] & 0x80) badRdata("a type bitmap must not include type 0", at); // type 0 is reserved (CLDMV/digby#38)
		if (win === 255 && len === 32 && map[31] & 1) badRdata("a type bitmap must not include type 65535", at); // 65535 is reserved (CLDMV/digby#38): the last bit of a full last window
		for (let i = 0; i < len; i++) for (let bit = 0; bit < 8; bit++) if (map[i] & (0x80 >> bit)) types.push(win * 256 + i * 8 + bit);
		last = win;
	}
	return types;
}

/**
 * Write a type bitmap. The types may come in any order; duplicates collapse. The list is copied once and validated on the
 * copy (CLDMV/digby#39), so a getter list cannot show the validation one set and the writer another.
 * @param {import("../buffer.mjs").Writer} w
 * @param {number[]} types
 */
export function writeTypeBitmap(w, types) {
	const list = [];
	for (const t of array(types, "the type list")) {
		if (!Number.isInteger(t) || t < 0 || t > 0xffff) badRdata(`type ${String(t)} is out of range`);
		if (t === 0) badRdata("a type bitmap must not include type 0"); // type 0 is reserved (CLDMV/digby#38)
		if (t === 0xffff) badRdata("a type bitmap must not include type 65535"); // 65535 is reserved (CLDMV/digby#38)
		list.push(t);
	}
	const sorted = [...new Set(list)].sort((a, b) => a - b);
	let i = 0;
	while (i < sorted.length) {
		const win = sorted[i] >> 8;
		const map = new Uint8Array(32);
		let len = 0;
		while (i < sorted.length && sorted[i] >> 8 === win) {
			const low = sorted[i] & 0xff;
			map[low >> 3] |= 0x80 >> (low & 7);
			len = (low >> 3) + 1;
			i++;
		}
		w.u8(win);
		w.u8(len);
		w.raw(map.subarray(0, len));
	}
}

const parseTypes = (t) => {
	const out = [];
	while (!t.done) {
		const type = typeFromString(t.word("type"));
		if (type === 0) fail(WireErrorCode.BAD_PRESENTATION, "a type bitmap must not include TYPE0"); // type 0 is reserved (CLDMV/digby#38)
		if (type === 0xffff) fail(WireErrorCode.BAD_PRESENTATION, "a type bitmap must not include TYPE65535"); // 65535 is reserved (CLDMV/digby#38)
		out.push(type);
	}
	return [...new Set(out)].sort((a, b) => a - b);
};
const formatTypes = (types) => types.map(typeToString).join(" ");

/**
 * DS and CDS share a format: key tag, algorithm, digest type, digest.
 * @param {string} type
 * @returns {import("./common.mjs").RdataCodec}
 */
function dsLike(type) {
	return {
		name: type,
		decode(r) {
			const keyTag = r.u16();
			const algorithm = r.u8();
			const digestType = r.u8();
			if (r.remaining === 0) badRdata(`${type} digest is empty`, r.pos);
			return { keyTag, algorithm, digestType, digest: r.rest() };
		},
		encode(w, data) {
			obj(data, type);
			w.u16(data.keyTag);
			w.u8(data.algorithm);
			w.u8(data.digestType);
			const d = bytes(data.digest, `${type} digest`);
			if (d.length === 0) badRdata(`${type} digest is empty`);
			w.raw(d);
		},
		parse(t) {
			const keyTag = t.int("key tag", 0xffff);
			const algorithm = t.int("algorithm", 0xff);
			const digestType = t.int("digest type", 0xff);
			const digest = fromHex(t.joinRest(), `${type} digest`);
			if (digest.length === 0) badRdata(`${type} digest is empty`);
			return { keyTag, algorithm, digestType, digest };
		},
		format: (d) => `${d.keyTag} ${d.algorithm} ${d.digestType} ${toHex(d.digest)}`
	};
}

export const DS = dsLike("DS");
export const CDS = dsLike("CDS");

/**
 * DNSKEY and CDNSKEY share a format: flags, protocol, algorithm, public key.
 * @param {string} type
 * @returns {import("./common.mjs").RdataCodec}
 */
function keyLike(type) {
	return {
		name: type,
		decode(r) {
			const flags = r.u16();
			const protocol = r.u8();
			const algorithm = r.u8();
			if (r.remaining === 0) badRdata(`${type} public key is empty`, r.pos);
			return { flags, protocol, algorithm, publicKey: r.rest() };
		},
		encode(w, data) {
			obj(data, type);
			w.u16(data.flags);
			w.u8(data.protocol);
			w.u8(data.algorithm);
			const k = bytes(data.publicKey, `${type} public key`);
			if (k.length === 0) badRdata(`${type} public key is empty`);
			w.raw(k);
		},
		parse(t) {
			const flags = t.int("flags", 0xffff);
			const protocol = t.int("protocol", 0xff);
			const algorithm = t.int("algorithm", 0xff);
			const publicKey = fromBase64(t.joinRest(), `${type} public key`);
			if (publicKey.length === 0) badRdata(`${type} public key is empty`);
			return { flags, protocol, algorithm, publicKey };
		},
		format: (d) => `${d.flags} ${d.protocol} ${d.algorithm} ${toBase64(d.publicKey)}`
	};
}

export const DNSKEY = keyLike("DNSKEY");
export const CDNSKEY = keyLike("CDNSKEY");

/** @type {import("./common.mjs").RdataCodec} */
export const RRSIG = {
	name: "RRSIG",
	decode(r) {
		const typeCovered = r.u16();
		if (typeCovered === 0 || typeCovered === 0xffff) badRdata(`RRSIG type covered ${typeCovered} is reserved`, r.pos - 2); // 0 and 65535 are reserved (CLDMV/digby#38)
		const out = {
			typeCovered,
			algorithm: r.u8(),
			labels: r.u8(),
			originalTtl: r.u32(),
			expiration: r.u32(),
			inception: r.u32(),
			keyTag: r.u16(),
			signerName: readName(r)
		};
		if (r.remaining === 0) badRdata("RRSIG signature is empty", r.pos);
		out.signature = r.rest();
		return out;
	},
	encode(w, data) {
		obj(data, "RRSIG");
		const covered = data.typeCovered; // read once: the check and the write act on the same value (CLDMV/digby#39)
		if (covered === 0 || covered === 0xffff) badRdata(`RRSIG type covered ${String(covered)} is reserved`); // 0 and 65535 are reserved (CLDMV/digby#38)
		w.u16(covered);
		w.u8(data.algorithm);
		w.u8(data.labels);
		w.u32(data.originalTtl);
		w.u32(data.expiration);
		w.u32(data.inception);
		w.u16(data.keyTag);
		writeName(w, string(data.signerName, "RRSIG signer name"), false);
		const s = bytes(data.signature, "RRSIG signature");
		if (s.length === 0) badRdata("RRSIG signature is empty");
		w.raw(s);
	},
	parse(t, origin) {
		const typeCovered = typeFromString(t.word("type covered"));
		if (typeCovered === 0 || typeCovered === 0xffff) fail(WireErrorCode.BAD_PRESENTATION, `RRSIG type covered ${typeCovered} is reserved`); // 0 and 65535 are reserved (CLDMV/digby#38)
		const algorithm = t.int("algorithm", 0xff);
		const labels = t.int("labels", 0xff);
		const originalTtl = t.int("original TTL", 0xffffffff);
		const expiration = parseTime(t.word("expiration"), "expiration");
		const inception = parseTime(t.word("inception"), "inception");
		const keyTag = t.int("key tag", 0xffff);
		const signerName = canonicalName(t.word("signer name"), origin);
		const signature = fromBase64(t.joinRest(), "RRSIG signature");
		if (signature.length === 0) badRdata("RRSIG signature is empty");
		return { typeCovered, algorithm, labels, originalTtl, expiration, inception, keyTag, signerName, signature };
	},
	format: (d) =>
		`${typeToString(d.typeCovered)} ${d.algorithm} ${d.labels} ${d.originalTtl} ${formatTime(d.expiration)} ${formatTime(d.inception)} ${d.keyTag} ${d.signerName} ${toBase64(d.signature)}`
};

/** @type {import("./common.mjs").RdataCodec} */
export const NSEC = {
	name: "NSEC",
	decode: (r) => ({ next: readName(r), types: readTypeBitmap(r) }),
	encode(w, data) {
		obj(data, "NSEC");
		writeName(w, string(data.next, "NSEC next name"), false);
		writeTypeBitmap(w, data.types);
	},
	parse(t, origin) {
		const next = canonicalName(t.word("next name"), origin);
		return { next, types: parseTypes(t) };
	},
	format: (d) => (d.types.length ? `${d.next} ${formatTypes(d.types)}` : d.next)
};

const parseSalt = (text) => (text === "-" ? new Uint8Array(0) : fromHex(text, "salt"));
const formatSalt = (salt) => (salt.length ? toHex(salt) : "-");

/** @type {import("./common.mjs").RdataCodec} */
export const NSEC3 = {
	name: "NSEC3",
	decode(r) {
		const hashAlgorithm = r.u8();
		const flags = r.u8();
		const iterations = r.u16();
		const salt = r.charString();
		const at = r.pos;
		const nextHashed = r.charString();
		if (nextHashed.length === 0) badRdata("NSEC3 next hashed owner is empty", at);
		return { hashAlgorithm, flags, iterations, salt, nextHashed, types: readTypeBitmap(r) };
	},
	encode(w, data) {
		obj(data, "NSEC3");
		w.u8(data.hashAlgorithm);
		w.u8(data.flags);
		w.u16(data.iterations);
		w.charString(bytes(data.salt, "NSEC3 salt"));
		const h = bytes(data.nextHashed, "NSEC3 next hashed owner");
		if (h.length === 0) badRdata("NSEC3 next hashed owner is empty");
		w.charString(h);
		writeTypeBitmap(w, data.types);
	},
	parse(t) {
		const hashAlgorithm = t.int("hash algorithm", 0xff);
		const flags = t.int("flags", 0xff);
		const iterations = t.int("iterations", 0xffff);
		const salt = parseSalt(t.word("salt"));
		if (salt.length > 255) badRdata("NSEC3 salt is at most 255 octets");
		const nextHashed = fromBase32Hex(t.word("next hashed owner"), "next hashed owner");
		if (nextHashed.length === 0 || nextHashed.length > 255) badRdata("NSEC3 next hashed owner is 1 to 255 octets");
		return { hashAlgorithm, flags, iterations, salt, nextHashed, types: parseTypes(t) };
	},
	format(d) {
		const head = `${d.hashAlgorithm} ${d.flags} ${d.iterations} ${formatSalt(d.salt)} ${toBase32Hex(d.nextHashed)}`;
		return d.types.length ? `${head} ${formatTypes(d.types)}` : head;
	}
};

/** @type {import("./common.mjs").RdataCodec} */
export const NSEC3PARAM = {
	name: "NSEC3PARAM",
	decode: (r) => ({ hashAlgorithm: r.u8(), flags: r.u8(), iterations: r.u16(), salt: r.charString() }),
	encode(w, data) {
		obj(data, "NSEC3PARAM");
		w.u8(data.hashAlgorithm);
		w.u8(data.flags);
		w.u16(data.iterations);
		w.charString(bytes(data.salt, "NSEC3PARAM salt"));
	},
	parse(t) {
		const hashAlgorithm = t.int("hash algorithm", 0xff);
		const flags = t.int("flags", 0xff);
		const iterations = t.int("iterations", 0xffff);
		const salt = parseSalt(t.word("salt"));
		if (salt.length > 255) badRdata("NSEC3PARAM salt is at most 255 octets");
		t.end();
		return { hashAlgorithm, flags, iterations, salt };
	},
	format: (d) => `${d.hashAlgorithm} ${d.flags} ${d.iterations} ${formatSalt(d.salt)}`
};
