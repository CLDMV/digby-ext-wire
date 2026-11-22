/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/rdata/tsig.mjs
 */

/**
 * @fileoverview TSIG rdata (RFC 8945 4.2). Structural only: computing and verifying the MAC is the TSIG verifier's job, not the
 * codec's.
 *
 * Data shape: `{ algorithm, timeSigned, fudge, mac, originalId, error, otherData }`; `timeSigned` is a 48-bit number of
 * seconds, `mac` and `otherData` are octets.
 *
 * TSIG has no standard master-file form (it never appears in zones). The presentation used here follows BIND's:
 * `algorithm timeSigned fudge macSize mac originalId error otherLen other`, with base64 octets and `-` for an empty field.
 */

import { canonicalName, readName, writeName } from "../names.mjs";
import { fromBase64, toBase64 } from "../text.mjs";
import { badRdata, bytes, obj, string } from "./common.mjs";

const parseOctets = (text, size, what) => {
	const b = text === "-" ? new Uint8Array(0) : fromBase64(text, what);
	if (b.length !== size) badRdata(`${what} is ${b.length} octets but its size says ${size}`);
	return b;
};
const formatOctets = (b) => (b.length ? toBase64(b) : "-");

/** @type {import("./common.mjs").RdataCodec} */
export const TSIG = {
	name: "TSIG",
	decode(r) {
		const algorithm = readName(r);
		const timeSigned = r.u48();
		const fudge = r.u16();
		const mac = r.take(r.u16());
		const originalId = r.u16();
		const error = r.u16();
		const otherData = r.take(r.u16());
		return { algorithm, timeSigned, fudge, mac, originalId, error, otherData };
	},
	encode(w, data) {
		obj(data, "TSIG");
		writeName(w, string(data.algorithm, "TSIG algorithm"), false);
		w.u48(data.timeSigned);
		w.u16(data.fudge);
		const mac = bytes(data.mac, "TSIG mac");
		w.u16(mac.length);
		w.raw(mac);
		w.u16(data.originalId);
		w.u16(data.error);
		const other = bytes(data.otherData, "TSIG other data");
		w.u16(other.length);
		w.raw(other);
	},
	parse(t, origin) {
		const algorithm = canonicalName(t.word("algorithm"), origin);
		const timeSigned = t.int("time signed", 0xffffffffffff);
		const fudge = t.int("fudge", 0xffff);
		const macSize = t.int("MAC size", 0xffff);
		const mac = parseOctets(t.word("MAC"), macSize, "TSIG MAC");
		const originalId = t.int("original id", 0xffff);
		const error = t.int("error", 0xffff);
		const otherLen = t.int("other length", 0xffff);
		const otherData = parseOctets(t.word("other data"), otherLen, "TSIG other data");
		t.end();
		return { algorithm, timeSigned, fudge, mac, originalId, error, otherData };
	},
	format: (d) =>
		`${d.algorithm} ${d.timeSigned} ${d.fudge} ${d.mac.length} ${formatOctets(d.mac)} ${d.originalId} ${d.error} ${d.otherData.length} ${formatOctets(d.otherData)}`
};
