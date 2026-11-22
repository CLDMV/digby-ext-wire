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
import { WireErrorCode, fail } from "./errors.mjs";
import { canonicalName } from "./names.mjs";
import { formatRdata, parseRdataTokens } from "./rdata/index.mjs";
import { Tokens, tokenize } from "./text.mjs";

export { formatRdata, parseRdata, formatGeneric } from "./rdata/index.mjs";

const UNIT = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };

/** The largest TTL the codec accepts (RFC 2181 8); encode's wire writer uses the same bound. */
const MAX_TTL = 0x7fffffff;

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
 * @returns {{ name: string, ttl: number, class: number, type: number, data: object }}
 */
export function parseRecord(text, { origin, ttl: defaultTtl, class: defaultClass = CLASS.IN } = {}) {
	const t = new Tokens(tokenize(text));
	const name = canonicalName(t.word("owner name"), origin);
	let ttl;
	let cls;
	for (let k = 0; k < 2 && !t.done; k++) {
		const tok = t.list[t.i];
		if (tok.quoted) break;
		if (ttl === undefined && isTtlToken(tok.value)) {
			ttl = parseTtl(tok.value);
			t.i++;
		} else if (cls === undefined && isClassToken(tok.value)) {
			cls = classFromString(tok.value);
			t.i++;
		} else break;
	}
	const type = typeFromString(t.word("type"));
	if (type === 0xffff) fail(WireErrorCode.BAD_PRESENTATION, "record type 65535 is reserved");
	ttl ??= defaultTtl;
	if (ttl === undefined) fail(WireErrorCode.BAD_PRESENTATION, "the record has no TTL and no default was given");
	const data = parseRdataTokens(type, t, origin);
	return { name, ttl, class: cls ?? defaultClass, type, data };
}

/**
 * Format one record on one line: `name ttl class type rdata`. Every field is validated first, so a bad shape raises a
 * {@link WireError} — the line can never carry injected record text (CLDMV/digby#37).
 * @param {{ name: string, ttl: number, class?: number, type: number, data: object | null }} rec
 * @returns {string}
 * @throws {import("./errors.mjs").WireError} VALUE_OUT_OF_RANGE, BAD_PRESENTATION, or whatever the rdata encoding raises
 */
export function formatRecord(rec) {
	if (rec === null || typeof rec !== "object" || Array.isArray(rec)) fail(WireErrorCode.VALUE_OUT_OF_RANGE, "a record must be an object");
	const name = canonicalName(rec.name); // parses, so no unvalidated name text reaches the line
	if (!Number.isInteger(rec.ttl) || rec.ttl < 0 || rec.ttl > MAX_TTL) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `TTL out of range: ${String(rec.ttl)}`);
	const cls = rec.class ?? CLASS.IN;
	if (!Number.isInteger(cls) || cls < 0 || cls > 0xffff) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `class out of range: ${String(cls)}`);
	if (!Number.isInteger(rec.type) || rec.type < 0 || rec.type > 0xffff) fail(WireErrorCode.VALUE_OUT_OF_RANGE, `type out of range: ${String(rec.type)}`);
	const head = `${name} ${rec.ttl} ${classToString(cls)} ${typeToString(rec.type)}`;
	if (rec.data === null) return head;
	return `${head} ${formatRdata(rec.type, rec.data)}`;
}
