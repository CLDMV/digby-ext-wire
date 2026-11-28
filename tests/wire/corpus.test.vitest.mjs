/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /tests/wire/corpus.test.vitest.mjs
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { classToString, typeToString } from "../../src/lib/constants.mjs";
import { decodeMessage, encodeMessage } from "../../src/lib/message.mjs";
import { formatRecord, parseRecord } from "../../src/lib/presentation.mjs";
import { decodeRdataBytes, encodeRdataBytes } from "../../src/lib/rdata/index.mjs";
import { hex } from "../helpers/wire-gen.mjs";

const load = (name) => JSON.parse(readFileSync(new URL(`../fixtures/wire/${name}`, import.meta.url), "utf8"));
const messages = load("messages.json").messages;
const presentation = load("presentation.json");

describe("wire corpus", () => {
	for (const fx of messages) {
		it(fx.name, () => {
			const bytes = hex.from(fx.hex.join("\n"));
			const m = decodeMessage(bytes);
			expect(m.id).toBe(fx.header.id);
			expect(m.rcode).toBe(fx.header.rcode);
			expect(m.flags).toMatchObject(fx.header.flags);
			expect(m.questions.map((q) => `${q.name} ${typeToString(q.type)} ${classToString(q.class)}`)).toEqual(fx.questions);
			expect([...m.answers, ...m.authorities, ...m.additionals].map(formatRecord)).toEqual(fx.records);
			if (fx.edns === null) expect(m.edns).toBeNull();
			else {
				const { optionCodes, ...fields } = fx.edns;
				expect(m.edns).toMatchObject(fields);
				expect(m.edns.options.map((o) => o.code)).toEqual(optionCodes);
			}
			if (fx.reencode) expect(hex.to(encodeMessage(m))).toBe(hex.to(bytes));
			expect(decodeMessage(encodeMessage(m))).toEqual(m);
		});
	}
});

describe("presentation corpus", () => {
	for (const fx of presentation.records) {
		it(fx.text, () => {
			const rec = parseRecord(fx.text, { origin: presentation.origin });
			expect(formatRecord(rec)).toBe(fx.canonical);
			expect(parseRecord(fx.canonical)).toEqual(rec);
			expect(decodeRdataBytes(rec.type, encodeRdataBytes(rec.type, rec.data))).toEqual(rec.data);
		});
	}
});
