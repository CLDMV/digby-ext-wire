/**
 *	@Project: @cldmv/digby-ext-server
 *	@Filename: /src/lib/wire/index.mjs
 */

/**
 * @fileoverview The DNS wire codec's public surface. A pure module: no I/O, no network, `node:` built-ins only.
 *
 * - messages: {@link decodeMessage}, {@link encodeMessage}, {@link encodeCapped}
 * - transports: {@link encodeForTransport}, {@link udpLimit}, {@link frameTcp}, {@link TcpFramer}
 * - rdata: {@link decodeRdataBytes}, {@link encodeRdataBytes}, {@link parseRdata}, {@link formatRdata}
 * - records in presentation form: {@link parseRecord}, {@link formatRecord}, {@link parseTtl}
 * - names: {@link canonicalName}, {@link namesEqual}, {@link parseName}, {@link formatName}
 * - constants and mnemonics: {@link TYPE}, {@link CLASS}, {@link RCODE}, {@link OPCODE}, {@link EDNS_OPTION}, {@link SVC_KEY}
 * - errors: {@link WireError}, {@link WireErrorCode}
 */

export { WireError, WireErrorCode } from "./errors.mjs";
export {
	CLASS,
	EDNS_OPTION,
	OPCODE,
	RCODE,
	SVC_KEY,
	TYPE,
	classFromString,
	classToString,
	svcKeyFromString,
	svcKeyToString,
	typeFromString,
	typeToString
} from "./constants.mjs";
export { MAX_MESSAGE } from "./buffer.mjs";
export { MAX_LABEL, MAX_NAME, canonicalName, formatName, labelCount, nameKey, namesEqual, parseName } from "./names.mjs";
export { decodeMessage, encodeCapped, encodeMessage } from "./message.mjs";
export { DEFAULT_UDP_CAP, TCP_MAX, TcpFramer, UDP_MIN, encodeForTransport, frameTcp, udpLimit } from "./limits.mjs";
export { TYPED, decodeRdataBytes, encodeRdataBytes, formatGeneric, formatRdata, isTyped, parseRdata } from "./rdata/index.mjs";
export { formatRecord, parseRecord, parseTtl } from "./presentation.mjs";
