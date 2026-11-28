/**
 *	@Project: @cldmv/digby-ext-wire
 *	@Filename: /scripts/build.mjs
 *	@Date: 2026-11-27T00:00:00-08:00
 *	@Author: Nate Corcoran <CLDMV>
 *	@Email: <Shinrai@users.noreply.github.com>
 *	-----
 *	@Last modified by: Nate Corcoran <CLDMV> (Shinrai@users.noreply.github.com)
 *	@Last modified time: 2026-11-27T00:00:00-08:00
 *	-----
 *	@Copyright: Copyright (c) 2013-2026 Catalyzed Motivation Inc. All rights reserved.
 *
 */

/**
 * @fileoverview The per-module build (npm run build): esbuild with `bundle: false` — every src file compiled and
 * minified in place with `keepNames: true`, dist/ mirroring src/ one file per module — plus the generic CommonJS
 * shim at dist/index.cjs. Nothing is merged, moved, split or duplicated: a module's code stays in exactly one file
 * at the path it lives at in src/, so import shapes and `new URL(..., import.meta.url)` paths survive (CLDMV
 * fleet build convention, package-layout). dist/ is a build artifact — gitignored, rebuilt by `prepack`, never
 * shipped (the package's main and the rummage manifest compose src/ directly).
 */

import { build } from "esbuild";
import { mkdir, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = path.join(pkgRoot, "src");
const dist = path.join(pkgRoot, "dist");

/** Every .mjs file under src/, recursively. */
const walk = async (dir) => {
	const out = [];
	for (const e of await readdir(dir, { withFileTypes: true, recursive: true })) if (e.isFile() && e.name.endsWith(".mjs")) out.push(path.join(e.parentPath, e.name));
	return out;
};

await rm(dist, { recursive: true, force: true });
const entries = await walk(src);
await build({
	entryPoints: entries,
	outdir: dist,
	outbase: src,
	// one file per module: no bundling, no chunking, no code movement — each file compiled and minified where it is
	bundle: false,
	minify: true,
	keepNames: true,
	format: "esm",
	target: "node24",
	outExtension: { ".js": ".mjs" },
	sourcemap: true,
	logLevel: "info"
});

// The generic CommonJS shim, dist/index.cjs — the same ~1 kB file in every repo, only the package name and the
// Node floor differ. Wire's ESM entry is src/api/wire/wire.mjs (the root leaf, `main`), so the shim requires the
// mirrored build of that path; `require(esm)` is synchronous and wire.mjs has no top-level await. When the entry
// exports one distinct value the shim returns it (require(x)(...) works); otherwise the module object, so
// require(x).named and destructuring match import.
await mkdir(dist, { recursive: true });
await writeFile(
	path.join(dist, "index.cjs"),
	`"use strict";

if (!process.features?.require_module) {
	const error = new Error(
		"@cldmv/digby-ext-wire: require() needs Node.js >=24.15.0 (this is " + process.version + "). On older Node.js, load the package with import() instead."
	);
	error.code = "ERR_REQUIRE_ESM";
	throw error;
}

const esm = require("./api/wire/wire.mjs");
const values = new Set(Object.keys(esm).filter((key) => key !== "__esModule").map((key) => esm[key]));
module.exports = values.size === 1 ? values.values().next().value : esm;
`,
	"utf8"
);
console.log(`built ${entries.length} module(s) into dist/ + dist/index.cjs`);
